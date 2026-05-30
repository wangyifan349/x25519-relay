#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
E2EE X25519 relay server over plain TCP with persistent encrypted-message synchronization.

Install dependencies:
    pip install "cryptography>=41"

Run:
    python server.py

Startup prompts:
    - listen address
    - listen port
    - SQLite database path
    - server safety and queue limits

Security model:
    - The server never receives plaintext chat text or plaintext file bytes.
    - The server stores encrypted envelopes exactly as clients upload them.
    - The server can still see metadata: sender public id, recipient public id,
      timestamps, encrypted frame sizes, file chunk counts, and traffic timing.

Scalability model:
    - One asyncio task handles each client connection.
    - Each connected client has independent outbound queues.
    - Urgent frames such as chat, ack, and sync control messages have priority.
    - Bulk frames such as file chunks are bounded so slow clients do not block
      unrelated users. If live delivery to a slow recipient queue is full, the
      already-persisted message remains available through /sync.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import signal
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import count
from typing import Any


PROTOCOL_VERSION = 4
VALID_ENVELOPE_KINDS = {"chat", "file_start", "file_chunk"}
DEFAULT_MAX_TCP_FRAME_SIZE = 2 * 1024 * 1024
TCP_FRAME_HEADER_SIZE = 4
DEFAULT_MAX_ENVELOPE_JSON_SIZE = 1_800_000
DEFAULT_URGENT_QUEUE_LIMIT = 4096
DEFAULT_BULK_QUEUE_LIMIT = 1024
DEFAULT_MAX_SYNC_LIMIT = 10000


def compact_json(value: Any) -> str:
    """Serialize JSON without whitespace so size limits are predictable."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def base64url_decode(value: str) -> bytes:
    """Decode unpadded base64url strings used by the client."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def is_valid_x25519_public_id(value: Any) -> bool:
    """A public id is the base64url encoding of a 32-byte X25519 public key."""
    if not isinstance(value, str):
        return False
    try:
        return len(base64url_decode(value)) == 32
    except Exception:
        return False


def is_base64url_bytes(value: Any, expected_length: int | None = None) -> bool:
    if not isinstance(value, str):
        return False
    try:
        decoded = base64url_decode(value)
    except Exception:
        return False
    return expected_length is None or len(decoded) == expected_length


def current_time_ms() -> int:
    return int(time.time() * 1000)


async def write_tcp_frame(
    writer: asyncio.StreamWriter,
    frame: dict[str, Any],
    *,
    max_frame_size: int,
) -> None:
    """Write one length-prefixed JSON frame over TCP."""
    payload = compact_json(frame).encode("utf-8")
    if len(payload) > max_frame_size:
        raise ValueError(f"TCP frame too large: {len(payload)} > {max_frame_size}")
    writer.write(len(payload).to_bytes(TCP_FRAME_HEADER_SIZE, "big") + payload)
    await writer.drain()


async def read_tcp_frame(
    reader: asyncio.StreamReader,
    *,
    max_frame_size: int,
) -> str:
    """Read one length-prefixed UTF-8 JSON frame from TCP."""
    header = await reader.readexactly(TCP_FRAME_HEADER_SIZE)
    payload_length = int.from_bytes(header, "big")
    if payload_length <= 0:
        raise ValueError("empty TCP frame is not allowed")
    if payload_length > max_frame_size:
        raise ValueError(f"TCP frame too large: {payload_length} > {max_frame_size}")
    payload = await reader.readexactly(payload_length)
    return payload.decode("utf-8")


@dataclass(frozen=True)
class ServerConfig:
    database_path: str
    max_tcp_frame_size: int = DEFAULT_MAX_TCP_FRAME_SIZE
    max_envelope_json_size: int = DEFAULT_MAX_ENVELOPE_JSON_SIZE
    urgent_queue_limit: int = DEFAULT_URGENT_QUEUE_LIMIT
    bulk_queue_limit: int = DEFAULT_BULK_QUEUE_LIMIT
    max_sync_limit: int = DEFAULT_MAX_SYNC_LIMIT


@dataclass(frozen=True)
class StoredMessage:
    server_id: int
    created_at_ms: int
    sender_id: str
    recipient_id: str
    kind: str
    client_message_id: str
    envelope: dict[str, Any]
    inserted: bool
    conversation_peer_id: str | None = None
    copy_role: str = "delivery"


class MessageStore:
    """SQLite-backed append-only store for encrypted envelopes.

    SQLite is intentionally simple and durable for this prototype. For very high
    write throughput or multi-node deployment, replace this class with a service
    backed by PostgreSQL, FoundationDB, ScyllaDB, or another production store.
    """

    def __init__(self, database_path: str, *, max_envelope_json_size: int):
        self.database_path = database_path
        self.max_envelope_json_size = max_envelope_json_size
        self.lock = threading.RLock()
        self.connection = sqlite3.connect(
            database_path,
            check_same_thread=False,
            timeout=30.0,
        )
        self.connection.row_factory = sqlite3.Row
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        with self.lock:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=NORMAL")
            self.connection.execute("PRAGMA temp_store=MEMORY")
            self.connection.execute("PRAGMA busy_timeout=30000")
            self.connection.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    server_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at_ms INTEGER NOT NULL,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    client_message_id TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    envelope_size INTEGER NOT NULL,
                    envelope_sha256 TEXT NOT NULL,
                    conversation_peer_id TEXT,
                    copy_role TEXT NOT NULL DEFAULT 'delivery'
                )
                """
            )

            # Lightweight schema migration for databases created by older versions.
            existing_columns = {
                row["name"]
                for row in self.connection.execute("PRAGMA table_info(messages)").fetchall()
            }
            if "conversation_peer_id" not in existing_columns:
                self.connection.execute("ALTER TABLE messages ADD COLUMN conversation_peer_id TEXT")
            if "copy_role" not in existing_columns:
                self.connection.execute("ALTER TABLE messages ADD COLUMN copy_role TEXT NOT NULL DEFAULT 'delivery'")

            self.connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_client_message_id "
                "ON messages(client_message_id)"
            )
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_recipient_server_id "
                "ON messages(recipient_id, server_id)"
            )
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_sender_server_id "
                "ON messages(sender_id, server_id)"
            )
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_pair_server_id "
                "ON messages(sender_id, recipient_id, server_id)"
            )
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_self_copy_server_id "
                "ON messages(recipient_id, conversation_peer_id, copy_role, server_id)"
            )
            self.connection.commit()

    def insert_envelope(
        self,
        *,
        sender_id: str,
        recipient_id: str,
        kind: str,
        client_message_id: str,
        envelope: dict[str, Any],
        conversation_peer_id: str | None = None,
        copy_role: str = "delivery",
    ) -> StoredMessage:
        """Persist an encrypted envelope and return its monotonic server id.

        client_message_id is unique, so retrying the same send is idempotent.
        """
        envelope_json = compact_json(envelope)
        envelope_bytes = envelope_json.encode("utf-8")
        envelope_size = len(envelope_bytes)
        if envelope_size > self.max_envelope_json_size:
            raise ValueError("encrypted envelope is too large")

        created_at_ms = current_time_ms()
        envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()

        with self.lock:
            try:
                cursor = self.connection.execute(
                    """
                    INSERT INTO messages(
                        created_at_ms,
                        sender_id,
                        recipient_id,
                        kind,
                        client_message_id,
                        envelope_json,
                        envelope_size,
                        envelope_sha256,
                        conversation_peer_id,
                        copy_role
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        created_at_ms,
                        sender_id,
                        recipient_id,
                        kind,
                        client_message_id,
                        envelope_json,
                        envelope_size,
                        envelope_sha256,
                        conversation_peer_id,
                        copy_role,
                    ),
                )
                self.connection.commit()
                return StoredMessage(
                    server_id=int(cursor.lastrowid),
                    created_at_ms=created_at_ms,
                    sender_id=sender_id,
                    recipient_id=recipient_id,
                    kind=kind,
                    client_message_id=client_message_id,
                    envelope=envelope,
                    inserted=True,
                    conversation_peer_id=conversation_peer_id,
                    copy_role=copy_role,
                )
            except sqlite3.IntegrityError:
                existing = self.connection.execute(
                    """
                    SELECT server_id, created_at_ms, sender_id, recipient_id, kind, envelope_json,
                           conversation_peer_id, copy_role
                    FROM messages
                    WHERE client_message_id = ?
                    """,
                    (client_message_id,),
                ).fetchone()
                if existing is None:
                    raise
                return self._row_to_stored_message(existing, inserted=False)

    def fetch_conversation(
        self,
        *,
        user_id: str,
        peer_id: str,
        after_server_id: int,
        limit: int,
    ) -> list[StoredMessage]:
        """Fetch stored envelopes between two public ids after a server id."""
        with self.lock:
            rows = self.connection.execute(
                """
                SELECT server_id, created_at_ms, sender_id, recipient_id, kind, envelope_json,
                       conversation_peer_id, copy_role
                FROM messages
                WHERE server_id > ?
                  AND (
                    -- Normal delivery copies that the peer sent to this user.
                    (sender_id = ? AND recipient_id = ? AND copy_role = 'delivery')
                    OR
                    -- Self copies that this user sent and encrypted back to self.
                    (sender_id = ? AND recipient_id = ? AND copy_role = 'self_copy' AND conversation_peer_id = ?)
                  )
                ORDER BY server_id ASC
                LIMIT ?
                """,
                (after_server_id, peer_id, user_id, user_id, user_id, peer_id, limit),
            ).fetchall()
        return [self._row_to_stored_message(row, inserted=True) for row in rows]

    def fetch_all_for_user(
        self,
        *,
        user_id: str,
        after_server_id: int,
        limit: int,
    ) -> list[StoredMessage]:
        """Fetch all envelopes involving a public id after a server id."""
        with self.lock:
            rows = self.connection.execute(
                """
                SELECT server_id, created_at_ms, sender_id, recipient_id, kind, envelope_json,
                       conversation_peer_id, copy_role
                FROM messages
                WHERE server_id > ?
                  AND recipient_id = ?
                  AND copy_role IN ('delivery', 'self_copy')
                ORDER BY server_id ASC
                LIMIT ?
                """,
                (after_server_id, user_id, limit),
            ).fetchall()
        return [self._row_to_stored_message(row, inserted=True) for row in rows]

    @staticmethod
    def _row_to_stored_message(row: sqlite3.Row, *, inserted: bool) -> StoredMessage:
        return StoredMessage(
            server_id=int(row["server_id"]),
            created_at_ms=int(row["created_at_ms"]),
            sender_id=str(row["sender_id"]),
            recipient_id=str(row["recipient_id"]),
            kind=str(row["kind"]),
            client_message_id=json.loads(row["envelope_json"])["id"],
            envelope=json.loads(row["envelope_json"]),
            inserted=inserted,
            conversation_peer_id=row["conversation_peer_id"],
            copy_role=str(row["copy_role"] or "delivery"),
        )


@dataclass(eq=False)
class ClientSession:
    """State and outbound queues for one connected TCP client."""

    public_id: str
    writer: asyncio.StreamWriter
    server: "RelayServer"
    urgent_queue: asyncio.Queue = field(init=False)
    bulk_queue: asyncio.Queue = field(init=False)
    writer_task: asyncio.Task | None = field(default=None, init=False)
    is_closed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        config = self.server.config
        self.urgent_queue = asyncio.Queue(maxsize=config.urgent_queue_limit)
        self.bulk_queue = asyncio.Queue(maxsize=config.bulk_queue_limit)

    async def start(self) -> None:
        self.writer_task = asyncio.create_task(self._writer_loop(), name=f"writer:{self.public_id[:12]}")

    async def close(self) -> None:
        if self.is_closed:
            return
        self.is_closed = True
        if self.writer_task is not None:
            self.writer_task.cancel()
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    async def put_urgent(self, frame: dict[str, Any] | None) -> None:
        await self.urgent_queue.put(frame)

    async def put_bulk(self, frame: dict[str, Any] | None) -> None:
        await self.bulk_queue.put(frame)

    def try_put_urgent(self, frame: dict[str, Any]) -> bool:
        if self.is_closed:
            return False
        try:
            self.urgent_queue.put_nowait(frame)
            return True
        except asyncio.QueueFull:
            return False

    def try_put_bulk(self, frame: dict[str, Any]) -> bool:
        if self.is_closed:
            return False
        try:
            self.bulk_queue.put_nowait(frame)
            return True
        except asyncio.QueueFull:
            return False

    async def _writer_loop(self) -> None:
        """Write queued frames to the TCP connection, always preferring urgent frames."""
        try:
            while True:
                frame = await self._next_outbound_frame()
                if frame is None:
                    return
                await write_tcp_frame(
                    self.writer,
                    frame,
                    max_frame_size=self.server.config.max_tcp_frame_size,
                )
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
            return
        except Exception as exc:
            print(f"writer error for {self.public_id[:12]}…: {exc}")

    async def _next_outbound_frame(self) -> dict[str, Any] | None:
        while True:
            try:
                urgent_frame = self.urgent_queue.get_nowait()
                return urgent_frame
            except asyncio.QueueEmpty:
                pass

            urgent_task = asyncio.create_task(self.urgent_queue.get())
            bulk_task = asyncio.create_task(self.bulk_queue.get())
            done, pending = await asyncio.wait(
                {urgent_task, bulk_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            return next(iter(done)).result()


class RelayServer:
    """Central server that authenticates by public id and stores opaque envelopes."""

    def __init__(self, config: ServerConfig):
        self.config = config
        self.message_store = MessageStore(
            config.database_path,
            max_envelope_json_size=config.max_envelope_json_size,
        )
        self.sessions_by_public_id: dict[str, set[ClientSession]] = defaultdict(set)
        self.sessions_lock = asyncio.Lock()
        self.request_counter = count(1)

    async def register_session(self, session: ClientSession) -> None:
        async with self.sessions_lock:
            self.sessions_by_public_id[session.public_id].add(session)

    async def unregister_session(self, session: ClientSession) -> None:
        async with self.sessions_lock:
            sessions = self.sessions_by_public_id.get(session.public_id)
            if sessions is not None:
                sessions.discard(session)
                if not sessions:
                    self.sessions_by_public_id.pop(session.public_id, None)
        await session.close()

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle one TCP connection from hello until disconnect."""
        session: ClientSession | None = None
        peer_name = writer.get_extra_info("peername")
        try:
            raw_hello = await asyncio.wait_for(
                read_tcp_frame(reader, max_frame_size=self.config.max_tcp_frame_size),
                timeout=20,
            )
            hello_frame = json.loads(raw_hello)

            if hello_frame.get("type") != "hello":
                await write_tcp_frame(
                    writer,
                    {"type": "error", "error": "first frame must be hello"},
                    max_frame_size=self.config.max_tcp_frame_size,
                )
                return

            public_id = hello_frame.get("id")
            if not is_valid_x25519_public_id(public_id):
                await write_tcp_frame(
                    writer,
                    {"type": "error", "error": "invalid X25519 public id"},
                    max_frame_size=self.config.max_tcp_frame_size,
                )
                return

            session = ClientSession(public_id=public_id, writer=writer, server=self)
            await session.start()
            await self.register_session(session)
            await session.put_urgent({
                "type": "hello_ok",
                "id": public_id,
                "server_time_ms": current_time_ms(),
                "protocol_version": PROTOCOL_VERSION,
                "capabilities": {
                    "persistent_sync": True,
                    "live_delivery": True,
                    "server_plaintext_access": False,
                    "max_tcp_frame_size": self.config.max_tcp_frame_size,
                    "max_sync_limit": self.config.max_sync_limit,
                    "transport": "tcp-length-prefixed-json",
                },
            })

            while True:
                raw_frame = await read_tcp_frame(
                    reader,
                    max_frame_size=self.config.max_tcp_frame_size,
                )
                await self.handle_client_frame(session, raw_frame)

        except asyncio.TimeoutError:
            try:
                await write_tcp_frame(
                    writer,
                    {"type": "error", "error": "hello timeout"},
                    max_frame_size=self.config.max_tcp_frame_size,
                )
            except Exception:
                pass
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception as exc:
            print(f"connection error from {peer_name}: {exc}")
            if session is not None:
                await session.put_urgent({"type": "error", "error": str(exc)})
        finally:
            if session is not None:
                await self.unregister_session(session)
            else:
                writer.close()
                await writer.wait_closed()

    async def handle_client_frame(self, session: ClientSession, raw_frame: str) -> None:
        try:
            frame = json.loads(raw_frame)
        except Exception:
            await session.put_urgent({"type": "error", "error": "invalid json"})
            return

        frame_type = frame.get("type")
        if frame_type == "send":
            await self.handle_send_frame(session, frame)
        elif frame_type == "send_self_copy":
            await self.handle_send_self_copy_frame(session, frame)
        elif frame_type == "sync_conversation":
            await self.handle_sync_conversation(session, frame)
        elif frame_type == "sync_all":
            await self.handle_sync_all(session, frame)
        elif frame_type == "ping":
            await session.put_urgent({"type": "pong", "server_time_ms": current_time_ms()})
        else:
            await session.put_urgent({"type": "error", "error": f"unknown frame type: {frame_type}"})

    def validate_envelope(
        self,
        *,
        session: ClientSession,
        recipient_id: Any,
        envelope: Any,
    ) -> tuple[str, str]:
        """Validate metadata that the server must rely on for routing.

        The server cannot validate plaintext because it cannot decrypt. It only
        validates envelope shape, sender identity binding, recipient id, and
        bounded sizes before storing and forwarding.
        """
        if not is_valid_x25519_public_id(recipient_id):
            raise ValueError("invalid recipient public id")
        if not isinstance(envelope, dict):
            raise ValueError("envelope must be an object")

        envelope_size = len(compact_json(envelope).encode("utf-8"))
        if envelope_size > self.config.max_envelope_json_size:
            raise ValueError("encrypted envelope is too large")

        if envelope.get("v") != PROTOCOL_VERSION:
            raise ValueError("unsupported protocol version")

        envelope_kind = envelope.get("kind")
        if envelope_kind not in VALID_ENVELOPE_KINDS:
            raise ValueError("invalid envelope kind")

        sender_id = envelope.get("from")
        envelope_recipient_id = envelope.get("to")
        client_message_id = envelope.get("id")

        if sender_id != session.public_id:
            raise ValueError("envelope.from must match connection identity")
        if envelope_recipient_id != recipient_id:
            raise ValueError("envelope.to must match recipient")
        if not isinstance(client_message_id, str) or not (16 <= len(client_message_id) <= 128):
            raise ValueError("invalid client message id")
        if not is_base64url_bytes(envelope.get("nonce"), 12):
            raise ValueError("invalid nonce")
        if not is_base64url_bytes(envelope.get("ciphertext")):
            raise ValueError("invalid ciphertext")

        if envelope_kind in {"chat", "file_start"}:
            if not is_valid_x25519_public_id(envelope.get("eph")):
                raise ValueError("missing or invalid ephemeral public key")
        elif envelope_kind == "file_chunk":
            file_id = envelope.get("file_id")
            sequence_number = envelope.get("seq")
            if not isinstance(file_id, str) or not (16 <= len(file_id) <= 128):
                raise ValueError("invalid file id")
            if not isinstance(sequence_number, int) or sequence_number < 0:
                raise ValueError("invalid file sequence number")

        return str(envelope_kind), str(client_message_id)

    async def handle_send_frame(self, session: ClientSession, frame: dict[str, Any]) -> None:
        try:
            recipient_id = frame.get("to")
            envelope = frame.get("envelope")
            envelope_kind, client_message_id = self.validate_envelope(
                session=session,
                recipient_id=recipient_id,
                envelope=envelope,
            )

            stored_message = await asyncio.to_thread(
                self.message_store.insert_envelope,
                sender_id=session.public_id,
                recipient_id=recipient_id,
                kind=envelope_kind,
                client_message_id=client_message_id,
                envelope=envelope,
                conversation_peer_id=recipient_id,
                copy_role="delivery",
            )

            await session.put_urgent({
                "type": "ack",
                "server_id": stored_message.server_id,
                "client_message_id": client_message_id,
                "kind": envelope_kind,
                "to": recipient_id,
                "inserted": stored_message.inserted,
            })

            if stored_message.inserted:
                await self.deliver_live(stored_message)

        except Exception as exc:
            await session.put_urgent({"type": "error", "error": str(exc)})

    async def handle_send_self_copy_frame(self, session: ClientSession, frame: dict[str, Any]) -> None:
        """Persist an encrypted sender-owned copy for future sync.

        This copy is encrypted to the sender's own public id, so the sender can
        decrypt it after reconnecting or moving identity.json to another device.
        It is not delivered to the peer; it is only returned to the sender by
        conversation sync.
        """
        try:
            peer_id = frame.get("peer_id")
            if not is_valid_x25519_public_id(peer_id):
                raise ValueError("invalid self-copy peer id")

            envelope = frame.get("envelope")
            envelope_kind, client_message_id = self.validate_envelope(
                session=session,
                recipient_id=session.public_id,
                envelope=envelope,
            )

            stored_message = await asyncio.to_thread(
                self.message_store.insert_envelope,
                sender_id=session.public_id,
                recipient_id=session.public_id,
                kind=envelope_kind,
                client_message_id=client_message_id,
                envelope=envelope,
                conversation_peer_id=peer_id,
                copy_role="self_copy",
            )

            await session.put_urgent({
                "type": "ack",
                "server_id": stored_message.server_id,
                "client_message_id": client_message_id,
                "kind": envelope_kind,
                "to": session.public_id,
                "peer_id": peer_id,
                "self_copy": True,
                "inserted": stored_message.inserted,
            })

        except Exception as exc:
            await session.put_urgent({"type": "error", "error": str(exc)})

    async def deliver_live(self, stored_message: StoredMessage) -> None:
        """Attempt live delivery without blocking the sender on slow recipients."""
        frame = self.stored_message_to_wire_frame(stored_message)
        is_bulk = stored_message.kind == "file_chunk"

        async with self.sessions_lock:
            recipient_sessions = list(self.sessions_by_public_id.get(stored_message.recipient_id, set()))

        for recipient_session in recipient_sessions:
            accepted = (
                recipient_session.try_put_bulk(frame)
                if is_bulk
                else recipient_session.try_put_urgent(frame)
            )
            if not accepted and not is_bulk:
                # Urgent queue exhaustion indicates an unhealthy or maliciously slow
                # connection. Close it; the client can reconnect and sync.
                asyncio.create_task(self.unregister_session(recipient_session))
            # For bulk queue exhaustion, do not close. The persisted message can
            # be recovered by sync, and chat/control frames remain unaffected.

    async def handle_sync_conversation(self, session: ClientSession, frame: dict[str, Any]) -> None:
        peer_id = frame.get("peer_id")
        if not is_valid_x25519_public_id(peer_id):
            await session.put_urgent({"type": "error", "error": "invalid peer public id"})
            return

        after_server_id = self.parse_nonnegative_int(frame.get("after_server_id", 0), "after_server_id")
        limit = self.parse_sync_limit(frame.get("limit", 5000))
        request_id = str(frame.get("request_id") or f"sync-{next(self.request_counter)}")

        rows = await asyncio.to_thread(
            self.message_store.fetch_conversation,
            user_id=session.public_id,
            peer_id=peer_id,
            after_server_id=after_server_id,
            limit=limit,
        )
        await self.stream_sync_result(session, rows, request_id=request_id, limit=limit)

    async def handle_sync_all(self, session: ClientSession, frame: dict[str, Any]) -> None:
        after_server_id = self.parse_nonnegative_int(frame.get("after_server_id", 0), "after_server_id")
        limit = self.parse_sync_limit(frame.get("limit", 5000))
        request_id = str(frame.get("request_id") or f"sync-{next(self.request_counter)}")

        rows = await asyncio.to_thread(
            self.message_store.fetch_all_for_user,
            user_id=session.public_id,
            after_server_id=after_server_id,
            limit=limit,
        )
        await self.stream_sync_result(session, rows, request_id=request_id, limit=limit)

    async def stream_sync_result(
        self,
        session: ClientSession,
        rows: list[StoredMessage],
        *,
        request_id: str,
        limit: int,
    ) -> None:
        """Stream sync results through the requesting session's own queues."""
        await session.put_urgent({"type": "sync_begin", "request_id": request_id, "count": len(rows)})

        last_server_id = 0
        for stored_message in rows:
            last_server_id = stored_message.server_id
            frame = self.stored_message_to_wire_frame(stored_message)
            frame["sync_request_id"] = request_id
            if stored_message.kind == "file_chunk":
                await session.put_bulk(frame)
            else:
                await session.put_urgent(frame)

        await session.put_urgent({
            "type": "sync_end",
            "request_id": request_id,
            "count": len(rows),
            "last_server_id": last_server_id,
            "has_more": len(rows) >= limit,
        })

    @staticmethod
    def stored_message_to_wire_frame(stored_message: StoredMessage) -> dict[str, Any]:
        return {
            "type": "message",
            "server_id": stored_message.server_id,
            "created_at_ms": stored_message.created_at_ms,
            "from": stored_message.sender_id,
            "to": stored_message.recipient_id,
            "kind": stored_message.kind,
            "envelope": stored_message.envelope,
            "conversation_peer_id": stored_message.conversation_peer_id,
            "copy_role": stored_message.copy_role,
        }

    def parse_sync_limit(self, value: Any) -> int:
        limit = self.parse_nonnegative_int(value, "limit")
        if limit <= 0:
            return 1
        return min(limit, self.config.max_sync_limit)

    @staticmethod
    def parse_nonnegative_int(value: Any, field_name: str) -> int:
        try:
            integer_value = int(value)
        except Exception:
            raise ValueError(f"{field_name} must be an integer")
        if integer_value < 0:
            raise ValueError(f"{field_name} must be nonnegative")
        return integer_value


def prompt_line(prompt: str, default: str) -> str:
    """Ask for a string setting while keeping a useful default value."""
    value = input(f"{prompt} [{default}]: ").strip()
    return value if value else default


def prompt_int(prompt: str, default: int, *, minimum: int | None = None) -> int:
    """Ask for an integer setting and repeat until the value is valid."""
    while True:
        raw_value = prompt_line(prompt, str(default))
        try:
            parsed_value = int(raw_value)
        except ValueError:
            print("请输入整数。")
            continue
        if minimum is not None and parsed_value < minimum:
            print(f"请输入不小于 {minimum} 的整数。")
            continue
        return parsed_value


def prompt_float(prompt: str, default: float, *, minimum: float | None = None) -> float:
    """Ask for a floating-point setting and repeat until the value is valid."""
    while True:
        raw_value = prompt_line(prompt, str(default))
        try:
            parsed_value = float(raw_value)
        except ValueError:
            print("请输入数字。")
            continue
        if minimum is not None and parsed_value < minimum:
            print(f"请输入不小于 {minimum} 的数字。")
            continue
        return parsed_value


def prompt_server_config() -> tuple[str, int, ServerConfig]:
    """Collect server startup settings interactively instead of using argv."""
    listen_host = prompt_line("服务器监听地址", "0.0.0.0")
    listen_port = prompt_int("服务器监听端口", 8765, minimum=1)
    database_path = prompt_line("SQLite 数据库文件", "messages.sqlite3")

    print()
    print("下面这些是高级参数。直接回车会使用推荐默认值。")
    max_tcp_frame_size = prompt_int(
        "单条 TCP frame 最大字节数",
        DEFAULT_MAX_TCP_FRAME_SIZE,
        minimum=1024,
    )
    max_envelope_json_size = prompt_int(
        "单个加密 envelope 最大 JSON 字节数",
        DEFAULT_MAX_ENVELOPE_JSON_SIZE,
        minimum=1024,
    )
    urgent_queue_limit = prompt_int(
        "每个连接 urgent 队列上限",
        DEFAULT_URGENT_QUEUE_LIMIT,
        minimum=1,
    )
    bulk_queue_limit = prompt_int(
        "每个连接 bulk 队列上限",
        DEFAULT_BULK_QUEUE_LIMIT,
        minimum=1,
    )
    max_sync_limit = prompt_int(
        "单次同步最大消息数",
        DEFAULT_MAX_SYNC_LIMIT,
        minimum=1,
    )
    config = ServerConfig(
        database_path=database_path,
        max_tcp_frame_size=max_tcp_frame_size,
        max_envelope_json_size=max_envelope_json_size,
        urgent_queue_limit=urgent_queue_limit,
        bulk_queue_limit=bulk_queue_limit,
        max_sync_limit=max_sync_limit,
    )
    return listen_host, listen_port, config


async def run_server() -> None:
    listen_host, listen_port, config = prompt_server_config()

    relay_server = RelayServer(config)
    stop_future = asyncio.Future()

    event_loop = asyncio.get_running_loop()
    for signal_number in (signal.SIGINT, signal.SIGTERM):
        try:
            event_loop.add_signal_handler(signal_number, stop_future.set_result, None)
        except NotImplementedError:
            # Windows event loops may not support add_signal_handler.
            pass

    tcp_server = await asyncio.start_server(
        relay_server.handle_connection,
        listen_host,
        listen_port,
        backlog=1024,
        limit=config.max_tcp_frame_size + TCP_FRAME_HEADER_SIZE,
    )

    async with tcp_server:
        print(f"relay server listening on tcp://{listen_host}:{listen_port}")
        print(f"database: {config.database_path}")
        print("plaintext access: disabled; server stores encrypted envelopes only")
        print("wire format: 4-byte length prefix + compact JSON frame")
        await stop_future


if __name__ == "__main__":
    asyncio.run(run_server())
