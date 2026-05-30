#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
E2EE X25519 + ChaCha20-Poly1305 chat/file client over plain TCP.

Install dependencies:
    pip install -U cryptography

Run:
    python client.py

Startup prompts:
    - server IP/domain
    - server port
    - peer public id to talk to
    - optional SOCKS5 TCP proxy

Usage model:
    - Plain input sends a chat message to the default peer.
    - /send, /file, and /files send one or more files.
    - Every outgoing chat/file also stores a sender-owned encrypted self-copy
      so full history can sync back after reconnecting.
    - The client automatically syncs the selected conversation on connect and
      periodically afterwards.

Security model:
    - Your identity private key stays only in the local identity JSON file.
    - You send to the recipient's X25519 public id directly.
    - If the public id was obtained and verified outside the server, the server
      cannot replace the recipient key without changing the destination identity.
    - If a future version lets the server search usernames and return public
      keys, then you must add public-key pinning, TOFU, fingerprints, or a
      signed directory to avoid key-substitution attacks.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
import re
import shlex
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL_VERSION = 4
CHUNK_SIZE = 64 * 1024
MAX_TCP_FRAME_SIZE = 2 * 1024 * 1024
TCP_CONNECT_TIMEOUT_SECONDS = 20.0
TCP_FRAME_HEADER_SIZE = 4
DOWNLOAD_DIRECTORY = Path("downloads")
URGENT_OUTBOX_LIMIT = 4096
BULK_STREAM_QUEUE_LIMIT = 8
MAX_TRACKED_MESSAGE_IDS = 200000
AUTO_SYNC_INTERVAL_SECONDS = 20.0


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_ALPHABET_INDEX = {char: index for index, char in enumerate(BASE58_ALPHABET)}


def base58_encode(data: bytes) -> str:
    """Encode bytes with the Bitcoin Base58 alphabet.

    This is used only for user-facing key display. The internal wire protocol
    still uses the older base64url public ids for compatibility.
    """
    if not data:
        return ""

    leading_zero_count = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")

    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded

    return ("1" * leading_zero_count) + (encoded or "")


def base58_decode(value: str) -> bytes:
    """Decode a Base58 string using the Bitcoin Base58 alphabet."""
    value = value.strip()
    if not value:
        return b""

    number = 0
    for char in value:
        try:
            digit = BASE58_ALPHABET_INDEX[char]
        except KeyError:
            raise ValueError("invalid Base58 character") from None
        number = number * 58 + digit

    byte_length = (number.bit_length() + 7) // 8
    data = number.to_bytes(byte_length, "big") if byte_length else b""
    leading_zero_count = len(value) - len(value.lstrip("1"))
    return (b"\x00" * leading_zero_count) + data


def public_id_to_base58(public_id: str) -> str:
    """Convert the internal base64url public id into user-facing Base58."""
    return base58_encode(base64url_decode(public_id))


def private_key_to_base58(private_key: x25519.X25519PrivateKey) -> str:
    """Return the raw X25519 private key bytes in user-facing Base58."""
    return base58_encode(private_key_bytes(private_key))


def normalize_public_id(public_id_text: str) -> str:
    """Accept either Base58 or the old base64url public id and return base64url.

    The server and encrypted envelope metadata still use base64url internally.
    Users can paste the newer Base58 display form at prompts and /to commands.
    """
    public_id_text = public_id_text.strip()
    if is_valid_x25519_public_id(public_id_text):
        return public_id_text

    try:
        raw_public_key = base58_decode(public_id_text)
    except ValueError:
        return public_id_text

    if len(raw_public_key) != 32:
        return public_id_text
    return base64url_encode(raw_public_key)


def current_time_ms() -> int:
    return int(time.time() * 1000)


def is_valid_x25519_public_id(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(base64url_decode(value)) == 32
    except Exception:
        return False


def safe_filename(filename: str) -> str:
    """Return a filesystem-safe basename while preserving common characters."""
    filename = Path(filename).name
    filename = re.sub(r"[^A-Za-z0-9._()\-\u4e00-\u9fff]+", "_", filename).strip("._")
    return filename or "file.bin"


def unique_path(path: Path) -> Path:
    """Avoid overwriting an existing downloaded file."""
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    for index in range(1, 100000):
        candidate = path.with_name(f"{stem}_{index}{suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError("too many duplicate filenames")


def prompt_line(prompt: str, default: str | None = None) -> str:
    if default is None:
        return input(prompt).strip()
    value = input(f"{prompt} [{default}]: ").strip()
    return value or default


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    value = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "1", "true"}


@dataclass(frozen=True)
class Socks5ProxyConfig:
    """Optional SOCKS5 proxy used only to create the TCP connection."""

    host: str
    port: int
    username: str | None = None
    password: str | None = None


async def write_tcp_frame(
    writer: asyncio.StreamWriter,
    frame: dict[str, Any],
    *,
    max_frame_size: int = MAX_TCP_FRAME_SIZE,
) -> None:
    """Write one length-prefixed JSON frame over TCP.

    Wire format:
        4-byte unsigned big-endian length + UTF-8 JSON bytes
    """
    payload = compact_json(frame).encode("utf-8")
    if len(payload) > max_frame_size:
        raise ValueError(f"TCP frame too large: {len(payload)} > {max_frame_size}")
    writer.write(len(payload).to_bytes(TCP_FRAME_HEADER_SIZE, "big") + payload)
    await writer.drain()


async def read_tcp_frame(
    reader: asyncio.StreamReader,
    *,
    max_frame_size: int = MAX_TCP_FRAME_SIZE,
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


async def open_tcp_connection(
    host: str,
    port: int,
    proxy_config: Socks5ProxyConfig | None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a direct TCP connection or a TCP connection through SOCKS5."""
    if proxy_config is None:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TCP_CONNECT_TIMEOUT_SECONDS,
        )
    return await open_socks5_tcp_connection(host, port, proxy_config)


async def open_socks5_tcp_connection(
    target_host: str,
    target_port: int,
    proxy_config: Socks5ProxyConfig,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Create a TCP tunnel through a SOCKS5 proxy using CONNECT.

    The target host is sent as a domain name, so DNS resolution happens on the
    proxy side. This is usually what users want when trying to avoid leaking the
    destination lookup through the local network.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_config.host, proxy_config.port),
        timeout=TCP_CONNECT_TIMEOUT_SECONDS,
    )

    try:
        methods = [0x00]
        if proxy_config.username:
            methods.append(0x02)
        writer.write(bytes([0x05, len(methods), *methods]))
        await writer.drain()

        response = await reader.readexactly(2)
        if response[0] != 0x05:
            raise OSError("invalid SOCKS5 greeting response")
        selected_method = response[1]
        if selected_method == 0xFF:
            raise OSError("SOCKS5 proxy rejected all authentication methods")

        if selected_method == 0x02:
            username = (proxy_config.username or "").encode("utf-8")
            password = (proxy_config.password or "").encode("utf-8")
            if len(username) > 255 or len(password) > 255:
                raise ValueError("SOCKS5 username/password is too long")
            writer.write(bytes([0x01, len(username)]) + username + bytes([len(password)]) + password)
            await writer.drain()
            auth_response = await reader.readexactly(2)
            if auth_response != b"\x01\x00":
                raise OSError("SOCKS5 username/password authentication failed")
        elif selected_method != 0x00:
            raise OSError(f"unsupported SOCKS5 authentication method: {selected_method}")

        host_bytes = target_host.encode("idna")
        if len(host_bytes) > 255:
            raise ValueError("target host is too long for SOCKS5 domain mode")
        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + int(target_port).to_bytes(2, "big")
        )
        writer.write(request)
        await writer.drain()

        reply_header = await reader.readexactly(4)
        if reply_header[0] != 0x05:
            raise OSError("invalid SOCKS5 CONNECT response")
        if reply_header[1] != 0x00:
            raise OSError(f"SOCKS5 CONNECT failed with code {reply_header[1]}")

        address_type = reply_header[3]
        if address_type == 0x01:
            await reader.readexactly(4)
        elif address_type == 0x03:
            domain_length = (await reader.readexactly(1))[0]
            await reader.readexactly(domain_length)
        elif address_type == 0x04:
            await reader.readexactly(16)
        else:
            raise OSError(f"invalid SOCKS5 address type: {address_type}")
        await reader.readexactly(2)
        return reader, writer
    except Exception:
        writer.close()
        await writer.wait_closed()
        raise


def public_key_bytes(private_key: x25519.X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_bytes(private_key: x25519.X25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_from_id(public_id: str) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(base64url_decode(public_id))


def load_or_create_identity(identity_path: Path) -> tuple[x25519.X25519PrivateKey, str]:
    """Load an X25519 identity or create one on first run."""
    if identity_path.exists():
        identity_data = json.loads(identity_path.read_text(encoding="utf-8"))
        private_key = x25519.X25519PrivateKey.from_private_bytes(
            base64url_decode(identity_data["private_key"])
        )
        public_id = identity_data["public_id"]
        if base64url_encode(public_key_bytes(private_key)) != public_id:
            raise ValueError("identity file public_id does not match private key")
        return private_key, public_id

    private_key = x25519.X25519PrivateKey.generate()
    public_id = base64url_encode(public_key_bytes(private_key))
    identity_data = {
        "type": "x25519-identity-v4",
        "public_id": public_id,
        "private_key": base64url_encode(private_key_bytes(private_key)),
        "created_at_ms": current_time_ms(),
    }
    identity_path.write_text(json.dumps(identity_data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"created identity file: {identity_path}")
    return private_key, public_id


def fingerprint_for_public_id(public_id: str) -> str:
    """Short display fingerprint for out-of-band public-id comparison."""
    digest = hashlib.sha256(base64url_decode(public_id)).hexdigest()
    return ":".join(digest[index : index + 4] for index in range(0, 32, 4))


def print_local_identity(private_key: x25519.X25519PrivateKey, public_id: str) -> None:
    """Print the local X25519 identity immediately when the client starts."""
    print()
    print("========== Your local identity ==========")
    print("WARNING: the private key is your identity secret. Do not share it.")
    print(f"private key base58: {private_key_to_base58(private_key)}")
    print(f"public key base58 / username: {public_id_to_base58(public_id)}")
    print(f"fingerprint: {fingerprint_for_public_id(public_id)}")
    print("=========================================")
    print()

def derive_box_key(
    *,
    static_shared_secret: bytes,
    ephemeral_shared_secret: bytes,
    envelope_kind: str,
    sender_id: str,
    recipient_id: str,
    ephemeral_id: str,
) -> bytes:
    """Derive an AEAD key for chat and file-start envelopes.

    static_shared_secret authenticates the long-term sender public id to the
    recipient who already knows that public id. ephemeral_shared_secret gives
    each envelope a fresh one-time contribution.
    """
    hkdf_info = compact_json({
        "protocol": "e2ee-x25519-chacha20poly1305-v4",
        "envelope_kind": envelope_kind,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "ephemeral_id": ephemeral_id,
    }).encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=hkdf_info,
    ).derive(static_shared_secret + ephemeral_shared_secret)


def box_aad(envelope: dict[str, Any]) -> bytes:
    """Authenticated metadata for encrypted chat/file-start envelopes."""
    aad = {
        "v": envelope["v"],
        "kind": envelope["kind"],
        "id": envelope["id"],
        "from": envelope["from"],
        "to": envelope["to"],
        "eph": envelope["eph"],
    }
    return compact_json(aad).encode("utf-8")


def encrypt_box(
    *,
    envelope_kind: str,
    payload: dict[str, Any],
    sender_private_key: x25519.X25519PrivateKey,
    sender_id: str,
    recipient_id: str,
) -> dict[str, Any]:
    """Encrypt a small JSON payload to a recipient public id."""
    if not is_valid_x25519_public_id(recipient_id):
        raise ValueError("recipient id is not a valid X25519 public id")

    recipient_public_key = public_key_from_id(recipient_id)
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_id = base64url_encode(public_key_bytes(ephemeral_private_key))

    static_shared_secret = sender_private_key.exchange(recipient_public_key)
    ephemeral_shared_secret = ephemeral_private_key.exchange(recipient_public_key)
    encryption_key = derive_box_key(
        static_shared_secret=static_shared_secret,
        ephemeral_shared_secret=ephemeral_shared_secret,
        envelope_kind=envelope_kind,
        sender_id=sender_id,
        recipient_id=recipient_id,
        ephemeral_id=ephemeral_id,
    )

    envelope = {
        "v": PROTOCOL_VERSION,
        "kind": envelope_kind,
        "id": uuid.uuid4().hex,
        "from": sender_id,
        "to": recipient_id,
        "eph": ephemeral_id,
        "nonce": "",
        "ciphertext": "",
    }
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(encryption_key).encrypt(
        nonce,
        compact_json(payload).encode("utf-8"),
        box_aad(envelope),
    )
    envelope["nonce"] = base64url_encode(nonce)
    envelope["ciphertext"] = base64url_encode(ciphertext)
    return envelope


def decrypt_box(
    *,
    envelope: dict[str, Any],
    recipient_private_key: x25519.X25519PrivateKey,
    local_public_id: str,
) -> dict[str, Any]:
    """Decrypt a chat or file-start envelope addressed to this client."""
    sender_id = envelope["from"]
    recipient_id = envelope["to"]
    ephemeral_id = envelope["eph"]
    envelope_kind = envelope["kind"]

    if recipient_id != local_public_id:
        raise ValueError("envelope is not addressed to this identity")
    if envelope.get("v") != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")

    sender_public_key = public_key_from_id(sender_id)
    ephemeral_public_key = public_key_from_id(ephemeral_id)

    static_shared_secret = recipient_private_key.exchange(sender_public_key)
    ephemeral_shared_secret = recipient_private_key.exchange(ephemeral_public_key)
    encryption_key = derive_box_key(
        static_shared_secret=static_shared_secret,
        ephemeral_shared_secret=ephemeral_shared_secret,
        envelope_kind=envelope_kind,
        sender_id=sender_id,
        recipient_id=recipient_id,
        ephemeral_id=ephemeral_id,
    )

    plaintext = ChaCha20Poly1305(encryption_key).decrypt(
        base64url_decode(envelope["nonce"]),
        base64url_decode(envelope["ciphertext"]),
        box_aad(envelope),
    )
    return json.loads(plaintext.decode("utf-8"))


def file_chunk_aad(*, sender_id: str, recipient_id: str, file_id: str, sequence_number: int) -> bytes:
    """Authenticated metadata for one encrypted file chunk."""
    return compact_json({
        "v": PROTOCOL_VERSION,
        "kind": "file_chunk",
        "from": sender_id,
        "to": recipient_id,
        "file_id": file_id,
        "seq": sequence_number,
    }).encode("utf-8")


def file_chunk_nonce(nonce_prefix: bytes, sequence_number: int) -> bytes:
    """Build a 96-bit nonce from a per-file random prefix and chunk sequence."""
    if len(nonce_prefix) != 4:
        raise ValueError("file nonce prefix must be 4 bytes")
    return nonce_prefix + sequence_number.to_bytes(8, "big")


def encrypt_file_chunk(
    *,
    file_key: bytes,
    nonce_prefix: bytes,
    sender_id: str,
    recipient_id: str,
    file_id: str,
    sequence_number: int,
    plaintext_chunk: bytes,
) -> dict[str, Any]:
    nonce = file_chunk_nonce(nonce_prefix, sequence_number)
    ciphertext = ChaCha20Poly1305(file_key).encrypt(
        nonce,
        plaintext_chunk,
        file_chunk_aad(
            sender_id=sender_id,
            recipient_id=recipient_id,
            file_id=file_id,
            sequence_number=sequence_number,
        ),
    )
    return {
        "v": PROTOCOL_VERSION,
        "kind": "file_chunk",
        "id": uuid.uuid4().hex,
        "from": sender_id,
        "to": recipient_id,
        "file_id": file_id,
        "seq": sequence_number,
        "nonce": base64url_encode(nonce),
        "ciphertext": base64url_encode(ciphertext),
    }


def decrypt_file_chunk(
    *,
    envelope: dict[str, Any],
    file_key: bytes,
    sender_id: str,
    recipient_id: str,
) -> bytes:
    file_id = envelope["file_id"]
    sequence_number = int(envelope["seq"])
    return ChaCha20Poly1305(file_key).decrypt(
        base64url_decode(envelope["nonce"]),
        base64url_decode(envelope["ciphertext"]),
        file_chunk_aad(
            sender_id=sender_id,
            recipient_id=recipient_id,
            file_id=file_id,
            sequence_number=sequence_number,
        ),
    )


def calculate_file_sha256_and_size(path: Path) -> tuple[str, int]:
    file_hash = hashlib.sha256()
    total_size = 0
    with path.open("rb") as file_handle:
        while True:
            block = file_handle.read(1024 * 1024)
            if not block:
                break
            total_size += len(block)
            file_hash.update(block)
    return file_hash.hexdigest(), total_size


async def read_file_chunk(file_handle: Any, chunk_size: int) -> bytes:
    return await asyncio.to_thread(file_handle.read, chunk_size)


async def append_bytes_to_file(path: Path, data: bytes) -> None:
    def write_block() -> None:
        with path.open("ab") as file_handle:
            file_handle.write(data)
    await asyncio.to_thread(write_block)


class OutboundMultiplexer:
    """Priority + round-robin outbound scheduler.

    Chat, acks, pings, and sync commands use urgent_queue. Every outgoing file
    gets its own bounded bulk stream queue. The TCP writer checks urgent
    frames first and then sends one chunk from each file stream in round-robin
    order, so several large files cannot monopolize the connection and chat
    messages can still pass quickly.
    """

    def __init__(self) -> None:
        self.urgent_queue: asyncio.Queue = asyncio.Queue(maxsize=URGENT_OUTBOX_LIMIT)
        self.bulk_queues: dict[str, asyncio.Queue] = {}
        self.bulk_stream_order: deque[str] = deque()
        self.bulk_available = asyncio.Event()
        self.lock = asyncio.Lock()

    async def put_urgent(self, frame: dict[str, Any] | None) -> None:
        await self.urgent_queue.put(frame)

    async def create_bulk_stream(self, stream_id: str) -> None:
        async with self.lock:
            if stream_id not in self.bulk_queues:
                self.bulk_queues[stream_id] = asyncio.Queue(maxsize=BULK_STREAM_QUEUE_LIMIT)
                self.bulk_stream_order.append(stream_id)

    async def put_bulk(self, stream_id: str, frame: dict[str, Any] | None) -> None:
        async with self.lock:
            queue = self.bulk_queues.get(stream_id)
        if queue is None:
            raise RuntimeError(f"bulk stream does not exist: {stream_id}")
        await queue.put(frame)
        self.bulk_available.set()

    async def finish_bulk_stream(self, stream_id: str) -> None:
        async with self.lock:
            queue = self.bulk_queues.get(stream_id)
        if queue is not None:
            await queue.put(None)
            self.bulk_available.set()

    async def next_frame(self) -> dict[str, Any] | None:
        """Return the next frame selected by priority and stream fairness."""
        while True:
            try:
                urgent_frame = self.urgent_queue.get_nowait()
                return urgent_frame
            except asyncio.QueueEmpty:
                pass

            bulk_frame = await self._try_get_next_bulk_frame()
            if bulk_frame is not _NO_BULK_FRAME:
                return bulk_frame

            urgent_task = asyncio.create_task(self.urgent_queue.get())
            bulk_task = asyncio.create_task(self.bulk_available.wait())
            done, pending = await asyncio.wait(
                {urgent_task, bulk_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()

            if urgent_task in done:
                return urgent_task.result()
            # A bulk stream became available; loop again so urgent frames that
            # arrived at the same time still win priority.

    async def _try_get_next_bulk_frame(self) -> Any:
        async with self.lock:
            streams_checked = len(self.bulk_stream_order)
            for _ in range(streams_checked):
                stream_id = self.bulk_stream_order.popleft()
                queue = self.bulk_queues.get(stream_id)
                if queue is None:
                    continue

                try:
                    frame = queue.get_nowait()
                except asyncio.QueueEmpty:
                    self.bulk_stream_order.append(stream_id)
                    continue

                if frame is None:
                    self.bulk_queues.pop(stream_id, None)
                    continue

                self.bulk_stream_order.append(stream_id)
                return frame

            if not any(not queue.empty() for queue in self.bulk_queues.values()):
                self.bulk_available.clear()
            return _NO_BULK_FRAME


_NO_BULK_FRAME = object()


@dataclass
class ReceivingFile:
    file_id: str
    sender_id: str
    filename: str
    destination_path: Path
    expected_size: int
    expected_sha256: str
    total_chunks: int
    file_key: bytes
    nonce_prefix: bytes
    next_expected_sequence: int = 0
    bytes_written: int = 0
    hasher: Any = field(default_factory=hashlib.sha256)
    pending_chunks: dict[int, bytes] = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    is_completed: bool = False


class FileReceiveManager:
    """Assembles encrypted file chunks and verifies final plaintext SHA-256."""

    def __init__(self, local_public_id: str):
        self.local_public_id = local_public_id
        self.active_files: dict[str, ReceivingFile] = {}
        self.completed_file_ids: set[str] = set()
        DOWNLOAD_DIRECTORY.mkdir(parents=True, exist_ok=True)

    async def start_file(self, *, sender_id: str, payload: dict[str, Any]) -> None:
        file_id = str(payload["file_id"])
        if file_id in self.completed_file_ids or file_id in self.active_files:
            return

        filename = safe_filename(str(payload.get("filename", "file.bin")))
        expected_size = int(payload["size"])
        expected_sha256 = str(payload["sha256"])
        total_chunks = int(payload["total_chunks"])
        file_key = base64url_decode(payload["file_key"])
        nonce_prefix = base64url_decode(payload["nonce_prefix"])

        if len(file_key) != 32:
            raise ValueError("invalid file key length")
        if len(nonce_prefix) != 4:
            raise ValueError("invalid file nonce prefix length")

        destination_path = unique_path(DOWNLOAD_DIRECTORY / f"{file_id[:12]}_{filename}")
        destination_path.write_bytes(b"")

        receiving_file = ReceivingFile(
            file_id=file_id,
            sender_id=sender_id,
            filename=filename,
            destination_path=destination_path,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            total_chunks=total_chunks,
            file_key=file_key,
            nonce_prefix=nonce_prefix,
        )
        self.active_files[file_id] = receiving_file
        print(f"\nReceiving file: {filename} -> {destination_path}")

        if total_chunks == 0:
            await self._finish_file_if_complete(receiving_file)
        pass

    async def handle_chunk(self, *, envelope: dict[str, Any]) -> None:
        file_id = envelope["file_id"]
        if file_id in self.completed_file_ids:
            return

        receiving_file = self.active_files.get(file_id)
        if receiving_file is None:
            # A malicious/broken server could deliver chunks before file_start.
            # The stored chunks can still be recovered later with /sync after the
            # file_start metadata is available.
            return

        sequence_number = int(envelope["seq"])
        plaintext_chunk = decrypt_file_chunk(
            envelope=envelope,
            file_key=receiving_file.file_key,
            sender_id=receiving_file.sender_id,
            recipient_id=self.local_public_id,
        )

        async with receiving_file.lock:
            if receiving_file.is_completed or sequence_number < receiving_file.next_expected_sequence:
                return
            receiving_file.pending_chunks[sequence_number] = plaintext_chunk

            while receiving_file.next_expected_sequence in receiving_file.pending_chunks:
                chunk = receiving_file.pending_chunks.pop(receiving_file.next_expected_sequence)
                await append_bytes_to_file(receiving_file.destination_path, chunk)
                receiving_file.hasher.update(chunk)
                receiving_file.bytes_written += len(chunk)
                receiving_file.next_expected_sequence += 1

                if (
                    receiving_file.next_expected_sequence % 64 == 0
                    or receiving_file.next_expected_sequence == receiving_file.total_chunks
                ):
                    print(f"Receiving file: {receiving_file.filename} {receiving_file.bytes_written}/{receiving_file.expected_size} bytes")
                    pass

            await self._finish_file_if_complete(receiving_file)

    async def _finish_file_if_complete(self, receiving_file: ReceivingFile) -> None:
        if receiving_file.is_completed:
            return
        if receiving_file.next_expected_sequence != receiving_file.total_chunks:
            return

        actual_sha256 = receiving_file.hasher.hexdigest()
        if receiving_file.bytes_written != receiving_file.expected_size:
            print(f"File size verification failed: {receiving_file.filename}: got {receiving_file.bytes_written}, expected {receiving_file.expected_size}")
        elif actual_sha256 != receiving_file.expected_sha256:
            print(f"File SHA-256 verification failed: {receiving_file.filename}")
            print(f"       got:      {actual_sha256}")
            print(f"       expected: {receiving_file.expected_sha256}")
        else:
            print(f"\nFile saved: {receiving_file.filename} -> {receiving_file.destination_path}")
            print(f"       sha256: {actual_sha256}")
            self.completed_file_ids.add(receiving_file.file_id)

        receiving_file.is_completed = True
        self.active_files.pop(receiving_file.file_id, None)
        pass


def strip_matching_outer_quotes(value: str) -> str:
    """Remove one pair of matching outer quotes from a path argument."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_file_path_arguments(argument_text: str) -> list[Path]:
    r"""Parse one or more file paths after /send, /file, or /files.

    Windows examples:
        /send C:\Users\me\a.txt D:\Downloads\b.zip
        /send "C:\Users\me\My File.txt" 'D:\Work\report.pdf'

    Linux/macOS examples:
        /send /tmp/a.txt ./b.zip
        /send "/home/me/My File.txt" './report final.pdf'
        /send ./escaped\ space.txt

    On Windows, shlex is used in non-POSIX mode so backslashes in paths are not
    treated as escape characters. On POSIX systems, shlex is used in POSIX mode
    so quoted paths and escaped spaces work naturally.
    """
    argument_text = argument_text.strip()
    if not argument_text:
        return []

    try:
        if os.name == "nt":
            raw_parts = shlex.split(argument_text, posix=False)
            string_paths = [strip_matching_outer_quotes(part) for part in raw_parts]
        else:
            string_paths = shlex.split(argument_text, posix=True)
    except ValueError as exc:
        raise ValueError(f"path parse error: {exc}") from exc

    paths: list[Path] = []
    for item in string_paths:
        item = strip_matching_outer_quotes(item.strip())
        if not item:
            continue
        paths.append(Path(os.path.expandvars(item)))
    return paths


class ChatClient:
    """Interactive E2EE client with one default peer chosen at startup."""

    def __init__(
        self,
        *,
        server_host: str,
        server_port: int,
        proxy_config: Socks5ProxyConfig | None,
        identity_path: Path,
        default_peer_public_id: str,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.proxy_config = proxy_config
        self.identity_path = identity_path
        self.private_key, self.local_public_id = load_or_create_identity(identity_path)
        self.default_peer_public_id = default_peer_public_id
        self.outbox = OutboundMultiplexer()
        self.file_tasks: set[asyncio.Task] = set()
        self.seen_message_ids: deque[str] = deque()
        self.seen_message_id_set: set[str] = set()
        self.file_receiver = FileReceiveManager(self.local_public_id)
        # Highest server_id seen for each peer. This lets the automatic sync loop
        # ask only for newer persisted envelopes instead of re-downloading history.
        self.last_server_id_by_peer: dict[str, int] = {}
        # request_id -> sync metadata. Used to suppress noisy periodic sync output
        # and to continue paginated sync requests automatically.
        self.sync_requests: dict[str, dict[str, Any]] = {}
        self.stop_event = asyncio.Event()

    async def run(self) -> None:
        print("Default peer is set.")
        print("Sent messages show as >>>; received messages show as <<<. History sync is automatic. Use /send, /file, or /files to send files.")

        reader, writer = await open_tcp_connection(
            self.server_host,
            self.server_port,
            self.proxy_config,
        )
        try:
            await write_tcp_frame(writer, {"type": "hello", "id": self.local_public_id})

            tasks = [
                asyncio.create_task(self.outbound_sender(writer), name="outbound-sender"),
                asyncio.create_task(self.receiver_loop(reader), name="receiver"),
                asyncio.create_task(self.input_loop(), name="input"),
                asyncio.create_task(self.auto_sync_loop(), name="auto-sync"),
            ]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            self.stop_event.set()
            await self.outbox.put_urgent(None)
            for task in pending:
                task.cancel()
            for task in self.file_tasks:
                task.cancel()
            for task in done:
                exception = task.exception()
                if exception is not None:
                    raise exception
        finally:
            writer.close()
            await writer.wait_closed()

    async def outbound_sender(self, writer: asyncio.StreamWriter) -> None:
        """Serialize frames from the multiplexer to the TCP connection."""
        try:
            while not self.stop_event.is_set():
                frame = await self.outbox.next_frame()
                if frame is None:
                    return
                await write_tcp_frame(writer, frame)
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
            return

    async def receiver_loop(self, reader: asyncio.StreamReader) -> None:
        """Read server frames continuously; individual handlers run independently."""
        try:
            while not self.stop_event.is_set():
                raw_frame = await read_tcp_frame(reader)
                try:
                    frame = json.loads(raw_frame)
                except Exception as exc:
                    print(f"\n[error] invalid server json: {exc}")
                    pass
                    continue
                asyncio.create_task(self.handle_server_frame(frame))
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
            print("\n[network] disconnected from server")
            pass
            return
        except asyncio.CancelledError:
            raise

    async def handle_server_frame(self, frame: dict[str, Any]) -> None:
        frame_type = frame.get("type")
        try:
            if frame_type == "hello_ok":
                # Startup sync is intentionally silent. It updates local sync state
                # without replaying the entire historical chat into the terminal.
                await self.request_conversation_sync(
                    self.default_peer_public_id,
                    after_server_id=self.last_server_id_by_peer.get(self.default_peer_public_id, 0),
                    silent=True,
                )
            elif frame_type == "ack":
                self.update_known_server_id_from_ack(frame)
                # ACKs are intentionally silent to keep the chat view clean.
            elif frame_type == "message":
                await self.handle_incoming_message(frame)
            elif frame_type == "sync_begin":
                # Sync progress is intentionally silent in the chat view.
                pass
            elif frame_type == "sync_end":
                await self.handle_sync_end(frame)
            elif frame_type == "error":
                print(f"\nServer error: {frame.get('error')}")
                pass
            elif frame_type == "pong":
                print("pong")
                pass
        except Exception as exc:
            pass
            pass

    @staticmethod
    def parse_optional_int(value: Any, *, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return default

    def update_known_server_id_for_peer(self, peer_public_id: str, server_id: int) -> None:
        """Remember the newest persisted server_id for one conversation."""
        if not is_valid_x25519_public_id(peer_public_id) or server_id <= 0:
            return
        current_server_id = self.last_server_id_by_peer.get(peer_public_id, 0)
        if server_id > current_server_id:
            self.last_server_id_by_peer[peer_public_id] = server_id

    def update_known_server_id_from_ack(self, frame: dict[str, Any]) -> None:
        """Track server ids for messages that this client just sent."""
        server_id = self.parse_optional_int(frame.get("server_id"), default=0)
        peer_id = frame.get("peer_id")
        recipient_id = frame.get("to")

        if isinstance(peer_id, str) and is_valid_x25519_public_id(peer_id):
            self.update_known_server_id_for_peer(peer_id, server_id)
        elif isinstance(recipient_id, str) and is_valid_x25519_public_id(recipient_id):
            self.update_known_server_id_for_peer(recipient_id, server_id)

    def update_known_server_id_from_message(self, frame: dict[str, Any]) -> None:
        """Track server ids for live or synced messages involving this client."""
        server_id = self.parse_optional_int(frame.get("server_id"), default=0)
        sender_id = frame.get("from")
        recipient_id = frame.get("to")
        conversation_peer_id = frame.get("conversation_peer_id")

        if frame.get("copy_role") == "self_copy" and isinstance(conversation_peer_id, str):
            self.update_known_server_id_for_peer(conversation_peer_id, server_id)
        elif sender_id == self.local_public_id and isinstance(recipient_id, str) and recipient_id != self.local_public_id:
            self.update_known_server_id_for_peer(recipient_id, server_id)
        elif recipient_id == self.local_public_id and isinstance(sender_id, str) and sender_id != self.local_public_id:
            self.update_known_server_id_for_peer(sender_id, server_id)

    async def handle_sync_end(self, frame: dict[str, Any]) -> None:
        """Finish a sync page and automatically request the next page if needed."""
        request_id = str(frame.get("request_id"))
        request_state = self.sync_requests.pop(request_id, {})
        is_silent = bool(request_state.get("silent"))
        count = self.parse_optional_int(frame.get("count"), default=0)
        last_server_id = self.parse_optional_int(frame.get("last_server_id"), default=0)
        has_more = bool(frame.get("has_more"))

        if not is_silent or count > 0:
            pass
            pass

        # When history is larger than the server's page limit, keep syncing until
        # there are no more rows. This makes the startup sync more reliable.
        if has_more and last_server_id > 0:
            if request_state.get("kind") == "conversation":
                peer_public_id = str(request_state.get("peer_public_id", self.default_peer_public_id))
                await self.request_conversation_sync(
                    peer_public_id,
                    after_server_id=last_server_id,
                    silent=is_silent,
                )
            elif request_state.get("kind") == "all":
                await self.request_all_sync(after_server_id=last_server_id, silent=is_silent)

    async def auto_sync_loop(self) -> None:
        """Periodically pull newer persisted messages for the current default peer."""
        while not self.stop_event.is_set():
            try:
                await asyncio.sleep(AUTO_SYNC_INTERVAL_SECONDS)
                peer_public_id = self.default_peer_public_id
                after_server_id = self.last_server_id_by_peer.get(peer_public_id, 0)
                await self.request_conversation_sync(
                    peer_public_id,
                    after_server_id=after_server_id,
                    silent=True,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                pass
                pass

    async def handle_incoming_message(self, frame: dict[str, Any]) -> None:
        self.update_known_server_id_from_message(frame)
        envelope = frame["envelope"]
        message_id = envelope.get("id")
        if not isinstance(message_id, str):
            return
        if self.has_seen_message_id(message_id):
            return
        self.remember_message_id(message_id)

        envelope_kind = envelope.get("kind")
        if envelope_kind == "chat":
            # Ignore legacy outgoing delivery envelopes that were encrypted only
            # to the peer. New v9 self-copy envelopes are addressed to this
            # identity and can always be decrypted after sync.
            if envelope.get("to") != self.local_public_id:
                return

            payload = decrypt_box(
                envelope=envelope,
                recipient_private_key=self.private_key,
                local_public_id=self.local_public_id,
            )
            message_text = str(payload.get("text", ""))

            if frame.get("copy_role") == "self_copy":
                print(f">>> {message_text}")
            else:
                print(f"<<< {message_text}")
        elif envelope_kind == "file_start":
            if envelope.get("to") != self.local_public_id:
                return
            payload = decrypt_box(
                envelope=envelope,
                recipient_private_key=self.private_key,
                local_public_id=self.local_public_id,
            )
            await self.file_receiver.start_file(sender_id=envelope["from"], payload=payload)
        elif envelope_kind == "file_chunk":
            if envelope.get("to") != self.local_public_id:
                return
            await self.file_receiver.handle_chunk(envelope=envelope)

    def has_seen_message_id(self, message_id: str) -> bool:
        return message_id in self.seen_message_id_set

    def remember_message_id(self, message_id: str) -> None:
        self.seen_message_ids.append(message_id)
        self.seen_message_id_set.add(message_id)
        while len(self.seen_message_ids) > MAX_TRACKED_MESSAGE_IDS:
            old_message_id = self.seen_message_ids.popleft()
            self.seen_message_id_set.discard(old_message_id)

    async def input_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                command_line = await asyncio.to_thread(input, ">>> ")
            except EOFError:
                self.stop_event.set()
                return
            command_line = command_line.strip()
            if command_line:
                await self.handle_command(command_line)

    def print_help(self) -> None:
        print("Usage:")
        print("  Type plain text                 Send a chat message; displayed as >>> text")
        print("  /send <path1> [path2 ...]       Send one or more files")
        print("  /file <path1> [path2 ...]       Send one or more files")
        print("  /files <path1> [path2 ...]      Send one or more files")
        print("  /to <peer-public-key/Base58>    Switch the default peer")
        print("  /id                            Show your Base58 public key")
        print("  /fingerprint                   Show your public-key fingerprint")
        print("  /peerfp                        Show current peer fingerprint")
        print("  /sync                          Sync the current conversation")
        print("  /quit                          Exit")
        print("Path examples:")
        print("  /send ./a.txt ./b.zip")
        print("  /file \"C:\\Users\\me\\My File.txt\" '/tmp/report final.pdf'")

    async def request_conversation_sync(
        self,
        peer_public_id: str,
        after_server_id: int = 0,
        *,
        silent: bool = False,
    ) -> None:
        """Request persisted history with the current peer.

        The server sends a bounded page of encrypted envelopes. If the page is
        full, handle_sync_end automatically requests the next page.
        """
        request_id = uuid.uuid4().hex
        self.sync_requests[request_id] = {
            "kind": "conversation",
            "peer_public_id": peer_public_id,
            "silent": silent,
        }
        await self.outbox.put_urgent({
            "type": "sync_conversation",
            "peer_id": peer_public_id,
            "after_server_id": after_server_id,
            "limit": 5000,
            "request_id": request_id,
        })

    async def request_all_sync(self, after_server_id: int = 0, *, silent: bool = False) -> None:
        """Request all persisted envelopes involving this identity."""
        request_id = uuid.uuid4().hex
        self.sync_requests[request_id] = {"kind": "all", "silent": silent}
        await self.outbox.put_urgent({
            "type": "sync_all",
            "after_server_id": after_server_id,
            "limit": 5000,
            "request_id": request_id,
        })

    async def handle_command(self, command_line: str) -> None:
        if command_line in {"/help", "help"}:
            self.print_help()
            return
        if command_line == "/quit":
            self.stop_event.set()
            await self.outbox.put_urgent(None)
            return
        if command_line == "/id":
            print(public_id_to_base58(self.local_public_id))
            return
        if command_line == "/fingerprint":
            print(fingerprint_for_public_id(self.local_public_id))
            return
        if command_line == "/peerfp":
            print(fingerprint_for_public_id(self.default_peer_public_id))
            return
        if command_line.startswith("/peerfp "):
            _, peer_public_id = command_line.split(" ", 1)
            peer_public_id = normalize_public_id(peer_public_id.strip())
            if not is_valid_x25519_public_id(peer_public_id):
                print("invalid peer public id")
                return
            print(fingerprint_for_public_id(peer_public_id))
            return
        if command_line.startswith("/to "):
            _, peer_public_id = command_line.split(" ", 1)
            peer_public_id = normalize_public_id(peer_public_id.strip())
            if not is_valid_x25519_public_id(peer_public_id):
                print("invalid peer public id")
                return
            self.default_peer_public_id = peer_public_id
            print("Default peer changed.")
            await self.request_conversation_sync(peer_public_id, after_server_id=0, silent=True)
            return
        if command_line == "/ping":
            await self.outbox.put_urgent({"type": "ping"})
            return
        if command_line.startswith("/sync-all"):
            parts = shlex.split(command_line)
            after_server_id = int(parts[1]) if len(parts) > 1 else 0
            await self.request_all_sync(after_server_id=after_server_id, silent=True)
            return
        if command_line.startswith("/sync"):
            parts = shlex.split(command_line)
            if len(parts) > 2:
                print("usage: /sync [after_server_id]")
                return
            after_server_id = int(parts[1]) if len(parts) == 2 else 0
            await self.request_conversation_sync(self.default_peer_public_id, after_server_id=after_server_id, silent=True)
            return
        if command_line == "/send" or command_line.startswith("/send "):
            await self.handle_file_send_command("/send", command_line[len("/send"):].strip())
            return
        if command_line == "/file" or command_line.startswith("/file "):
            await self.handle_file_send_command("/file", command_line[len("/file"):].strip())
            return
        if command_line == "/files" or command_line.startswith("/files "):
            await self.handle_file_send_command("/files", command_line[len("/files"):].strip())
            return
        if not command_line.startswith("/"):
            await self.send_chat_message(self.default_peer_public_id, command_line)
            return
        print("unknown command; type /help")

    async def handle_file_send_command(self, command_name: str, argument_text: str) -> None:
        """Start one or more asynchronous file transfers.

        /send, /file, and /files are file-transfer aliases. Plain input without
        a slash is the chat-message path.
        """
        try:
            file_paths = parse_file_path_arguments(argument_text)
        except ValueError as exc:
            print(str(exc))
            return

        if not file_paths:
            print(f"usage: {command_name} <path1> [path2 ...]")
            return

        for file_path in file_paths:
            self.start_file_send_task(self.default_peer_public_id, file_path)

    async def send_chat_message(self, peer_public_id: str, message_text: str) -> None:
        payload = {
            "kind": "chat",
            "text": message_text,
            "created_at_ms": current_time_ms(),
        }
        delivery_envelope = encrypt_box(
            envelope_kind="chat",
            payload=payload,
            sender_private_key=self.private_key,
            sender_id=self.local_public_id,
            recipient_id=peer_public_id,
        )
        self_copy_envelope = encrypt_box(
            envelope_kind="chat",
            payload=payload,
            sender_private_key=self.private_key,
            sender_id=self.local_public_id,
            recipient_id=self.local_public_id,
        )

        # The delivery copy is for the peer. The self copy is for this sender's
        # future sync and is encrypted to this sender's own identity key.
        await self.outbox.put_urgent({"type": "send", "to": peer_public_id, "envelope": delivery_envelope})
        await self.outbox.put_urgent({
            "type": "send_self_copy",
            "peer_id": peer_public_id,
            "envelope": self_copy_envelope,
        })

        # Avoid showing this same self-copy again if an immediate sync returns it
        # during the current process lifetime.
        self.remember_message_id(str(self_copy_envelope["id"]))
        #print(f">>> {message_text}")

    def start_file_send_task(self, peer_public_id: str, file_path: Path) -> None:
        task = asyncio.create_task(self.send_file(peer_public_id, file_path))
        self.file_tasks.add(task)
        task.add_done_callback(self.file_tasks.discard)

    async def send_file(self, peer_public_id: str, file_path: Path) -> None:
        file_id: str | None = None
        try:
            file_path = Path(os.path.expandvars(str(file_path))).expanduser().resolve()
            if not file_path.exists() or not file_path.is_file():
                print(f"File not found: {file_path}")
                pass
                return
            if not is_valid_x25519_public_id(peer_public_id):
                print("invalid peer public id")
                return

            print(f"Preparing file: {file_path.name}")
            pass
            file_sha256, file_size = await asyncio.to_thread(calculate_file_sha256_and_size, file_path)
            total_chunks = math.ceil(file_size / CHUNK_SIZE) if file_size else 0
            file_id = uuid.uuid4().hex
            delivery_file_key = ChaCha20Poly1305.generate_key()
            delivery_nonce_prefix = os.urandom(4)
            self_copy_file_key = ChaCha20Poly1305.generate_key()
            self_copy_nonce_prefix = os.urandom(4)

            await self.outbox.create_bulk_stream(file_id)

            file_start_payload = {
                "kind": "file_start",
                "file_id": file_id,
                "filename": file_path.name,
                "size": file_size,
                "sha256": file_sha256,
                "chunk_size": CHUNK_SIZE,
                "total_chunks": total_chunks,
                "file_key": base64url_encode(delivery_file_key),
                "nonce_prefix": base64url_encode(delivery_nonce_prefix),
                "created_at_ms": current_time_ms(),
            }
            file_start_envelope = encrypt_box(
                envelope_kind="file_start",
                payload=file_start_payload,
                sender_private_key=self.private_key,
                sender_id=self.local_public_id,
                recipient_id=peer_public_id,
            )

            self_copy_file_start_payload = dict(file_start_payload)
            self_copy_file_start_payload["file_key"] = base64url_encode(self_copy_file_key)
            self_copy_file_start_payload["nonce_prefix"] = base64url_encode(self_copy_nonce_prefix)
            self_copy_file_start_envelope = encrypt_box(
                envelope_kind="file_start",
                payload=self_copy_file_start_payload,
                sender_private_key=self.private_key,
                sender_id=self.local_public_id,
                recipient_id=self.local_public_id,
            )

            await self.outbox.put_urgent({"type": "send", "to": peer_public_id, "envelope": file_start_envelope})
            await self.outbox.put_urgent({
                "type": "send_self_copy",
                "peer_id": peer_public_id,
                "envelope": self_copy_file_start_envelope,
            })
            self.remember_message_id(str(self_copy_file_start_envelope["id"]))

            queued_bytes = 0
            sequence_number = 0
            with file_path.open("rb") as file_handle:
                while True:
                    plaintext_chunk = await read_file_chunk(file_handle, CHUNK_SIZE)
                    if not plaintext_chunk:
                        break
                    file_chunk_envelope = encrypt_file_chunk(
                        file_key=delivery_file_key,
                        nonce_prefix=delivery_nonce_prefix,
                        sender_id=self.local_public_id,
                        recipient_id=peer_public_id,
                        file_id=file_id,
                        sequence_number=sequence_number,
                        plaintext_chunk=plaintext_chunk,
                    )
                    self_copy_file_chunk_envelope = encrypt_file_chunk(
                        file_key=self_copy_file_key,
                        nonce_prefix=self_copy_nonce_prefix,
                        sender_id=self.local_public_id,
                        recipient_id=self.local_public_id,
                        file_id=file_id,
                        sequence_number=sequence_number,
                        plaintext_chunk=plaintext_chunk,
                    )
                    await self.outbox.put_bulk(
                        file_id,
                        {"type": "send", "to": peer_public_id, "envelope": file_chunk_envelope},
                    )
                    await self.outbox.put_bulk(
                        file_id,
                        {
                            "type": "send_self_copy",
                            "peer_id": peer_public_id,
                            "envelope": self_copy_file_chunk_envelope,
                        },
                    )
                    self.remember_message_id(str(self_copy_file_chunk_envelope["id"]))
                    queued_bytes += len(plaintext_chunk)
                    sequence_number += 1

                    if sequence_number % 64 == 0 or queued_bytes == file_size:
                        print(f"Queued file data: {file_path.name} {queued_bytes}/{file_size} bytes")
                        pass

            print(f"File queued for sending: {file_path.name}")
            pass

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"File send failed: {file_path}: {exc}")
            pass
        finally:
            if file_id is not None:
                await self.outbox.finish_bulk_stream(file_id)


def parse_socks5_proxy_config(raw_proxy_value: str) -> Socks5ProxyConfig | None:
    """Parse an optional SOCKS5 proxy setting.

    Supported forms:
        - empty string: no proxy
        - host:port
        - socks5://host:port
        - socks5://username:password@host:port
    """
    raw_proxy_value = raw_proxy_value.strip()
    if not raw_proxy_value:
        return None

    if "://" not in raw_proxy_value:
        raw_proxy_value = "socks5://" + raw_proxy_value

    parsed = urlparse(raw_proxy_value)
    if parsed.scheme.lower() != "socks5":
        raise ValueError("proxy must be empty, host:port, or socks5://host:port")
    if not parsed.hostname or not parsed.port:
        raise ValueError("proxy must include host and port")

    username = unquote(parsed.username) if parsed.username else None
    password = unquote(parsed.password) if parsed.password else None
    if username is None:
        username_input = input("SOCKS5 username, optional: ").strip()
        password_input = input("SOCKS5 password, optional: ").strip() if username_input else ""
        username = username_input or None
        password = password_input or None

    return Socks5ProxyConfig(
        host=parsed.hostname,
        port=int(parsed.port),
        username=username,
        password=password,
    )


def prompt_peer_public_id() -> str:
    """Ask for the default recipient public id.

    Users may paste either the new Base58 display form or the older base64url
    public id. The returned value is always normalized to the internal base64url
    id used by the server and protocol frames.
    """
    while True:
        peer_public_id = normalize_public_id(input("Peer public key/Base58: ").strip())
        if is_valid_x25519_public_id(peer_public_id):
            return peer_public_id
        print("Invalid public key. Enter a 32-byte X25519 public key in Base58 or legacy base64url form.")


def prompt_startup_config() -> tuple[Path, str, int, Socks5ProxyConfig | None, str]:
    """Collect only the normal user-facing startup settings."""
    server_host = prompt_line("Server address", "127.0.0.1")
    while server_host.startswith("tcp://"):
        server_host = server_host.removeprefix("tcp://")
    server_port_text = prompt_line("Server port", "8765")
    try:
        server_port = int(server_port_text)
    except ValueError:
        raise ValueError("Server port must be an integer")

    peer_public_id = prompt_peer_public_id()

    raw_proxy_value = input("Optional SOCKS5 TCP proxy, leave empty for direct connection, e.g. 127.0.0.1:1080: ").strip()
    proxy_config = parse_socks5_proxy_config(raw_proxy_value)

    identity_path = Path("identity.json")
    if proxy_config:
        print(f"Using SOCKS5 proxy: {proxy_config.host}:{proxy_config.port}")
    else:
        pass
    return identity_path, server_host, server_port, proxy_config, peer_public_id


async def main() -> None:
    # Load or create the local identity immediately, before asking for server
    # address, port, peer public key, or proxy settings. This makes passive
    # receiving easier because the user can copy their public key right away.
    identity_path = Path("identity.json")
    startup_private_key, startup_public_id = load_or_create_identity(identity_path)
    print_local_identity(startup_private_key, startup_public_id)

    configured_identity_path, server_host, server_port, proxy_config, peer_public_id = prompt_startup_config()
    chat_client = ChatClient(
        server_host=server_host,
        server_port=server_port,
        proxy_config=proxy_config,
        identity_path=configured_identity_path,
        default_peer_public_id=peer_public_id,
    )
    await chat_client.run()


if __name__ == "__main__":
    asyncio.run(main())
