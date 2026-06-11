#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
x25519 Relay GUI Client
=======================

This is a single-file PyQt6 desktop client for the x25519-relay encrypted chat
prototype. It keeps the same wire protocol as the working command-line client
and relay server:

    4-byte big-endian length prefix || compact UTF-8 JSON frame

Application messages are end-to-end encrypted before they are sent to the relay.
The relay stores and forwards opaque encrypted envelopes only. The server can see
routing metadata such as sender public id, recipient public id, timestamps, frame
sizes, and encrypted file-chunk counts, but it cannot read chat text, file names,
file hashes, file keys, or file bytes.

Major responsibilities in this file:

    1. Identity management
       - Load, create, import, export, and display X25519 identities.
       - The identity private key stays local and is never sent to the server.

    2. Wire protocol compatibility
       - Send hello, send, send_self_copy, sync_conversation, sync_all, and ping
         frames using the same protocol version and frame format as client.py.
       - Receive ack, message, sync_begin, sync_end, error, and pong frames.

    3. End-to-end encryption
       - Use X25519 static and ephemeral key agreement, HKDF-SHA256, and
         ChaCha20-Poly1305 for chat and file-start envelopes.
       - Use per-file symmetric keys for encrypted file chunks.

    4. Local persistence
       - Store identities, contacts, conversations, message records, attachment
         indexes, and sync checkpoints in a local SQLite database.
       - Treat SQLite as the source of truth for local history. Runtime caches
         are only optimization helpers and must not override database state.

    5. Graphical user interface
       - Provide a contact list, message view, composer, file sending, manual
         sync, contact details, contact deletion, key copying, and chat-history
         export.

    6. Chat-history export
       - Export locally stored chat history to a clear UTF-8 text file.
       - Include message timestamps, direction, message status, errors, and file
         metadata.
       - Do not export attachment binary contents. File messages are represented
         by readable metadata such as file id, file name, size, SHA-256, chunk
         progress, and local status.

Maintenance notes:

    - Keep protocol constants and envelope formats synchronized with server.py
      and the known-good command-line client.py.
    - Do not update sync checkpoints merely because an ack or sync_end frame was
      received. A checkpoint should advance only after a message frame has been
      successfully processed and saved locally.
    - When deleting local conversation history or forcing a full resync, clear
      runtime message-id deduplication caches so that server-returned historical
      envelopes can be processed again.
    - Prefer descriptive English identifiers. Short names are used only for
      conventional ignored values or very narrow local scopes.

Dependencies:

    pip install -U PyQt6 cryptography

Run:

    python GUI_client_export_clean.py
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
import re
import signal
import sqlite3
import sys
import threading
import time
import uuid
from collections import deque
from concurrent.futures import Future
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse

from PyQt6.QtCore import (
    QAbstractListModel,
    QItemSelection,
    QModelIndex,
    QObject,
    QPoint,
    QRect,
    QRectF,
    QSize,
    Qt,
    QUrl,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QAction,
    QClipboard,
    QColor,
    QDesktopServices,
    QFont,
    QFontMetrics,
    QKeyEvent,
    QPainter,
    QPainterPath,
    QPen,
)
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListView,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSlider,
    QSpinBox,
    QSplitter,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF



# ===== Application paths =====

import os
from pathlib import Path

APP_DIR_NAME = "x25519-relay-gui"


def user_data_dir() -> Path:
    if os.name == "nt":
        base = Path(os.getenv("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys_platform_is_macos():
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    path = base / APP_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def sys_platform_is_macos() -> bool:
    import sys

    return sys.platform == "darwin"


def default_database_path() -> Path:
    return user_data_dir() / "client.sqlite3"


def default_download_dir() -> Path:
    path = user_data_dir() / "downloads"
    path.mkdir(parents=True, exist_ok=True)
    return path


# ===== Cryptographic primitives and envelope helpers =====

import base64
import hashlib
import json
import math
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = 4
CHUNK_SIZE = 64 * 1024

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_ALPHABET_INDEX = {char: index for index, char in enumerate(BASE58_ALPHABET)}


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def current_time_ms() -> int:
    return int(time.time() * 1000)


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def base58_encode(data: bytes) -> str:
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


def is_valid_x25519_public_id(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(base64url_decode(value)) == 32
    except Exception:
        return False


def normalize_public_id(public_id_text: str) -> str:
    """Accept Base58 display id or legacy base64url id and return base64url id."""
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


def public_id_to_base58(public_id: str) -> str:
    return base58_encode(base64url_decode(public_id))


def private_key_bytes(private_key: x25519.X25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_bytes(private_key: x25519.X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_to_base58(private_key: x25519.X25519PrivateKey) -> str:
    return base58_encode(private_key_bytes(private_key))


def private_key_from_base58(value: str) -> x25519.X25519PrivateKey:
    raw_value = base58_decode(value.strip())
    if len(raw_value) != 32:
        raise ValueError("private key must decode to 32 bytes")
    return x25519.X25519PrivateKey.from_private_bytes(raw_value)


def private_key_from_base64url(value: str) -> x25519.X25519PrivateKey:
    raw_value = base64url_decode(value.strip())
    if len(raw_value) != 32:
        raise ValueError("private key must decode to 32 bytes")
    return x25519.X25519PrivateKey.from_private_bytes(raw_value)


def public_key_from_id(public_id: str) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(base64url_decode(public_id))


def fingerprint_for_public_id(public_id: str) -> str:
    digest = hashlib.sha256(base64url_decode(public_id)).hexdigest()
    return ":".join(digest[index : index + 4] for index in range(0, 32, 4))


def safe_filename(filename: str) -> str:
    filename = Path(filename).name
    filename = re.sub(r"[^A-Za-z0-9._()\-\u4e00-\u9fff]+", "_", filename).strip("._")
    return filename or "file.bin"


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    for index in range(1, 100000):
        candidate = path.with_name(f"{stem}_{index}{suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError("too many duplicate filenames")


@dataclass(frozen=True)
class Identity:
    private_key: x25519.X25519PrivateKey
    public_id: str

    @property
    def private_key_b64(self) -> str:
        return base64url_encode(private_key_bytes(self.private_key))

    @property
    def private_key_base58(self) -> str:
        return private_key_to_base58(self.private_key)

    @property
    def public_base58(self) -> str:
        return public_id_to_base58(self.public_id)

    @property
    def fingerprint(self) -> str:
        return fingerprint_for_public_id(self.public_id)



def create_identity() -> Identity:
    private_key = x25519.X25519PrivateKey.generate()
    return Identity(private_key=private_key, public_id=base64url_encode(public_key_bytes(private_key)))


def identity_from_private_key(private_key: x25519.X25519PrivateKey) -> Identity:
    return Identity(private_key=private_key, public_id=base64url_encode(public_key_bytes(private_key)))


def load_identity_json(path: Path) -> Identity:
    data = json.loads(path.read_text(encoding="utf-8"))
    private_key = private_key_from_base64url(str(data["private_key"]))
    identity = identity_from_private_key(private_key)
    if data.get("public_id") and data["public_id"] != identity.public_id:
        raise ValueError("identity file public_id does not match private key")
    return identity


def save_identity_json(path: Path, identity: Identity) -> None:
    data = {
        "type": "x25519-identity-v4",
        "public_id": identity.public_id,
        "private_key": identity.private_key_b64,
        "created_at_ms": current_time_ms(),
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def derive_box_key(
    *,
    static_shared_secret: bytes,
    ephemeral_shared_secret: bytes,
    envelope_kind: str,
    sender_id: str,
    recipient_id: str,
    ephemeral_id: str,
) -> bytes:
    hkdf_info = compact_json(
        {
            "protocol": "e2ee-x25519-chacha20poly1305-v4",
            "envelope_kind": envelope_kind,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "ephemeral_id": ephemeral_id,
        }
    ).encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=hkdf_info,
    ).derive(static_shared_secret + ephemeral_shared_secret)


def box_aad(envelope: dict[str, Any]) -> bytes:
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
    return compact_json(
        {
            "v": PROTOCOL_VERSION,
            "kind": "file_chunk",
            "from": sender_id,
            "to": recipient_id,
            "file_id": file_id,
            "seq": sequence_number,
        }
    ).encode("utf-8")


def file_chunk_nonce(nonce_prefix: bytes, sequence_number: int) -> bytes:
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
    file_id = str(envelope["file_id"])
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


def total_chunks_for_size(size: int) -> int:
    return math.ceil(size / CHUNK_SIZE) if size else 0


# ===== core/framing.py =====

import asyncio
import json
from typing import Any


MAX_TCP_FRAME_SIZE = 2 * 1024 * 1024
TCP_CONNECT_TIMEOUT_SECONDS = 20.0
TCP_FRAME_HEADER_SIZE = 4


async def write_tcp_frame(
    writer: asyncio.StreamWriter,
    frame: dict[str, Any],
    *,
    max_frame_size: int = MAX_TCP_FRAME_SIZE,
) -> None:
    payload = compact_json(frame).encode("utf-8")
    if len(payload) > max_frame_size:
        raise ValueError(f"TCP frame too large: {len(payload)} > {max_frame_size}")
    writer.write(len(payload).to_bytes(TCP_FRAME_HEADER_SIZE, "big") + payload)
    await writer.drain()


async def read_tcp_frame(
    reader: asyncio.StreamReader,
    *,
    max_frame_size: int = MAX_TCP_FRAME_SIZE,
) -> dict[str, Any]:
    header = await reader.readexactly(TCP_FRAME_HEADER_SIZE)
    payload_length = int.from_bytes(header, "big")
    if payload_length <= 0:
        raise ValueError("empty TCP frame is not allowed")
    if payload_length > max_frame_size:
        raise ValueError(f"TCP frame too large: {payload_length} > {max_frame_size}")
    payload = await reader.readexactly(payload_length)
    return json.loads(payload.decode("utf-8"))


# ===== core/socks5.py =====

import asyncio
from dataclasses import dataclass
from urllib.parse import unquote, urlparse



@dataclass(frozen=True)
class Socks5ProxyConfig:
    host: str
    port: int
    username: str | None = None
    password: str | None = None


def parse_socks5_proxy_config(raw_proxy_value: str) -> Socks5ProxyConfig | None:
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
    return Socks5ProxyConfig(
        host=parsed.hostname,
        port=int(parsed.port),
        username=unquote(parsed.username) if parsed.username else None,
        password=unquote(parsed.password) if parsed.password else None,
    )


async def open_tcp_connection(
    host: str,
    port: int,
    proxy_config: Socks5ProxyConfig | None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
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


# ===== storage/database.py =====

import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable



@dataclass(frozen=True)
class IdentityRecord:
    public_id: str
    public_base58: str
    private_key_b64: str
    fingerprint: str
    label: str
    created_at_ms: int
    last_used_at_ms: int | None


@dataclass(frozen=True)
class ContactRecord:
    peer_public_id: str
    peer_base58: str
    fingerprint: str
    alias: str
    verified: bool
    pinned: bool
    blocked: bool


class ConversationRecord:
    """Lightweight conversation row.

    This is intentionally not a frozen dataclass. A few PyQt/Python builds can produce
    hard-to-diagnose recursion while resetting models that hold dataclass records as
    UserRole payloads. Keeping this as a tiny slots object avoids that path and also
    makes the model payload cheaper.
    """

    __slots__ = (
        "peer_public_id",
        "display_name",
        "peer_base58",
        "fingerprint",
        "last_message_preview",
        "last_message_at_ms",
        "unread_count",
        "pinned",
        "verified",
    )

    def __init__(
        self,
        peer_public_id: str,
        display_name: str,
        peer_base58: str,
        fingerprint: str,
        last_message_preview: str | None,
        last_message_at_ms: int | None,
        unread_count: int,
        pinned: bool,
        verified: bool = False,
    ) -> None:
        self.peer_public_id = peer_public_id
        self.display_name = display_name
        self.peer_base58 = peer_base58
        self.fingerprint = fingerprint
        self.last_message_preview = last_message_preview or ""
        self.last_message_at_ms = last_message_at_ms
        self.unread_count = unread_count
        self.pinned = pinned
        self.verified = verified


@dataclass(frozen=True)
class MessageRecord:
    envelope_id: str
    peer_public_id: str
    direction: str
    kind: str
    text: str
    status: str
    created_at_ms: int | None
    server_id: int | None
    error: str | None


@dataclass(frozen=True)
class AttachmentRecord:
    identity_public_id: str
    file_id: str
    peer_public_id: str
    direction: str
    filename: str
    size: int
    sha256: str
    local_path: str
    total_chunks: int
    completed_chunks: int
    bytes_done: int
    status: str
    created_at_ms: int


class LocalDatabase:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.connection = sqlite3.connect(self.path, check_same_thread=False, timeout=30.0)
        self.connection.row_factory = sqlite3.Row
        self.initialize_schema()

    def close(self) -> None:
        with self.lock:
            self.connection.close()

    def initialize_schema(self) -> None:
        with self.lock:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=NORMAL")
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS identities (
                    public_id TEXT PRIMARY KEY,
                    public_base58 TEXT NOT NULL,
                    private_key_b64 TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    label TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    last_used_at_ms INTEGER
                );

                CREATE TABLE IF NOT EXISTS contacts (
                    identity_public_id TEXT NOT NULL,
                    peer_public_id TEXT NOT NULL,
                    peer_base58 TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    alias TEXT NOT NULL DEFAULT '',
                    verified INTEGER NOT NULL DEFAULT 0,
                    pinned INTEGER NOT NULL DEFAULT 0,
                    blocked INTEGER NOT NULL DEFAULT 0,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(identity_public_id, peer_public_id)
                );

                CREATE TABLE IF NOT EXISTS conversations (
                    identity_public_id TEXT NOT NULL,
                    peer_public_id TEXT NOT NULL,
                    last_server_id INTEGER NOT NULL DEFAULT 0,
                    last_message_preview TEXT NOT NULL DEFAULT '',
                    last_message_at_ms INTEGER,
                    unread_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(identity_public_id, peer_public_id)
                );

                CREATE TABLE IF NOT EXISTS messages (
                    identity_public_id TEXT NOT NULL,
                    envelope_id TEXT NOT NULL,
                    peer_public_id TEXT NOT NULL,
                    server_id INTEGER,
                    direction TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    copy_role TEXT,
                    text TEXT NOT NULL DEFAULT '',
                    created_at_ms INTEGER,
                    received_at_ms INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT,
                    PRIMARY KEY(identity_public_id, envelope_id)
                );

                CREATE INDEX IF NOT EXISTS idx_messages_conversation
                    ON messages(identity_public_id, peer_public_id, created_at_ms, received_at_ms);

                CREATE TABLE IF NOT EXISTS attachments (
                    identity_public_id TEXT NOT NULL,
                    file_id TEXT NOT NULL,
                    peer_public_id TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    size INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL DEFAULT '',
                    local_path TEXT NOT NULL DEFAULT '',
                    total_chunks INTEGER NOT NULL DEFAULT 0,
                    completed_chunks INTEGER NOT NULL DEFAULT 0,
                    bytes_done INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(identity_public_id, file_id)
                );

                CREATE TABLE IF NOT EXISTS sync_state (
                    identity_public_id TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    peer_public_id TEXT NOT NULL DEFAULT '',
                    last_server_id INTEGER NOT NULL DEFAULT 0,
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(identity_public_id, scope, peer_public_id)
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            self.connection.commit()

    def set_setting(self, key: str, value: str) -> None:
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO settings(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (key, value),
            )
            self.connection.commit()

    def get_setting(self, key: str, default: str = "") -> str:
        with self.lock:
            database_row = self.connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return str(database_row["value"]) if database_row else default

    def upsert_identity(
        self,
        *,
        public_id: str,
        public_base58: str,
        private_key_b64: str,
        fingerprint: str,
        label: str,
        created_at_ms: int | None = None,
    ) -> None:
        created_at_ms = created_at_ms or current_time_ms()
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO identities(public_id, public_base58, private_key_b64, fingerprint, label, created_at_ms, last_used_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(public_id) DO UPDATE SET
                    public_base58=excluded.public_base58,
                    private_key_b64=excluded.private_key_b64,
                    fingerprint=excluded.fingerprint,
                    label=excluded.label,
                    last_used_at_ms=excluded.last_used_at_ms
                """,
                (public_id, public_base58, private_key_b64, fingerprint, label, created_at_ms, current_time_ms()),
            )
            self.connection.commit()

    def list_identities(self) -> list[IdentityRecord]:
        with self.lock:
            database_rows = self.connection.execute(
                "SELECT * FROM identities ORDER BY last_used_at_ms DESC, created_at_ms DESC"
            ).fetchall()
        return [self._identity_from_row(database_row) for database_row in database_rows]

    def get_identity(self, public_id: str) -> IdentityRecord | None:
        with self.lock:
            database_row = self.connection.execute(
                "SELECT * FROM identities WHERE public_id = ?", (public_id,)
            ).fetchone()
        return self._identity_from_row(database_row) if database_row else None

    def mark_identity_used(self, public_id: str) -> None:
        with self.lock:
            self.connection.execute(
                "UPDATE identities SET last_used_at_ms = ? WHERE public_id = ?",
                (current_time_ms(), public_id),
            )
            self.connection.commit()

    def delete_identity(self, public_id: str) -> None:
        """Delete one local identity and all local data scoped to it.

        This never contacts the relay server and never deletes server-side envelopes.
        Downloaded files on disk are intentionally left in place; only local indexes are removed.
        """
        with self.lock:
            self.connection.execute("DELETE FROM contacts WHERE identity_public_id = ?", (public_id,))
            self.connection.execute("DELETE FROM conversations WHERE identity_public_id = ?", (public_id,))
            self.connection.execute("DELETE FROM messages WHERE identity_public_id = ?", (public_id,))
            self.connection.execute("DELETE FROM attachments WHERE identity_public_id = ?", (public_id,))
            self.connection.execute("DELETE FROM sync_state WHERE identity_public_id = ?", (public_id,))
            self.connection.execute("DELETE FROM identities WHERE public_id = ?", (public_id,))
            self.connection.commit()

    @staticmethod
    def _identity_from_row(database_row: sqlite3.Row) -> IdentityRecord:
        return IdentityRecord(
            public_id=database_row["public_id"],
            public_base58=database_row["public_base58"],
            private_key_b64=database_row["private_key_b64"],
            fingerprint=database_row["fingerprint"],
            label=database_row["label"],
            created_at_ms=int(database_row["created_at_ms"]),
            last_used_at_ms=database_row["last_used_at_ms"],
        )

    def upsert_contact(
        self,
        *,
        identity_public_id: str,
        peer_public_id: str,
        peer_base58: str,
        fingerprint: str,
        alias: str = "",
        verified: bool = False,
        pinned: bool | None = None,
    ) -> None:
        pinned_value = 1 if pinned else 0
        with self.lock:
            if pinned is None:
                self.connection.execute(
                    """
                    INSERT INTO contacts(identity_public_id, peer_public_id, peer_base58, fingerprint, alias, verified, created_at_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(identity_public_id, peer_public_id) DO UPDATE SET
                        peer_base58=excluded.peer_base58,
                        fingerprint=excluded.fingerprint,
                        alias=CASE WHEN excluded.alias != '' THEN excluded.alias ELSE contacts.alias END,
                        verified=MAX(contacts.verified, excluded.verified)
                    """,
                    (
                        identity_public_id,
                        peer_public_id,
                        peer_base58,
                        fingerprint,
                        alias,
                        int(verified),
                        current_time_ms(),
                    ),
                )
            else:
                self.connection.execute(
                    """
                    INSERT INTO contacts(identity_public_id, peer_public_id, peer_base58, fingerprint, alias, verified, pinned, created_at_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(identity_public_id, peer_public_id) DO UPDATE SET
                        peer_base58=excluded.peer_base58,
                        fingerprint=excluded.fingerprint,
                        alias=CASE WHEN excluded.alias != '' THEN excluded.alias ELSE contacts.alias END,
                        verified=MAX(contacts.verified, excluded.verified),
                        pinned=excluded.pinned
                    """,
                    (
                        identity_public_id,
                        peer_public_id,
                        peer_base58,
                        fingerprint,
                        alias,
                        int(verified),
                        pinned_value,
                        current_time_ms(),
                    ),
                )
            self.ensure_conversation(identity_public_id, peer_public_id)
            self.connection.commit()

    def get_contact(self, identity_public_id: str, peer_public_id: str) -> ContactRecord | None:
        with self.lock:
            database_row = self.connection.execute(
                """
                SELECT * FROM contacts
                WHERE identity_public_id = ? AND peer_public_id = ?
                """,
                (identity_public_id, peer_public_id),
            ).fetchone()
        return self._contact_from_row(database_row) if database_row else None

    def update_contact(
        self,
        *,
        identity_public_id: str,
        peer_public_id: str,
        alias: str,
        verified: bool,
        pinned: bool,
    ) -> None:
        with self.lock:
            self.connection.execute(
                """
                UPDATE contacts
                SET alias = ?, verified = ?, pinned = ?
                WHERE identity_public_id = ? AND peer_public_id = ?
                """,
                (alias, int(verified), int(pinned), identity_public_id, peer_public_id),
            )
            self.ensure_conversation(identity_public_id, peer_public_id)
            self.connection.commit()

    def delete_contact_and_local_history(self, identity_public_id: str, peer_public_id: str) -> None:
        """Remove one peer from the current local identity.

        This deletes the contact, conversation row, local messages, attachment index rows,
        and the per-conversation sync checkpoint. It does not contact the relay server.
        """
        with self.lock:
            self.connection.execute(
                "DELETE FROM contacts WHERE identity_public_id = ? AND peer_public_id = ?",
                (identity_public_id, peer_public_id),
            )
            self.connection.execute(
                "DELETE FROM messages WHERE identity_public_id = ? AND peer_public_id = ?",
                (identity_public_id, peer_public_id),
            )
            self.connection.execute(
                "DELETE FROM attachments WHERE identity_public_id = ? AND peer_public_id = ?",
                (identity_public_id, peer_public_id),
            )
            self.connection.execute(
                "DELETE FROM conversations WHERE identity_public_id = ? AND peer_public_id = ?",
                (identity_public_id, peer_public_id),
            )
            self.connection.execute(
                """
                DELETE FROM sync_state
                WHERE identity_public_id = ? AND scope = 'conversation' AND peer_public_id = ?
                """,
                (identity_public_id, peer_public_id),
            )
            self.connection.commit()

    def list_contacts(self, identity_public_id: str) -> list[ContactRecord]:
        with self.lock:
            database_rows = self.connection.execute(
                """
                SELECT * FROM contacts
                WHERE identity_public_id = ? AND blocked = 0
                ORDER BY pinned DESC, alias COLLATE NOCASE ASC, peer_base58 ASC
                """,
                (identity_public_id,),
            ).fetchall()
        return [self._contact_from_row(database_row) for database_row in database_rows]

    @staticmethod
    def _contact_from_row(database_row: sqlite3.Row) -> ContactRecord:
        return ContactRecord(
            peer_public_id=database_row["peer_public_id"],
            peer_base58=database_row["peer_base58"],
            fingerprint=database_row["fingerprint"],
            alias=database_row["alias"],
            verified=bool(database_row["verified"]),
            pinned=bool(database_row["pinned"]),
            blocked=bool(database_row["blocked"]),
        )

    def ensure_conversation(self, identity_public_id: str, peer_public_id: str) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO conversations(identity_public_id, peer_public_id)
            VALUES (?, ?)
            """,
            (identity_public_id, peer_public_id),
        )

    def list_conversations(self, identity_public_id: str) -> list[ConversationRecord]:
        with self.lock:
            database_rows = self.connection.execute(
                """
                SELECT
                    c.peer_public_id,
                    COALESCE(NULLIF(ct.alias, ''), substr(COALESCE(ct.peer_base58, c.peer_public_id), 1, 16) || '…') AS display_name,
                    COALESCE(ct.peer_base58, c.peer_public_id) AS peer_base58,
                    COALESCE(ct.fingerprint, '') AS fingerprint,
                    c.last_message_preview,
                    c.last_message_at_ms,
                    c.unread_count,
                    COALESCE(ct.pinned, 0) AS pinned,
                    COALESCE(ct.verified, 0) AS verified
                FROM conversations c
                LEFT JOIN contacts ct
                    ON ct.identity_public_id = c.identity_public_id
                   AND ct.peer_public_id = c.peer_public_id
                WHERE c.identity_public_id = ?
                ORDER BY pinned DESC, COALESCE(c.last_message_at_ms, 0) DESC, display_name ASC
                """,
                (identity_public_id,),
            ).fetchall()
        return [
            ConversationRecord(
                peer_public_id=database_row["peer_public_id"],
                display_name=database_row["display_name"],
                peer_base58=database_row["peer_base58"],
                fingerprint=database_row["fingerprint"],
                last_message_preview=database_row["last_message_preview"],
                last_message_at_ms=database_row["last_message_at_ms"],
                unread_count=int(database_row["unread_count"]),
                pinned=bool(database_row["pinned"]),
                verified=bool(database_row["verified"]),
            )
            for database_row in database_rows
        ]

    def mark_conversation_read(self, identity_public_id: str, peer_public_id: str) -> None:
        with self.lock:
            self.connection.execute(
                """
                UPDATE conversations SET unread_count = 0
                WHERE identity_public_id = ? AND peer_public_id = ?
                """,
                (identity_public_id, peer_public_id),
            )
            self.connection.commit()

    def get_last_global_server_id(self, identity_public_id: str) -> int:
        return self.get_sync_state(identity_public_id, "global", "")

    def get_last_conversation_server_id(self, identity_public_id: str, peer_public_id: str) -> int:
        return self.get_sync_state(identity_public_id, "conversation", peer_public_id)

    def get_sync_state(self, identity_public_id: str, scope: str, peer_public_id: str) -> int:
        with self.lock:
            database_row = self.connection.execute(
                """
                SELECT last_server_id FROM sync_state
                WHERE identity_public_id = ? AND scope = ? AND peer_public_id = ?
                """,
                (identity_public_id, scope, peer_public_id),
            ).fetchone()
        return int(database_row["last_server_id"]) if database_row else 0

    def update_sync_state(
        self, identity_public_id: str, scope: str, peer_public_id: str, server_id: int
    ) -> None:
        if server_id <= 0:
            return
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO sync_state(identity_public_id, scope, peer_public_id, last_server_id, updated_at_ms)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(identity_public_id, scope, peer_public_id) DO UPDATE SET
                    last_server_id=MAX(sync_state.last_server_id, excluded.last_server_id),
                    updated_at_ms=excluded.updated_at_ms
                """,
                (identity_public_id, scope, peer_public_id, server_id, current_time_ms()),
            )
            self.connection.commit()

    def save_message(
        self,
        *,
        identity_public_id: str,
        envelope_id: str,
        peer_public_id: str,
        server_id: int | None,
        direction: str,
        kind: str,
        copy_role: str | None,
        text: str,
        created_at_ms: int | None,
        status: str,
        error: str | None = None,
        selected_peer_public_id: str | None = None,
    ) -> bool:
        received_at_ms = current_time_ms()
        with self.lock:
            self.ensure_conversation(identity_public_id, peer_public_id)
            cursor = self.connection.execute(
                """
                INSERT OR IGNORE INTO messages(
                    identity_public_id, envelope_id, peer_public_id, server_id, direction, kind,
                    copy_role, text, created_at_ms, received_at_ms, status, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    identity_public_id,
                    envelope_id,
                    peer_public_id,
                    server_id,
                    direction,
                    kind,
                    copy_role,
                    text,
                    created_at_ms,
                    received_at_ms,
                    status,
                    error,
                ),
            )
            inserted = cursor.rowcount > 0
            if inserted:
                preview = text
                if text.startswith("[file:"):
                    preview = "[File] " + text.split("]", 1)[-1].strip()
                elif kind == "file_start":
                    preview = text or "[File]"
                increment_unread = 1 if direction == "incoming" and peer_public_id != selected_peer_public_id else 0
                self.connection.execute(
                    """
                    UPDATE conversations
                    SET last_message_preview = ?,
                        last_message_at_ms = COALESCE(?, ?),
                        unread_count = unread_count + ?
                    WHERE identity_public_id = ? AND peer_public_id = ?
                    """,
                    (
                        preview[:200],
                        created_at_ms,
                        received_at_ms,
                        increment_unread,
                        identity_public_id,
                        peer_public_id,
                    ),
                )
            self.connection.commit()
        return inserted

    def has_message(self, identity_public_id: str, envelope_id: str) -> bool:
        """Return whether an envelope has already been saved in local SQLite.

        This is deliberately separate from RelayClient.seen_message_id_set. The
        seen set is only an in-memory duplicate guard for the current GUI
        process, while SQLite is the source of truth for whether local history
        still contains the message.
        """
        with self.lock:
            database_row = self.connection.execute(
                """
                SELECT 1 FROM messages
                WHERE identity_public_id = ? AND envelope_id = ?
                LIMIT 1
                """,
                (identity_public_id, envelope_id),
            ).fetchone()
        return database_row is not None

    def update_message_status(
        self,
        *,
        identity_public_id: str,
        envelope_id: str,
        status: str,
        server_id: int | None = None,
        error: str | None = None,
    ) -> None:
        with self.lock:
            self.connection.execute(
                """
                UPDATE messages
                SET status = ?, server_id = COALESCE(?, server_id), error = ?
                WHERE identity_public_id = ? AND envelope_id = ?
                """,
                (status, server_id, error, identity_public_id, envelope_id),
            )
            self.connection.commit()

    def list_messages(
        self, identity_public_id: str, peer_public_id: str, *, limit: int = 500
    ) -> list[MessageRecord]:
        with self.lock:
            database_rows = self.connection.execute(
                """
                SELECT * FROM (
                    SELECT * FROM messages
                    WHERE identity_public_id = ? AND peer_public_id = ?
                    ORDER BY COALESCE(created_at_ms, received_at_ms) DESC
                    LIMIT ?
                ) ORDER BY COALESCE(created_at_ms, received_at_ms) ASC
                """,
                (identity_public_id, peer_public_id, limit),
            ).fetchall()
        return [
            MessageRecord(
                envelope_id=database_row["envelope_id"],
                peer_public_id=database_row["peer_public_id"],
                direction=database_row["direction"],
                kind=database_row["kind"],
                text=database_row["text"],
                status=database_row["status"],
                created_at_ms=database_row["created_at_ms"],
                server_id=database_row["server_id"],
                error=database_row["error"],
            )
            for database_row in database_rows
        ]

    def list_messages_for_export(self, identity_public_id: str, peer_public_id: str) -> list[MessageRecord]:
        """Return all locally saved messages for one conversation in chronological order.

        Export uses COALESCE(created_at_ms, received_at_ms) as its display time so
        imported/synced records with incomplete payload timestamps still produce a
        stable, readable transcript.
        """
        with self.lock:
            database_rows = self.connection.execute(
                """
                SELECT
                    envelope_id,
                    peer_public_id,
                    direction,
                    kind,
                    text,
                    status,
                    COALESCE(created_at_ms, received_at_ms) AS export_time_ms,
                    server_id,
                    error
                FROM messages
                WHERE identity_public_id = ? AND peer_public_id = ?
                ORDER BY COALESCE(created_at_ms, received_at_ms) ASC, rowid ASC
                """,
                (identity_public_id, peer_public_id),
            ).fetchall()
        return [
            MessageRecord(
                envelope_id=database_row["envelope_id"],
                peer_public_id=database_row["peer_public_id"],
                direction=database_row["direction"],
                kind=database_row["kind"],
                text=database_row["text"],
                status=database_row["status"],
                created_at_ms=database_row["export_time_ms"],
                server_id=database_row["server_id"],
                error=database_row["error"],
            )
            for database_row in database_rows
        ]

    def upsert_attachment(
        self,
        *,
        identity_public_id: str,
        file_id: str,
        peer_public_id: str,
        direction: str,
        filename: str,
        size: int,
        sha256: str,
        local_path: str,
        total_chunks: int,
        completed_chunks: int,
        bytes_done: int,
        status: str,
    ) -> None:
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO attachments(
                    identity_public_id, file_id, peer_public_id, direction, filename, size, sha256,
                    local_path, total_chunks, completed_chunks, bytes_done, status, created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(identity_public_id, file_id) DO UPDATE SET
                    filename=excluded.filename,
                    size=excluded.size,
                    sha256=excluded.sha256,
                    total_chunks=excluded.total_chunks,
                    completed_chunks=excluded.completed_chunks,
                    bytes_done=excluded.bytes_done,
                    status=excluded.status,
                    local_path=CASE WHEN excluded.local_path != '' THEN excluded.local_path ELSE attachments.local_path END
                """,
                (
                    identity_public_id,
                    file_id,
                    peer_public_id,
                    direction,
                    filename,
                    size,
                    sha256,
                    local_path,
                    total_chunks,
                    completed_chunks,
                    bytes_done,
                    status,
                    current_time_ms(),
                ),
            )
            self.connection.commit()

    def get_attachment(self, peer_public_id: str, file_id: str | None) -> AttachmentRecord | None:
        if not file_id:
            return None
        with self.lock:
            database_row = self.connection.execute(
                """
                SELECT * FROM attachments
                WHERE peer_public_id = ? AND file_id = ?
                ORDER BY created_at_ms DESC
                LIMIT 1
                """,
                (peer_public_id, file_id),
            ).fetchone()
        return self._attachment_from_row(database_row) if database_row else None

    def get_attachment_by_file_id(self, file_id: str) -> AttachmentRecord | None:
        with self.lock:
            database_row = self.connection.execute(
                """
                SELECT * FROM attachments
                WHERE file_id = ?
                ORDER BY created_at_ms DESC
                LIMIT 1
                """,
                (file_id,),
            ).fetchone()
        return self._attachment_from_row(database_row) if database_row else None

    @staticmethod
    def _attachment_from_row(database_row: sqlite3.Row) -> AttachmentRecord:
        return AttachmentRecord(
            identity_public_id=database_row["identity_public_id"],
            file_id=database_row["file_id"],
            peer_public_id=database_row["peer_public_id"],
            direction=database_row["direction"],
            filename=database_row["filename"],
            size=int(database_row["size"]),
            sha256=database_row["sha256"],
            local_path=database_row["local_path"],
            total_chunks=int(database_row["total_chunks"]),
            completed_chunks=int(database_row["completed_chunks"]),
            bytes_done=int(database_row["bytes_done"]),
            status=database_row["status"],
            created_at_ms=int(database_row["created_at_ms"]),
        )

    def bulk_add_contacts(self, identity_public_id: str, contacts: Iterable[ContactRecord]) -> None:
        for contact in contacts:
            self.upsert_contact(
                identity_public_id=identity_public_id,
                peer_public_id=contact.peer_public_id,
                peer_base58=contact.peer_base58,
                fingerprint=contact.fingerprint,
                alias=contact.alias,
                verified=contact.verified,
                pinned=contact.pinned,
            )


# ===== gui/models.py =====

from typing import Any

from PyQt6.QtCore import QAbstractListModel, QModelIndex, QSize, Qt


ConversationRecordRole = int(Qt.ItemDataRole.UserRole) + 1
MessageRecordRole = int(Qt.ItemDataRole.UserRole) + 2


class ConversationListModel(QAbstractListModel):
    def __init__(self, database: LocalDatabase):
        super().__init__()
        self.database = database
        self.identity_public_id: str | None = None
        self.filter_text = ""
        self.items: list[ConversationRecord] = []

    def set_identity(self, identity_public_id: str | None) -> None:
        self.identity_public_id = identity_public_id
        self.reload()

    def set_filter(self, text: str) -> None:
        self.filter_text = text.strip().lower()
        self.reload()

    def reload(self) -> None:
        self.beginResetModel()
        if not self.identity_public_id:
            self.items = []
        else:
            items = self.database.list_conversations(self.identity_public_id)
            if self.filter_text:
                needle = self.filter_text
                items = [
                    item
                    for item in items
                    if needle in item.display_name.lower()
                    or needle in item.peer_base58.lower()
                    or needle in item.fingerprint.lower()
                    or needle in (item.last_message_preview or "").lower()
                ]
            self.items = items
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.items)

    def data(self, index: QModelIndex, role: int = int(Qt.ItemDataRole.DisplayRole)) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self.items)):
            return None
        record = self.items[index.row()]
        if role == int(Qt.ItemDataRole.DisplayRole):
            return record.display_name
        if role == ConversationRecordRole:
            return record
        if role == int(Qt.ItemDataRole.ToolTipRole):
            return f"{record.peer_base58}\n{record.fingerprint}"
        if role == int(Qt.ItemDataRole.SizeHintRole):
            return QSize(280, 72)
        return None

    def record_at(self, database_row: int) -> ConversationRecord | None:
        if 0 <= database_row < len(self.items):
            return self.items[database_row]
        return None

    def index_for_peer(self, peer_public_id: str) -> QModelIndex:
        for database_row, record in enumerate(self.items):
            if record.peer_public_id == peer_public_id:
                return self.index(database_row, 0)
        return QModelIndex()


class MessageListModel(QAbstractListModel):
    def __init__(self, database: LocalDatabase):
        super().__init__()
        self.database = database
        self.identity_public_id: str | None = None
        self.peer_public_id: str | None = None
        self.items: list[MessageRecord] = []

    def set_conversation(self, identity_public_id: str | None, peer_public_id: str | None) -> None:
        self.identity_public_id = identity_public_id
        self.peer_public_id = peer_public_id
        self.reload()

    def reload(self) -> None:
        self.beginResetModel()
        if self.identity_public_id and self.peer_public_id:
            self.items = self.database.list_messages(self.identity_public_id, self.peer_public_id)
        else:
            self.items = []
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.items)

    def data(self, index: QModelIndex, role: int = int(Qt.ItemDataRole.DisplayRole)) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self.items)):
            return None
        record = self.items[index.row()]
        if role == int(Qt.ItemDataRole.DisplayRole):
            return record.text
        if role == MessageRecordRole:
            return record
        if role == int(Qt.ItemDataRole.SizeHintRole):
            return QSize(100, 86)
        return None

    def message_at(self, database_row: int) -> MessageRecord | None:
        if 0 <= database_row < len(self.items):
            return self.items[database_row]
        return None


# ===== gui/delegates.py =====

import re
import textwrap
from datetime import datetime
from typing import Any

from PyQt6.QtCore import QRect, QSize, Qt
from PyQt6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import QApplication, QStyle, QStyledItemDelegate, QStyleOptionViewItem


FILE_TOKEN_RE = re.compile(r"^\[file:([0-9a-fA-F\-]+)\]\s*(.*)$")


def short_time(timestamp_ms: int | None) -> str:
    if not timestamp_ms:
        return ""
    date_time = datetime.fromtimestamp(timestamp_ms / 1000)
    return date_time.strftime("%H:%M")


def short_date_time(timestamp_ms: int | None) -> str:
    if not timestamp_ms:
        return ""
    date_time = datetime.fromtimestamp(timestamp_ms / 1000)
    now = datetime.now()
    if date_time.date() == now.date():
        return date_time.strftime("%H:%M")
    return date_time.strftime("%m-%d %H:%M")


def elide(text: str, metrics: QFontMetrics, width: int) -> str:
    return metrics.elidedText(text, Qt.TextElideMode.ElideRight, max(1, width))


def parse_file_token(text: str) -> tuple[str | None, str]:
    match = FILE_TOKEN_RE.match(text.strip())
    if match:
        return match.group(1), match.group(2).strip() or "file"
    if text.startswith("[File]"):
        return None, text.removeprefix("[File]").strip() or "file"
    return None, text


def full_date_time(timestamp_ms: int | None) -> str:
    if not timestamp_ms:
        return "Unknown time"
    return datetime.fromtimestamp(timestamp_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")


def human_file_size(size: int | None) -> str:
    try:
        value = int(size or 0)
    except Exception:
        value = 0
    if value < 1024:
        return f"{value} B"
    units = ["KB", "MB", "GB", "TB"]
    amount = float(value)
    for unit in units:
        amount /= 1024.0
        if amount < 1024.0 or unit == units[-1]:
            return f"{amount:.2f} {unit}"
    return f"{value} B"


def indent_multiline_text(text: str, prefix: str = "    ") -> str:
    if not text:
        return ""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join((prefix + line) if line else prefix.rstrip() for line in normalized.split("\n"))


class ConversationDelegate(QStyledItemDelegate):
    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:  # noqa: ANN001
        record = index.data(ConversationRecordRole)
        if record is None:
            super().paint(painter, option, index)
            return
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        rect = option.rect.adjusted(6, 4, -6, -4)
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        hover = bool(option.state & QStyle.StateFlag.State_MouseOver)

        if selected:
            background_color = QColor("#D8CCB9")
        elif hover:
            background_color = QColor("#E8DECf")
        else:
            background_color = QColor("#EFE8DC")
        path = QPainterPath()
        path.addRoundedRect(rect.x(), rect.y(), rect.width(), rect.height(), 16, 16)
        painter.fillPath(path, background_color)

        avatar_rect = QRect(rect.x() + 12, rect.y() + 13, 40, 40)
        avatar_color = QColor("#7C6B4D") if not record.pinned else QColor("#8A5F3E")
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(avatar_color)
        painter.drawEllipse(avatar_rect)
        painter.setPen(QColor("#FFF8EC"))
        avatar_font = QFont(option.font)
        avatar_font.setBold(True)
        avatar_font.setPointSize(13)
        painter.setFont(avatar_font)
        initial = (record.display_name or record.peer_base58 or "?").strip()[:1].upper()
        painter.drawText(avatar_rect, Qt.AlignmentFlag.AlignCenter, initial)

        title_font = QFont(option.font)
        title_font.setBold(True)
        title_font.setPointSize(10)
        preview_font = QFont(option.font)
        preview_font.setPointSize(9)
        meta_font = QFont(option.font)
        meta_font.setPointSize(8)
        meta_font.setBold(False)

        left = avatar_rect.right() + 12
        right = rect.right() - 12
        painter.setFont(title_font)
        title_metrics = QFontMetrics(title_font)
        time_text = short_date_time(record.last_message_at_ms)
        time_width = QFontMetrics(meta_font).horizontalAdvance(time_text) + 6 if time_text else 0
        title_rect = QRect(left, rect.y() + 12, max(10, right - left - time_width - 8), 20)
        painter.setPen(QColor("#2C2821"))
        title_prefix = "★ " if record.pinned else ""
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, elide(title_prefix + record.display_name, title_metrics, title_rect.width()))

        painter.setFont(meta_font)
        painter.setPen(QColor("#7F7569"))
        painter.drawText(QRect(right - time_width, rect.y() + 13, time_width, 18), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, time_text)

        painter.setFont(preview_font)
        preview_metrics = QFontMetrics(preview_font)
        preview = record.last_message_preview or record.peer_base58[:26] + "…"
        preview_rect = QRect(left, rect.y() + 38, right - left - (38 if record.unread_count else 0), 18)
        painter.setPen(QColor("#766D62"))
        painter.drawText(preview_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, elide(preview.replace("\n", " "), preview_metrics, preview_rect.width()))

        if record.unread_count:
            badge_text = str(record.unread_count if record.unread_count < 99 else "99+")
            badge_w = max(24, QFontMetrics(meta_font).horizontalAdvance(badge_text) + 12)
            badge = QRect(right - badge_w, rect.y() + 38, badge_w, 20)
            badge_path = QPainterPath()
            badge_path.addRoundedRect(badge.x(), badge.y(), badge.width(), badge.height(), 10, 10)
            painter.fillPath(badge_path, QColor("#8F4D3E"))
            painter.setPen(QColor("#FFF8EC"))
            painter.drawText(badge, Qt.AlignmentFlag.AlignCenter, badge_text)
        painter.restore()

    def sizeHint(self, option: QStyleOptionViewItem, index) -> QSize:  # noqa: ANN001,N802
        return QSize(option.rect.width(), 76)


class MessageBubbleDelegate(QStyledItemDelegate):
    def __init__(self, database: LocalDatabase, parent=None):
        super().__init__(parent)
        self.database = database
        self.chat_font_size = 18

    def set_chat_font_size(self, point_size: int) -> None:
        self.chat_font_size = max(18, min(25, int(point_size)))

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:  # noqa: ANN001
        message: MessageRecord | None = index.data(MessageRecordRole)
        if message is None:
            super().paint(painter, option, index)
            return
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        rect = option.rect.adjusted(14, 5, -14, -5)
        outgoing = message.direction == "outgoing"
        max_bubble_width = int(rect.width() * self._bubble_width_ratio())
        min_bubble_width = 190 if message.kind == "file_start" else 80

        font = QFont(option.font)
        font.setPointSize(self.chat_font_size)
        metrics = QFontMetrics(font)
        meta_font = QFont(option.font)
        meta_font.setPointSize(8)

        display_text = self._display_text(message)
        wrapped = self._wrap_text(display_text, metrics, max_bubble_width - 28)
        text_width = min(max_bubble_width - 28, max((metrics.horizontalAdvance(line) for line in wrapped), default=0))
        bubble_width = max(min_bubble_width, text_width + 28)
        bubble_height = metrics.lineSpacing() * max(1, len(wrapped)) + 38
        if message.kind == "file_start":
            bubble_height = max(82, bubble_height)
            bubble_width = max(250, bubble_width)
        bubble_x = rect.right() - bubble_width if outgoing else rect.x()
        bubble = QRect(bubble_x, rect.y() + 4, bubble_width, bubble_height)

        bubble_path = QPainterPath()
        bubble_path.addRoundedRect(bubble.x(), bubble.y(), bubble.width(), bubble.height(), 17, 17)
        bubble_color = QColor("#DED1BC") if outgoing else QColor("#FFFDF8")
        painter.fillPath(bubble_path, bubble_color)
        painter.setPen(QPen(QColor("#D0C2AF"), 1))
        painter.drawPath(bubble_path)

        if message.kind == "file_start":
            self._paint_file_message(painter, bubble, message, font, meta_font)
        else:
            painter.setFont(font)
            painter.setPen(QColor("#2C2821"))
            text_y = bubble.y() + 14
            for line in wrapped:
                painter.drawText(QRect(bubble.x() + 14, text_y, bubble.width() - 28, metrics.lineSpacing()), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, line)
                text_y += metrics.lineSpacing()

        meta = ""
        message_time_text = short_time(message.created_at_ms)
        if outgoing:
            meta = f"{message_time_text} · {self._status_label(message.status)}" if message_time_text else self._status_label(message.status)
        elif message_time_text:
            meta = message_time_text
        if message.error:
            meta = (meta + " · " if meta else "") + "Error"
        painter.setFont(meta_font)
        painter.setPen(QColor("#82786D"))
        meta_rect = QRect(bubble.x() + 14, bubble.bottom() - 24, bubble.width() - 28, 17)
        align = Qt.AlignmentFlag.AlignRight if outgoing else Qt.AlignmentFlag.AlignLeft
        painter.drawText(meta_rect, align | Qt.AlignmentFlag.AlignVCenter, meta)
        painter.restore()

    def _paint_file_message(self, painter: QPainter, bubble: QRect, message: MessageRecord, font: QFont, meta_font: QFont) -> None:
        file_id, fallback_name = parse_file_token(message.text)
        attachment: AttachmentRecord | None = self.database.get_attachment(message.peer_public_id, file_id) if file_id else None
        filename = attachment.filename if attachment else fallback_name
        status = attachment.status if attachment else message.status
        total = attachment.size if attachment else 0
        done = attachment.bytes_done if attachment else 0
        icon_rect = QRect(bubble.x() + 14, bubble.y() + 14, 38, 38)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#8A7353"))
        painter.drawRoundedRect(icon_rect, 10, 10)
        painter.setPen(QColor("#FFF8EC"))
        icon_font = QFont(font)
        icon_font.setBold(True)
        icon_font.setPointSize(15)
        painter.setFont(icon_font)
        painter.drawText(icon_rect, Qt.AlignmentFlag.AlignCenter, "↧" if message.direction == "incoming" else "↥")

        title_rect = QRect(icon_rect.right() + 12, bubble.y() + 12, bubble.width() - 78, 22)
        painter.setFont(font)
        painter.setPen(QColor("#2C2821"))
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, elide(filename, QFontMetrics(font), title_rect.width()))

        subtitle_text = self._file_subtitle(status, done, total)
        painter.setFont(meta_font)
        painter.setPen(QColor("#796F63"))
        painter.drawText(QRect(icon_rect.right() + 12, bubble.y() + 36, bubble.width() - 78, 18), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, subtitle_text)

        if total > 0 and status not in {"saved", "sha256_failed", "size_failed"}:
            progress_bar_rect = QRect(icon_rect.right() + 12, bubble.y() + 58, bubble.width() - 92, 5)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#D1C3B0"))
            painter.drawRoundedRect(progress_bar_rect, 2, 2)
            completed_progress_width = int(progress_bar_rect.width() * max(0, min(done, total)) / total)
            painter.setBrush(QColor("#8A7353"))
            painter.drawRoundedRect(QRect(progress_bar_rect.x(), progress_bar_rect.y(), completed_progress_width, progress_bar_rect.height()), 2, 2)

    def _bubble_width_ratio(self) -> float:
        """Widen bubbles as chat font grows, so larger text wraps less vertically."""
        growth = (self.chat_font_size - 18) / 7
        return min(0.86, 0.68 + max(0.0, growth) * 0.18)

    @staticmethod
    def _file_subtitle(status: str, done: int, total: int) -> str:
        if total:
            total_text = _human_size(total)
            if status in {"receiving", "sending"}:
                return f"{_human_size(done)} / {total_text} · {status}"
            return f"{total_text} · {status}"
        return status or "file"

    @staticmethod
    def _status_label(status: str) -> str:
        return {
            "queued": "Queued",
            "sent_to_server": "Submitted",
            "sent_to_server_queue": "Queued",
            "synced": "Synced",
            "failed": "Failed",
        }.get(status, status or "")

    @staticmethod
    def _display_text(message: MessageRecord) -> str:
        if message.kind == "file_start":
            _, filename = parse_file_token(message.text)
            return filename
        return message.text or " "

    @staticmethod
    def _wrap_text(text: str, metrics: QFontMetrics, max_width: int) -> list[str]:
        lines: list[str] = []
        for paragraph in text.splitlines() or [""]:
            current = ""
            for char in paragraph:
                if metrics.horizontalAdvance(current + char) <= max_width or not current:
                    current += char
                else:
                    lines.append(current)
                    current = char
            lines.append(current)
        return lines or [""]

    def sizeHint(self, option: QStyleOptionViewItem, index) -> QSize:  # noqa: ANN001,N802
        message: MessageRecord | None = index.data(MessageRecordRole)
        if message is None:
            return QSize(100, 60)
        font = QApplication.font()
        font.setPointSize(self.chat_font_size)
        metrics = QFontMetrics(font)
        width = max(360, option.widget.width() if option.widget else 760)
        max_bubble_width = int((width - 28) * self._bubble_width_ratio())
        text = self._display_text(message)
        wrapped = self._wrap_text(text, metrics, max_bubble_width - 28)
        height = metrics.lineSpacing() * max(1, len(wrapped)) + 54
        if message.kind == "file_start":
            height = max(96, height)
        return QSize(width, height + 6)


def _human_size(size: int) -> str:
    value = float(size)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024


# ===== Dialogs =====

from dataclasses import dataclass

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
)



@dataclass(frozen=True)
class ContactDialogResult:
    peer_public_id: str
    alias: str
    verified: bool
    pinned: bool


class AddContactDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Contact")
        self.setMinimumWidth(520)
        self._public_id: str | None = None

        layout = QVBoxLayout(self)
        hint = QLabel("Paste the peer's Base58 public key/username, or a legacy base64url public id.")
        hint.setWordWrap(True)
        hint.setObjectName("MutedLabel")
        layout.addWidget(hint)

        form = QFormLayout()
        self.key_edit = QPlainTextEdit()
        self.key_edit.setPlaceholderText("Peer public key / username")
        self.key_edit.setFixedHeight(92)
        self.alias_edit = QLineEdit()
        self.alias_edit.setPlaceholderText("For example: Alice / work account / test node")
        self.verified_check = QCheckBox("I have verified the fingerprint through another channel")
        self.pinned_check = QCheckBox("Pin this conversation")
        self.preview_label = QLabel("Not parsed yet")
        self.preview_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.preview_label.setWordWrap(True)
        self.preview_label.setObjectName("MutedLabel")
        form.addRow("Public key", self.key_edit)
        form.addRow("Alias", self.alias_edit)
        form.addRow("Security", self.verified_check)
        form.addRow("List", self.pinned_check)
        form.addRow("Preview", self.preview_label)
        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.key_edit.textChanged.connect(self._update_preview)
        self._update_preview()

    def _update_preview(self) -> None:
        raw_value = self.key_edit.toPlainText().strip()
        if not raw_value:
            self._public_id = None
            self.preview_label.setText("Not parsed yet")
            return
        public_id = normalize_public_id(raw_value)
        if not is_valid_x25519_public_id(public_id):
            self._public_id = None
            self.preview_label.setText("Invalid format: enter a Base58 or base64url encoded 32-byte X25519 public key.")
            return
        self._public_id = public_id
        self.preview_label.setText(
            f"Base58：{public_id_to_base58(public_id)}\nFingerprint：{fingerprint_for_public_id(public_id)}"
        )

    def result_value(self) -> ContactDialogResult | None:
        self._update_preview()
        if not self._public_id:
            return None
        return ContactDialogResult(
            peer_public_id=self._public_id,
            alias=self.alias_edit.text().strip(),
            verified=self.verified_check.isChecked(),
            pinned=self.pinned_check.isChecked(),
        )


class ContactDetailsDialog(QDialog):
    def __init__(self, contact: ContactRecord | None, peer_public_id: str, peer_base58: str, fingerprint: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Contact Details")
        self.setMinimumWidth(560)
        self.peer_public_id = peer_public_id

        layout = QVBoxLayout(self)
        info = QLabel(f"Public key: {peer_base58}\nFingerprint：{fingerprint}")
        info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        info.setWordWrap(True)
        info.setObjectName("MutedLabel")
        layout.addWidget(info)

        form = QFormLayout()
        self.alias_edit = QLineEdit(contact.alias if contact else "")
        self.alias_edit.setPlaceholderText("Local alias; not sent to the server")
        self.verified_check = QCheckBox("Fingerprint verified through another channel")
        self.verified_check.setChecked(bool(contact.verified) if contact else False)
        self.pinned_check = QCheckBox("Pin this conversation")
        self.pinned_check.setChecked(bool(contact.pinned) if contact else False)
        form.addRow("Alias", self.alias_edit)
        form.addRow("Verification", self.verified_check)
        form.addRow("Pin", self.pinned_check)
        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Save)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, bool, bool]:
        return self.alias_edit.text().strip(), self.verified_check.isChecked(), self.pinned_check.isChecked()


# ===== gui/theme.py =====

APP_QSS = """
* {
    font-family: "Inter", "Segoe UI", "SF Pro Text", "Noto Sans CJK SC", "Microsoft YaHei", sans-serif;
    font-size: 13px;
}
QMainWindow, QWidget {
    background: #F4F0E8;
    color: #292520;
}
QToolBar {
    background: #EFE8DC;
    border: 0;
    border-bottom: 1px solid #D8CDBD;
    spacing: 8px;
    padding: 8px;
}
QStatusBar {
    background: #EFE8DC;
    border-top: 1px solid #D8CDBD;
    color: #6F665B;
}
QFrame#Sidebar {
    background: #EFE8DC;
    border-right: 1px solid #D6CABA;
}
QFrame#ChatPanel {
    background: #F8F5EF;
}
QFrame#IdentityCard, QFrame#PeerHeader, QFrame#Composer, QFrame#EmptyState {
    background: #FFFDF8;
    border: 1px solid #DED2C2;
    border-radius: 18px;
}
QLabel#AppTitle {
    font-size: 18px;
    font-weight: 700;
    color: #2F2A23;
}
QLabel#MutedLabel, QLabel#TinyMuted {
    color: #7A7166;
}
QLabel#TinyMuted {
    font-size: 11px;
}
QLabel#PeerTitle {
    font-size: 17px;
    font-weight: 700;
    color: #292520;
}
QLabel#ConnectionPill {
    background: #E4D8C6;
    color: #5B5145;
    border-radius: 12px;
    padding: 5px 12px;
    font-weight: 600;
}
QLineEdit, QTextEdit, QSpinBox, QComboBox {
    background: #FFFDF8;
    border: 1px solid #D5C8B7;
    border-radius: 12px;
    padding: 7px 10px;
    selection-background-color: #D9C7A4;
    selection-color: #221F1A;
}
QTextEdit {
    padding: 10px 12px;
}
QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus {
    border: 1px solid #9F7E53;
    background: #FFFFFF;
}
QComboBox#IdentityCombo {
    min-height: 22px;
    padding-right: 30px;
    font-weight: 600;
}
QComboBox#IdentityCombo::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 28px;
    border-left: 1px solid #D5C8B7;
    border-top-right-radius: 12px;
    border-bottom-right-radius: 12px;
}
QComboBox#IdentityCombo QAbstractItemView {
    background: #FFFDF8;
    color: #292520;
    border: 1px solid #CDBDA8;
    border-radius: 10px;
    padding: 6px;
    selection-background-color: #D9C7A4;
    selection-color: #221F1A;
    outline: 0;
}
QComboBox#IdentityCombo QAbstractItemView::item {
    min-height: 30px;
    padding: 6px 10px;
}
QPushButton {
    background: #E6DDCF;
    color: #2D2923;
    border: 1px solid #D0C2AF;
    border-radius: 12px;
    padding: 8px 13px;
    font-weight: 600;
}
QPushButton:hover {
    background: #DCD0BE;
}
QPushButton:pressed {
    background: #CDBDA8;
}
QPushButton#PrimaryButton {
    background: #6D5E45;
    color: #FFF9EE;
    border: 1px solid #6D5E45;
}
QPushButton#PrimaryButton:hover {
    background: #5F523D;
}
QPushButton#ConnectButton {
    background: #B65A49;
    color: #FFF9EE;
    border: 1px solid #B65A49;
}
QPushButton#ConnectButton:hover {
    background: #A94E3F;
}
QPushButton#ConnectButton[connectionState="connected"] {
    background: #3E8A55;
    color: #FFFDF8;
    border: 1px solid #3E8A55;
}
QPushButton#ConnectButton[connectionState="connected"]:hover {
    background: #357849;
}
QPushButton#ConnectButton[connectionState="connecting"] {
    background: #9F7E53;
    color: #FFFDF8;
    border: 1px solid #9F7E53;
}
QPushButton#ConnectButton[connectionState="failed"] {
    background: #B65A49;
    color: #FFF9EE;
    border: 1px solid #B65A49;
}
QPushButton#DangerButton {
    background: #9B4C3E;
    color: #FFF9EE;
    border: 1px solid #9B4C3E;
}
QListView {
    background: transparent;
    border: 0;
    outline: 0;
    padding: 4px;
}
QListView::item {
    border: 0;
}
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 3px;
}
QScrollBar::handle:vertical {
    background: #CBBEAD;
    border-radius: 5px;
    min-height: 32px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QMenu {
    background: #FFFDF8;
    border: 1px solid #D5C8B7;
    border-radius: 10px;
    padding: 6px;
}
QMenu::item {
    padding: 7px 22px 7px 14px;
    border-radius: 8px;
}
QMenu::item:selected {
    background: #E7DCCB;
}
QSplitter::handle {
    background: #D8CDBD;
}
"""


# ===== services/relay_client.py =====

import asyncio
import hashlib
import math
import os
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


URGENT_OUTBOX_LIMIT = 4096
BULK_STREAM_QUEUE_LIMIT = 8
MAX_TRACKED_MESSAGE_IDS = 200000
AUTO_SYNC_INTERVAL_SECONDS = 20.0
SYNC_PAGE_LIMIT = 5000


class OutboundMultiplexer:
    def __init__(self) -> None:
        self.urgent_queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(
            maxsize=URGENT_OUTBOX_LIMIT
        )
        self.bulk_queues: dict[str, asyncio.Queue[dict[str, Any] | None]] = {}
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
        while True:
            try:
                return self.urgent_queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            bulk_frame = await self._try_get_next_bulk_frame()
            if bulk_frame is not _NO_BULK_FRAME:
                return bulk_frame
            urgent_task = asyncio.create_task(self.urgent_queue.get())
            bulk_task = asyncio.create_task(self.bulk_available.wait())
            done, pending = await asyncio.wait(
                {urgent_task, bulk_task}, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            if urgent_task in done:
                return urgent_task.result()

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
    peer_public_id: str = ""
    direction: str = "incoming"


class RelayClient(QObject):
    connection_state_changed = pyqtSignal(str)
    conversations_changed = pyqtSignal()
    messages_changed = pyqtSignal(str)
    error_happened = pyqtSignal(str)
    sync_state_changed = pyqtSignal(str)
    file_progress_changed = pyqtSignal(dict)

    def __init__(self, database: LocalDatabase, download_dir: Path):
        super().__init__()
        self.database = database
        self.download_dir = download_dir
        self.download_dir.mkdir(parents=True, exist_ok=True)

        self.identity: Identity | None = None
        self.selected_peer_public_id: str | None = None
        self.server_host = "127.0.0.1"
        self.server_port = 8765
        self.proxy_config: Socks5ProxyConfig | None = None

        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.outbox = OutboundMultiplexer()
        self.tasks: set[asyncio.Task] = set()
        self.file_tasks: set[asyncio.Task] = set()
        self.stop_event: asyncio.Event | None = None
        self.sync_requests: dict[str, dict[str, Any]] = {}
        self.seen_message_ids: deque[str] = deque()
        self.seen_message_id_set: set[str] = set()
        self.active_files: dict[str, ReceivingFile] = {}
        self.completed_file_ids: set[str] = set()

    @property
    def is_connected(self) -> bool:
        return self.writer is not None and not self.writer.is_closing()

    @property
    def local_public_id(self) -> str:
        if self.identity is None:
            raise RuntimeError("identity is not loaded")
        return self.identity.public_id

    def set_identity(self, identity: Identity | None) -> None:
        self.identity = identity
        if identity is not None:
            self.database.mark_identity_used(identity.public_id)
        self.conversations_changed.emit()

    def set_selected_peer(self, peer_public_id: str | None) -> None:
        self.selected_peer_public_id = peer_public_id
        if self.identity and peer_public_id:
            self.database.mark_conversation_read(self.identity.public_id, peer_public_id)
            self.messages_changed.emit(peer_public_id)
            self.conversations_changed.emit()

    def clear_message_dedup_cache(self) -> None:
        """Clear only runtime duplicate guards, not persistent local data.

        The relay can legitimately resend the same encrypted envelopes during a
        from-beginning sync. If the user deleted local history in this GUI
        process, old envelope ids may still be remembered in RAM and would be
        skipped until restart. Clearing this cache lets SQLite rebuild history;
        SQLite primary keys still prevent duplicate local rows.
        """
        self.seen_message_ids.clear()
        self.seen_message_id_set.clear()

    async def connect_to_server(
        self,
        *,
        host: str,
        port: int,
        proxy_config: Socks5ProxyConfig | None = None,
    ) -> None:
        if self.identity is None:
            raise RuntimeError("load an identity before connecting")
        await self.disconnect()
        self.server_host = host
        self.server_port = port
        self.proxy_config = proxy_config
        self.stop_event = asyncio.Event()
        self.outbox = OutboundMultiplexer()
        self.connection_state_changed.emit("Connecting")
        try:
            self.reader, self.writer = await open_tcp_connection(host, port, proxy_config)
            await write_tcp_frame(self.writer, {"type": "hello", "id": self.local_public_id})
            self._create_task(self._outbound_sender(), "relay-outbound")
            self._create_task(self._receiver_loop(), "relay-receiver")
            self._create_task(self._auto_sync_loop(), "relay-auto-sync")
            self.connection_state_changed.emit("Connected")
        except Exception as exception:
            self.connection_state_changed.emit("Connection failed")
            self.error_happened.emit(str(exception))
            raise

    async def disconnect(self) -> None:
        if self.stop_event is not None:
            self.stop_event.set()
        try:
            await self.outbox.put_urgent(None)
        except Exception:
            pass
        for task in list(self.tasks):
            task.cancel()
        for task in list(self.file_tasks):
            task.cancel()
        if self.writer is not None:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass
        self.reader = None
        self.writer = None
        self.tasks.clear()
        self.file_tasks.clear()
        self.connection_state_changed.emit("Disconnected")

    def _create_task(self, coroutine: Any, name: str) -> asyncio.Task:
        task = asyncio.create_task(coroutine, name=name)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def _outbound_sender(self) -> None:
        if self.writer is None or self.stop_event is None:
            return
        try:
            while not self.stop_event.is_set():
                frame = await self.outbox.next_frame()
                if frame is None:
                    return
                await write_tcp_frame(self.writer, frame)
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
            return
        except Exception as exception:
            self.error_happened.emit(f"Send loop error: {exception}")

    async def _receiver_loop(self) -> None:
        if self.reader is None or self.stop_event is None:
            return
        try:
            while not self.stop_event.is_set():
                frame = await read_tcp_frame(self.reader)
                asyncio.create_task(self.handle_server_frame(frame))
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
            self.connection_state_changed.emit("Disconnected")
        except asyncio.CancelledError:
            raise
        except Exception as exception:
            self.error_happened.emit(f"Receive loop error: {exception}")
            self.connection_state_changed.emit("Disconnected")

    async def handle_server_frame(self, frame: dict[str, Any]) -> None:
        frame_type = frame.get("type")
        try:
            if frame_type == "hello_ok":
                await self.request_all_sync(
                    after_server_id=self.database.get_last_global_server_id(self.local_public_id),
                    silent=True,
                )
            elif frame_type == "ack":
                self.handle_ack(frame)
            elif frame_type == "message":
                await self.handle_message_frame(frame)
            elif frame_type == "sync_begin":
                self.sync_state_changed.emit("Syncing")
            elif frame_type == "sync_end":
                await self.handle_sync_end(frame)
            elif frame_type == "error":
                self.error_happened.emit(str(frame.get("error", "unknown server error")))
            elif frame_type == "pong":
                self.sync_state_changed.emit("pong")
        except Exception as exception:
            self.error_happened.emit(f"Failed to process server frame: {exception}")

    def handle_ack(self, frame: dict[str, Any]) -> None:
        client_message_id = frame.get("client_message_id")
        server_id = _parse_int(frame.get("server_id"), 0)
        if isinstance(client_message_id, str):
            self.database.update_message_status(
                identity_public_id=self.local_public_id,
                envelope_id=client_message_id,
                status="sent_to_server",
                server_id=server_id or None,
            )
        peer_id = frame.get("peer_id") or frame.get("to")
        if isinstance(peer_id, str) and is_valid_x25519_public_id(peer_id):
            self.database.update_sync_state(
                self.local_public_id, "conversation", peer_id, server_id
            )
            self.messages_changed.emit(peer_id)
        self.conversations_changed.emit()

    async def handle_sync_end(self, frame: dict[str, Any]) -> None:
        request_id = str(frame.get("request_id"))
        request_state = self.sync_requests.pop(request_id, {})
        count = _parse_int(frame.get("count"), 0)
        last_server_id = _parse_int(frame.get("last_server_id"), 0)
        has_more = bool(frame.get("has_more"))
        kind = request_state.get("kind")
        if kind == "all":
            self.database.update_sync_state(self.local_public_id, "global", "", last_server_id)
        elif kind == "conversation":
            peer_public_id = str(request_state.get("peer_public_id", ""))
            if peer_public_id:
                self.database.update_sync_state(
                    self.local_public_id, "conversation", peer_public_id, last_server_id
                )
        if has_more and last_server_id > 0:
            if kind == "all":
                await self.request_all_sync(after_server_id=last_server_id, silent=True)
            elif kind == "conversation":
                await self.request_conversation_sync(
                    str(request_state.get("peer_public_id", "")),
                    after_server_id=last_server_id,
                    silent=True,
                )
        else:
            self.sync_state_changed.emit("Sync complete" if count else "Already up to date")
        self.conversations_changed.emit()

    async def _auto_sync_loop(self) -> None:
        if self.stop_event is None:
            return
        while not self.stop_event.is_set():
            try:
                await asyncio.sleep(AUTO_SYNC_INTERVAL_SECONDS)
                await self.request_all_sync(
                    after_server_id=self.database.get_last_global_server_id(self.local_public_id),
                    silent=True,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                self.error_happened.emit(f"Auto-sync failed: {exception}")

    async def request_conversation_sync(
        self, peer_public_id: str, after_server_id: int = 0, *, silent: bool = False
    ) -> None:
        if not peer_public_id or not is_valid_x25519_public_id(peer_public_id):
            return
        request_id = uuid.uuid4().hex
        self.sync_requests[request_id] = {
            "kind": "conversation",
            "peer_public_id": peer_public_id,
            "silent": silent,
        }
        await self.outbox.put_urgent(
            {
                "type": "sync_conversation",
                "peer_id": peer_public_id,
                "after_server_id": max(0, int(after_server_id)),
                "limit": SYNC_PAGE_LIMIT,
                "request_id": request_id,
            }
        )

    async def request_all_sync(self, after_server_id: int = 0, *, silent: bool = False) -> None:
        request_id = uuid.uuid4().hex
        self.sync_requests[request_id] = {"kind": "all", "silent": silent}
        await self.outbox.put_urgent(
            {
                "type": "sync_all",
                "after_server_id": max(0, int(after_server_id)),
                "limit": SYNC_PAGE_LIMIT,
                "request_id": request_id,
            }
        )

    async def ping(self) -> None:
        await self.outbox.put_urgent({"type": "ping"})

    async def send_chat_message(self, peer_public_id: str, message_text: str) -> None:
        peer_public_id = normalize_public_id(peer_public_id)
        if not is_valid_x25519_public_id(peer_public_id):
            raise ValueError("invalid peer public id")
        if not message_text.strip():
            return
        payload = {
            "kind": "chat",
            "text": message_text,
            "created_at_ms": current_time_ms(),
        }
        delivery_envelope = encrypt_box(
            envelope_kind="chat",
            payload=payload,
            sender_private_key=self.identity.private_key,  # type: ignore[union-attr]
            sender_id=self.local_public_id,
            recipient_id=peer_public_id,
        )
        self_copy_envelope = encrypt_box(
            envelope_kind="chat",
            payload=payload,
            sender_private_key=self.identity.private_key,  # type: ignore[union-attr]
            sender_id=self.local_public_id,
            recipient_id=self.local_public_id,
        )
        self.database.save_message(
            identity_public_id=self.local_public_id,
            envelope_id=str(self_copy_envelope["id"]),
            peer_public_id=peer_public_id,
            server_id=None,
            direction="outgoing",
            kind="chat",
            copy_role="self_copy",
            text=message_text,
            created_at_ms=payload["created_at_ms"],
            status="queued",
            selected_peer_public_id=self.selected_peer_public_id,
        )
        self.remember_message_id(str(self_copy_envelope["id"]))
        self.messages_changed.emit(peer_public_id)
        self.conversations_changed.emit()
        await self.outbox.put_urgent({"type": "send", "to": peer_public_id, "envelope": delivery_envelope})
        await self.outbox.put_urgent(
            {
                "type": "send_self_copy",
                "peer_id": peer_public_id,
                "envelope": self_copy_envelope,
            }
        )

    def start_file_send_task(self, peer_public_id: str, file_path: Path) -> None:
        task = asyncio.create_task(self.send_file(peer_public_id, file_path))
        self.file_tasks.add(task)
        task.add_done_callback(self.file_tasks.discard)

    async def send_file(self, peer_public_id: str, file_path: Path) -> None:
        file_id: str | None = None
        try:
            peer_public_id = normalize_public_id(peer_public_id)
            if not is_valid_x25519_public_id(peer_public_id):
                raise ValueError("invalid peer public id")
            file_path = Path(os.path.expandvars(str(file_path))).expanduser().resolve()
            if not file_path.exists() or not file_path.is_file():
                raise FileNotFoundError(str(file_path))
            file_sha256, file_size = await asyncio.to_thread(calculate_file_sha256_and_size, file_path)
            total_chunks = total_chunks_for_size(file_size)
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
            delivery_start = encrypt_box(
                envelope_kind="file_start",
                payload=file_start_payload,
                sender_private_key=self.identity.private_key,  # type: ignore[union-attr]
                sender_id=self.local_public_id,
                recipient_id=peer_public_id,
            )
            self_copy_start_payload = dict(file_start_payload)
            self_copy_start_payload["file_key"] = base64url_encode(self_copy_file_key)
            self_copy_start_payload["nonce_prefix"] = base64url_encode(self_copy_nonce_prefix)
            self_copy_start = encrypt_box(
                envelope_kind="file_start",
                payload=self_copy_start_payload,
                sender_private_key=self.identity.private_key,  # type: ignore[union-attr]
                sender_id=self.local_public_id,
                recipient_id=self.local_public_id,
            )

            self.database.upsert_attachment(
                identity_public_id=self.local_public_id,
                file_id=file_id,
                peer_public_id=peer_public_id,
                direction="outgoing",
                filename=file_path.name,
                size=file_size,
                sha256=file_sha256,
                local_path=str(file_path),
                total_chunks=total_chunks,
                completed_chunks=0,
                bytes_done=0,
                status="queued",
            )
            self.database.save_message(
                identity_public_id=self.local_public_id,
                envelope_id=str(self_copy_start["id"]),
                peer_public_id=peer_public_id,
                server_id=None,
                direction="outgoing",
                kind="file_start",
                copy_role="self_copy",
                text=f"[file:{file_id}] {file_path.name}",
                created_at_ms=file_start_payload["created_at_ms"],
                status="queued",
                selected_peer_public_id=self.selected_peer_public_id,
            )
            self.file_progress_changed.emit(
                self._file_progress_dict(file_id, file_path.name, 0, file_size, "queued")
            )
            await self.outbox.put_urgent({"type": "send", "to": peer_public_id, "envelope": delivery_start})
            await self.outbox.put_urgent(
                {"type": "send_self_copy", "peer_id": peer_public_id, "envelope": self_copy_start}
            )
            self.remember_message_id(str(self_copy_start["id"]))

            queued_bytes = 0
            sequence_number = 0
            with file_path.open("rb") as file_handle:
                while True:
                    plaintext_chunk = await asyncio.to_thread(file_handle.read, CHUNK_SIZE)
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
                    self_copy_file_chunk = encrypt_file_chunk(
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
                            "envelope": self_copy_file_chunk,
                        },
                    )
                    self.remember_message_id(str(self_copy_file_chunk["id"]))
                    queued_bytes += len(plaintext_chunk)
                    sequence_number += 1
                    self.database.upsert_attachment(
                        identity_public_id=self.local_public_id,
                        file_id=file_id,
                        peer_public_id=peer_public_id,
                        direction="outgoing",
                        filename=file_path.name,
                        size=file_size,
                        sha256=file_sha256,
                        local_path=str(file_path),
                        total_chunks=total_chunks,
                        completed_chunks=sequence_number,
                        bytes_done=queued_bytes,
                        status="sending",
                    )
                    self.file_progress_changed.emit(
                        self._file_progress_dict(file_id, file_path.name, queued_bytes, file_size, "sending")
                    )
            self.database.upsert_attachment(
                identity_public_id=self.local_public_id,
                file_id=file_id,
                peer_public_id=peer_public_id,
                direction="outgoing",
                filename=file_path.name,
                size=file_size,
                sha256=file_sha256,
                local_path=str(file_path),
                total_chunks=total_chunks,
                completed_chunks=total_chunks,
                bytes_done=file_size,
                status="sent_to_server_queue",
            )
            self.file_progress_changed.emit(
                self._file_progress_dict(file_id, file_path.name, file_size, file_size, "sent_to_server_queue")
            )
            self.messages_changed.emit(peer_public_id)
            self.conversations_changed.emit()
        except asyncio.CancelledError:
            raise
        except Exception as exception:
            self.error_happened.emit(f"File send failed: {exception}")
            if file_id:
                self.file_progress_changed.emit(
                    self._file_progress_dict(file_id, Path(file_path).name, 0, 0, "failed")
                )
        finally:
            if file_id is not None:
                await self.outbox.finish_bulk_stream(file_id)

    async def handle_message_frame(self, frame: dict[str, Any]) -> None:
        envelope = frame.get("envelope")
        if not isinstance(envelope, dict):
            return
        message_id = envelope.get("id")
        if not isinstance(message_id, str):
            return
        # Do not let the process-local dedup cache hide server history after
        # local deletion/re-add. If SQLite no longer has this envelope, process
        # it again even if the id was seen earlier in this GUI process.
        if self.has_seen_message_id(message_id) and self.database.has_message(
            self.local_public_id,
            message_id,
        ):
            return
        self.remember_message_id(message_id)
        server_id = _parse_int(frame.get("server_id"), 0)
        envelope_kind = envelope.get("kind")
        sender_id = envelope.get("from")
        conversation_peer_id = self._conversation_peer_from_frame(frame)
        if conversation_peer_id is None:
            return
        self._ensure_discovered_contact(conversation_peer_id)
        if server_id > 0:
            self.database.update_sync_state(self.local_public_id, "global", "", server_id)
            self.database.update_sync_state(
                self.local_public_id, "conversation", conversation_peer_id, server_id
            )

        if envelope_kind == "chat":
            if envelope.get("to") != self.local_public_id:
                return
            payload = decrypt_box(
                envelope=envelope,
                recipient_private_key=self.identity.private_key,  # type: ignore[union-attr]
                local_public_id=self.local_public_id,
            )
            message_text = str(payload.get("text", ""))
            direction = "outgoing" if frame.get("copy_role") == "self_copy" else "incoming"
            self.database.save_message(
                identity_public_id=self.local_public_id,
                envelope_id=message_id,
                peer_public_id=conversation_peer_id,
                server_id=server_id or None,
                direction=direction,
                kind="chat",
                copy_role=frame.get("copy_role"),
                text=message_text,
                created_at_ms=_parse_optional_int(payload.get("created_at_ms")),
                status="synced",
                selected_peer_public_id=self.selected_peer_public_id,
            )
            self.messages_changed.emit(conversation_peer_id)
            self.conversations_changed.emit()
        elif envelope_kind == "file_start":
            if envelope.get("to") != self.local_public_id:
                return
            payload = decrypt_box(
                envelope=envelope,
                recipient_private_key=self.identity.private_key,  # type: ignore[union-attr]
                local_public_id=self.local_public_id,
            )
            await self._start_receiving_file(sender_id=str(sender_id), payload=payload, frame=frame)
            direction = "outgoing" if frame.get("copy_role") == "self_copy" else "incoming"
            file_id = str(payload.get("file_id", ""))
            filename = str(payload.get("filename", "file.bin"))
            self.database.save_message(
                identity_public_id=self.local_public_id,
                envelope_id=message_id,
                peer_public_id=conversation_peer_id,
                server_id=server_id or None,
                direction=direction,
                kind="file_start",
                copy_role=frame.get("copy_role"),
                text=f"[file:{file_id}] {filename}",
                created_at_ms=_parse_optional_int(payload.get("created_at_ms")),
                status="synced",
                selected_peer_public_id=self.selected_peer_public_id,
            )
            self.messages_changed.emit(conversation_peer_id)
            self.conversations_changed.emit()
        elif envelope_kind == "file_chunk":
            if envelope.get("to") != self.local_public_id:
                return
            await self._handle_file_chunk(envelope=envelope)

    def _conversation_peer_from_frame(self, frame: dict[str, Any]) -> str | None:
        copy_role = frame.get("copy_role")
        if copy_role == "self_copy" and isinstance(frame.get("conversation_peer_id"), str):
            return str(frame["conversation_peer_id"])
        sender_id = frame.get("from")
        recipient_id = frame.get("to")
        if sender_id == self.local_public_id and isinstance(recipient_id, str):
            return recipient_id
        if recipient_id == self.local_public_id and isinstance(sender_id, str):
            return sender_id
        return None

    def _ensure_discovered_contact(self, peer_public_id: str) -> None:
        if peer_public_id == self.local_public_id or not is_valid_x25519_public_id(peer_public_id):
            return
        self.database.upsert_contact(
            identity_public_id=self.local_public_id,
            peer_public_id=peer_public_id,
            peer_base58=public_id_to_base58(peer_public_id),
            fingerprint=fingerprint_for_public_id(peer_public_id),
            alias="",
            verified=False,
        )

    async def _start_receiving_file(
        self, *, sender_id: str, payload: dict[str, Any], frame: dict[str, Any]
    ) -> None:
        file_id = str(payload["file_id"])
        conversation_peer_id = self._conversation_peer_from_frame(frame)
        if not conversation_peer_id:
            return
        if file_id in self.completed_file_ids or file_id in self.active_files:
            return
        filename = safe_filename(str(payload.get("filename", "file.bin")))
        expected_size = int(payload.get("size", 0))
        expected_sha256 = str(payload.get("sha256", ""))
        total_chunks = int(payload.get("total_chunks", 0))
        file_key = base64url_decode(str(payload["file_key"]))
        nonce_prefix = base64url_decode(str(payload["nonce_prefix"]))
        destination_path = unique_path(self.download_dir / f"{file_id[:12]}_{filename}")
        await asyncio.to_thread(destination_path.write_bytes, b"")
        direction = "outgoing" if frame.get("copy_role") == "self_copy" else "incoming"
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
            peer_public_id=conversation_peer_id,
            direction=direction,
        )
        self.active_files[file_id] = receiving_file
        self.database.upsert_attachment(
            identity_public_id=self.local_public_id,
            file_id=file_id,
            peer_public_id=conversation_peer_id,
            direction=direction,
            filename=filename,
            size=expected_size,
            sha256=expected_sha256,
            local_path=str(destination_path),
            total_chunks=total_chunks,
            completed_chunks=0,
            bytes_done=0,
            status="receiving",
        )
        self.file_progress_changed.emit(
            self._file_progress_dict(file_id, filename, 0, expected_size, "receiving")
        )
        if total_chunks == 0:
            await self._finish_file_if_complete(receiving_file, conversation_peer_id, direction)

    async def _handle_file_chunk(self, *, envelope: dict[str, Any]) -> None:
        file_id = str(envelope["file_id"])
        if file_id in self.completed_file_ids:
            return
        receiving_file = self.active_files.get(file_id)
        if receiving_file is None:
            return
        plaintext_chunk = decrypt_file_chunk(
            envelope=envelope,
            file_key=receiving_file.file_key,
            sender_id=receiving_file.sender_id,
            recipient_id=self.local_public_id,
        )
        sequence_number = int(envelope["seq"])
        async with receiving_file.lock:
            if receiving_file.is_completed or sequence_number < receiving_file.next_expected_sequence:
                return
            receiving_file.pending_chunks[sequence_number] = plaintext_chunk
            while receiving_file.next_expected_sequence in receiving_file.pending_chunks:
                chunk = receiving_file.pending_chunks.pop(receiving_file.next_expected_sequence)
                await asyncio.to_thread(_append_bytes, receiving_file.destination_path, chunk)
                receiving_file.hasher.update(chunk)
                receiving_file.bytes_written += len(chunk)
                receiving_file.next_expected_sequence += 1
            progress = self._file_progress_dict(
                file_id,
                receiving_file.filename,
                receiving_file.bytes_written,
                receiving_file.expected_size,
                "receiving",
            )
            self.file_progress_changed.emit(progress)
            conversation_peer_id = receiving_file.peer_public_id
            direction = receiving_file.direction
            self.database.upsert_attachment(
                identity_public_id=self.local_public_id,
                file_id=file_id,
                peer_public_id=conversation_peer_id,
                direction=direction,
                filename=receiving_file.filename,
                size=receiving_file.expected_size,
                sha256=receiving_file.expected_sha256,
                local_path=str(receiving_file.destination_path),
                total_chunks=receiving_file.total_chunks,
                completed_chunks=receiving_file.next_expected_sequence,
                bytes_done=receiving_file.bytes_written,
                status="receiving",
            )
            await self._finish_file_if_complete(receiving_file, conversation_peer_id, direction)

    async def _finish_file_if_complete(
        self, receiving_file: ReceivingFile, peer_public_id: str, direction: str
    ) -> None:
        if receiving_file.is_completed:
            return
        if receiving_file.next_expected_sequence != receiving_file.total_chunks:
            return
        actual_sha256 = receiving_file.hasher.hexdigest()
        if receiving_file.bytes_written != receiving_file.expected_size:
            status = "size_failed"
        elif actual_sha256 != receiving_file.expected_sha256:
            status = "sha256_failed"
        else:
            status = "saved"
        receiving_file.is_completed = True
        self.completed_file_ids.add(receiving_file.file_id)
        self.active_files.pop(receiving_file.file_id, None)
        self.database.upsert_attachment(
            identity_public_id=self.local_public_id,
            file_id=receiving_file.file_id,
            peer_public_id=peer_public_id,
            direction=direction,
            filename=receiving_file.filename,
            size=receiving_file.expected_size,
            sha256=receiving_file.expected_sha256,
            local_path=str(receiving_file.destination_path),
            total_chunks=receiving_file.total_chunks,
            completed_chunks=receiving_file.total_chunks,
            bytes_done=receiving_file.bytes_written,
            status=status,
        )
        self.file_progress_changed.emit(
            self._file_progress_dict(
                receiving_file.file_id,
                receiving_file.filename,
                receiving_file.bytes_written,
                receiving_file.expected_size,
                status,
            )
        )

    @staticmethod
    def _file_progress_dict(
        file_id: str, filename: str, bytes_done: int, total_bytes: int, status: str
    ) -> dict[str, Any]:
        return {
            "file_id": file_id,
            "filename": filename,
            "bytes_done": bytes_done,
            "total_bytes": total_bytes,
            "status": status,
        }

    def has_seen_message_id(self, message_id: str) -> bool:
        return message_id in self.seen_message_id_set

    def remember_message_id(self, message_id: str) -> None:
        self.seen_message_ids.append(message_id)
        self.seen_message_id_set.add(message_id)
        while len(self.seen_message_ids) > MAX_TRACKED_MESSAGE_IDS:
            old_message_id = self.seen_message_ids.popleft()
            self.seen_message_id_set.discard(old_message_id)


def _append_bytes(path: Path, data: bytes) -> None:
    with path.open("ab") as file_handle:
        file_handle.write(data)


def _parse_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _parse_optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


# ===== gui/main_window.py =====

import asyncio
import os
from pathlib import Path

from PyQt6.QtCore import QItemSelection, QModelIndex, Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QAction, QDesktopServices, QKeyEvent
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListView,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
    QComboBox,
    QDialog,
)



class ComposerTextEdit(QTextEdit):
    send_requested = pyqtSignal()
    files_dropped = pyqtSignal(list)

    def __init__(self) -> None:
        super().__init__()
        self.setAcceptDrops(True)
        self.setPlaceholderText("Type a message. Press Enter to send, Shift+Enter for a new line. You can also drag files here.")
        self.setMaximumHeight(112)

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and not (
            event.modifiers() & Qt.KeyboardModifier.ShiftModifier
        ):
            self.send_requested.emit()
            return
        super().keyPressEvent(event)

    def dragEnterEvent(self, event) -> None:  # noqa: ANN001,N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event) -> None:  # noqa: ANN001,N802
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        paths = [path for path in paths if path]
        if paths:
            self.files_dropped.emit(paths)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)


class MessageListView(QListView):
    files_dropped = pyqtSignal(list)

    def __init__(self) -> None:
        super().__init__()
        self.setAcceptDrops(True)
        self.setUniformItemSizes(False)
        self.setVerticalScrollMode(QListView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSelectionMode(QListView.SelectionMode.SingleSelection)
        self.setSpacing(4)

    def dragEnterEvent(self, event) -> None:  # noqa: ANN001,N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event) -> None:  # noqa: ANN001,N802
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        paths = [path for path in paths if path]
        if paths:
            self.files_dropped.emit(paths)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)




class IdentityCardFrame(QFrame):
    copy_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.DefaultContextMenu)

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.MouseButton.LeftButton:
            self.copy_requested.emit()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def contextMenuEvent(self, event):  # type: ignore[override]
        menu = QMenu(self)
        action = menu.addAction("Copy Full Public Key")
        chosen = menu.exec(event.globalPos())
        if chosen == action:
            self.copy_requested.emit()
        event.accept()

class MainWindow(QMainWindow):
    def __init__(self, database: LocalDatabase, relay_client: RelayClient, async_runner: AsyncRunner):
        super().__init__()
        self.database = database
        self.relay = relay_client
        self.async_runner = async_runner
        self.current_identity_public_id: str | None = None
        self.current_peer_public_id: str | None = None
        self._refreshing_conversations = False
        self._async_connection_lock: asyncio.Lock | None = None

        self.conversation_model = ConversationListModel(database)
        self.message_model = MessageListModel(database)

        self.setWindowTitle("x25519 Relay Messenger")
        self.resize(1220, 800)
        self.setMinimumSize(960, 620)
        self._build_ui()
        self._connect_signals()
        self._restore_settings()
        self.reload_identities()
        self.refresh_conversations()

    def _build_ui(self) -> None:
        QApplication.instance().setStyleSheet(APP_QSS)  # type: ignore[union-attr]
        toolbar = QToolBar("Connection")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        self.app_title = QLabel("x25519 Relay")
        self.app_title.setObjectName("AppTitle")
        toolbar.addWidget(self.app_title)
        toolbar.addSeparator()

        toolbar.addWidget(QLabel("Identity"))
        self.identity_combo = QComboBox()
        self.identity_combo.setObjectName("IdentityCombo")
        self.identity_combo.setMinimumWidth(360)
        self.identity_combo.setMaximumWidth(560)
        self.identity_combo.setMinimumContentsLength(28)
        self.identity_combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.identity_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.identity_combo.setToolTip("Select the current local identity. The list shows the alias, public-key prefix/suffix, and fingerprint.")
        self.identity_combo.view().setMinimumWidth(620)
        self.identity_combo.view().setTextElideMode(Qt.TextElideMode.ElideMiddle)
        toolbar.addWidget(self.identity_combo)

        self.create_identity_button = QPushButton("New Identity")
        toolbar.addWidget(self.create_identity_button)
        self.import_identity_button = QPushButton("Import")
        toolbar.addWidget(self.import_identity_button)
        self.copy_identity_button = QPushButton("Copy Public Key")
        toolbar.addWidget(self.copy_identity_button)
        self.export_identity_button = QPushButton("Export Identity")
        toolbar.addWidget(self.export_identity_button)
        self.delete_identity_button = QPushButton("Delete Identity")
        self.delete_identity_button.setObjectName("DangerButton")
        toolbar.addWidget(self.delete_identity_button)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)

        self.connect_button = QPushButton("Disconnected")
        self.connect_button.setObjectName("ConnectButton")
        self.connect_button.setProperty("connectionState", "disconnected")
        self.connect_button.setToolTip("Click to connect to the server. All messages will sync automatically after connection succeeds.")
        toolbar.addWidget(self.connect_button)
        self.sync_button = QPushButton("Sync Messages")
        self.sync_button.setToolTip("Sync the current contact. If no contact is selected, sync all messages. If disconnected, connect automatically first.")
        toolbar.addWidget(self.sync_button)

        root = QSplitter(Qt.Orientation.Horizontal)
        root.setHandleWidth(1)
        self.setCentralWidget(root)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setMinimumWidth(300)
        sidebar.setMaximumWidth(420)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 16, 14, 16)
        sidebar_layout.setSpacing(12)

        self.identity_card = IdentityCardFrame()
        self.identity_card.setObjectName("IdentityCard")
        identity_layout = QVBoxLayout(self.identity_card)
        identity_layout.setContentsMargins(14, 12, 14, 12)
        identity_layout.setSpacing(10)
        self.identity_label = QLabel("No identity yet")
        self.identity_label.setWordWrap(True)
        # Do not copy the displayed text directly because it is intentionally truncated; copying must use the full public_base58 field.
        self.identity_label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        identity_layout.addWidget(self.identity_label)
        self.identity_card_copy_button = QPushButton("Copy Full Public Key")
        self.identity_card_copy_button.setObjectName("SoftButton")
        identity_layout.addWidget(self.identity_card_copy_button)
        sidebar_layout.addWidget(self.identity_card)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search conversations or public keys")
        sidebar_layout.addWidget(self.search_edit)

        top_buttons = QHBoxLayout()
        self.add_contact_button = QPushButton("+ Add Contact")
        self.contact_detail_button = QPushButton("Details")
        top_buttons.addWidget(self.add_contact_button, 1)
        top_buttons.addWidget(self.contact_detail_button)
        sidebar_layout.addLayout(top_buttons)

        self.conversation_list = QListView()
        self.conversation_list.setModel(self.conversation_model)
        self.conversation_list.setItemDelegate(ConversationDelegate(self.conversation_list))
        self.conversation_list.setVerticalScrollMode(QListView.ScrollMode.ScrollPerPixel)
        self.conversation_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.conversation_list.setEditTriggers(QListView.EditTrigger.NoEditTriggers)
        self.conversation_list.setSelectionMode(QListView.SelectionMode.SingleSelection)
        self.conversation_list.setMouseTracking(True)
        self.conversation_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        sidebar_layout.addWidget(self.conversation_list, 1)
        root.addWidget(sidebar)

        chat_panel = QFrame()
        chat_panel.setObjectName("ChatPanel")
        chat_layout = QVBoxLayout(chat_panel)
        chat_layout.setContentsMargins(18, 16, 18, 16)
        chat_layout.setSpacing(12)

        self.peer_header = QFrame()
        self.peer_header.setObjectName("PeerHeader")
        header_layout = QHBoxLayout(self.peer_header)
        header_layout.setContentsMargins(16, 12, 16, 12)
        peer_text_layout = QVBoxLayout()
        self.peer_title = QLabel("Select a conversation")
        self.peer_title.setObjectName("PeerTitle")
        self.peer_subtitle = QLabel("Local cache is shown at startup; after connecting to the server, incremental sync runs automatically.")
        self.peer_subtitle.setObjectName("MutedLabel")
        self.peer_subtitle.setWordWrap(True)
        self.peer_subtitle.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        peer_text_layout.addWidget(self.peer_title)
        peer_text_layout.addWidget(self.peer_subtitle)
        header_layout.addLayout(peer_text_layout, 1)
        chat_layout.addWidget(self.peer_header)

        self.message_list = MessageListView()
        self.message_list.setModel(self.message_model)
        self.message_delegate = MessageBubbleDelegate(self.database, self.message_list)
        self.message_list.setItemDelegate(self.message_delegate)
        self.message_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        chat_layout.addWidget(self.message_list, 1)

        self.composer = QFrame()
        self.composer.setObjectName("Composer")
        composer_layout = QHBoxLayout(self.composer)
        composer_layout.setContentsMargins(12, 10, 12, 10)
        composer_layout.setSpacing(10)
        self.input_edit = ComposerTextEdit()
        composer_layout.addWidget(self.input_edit, 1)
        action_layout = QVBoxLayout()
        self.attach_button = QPushButton("File")
        self.send_button = QPushButton("Send")
        self.send_button.setObjectName("PrimaryButton")
        action_layout.addWidget(self.attach_button)
        action_layout.addWidget(self.send_button)
        composer_layout.addLayout(action_layout)
        chat_layout.addWidget(self.composer)

        root.addWidget(chat_panel)
        root.setStretchFactor(0, 1)
        root.setStretchFactor(1, 3)
        self.statusBar().showMessage("Disconnected")
        self.chat_font_slider_label = QLabel("Text")
        self.chat_font_slider_label.setToolTip("Chat text size")
        self.chat_font_slider = QSlider(Qt.Orientation.Horizontal)
        self.chat_font_slider.setObjectName("ChatFontSlider")
        self.chat_font_slider.setRange(18, 25)
        self.chat_font_slider.setValue(18)
        self.chat_font_slider.setFixedSize(54, 14)
        self.chat_font_slider.setToolTip("Only adjust chat text size; message boxes, borders, and layout are unchanged.")
        self.chat_font_slider.setStyleSheet(
            "QSlider#ChatFontSlider::groove:horizontal { height: 3px; border-radius: 1px; background: #D1C3B0; }"
            "QSlider#ChatFontSlider::handle:horizontal { width: 8px; height: 8px; margin: -3px 0; border-radius: 4px; background: #8A7353; }"
        )
        self.statusBar().addPermanentWidget(self.chat_font_slider_label)
        self.statusBar().addPermanentWidget(self.chat_font_slider)

        # Advanced connection controls are kept in the toolbar as compact fields.
        toolbar.addSeparator()
        toolbar.addWidget(QLabel("Server"))
        self.host_edit = QLineEdit("127.0.0.1")
        self.host_edit.setMaximumWidth(145)
        toolbar.addWidget(self.host_edit)
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(8765)
        self.port_spin.setMaximumWidth(92)
        toolbar.addWidget(self.port_spin)
        self.proxy_edit = QLineEdit()
        self.proxy_edit.setPlaceholderText("SOCKS5 optional")
        self.proxy_edit.setMaximumWidth(170)
        toolbar.addWidget(self.proxy_edit)

    def _connect_signals(self) -> None:
        self.create_identity_button.clicked.connect(self.create_new_identity)
        self.import_identity_button.clicked.connect(self.import_identity)
        self.copy_identity_button.clicked.connect(self.copy_identity_public_key)
        self.identity_card_copy_button.clicked.connect(self.copy_identity_public_key)
        self.identity_card.copy_requested.connect(self.copy_identity_public_key)
        self.export_identity_button.clicked.connect(self.export_identity)
        self.delete_identity_button.clicked.connect(self.delete_current_identity)
        self.identity_combo.currentIndexChanged.connect(self.on_identity_changed)
        self.search_edit.textChanged.connect(self.conversation_model.set_filter)
        self.add_contact_button.clicked.connect(self.add_contact)
        self.contact_detail_button.clicked.connect(self.show_contact_details)
        self.connect_button.clicked.connect(self.connect_or_disconnect)
        self.sync_button.clicked.connect(self.sync_current)
        self.conversation_list.selectionModel().selectionChanged.connect(self.on_conversation_selection_changed)
        self.send_button.clicked.connect(self.send_message)
        self.input_edit.send_requested.connect(self.send_message)
        self.attach_button.clicked.connect(self.choose_files)
        self.input_edit.files_dropped.connect(self.send_file_paths)
        self.message_list.files_dropped.connect(self.send_file_paths)
        self.message_list.doubleClicked.connect(self.open_message_attachment)
        self.message_list.customContextMenuRequested.connect(self.show_message_context_menu)
        self.conversation_list.customContextMenuRequested.connect(self.show_conversation_context_menu)
        self.chat_font_slider.valueChanged.connect(self.on_chat_font_size_changed)

        self.relay.connection_state_changed.connect(self.on_connection_state_changed)
        self.relay.sync_state_changed.connect(self.on_sync_state_changed)
        self.relay.error_happened.connect(self.show_error)
        self.relay.conversations_changed.connect(self.refresh_conversations)
        self.relay.messages_changed.connect(self.on_messages_changed)
        self.relay.file_progress_changed.connect(self.on_file_progress)
        self.async_runner.task_failed.connect(self.show_error)

    def _restore_settings(self) -> None:
        self.host_edit.setText(self.database.get_setting("server_host", "127.0.0.1"))
        try:
            self.port_spin.setValue(int(self.database.get_setting("server_port", "8765")))
        except ValueError:
            self.port_spin.setValue(8765)
        self.proxy_edit.setText(self.database.get_setting("socks5_proxy", ""))
        try:
            chat_font_size = int(self.database.get_setting("chat_font_size", "18"))
        except ValueError:
            chat_font_size = 18
        chat_font_size = max(18, min(25, chat_font_size))
        self.chat_font_slider.blockSignals(True)
        self.chat_font_slider.setValue(chat_font_size)
        self.chat_font_slider.blockSignals(False)
        self.message_delegate.set_chat_font_size(chat_font_size)

    def on_chat_font_size_changed(self, value: int) -> None:
        self.message_delegate.set_chat_font_size(value)
        self.database.set_setting("chat_font_size", str(self.message_delegate.chat_font_size))
        self.message_list.viewport().update()

    def _save_connection_settings(self) -> None:
        self.database.set_setting("server_host", self.host_edit.text().strip() or "127.0.0.1")
        self.database.set_setting("server_port", str(int(self.port_spin.value())))
        self.database.set_setting("socks5_proxy", self.proxy_edit.text().strip())

    @staticmethod
    def _identity_combo_text(record: IdentityRecord) -> str:
        public_key = record.public_base58.strip()
        if len(public_key) > 22:
            compact_public_key = f"{public_key[:12]}…{public_key[-8:]}"
        else:
            compact_public_key = public_key
        fingerprint_short = record.fingerprint[:19] if record.fingerprint else "No fingerprint"
        return f"{record.label} · {compact_public_key} · {fingerprint_short}"

    @staticmethod
    def _identity_combo_tooltip(record: IdentityRecord) -> str:
        return (
            f"Identity alias：{record.label}\n"
            f"Full public key：{record.public_base58}\n"
            f"Fingerprint：{record.fingerprint}"
        )

    def reload_identities(self) -> None:
        current_public_id = self.current_identity_public_id
        self.identity_combo.blockSignals(True)
        self.identity_combo.clear()
        identities = self.database.list_identities()
        for identity_record in identities:
            self.identity_combo.addItem(self._identity_combo_text(identity_record), identity_record.public_id)
            item_index = self.identity_combo.count() - 1
            self.identity_combo.setItemData(
                item_index,
                self._identity_combo_tooltip(identity_record),
                Qt.ItemDataRole.ToolTipRole,
            )
        self.identity_combo.setEnabled(bool(identities))
        self.identity_combo.blockSignals(False)
        if identities:
            target_public_id = current_public_id or identities[0].public_id
            self._select_identity(target_public_id)
            if self.identity_combo.currentIndex() < 0:
                self.identity_combo.setCurrentIndex(0)
            public_id = self.identity_combo.currentData()
            if isinstance(public_id, str):
                self.load_identity_record(public_id)
        else:
            self.identity_combo.blockSignals(True)
            self.identity_combo.addItem("No identity yet. Click “New Identity” or “Import”.", None)
            self.identity_combo.setCurrentIndex(0)
            self.identity_combo.blockSignals(False)
            self.identity_combo.setEnabled(False)
            self.current_identity_public_id = None
            self.identity_label.setText("No identity yet. Click “New Identity” to create one, or import an existing identity.json/private key.")
            self.identity_card.setToolTip("")
            self.identity_card_copy_button.setEnabled(False)
            self.delete_identity_button.setEnabled(False)
            self.conversation_model.set_identity(None)
            self.message_model.set_conversation(None, None)

    def load_identity_record(self, public_id: str) -> None:
        record = self.database.get_identity(public_id)
        if record is None:
            return
        identity = identity_from_private_key(private_key_from_base64url(record.private_key_b64))
        self.current_identity_public_id = identity.public_id
        self.current_peer_public_id = None
        self.relay.set_identity(identity)
        shown_key = record.public_base58 if len(record.public_base58) <= 34 else f"{record.public_base58[:28]}…"
        self.identity_label.setText(
            f"<b>{record.label}</b><br>"
            f"Public key: {shown_key}<br>"
            "<span style='color:#8F4D3E;'>Click the card or button to copy the full public key. Do not share your private key.</span>"
        )
        self.identity_card.setToolTip(f"Click to copy the full public key：{record.public_base58}")
        self.identity_card_copy_button.setEnabled(True)
        self.delete_identity_button.setEnabled(True)
        self.conversation_model.set_identity(identity.public_id)
        self.message_model.set_conversation(identity.public_id, None)
        self._update_peer_header(None)
        self.refresh_conversations()

    def on_identity_changed(self, index: int) -> None:
        public_id = self.identity_combo.itemData(index)
        if isinstance(public_id, str):
            self.load_identity_record(public_id)

    def create_new_identity(self) -> None:
        label, confirmed = QInputDialog.getText(self, "New Identity", "Identity alias:", text="My Identity")
        if not confirmed:
            return
        identity = create_identity()
        self.database.upsert_identity(
            public_id=identity.public_id,
            public_base58=identity.public_base58,
            private_key_b64=identity.private_key_b64,
            fingerprint=identity.fingerprint,
            label=label.strip() or "My Identity",
        )
        self.reload_identities()
        self._select_identity(identity.public_id)
        self.copy_text(identity.public_base58)
        QMessageBox.information(
            self,
            "Identity Created",
            f"The full public key / username has been copied to the clipboard:\n{identity.public_base58}\n\nNote: the private key is the identity. Since you said plaintext storage is acceptable, this version does not encrypt the private key, but do not share it.",
        )

    def import_identity(self) -> None:
        choice, confirmed = QInputDialog.getItem(
            self,
            "Import Identity",
            "Import method:",
            ["Choose identity.json", "Paste Base58 Private Key", "Paste Legacy base64url Private Key"],
            0,
            False,
        )
        if not confirmed:
            return
        try:
            if choice == "Choose identity.json":
                path, _ = QFileDialog.getOpenFileName(self, "Choose identity.json", "", "JSON (*.json);;All files (*)")
                if not path:
                    return
                identity = load_identity_json(Path(path))
            elif choice == "Paste Base58 Private Key":
                value, confirmed = QInputDialog.getMultiLineText(self, "Import Private Key", "Base58 private key:")
                if not confirmed or not value.strip():
                    return
                identity = identity_from_private_key(private_key_from_base58(value.strip()))
            else:
                value, confirmed = QInputDialog.getMultiLineText(self, "Import Private Key", "base64url private key:")
                if not confirmed or not value.strip():
                    return
                identity = identity_from_private_key(private_key_from_base64url(value.strip()))
            label, confirmed = QInputDialog.getText(self, "Identity alias", "Identity alias:", text="Import Identity")
            if not confirmed:
                label = "Import Identity"
            self.database.upsert_identity(
                public_id=identity.public_id,
                public_base58=identity.public_base58,
                private_key_b64=identity.private_key_b64,
                fingerprint=identity.fingerprint,
                label=label.strip() or "Import Identity",
            )
            self.reload_identities()
            self._select_identity(identity.public_id)
        except Exception as exception:
            self.show_error(f"Import failed: {exception}")

    def _select_identity(self, public_id: str) -> None:
        for index in range(self.identity_combo.count()):
            if self.identity_combo.itemData(index) == public_id:
                self.identity_combo.setCurrentIndex(index)
                return


    def delete_current_identity(self) -> None:
        if not self.current_identity_public_id:
            self.show_error("Select an identity first.")
            return
        identity_record = self.database.get_identity(self.current_identity_public_id)
        if identity_record is None:
            return
        message = (
            f"Delete local identity ‘{identity_record.label}’?\n\n"
            "This will delete this identity's contacts, conversations, local messages, attachment indexes, and sync state on this device."
            "Encrypted messages on the server will not be deleted, and files already downloaded to disk will not be physically removed."
        )
        answer = QMessageBox.question(
            self,
            "Delete Identity",
            message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        deleted_public_id = self.current_identity_public_id
        if self.relay.is_connected:
            self.run_async(self.relay.disconnect(), "Disconnect failed")
        self.database.delete_identity(deleted_public_id)
        self.current_identity_public_id = None
        self.current_peer_public_id = None
        self.relay.set_identity(None)
        self.relay.set_selected_peer(None)
        self.message_model.set_conversation(None, None)
        self.reload_identities()
        self.statusBar().showMessage("Local identity deleted.")


    def export_identity(self) -> None:
        if not self.current_identity_public_id:
            self.show_error("Create or select an identity first.")
            return
        record = self.database.get_identity(self.current_identity_public_id)
        if record is None:
            return
        identity = identity_from_private_key(private_key_from_base64url(record.private_key_b64))
        suggested = f"identity_{record.public_base58[:12]}.json"
        path, _ = QFileDialog.getSaveFileName(self, "Export identity.json", suggested, "JSON (*.json);;All files (*)")
        if not path:
            return
        try:
            save_identity_json(Path(path), identity)
            QMessageBox.information(self, "Export Complete", "Identity exported. This file contains the private key; store it safely and do not send it to anyone.")
        except Exception as exception:
            self.show_error(f"Export failed: {exception}")

    def current_identity_public_base58(self) -> str | None:
        if not self.current_identity_public_id:
            return None
        record = self.database.get_identity(self.current_identity_public_id)
        if record is not None and record.public_base58:
            return record.public_base58.strip()
        return public_id_to_base58(self.current_identity_public_id)

    def copy_identity_public_key(self) -> None:
        public_key = self.current_identity_public_base58()
        if not public_key:
            self.show_error("Create or select an identity first.")
            return
        # Important: copy the internal full public_base58, not the truncated display text from the QLabel.
        self.copy_text(public_key)
        self.statusBar().showMessage(f"Full public key copied: {public_key}")

    @staticmethod
    def copy_text(text: str) -> None:
        clipboard = QApplication.clipboard()
        # Explicitly write to the system clipboard; do not read any displayed QLabel text.
        clipboard.setText(text, QClipboard.Mode.Clipboard)
        # Linux/X11 also write to Selection for middle-click paste; Windows/macOS skip this automatically.
        if clipboard.supportsSelection():
            clipboard.setText(text, QClipboard.Mode.Selection)

    def add_contact(self) -> None:
        if not self.current_identity_public_id:
            self.show_error("Create or select an identity first.")
            return
        dialog = AddContactDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        result = dialog.result_value()
        if result is None:
            self.show_error("Invalid contact public key format.")
            return
        self.database.upsert_contact(
            identity_public_id=self.current_identity_public_id,
            peer_public_id=result.peer_public_id,
            peer_base58=public_id_to_base58(result.peer_public_id),
            fingerprint=fingerprint_for_public_id(result.peer_public_id),
            alias=result.alias,
            verified=result.verified,
            pinned=result.pinned,
        )
        self.refresh_conversations()
        index = self.conversation_model.index_for_peer(result.peer_public_id)
        if index.isValid():
            self.conversation_list.setCurrentIndex(index)
        # When a contact is newly added or re-added, sync this conversation from the beginning.
        # This lets historical encrypted messages still present on the server be fetched again after a local contact deletion and re-add.
        self.sync_peer_conversation(result.peer_public_id, from_beginning=True)

    def show_contact_details(self) -> None:
        if not self.current_identity_public_id or not self.current_peer_public_id:
            self.show_error("Select a conversation first.")
            return
        contact = self.database.get_contact(self.current_identity_public_id, self.current_peer_public_id)
        peer_base58 = public_id_to_base58(self.current_peer_public_id)
        fingerprint = fingerprint_for_public_id(self.current_peer_public_id)
        dialog = ContactDetailsDialog(contact, self.current_peer_public_id, peer_base58, fingerprint, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        alias, verified, pinned = dialog.values()
        if contact is None:
            self.database.upsert_contact(
                identity_public_id=self.current_identity_public_id,
                peer_public_id=self.current_peer_public_id,
                peer_base58=peer_base58,
                fingerprint=fingerprint,
                alias=alias,
                verified=verified,
                pinned=pinned,
            )
        else:
            self.database.update_contact(
                identity_public_id=self.current_identity_public_id,
                peer_public_id=self.current_peer_public_id,
                alias=alias,
                verified=verified,
                pinned=pinned,
            )
        self.refresh_conversations()
        self._update_peer_header(self.current_peer_public_id)

    def _connection_parameters(self) -> tuple[str, int, Socks5ProxyConfig | None]:
        self._save_connection_settings()
        host = self.host_edit.text().strip() or "127.0.0.1"
        port = int(self.port_spin.value())
        proxy_config = parse_socks5_proxy_config(self.proxy_edit.text())
        return host, port, proxy_config

    async def _ensure_connected(
        self,
        host: str,
        port: int,
        proxy_config: Socks5ProxyConfig | None,
    ) -> None:
        if self.relay.is_connected:
            return
        if self._async_connection_lock is None:
            self._async_connection_lock = asyncio.Lock()
        async with self._async_connection_lock:
            if not self.relay.is_connected:
                await self.relay.connect_to_server(host=host, port=port, proxy_config=proxy_config)

    async def _connect_and_sync_all(
        self,
        host: str,
        port: int,
        proxy_config: Socks5ProxyConfig | None,
        after_server_id: int,
        *,
        silent: bool = False,
    ) -> None:
        await self._ensure_connected(host, port, proxy_config)
        await self.relay.request_all_sync(after_server_id=after_server_id, silent=silent)

    async def _connect_and_sync_conversation(
        self,
        host: str,
        port: int,
        proxy_config: Socks5ProxyConfig | None,
        peer_public_id: str,
        after_server_id: int,
        *,
        silent: bool = False,
    ) -> None:
        await self._ensure_connected(host, port, proxy_config)
        await self.relay.request_conversation_sync(
            peer_public_id,
            after_server_id=after_server_id,
            silent=silent,
        )

    def connect_or_disconnect(self) -> None:
        if self.connect_button.property("connectionState") == "connecting":
            self.statusBar().showMessage("Connecting to the server, please wait…")
            return
        if self.relay.is_connected:
            self.run_async(self.relay.disconnect(), "Disconnect failed")
            self._set_connection_button_state("disconnected")
            return
        if not self.current_identity_public_id:
            self.show_error("Create or select an identity first.")
            return
        try:
            host, port, proxy_config = self._connection_parameters()
            after_server_id = self.database.get_last_global_server_id(self.current_identity_public_id)
            self._set_connection_button_state("connecting")
            self.statusBar().showMessage("Connecting to the server; all messages will sync automatically after connection…")
            self.run_async(
                self._connect_and_sync_all(host, port, proxy_config, after_server_id, silent=True),
                "Connection or sync failed",
            )
        except Exception as exception:
            self._set_connection_button_state("failed")
            self.show_error(f"Connection failed: {exception}")

    def sync_current(self) -> None:
        if not self.current_identity_public_id:
            self.show_error("Create or select an identity first.")
            return
        try:
            host, port, proxy_config = self._connection_parameters()
        except Exception as exception:
            self.show_error(f"Invalid connection configuration: {exception}")
            return
        if self.current_peer_public_id:
            peer_public_id = self.current_peer_public_id
            after_server_id = self.database.get_last_conversation_server_id(
                self.current_identity_public_id,
                peer_public_id,
            )
            self.statusBar().showMessage("Syncing messages for the current contact…")
            self.run_async(
                self._connect_and_sync_conversation(
                    host,
                    port,
                    proxy_config,
                    peer_public_id,
                    after_server_id,
                ),
                "Message sync failed",
            )
        else:
            after_server_id = self.database.get_last_global_server_id(self.current_identity_public_id)
            self.statusBar().showMessage("Syncing all messages…")
            self.run_async(
                self._connect_and_sync_all(host, port, proxy_config, after_server_id),
                "Message sync failed",
            )

    def sync_peer_conversation(
        self,
        peer_public_id: str,
        *,
        from_beginning: bool = False,
        silent: bool = False,
    ) -> None:
        if not self.current_identity_public_id:
            self.show_error("Create or select an identity first.")
            return
        if not peer_public_id:
            return
        try:
            host, port, proxy_config = self._connection_parameters()
        except Exception as exception:
            self.show_error(f"Invalid connection configuration: {exception}")
            return
        after_server_id = 0
        if from_beginning:
            # A manual full sync should rebuild from the relay, not be blocked
            # by in-memory ids remembered before local history was deleted.
            self.relay.clear_message_dedup_cache()
        else:
            after_server_id = self.database.get_last_conversation_server_id(
                self.current_identity_public_id,
                peer_public_id,
            )
        if not silent:
            if self.relay.is_connected:
                self.statusBar().showMessage("Syncing messages…")
            else:
                self.statusBar().showMessage("Connecting to the server and syncing messages…")
        self.run_async(
            self._connect_and_sync_conversation(
                host,
                port,
                proxy_config,
                peer_public_id,
                after_server_id,
                silent=silent,
            ),
            "Message sync failed",
        )

    def refresh_conversations(self) -> None:
        # Model reset can trigger selectionChanged in some Qt/PyQt builds. If that
        # selection handler starts a sync that emits conversations_changed, the refresh
        # path may recurse until Python hits RecursionError. Guard and reselect silently.
        if self._refreshing_conversations:
            return
        self._refreshing_conversations = True
        try:
            current_peer = self.current_peer_public_id
            self.conversation_model.reload()
            if current_peer:
                index = self.conversation_model.index_for_peer(current_peer)
                if index.isValid():
                    selection_model = self.conversation_list.selectionModel()
                    if selection_model is not None:
                        selection_model.blockSignals(True)
                    try:
                        self.conversation_list.setCurrentIndex(index)
                    finally:
                        if selection_model is not None:
                            selection_model.blockSignals(False)
        finally:
            self._refreshing_conversations = False

    def on_conversation_selection_changed(self, selected: QItemSelection, _deselected: QItemSelection) -> None:
        if self._refreshing_conversations:
            return
        indexes = selected.indexes()
        if not indexes:
            return
        index = indexes[0]
        record = index.data(ConversationRecordRole)
        if record is None:
            return
        self.current_peer_public_id = record.peer_public_id
        self.relay.set_selected_peer(record.peer_public_id)
        self._update_peer_header(record.peer_public_id)
        self.message_model.set_conversation(self.current_identity_public_id, record.peer_public_id)
        self._scroll_messages_to_bottom()
        self.sync_peer_conversation(record.peer_public_id, from_beginning=False, silent=True)

    def _update_peer_header(self, peer_public_id: str | None) -> None:
        if not peer_public_id or not self.current_identity_public_id:
            self.peer_title.setText("Select a conversation")
            self.peer_subtitle.setText("Local cache is shown at startup; after connecting to the server, incremental sync runs automatically.")
            return
        contact = self.database.get_contact(self.current_identity_public_id, peer_public_id)
        base58 = public_id_to_base58(peer_public_id)
        title = contact.alias if contact and contact.alias else base58[:18] + "…"
        self.peer_title.setText(title)
        self.peer_subtitle.setText(f"Public key: {base58}")

    def on_messages_changed(self, peer_public_id: str) -> None:
        if peer_public_id == self.current_peer_public_id:
            self.message_model.reload()
            self._scroll_messages_to_bottom()

    def _scroll_messages_to_bottom(self) -> None:
        self.message_list.scrollToBottom()

    def send_message(self) -> None:
        if not self.current_peer_public_id:
            self.show_error("Select a contact first.")
            return
        text = self.input_edit.toPlainText().strip()
        if not text:
            return
        self.input_edit.clear()
        self.run_async(self.relay.send_chat_message(self.current_peer_public_id, text), "Send failed")

    def choose_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Select files to send")
        self.send_file_paths(files)

    def send_file_paths(self, files: list[str]) -> None:
        if not self.current_peer_public_id:
            self.show_error("Select a contact first.")
            return
        for file_name in files:
            path = Path(file_name)
            if path.is_file():
                self.run_async(self.relay.send_file(self.current_peer_public_id, path), "File send failed")

    def open_message_attachment(self, index: QModelIndex) -> None:
        message: MessageRecord | None = index.data(MessageRecordRole)
        if not message or message.kind != "file_start":
            return
        file_id, _ = parse_file_token(message.text)
        attachment = self.database.get_attachment(message.peer_public_id, file_id)
        if not attachment or not attachment.local_path:
            self.statusBar().showMessage("This file does not have a local path yet")
            return
        path = Path(attachment.local_path)
        if path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        else:
            self.statusBar().showMessage("Local file does not exist")

    def show_conversation_context_menu(self, position) -> None:  # noqa: ANN001
        index = self.conversation_list.indexAt(position)
        if not index.isValid():
            return
        conversation_record = index.data(ConversationRecordRole)
        if conversation_record is None or not self.current_identity_public_id:
            return
        menu = QMenu(self)
        detail_action = QAction("Contact Details", self)
        sync_action = QAction("Sync Messages", self)
        export_action = QAction("Export Chat History", self)
        copy_key_action = QAction("Copy Peer Public Key", self)
        delete_action = QAction("Delete Contact", self)
        menu.addAction(detail_action)
        menu.addAction(sync_action)
        menu.addAction(export_action)
        menu.addAction(copy_key_action)
        menu.addSeparator()
        menu.addAction(delete_action)
        chosen_action = menu.exec(self.conversation_list.viewport().mapToGlobal(position))
        if chosen_action == detail_action:
            self.conversation_list.setCurrentIndex(index)
            self.show_contact_details()
        elif chosen_action == sync_action:
            self.conversation_list.setCurrentIndex(index)
            self.sync_peer_conversation(conversation_record.peer_public_id, from_beginning=True)
        elif chosen_action == export_action:
            self.conversation_list.setCurrentIndex(index)
            self.export_chat_history(conversation_record)
        elif chosen_action == copy_key_action:
            self.copy_text(conversation_record.peer_base58)
            self.statusBar().showMessage(f"Peer public key copied: {conversation_record.peer_base58}")
        elif chosen_action == delete_action:
            self.delete_contact(conversation_record)

    def export_chat_history(self, conversation_record: ConversationRecord) -> None:
        if not self.current_identity_public_id:
            self.show_error("Select an identity first.")
            return
        messages = self.database.list_messages_for_export(
            self.current_identity_public_id,
            conversation_record.peer_public_id,
        )
        if not messages:
            QMessageBox.information(self, "Export Chat History", "This contact currently has no local chat history to export.")
            return

        contact = self.database.get_contact(self.current_identity_public_id, conversation_record.peer_public_id)
        identity = self.database.get_identity(self.current_identity_public_id)
        display_name = conversation_record.display_name or (contact.alias if contact and contact.alias else conversation_record.peer_base58)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        suggested_name = safe_filename(f"chat_history_{display_name}_{timestamp}.txt")
        default_path = str(Path.home() / suggested_name)
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Export Chat History",
            default_path,
            "Text Files (*.txt);;All Files (*)",
        )
        if not file_name:
            return
        output_path = Path(file_name)
        if output_path.suffix.lower() != ".txt":
            output_path = output_path.with_suffix(".txt")

        try:
            export_text = self._build_chat_export_text(
                conversation_record=conversation_record,
                contact=contact,
                identity=identity,
                messages=messages,
            )
            output_path.write_text(export_text, encoding="utf-8", newline="\n")
        except Exception as exception:
            self.show_error(f"Failed to export chat history: {exception}")
            return

        self.statusBar().showMessage(f"Chat history exported: {output_path}")
        QMessageBox.information(self, "Export Chat History", f"Exported {len(messages)} local chat messages:\n\n{output_path}")

    def _build_chat_export_text(
        self,
        *,
        conversation_record: ConversationRecord,
        contact: ContactRecord | None,
        identity: IdentityRecord | None,
        messages: list[MessageRecord],
    ) -> str:
        peer_label = conversation_record.display_name or (contact.alias if contact and contact.alias else conversation_record.peer_base58)
        peer_base58 = conversation_record.peer_base58
        peer_fingerprint = conversation_record.fingerprint or (contact.fingerprint if contact else "")
        identity_label = identity.label if identity else "Current Identity"
        identity_base58 = identity.public_base58 if identity else public_id_to_base58(self.current_identity_public_id or "")
        identity_fingerprint = identity.fingerprint if identity else fingerprint_for_public_id(self.current_identity_public_id or "")

        lines: list[str] = [
            "x25519 Relay Chat History Export",
            "=" * 34,
            f"Export time：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Message count：{len(messages)}",
            "",
            "Local Identity",
            f"  Name：{identity_label}",
            f"  Public Key Base58：{identity_base58}",
            f"  Fingerprint：{identity_fingerprint}",
            "",
            "Contact",
            f"  Name：{peer_label}",
            f"  Public Key Base58：{peer_base58}",
            f"  Fingerprint：{peer_fingerprint}",
            "",
            "Notes",
            "  This file only exports locally saved chat history.",
            "  Attachment binary contents are not exported; file messages only include index metadata such as filename, size, SHA-256, and status.",
            "",
            "Chat History",
            "-" * 34,
        ]

        for message in messages:
            lines.extend(self._format_export_message(message))
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def _format_export_message(self, message: MessageRecord) -> list[str]:
        timestamp = full_date_time(message.created_at_ms)
        speaker = "Me" if message.direction == "outgoing" else "Peer" if message.direction == "incoming" else message.direction
        status_suffix = "" if message.status in {"synced", "sent", "delivered", "saved"} else f" · Status：{message.status}"
        if message.error:
            status_suffix += f" · Error：{message.error}"

        if message.kind == "file_start":
            file_id, fallback_name = parse_file_token(message.text)
            attachment = self.database.get_attachment(message.peer_public_id, file_id) if file_id else None
            filename = attachment.filename if attachment else fallback_name
            file_status = attachment.status if attachment else message.status
            result = [
                f"[{timestamp}] {speaker} sent a file{status_suffix}",
                f"    Filename：{filename}",
            ]
            if file_id:
                result.append(f"    File ID：{file_id}")
            if attachment:
                result.extend([
                    f"    Size：{human_file_size(attachment.size)} ({attachment.size} bytes)",
                    f"    SHA-256：{attachment.sha256 or 'Unknown'}",
                    f"    Chunks：{attachment.completed_chunks}/{attachment.total_chunks}",
                    f"    File status：{file_status}",
                ])
            else:
                result.append(f"    File status：{file_status}")
            result.append("    Attachment contents：not exported")
            return result

        text = message.text or ""
        if "\n" in text:
            return [f"[{timestamp}] {speaker}{status_suffix}:", indent_multiline_text(text)]
        return [f"[{timestamp}] {speaker}{status_suffix}: {text}"]

    def delete_contact(self, conversation_record: ConversationRecord) -> None:
        if not self.current_identity_public_id:
            self.show_error("Select an identity first.")
            return
        display_name = conversation_record.display_name or conversation_record.peer_base58
        message = (
            f"Delete contact ‘{display_name}’?\n\n"
            "This only deletes local data: contacts, conversations, local messages, and attachment indexes. Encrypted messages on the server will not be deleted."
        )
        answer = QMessageBox.question(
            self,
            "Delete Contact",
            message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        peer_public_id = conversation_record.peer_public_id
        self.database.delete_contact_and_local_history(self.current_identity_public_id, peer_public_id)
        # Local SQLite history is gone, but this process may still remember old
        # envelope ids in RAM. Without clearing them, re-adding this contact and
        # syncing history will silently skip those server-returned envelopes.
        self.relay.clear_message_dedup_cache()
        if self.current_peer_public_id == peer_public_id:
            self.current_peer_public_id = None
            self.relay.set_selected_peer(None)
            self.message_model.set_conversation(self.current_identity_public_id, None)
            self._update_peer_header(None)
        self.refresh_conversations()
        self.statusBar().showMessage("Local contact deleted.")

    def show_message_context_menu(self, position) -> None:  # noqa: ANN001
        index = self.message_list.indexAt(position)
        if not index.isValid():
            return
        message: MessageRecord | None = index.data(MessageRecordRole)
        if not message:
            return
        menu = QMenu(self)
        copy_action = QAction("Copy Text", self)
        copy_action.triggered.connect(lambda: self.copy_text(_copyable_text(message)))
        menu.addAction(copy_action)
        if message.kind == "file_start":
            open_action = QAction("Open File", self)
            open_action.triggered.connect(lambda: self.open_message_attachment(index))
            menu.addAction(open_action)
            folder_action = QAction("Open Containing Folder", self)
            folder_action.triggered.connect(lambda: self.open_attachment_folder(message))
            menu.addAction(folder_action)
        menu.exec(self.message_list.viewport().mapToGlobal(position))

    def open_attachment_folder(self, message: MessageRecord) -> None:
        file_id, _ = parse_file_token(message.text)
        attachment = self.database.get_attachment(message.peer_public_id, file_id)
        if not attachment or not attachment.local_path:
            return
        parent = Path(attachment.local_path).parent
        if parent.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(parent)))

    def on_file_progress(self, progress: dict) -> None:
        filename = progress.get("filename", "file")
        done = int(progress.get("bytes_done", 0) or 0)
        total = int(progress.get("total_bytes", 0) or 0)
        status = str(progress.get("status", ""))
        if total > 0:
            percent = int(done * 100 / total)
            self.statusBar().showMessage(f"File {filename}: {percent}% · {status}")
        else:
            self.statusBar().showMessage(f"File {filename}: {status}")
        if self.current_peer_public_id:
            self.message_model.reload()

    def _set_connection_button_state(self, state: str) -> None:
        state_text = {
            "connected": "Connected",
            "connecting": "Connecting",
            "failed": "Disconnected",
            "disconnected": "Disconnected",
        }.get(state, "Disconnected")
        self.connect_button.setText(state_text)
        self.connect_button.setProperty("connectionState", state)
        self.connect_button.style().unpolish(self.connect_button)
        self.connect_button.style().polish(self.connect_button)
        self.connect_button.update()

    def on_connection_state_changed(self, message: str) -> None:
        self.statusBar().showMessage(message)
        if message in {"Disconnected", "Disconnected"}:
            self._set_connection_button_state("disconnected")
        elif message == "Connection failed":
            self._set_connection_button_state("failed")
        elif message == "Connecting":
            self._set_connection_button_state("connecting")
        elif message == "Connected":
            self._set_connection_button_state("connected")

    def on_sync_state_changed(self, message: str) -> None:
        self.statusBar().showMessage(message)

    def show_error(self, message: str) -> None:
        QMessageBox.warning(self, "Error", message)


    def run_async(self, coroutine: Any, error_prefix: str = "Task failed") -> None:
        self.async_runner.submit(coroutine, error_prefix)


def _copyable_text(message: MessageRecord) -> str:
    if message.kind == "file_start":
        _, filename = parse_file_token(message.text)
        return filename
    return message.text or ""


# ===== single-file runtime glue =====
class AsyncRunner(QObject):
    task_failed = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self.loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, name="x25519-relay-asyncio", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def _run_loop(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self._ready.set()
        self.loop.run_forever()
        pending = asyncio.all_tasks(self.loop)
        for task in pending:
            task.cancel()
        if pending:
            self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        self.loop.close()

    def submit(self, coroutine: Any, error_prefix: str = "Task failed") -> Future:
        if self.loop is None:
            raise RuntimeError("asyncio loop is not ready")
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)

        def _done(done_future: Future) -> None:
            try:
                done_future.result()
            except asyncio.CancelledError:
                return
            except Exception as exception:
                self.task_failed.emit(f"{error_prefix}: {exception}")

        future.add_done_callback(_done)
        return future

    def stop(self) -> None:
        if self.loop is not None and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self._thread.is_alive():
            self._thread.join(timeout=3.0)


def default_data_dir() -> Path:
    if sys.platform.startswith("win"):
        root = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(root) / "x25519-relay-gui"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "x25519-relay-gui"
    return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "x25519-relay-gui"


def default_database_path() -> Path:
    return default_data_dir() / "client.sqlite3"


def default_download_dir() -> Path:
    return default_data_dir() / "downloads"


def main() -> None:
    application = QApplication(sys.argv)
    application.setApplicationName("x25519 Relay Messenger")
    application.setOrganizationName("x25519-relay")

    database = LocalDatabase(default_database_path())
    relay_client = RelayClient(database, default_download_dir())
    runner = AsyncRunner()
    runner.task_failed.connect(lambda message: None)  # ensure signal object is kept alive

    window = MainWindow(database, relay_client, runner)
    window.show()

    def shutdown() -> None:
        try:
            runner.submit(relay_client.disconnect(), "Failed to close connection").result(timeout=2.0)
        except Exception:
            pass
        try:
            database.close()
        except Exception:
            pass
        runner.stop()

    application.aboutToQuit.connect(shutdown)
    signal.signal(signal.SIGINT, lambda *_: application.quit())
    signal.signal(signal.SIGTERM, lambda *_: application.quit())
    sys.exit(application.exec())


if __name__ == "__main__":
    main()
