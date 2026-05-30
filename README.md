# x25519-relay 🔐

A minimal **No-KYC TCP relay** for end-to-end encrypted chat and file transfer using **X25519**, **HKDF-SHA256**, and **ChaCha20-Poly1305**.

Repository: `https://github.com/wangyifan349/x25519-relay`

`x25519-relay` is an accountless encrypted relay prototype. Users are identified by a locally generated X25519 keypair. The public key is the address/username, shown to users as Base58. The server is centralized, but it only stores and relays encrypted envelopes. It cannot read chat messages or file contents.

## ✨ Features

- 🔑 Local X25519 identity: no phone number, no email, no account registration, no KYC.
- 🔐 End-to-end encrypted chat using X25519 + HKDF-SHA256 + ChaCha20-Poly1305.
- 📁 End-to-end encrypted file transfer with chunking for large files.
- 🧩 `/send`, `/file`, and `/files` support one or many paths.
- 🔄 Persistent encrypted sync for chat and files.
- 🧾 Sender self-copies, so both incoming and outgoing history can sync back.
- 🧅 Optional SOCKS5 TCP proxy support for the client.
- 🧱 Plain TCP transport with a compact length-prefixed JSON frame protocol.
- 🗄️ SQLite server storage for encrypted envelopes.
- 🪪 Base58 display for public/private keys.
- 🖥️ Minimal terminal UI: sent messages show as `>>>`, received messages show as `<<<`.

## ⚡ One-line install

Basic dependency install:

```bash
python -m pip install "cryptography>=41"
```

Clone and install:

```bash
git clone https://github.com/wangyifan349/x25519-relay.git && cd x25519-relay && python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
git clone https://github.com/wangyifan349/x25519-relay.git; cd x25519-relay; py -m pip install -r requirements.txt
```

The current dependency list is intentionally small:

```text
cryptography>=41
```

SOCKS5 support is implemented directly in `client.py`, so no extra proxy package is required.

## 🚀 Quick start

Start the relay server:

```bash
python server.py
```

Start a client:

```bash
python client.py
```

On first run, the client creates `identity.json` and prints your identity:

```text
========== Your local identity ==========
WARNING: the private key is your identity secret. Do not share it.
private key base58: <your Base58 private key>
public key base58 / username: <your Base58 public key>
fingerprint: <short public-key fingerprint>
=========================================
```

Share only your public key. Never share your private key.

## 👥 How users connect

Each user runs `client.py`, copies their Base58 public key, and gives it to the other person through any channel. When the client asks:

```text
你现在想发给谁，请输入对方公钥/Base58:
```

paste the other user’s Base58 public key. The client also accepts the older internal base64url public id for compatibility. Internally, the protocol still uses the base64url form, but the user-facing key format is Base58.

## 🖥️ Server usage

Run:

```bash
python server.py
```

The server asks for listen address, port, SQLite database path, and several queue/frame limits. Defaults are suitable for local testing and small deployments.

Typical values:

```text
服务器监听地址 [0.0.0.0]:
服务器监听端口 [8765]:
SQLite 数据库文件 [messages.sqlite3]:
```

Runtime server data:

```text
messages.sqlite3
```

The server stores encrypted envelopes, routing metadata, timestamps, and sync metadata. It does not store plaintext messages or plaintext file bytes.

## 💬 Client usage

Run:

```bash
python client.py
```

The client asks:

```text
服务器地址 [127.0.0.1]:
服务器端口 [8765]:
你现在想发给谁，请输入对方公钥/Base58:
SOCKS5 TCP 代理，可选，留空不用，例如 127.0.0.1:1080:
```

Normal text input sends chat messages:

```text
hello
>>> hello
<<< hi
```

Commands:

```text
/help
/id
/fingerprint
/peerfp
/peerfp <public-key-or-base58>
/to <public-key-or-base58>
/sync [after_server_id]
/sync-all [after_server_id]
/ping
/quit
```

File commands:

```text
/send <path1> [path2 ...]
/file <path1> [path2 ...]
/files <path1> [path2 ...]
```

`/send`, `/file`, and `/files` are all file-transfer commands. They support single-file and multi-file sending.

Examples:

```text
/send ./a.txt
/send ./a.txt ./b.zip ./c.pdf
/file "/home/me/My File.txt"
/file "C:\Users\me\My File.txt"
/files "./a b.txt" './c d.pdf'
```

Windows paths and Linux/macOS paths are both supported. On Windows, the parser avoids treating backslashes in `C:\Users\...` as escape characters. On POSIX systems, quoted paths and escaped spaces are supported.

## 🔄 Sync model

The server persists encrypted envelopes in SQLite. The client syncs the selected conversation on connect, periodically after that, when switching peer with `/to`, and when `/sync` is run manually.

Since v9, every outgoing chat/file is stored as two encrypted copies:

```text
delivery copy -> encrypted for the peer
self copy     -> encrypted for the sender
```

This is necessary because file and chat envelopes use ephemeral X25519 keys. A delivery copy encrypted to the peer is for the peer to decrypt; the sender-owned self copy is for the sender to decrypt later during sync.

Synced chat displays as:

```text
>>> message I previously sent
<<< message I received
```

Files also sync. `file_start` metadata and every `file_chunk` are stored in both delivery-copy and self-copy form, so both sides can recover file history when using the same `identity.json`.

Compatibility note: full bidirectional sync works for v9+ messages and files. Older messages created before self-copy support may not be recoverable on the sender side if only the peer-encrypted delivery copy exists on the server.

## 📁 File transfer

Files are split into encrypted chunks instead of being sent as one huge frame. Current chunk size:

```text
64 KiB
```

Flow:

```text
file_start  -> encrypted file metadata
file_chunk  -> encrypted file data
file_chunk  -> encrypted file data
...
```

The encrypted `file_start` payload contains filename, file size, plaintext SHA-256, chunk size, total chunk count, file key, and nonce prefix. The server cannot read those fields. The receiver writes files to `downloads/` and verifies plaintext size and SHA-256 before accepting the final result.

## 🧱 Transport protocol

`x25519-relay` uses plain TCP, not WebSocket. Each frame is:

```text
4-byte big-endian length || UTF-8 JSON frame
```

Frame types include:

```text
hello, hello_ok, send, send_self_copy, message, ack, sync_conversation,
sync_all, sync_begin, sync_end, ping, pong, error
```

The client and server separate urgent traffic and bulk traffic. Chat, ACK, sync control, and file-start frames are urgent. File chunks are bulk. This helps large file transfers avoid blocking ordinary chat.

## 🔐 Cryptography

Chat and `file_start` metadata use:

```text
static_shared    = X25519(sender_identity_private, recipient_identity_public)
ephemeral_shared = X25519(sender_ephemeral_private, recipient_identity_public)
key              = HKDF-SHA256(static_shared || ephemeral_shared)
cipher           = ChaCha20-Poly1305
```

Each chat or `file_start` envelope gets a fresh ephemeral X25519 key. File chunks use a per-file random 32-byte key and ChaCha20-Poly1305. Chunk nonces are:

```text
4-byte random per-file prefix || 8-byte chunk sequence number
```

File integrity is checked using SHA-256 after decryption.

## 👀 What the server cannot see

The relay server cannot see:

```text
plaintext chat messages
plaintext file bytes
plaintext filenames
plaintext file SHA-256 hashes
file encryption keys
user private keys
```

The server stores encrypted envelopes and encrypted file chunks. It does not have the keys needed to decrypt them.

## 🧾 What the server can still see

End-to-end encryption does not hide all metadata. The server can still see:

```text
sender public id
recipient public id
conversation_peer_id
copy_role: delivery or self_copy
message kind: chat, file_start, or file_chunk
server timestamps
encrypted envelope size
file chunk sequence numbers
file id for chunk grouping
traffic timing
client source IP, unless the client uses a proxy
```

With SOCKS5 enabled, the relay server sees the proxy IP instead of the user’s direct IP. The proxy itself can still see the user IP and the target relay server. This project is No-KYC and minimal-collection, but it is not a complete anonymity network.

## 🧅 Proxy and No-KYC model

The client can connect entirely through a SOCKS5 TCP proxy:

```text
127.0.0.1:1080
socks5://127.0.0.1:1080
socks5://username:password@127.0.0.1:1080
```

No-KYC means the software does not require:

```text
phone number
email
password account
real name
identity documents
central username registration
```

The only identity is a locally generated X25519 keypair. A relay operator only needs to store encrypted envelopes and routing/sync metadata. If the client uses a proxy, the relay server does not need to see the user’s direct IP address. This makes the project suitable for a minimal effective collection model.

## 🪪 Public-key identity and MITM boundary

Users send directly to a public key. If Alice manually obtains and verifies Bob’s public key outside the relay server, the relay server cannot silently replace Bob’s key without Alice sending to a different identity.

Useful commands:

```text
/fingerprint
/peerfp
/peerfp <public-key-or-base58>
```

If a future version adds server-side username lookup or public-key directory features, key-substitution protection should be added, such as TOFU pinning, signed key directories, Ed25519 identity signatures, or transparency logs.

## ⚠️ Security limitations

This is a compact prototype, not an audited secure messenger. Current limitations:

- No formal security audit.
- No Double Ratchet.
- No post-compromise security.
- No deniability model.
- No group chat protocol.
- No multi-device identity management.
- `identity.json` stores the raw private key.
- No transport TLS; confidentiality is at the message/file envelope layer.
- No padding or traffic shaping.
- Metadata remains visible to the relay.
- SQLite is not ideal for large public deployments.
- If `identity.json` is stolen, encrypted history stored on the server may become decryptable.
- Base58 display is plain Base58, not Base58Check.

Recommended precautions: protect `identity.json`, verify peer fingerprints out of band, use a proxy when needed, minimize relay logs, and do not advertise this as a Signal replacement.

## 🗄️ Persistence

The server stores messages in SQLite with fields conceptually equivalent to:

```text
server_id
created_at_ms
sender_id
recipient_id
kind
client_message_id
envelope_json
envelope_size
envelope_sha256
conversation_peer_id
copy_role
```

`copy_role` is important:

```text
delivery  -> encrypted for the peer
self_copy -> encrypted for the sender
```

This is what enables full sync while keeping the server unable to decrypt content.

## 🛠️ Deployment notes

For local testing, bind the server to `127.0.0.1`. For LAN or public testing, bind to `0.0.0.0` and open the TCP port in your firewall.

For public relays, consider:

```text
systemd service
low-privilege user
database backups
disk quotas
log minimization
rate limiting
monitoring disk usage
storage expiry policy
```

For high-throughput deployments, replace SQLite with PostgreSQL or another database designed for concurrent write-heavy workloads.

## 🧪 Example

Server:

```bash
python server.py
```

Client:

```bash
python client.py
```

Chat:

```text
hello
>>> hello
<<< hi
```

Files:

```text
/send ./document.pdf
准备发送文件: document.pdf
文件发送排队中: document.pdf 65536/1048576 bytes
文件已加入发送队列: document.pdf
```

## 🗺️ Roadmap

Possible future work:

- Resumable file-transfer state.
- Local encrypted conversation database.
- Optional encrypted `identity.json`.
- Contact aliases for public keys.
- Public-key pinning / TOFU.
- Ed25519 signing identity.
- TLS transport option.
- PostgreSQL backend.
- Storage quotas and expiry.
- Better terminal UI or GUI.
- Group messaging.
- Message retention and deletion policy.
- Fuzz tests and integration tests.

## ☕ Sponsor

If this project helps you, you can sponsor development with Bitcoin:

```text
bc1qxqfhumpqtnxrznkx9r4xsp8m6zsedtgusjns7p
```

## 📜 License

This project is licensed under the **GNU General Public License v3.0**.

Recommended repository license file:

```text
GPL-3.0-only
```

Short SPDX identifier:

```text
SPDX-License-Identifier: GPL-3.0-only
```

## Short description

English:

```text
A minimal No-KYC TCP relay for end-to-end encrypted chat and file transfer using X25519 and ChaCha20-Poly1305.
```

Chinese:

```text
一个基于 TCP 的 No-KYC 端到端加密聊天与文件中继原型，使用 X25519 和 ChaCha20-Poly1305。
```
