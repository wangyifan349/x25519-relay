# x25519-relay 🔐

**x25519-relay** is a minimal centralized TCP relay for end-to-end encrypted chat, file transfer, and persistent message/file sync using **X25519**, **HKDF-SHA256**, and **ChaCha20-Poly1305**. Users are identified by locally generated X25519 keypairs; the public key is the address/username and is shown as Base58.

Repository: `https://github.com/wangyifan349/x25519-relay`

The relay server stores and forwards encrypted envelopes only. It cannot read chat messages, file contents, filenames, plaintext file hashes, file keys, or user private keys.

## ✨ Highlights

- 🔐 **X25519 + HKDF-SHA256 + ChaCha20-Poly1305** for encrypted chat and file metadata.
- 📁 **Encrypted file transfer** with chunking for large files.
- 🔄 **Persistent sync** for chat and files. Messages and files can be recovered as long as the server still stores the encrypted envelopes and the user keeps the same `identity.json`.
- 🧾 **Sender self-copies** so both incoming and outgoing history can sync back.
- 🧅 **Optional SOCKS5 TCP proxy** support in the client.
- 🪪 **Base58 public-key identity** for easier copy/paste.
- 🖥️ **Minimal terminal UI**: `>>>` means sent, `<<<` means received.
- 🧱 **Plain TCP protocol**, not WebSocket.
- 🗄️ **SQLite persistence** on the server.
- 🚫 **No account system**: no phone number, email, password account, or KYC flow.

## ⚡ Install

Install the dependency directly:

```bash
pip install -U cryptography
```

Clone and install:

```bash
git clone https://github.com/wangyifan349/x25519-relay.git
cd x25519-relay
pip install -r requirements.txt
```

Current `requirements.txt`:

```text
cryptography>=48.0.0
```

## 🚀 Quick start

Start the server:

```bash
python server.py
```

Start a client:

```bash
python client.py
```

On first run, the client creates `identity.json` and prints your local identity:

```text
========== Your local identity ==========
WARNING: the private key is your identity secret. Do not share it.
private key base58: <your Base58 private key>
public key base58 / username: <your Base58 public key>
fingerprint: <short public-key fingerprint>
=========================================
```

Share only your public key. Never share your private key.

## 👥 Connecting users

Each user runs `client.py` and shares their Base58 public key. When the client asks for the peer key, paste the other user's public key:

```text
Peer public key/Base58:
```

The client accepts both the new Base58 display format and the older internal base64url public id. Internally, the protocol still uses the base64url public id for routing and envelope metadata.

## 🖥️ Server usage

Run:

```bash
python server.py
```

Typical prompts:

```text
Server listen address [0.0.0.0]:
Server listen port [8765]:
SQLite database file [messages.sqlite3]:
Advanced settings follow. Press Enter to use recommended defaults.
Maximum bytes per TCP frame [2097152]:
Maximum JSON bytes per encrypted envelope [1800000]:
Urgent queue limit per connection [4096]:
Bulk queue limit per connection [1024]:
Maximum messages per sync page [10000]:
```

The server database is usually:

```text
messages.sqlite3
```

## 💬 Client usage

Run:

```bash
python client.py
```

Typical prompts:

```text
Server address [127.0.0.1]:
Server port [8765]:
Peer public key/Base58:
Optional SOCKS5 TCP proxy, leave empty for direct connection, e.g. 127.0.0.1:1080:
```

Normal text input sends a chat message:

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

`/send`, `/file`, and `/files` all send files. They support one file or many files.

Path examples:

```text
/send ./a.txt
/send ./a.txt ./b.zip ./c.pdf
/file "/home/me/My File.txt"
/file "C:\Users\me\My File.txt"
/files "./a b.txt" './c d.pdf'
```

Windows paths and Linux/macOS paths are both supported.

## 🔄 Sync and recovery

The server persistently stores encrypted envelopes. The client syncs the selected conversation after connecting, periodically afterward, when switching peers with `/to`, and when `/sync` is run manually.

Every outgoing chat message and file is stored as two encrypted copies:

```text
delivery copy -> encrypted for the peer
self copy     -> encrypted for the sender
```

This makes full history sync possible:

```text
>>> message I previously sent
<<< message I received
```

Files sync too. `file_start` metadata and every `file_chunk` are stored in delivery-copy and self-copy form. Recovery works as long as the encrypted server data is retained and the same identity key is used.

Compatibility note: full bidirectional sync works for v9+ messages and files. Older messages created before self-copy support may not be recoverable on the sender side if only the peer-encrypted delivery copy exists.

## 📁 File transfer

Files are split into encrypted chunks. Current chunk size:

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

The encrypted `file_start` payload contains filename, file size, plaintext SHA-256, chunk size, total chunk count, file key, and nonce prefix. The server cannot read those fields. The receiver writes files to `downloads/` and verifies plaintext size and SHA-256.

## 🧱 Transport protocol

x25519-relay uses plain TCP. Each frame is:

```text
4-byte big-endian length || UTF-8 JSON frame
```

Frame types:

```text
hello
hello_ok
send
send_self_copy
message
ack
sync_conversation
sync_all
sync_begin
sync_end
ping
pong
error
```

Urgent frames and bulk file frames use separate queues so large file transfer is less likely to block chat.

## 🔐 Cryptography

Chat and `file_start` metadata use:

```text
static_shared    = X25519(sender_identity_private, recipient_identity_public)
ephemeral_shared = X25519(sender_ephemeral_private, recipient_identity_public)
key              = HKDF-SHA256(static_shared || ephemeral_shared)
cipher           = ChaCha20-Poly1305
```

Each chat or `file_start` envelope uses a fresh ephemeral X25519 key.

File chunks use a per-file random 32-byte key and ChaCha20-Poly1305. Chunk nonces are:

```text
4-byte random per-file prefix || 8-byte chunk sequence number
```

File integrity is verified with SHA-256 after decryption.

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

The server stores encrypted envelopes and encrypted file chunks only.

## 🧾 What the server can still see

The server can still see necessary metadata:

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
client source IP, unless a proxy is used
```

With SOCKS5 enabled, the relay server sees the proxy IP instead of the user's direct IP. The proxy itself can still see the user IP and target relay server.

## 🧅 SOCKS5 proxy

The client supports SOCKS5 TCP proxy connections:

```text
127.0.0.1:1080
socks5://127.0.0.1:1080
socks5://username:password@127.0.0.1:1080
```

This is useful when the user does not want the relay server to see their direct IP address.

## 🪪 Public-key identity

Users send directly to public keys. If Alice verifies Bob's public key outside the relay server, the relay cannot silently replace Bob's key without Alice sending to a different identity.

Useful commands:

```text
/fingerprint
/peerfp
/peerfp <public-key-or-base58>
```

If a future version adds usernames or server-side public-key lookup, it should also add key-substitution protection such as TOFU pinning, signed directories, Ed25519 identity signatures, or transparency logs.

## ⚠️ Security limitations

This is a compact prototype, not an audited secure messenger.

```text
No formal security audit.
No Double Ratchet.
No post-compromise security.
No deniability model.
No group chat protocol.
No multi-device identity management.
identity.json stores the raw private key.
No transport TLS; confidentiality is at the message/file envelope layer.
No padding or traffic shaping.
Metadata remains visible to the relay.
SQLite is not ideal for large public deployments.
If identity.json is stolen, encrypted server history may become decryptable.
Base58 display is plain Base58, not Base58Check.
```

Protect `identity.json`, verify fingerprints out of band, use a proxy when needed, and do not present this as a Signal replacement.

## 🗄️ Persistence

The server stores messages with fields conceptually equivalent to:

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

`copy_role` enables full sync:

```text
delivery  -> encrypted for the peer
self_copy -> encrypted for the sender
```

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

## ☕ Sponsor

If this project helps you, you can sponsor development with Bitcoin:

```text
bc1qxqfhumpqtnxrznkx9r4xsp8m6zsedtgusjns7p
```

## 📜 License

This project is licensed under the **GNU General Public License v3.0 only**.

```text
SPDX-License-Identifier: GPL-3.0-only
```

## Short description

```text
A minimal centralized TCP relay for end-to-end encrypted chat, file transfer, and persistent message/file sync using X25519 and ChaCha20-Poly1305.
```

## 🧩 Code maintenance notes

The server SQL is intentionally commented around schema creation, indexes, inserts, and sync queries. The key point is that `delivery` rows are encrypted for the peer, while `self_copy` rows are encrypted for the sender. Sync queries return only rows the requesting client can decrypt.
