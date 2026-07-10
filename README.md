# EnderLock

> Enable TCP encryption in offline-mode GTNH servers

## AI Usage Disclaimer

Generative AI (LLM) was used in developing this mod, every AI contribution was marked as such in corresponding commits.

If you're turned off by this, then please skip over this mod.

## About

Minecraft encrypts TCP packets only if the server is configured to run as online-mode, but offline-mode servers don't
have such a feature thus making all communications with clients in cleartext. This mod fixes this gap and enables
packets encryption

## Features

- Encrypt the TCP channel with clients
- Connecting clients can authenticate your server

## Installation

Simply drop the `.jar` mod file inside `mods/` on both the server and the client

## Configuration

| Option                     | Side   | Default | Description                                                     |
|----------------------------|--------|---------|-----------------------------------------------------------------|
| `enabled`                  | Server | `true`  | Whether the mod should be enabled                               |
| `loginTimeoutSeconds`      | Both   | `300`   | Login timeout in seconds                                        |
| `attemptMojangSessionJoin` | Client | `true`  | Attempt the regular session join before the EnderLock handshake |

## FAQ

**Do I need this mod in the client?**
Yes, servers using this mod expect clients to follow the login protocol, plus it would break the security model to allow
unencrypted network channels

**Does this mod authenticate clients?**
No, this mod authenticates servers, not clients; for this feature check
out [SeamlessAuth](https://github.com/lubinacourec/SeamlessAuth)

**What do you mean by clients can authenticate servers?**
Simply put, who assures the client that the server you're trying to connect to is the right server and not a fake server
set up by a malicious actor? This mod resolves it by using asymmetric encryption (RSA) to negotiate a symmetric key
(AES); because the server sends its own public key at the handshake phase the client can check against its known hosts
file (server: public key fingerprint) to know if the server is correct.
