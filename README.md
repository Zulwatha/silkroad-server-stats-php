# Silkroad Server Stats Tool

A unique PHP-based diagnostic tool to query and decode live server statistics from Silkroad Online gateway servers.  
It performs raw socket connections and applies custom binary protocol decoding tailored for the Silkroad architecture.

---

## 📡 Key Features

- Real-time data extraction from GatewayServer (via IP:port)
- Custom implementation of Silkroad's security logic
- Supports locale/version-specific parsing logic
- Works over browser query string or command line
- Useful for monitoring, automation, or research

---

## 🧪 Example Usage

You can directly invoke the `ServerStats.php` file with proper query parameters via browser or CLI:

```text
http://localhost/sro/ServerStats.php?host=gwgt1.example.com&port=15779&locale=18&version=311&timeout=5
```

### Parameters:

| Parameter | Description |
|----------|-------------|
| `host` | Gateway server IP or hostname |
| `port` | Gateway server port (typically 15779 or custom) |
| `locale` | The locale code of the SRO version |
| `version` | The current version number (e.g., 311) |
| `timeout` | Max seconds to wait for connection/response |

> 📝 Most official GatewayServers ignore locale value, but private servers often require a matching one.

---

## 🛠 Developer Notes

The flow is simple:

1. Invoke `ServerStats.php` with accurate parameters.
2. Script connects, sends handshake, receives packet.
3. Packet is decrypted and parsed into human-readable server info.
4. Output can be logged, visualized, or exported.

All logic is self-contained — no external PHP libraries required.

---

## 📁 File Overview

| File | Description |
|------|-------------|
| `ServerStats.php` | Main entrypoint, handles connection and output |
| `SocketUtility.php` | Socket creation, reading, writing |
| `SilkroadSecurity.php` | Core decryption & encryption logic |
| `SecurityTable.php` | Static tables used by the protocol |
| `HexDump.php` | Utility to dump binary packets for inspection |
| `index.php` | Minimal browser UI to run queries |
| `bcmath.php` | Optional fallback for math operations |

---

## ⚠️ Disclaimer

This codebase is provided **for educational and archival purposes only**.  
It does not include nor rely on any proprietary Silkroad files.

- Do **not** use on private servers without proper authorization.
- The project authors are **not responsible** for any misuse or abuse.

---

## 🚀 Quick Start

To test locally:

```bash
php -S localhost:8000
```

Then navigate to:

```
http://localhost:8000/index.php
```

Or call `ServerStats.php` directly via browser or CURL.

---

## 📜 License

This project is open-sourced under the [MIT License](LICENSE).

---

## 🤝 Contribute

This tool is no longer actively developed but you are welcome to:

- Fork it for your own projects
- Extend it for packet analysis, dashboards, monitoring
- Share improvements via GitHub
