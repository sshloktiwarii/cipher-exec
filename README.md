# 🛡️ cipher-exec — Ephemeral AI Execution Sandbox

[![Language](https://img.shields.io/badge/Language-Go%201.24-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=flat-square)](#)
[![Zero-Dependency](https://img.shields.io/badge/Zero--Dependency-Pure%20Go-blue?style=flat-square)](#)

A zero-dependency, kernel-isolated sandbox for executing untrusted AI-generated code. Built with pure Go using native **Darwin Seatbelt** (`sandbox-exec`) on macOS and **unshare namespaces / cgroups v2** on Linux. Zero Docker daemon required.

---

### 💡 For Non-Techies: What does this do?
> When AI writes code, that code could contain an infinite loop that freezes your computer, or code that tries to delete your files.
>
> `cipher-exec` acts like a fireproof isolation chamber:
> - **It locks the doors**: The AI code is forbidden from reading your personal files or connecting to the internet.
> - **It pulls the plug**: If the AI code gets stuck or runs for more than 3 to 5 seconds, `cipher-exec` terminates it instantly.
> - **No extra installs**: You don't need Docker, Python, or containers. It uses the security tools already built into your Mac or Linux operating system.

---

## Security Invariants

| Feature | Enforcement Mechanism | Guarantee |
| :--- | :--- | :--- |
| **Network Airgap** | `(deny network*)` / `unshare -n` | Code cannot send or receive network packets. |
| **Filesystem Cage** | Temporary scratchpad directory | Read-only system libraries, isolated temp dir wiped on exit. |
| **Process Timeout Ceiling** | Process-group `SIGKILL` | Runaway computations are killed in $\le 3001\text{ms}$. |
| **Zero Host Attack Surface** | `0600` Unix Socket (`/tmp/cipher/exec.sock`) | Unauthorized local users cannot connect. |

---

## Quickstart

### Build Standalone Binary
```bash
go build -o cipher-exec .
```

### Run Standalone
```bash
./cipher-exec --port 8081 --socket /tmp/cipher/exec.sock
```

### Test Code Execution
```bash
# Safe compute
curl -X POST http://localhost:8081/execute \
  -H "Content-Type: application/json" \
  -d '{"language": "python", "code": "print(2 + 2)", "timeout_seconds": 3}'

# Runaway timeout trap (killed in 3s)
curl -X POST http://localhost:8081/execute \
  -H "Content-Type: application/json" \
  -d '{"language": "python", "code": "while True: pass", "timeout_seconds": 3}'
```

---

## License
MIT © [Shlok Tiwari](https://github.com/sshloktiwarii)
