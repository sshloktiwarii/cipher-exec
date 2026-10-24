# cipher-exec: Ephemeral AI Execution Sandbox

A zero-trust execution environment built with Python, FastAPI, and Docker SDK designed to execute untrusted AI-generated code securely.

## Zero-Trust Security Guarantees
- **Isolated Network**: `network_mode="none"` prevents data exfiltration, socket creation, and internal network scanning.
- **Read-Only Root Filesystem**: Blocks root tampering or persistence.
- **Micro-Limits**: Strict RAM (128MB) and CPU (1 core) caps prevent resource starvation.
- **Hard Timeout**: Enforces a strict 5-second execution timeout; runaway containers are forcefully killed (`SIGKILL`) and purged.
- **Guaranteed Cleanup**: Containers are immediately deleted in `finally` blocks.

## API Usage
```bash
curl -X POST http://localhost:8081/execute \
  -H "Content-Type: application/json" \
  -d '{"code": "import math\nprint(math.factorial(10))", "timeout_seconds": 5}'
```
