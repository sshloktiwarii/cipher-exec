import asyncio
import json
import os
import time
from typing import Dict, Literal, Optional
import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field
import docker
from docker.errors import ContainerError, ImageNotFound, APIError

app = FastAPI(
    title="Polyglot AI Execution Sandbox",
    version="2.0.0",
    description="Zero-trust polyglot micro-container sandbox supporting Python, Go, and TypeScript with live WebSockets."
)

TELEMETRY_ENDPOINT = os.getenv("TELEMETRY_ENDPOINT", "http://localhost:8082/ingest")
DEFAULT_TIMEOUT_SEC = 5
MAX_TIMEOUT_SEC = 15

# Supported language images and execution command mappings
LANGUAGE_CONFIGS = {
    "python": {
        "image": "python:3.11-alpine",
        "cmd_builder": lambda code: ["python", "-c", code],
    },
    "go": {
        "image": "golang:1.24-alpine",
        "cmd_builder": lambda code: ["sh", "-c", f"echo {json.dumps(code)} > /tmp/main.go && go run /tmp/main.go"],
    },
    "typescript": {
        "image": "node:22-alpine",
        "cmd_builder": lambda code: ["node", "-e", code],
    },
    "javascript": {
        "image": "node:22-alpine",
        "cmd_builder": lambda code: ["node", "-e", code],
    }
}

try:
    docker_client = docker.from_env()
except Exception as e:
    docker_client = None
    print(f"[WARN] Docker connection deferred: {e}")


class ExecutionRequest(BaseModel):
    code: str = Field(..., description="Source code to execute")
    language: Literal["python", "go", "typescript", "javascript"] = Field(
        default="python",
        description="Target programming language runtime"
    )
    timeout_seconds: Optional[int] = Field(
        default=DEFAULT_TIMEOUT_SEC,
        ge=1,
        le=MAX_TIMEOUT_SEC,
        description="Execution timeout in seconds (max 15s)"
    )


class ExecutionResponse(BaseModel):
    status: str = Field(..., description="'success', 'timeout', 'error', or 'killed'")
    language: str
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    container_id: Optional[str] = None


async def emit_telemetry(language: str, duration_ms: float, exit_code: int, exec_status: str):
    if not TELEMETRY_ENDPOINT:
        return

    payload = {
        "source": "ephemeral-sandbox-polyglot",
        "event_type": "code_executed",
        "metrics": {
            "duration_ms": duration_ms,
            "exit_code": float(exit_code)
        },
        "metadata": {
            "language": language,
            "status": exec_status
        },
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            await client.post(TELEMETRY_ENDPOINT, json=payload)
    except Exception:
        pass


@app.get("/healthz", status_code=status.HTTP_200_OK)
def health_check():
    docker_healthy = False
    if docker_client:
        try:
            docker_healthy = docker_client.ping()
        except Exception:
            docker_healthy = False

    return {
        "service": "polyglot-ai-execution-sandbox",
        "status": "healthy" if docker_healthy else "degraded",
        "docker_available": docker_healthy,
        "supported_languages": list(LANGUAGE_CONFIGS.keys()),
        "resource_limits": {
            "memory": "512m",
            "cpu_cores": 0.5,
            "network": "disabled"
        }
    }


def build_container_config(language: str, code: str):
    lang_info = LANGUAGE_CONFIGS.get(language.lower(), LANGUAGE_CONFIGS["python"])
    return {
        "image": lang_info["image"],
        "command": lang_info["cmd_builder"](code),
        "detach": True,
        "network_mode": "none",                     # Zero-trust: isolated from internet
        "read_only": True,                          # Read-only rootfs
        "mem_limit": "512m",                        # Hard memory cap at 512MB
        "nano_cpus": 500_000_000,                   # Strict 0.5 CPU core limit
        "cap_drop": ["ALL"],                        # Drop all capabilities
        "security_opt": ["no-new-privileges:true"], # Block privilege escalation
        "tmpfs": {"/tmp": "rw,noexec,nosuid,size=64m"},
        "user": "1000:1000"
    }


@app.post("/execute", response_model=ExecutionResponse, status_code=status.HTTP_200_OK)
async def execute_code(req: ExecutionRequest):
    global docker_client
    if docker_client is None:
        try:
            docker_client = docker.from_env()
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Docker host unreachable: {e}")

    start_time = time.perf_counter()
    timeout = req.timeout_seconds or DEFAULT_TIMEOUT_SEC
    container = None
    container_config = build_container_config(req.language, req.code)

    try:
        container = docker_client.containers.create(**container_config)
        container.start()
        short_id = container.id[:12]

        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, container.wait),
                timeout=float(timeout)
            )
            exit_code = result.get("StatusCode", -1)
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            exec_status = "success" if exit_code == 0 else "error"

            asyncio.create_task(emit_telemetry(req.language, duration_ms, exit_code, exec_status))

            return ExecutionResponse(
                status=exec_status,
                language=req.language,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration_ms=duration_ms,
                container_id=short_id
            )

        except asyncio.TimeoutError:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            try:
                container.kill()
            except Exception:
                pass

            asyncio.create_task(emit_telemetry(req.language, duration_ms, -1, "timeout"))

            return ExecutionResponse(
                status="timeout",
                language=req.language,
                stdout="",
                stderr=f"Execution timed out after {timeout}s (0.5 CPU / 512MB limit).",
                exit_code=-1,
                duration_ms=duration_ms,
                container_id=short_id
            )

    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass


@app.websocket("/ws/execute")
async def websocket_execute(websocket: WebSocket):
    """Live streaming execution endpoint over WebSocket."""
    await websocket.accept()
    global docker_client
    if docker_client is None:
        try:
            docker_client = docker.from_env()
        except Exception as e:
            await websocket.send_json({"type": "error", "message": f"Docker unreachable: {e}"})
            await websocket.close()
            return

    try:
        raw_msg = await websocket.receive_text()
        data = json.loads(raw_msg)
        code = data.get("code", "")
        language = data.get("language", "python")
        timeout = min(int(data.get("timeout_seconds", DEFAULT_TIMEOUT_SEC)), MAX_TIMEOUT_SEC)

        container_config = build_container_config(language, code)
        container = docker_client.containers.create(**container_config)
        container.start()
        short_id = container.id[:12]

        await websocket.send_json({"type": "started", "container_id": short_id, "language": language})

        # Stream logs in chunks
        start_time = time.perf_counter()
        loop = asyncio.get_running_loop()

        try:
            # Stream logs via generator in thread executor
            def stream_container_logs():
                return list(container.logs(stream=True, follow=True))

            log_stream = await asyncio.wait_for(
                loop.run_in_executor(None, stream_container_logs),
                timeout=float(timeout)
            )

            for chunk in log_stream:
                decoded = chunk.decode("utf-8", errors="replace")
                await websocket.send_json({"type": "output", "chunk": decoded})

            result = container.wait()
            exit_code = result.get("StatusCode", 0)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            await websocket.send_json({
                "type": "finished",
                "exit_code": exit_code,
                "duration_ms": duration_ms,
                "status": "success" if exit_code == 0 else "error"
            })

        except asyncio.TimeoutError:
            try:
                container.kill()
            except Exception:
                pass
            await websocket.send_json({"type": "timeout", "message": f"Timed out after {timeout} seconds."})

        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass

    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({"type": "error", "message": str(e)})
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8081"))
    print(f"[INIT] Polyglot AI Execution Sandbox listening on port :{port}")
    uvicorn.run("server:app", host="0.0.0.0", port=port, log_level="info")
