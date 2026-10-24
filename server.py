import asyncio
import os
import time
from typing import Dict, Optional
import httpx
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
import docker
from docker.errors import ContainerError, ImageNotFound, APIError

app = FastAPI(
    title="Ephemeral AI Execution Sandbox",
    version="1.0.0",
    description="Zero-trust ephemeral micro-container execution environment for AI-generated code."
)

TELEMETRY_ENDPOINT = os.getenv("TELEMETRY_ENDPOINT", "http://localhost:8082/ingest")
SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "python:3.11-alpine")
DEFAULT_TIMEOUT_SEC = 5
MAX_TIMEOUT_SEC = 15

# Initialize Docker client
try:
    docker_client = docker.from_env()
except Exception as e:
    docker_client = None
    print(f"[WARN] Docker daemon connection deferred: {e}")


class ExecutionRequest(BaseModel):
    code: str = Field(..., description="Python source code to execute")
    timeout_seconds: Optional[int] = Field(
        default=DEFAULT_TIMEOUT_SEC,
        ge=1,
        le=MAX_TIMEOUT_SEC,
        description="Execution timeout in seconds (max 15s)"
    )
    memory_limit: Optional[str] = Field(
        default="128m",
        description="Container RAM limit (e.g., '128m', '256m')"
    )


class ExecutionResponse(BaseModel):
    status: str = Field(..., description="'success', 'timeout', 'error', or 'killed'")
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    container_id: Optional[str] = None


async def emit_telemetry(event_type: str, duration_ms: float, exit_code: int, exec_status: str):
    """Asynchronously emit metrics to Project 4 Local Telemetry Engine."""
    if not TELEMETRY_ENDPOINT:
        return

    payload = {
        "source": "ephemeral-sandbox",
        "event_type": event_type,
        "metrics": {
            "duration_ms": duration_ms,
            "exit_code": float(exit_code)
        },
        "metadata": {
            "status": exec_status,
            "image": SANDBOX_IMAGE
        },
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            await client.post(TELEMETRY_ENDPOINT, json=payload)
    except Exception:
        # Observability pipeline failures must never crash the sandbox
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
        "service": "ephemeral-ai-execution-sandbox",
        "status": "healthy" if docker_healthy else "degraded",
        "docker_available": docker_healthy,
        "sandbox_image": SANDBOX_IMAGE
    }


@app.post("/execute", response_model=ExecutionResponse, status_code=status.HTTP_200_OK)
async def execute_code(req: ExecutionRequest):
    global docker_client
    if docker_client is None:
        try:
            docker_client = docker.from_env()
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Docker host socket unreachable: {str(e)}"
            )

    start_time = time.perf_counter()
    timeout = req.timeout_seconds or DEFAULT_TIMEOUT_SEC
    container = None

    # Zero-trust container execution configuration
    container_config = {
        "image": SANDBOX_IMAGE,
        "command": ["python", "-c", req.code],
        "detach": True,
        "network_mode": "none",                     # Strict zero-trust: no internet/local sockets
        "read_only": True,                          # Immutable root filesystem
        "mem_limit": req.memory_limit,              # Strict memory quota
        "nano_cpus": 1_000_000_000,                 # Bound to 1 CPU core
        "cap_drop": ["ALL"],                        # Drop all Linux capabilities
        "security_opt": ["no-new-privileges:true"], # Block privilege escalation
        "tmpfs": {"/tmp": "rw,noexec,nosuid,size=32m"}, # Writable execution scratchpad
        "user": "1000:1000"                         # Execute as unprivileged UID
    }

    try:
        # Create and start the micro-container
        container = docker_client.containers.create(**container_config)
        container.start()
        short_id = container.id[:12]

        # Enforce execution timeout via async waiting
        loop = asyncio.get_running_loop()
        try:
            # Wait with strict timeout
            result = await asyncio.wait_for(
                loop.run_in_executor(None, container.wait),
                timeout=float(timeout)
            )
            exit_code = result.get("StatusCode", -1)
            raw_stdout = container.logs(stdout=True, stderr=False)
            raw_stderr = container.logs(stdout=False, stderr=True)

            stdout = raw_stdout.decode("utf-8", errors="replace")
            stderr = raw_stderr.decode("utf-8", errors="replace")
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            exec_status = "success" if exit_code == 0 else "error"

            asyncio.create_task(emit_telemetry("code_executed", duration_ms, exit_code, exec_status))

            return ExecutionResponse(
                status=exec_status,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration_ms=duration_ms,
                container_id=short_id
            )

        except asyncio.TimeoutError:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            # Kill runaway container immediately
            try:
                container.kill()
            except Exception:
                pass

            asyncio.create_task(emit_telemetry("execution_timeout", duration_ms, -1, "timeout"))

            return ExecutionResponse(
                status="timeout",
                stdout="",
                stderr=f"Execution timed out after {timeout} seconds. Process terminated.",
                exit_code=-1,
                duration_ms=duration_ms,
                container_id=short_id
            )

    except ImageNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sandbox image '{SANDBOX_IMAGE}' not found on host. Pull with `docker pull {SANDBOX_IMAGE}`"
        )
    except APIError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Docker engine error: {str(e)}"
        )
    finally:
        # Invariant: Guarantee micro-container destruction
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8081"))
    print(f"[INIT] Ephemeral AI Execution Sandbox booting on port :{port}...")
    uvicorn.run("server:app", host="0.0.0.0", port=port, log_level="info", access_log=True)
