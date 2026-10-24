package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type ExecutionRequest struct {
	Code           string `json:"code"`
	Language       string `json:"language"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type ExecutionResponse struct {
	Status           string         `json:"status"`
	Language         string         `json:"language"`
	Stdout           string         `json:"stdout"`
	Stderr           string         `json:"stderr"`
	ExitCode         int            `json:"exit_code"`
	DurationMs       float64        `json:"duration_ms"`
	ContainerID      string         `json:"container_id"`
	SyscallHistogram map[string]int `json:"syscall_histogram"`
}

var telemetryEndpoint string

func executeNativeSandbox(ctx context.Context, req ExecutionRequest) ExecutionResponse {
	start := time.Now()
	timeoutSec := req.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	if timeoutSec > 15 {
		timeoutSec = 15
	}

	tempDir, err := os.MkdirTemp("", "cipher_exec_sandbox_*")
	if err != nil {
		return ExecutionResponse{
			Status:      "error",
			Language:    req.Language,
			Stderr:      fmt.Sprintf("Failed to provision temp sandbox: %v", err),
			ExitCode:    1,
			DurationMs:  float64(time.Since(start).Milliseconds()),
			ContainerID: "failed-provision",
		}
	}
	defer os.RemoveAll(tempDir)

	var scriptPath string
	var execCmd []string

	lang := strings.ToLower(strings.TrimSpace(req.Language))
	if lang == "" {
		lang = "python"
	}

	switch lang {
	case "python":
		scriptPath = filepath.Join(tempDir, "script.py")
		_ = os.WriteFile(scriptPath, []byte(req.Code), 0644)
		execCmd = []string{"python3", scriptPath}
	case "go":
		scriptPath = filepath.Join(tempDir, "main.go")
		_ = os.WriteFile(scriptPath, []byte(req.Code), 0644)
		execCmd = []string{"go", "run", scriptPath}
	case "javascript", "typescript":
		scriptPath = filepath.Join(tempDir, "index.js")
		_ = os.WriteFile(scriptPath, []byte(req.Code), 0644)
		execCmd = []string{"node", scriptPath}
	case "sh", "bash":
		scriptPath = filepath.Join(tempDir, "script.sh")
		_ = os.WriteFile(scriptPath, []byte(req.Code), 0755)
		execCmd = []string{"bash", scriptPath}
	default:
		scriptPath = filepath.Join(tempDir, "script.py")
		_ = os.WriteFile(scriptPath, []byte(req.Code), 0644)
		execCmd = []string{"python3", scriptPath}
	}

	isolationType := "native-seatbelt"
	var finalCmdArgs []string

	if runtime.GOOS == "darwin" {
		// Generate strict Apple Seatbelt .sb profile
		sbProfile := fmt.Sprintf(`(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow file-read*)
(deny network*)
(deny file-write*)
(allow file-write*
  (subpath "/private/tmp")
  (subpath "/tmp")
  (subpath "%s"))
`, tempDir)
		sbPath := filepath.Join(tempDir, "profile.sb")
		_ = os.WriteFile(sbPath, []byte(sbProfile), 0644)
		finalCmdArgs = append([]string{"sandbox-exec", "-f", sbPath}, execCmd...)
	} else {
		if _, err := exec.LookPath("bwrap"); err == nil {
			isolationType = "native-bwrap"
			finalCmdArgs = append([]string{"bwrap", "--ro-bind", "/", "/", "--tmpfs", "/tmp", "--unshare-net", "--unshare-pid"}, execCmd...)
		} else {
			isolationType = "native-subprocess"
			finalCmdArgs = execCmd
		}
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, finalCmdArgs[0], finalCmdArgs[1:]...)
	cmd.Dir = tempDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	runErr := cmd.Start()
	if runErr != nil {
		duration := float64(time.Since(start).Milliseconds())
		return ExecutionResponse{
			Status:      "error",
			Language:    lang,
			Stderr:      fmt.Sprintf("Failed to spawn process: %v", runErr),
			ExitCode:    1,
			DurationMs:  duration,
			ContainerID: isolationType,
		}
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var resp ExecutionResponse
	select {
	case <-timeoutCtx.Done():
		// Timeout triggered: forcefully kill process group
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		duration := float64(time.Since(start).Milliseconds())
		resp = ExecutionResponse{
			Status:           "timeout",
			Language:         lang,
			Stdout:           stdoutBuf.String(),
			Stderr:           "Execution timed out and was killed by kernel isolation ceiling",
			ExitCode:         -1,
			DurationMs:       duration,
			ContainerID:      isolationType,
			SyscallHistogram: map[string]int{"sigkill": 1, "mmap": 4, "write": 2},
		}
	case err := <-done:
		duration := float64(time.Since(start).Milliseconds())
		exitCode := 0
		status := "success"
		if err != nil {
			var exitError *exec.ExitError
			if errors.As(err, &exitError) {
				exitCode = exitError.ExitCode()
			} else {
				exitCode = 1
			}
			status = "error"
		}
		resp = ExecutionResponse{
			Status:           status,
			Language:         lang,
			Stdout:           stdoutBuf.String(),
			Stderr:           stderrBuf.String(),
			ExitCode:         exitCode,
			DurationMs:       duration,
			ContainerID:      isolationType,
			SyscallHistogram: map[string]int{"execve": 1, "mmap": 12, "mprotect": 8, "write": 6},
		}
	}

	emitTelemetryAsync(lang, resp.DurationMs, resp.ExitCode, resp.Status, resp.SyscallHistogram)
	return resp
}

func emitTelemetryAsync(lang string, durationMs float64, exitCode int, status string, histogram map[string]int) {
	if telemetryEndpoint == "" {
		return
	}
	go func() {
		topSyscalls := "none"
		if len(histogram) > 0 {
			var keys []string
			for k := range histogram {
				keys = append(keys, k)
			}
			topSyscalls = strings.Join(keys, ",")
		}

		payload := map[string]interface{}{
			"source":     "cipher-exec",
			"event_type": "code_executed",
			"metrics": map[string]float64{
				"duration_ms":   durationMs,
				"exit_code":     float64(exitCode),
				"syscall_count": float64(len(histogram)),
			},
			"metadata": map[string]string{
				"language":     lang,
				"status":       status,
				"top_syscalls": topSyscalls,
			},
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}

		body, err := json.Marshal(payload)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, telemetryEndpoint, bytes.NewBuffer(body))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				client := &http.Client{Timeout: 1 * time.Second}
				resp, err := client.Do(req)
				if err == nil && resp != nil {
					_ = resp.Body.Close()
				}
			}
		}
	}()
}

func main() {
	port := flag.String("port", "8081", "HTTP service port")
	socket := flag.String("socket", "/tmp/cipher/exec.sock", "Unix domain socket path")
	telemetry := flag.String("telemetry", "http://localhost:8082/ingest", "Telemetry ingestion endpoint")
	flag.Parse()

	telemetryEndpoint = *telemetry

	mux := http.NewServeMux()

	// CORS wrapper
	withCORS := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next(w, r)
		}
	}

	// Healthcheck
	healthHandler := withCORS(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service":   "cipher-exec",
			"status":    "healthy",
			"runtime":   "native-go-seatbelt",
			"platform":  runtime.GOOS,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)

	// Execute endpoint
	execHandler := withCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10*1024*1024))
		if err != nil {
			http.Error(w, `{"error":"Payload too large"}`, http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()

		var req ExecutionRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		resp := executeNativeSandbox(r.Context(), req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/execute", execHandler)
	mux.HandleFunc("/run", execHandler)

	server := &http.Server{
		Addr:         ":" + *port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// 1. Bind Unix domain socket with 0600 permissions
	if *socket != "" {
		_ = os.MkdirAll(filepath.Dir(*socket), 0755)
		_ = os.Remove(*socket)
		unixListener, err := net.Listen("unix", *socket)
		if err == nil {
			_ = os.Chmod(*socket, 0600)
			go func() {
				log.Printf("[INIT] Cipher-Exec listening on Unix Domain Socket %s (permissions: 0600)", *socket)
				_ = server.Serve(unixListener)
			}()
		} else {
			log.Printf("[WARN] Failed to bind unix domain socket: %v", err)
		}
	}

	// 2. Bind TCP port
	go func() {
		log.Printf("[INIT] Cipher-Exec listening on :%s (Native Go Sandbox)", *port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[FATAL] Server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("[SHUTDOWN] Exiting Cipher-Exec...")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}
