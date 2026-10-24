# cipher-exec: The Plain-English Guide

## What does this do?

When you ask an AI assistant to write software, it often needs to test that code by running it on your computer.

Running untrusted code directly on your laptop is risky for two reasons:
1. **The code might freeze your computer.** If the AI accidentally writes an infinite loop (code that never finishes), it will consume 100% of your computer's processing power and memory until your screen locks up.
2. **The code could touch your files.** A buggy script could accidentally modify or delete your personal documents, or attempt to connect to the internet.

`cipher-exec` runs code in a secure temporary box:
* **Strict 3-second limit:** If any code takes longer than 3 seconds to finish, `cipher-exec` kills the process immediately. Your computer never locks up.
* **No internet access:** The code cannot connect to external websites or transfer data across your network.
* **Disposable workspace:** The code runs in an isolated temporary folder that gets completely erased the moment the test finishes.

---

## What happens if I don't use this?

Without a sandbox, AI code runs with the exact same permissions as your own user account. If an AI writes a script with a bug, that script can fill your hard drive, freeze your laptop, or corrupt files in your home directory.

---

## Frequently Asked Questions

#### Do I need to install Docker?
No. `cipher-exec` uses security controls built directly into macOS (Seatbelt) and Linux (namespaces). It is a single program with zero extra downloads.

#### Does this slow down code execution?
No. It launches tests in less than 40 milliseconds.

#### How do I run it?
If you are running the full Cipher system, `cipher appliance` starts `cipher-exec` automatically. If you want to run it on its own:
```bash
./cipher-exec --port 8081
```
