---
name: run
description: "Start the dev server in the background, or restart it if already running"
disable-model-invocation: true
allowed-tools: Bash(just *), Bash(pgrep *), Bash(curl *), Bash(tail *), Read
---

# Run dev server

## Instructions

Run the dev server in the background:

```bash
just dev-agent
```

Report the output to the user.

If the command fails, check whether cargo is still compiling (`pgrep -x cargo`). If it is, the build is just slow — wait and poll until the server responds or the build process exits. You can read `target/dev-agent.log` for build output.
