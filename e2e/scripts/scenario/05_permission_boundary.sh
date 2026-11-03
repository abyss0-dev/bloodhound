#!/bin/bash
# Scenario 05: Permission boundaries and security
# ─────────────────────────────────────────────────
# Key events to verify:
#   - DAC denial for an unprivileged kill attempt (not proof of LSM enforcement)
#   - execve          : privilege escalation via sudo
#   - openat          : access denied due to insufficient permissions (return_code)
#   - SYSCALL         : various permission check failures

# Attempt to read a restricted file
cat /etc/shadow 2>/dev/null || echo "permission denied (expected)"

# Escalate privileges with sudo
sudo whoami

# Read a restricted file via sudo
sudo cat /etc/shadow | head -1

# An ordinary user cannot kill the root daemon; this exercises DAC, not LSM.
DAEMON_PID=$(pgrep bloodhound 2>/dev/null || echo "")
[ -n "$DAEMON_PID" ] && kill -9 $DAEMON_PID 2>/dev/null || echo "kill blocked (expected)"

# Read process info via /proc
cat /proc/self/status | head -5
cat /proc/self/loginuid
