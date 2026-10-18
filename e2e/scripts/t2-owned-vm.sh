#!/usr/bin/env bash
# Task-owned T2 guest runner. Never invokes repository rootfs/vm-down/clean targets.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IDENTITY="$ROOT/e2e/scripts/t2_process_identity.py"
LOCK="${T2_VM_LOCK:-/tmp/bloodhound-t2-vm.lock}"
mkdir -p "$(dirname "$LOCK")"
RUN="$(mktemp -d /tmp/bloodhound-t2.XXXXXXXX)"
SUFFIX="$(basename "$RUN" | tr '[:upper:]' '[:lower:]' | tr . -)"
TAG="bloodhound-t2-$SUFFIX"
EVIDENCE="$ROOT/docs/evidence/t2-vm-$SUFFIX"
CID="" QPID="" QSTART="" IMAGE_ID=""
cleanup() {
  local result=$? safe=1 stop_result=0
  set +e
  if [[ -n "$QPID" && -n "$QSTART" ]]; then
    timeout --signal=TERM --kill-after=5s 25s python3 "$IDENTITY" stop "$QPID" "$QSTART" "$RUN/rootfs.img"
    stop_result=$?
    if (( stop_result == 0 )); then
      # The ownership helper proved termination; reap our child synchronously.
      wait "$QPID" 2>/dev/null
    else
      # Never wait on a PID after a start-time/argv mismatch. Retain disk/image
      # if any process still references this unique image path.
      timeout --signal=TERM --kill-after=2s 10s python3 "$IDENTITY" in-use 0 0 "$RUN/rootfs.img"
      (( $? == 1 )) || safe=0
    fi
  fi
  if (( safe == 0 )); then
    mkdir -p "$EVIDENCE"
    [[ ! -f "$RUN/qemu.log" ]] || cp "$RUN/qemu.log" "$EVIDENCE/qemu.log"
    [[ ! -f "$RUN/pytest.log" ]] || cp "$RUN/pytest.log" "$EVIDENCE/pytest.log"
    echo "cleanup=unverified; retained resources and disk may still be in use" > "$EVIDENCE/cleanup-blocker.txt"
    echo "Owned VM cleanup could not be verified; retaining exact run directory $RUN" >&2
    return 1
  fi

  mkdir -p "$EVIDENCE"
  [[ ! -f "$RUN/qemu.log" ]] || cp "$RUN/qemu.log" "$EVIDENCE/qemu.log"
  [[ ! -f "$RUN/pytest.log" ]] || cp "$RUN/pytest.log" "$EVIDENCE/pytest.log"
  [[ ! -f "$RUN/events.ndjson" ]] || cp "$RUN/events.ndjson" "$EVIDENCE/events.ndjson"
  [[ ! -f "$RUN/acceptance.ndjson" ]] || cp "$RUN/acceptance.ndjson" "$EVIDENCE/acceptance.ndjson"
  [[ ! -f "$RUN/guest-provenance.txt" ]] || cp "$RUN/guest-provenance.txt" "$EVIDENCE/guest-provenance.txt"
  [[ ! -f "$RUN/bloodhound-journal.log" ]] || cp "$RUN/bloodhound-journal.log" "$EVIDENCE/bloodhound-journal.log"
  {
    echo "result=$result"
    echo "source_commit=$(git -C "$ROOT" rev-parse HEAD)"
    echo "image_tag=$TAG"
    echo "image_id=$IMAGE_ID"
    [[ ! -f "$RUN/vmlinuz" ]] || sha256sum "$RUN/vmlinuz"
    [[ ! -f "$RUN/rootfs.img" ]] || sha256sum "$RUN/rootfs.img"
    [[ ! -f "$RUN/rootfs.tar" ]] || sha256sum "$RUN/rootfs.tar"
  } >"$EVIDENCE/provenance.txt"
  if [[ -n "$CID" ]]; then timeout --signal=TERM --kill-after=3s 20s docker rm "$CID" >/dev/null; fi
  if [[ -n "$IMAGE_ID" ]]; then timeout --signal=TERM --kill-after=5s 30s docker image rm "$IMAGE_ID" >/dev/null; fi
  if [[ -d "$RUN/rootfs" ]]; then
    timeout --signal=TERM --kill-after=10s 300s docker run --rm -v "$RUN:/task" ubuntu:24.04 bash -c 'rm -rf /task/rootfs'
  fi
  rm -rf -- "$RUN"
}
trap cleanup EXIT

# Each long-running command has an outer finite deadline and touches only this run.
timeout --signal=TERM --kill-after=30s "${T2_BUILD_TIMEOUT:-2400}s" \
  docker build --platform linux/amd64 -t "$TAG" -f "$ROOT/e2e/Dockerfile" "$ROOT/e2e"
IMAGE_ID="$(timeout --signal=TERM --kill-after=3s 30s docker image inspect "$TAG" --format '{{.Id}}')"
CID="$(timeout --signal=TERM --kill-after=3s 30s docker create "$IMAGE_ID")"
timeout --signal=TERM --kill-after=10s 180s docker export "$CID" -o "$RUN/rootfs.tar"
timeout --signal=TERM --kill-after=5s 60s docker cp "$CID:/boot/vmlinuz-6.8.0-49-generic" "$RUN/vmlinuz"
timeout --signal=TERM --kill-after=3s 30s docker rm "$CID" >/dev/null
CID=""
timeout --signal=TERM --kill-after=30s "${T2_BUILD_TIMEOUT:-2400}s" \
  docker build --platform linux/amd64 -f "$ROOT/Dockerfile.build" \
  --output "type=local,dest=$RUN/build-output" "$ROOT"
BIN="$RUN/build-output/bloodhound"
[[ -x "$BIN" ]]
cp "$BIN" "$RUN/bloodhound"

timeout --signal=TERM --kill-after=10s "${T2_IMAGE_TIMEOUT:-900}s" docker run --rm \
  -v "$RUN:/task" -v "$ROOT/e2e/config:/config:ro" "$IMAGE_ID" bash -Eeuc '
  mkdir /task/rootfs
  tar xf /task/rootfs.tar -C /task/rootfs
  install -D -m 0755 /task/bloodhound /task/rootfs/opt/bloodhound/bloodhound
  install -D -m 0644 /config/usdt.d/training-shell-v3.toml /task/rootfs/etc/bloodhound/usdt.d/training-shell-v3.toml
  install -D -m 0644 /config/usdt.d/training-peer-v1.toml /task/rootfs/etc/bloodhound/usdt.d/training-peer-v1.toml
  cat > /task/rootfs/etc/systemd/system/bloodhound.service <<"UNIT"
[Unit]
Description=Bloodhound T2 producer validation
After=network.target
[Service]
Environment=RUST_LOG=info
Type=simple
ExecStart=/opt/bloodhound/bloodhound --uid 1000 --usdt-config /etc/bloodhound/usdt.d/training-shell-v3.toml --usdt-config /etc/bloodhound/usdt.d/training-peer-v1.toml
StandardOutput=append:/var/log/bloodhound.ndjson
StandardError=journal
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
  ln -sf /etc/systemd/system/bloodhound.service /task/rootfs/etc/systemd/system/multi-user.target.wants/bloodhound.service
  mkdir -p /task/rootfs/etc/systemd/network /task/rootfs/etc/systemd/system/multi-user.target.wants /task/rootfs/etc/systemd/system/sockets.target.wants
  cat > /task/rootfs/etc/systemd/network/80-dhcp.network <<"NET"
[Match]
Name=e*

[Network]
DHCP=yes
NET
  rm -f /task/rootfs/etc/resolv.conf
  printf "nameserver 10.0.2.3\\n" > /task/rootfs/etc/resolv.conf
  ln -sf /usr/lib/systemd/system/systemd-networkd.service /task/rootfs/etc/systemd/system/multi-user.target.wants/systemd-networkd.service
  ln -sf /lib/systemd/system/ssh.socket /task/rootfs/etc/systemd/system/sockets.target.wants/ssh.socket
  mkfs.ext4 -F -q -d /task/rootfs /task/rootfs.img 8G
'

# Build and image preparation above is independent of QEMU. Acquire the shared
# measurement lock only for port reservation, VM startup, test, and cleanup.
exec 9>"$LOCK"
flock -w "${T2_LOCK_WAIT_SECONDS:-3600}" 9

PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
)"
if ss -Hlt "sport = :$PORT" | grep -q .; then echo "SSH port $PORT was claimed after reservation" >&2; exit 1; fi
qemu-system-x86_64 -name "$TAG" -kernel "$RUN/vmlinuz" \
  -drive "file=$RUN/rootfs.img,format=raw,if=virtio" \
  -append 'root=/dev/vda rw console=ttyS0 lsm=landlock,lockdown,yama,apparmor,bpf' \
  -m "${T2_VM_MEMORY:-2048}" -smp "${T2_VM_CPUS:-2}" -nographic -enable-kvm \
  -net nic,model=virtio -net "user,hostfwd=tcp:127.0.0.1:$PORT-:22" \
  >"$RUN/qemu.log" 2>&1 &
QPID=$!
for _ in $(seq 1 100); do [[ -r "/proc/$QPID/stat" ]] && break; sleep .02; done
QSTART="$(timeout --signal=TERM --kill-after=2s 5s python3 "$IDENTITY" start "$QPID" 0 "")"
[[ -n "$QSTART" ]]
ssh_guest() {
  timeout --signal=TERM --kill-after=3s "${T2_SSH_TIMEOUT:-12}s" \
    sshpass -p root ssh -p "$PORT" -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile="$RUN/known_hosts" -o ConnectTimeout=3 "$@"
}
READY="${T2_VM_READY_SECONDS:-900}"
end=$((SECONDS + READY)); ready=0
while (( SECONDS < end )); do
  if ! kill -0 "$QPID" 2>/dev/null; then tail -200 "$RUN/qemu.log"; exit 1; fi
  ssh_guest root@127.0.0.1 true >/dev/null 2>&1 && { ready=1; break; }
  sleep 2
done
(( ready )) || { echo "SSH readiness timeout (${READY}s)" >&2; tail -200 "$RUN/qemu.log"; exit 1; }
NET_READY="${T2_NET_READY_SECONDS:-180}"
net_end=$((SECONDS + NET_READY)); net_ready=0
while (( SECONDS < net_end )); do
  if ssh_guest root@127.0.0.1 'systemctl is-active --quiet systemd-networkd && ip -4 -o addr show scope global | grep -q . && ip -4 route show default | grep -q .' >/dev/null 2>&1; then
    net_ready=1; break
  fi
  sleep 2
done
(( net_ready )) || { echo "guest network-health timeout (${NET_READY}s)" >&2; tail -200 "$RUN/qemu.log"; exit 1; }
ssh_guest root@127.0.0.1 'systemctl is-active --quiet bloodhound' || {
  echo "Bloodhound service failed before tests" >&2
  ssh_guest root@127.0.0.1 'journalctl -u bloodhound --no-pager -n 200' >&2 || true
  exit 1
}
if [[ -n "${T2_TEST_FILE:-}" ]]; then
  TEST_PATH="$ROOT/e2e/tests/$T2_TEST_FILE"
else
  TEST_PATH="$ROOT/e2e/tests"
fi
export T2_ACCEPTANCE_EVIDENCE="$RUN/acceptance.ndjson"
set +e
timeout --signal=TERM --kill-after=30s "${T2_TEST_TIMEOUT:-2400}s" \
  python3 -m pytest -v --ssh-port="$PORT" --ssh-host=127.0.0.1 --tb=long "${TEST_PATH:-$ROOT/e2e/tests}" >"$RUN/pytest.log" 2>&1
TEST_RESULT=$?
set -e
cat "$RUN/pytest.log"
# Capture raw producer events and startup/BPF diagnostics while SSH is usable.
ssh_guest root@127.0.0.1 'cat /var/log/bloodhound.ndjson' >"$RUN/events.ndjson" 2>/dev/null || true
ssh_guest root@127.0.0.1 'uname -a; python3 -c '\''import os; f=os.open("/proc/self/ns/net", os.O_RDONLY); s=os.fstat(f); print("management_nsfs", s.st_dev, s.st_ino)'\''' >"$RUN/guest-provenance.txt" 2>/dev/null || true
ssh_guest root@127.0.0.1 'journalctl -u bloodhound -b --no-pager' >"$RUN/bloodhound-journal.log" 2>/dev/null || true
exit "$TEST_RESULT"
