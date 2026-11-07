#!/usr/bin/env bash
# Minimal SSH/SCP transport for an LG webOS TV configured with
# ares-setup-device. Credentials are read at runtime and never persisted.
set -uo pipefail

action="${1:-}"
shift || true

case "$action" in
  run)
    [ $# -eq 1 ] || { echo "usage: tv.sh run '<command>'" >&2; exit 2; }
    ;;
  push|pull)
    [ $# -eq 2 ] || { echo "usage: tv.sh $action <source> <destination>" >&2; exit 2; }
    ;;
  *)
    echo "usage: tv.sh {run|push|pull} ..." >&2
    exit 2
    ;;
esac

command -v ares-setup-device >/dev/null 2>&1 || {
  echo "tv.sh: ares-setup-device not found" >&2
  exit 1
}

info=$(ares-setup-device -F -j 2>/dev/null) || {
  echo "tv.sh: ares-setup-device failed" >&2
  exit 1
}
creds=$(printf '%s' "$info" | TV_DEVICE="${TV_DEVICE:-}" node -e '
let data="";
process.stdin.on("data", chunk => data += chunk);
process.stdin.on("end", () => {
  const devices = JSON.parse(data);
  const wanted = process.env.TV_DEVICE || "";
  const target = devices.find(item => wanted ? item.name === wanted : item.default) || devices[0];
  if (!target) process.exit(3);
  const info = target.deviceinfo || {};
  const details = target.details || {};
  const values = [
    info.ip || info.host || details.host || "",
    info.port || details.port || "",
    info.user || info.username || details.username || "",
    details.privatekey || "",
    details.passphrase || "",
    details.password || ""
  ];
  process.stdout.write(values.map(value =>
    "x" + Buffer.from(String(value), "utf8").toString("base64")
  ).join("\t"));
});') || {
  echo "tv.sh: no matching device${TV_DEVICE:+ '$TV_DEVICE'}" >&2
  exit 1
}

IFS=$'\t' read -r ip_encoded port_encoded user_encoded key_encoded \
  passphrase_encoded password_encoded <<<"$creds"

decode_field() {
  TV_ENCODED="$1" node -e \
    'process.stdout.write(Buffer.from(process.env.TV_ENCODED.slice(1),"base64").toString("utf8"))'
}

ip=$(decode_field "$ip_encoded")
port=$(decode_field "$port_encoded")
user=$(decode_field "$user_encoded")
key=$(decode_field "$key_encoded")
passphrase=$(decode_field "$passphrase_encoded")
password=$(decode_field "$password_encoded")

[ -n "$ip" ] && [ -n "$port" ] && [ -n "$user" ] \
  && { [ -n "$key" ] || [ -n "$password" ]; } || {
    echo "tv.sh: selected device has incomplete SSH details" >&2
    exit 1
  }

case "$key" in
  "") key_path="" ;;
  /*) key_path="$key" ;;
  *) key_path="${HOME:-}/.ssh/$key" ;;
esac

export TV_KEY="$key_path" TV_PORT="$port" TV_HOST="$user@$ip" \
  TV_PASSPHRASE="$passphrase" TV_PASSWORD="$password" \
  TV_TIMEOUT="${TV_TIMEOUT:-120}" \
  TV_CONTROL_PATH="/tmp/lg-ipk-download-tv-%C"

case "$action" in
  run)
    export TV_MODE=run TV_CMD="$1"
    ;;
  push)
    export TV_MODE=push TV_SRC="$1" TV_DST="$2"
    ;;
  pull)
    export TV_MODE=pull TV_SRC="$1" TV_DST="$2"
    ;;
esac

if ! command -v expect >/dev/null 2>&1; then
  if [ -n "$passphrase" ] || [ -n "$password" ]; then
    echo "tv.sh: expect not found (required when a passphrase or password is set)" >&2
    exit 1
  fi
  opts=()
  [ -n "$key_path" ] && opts+=(-i "$key_path")
  opts+=(
    -o "ConnectTimeout=${TV_TIMEOUT:-120}"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o ControlMaster=auto
    -o ControlPersist=60
    -o ControlPath="$TV_CONTROL_PATH"
    -o HostKeyAlgorithms=+ssh-rsa
    -o PubkeyAcceptedKeyTypes=+ssh-rsa
  )
  case "$action" in
    run)
      exec ssh -p "$port" "${opts[@]}" "$user@$ip" "$1"
      ;;
    push)
      exec scp -P "$port" "${opts[@]}" "$1" "$user@$ip:$2"
      ;;
    pull)
      exec scp -P "$port" "${opts[@]}" "$user@$ip:$1" "$2"
      ;;
  esac
fi

expect <<'EOF'
set timeout $env(TV_TIMEOUT)
set opts [list]
if {[string length $env(TV_KEY)] > 0} { lappend opts -i $env(TV_KEY) }
lappend opts -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR -o ControlMaster=auto -o ControlPersist=60 \
  -o ControlPath=$env(TV_CONTROL_PATH) -o HostKeyAlgorithms=+ssh-rsa \
  -o PubkeyAcceptedKeyTypes=+ssh-rsa

# Authenticate silently and reuse the SSH control connection.
log_user 0
spawn -noecho ssh -p $env(TV_PORT) {*}$opts $env(TV_HOST) true
expect {
  -re {[Pp]assphrase.*:} { send "$env(TV_PASSPHRASE)\r"; exp_continue }
  -re {[Pp]assword:} { send "$env(TV_PASSWORD)\r"; exp_continue }
  timeout { puts stderr "tv.sh: connection timed out"; exit 1 }
  eof {}
}
catch wait auth
if {[lindex $auth 3] != 0} {
  puts stderr "tv.sh: SSH authentication failed"
  exit [lindex $auth 3]
}
log_user 1

if {$env(TV_MODE) eq "run"} {
  set command [list ssh -p $env(TV_PORT) {*}$opts $env(TV_HOST) $env(TV_CMD)]
} elseif {$env(TV_MODE) eq "push"} {
  set command [list scp -P $env(TV_PORT) {*}$opts \
    $env(TV_SRC) "$env(TV_HOST):$env(TV_DST)"]
} else {
  set command [list scp -P $env(TV_PORT) {*}$opts \
    "$env(TV_HOST):$env(TV_SRC)" $env(TV_DST)]
}

spawn -noecho {*}$command
expect {
  -re {[Pp]assphrase.*:} {
    log_user 0
    send "$env(TV_PASSPHRASE)\r"
    expect -re {\r?\n}
    log_user 1
    exp_continue
  }
  -re {[Pp]assword:} {
    log_user 0
    send "$env(TV_PASSWORD)\r"
    expect -re {\r?\n}
    log_user 1
    exp_continue
  }
  timeout {
    puts stderr "tv.sh: operation timed out"
    exit 1
  }
  eof {}
}
catch wait result
exit [lindex $result 3]
EOF
