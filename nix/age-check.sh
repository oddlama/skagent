# skagent-age-check: age identities, batches and what ends them, against a
# real security key. Guided: it says what to do and what to watch, checks
# what it can itself, and prints a block of results to report at the end.
#
#   nix run .#age-check
#
# It runs an agent of its own on sockets and state in a temporary directory,
# next to the one you use; yours is never asked anything. On the security
# key it creates one credential (relying party "skagent:age") and offers to
# delete it at the end. PINs are typed into skagent's prompt and, for the
# deletion, into fido2-token; never into this script.
#
# Expect to enter the PIN about four times and to touch the key about
# fifteen times. It takes five to ten minutes.

set +o errexit
umask 077

usage() {
  cat <<'EOF'
usage: skagent-age-check [--popup PROGRAM | --pinentry PROGRAM | --askpass PROGRAM]
                         [--files N] [--skip-unplug] [--skip-lock] [--skip-stop]

Prompts come from skagent's popup unless you name another program.
--files N       how many files the batch decrypts (default 40)
--skip-unplug   leave out the step that has you unplug the key
--skip-lock     leave out the step that has you lock the screen
--skip-stop     leave out the step that has you press Stop in a notification
EOF
}

# skagent's popup, if this check was built with it.
prompt=()
popup=no
if [ -n "${SKAGENT_CHECK_POPUP:-}" ]; then
  prompt=(--popup "$SKAGENT_CHECK_POPUP")
  popup=yes
fi
files=40
skip_unplug=no
skip_lock=no
skip_stop=no
while [ $# -gt 0 ]; do
  case $1 in
    --popup)
      prompt=(--popup "${2:?--popup needs a program}")
      popup=yes
      shift
      ;;
    --pinentry)
      prompt=(--pinentry "${2:?--pinentry needs a program}")
      popup=no
      shift
      ;;
    --askpass)
      prompt=(--askpass "${2:?--askpass needs a program}")
      popup=no
      shift
      ;;
    --files)
      files=${2:?--files needs a number}
      shift
      ;;
    --skip-unplug) skip_unplug=yes ;;
    --skip-lock) skip_lock=yes ;;
    --skip-stop) skip_stop=yes ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ ${#prompt[@]} = 0 ]; then
  usage >&2
  exit 2
fi

# ----------------------------------------------------------------- talking

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
say() { printf '%s\n' "$*"; }
todo() { printf '\033[1;33m>>>\033[0m %s\n' "$*"; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

results=()
failures=0
step_number=0
# step TITLE: the next part of the check. Its number goes with its results.
step() {
  step_number=$((step_number + 1))
  bold "$step_number. $1"
}
result() { results+=("$1"); }
ok() {
  say "  ok: $1"
  result "ok    [$step_number] $1"
}
bad() {
  say "  FAILED: $1"
  result "FAIL  [$step_number] $1"
  failures=$((failures + 1))
}
skipped() {
  say "  skipped: $1"
  result "skip  [$step_number] $1"
}
# check DESCRIPTION COMMAND...: the command's success is the verdict.
check() {
  local what=$1
  shift
  if "$@"; then ok "$what"; else bad "$what"; fi
}

# What only you can see. The answer goes into the results as it is.
ask() {
  local name=$1 question=$2 answer
  printf '\033[1;36m ? \033[0m %s [y/n, or a few words] ' "$question"
  read -r answer </dev/tty
  result "saw   [$step_number] $name: ${answer:-no answer}"
}

pause() {
  printf '\033[1;36m ? \033[0m %s [Enter] ' "$1"
  read -r _ </dev/tty
}

# ------------------------------------------------------------ the key's side

# The security keys skagent would use: those on USB HID. Where pcscd runs,
# libfido2 lists a YubiKey once more over PC/SC (pcsc://slot0), which
# skagent leaves alone.
listed() { fido2-token -L 2>/dev/null | grep '^/dev/hidraw'; }
device() { listed | cut -d: -f1; }
device_field() { fido2-token -I "$1" 2>/dev/null | sed -n "s/^$2: //p" | head -n 1; }

mapfile -t devices < <(device)
case ${#devices[@]} in
  0) die "no security key found (fido2-token -L lists none on /dev/hidraw*)" ;;
  1) dev=${devices[0]} ;;
  *) die "several security keys are plugged in; leave only the one to check" ;;
esac

bold "skagent age check"
say "Security key: $(listed | head -n 1)"
say "This creates one credential (skagent:age) on it and offers to delete it"
say "at the end. Don't use ssh or sign commits with this key meanwhile: your"
say "own agent would ask the key at the same time."
pause "Go on?"

result "key   firmware $(device_field "$dev" fwversion), versions $(device_field "$dev" 'version strings')"
result "key   extensions $(device_field "$dev" 'extension strings')"
retries_before=$(device_field "$dev" 'pin retries')
slots_before=$(device_field "$dev" 'remaining rk(s)')
result "key   PIN retries $retries_before, free slots ${slots_before:-unknown} before"

# --------------------------------------------------------- the agent's side

base=${XDG_RUNTIME_DIR:-/tmp}
dir=$(mktemp -d "$base/skagent-check.XXXXXX") || die "mktemp failed"
work=$dir/work
mkdir -p "$work"
log=$dir/agent.log
sock=$dir/agent.sock
export SKAGENT_AGE_SOCKET=$dir/agent-age.sock
agent_pid=""
credential=""
deleted=no

stop_agent() {
  if [ -n "$agent_pid" ]; then
    kill "$agent_pid" 2>/dev/null
    wait "$agent_pid" 2>/dev/null
    agent_pid=""
  fi
}

# start_agent STATE: an agent that knows nothing but what is in STATE.
start_agent() {
  XDG_STATE_HOME=$1 skagent serve --socket "$sock" --age-socket "$SKAGENT_AGE_SOCKET" \
    --no-pairing --age-forwarding --log skagent=debug "${prompt[@]}" 2>>"$log" &
  agent_pid=$!
  local waited=0
  until [ -S "$sock" ] && [ -S "$SKAGENT_AGE_SOCKET" ]; do
    sleep 0.1
    waited=$((waited + 1))
    if [ "$waited" -gt 100 ] || ! kill -0 "$agent_pid" 2>/dev/null; then
      tail -n 5 "$log" >&2
      die "the agent didn't start; its log is $log"
    fi
  done
  # Watching lock and sleep starts a moment after the sockets are there.
  sleep 2
}

cleanup() {
  stop_agent
  if [ -n "$credential" ] && [ "$deleted" = no ]; then
    printf '\nThe test credential is still on the key. Delete it with:\n  fido2-token -D -i %s %s\n' \
      "$credential" "$(device | head -n 1)" >&2
  fi
  printf 'The agent'"'"'s log (no PINs in it) is kept: %s\n' "$log" >&2
}
trap cleanup EXIT

# How often the agent said TEXT so far.
said() { grep -cF -- "$1" "$log" 2>/dev/null || true; }

# wait_said TEXT COUNT SECONDS: until the agent said TEXT COUNT times.
wait_said() {
  local waited=0
  while [ "$(said "$1")" -lt "$2" ]; do
    sleep 0.5
    waited=$((waited + 1))
    [ "$waited" -ge $(($3 * 2)) ] && return 1
  done
  return 0
}

# Seconds between the last line saying FROM and the last one saying TO.
seconds_between() {
  local from to
  from=$(grep -F -- "$1" "$log" | tail -n 1 | sed 's/\x1b\[[0-9;]*m//g' | cut -d' ' -f1)
  to=$(grep -F -- "$2" "$log" | tail -n 1 | sed 's/\x1b\[[0-9;]*m//g' | cut -d' ' -f1)
  [ -n "$from" ] && [ -n "$to" ] || return 1
  awk -v a="$(date -d "$from" +%s.%N)" -v b="$(date -d "$to" +%s.%N)" 'BEGIN { printf "%.1f", b - a }'
}

decrypt() { (cd "$work" && age -d -i id.txt "$1"); }

# What the batches run, in the working directory so prompts name them short.
cat >"$work/decrypt-all" <<'EOF'
#!/bin/sh
for file in "$@"; do
  age -d -i id.txt "$file" || exit 1
done
EOF
cat >"$work/gated" <<'EOF'
#!/bin/sh
# Decrypts the first file, says so, and goes on with the rest once told to.
age -d -i id.txt "$1" || exit 1
touch first-done
while [ ! -e go ]; do sleep 0.2; done
shift
for file in "$@"; do
  age -d -i id.txt "$file" || exit 1
done
EOF
chmod +x "$work/decrypt-all" "$work/gated"

# start_gated FILE...: a batch that decrypts the first file (one touch) and
# waits. Its output goes to gated.out, its exit status to gated.status.
start_gated() {
  rm -f "$work/first-done" "$work/go" "$work/gated.out" "$work/gated.status"
  (
    cd "$work" || exit 1
    skagent batch -- ./gated "$@" >gated.out 2>gated.err
    echo $? >gated.status
  ) &
  todo "Touch the key when it blinks (enter the PIN first if it asks)."
  local waited=0
  until [ -e "$work/first-done" ]; do
    sleep 0.5
    waited=$((waited + 1))
    if [ -e "$work/gated.status" ] || [ "$waited" -gt 240 ]; then
      cat "$work/gated.err" >&2
      return 1
    fi
  done
}

# finish_gated EXPECTED: lets the batch's command go on, and compares what
# it printed in the end.
finish_gated() {
  touch "$work/go"
  local waited=0
  until [ -e "$work/gated.status" ]; do
    sleep 0.5
    waited=$((waited + 1))
    [ "$waited" -gt 360 ] && return 1
  done
  [ "$(cat "$work/gated.status")" = 0 ] && [ "$(grep -c '^file-' "$work/gated.out")" = "$1" ]
}

step "The agent"
start_agent "$dir/state"
if [ "$(said 'machine sleeps (logind)')" -ge 1 ]; then
  ok "the agent watches lock and sleep, so it caches PINs and batches keep their key"
else
  bad "the agent can't watch lock and sleep (no logind session?): nothing is kept, the batch steps will fail"
fi

step "A new identity"
say "skagent asks for the PIN. Then the key should blink twice: once to create"
say "the credential, once to read its recipient."
todo "Enter the PIN, then touch the key each time it blinks."
started=$(date +%s.%N)
recipient=$(skagent age new 2>"$work/new.err")
if [ -z "$recipient" ] && grep -q . "$work/new.err" && [ "$(said 'holds an age identity already')" -ge 1 ]; then
  say "  The key holds an age identity already; adding one more for the check."
  todo "Enter the PIN again, then touch the key each time it blinks."
  recipient=$(skagent age new --another 2>"$work/new.err")
fi
[ -n "$recipient" ] || {
  cat "$work/new.err" >&2
  die "no identity was created"
}
result "time  [$step_number] creating took $(awk -v a="$started" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }') s, PIN included"
is_recipient() { [ "${#1}" = 1959 ] && [ "${1#age1pq1}" != "$1" ]; }
check "the recipient is a post-quantum age recipient of 1959 characters" is_recipient "$recipient"
# The fresh state knows this one identity: its credential is the one to
# delete in the end, as fido2-token names it (base64).
hex=$(sed -n 's/^credential = "\(.*\)"$/\1/p' "$dir/state/skagent/age.toml" | head -n 1)
# shellcheck disable=SC2059
credential=$(printf "$(printf '%s' "$hex" | sed 's/../\\x&/g')" | base64 -w0)
[ -n "$hex" ] || bad "the agent's state names no credential"
ask "creating" "Did the key want exactly two touches, and did the prompt say it creates an age identity?"

skagent age identity >"$work/id.txt" || die "no identity file"
age-keygen -pq -o "$work/other.key" 2>/dev/null
for number in $(seq 1 "$files"); do
  echo "file-$number" | age -r "$recipient" -o "$work/f$number.age" || die "age can't encrypt to the recipient"
done
echo "for-someone-else" | age -r "$(age-keygen -y "$work/other.key")" -o "$work/other.age"
ok "stock age encrypted $files files to the recipient, without the agent"

step "One file, one touch"
say "The PIN is cached from creating the identity: only a touch is needed."
todo "Touch the key when it blinks."
cached=$(said 'using the cached PIN')
check "a file is decrypted" test "$(decrypt f1.age 2>"$work/err")" = file-1
check "with the cached PIN" test "$(said 'using the cached PIN')" -gt "$cached"
todo "Touch the key once more: a file for somebody else."
if decrypt other.age >/dev/null 2>"$work/err"; then
  bad "a file for another recipient was decrypted"
else
  ok "a file for another recipient costs a touch and opens nothing"
fi
ask "one-file" "Did each of the two ask for one touch, without the PIN, and say that a file is decrypted?"

step "No touch, no file"
say "This measures how long the key waits for a touch."
todo "Do NOT touch the key. Wait until this step says it is over (up to a minute)."
before=$(said 'nobody touched the security key in time')
(decrypt f1.age >"$work/untouched.out" 2>"$work/untouched.err") &
untouched=$!
if [ "$popup" = yes ]; then
  # Once the key gave up, the popup offers to try again and waits for that.
  while kill -0 "$untouched" 2>/dev/null &&
    [ "$(said 'nobody touched the security key in time')" -le "$before" ]; do
    sleep 0.5
  done
  if kill -0 "$untouched" 2>/dev/null; then
    todo "The popup says \"Timed out\". Press Esc in it."
  fi
fi
wait "$untouched"
if [ -s "$work/untouched.out" ]; then
  bad "a file was decrypted without a touch"
else
  why=$(grep -m 1 -F 'error:' "$work/untouched.err" || tail -n 1 "$work/untouched.err")
  ok "without a touch nothing is decrypted (${why#age: error: })"
fi
# The popup says "Timed out" and logs it; without one the plugin is told.
if [ "$(said 'nobody touched the security key in time')" -gt "$before" ] ||
  grep -q 'nobody answered in time' "$work/untouched.err"; then
  ok "and the agent takes the key's answer for a touch that never came"
else
  bad "the agent doesn't take the key's answer for a touch that never came"
fi
if waited=$(seconds_between 'decrypting on the security key' 'nobody touched the security key in time'); then
  result "time  [$step_number] the key waits $waited s for a touch"
elif waited=$(seconds_between 'decrypting on the security key' 'refused to decrypt'); then
  result "time  [$step_number] the key waits about $waited s for a touch"
fi

step "A batch: $files files for one touch"
say "The prompt should say that this starts a batch: \"Decrypt files for 10 min ·"
say "./decrypt-all …\" in the popup, \"(a batch)\" in pinentry. Look at it before"
say "you touch."
todo "Touch the key once when it blinks."
in_batch=$(said 'decrypted in a batch, without a touch')
list=$(for number in $(seq 1 "$files"); do printf 'f%s.age ' "$number"; done)
started=$(date +%s.%N)
# shellcheck disable=SC2086
out=$(cd "$work" && skagent batch -- ./decrypt-all $list 2>"$work/err")
elapsed=$(awk -v a="$started" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }')
check "all $files files are decrypted" test "$(printf '%s\n' "$out" | grep -c '^file-')" = "$files"
check "all but the first without the key" \
  test $(($(said 'decrypted in a batch, without a touch') - in_batch)) = $((files - 1))
result "time  [$step_number] the batch took $elapsed s, the touch included"
result "seed  [$step_number] kept in $(grep -F 'the batch started' "$log" | tail -n 1 | sed -n 's/.*memory=\([A-Za-z]*\).*/\1/p') memory"
ask "batch" "Was it exactly one touch, and did the prompt name the batch and its command?"

step "After the batch, and next to one"
todo "Touch the key when it blinks: the batch is over, a file takes a touch again."
ordinary=$(said 'decrypting on the security key')
check "a file is decrypted after the batch" test "$(decrypt f2.age 2>"$work/err")" = file-2
check "by the key, not from a kept one" test "$(said 'decrypting on the security key')" -gt "$ordinary"

say "Now a batch that waits after its first file, and a program outside it."
if start_gated f1.age f2.age f3.age; then
  todo "Touch the key once more: this decryption isn't the batch's."
  in_batch=$(said 'decrypted in a batch, without a touch')
  check "a program outside the batch is asked for a touch" test "$(decrypt f4.age 2>"$work/err")" = file-4
  check "and gets nothing from the batch" test "$(said 'decrypted in a batch, without a touch')" = "$in_batch"
  check "the batch's own further files need no touch" finish_gated 3
else
  bad "the waiting batch didn't start"
fi

step "Stop, in the notification"
if [ "$skip_stop" = yes ]; then
  skipped "stopping a batch from its notification"
elif start_gated f1.age f2.age f3.age; then
  stopped=$(said 'reason=stopped by the user')
  say "A notification \"skagent batch: ./gated …\" should be up by now, saying"
  say "\"1 file decrypted without a touch\", with a Stop button."
  todo "Press Stop in the notification."
  todo "If there is no such button, press Enter here to go on without."
  while [ "$(said 'reason=stopped by the user')" = "$stopped" ]; do
    if read -r -t 1 _ </dev/tty; then break; fi
  done
  if [ "$(said 'reason=stopped by the user')" -gt "$stopped" ]; then
    ok "Stop ended the batch"
    todo "Touch the key twice, as it blinks: the two files left take a touch each."
    ordinary=$(said 'decrypting on the security key')
    check "the command's further files are decrypted" finish_gated 3
    check "each by the key" test $(($(said 'decrypting on the security key') - ordinary)) = 2
  else
    skipped "stopping a batch from its notification (no button, or not pressed)"
    finish_gated 3 || true
  fi
  ask "notification" "What did the notification look like, and which notification program do you use?"
else
  bad "the waiting batch didn't start"
fi

step "Unplugging the key"
if [ "$skip_unplug" = yes ]; then
  skipped "unplugging the key during a batch"
elif start_gated f1.age f2.age; then
  unplugged=$(said 'reason=the security key was unplugged')
  todo "Unplug the key now. Leave it out until told (up to 20 s)."
  if wait_said 'reason=the security key was unplugged' $((unplugged + 1)) 60; then
    ok "the agent noticed and ended the batch"
  else
    bad "the batch wasn't ended within a minute of unplugging"
  fi
  todo "Plug the key back in."
  until [ -n "$(device)" ]; do sleep 0.5; done
  sleep 1
  todo "Enter the PIN (it was dropped with the unplug), then touch the key."
  selections=$(said 'touch the key holding the requested credential')
  check "the command's further file is decrypted" finish_gated 2
  if [ "$(said 'touch the key holding the requested credential')" -gt "$selections" ]; then
    result "note  [$step_number] after the replug the key had to be selected by a touch of its own"
  else
    result "note  [$step_number] after the replug the key was recognized without a touch of its own"
  fi
  ask "replug" "After plugging in again: was the PIN asked for, and how many touches did the one file take?"
else
  bad "the waiting batch didn't start"
fi

step "Locking the screen"
if [ "$skip_lock" = yes ]; then
  skipped "locking the screen during a batch"
elif start_gated f1.age f2.age; then
  evicted=$(said 'reason=PINs were dropped')
  todo "Lock your screen, and unlock it again. (Enter here goes on without.)"
  while [ "$(said 'reason=PINs were dropped')" = "$evicted" ]; do
    if read -r -t 1 _ </dev/tty; then break; fi
  done
  if [ "$(said 'reason=PINs were dropped')" -gt "$evicted" ]; then
    ok "locking ended the batch"
  else
    skipped "locking the screen (the agent heard of no lock); forgetting the PINs in its place"
    skagent forget --socket "$sock"
    check "skagent forget ended the batch" test "$(said 'reason=PINs were dropped')" -gt "$evicted"
  fi
  todo "Enter the PIN, then touch the key."
  check "the command's further file is decrypted" finish_gated 2
else
  bad "the waiting batch didn't start"
fi

step "Asked through the ssh-agent socket"
say "What comes in there counts as another machine. The touch prompt should say"
say "so: \"Decrypt a file · for Unknown host\" in the popup. Look at it before"
say "you touch."
todo "Touch the key when it blinks."
out=$(cd "$work" && SKAGENT_AGE_SOCKET=$sock age -d -i id.txt f3.age 2>"$work/err")
check "a file is decrypted" test "$out" = file-3
check "for an unverified host, as the log has it" \
  test "$(said 'decrypt a file for an unverified host (through your forwarded agent)')" -ge 1
ask "forwarded" "Did the touch prompt say that an unknown host asks?"

step "An agent that knows nothing yet"
say "A new agent with empty state, as on another machine: skagent load finds"
say "the identity on the key, and its key is the same as before."
stop_agent
start_agent "$dir/state-fresh"
todo "Enter the PIN for skagent load."
loaded=$(skagent load --socket "$sock" 2>&1)
say "  $loaded" | tr '\n' ' '
say ""
found=$(sed -n 's/^Found \([0-9]*\) age identity.*/\1/p' <<<"$loaded")
check "skagent load finds the age identity" test "${found:-0}" -ge 1
if [ "${found:-0}" -le 1 ]; then
  todo "Touch the key when it blinks."
else
  # Which of them the file names, only the key's answers tell: the agent
  # tries them in turn, and knows each from then on.
  say "The key holds $found identities, and this agent has used none of them yet."
  todo "Touch the key each time it blinks: up to $found times, until it found the one."
fi
ordinary=$(said 'decrypting on the security key')
check "a file is decrypted" test "$(decrypt f5.age 2>"$work/err")" = file-5
check "the identity's recipient is the one from the start" grep -qxF "$recipient" <<<"$(skagent age list 2>/dev/null)"
result "note  [$step_number] finding the identity among ${found:-0} took $(($(said 'decrypting on the security key') - ordinary)) touch(es)"

step "The key afterwards"
stop_agent
dev=$(device | head -n 1)
retries_after=$(device_field "$dev" 'pin retries')
check "the PIN retry counter is where it was ($retries_before)" test "$retries_after" = "$retries_before"
printf '\033[1;36m ? \033[0m %s [Y/n] ' "Delete the test identity from the key now? fido2-token asks for the PIN."
read -r answer </dev/tty
if [ "${answer:-y}" = y ] || [ "${answer:-y}" = Y ]; then
  if fido2-token -D -i "$credential" "$dev"; then
    deleted=yes
    ok "the test credential is deleted"
    slots_after=$(device_field "$dev" 'remaining rk(s)')
    result "key   free slots ${slots_after:-unknown} after (${slots_before:-unknown} before)"
  else
    bad "deleting the test credential failed"
  fi
else
  deleted=kept
  result "key   the test credential was kept: fido2-token -D -i $credential $dev"
fi

bold "Results (paste these)"
say "skagent $(skagent --version 2>/dev/null | cut -d' ' -f2), age $(age --version 2>/dev/null), kernel $(uname -r), prompt ${prompt[0]}"
printf '%s\n' "${results[@]}"
say "$failures failed"
[ "$failures" = 0 ]
