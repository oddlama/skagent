#!/usr/bin/env bash
# Hardware check for skagent's planned age support: how does this security key
# handle the FIDO2 hmac-secret extension?
#
# It uses Yubico's own command line tools (fido2-token, fido2-cred and
# fido2-assert from libfido2). The PIN is typed into those tools, never into
# this script, and no secret is printed.
#
# It creates one discoverable test credential (relying party
# "skagent:hmac-check") and deletes it at the end. If it stops early, it prints
# the command that deletes the credential.
#
# Usage: hmac-secret-check.sh [/dev/hidrawN]

set -u
umask 077

RP="skagent:hmac-check"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

results=()
result() { results+=("$1"); }

for tool in fido2-token fido2-cred fido2-assert base64 head sed grep; do
  command -v "$tool" >/dev/null || die "$tool not found; run this inside: nix shell --inputs-from . nixpkgs#libfido2"
done

# --- device ---------------------------------------------------------------

if [ $# -ge 1 ]; then
  dev=$1
else
  # Over USB HID only: where pcscd runs, a YubiKey is listed once more as
  # pcsc://slot0.
  mapfile -t devices < <(fido2-token -L | grep '^/dev/hidraw' | cut -d: -f1)
  case ${#devices[@]} in
    0) die "no FIDO2 device found (fido2-token -L lists none)" ;;
    1) dev=${devices[0]} ;;
    *)
      fido2-token -L >&2
      die "several devices; pass the one to check, e.g. $0 ${devices[0]}"
      ;;
  esac
fi

work=$(mktemp -d) || die "mktemp failed"
cred_id=""
deleted=no
cleanup() {
  rm -rf "$work"
  if [ -n "$cred_id" ] && [ "$deleted" = no ]; then
    printf '\nThe test credential is still on the key. Delete it with:\n  fido2-token -D -i %s %s\n' "$cred_id" "$dev" >&2
  fi
}
trap cleanup EXIT

random_b64() { head -c "$1" /dev/urandom | base64 -w0; }
decoded_len() { printf '%s' "$1" | base64 -d 2>/dev/null | wc -c; }
# The lines a tool wrote to stderr, without the PIN prompt.
errors_of() { grep -v '^Enter PIN' "$1" | tr '\n' ' '; }

# --- 0: what the key says about itself --------------------------------------

bold "0/6  Device information ($dev)"
info=$(fido2-token -I "$dev") || die "fido2-token -I $dev failed"
printf '%s\n' "$info" | grep -E '^(version strings|extension strings|algorithms|options|fwversion|remaining rk\(s\)|pin protocols|pin retries):'

extensions=$(printf '%s\n' "$info" | sed -n 's/^extension strings: //p')
has_extension() {
  case ", $extensions," in
    *", $1,"*) return 0 ;;
    *) return 1 ;;
  esac
}
result "device: $(fido2-token -L | grep -F "$dev:" | cut -d: -f2- | sed 's/^ //')"
result "firmware: $(printf '%s\n' "$info" | sed -n 's/^fwversion: //p')"
result "pin protocols: $(printf '%s\n' "$info" | sed -n 's/^pin protocols: //p')"
for extension in hmac-secret hmac-secret-mc credProtect; do
  if has_extension "$extension"; then
    result "extension $extension: listed"
  else
    result "extension $extension: NOT listed"
  fi
done
has_extension hmac-secret || die "the key doesn't list hmac-secret; nothing to check"

# --- 1: create the test credential -------------------------------------------

bold "1/6  Create the test credential (discoverable, credProtect 3, hmac-secret)"
echo "Type the FIDO2 PIN, then TOUCH the key when it blinks."
{
  random_b64 32
  echo
  echo "$RP"
  echo "skagent hmac-secret check"
  random_b64 16
  echo
} >"$work/cred_param"
if ! fido2-cred -M -r -h -c 3 -t pin=true -i "$work/cred_param" -o "$work/cred_out" "$dev" eddsa; then
  result "create: FAILED"
  die "creating the credential failed"
fi
cred_id=$(sed -n 5p "$work/cred_out")
[ -n "$cred_id" ] || die "no credential id in fido2-cred's output"
result "create: ok (attestation format: $(sed -n 3p "$work/cred_out"))"

# The key signs what it created: check that this says hmac-secret and credProtect 3.
if fido2-cred -V -h -c 3 -i "$work/cred_out" -o "$work/cred_verified" eddsa 2>"$work/err_verify"; then
  result "created with hmac-secret and credProtect 3 (signed by the key): yes"
else
  result "created with hmac-secret and credProtect 3 (signed by the key): NOT CONFIRMED ($(errors_of "$work/err_verify"))"
fi

# --- 2: derive with PIN and touch --------------------------------------------

bold "2/6  Derive a secret: PIN and touch"
echo "Type the PIN, then TOUCH the key when it blinks."
salt1=$(random_b64 32)
challenge=$(random_b64 32)
printf '%s\n%s\n%s\n%s\n' "$challenge" "$RP" "$cred_id" "$salt1" >"$work/assert_a"
secret_a=""
if fido2-assert -G -h -t pin=true -i "$work/assert_a" -o "$work/out_a" "$dev" 2>"$work/err_a"; then
  secret_a=$(tail -n 1 "$work/out_a")
  result "PIN + touch: ok, secret of $(decoded_len "$secret_a") bytes"
else
  result "PIN + touch: FAILED ($(errors_of "$work/err_a"))"
fi

# --- 3: same salt again, plus a second salt ----------------------------------

bold "3/6  Derive again with two salts: PIN and touch"
echo "Type the PIN, then TOUCH the key when it blinks."
{
  printf '%s' "$salt1" | base64 -d
  head -c 32 /dev/urandom
} | base64 -w0 >"$work/salt12"
printf '%s\n%s\n%s\n%s\n' "$challenge" "$RP" "$cred_id" "$(cat "$work/salt12")" >"$work/assert_b"
if fido2-assert -G -h -t pin=true -i "$work/assert_b" -o "$work/out_b" "$dev" 2>"$work/err_b"; then
  secret_b=$(tail -n 1 "$work/out_b")
  length_b=$(decoded_len "$secret_b")
  first=$(printf '%s' "$secret_b" | base64 -d | head -c 32 | base64 -w0)
  second=$(printf '%s' "$secret_b" | base64 -d | tail -c +33 | base64 -w0)
  result "two salts in one request: ok, $length_b bytes"
  if [ -n "$secret_a" ] && [ "$first" = "$secret_a" ]; then
    result "same salt gives the same secret: yes"
  else
    result "same salt gives the same secret: NO"
  fi
  if [ "$length_b" = 64 ] && [ "$first" != "$second" ]; then
    result "another salt gives another secret: yes"
  else
    result "another salt gives another secret: NO"
  fi
else
  result "two salts in one request: FAILED ($(errors_of "$work/err_b"))"
fi

# --- 4: PIN, but no touch ----------------------------------------------------

bold "4/6  Derive WITHOUT a touch: PIN only"
echo "Type the PIN. Do NOT touch the key, even if it blinks: this should fail right away."
echo "(If it blinks, leave it alone; it gives up after about 30 seconds.)"
if fido2-assert -G -h -t pin=true -t up=false -i "$work/assert_a" -o "$work/out_c" "$dev" 2>"$work/err_c"; then
  secret_c=$(tail -n 1 "$work/out_c")
  if [ "$(decoded_len "$secret_c")" = 32 ]; then
    if [ "$secret_c" = "$secret_a" ]; then
      result "without touch: RETURNED THE SAME SECRET (the key does not enforce the touch)"
    else
      result "without touch: returned a different 32-byte secret"
    fi
  else
    result "without touch: assertion succeeded, but no secret came back"
  fi
elif grep -qE 'FIDO_ERR_(UNSUPPORTED_OPTION|UP_REQUIRED)' "$work/err_c"; then
  # CTAP 2.1 names UNSUPPORTED_OPTION; older firmware answers UP_REQUIRED.
  # libfido2 never produces either itself, so the key said this.
  result "without touch: refused by the key ($(grep -oE 'FIDO_ERR_[A-Z_]+' "$work/err_c" | head -n 1))"
else
  result "without touch: failed another way ($(errors_of "$work/err_c"))"
fi

# --- 5: no PIN, no touch -----------------------------------------------------

bold "5/6  Use the credential without PIN and without touch (no input needed)"
printf '%s\n%s\n%s\n' "$challenge" "$RP" "$cred_id" >"$work/assert_d"
if fido2-assert -G -t up=false -t pin=false -i "$work/assert_d" -o "$work/out_d" "$dev" 2>"$work/err_d"; then
  result "without PIN: THE KEY ANSWERED (credProtect 3 not enforced)"
elif grep -q 'FIDO_ERR_NO_CREDENTIALS' "$work/err_d"; then
  result "without PIN: refused (FIDO_ERR_NO_CREDENTIALS), as expected"
else
  result "without PIN: failed another way ($(errors_of "$work/err_d"))"
fi

# --- 6: delete ---------------------------------------------------------------

bold "6/6  Delete the test credential"
echo "Type the PIN one last time."
if fido2-token -D -i "$cred_id" "$dev"; then
  deleted=yes
  result "delete: ok"
else
  result "delete: FAILED"
fi

bold "Results (paste these back)"
printf '%s\n' "${results[@]}"
