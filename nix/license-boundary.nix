# Fails if one of `shippedCrates` depends, directly or transitively, on a
# crate it has to stay clear of: by default the ones that may only be used
# by tests (soft-fido2 is AGPL-3.0). Walks Cargo.lock, so it covers every
# target and feature combination cargo resolved, build and test dependencies
# included.
{
  lib,
  runCommand,
  cargoLock,
  shippedCrates,
  # Crates that mustn't be reached: every name that starts with one of
  # these, and exactly these names.
  forbiddenPrefixes ? [ ],
  forbiddenNames ? [ ],
  name ? "license-boundary",
  # What the forbidden crates are, for the error.
  what ? "test-only crates",
}:
let
  lock = builtins.fromTOML (builtins.readFile cargoLock);
  # Lockfile dependency entries are "name", "name version" or "name version (source)".
  dependencyName = entry: builtins.head (lib.splitString " " entry);
  dependenciesOf =
    crate:
    lib.concatMap (package: map dependencyName (package.dependencies or [ ])) (
      builtins.filter (package: package.name == crate) lock.package
    );
  closure = lib.genericClosure {
    startSet = map (crate: { key = crate; }) shippedCrates;
    operator = item: map (crate: { key = crate; }) (dependenciesOf item.key);
  };
  reachable = map (item: item.key) closure;
  forbidden = builtins.filter (
    crate:
    builtins.any (prefix: lib.hasPrefix prefix crate) forbiddenPrefixes
    || builtins.elem crate forbiddenNames
  ) reachable;
in
runCommand name { } (
  if forbidden == [ ] then
    ''
      echo "${toString (builtins.length reachable)} crates reachable from ${toString shippedCrates}, none of them ${what}"
      touch $out
    ''
  else
    ''
      echo "${toString shippedCrates} depend on ${what}: ${toString forbidden}" >&2
      exit 1
    ''
)
