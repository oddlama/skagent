# Fails if a shipped crate depends, directly or transitively, on a crate that
# may only be used by tests (soft-fido2 is AGPL-3.0). Walks Cargo.lock, so it
# covers every target and feature combination cargo resolved.
{
  lib,
  runCommand,
  cargoLock,
  shippedCrates,
  forbiddenPrefixes,
}:
let
  lock = builtins.fromTOML (builtins.readFile cargoLock);
  # Lockfile dependency entries are "name", "name version" or "name version (source)".
  dependencyName = entry: builtins.head (lib.splitString " " entry);
  dependenciesOf =
    name:
    lib.concatMap (package: map dependencyName (package.dependencies or [ ])) (
      builtins.filter (package: package.name == name) lock.package
    );
  closure = lib.genericClosure {
    startSet = map (name: { key = name; }) shippedCrates;
    operator = item: map (name: { key = name; }) (dependenciesOf item.key);
  };
  reachable = map (item: item.key) closure;
  forbidden = builtins.filter (
    name: builtins.any (prefix: lib.hasPrefix prefix name) forbiddenPrefixes
  ) reachable;
in
runCommand "license-boundary" { } (
  if forbidden == [ ] then
    ''
      echo "${toString (builtins.length reachable)} crates reachable from ${toString shippedCrates}, none test-only"
      touch $out
    ''
  else
    ''
      echo "shipped crates depend on test-only crates: ${toString forbidden}" >&2
      exit 1
    ''
)
