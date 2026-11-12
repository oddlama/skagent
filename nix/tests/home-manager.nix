# The home-manager module on NixOS: a socket-activated user service that
# loads keys when the graphical session starts, prompts with that session's
# display variables, and stops with the session.
{
  pkgs,
  testkey,
  homeManager,
  skagentModule,
}:
let
  common = import ./common.nix { inherit pkgs; };
  pin = "246810";
  uid = 1000;
  runtimeDir = "/run/user/${toString uid}";
  socket = "${runtimeDir}/skagent.sock";
  touchFile = "/run/testkey-touch";
  testDir = "/home/alice/test";

  # The test pinentry, recording what the agent handed it: the display
  # variable, systemd's activation variables and every open descriptor.
  envPinentry = pkgs.writeShellApplication {
    name = "env-pinentry";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      {
        echo "start WAYLAND_DISPLAY=''${WAYLAND_DISPLAY:-} LISTEN_PID=''${LISTEN_PID:-} LISTEN_FDS=''${LISTEN_FDS:-}"
        for fd in /proc/"$$"/fd/*; do
          echo "fd $(readlink "$fd")"
        done
      } >>"$SKAGENT_TEST_PINENTRY_ENV"
      exec ${pkgs.lib.getExe common.testPinentry}
    '';
  };
in
pkgs.testers.runNixOSTest {
  name = "skagent-home-manager";

  nodes.machine = {
    imports = [
      common.virtualKeyMachine
      homeManager
    ];
    environment.systemPackages = [
      testkey
      common.testAskpass
      common.fakeNotifications
      pkgs.libfido2
      pkgs.openssh
    ];
    security.polkit.enable = true;
    # A logind session for alice starts her user manager.
    services.getty.autologinUser = "alice";
    security.pam.services.login.rules.session.systemd.args = [ "type=wayland" ];
    users.users.alice = {
      isNormalUser = true;
      inherit uid;
    };

    home-manager.useGlobalPkgs = true;
    home-manager.users.alice = {
      imports = [ skagentModule ];
      home.stateVersion = "26.05";
      programs.bash.enable = true;
      services.skagent = {
        enable = true;
        pinentry.package = envPinentry;
        loadAtLogin = true;
        pinPolicies = [
          {
            application = "ssh:example";
            lifetime = "4h";
          }
        ];
        secretMemory = "memfd-secret";
      };
      # Stands in for a compositor's session target (sway-session.target).
      systemd.user.targets.test-session.Unit = {
        BindsTo = [ "graphical-session.target" ];
        Wants = [ "graphical-session-pre.target" ];
        After = [ "graphical-session-pre.target" ];
      };
    };
  };

  testScript = ''
    import shlex

    def as_alice(command: str) -> str:
        """A login shell in alice's user manager, like a terminal on her desktop."""
        return f"systemd-run --machine=alice@ --user --wait --pipe --quiet -- /run/current-system/sw/bin/bash -lc {shlex.quote(command)} 2>&1"

    def user(command: str) -> tuple[int, str]:
        return machine.execute(as_alice(command))

    def user_ok(command: str) -> str:
        status, out = user(command)
        assert status == 0, f"{command!r} exited {status}: {out}"
        return out

    def state(unit: str) -> str:
        return user_ok(f"systemctl --user show {unit} -p ActiveState --value").strip()

    def journal(unit: str) -> str:
        # Not --user-unit: that also matches the caller's uid.
        return machine.succeed(f"journalctl _SYSTEMD_USER_UNIT={unit}.service --no-pager -o cat")

    def prompts() -> int:
        return machine.succeed("cat ${testDir}/pinentry 2>/dev/null || true").count("GETPIN")

    def pinentry_env() -> list[str]:
        return machine.succeed("cat ${testDir}/pinentry-env 2>/dev/null || true").splitlines()

    def touch() -> None:
        machine.succeed("touch ${touchFile}")

    def login(display: str) -> None:
        """Starts a graphical session the way compositors do: environment first."""
        user_ok(f"systemctl --user set-environment WAYLAND_DISPLAY={display}")
        user_ok("systemctl --user start test-session.target")

    def logout() -> None:
        user_ok("systemctl --user stop test-session.target")

    def loaded() -> None:
        """Waits for the login's `skagent load` to finish, successfully."""
        retry(lambda _last_try: state("skagent-load") in ["inactive", "failed"], timeout_seconds=30)
        result = user_ok("systemctl --user show skagent-load -p Result --value").strip()
        assert result == "success", (result, journal("skagent-load"), journal("skagent"))

    machine.wait_for_unit("home-manager-alice.service")
    machine.wait_for_unit("user@${toString uid}.service")
    machine.succeed(
        "systemd-run --unit testkey --setenv SKAGENT_TESTKEY_PIN=${pin}"
        " ${testkey}/bin/skagent-testkey --touch file --touch-file ${touchFile} --name 'test key'"
    )
    machine.wait_until_succeeds("fido2-token -L | grep -F 'test key' >/dev/null")
    retry(lambda _last_try: state("skagent.socket") == "active", timeout_seconds=30)

    with subtest("the socket is owner-only and waits for the first client"):
        assert machine.succeed("stat -c '%a %U %F' ${socket}").strip() == "600 alice socket", \
            machine.succeed("ls -la ${runtimeDir}")
        assert state("skagent") == "inactive", state("skagent")

    with subtest("SSH_AUTH_SOCK points at skagent in login shells and in systemd"):
        out = user_ok("env -u SSH_AUTH_SOCK bash -lc 'echo $SSH_AUTH_SOCK'")
        assert out.strip() == "${socket}", out
        assert "SSH_AUTH_SOCK=${socket}\n" in user_ok("systemctl --user show-environment")
        assert state("skagent") == "inactive", "setting SSH_AUTH_SOCK started the agent"

    with subtest("enroll a resident verify-required key"):
        user_ok("install -d -m 700 ${testDir} && echo ${pin} > ${testDir}/pin && echo hello > ${testDir}/msg")
        touch()
        user_ok(
            "SSH_ASKPASS=test-askpass SSH_ASKPASS_REQUIRE=force SKAGENT_TEST_ANSWER=${pin}"
            " ssh-keygen -q -t ed25519-sk -O resident -O verify-required -O application=ssh:example"
            " -N ''' -C alice@virtual -f ~/id_sk"
        )
        user_ok("echo \"alice $(cat ~/id_sk.pub)\" > ${testDir}/allowed")
        user_ok(
            "systemctl --user set-environment"
            " SKAGENT_TEST_ANSWER_FILE=${testDir}/pin"
            " SKAGENT_TEST_PINENTRY_LOG=${testDir}/pinentry"
            " SKAGENT_TEST_PINENTRY_ENV=${testDir}/pinentry-env"
        )
        machine.succeed(
            "systemd-run --machine=alice@ --user --unit fake-notifications"
            " --setenv DBUS_SESSION_BUS_ADDRESS=unix:path=${runtimeDir}/bus"
            " /run/current-system/sw/bin/fake-notifications ${testDir}/notifications"
        )
        machine.wait_until_succeeds(as_alice(
            "busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus"
            " NameHasOwner s org.freedesktop.Notifications | grep -F 'b true'"
        ), timeout=15)

    with subtest("logging in loads the keys, asking with the session's pinentry"):
        login("wayland-first")
        loaded()
        assert prompts() == 1, prompts()
        public = user_ok("cut -d' ' -f1,2 ~/id_sk.pub").strip()
        assert public in user_ok("ssh-add -L")
        start, *fds = pinentry_env()
        assert start == "start WAYLAND_DISPLAY=wayland-first LISTEN_PID= LISTEN_FDS=", start
        # Neither the activated socket nor the security key the agent has
        # open while asking (libfido2 opens it without close-on-exec).
        assert not any("socket:" in fd or "/dev/hidraw" in fd for fd in fds), fds

    with subtest("the module's options reach the agent"):
        out = journal("skagent")
        assert "activated=true" in out, out
        assert "caching the PINs of matching keys differently" in out, out
        assert 'Application("ssh:example")' in out, out
        pid = user_ok("systemctl --user show skagent -p MainPID --value").strip()
        maps = machine.succeed(f"cat /proc/{pid}/maps")
        assert "secretmem" in maps, (pid, maps)
        status = machine.succeed(f"cat /proc/{pid}/status")
        assert "\nNoNewPrivs:\t1\n" in status, status
        assert "\nSeccomp:\t2\n" in status, "no seccomp filter: " + status

    with subtest("signing needs a touch, notified, and uses the PIN cached by loading"):
        touch()
        user_ok("rm -f ${testDir}/msg.sig && ssh-keygen -Y sign -f ~/id_sk.pub -n test ${testDir}/msg")
        out = user_ok(
            "ssh-keygen -Y verify -f ${testDir}/allowed -I alice -n test"
            " -s ${testDir}/msg.sig < ${testDir}/msg"
        )
        assert "Good" in out, out
        assert prompts() == 1, "signing asked for the PIN again"
        shown = machine.succeed("cat ${testDir}/notifications")
        assert "Touch your security key" in shown, shown
        retry(lambda _last_try: "close 1\n" in machine.succeed("cat ${testDir}/notifications"), timeout_seconds=5)

    with subtest("ending the session stops the agent, and with it every PIN and key"):
        logout()
        retry(lambda _last_try: state("skagent") == "inactive", timeout_seconds=15)
        assert state("skagent.socket") == "active"
        machine.succeed("test -S ${socket}")
        # The next client starts a fresh, empty agent.
        status, out = user("ssh-add -L")
        assert status == 1 and "no identities" in out, (status, out)
        assert state("skagent") == "active"
        # Started outside a session, it would keep that environment.
        user_ok("systemctl --user stop skagent.service")

    with subtest("the next session's prompt gets that session's display"):
        login("wayland-second")
        loaded()
        assert prompts() == 2, prompts()
        assert pinentry_env().count("start WAYLAND_DISPLAY=wayland-second LISTEN_PID= LISTEN_FDS=") == 1, pinentry_env()

    with subtest("skagent forget finds the socket without --socket"):
        user_ok("skagent forget")
        touch()
        user_ok("rm -f ${testDir}/msg.sig && ssh-keygen -Y sign -f ~/id_sk.pub -n test ${testDir}/msg")
        assert prompts() == 3, "forgetting didn't drop the cached PIN"
  '';
}
