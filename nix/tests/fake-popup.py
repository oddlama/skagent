"""A fake skagent popup for the VM tests. Logs what it is shown and answers
like a user would, as the files in $SKAGENT_TEST_POPUP_DIR say:

- log: every line received, plus "start" and "exit"
- blind: take the states without saying that they are shown, like a popup
  whose window never appears
- answers: PINs to enter, one line each, used up in order; then pin
- cancel-pin: cancel PIN prompts
- hold-pin: wait with the answer to a PIN prompt while this exists
- cancel-wait: cancel while waiting for a security key to be plugged in
- cancel-touch: cancel while the key waits for a touch
- retry: try again after a touch timeout, else cancel
"""

import json
import os
import sys
import time

directory = os.environ["SKAGENT_TEST_POPUP_DIR"]


def path(name):
    return os.path.join(directory, name)


def log(line):
    with open(path("log"), "a") as file:
        file.write(line + "\n")


def say(line):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def escaped(pin):
    return pin.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def next_pin():
    try:
        with open(path("answers")) as file:
            answers = file.read().splitlines()
    except FileNotFoundError:
        answers = []
    if answers:
        with open(path("answers"), "w") as file:
            file.write("".join(answer + "\n" for answer in answers[1:]))
        return answers[0]
    with open(path("pin")) as file:
        return file.read().strip()


log("start")
say("READY 2")
for line in sys.stdin:
    line = line.rstrip("\n")
    log(line)
    message = json.loads(line)
    if message["type"] != "show":
        continue
    seq = message["seq"]
    name = message["state"]["name"]
    if os.path.exists(path("blind")):
        continue
    say(f"SHOWN {seq}")
    if name in ("pin", "load-pin"):
        while os.path.exists(path("hold-pin")):
            time.sleep(0.1)
        if os.path.exists(path("cancel-pin")):
            say(f"CANCEL {seq}")
        else:
            say(f"PIN {seq} {escaped(next_pin())}")
    elif name == "touch" and os.path.exists(path("cancel-touch")):
        say(f"CANCEL {seq}")
    elif name in ("no-key", "wrong-key"):
        if os.path.exists(path("cancel-wait")):
            say(f"CANCEL {seq}")
    elif name == "timeout":
        retry = os.path.exists(path("retry"))
        say(f"RETRY {seq}" if retry else f"CANCEL {seq}")
log("exit")
