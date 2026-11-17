"""A fake skagent popup for the VM tests. Logs what it is shown and answers
like a user would, as the files in $SKAGENT_TEST_POPUP_DIR say:

- log: every line received, plus "start" and "exit"
- answers: PINs to enter, one line each, used up in order; then pin
- cancel-pin: cancel PIN prompts
- cancel-touch: cancel while the key waits for a touch
"""

import json
import os
import sys

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
say("READY 1")
for line in sys.stdin:
    line = line.rstrip("\n")
    log(line)
    message = json.loads(line)
    if message["type"] != "show":
        continue
    seq = message["seq"]
    name = message["state"]["name"]
    if name in ("pin", "load-pin"):
        if os.path.exists(path("cancel-pin")):
            say(f"CANCEL {seq}")
        else:
            say(f"PIN {seq} {escaped(next_pin())}")
    elif name == "touch" and os.path.exists(path("cancel-touch")):
        say(f"CANCEL {seq}")
log("exit")
