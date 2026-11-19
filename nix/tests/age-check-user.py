"""Runs skagent-age-check like a person would, and only as told: answers
its questions, touches the key as often as it says, unplugs and plugs the
key, and presses Stop.

usage: age-check-user PIN TOUCH_FILE UNPLUGGED_FILE PRESS_FILE -- COMMAND...

A touch is the touch file; the virtual key removes it when it takes one.
"""

import os
import sys
import time

import pexpect

pin, touch_file, unplugged, press = sys.argv[1:5]
command = sys.argv[6:]

child = pexpect.spawn(command[0], command[1:], encoding="utf-8", timeout=180)
child.logfile_read = sys.stdout


def answer(text):
    return lambda: child.sendline(text)


def touch(times):
    """Touches the key `times` times, each once it took the one before."""

    def act():
        for _ in range(times):
            with open(touch_file, "w"):
                pass
            deadline = time.monotonic() + 120
            while os.path.exists(touch_file):
                if time.monotonic() > deadline:
                    sys.exit("the key never asked for a touch it was told of")
                time.sleep(0.05)

    return act


def unplug():
    with open(unplugged, "w"):
        pass


def press_stop():
    with open(press, "w") as file:
        file.write("stop\n")


def nothing():
    pass


# What the check says, and what a person does then. In its order.
steps = [
    ("Go on?", answer("")),
    ("touch the key each time it blinks", touch(2)),
    ("exactly two touches", answer("y")),
    ("Touch the key when it blinks.", touch(1)),
    ("Touch the key once more: a file for somebody else", touch(1)),
    ("Did each of the two ask for one touch", answer("y")),
    ("Do NOT touch the key", nothing),
    ("Touch the key once when it blinks", touch(1)),
    ("Was it exactly one touch", answer("y")),
    ("Did a notification count", answer("a fake one")),
    ("the batch is over, a file takes a touch again", touch(1)),
    ("enter the PIN first if it asks", touch(1)),
    ("this decryption isn't the batch's", touch(1)),
    ("enter the PIN first if it asks", touch(1)),
    ("Press Stop in the notification", press_stop),
    ("Touch the key twice", touch(2)),
    ("enter the PIN first if it asks", touch(1)),
    ("Unplug the key now", unplug),
    ("Plug the key back in", lambda: os.remove(unplugged)),
    ("it was dropped with the unplug", touch(1)),
    ("how many touches did the one file take", answer("one")),
    ("enter the PIN first if it asks", touch(1)),
    # No screen to lock here: Enter goes on, and the check forgets the PINs
    # itself.
    ("Lock your screen", answer("")),
    ("Enter the PIN, then touch the key", touch(1)),
    ("Touch the key when it blinks.", touch(1)),
    ("Did the touch prompt say that an unknown host asks", answer("y")),
    ("Enter the PIN for skagent load", nothing),
    ("Touch the key when it blinks.", touch(1)),
    ("Delete the test identity", answer("y")),
    ("Enter PIN for", answer(pin)),
    ("Results (paste these)", nothing),
]

for text, act in steps:
    child.expect_exact(text)
    act()

child.expect(pexpect.EOF)
child.close()
sys.exit(child.exitstatus if child.exitstatus is not None else 1)
