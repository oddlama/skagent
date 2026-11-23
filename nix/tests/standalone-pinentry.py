"""A pinentry for the age client in the standalone plugin's test.

Speaks just enough Assuan. Each GETPIN is answered with the next line of
$STANDALONE_ANSWERS, which is used up; the line CANCEL, or none left, is a
cancel. An empty line is an empty answer. Every prompt's description goes
to $STANDALONE_PROMPTS, one line each, as a person would read it.
"""

import os
import re
import sys

answers = os.environ["STANDALONE_ANSWERS"]
prompts = os.environ["STANDALONE_PROMPTS"]


def say(line):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def unescaped(text):
    def byte(hexed):
        return chr(int(hexed[1], 16))

    return re.sub(r"%([0-9A-Fa-f]{2})", byte, text)


def escaped(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def next_answer():
    """The next line of the answers, or None for a cancel."""
    try:
        with open(answers) as file:
            lines = file.read().split("\n")
    except FileNotFoundError:
        return None
    if lines and lines[-1] == "":
        lines.pop()
    if not lines:
        return None
    with open(answers, "w") as file:
        file.write("".join(line + "\n" for line in lines[1:]))
    return None if lines[0] == "CANCEL" else lines[0]


description = ""
say("OK Pleased to meet you")
for line in sys.stdin:
    command, _, argument = line.rstrip("\n").partition(" ")
    if command == "SETDESC":
        description = unescaped(argument)
        say("OK")
    elif command == "GETPIN":
        with open(prompts, "a") as file:
            file.write(description.replace("\n", " ") + "\n")
        answer = next_answer()
        if answer is None:
            say("ERR 83886179 Operation cancelled <Pinentry>")
        else:
            if answer:
                say("D " + escaped(answer))
            say("OK")
    elif command == "BYE":
        say("OK closing connection")
        break
    else:
        say("OK")
