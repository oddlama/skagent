"""Runs a command on a terminal of its own and types an answer whenever it
asks for a PIN, for age, which reads secrets from the terminal alone.

usage: pty-answers ANSWER... -- COMMAND...

Each prompt (it ends in "then touch it") gets the next answer. What the
command wrote to the terminal is printed; the exit status is the command's.
"""

import sys

import pexpect

split = sys.argv.index("--")
answers = sys.argv[1:split]
command = sys.argv[split + 1:]

child = pexpect.spawn(command[0], command[1:], encoding="utf-8", timeout=60)
# No echo from the start: an answer typed before the command switched it off
# would be on the screen.
child.setecho(False)
child.logfile_read = sys.stdout
for answer in answers:
    child.expect("then touch it")
    child.sendline(answer)
child.expect(pexpect.EOF)
child.close()
sys.exit(child.exitstatus if child.exitstatus is not None else 1)
