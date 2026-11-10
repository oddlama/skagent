"""Write an unencrypted OpenSSH sk-ssh-ed25519 key file without a device.

The file is what `ssh-keygen -K` writes: public key, application, flags and
key handle, no secret. The public key is made up, so nothing can sign with
it; it is only for loading into an agent with `ssh-add`.

usage: make-sk-stub PATH SEED COMMENT
"""

import base64
import os
import struct
import sys
import textwrap

KEY_TYPE = b"sk-ssh-ed25519@openssh.com"
APPLICATION = b"ssh:example"
# user presence required | user verification required
FLAGS = 0x05


def string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def stub(seed: int, comment: bytes) -> bytes:
    public_key = bytes([seed]) * 32
    key_handle = bytes([seed ^ 0xFF]) * 64
    public_blob = string(KEY_TYPE) + string(public_key) + string(APPLICATION)
    check = struct.pack(">I", seed)
    private = (
        check
        + check
        + string(KEY_TYPE)
        + string(public_key)
        + string(APPLICATION)
        + bytes([FLAGS])
        + string(key_handle)
        + string(b"")  # reserved
        + string(comment)
    )
    # Unencrypted keys are padded to a multiple of 8 with 1, 2, 3, ...
    padding = (8 - len(private) % 8) % 8
    private += bytes(range(1, padding + 1))
    body = (
        b"openssh-key-v1\0"
        + string(b"none")  # cipher
        + string(b"none")  # kdf
        + string(b"")  # kdf options
        + struct.pack(">I", 1)  # number of keys
        + string(public_blob)
        + string(private)
    )
    encoded = base64.b64encode(body).decode("ascii")
    lines = textwrap.wrap(encoded, 70)
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(lines)
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    ).encode("ascii")


def main() -> None:
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    path, seed, comment = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    if not 0 < seed < 256:
        sys.exit("SEED must be in 1..255")
    # ssh-add refuses key files other users can read.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(stub(seed, comment.encode("utf-8")))


if __name__ == "__main__":
    main()
