import re


def normalize_command(command):
    command = command.strip()

    # ---------------------------
    # passwd
    # ---------------------------
    # Matches things like:
    # echo "123\nnewpass\nnewpass"|passwd|bash
    # echo -e "123\nnewpass\nnewpass"|passwd|bash
    # echo "anything"|passwd
    #
    # Keep the passwd/bash pipeline structure while
    # removing the actual input.

    command = re.sub(
        r"""echo(?:\s+-e)?\s+(['"]).*?\1\s*\|\s*passwd(\s*\|\s*bash)?""",
        lambda m: 'echo "<INPUT>" | passwd' + (
            " | bash" if m.group(2) else ""
        ),
        command,
        flags=re.IGNORECASE,
    )

    # ---------------------------
    # chpasswd
    # ---------------------------
    # Matches things like:
    # echo "root:password"|chpasswd|bash

    command = re.sub(
        r"""echo\s+(['"]).*?\1\s*\|\s*chpasswd(\s*\|\s*bash)?""",
        lambda m: 'echo "<INPUT>" | chpasswd' + (
            " | bash" if m.group(2) else ""
        ),
        command,
        flags=re.IGNORECASE,
    )

    # Normalize whitespace
    command = re.sub(r"\s+", " ", command)

    return command