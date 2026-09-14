import html
import ipaddress
import re


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![\w:])[0-9A-Fa-f:]+(?:%[0-9A-Za-z\_.-]+)?(?![\w:])"
)

_SSH_PUBLIC_KEY_RE = re.compile(
    r"ssh-(?:rsa|ed25519|ecdsa-[A-Za-z0-9-]+)\s+"
    r"[A-Za-z0-9+/=]+(?:\s+[^\s\"'<>]+)?",
    re.IGNORECASE,
)

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN "
    r"(?:OPENSSH PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|PRIVATE KEY)"
    r"-----.*?"
    r"-----END "
    r"(?:OPENSSH PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|PRIVATE KEY)"
    r"-----",
    re.DOTALL,
)

_ANSI_ESCAPE_RE = re.compile(
    r"""
    \x1B
    (?:
        \][^\x07]*(?:\x07|\x1B\\)
        |
        \[[0-?]*[ -/]*[@-~]
        |
        [@-Z\\-_]
    )
    """,
    re.VERBOSE,
)

_IPV4_MAPPED_IPV6_RE = re.compile(
    r"(?<![\w:])"
    r"(?:::[Ff]{4}:)"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\w:])"
)

def _mask_ip(value: str) -> str:
    try:
        # IPv6 zone IDs (for example %eth0) are not part of the
        # address itself and need to be removed before parsing.
        parse_value = value.split("%", 1)[0]
        ip = ipaddress.ip_address(parse_value)
    except ValueError:
        return value

    if ip.version == 4:
        parts = parse_value.split(".")
        return f"{parts[0]}.{parts[1]}.x.x"

    # IPv4-mapped IPv6 address, for example:
    # ::ffff:192.168.1.100
    if ip.ipv4_mapped is not None:
        mapped = ip.ipv4_mapped
        parts = str(mapped).split(".")
        return f"::ffff:{parts[0]}.{parts[1]}.x.x"

    if ip.is_unspecified or ip.is_loopback:
        return "::x"

    # IPv6: preserve first 4 hextets from canonical address.
    hextets = ip.exploded.split(":")
    prefix = ":".join(
        part.lstrip("0") or "0"
        for part in hextets[:4]
    )

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


def _mask_ssh_public_key(match: re.Match[str]) -> str:
    return "<SSH_PUBLIC_KEY>"


def _mask_private_key(match: re.Match[str]) -> str:
    return "<PRIVATE_KEY>"

def _mask_ipv4_mapped_ipv6(match: re.Match[str]) -> str:
    value = match.group(0)

    ipv4 = value.rsplit(":", 1)[-1]
    parts = ipv4.split(".")

    return f"::ffff:{parts[0]}.{parts[1]}.x.x"

def sanitize_display_value(
    value: str,
    *,
    max_length: int = 200,
) -> str:
    """Sanitize an attacker-controlled value for public display."""

    if not isinstance(value, str):
        value = str(value)

    value = _ANSI_ESCAPE_RE.sub("", value)

    value = _PRIVATE_KEY_RE.sub(_mask_private_key, value)

    value = "".join(
        char if char.isprintable() else " "
        for char in value
    )
    value = re.sub(r"\s+", " ", value).strip()

    # Protect IPv4-mapped IPv6 addresses from the separate IPv4/IPv6 passes.
    mapped_ipv6_values: list[str] = []

    def protect_mapped_ipv6(match: re.Match[str]) -> str:
        value = match.group(0)
        ipv4 = value.rsplit(":", 1)[-1]
        parts = ipv4.split(".")

        masked = f"::ffff:{parts[0]}.{parts[1]}.x.x"
        mapped_ipv6_values.append(masked)

        return f"__MAPPED_IPV6_{len(mapped_ipv6_values) - 1}__"

    value = _IPV4_MAPPED_IPV6_RE.sub(
        protect_mapped_ipv6,
        value,
    )

    value = _IPV4_RE.sub(_mask_ipv4, value)
    value = _mask_ipv6_candidates(value)

    # Restore protected mapped IPv6 values.
    for index, masked in enumerate(mapped_ipv6_values):
        value = value.replace(
            f"__MAPPED_IPV6_{index}__",
            masked,
        )

    value = _SSH_PUBLIC_KEY_RE.sub(
        _mask_ssh_public_key,
        value,
    )

    if len(value) > max_length:
        value = value[: max_length - 1] + "…"

    return value