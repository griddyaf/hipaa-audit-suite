"""Input-validation helpers used to harden the web API.

Stops two classes of bug that were present in the original Flask app:
  * SSRF via an attacker-supplied target_url pointing at internal hosts.
  * Path traversal / arbitrary file read via attacker-supplied config paths.
"""
import ipaddress
import os
import socket
from urllib.parse import urlparse


class ValidationError(ValueError):
    """Raised when user-supplied input fails a security check."""


def validate_target_url(url, allow_private=False):
    """Validate an https/http target URL and block SSRF to internal ranges.

    Returns the parsed (hostname, port). Raises ValidationError on failure.
    Set allow_private=True only for explicit local testing.
    """
    if not url or not isinstance(url, str):
        raise ValidationError("target_url must be a non-empty string")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError("target_url must use http or https")
    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("target_url has no hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if allow_private:
        return hostname, port

    # Resolve and ensure no address maps to a private/reserved/loopback range.
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValidationError(f"could not resolve host: {exc}") from exc

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ValidationError(
                f"target resolves to a non-public address ({ip}); blocked to prevent SSRF"
            )
    return hostname, port


def validate_config_path(path, allowed_root):
    """Ensure a user-supplied file path stays within allowed_root.

    Returns the resolved absolute path. Raises ValidationError on escape
    attempts or missing files.
    """
    if not path or not isinstance(path, str):
        raise ValidationError("path must be a non-empty string")

    allowed_root = os.path.realpath(allowed_root)
    candidate = os.path.realpath(os.path.join(allowed_root, path))
    if not (candidate == allowed_root or candidate.startswith(allowed_root + os.sep)):
        raise ValidationError("path escapes the allowed directory")
    if not os.path.isfile(candidate):
        raise ValidationError(f"file not found: {path}")
    return candidate
