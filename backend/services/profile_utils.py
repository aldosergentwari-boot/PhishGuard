import base64
import binascii
import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,24}$")
MAX_PROFILE_IMAGE_BYTES = 2 * 1024 * 1024


def validate_profile_image(value):
    """Accept a small, base64-encoded raster image; return a normalized data URI."""
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > (MAX_PROFILE_IMAGE_BYTES * 4 // 3 + 256):
        raise ValueError("Profile image must be 2 MB or smaller.")
    match = re.fullmatch(r"data:(image/(?:jpeg|png|webp));base64,([A-Za-z0-9+/]+={0,2})", value)
    if not match:
        raise ValueError("Choose a JPG, PNG or WEBP image.")
    mime, encoded = match.groups()
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("The selected profile image is invalid.") from exc
    if not raw or len(raw) > MAX_PROFILE_IMAGE_BYTES:
        raise ValueError("Profile image must be 2 MB or smaller.")
    valid = (
        (mime == "image/jpeg" and raw.startswith(b"\xff\xd8\xff"))
        or (mime == "image/png" and raw.startswith(b"\x89PNG\r\n\x1a\n"))
        or (mime == "image/webp" and len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP")
    )
    if not valid:
        raise ValueError("The image file does not match its file type.")
    return value
