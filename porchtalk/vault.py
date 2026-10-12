"""Gate B4b: passphrase-encrypted local Ed25519 test identity vault.

No network operations. Password-based encryption protects keys at rest against
casual file disclosure, not against malware, privileged users, weak passphrases,
compromised endpoints, stolen unlocked memory, or offline password guessing.
NOT a hardware-backed keystore or production node-identity service.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .identity import DeviceIdentity, IdentityDenied

_FORMAT = "PORCHTALK_ENCRYPTED_IDENTITY_V1"
_N, _R, _P = 32768, 8, 1
_MAX_VAULT_BYTES = 8192
_MIN_PASSPHRASE_LEN = 14
_MAX_PASSPHRASE_BYTES = 1024


def _passphrase(raw: Any) -> bytes:
    if type(raw) is not str:
        raise IdentityDenied("passphrase must be provided interactively")
    encoded = raw.encode("utf-8")
    if len(raw) < _MIN_PASSPHRASE_LEN or not 14 <= len(encoded) <= _MAX_PASSPHRASE_BYTES:
        raise IdentityDenied("passphrase must have at least 14 characters and at most 1024 UTF-8 bytes")
    return encoded


def _decode(raw: Any, expected: int | None, name: str) -> bytes:
    if type(raw) is not str or len(raw) > 4096:
        raise IdentityDenied(f"invalid {name}")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise IdentityDenied(f"invalid {name}") from exc
    if expected is not None and len(decoded) != expected:
        raise IdentityDenied(f"invalid {name} length")
    return decoded


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _derive(passphrase: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=_N, r=_R, p=_P).derive(passphrase)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _path_guard(raw: str | Path, *, writing: bool) -> Path:
    path = Path(raw).absolute()
    if ".." in Path(raw).parts or not path.name or path.is_symlink():
        raise IdentityDenied("unsafe vault path")
    if not path.parent.is_dir():
        raise IdentityDenied("vault parent directory does not exist")
    # Reject symlinked ancestors, not merely symlinked final file.
    current = path.parent
    while current != current.parent:
        if current.is_symlink():
            raise IdentityDenied("symlinked vault directory denied")
        current = current.parent
    if os.name == "posix":
        if path.parent.stat().st_mode & 0o022:
            raise IdentityDenied("vault parent directory must not be group/world writable")
    if writing and (path.exists() or path.is_symlink()):
        raise IdentityDenied("vault already exists; refusing overwrite")
    return path


def create_encrypted_vault(raw_path: str | Path, identity: DeviceIdentity, *, passphrase: str) -> str:
    """Create exactly one encrypted identity file, exclusive-write; never overwrite.

    The caller should create a private parent directory and arrange backups.
    Does not rotate keys or grant peer trust.
    """
    if not isinstance(identity, DeviceIdentity):
        raise IdentityDenied("device identity required")
    phrase = _passphrase(passphrase)
    path = _path_guard(raw_path, writing=True)
    private_seed = identity.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public = identity.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    salt = os.urandom(16)
    nonce = os.urandom(12)
    metadata = {
        "format": _FORMAT,
        "device_id": identity.device_id,
        "public_key_b64": _b64(public),
        "kdf": {"name": "scrypt", "n": _N, "r": _R, "p": _P, "salt_b64": _b64(salt)},
        "cipher": {"name": "AES-256-GCM", "nonce_b64": _b64(nonce)},
    }
    ciphertext = AESGCM(_derive(phrase, salt)).encrypt(nonce, private_seed, _canonical(metadata))
    document = {"metadata": metadata, "ciphertext_b64": _b64(ciphertext)}
    data = _canonical(document) + b"\n"
    if len(data) > _MAX_VAULT_BYTES:
        raise IdentityDenied("vault exceeds maximum size")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = None
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            os.chmod(path, 0o600)
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        # Do not delete an existing file opened by another process.
        raise IdentityDenied("vault could not be created") from exc
    return identity.fingerprint


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, entry in pairs:
        if key in value:
            raise IdentityDenied("duplicate JSON key in vault")
        value[key] = entry
    return value


def _read_document(path: Path) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes, bytes]:
    if path.is_symlink() or not path.is_file():
        raise IdentityDenied("vault not a regular file")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _MAX_VAULT_BYTES:
        raise IdentityDenied("invalid vault filesystem metadata")
    if os.name == "posix" and info.st_mode & 0o077:
        raise IdentityDenied("vault permissions expose private material")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(_MAX_VAULT_BYTES + 1)
    except OSError as exc:
        raise IdentityDenied("vault cannot be read") from exc
    if len(data) > _MAX_VAULT_BYTES:
        raise IdentityDenied("oversized vault")
    try:
        document = json.loads(data.decode("ascii"), object_pairs_hook=_unique_object)
    except IdentityDenied:
        raise
    except (UnicodeError, ValueError) as exc:
        raise IdentityDenied("invalid vault JSON") from exc
    if type(document) is not dict or set(document) != {"metadata", "ciphertext_b64"}:
        raise IdentityDenied("invalid vault envelope")
    metadata = document["metadata"]
    if type(metadata) is not dict or set(metadata) != {"format", "device_id", "public_key_b64", "kdf", "cipher"}:
        raise IdentityDenied("invalid vault metadata")
    if metadata["format"] != _FORMAT:
        raise IdentityDenied("unsupported vault format")
    # Validate device ID independently of the private key.
    name = metadata["device_id"]
    if (type(name) is not str or not 1 <= len(name) <= 80 or not name.isascii()
            or any(not (c.isalnum() or c in "._-") for c in name)):
        raise IdentityDenied("invalid device ID")
    pub = _decode(metadata["public_key_b64"], 32, "public key")
    kdf = metadata["kdf"]
    cipher = metadata["cipher"]
    if (type(kdf) is not dict or set(kdf) != {"name", "n", "r", "p", "salt_b64"}
            or kdf["name"] != "scrypt" or type(kdf["n"]) is not int or type(kdf["r"]) is not int
            or type(kdf["p"]) is not int or (kdf["n"], kdf["r"], kdf["p"]) != (_N, _R, _P)):
        raise IdentityDenied("unsupported KDF parameters")
    if type(cipher) is not dict or set(cipher) != {"name", "nonce_b64"} or cipher["name"] != "AES-256-GCM":
        raise IdentityDenied("unsupported cipher")
    salt = _decode(kdf["salt_b64"], 16, "salt")
    nonce = _decode(cipher["nonce_b64"], 12, "nonce")
    encrypted = _decode(document["ciphertext_b64"], 48, "ciphertext")
    return metadata, {"public": pub}, salt, nonce, encrypted


def unlock_encrypted_vault(raw_path: str | Path, *, passphrase: str) -> DeviceIdentity:
    """Load a previously encrypted vault. Wrong passphrase/tampering fail closed."""
    phrase = _passphrase(passphrase)
    path = _path_guard(raw_path, writing=False)
    metadata, value, salt, nonce, ciphertext = _read_document(path)
    try:
        private_seed = AESGCM(_derive(phrase, salt)).decrypt(
            nonce, ciphertext, _canonical(metadata)
        )
        identity = DeviceIdentity(metadata["device_id"], Ed25519PrivateKey.from_private_bytes(private_seed))
    except (InvalidTag, ValueError) as exc:
        raise IdentityDenied("vault unlock denied: wrong passphrase or altered data") from exc
    public = identity.public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    if public != value["public"]:
        raise IdentityDenied("vault key identity mismatch")
    return identity
