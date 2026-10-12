"""Gate B3: loopback-only TLS 1.3 First Knock laboratory.

Uses mutually verified ephemeral Ed25519 test certificates, explicitly pinned
public device identities from Gate B2, and B2 signed challenge/response.

No LAN binding, background listener, remote job execution, cloud connection,
network discovery, persistent private keys, model loading, or resource grants.
A transient unencrypted private-key PEM is written with restrictive permissions
only to initialize Python ssl.SSLContext; it is removed immediately thereafter.
NOT suitable as a production transport/key-management service.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import queue
import socket
import ssl
import struct
import tempfile
import threading
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .identity import (
    DeviceIdentity, IdentityDenied, PinnedPeers, create_challenge,
    public_fingerprint, respond_to_challenge, verify_response,
)

_MAX_FRAME = 4096
_HOST = "127.0.0.1"


class FirstKnockDenied(ValueError):
    """Rejected loopback laboratory connection."""


def _recv_exact(sock: ssl.SSLSocket | socket.socket, size: int) -> bytes:
    if size < 1 or size > _MAX_FRAME:
        raise FirstKnockDenied("invalid frame size")
    parts = bytearray()
    while len(parts) < size:
        block = sock.recv(size - len(parts))
        if not block:
            raise FirstKnockDenied("connection closed during frame")
        parts.extend(block)
    return bytes(parts)


def _read_frame(sock: ssl.SSLSocket | socket.socket) -> dict[str, Any]:
    header = _recv_exact(sock, 4)
    size = struct.unpack("!I", header)[0]
    if not 1 <= size <= _MAX_FRAME:
        raise FirstKnockDenied("frame exceeds fixed limit or is empty")
    try:
        frame = json.loads(_recv_exact(sock, size).decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise FirstKnockDenied("malformed frame") from exc
    if type(frame) is not dict:
        raise FirstKnockDenied("frame must be an object")
    return frame


def _write_frame(sock: ssl.SSLSocket | socket.socket, value: dict[str, Any]) -> None:
    if type(value) is not dict:
        raise FirstKnockDenied("invalid outbound frame")
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if not 1 <= len(data) <= _MAX_FRAME:
        raise FirstKnockDenied("outbound frame exceeds fixed limit")
    sock.sendall(struct.pack("!I", len(data)) + data)


def _cert_pem(identity: DeviceIdentity) -> tuple[bytes, bytes]:
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity.device_id)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(identity.public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(minutes=20))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(identity.private_key, None)
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    private_bytes = identity.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_bytes, private_bytes


def _put_secret(folder: str, name: str, data: bytes) -> str:
    filename = os.path.join(folder, name)
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
    except BaseException:
        try:
            os.unlink(filename)
        except OSError:
            pass
        raise
    return filename


def _contexts(alice: DeviceIdentity, bob: DeviceIdentity) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """Mutual TLS contexts; transient key files are deleted before returning."""
    with tempfile.TemporaryDirectory(prefix="porchtalk-ephemeral-tls-") as directory:
        ac, ak = _cert_pem(alice)
        bc, bk = _cert_pem(bob)
        ac_file = _put_secret(directory, "alice.cert", ac)
        ak_file = _put_secret(directory, "alice.key", ak)
        bc_file = _put_secret(directory, "bob.cert", bc)
        bk_file = _put_secret(directory, "bob.key", bk)

        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.minimum_version = ssl.TLSVersion.TLSv1_3
        server.maximum_version = ssl.TLSVersion.TLSv1_3
        server.verify_mode = ssl.CERT_REQUIRED
        server.load_cert_chain(bc_file, bk_file)
        server.load_verify_locations(cadata=ac.decode("ascii"))

        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.minimum_version = ssl.TLSVersion.TLSv1_3
        client.maximum_version = ssl.TLSVersion.TLSv1_3
        client.check_hostname = False  # exact certificate trust + explicit key pin, not DNS
        client.verify_mode = ssl.CERT_REQUIRED
        client.load_cert_chain(ac_file, ak_file)
        client.load_verify_locations(cadata=bc.decode("ascii"))
        return client, server


def _verify_pinned_tls(sock: ssl.SSLSocket, peers: PinnedPeers, expected_id: str) -> str:
    if sock.version() != "TLSv1.3":
        raise FirstKnockDenied("TLS 1.3 required")
    der = sock.getpeercert(binary_form=True)
    if not der:
        raise FirstKnockDenied("client/server certificate missing")
    try:
        cert = x509.load_der_x509_certificate(der)
        actual = cert.public_key()
        expected = peers.approved_key(expected_id)
        if public_fingerprint(actual) != public_fingerprint(expected):
            raise FirstKnockDenied("pinned device key mismatch")
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(names) != 1 or names[0].value != expected_id:
            raise FirstKnockDenied("certificate identity mismatch")
        return public_fingerprint(expected)
    except (ValueError, TypeError, IdentityDenied) as exc:
        raise FirstKnockDenied("unapproved peer identity") from exc


def run_loopback_first_knock(
    *, alice: DeviceIdentity, bob: DeviceIdentity,
    alice_trust_path: str | Path, bob_trust_path: str | Path,
    timeout_seconds: float = 4.0,
) -> dict[str, Any]:
    """One authorized *simulation* over real loopback TLS; no commands execute.

    Trust databases must already contain manually enrolled peer public keys.
    This call never modifies trust enrollment and never starts a persistent server.
    """
    if (not isinstance(alice, DeviceIdentity) or not isinstance(bob, DeviceIdentity)
            or alice.device_id == bob.device_id):
        raise FirstKnockDenied("two distinct device identities required")
    if type(timeout_seconds) not in (int, float) or not 0.2 <= timeout_seconds <= 10:
        raise FirstKnockDenied("invalid timeout")

    # Both peers must already be pinned, and revocation must not have been applied.
    with_db_a = PinnedPeers(alice_trust_path)
    with_db_b = PinnedPeers(bob_trust_path)
    try:
        if public_fingerprint(with_db_a.approved_key(bob.device_id)) != bob.fingerprint:
            raise FirstKnockDenied("Alice has not pinned Bob's current key")
        if public_fingerprint(with_db_b.approved_key(alice.device_id)) != alice.fingerprint:
            raise FirstKnockDenied("Bob has not pinned Alice's current key")
    except IdentityDenied as exc:
        raise FirstKnockDenied("preflight trust rejected") from exc
    finally:
        with_db_a.close()
        with_db_b.close()

    client_ctx, server_ctx = _contexts(alice, bob)
    result_queue: queue.Queue[BaseException | None] = queue.Queue(maxsize=1)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(timeout_seconds)
    listener.bind((_HOST, 0))  # literal loopback; cannot expose a LAN interface
    listener.listen(1)
    port = listener.getsockname()[1]

    def _responder() -> None:
        peers = None
        try:
            peers = PinnedPeers(bob_trust_path)
            conn, address = listener.accept()
            with conn:
                conn.settimeout(timeout_seconds)
                if address[0] != _HOST:
                    raise FirstKnockDenied("non-loopback peer refused")
                with server_ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(timeout_seconds)
                    _verify_pinned_tls(tls, peers, alice.device_id)
                    challenge = _read_frame(tls)
                    reply = respond_to_challenge(bob, challenge, peers)
                    _write_frame(tls, reply)
            result_queue.put(None)
        except BaseException as exc:
            result_queue.put(exc)
        finally:
            if peers is not None:
                peers.close()

    worker = threading.Thread(target=_responder, name="porchtalk-b3-once", daemon=True)
    worker.start()
    result: dict[str, Any] | None = None
    client_error: BaseException | None = None
    try:
        with socket.create_connection((_HOST, port), timeout=timeout_seconds) as plain:
            plain.settimeout(timeout_seconds)
            with client_ctx.wrap_socket(plain, server_hostname=None) as tls:
                tls.settimeout(timeout_seconds)
                peers = PinnedPeers(alice_trust_path)
                try:
                    fingerprint = _verify_pinned_tls(tls, peers, bob.device_id)
                    challenge = create_challenge(alice, bob.device_id)
                    _write_frame(tls, challenge)
                    reply = _read_frame(tls)
                    verified = verify_response(alice, challenge, reply, peers)
                    result = {
                        "status": "LOOPBACK_FIRST_KNOCK_PASS",
                        "tls_version": tls.version(),
                        "peer_id": verified["peer_id"],
                        "peer_fingerprint": fingerprint,
                        "verified_challenge": True,
                        "route_authorized": False,
                        "compute_authorized": False,
                        "network_scope": "127.0.0.1_ONLY",
                        "warnings": ["EPHEMERAL_PRIVATE_KEY_TEMPFILES", "NOT_LAN_OR_PRODUCTION", "NO_RESOURCE_GRANT"],
                    }
                finally:
                    peers.close()
    except BaseException as exc:
        client_error = exc
    finally:
        listener.close()
        worker.join(timeout_seconds + 1)
    if worker.is_alive():
        raise FirstKnockDenied("responder did not stop")
    server_error = result_queue.get_nowait() if not result_queue.empty() else FirstKnockDenied("missing responder result")
    if client_error is not None or server_error is not None or result is None:
        raise FirstKnockDenied("loopback handshake denied or incomplete") from (client_error or server_error)
    return result
