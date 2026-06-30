"""Offline tests for Relay signing, anti-replay, and scope enforcement."""
from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from specter.relay import (  # noqa: E402
    KeyPair,
    RelayExecutor,
    RelayRequest,
    ReplayGuard,
)
from specter.tools.registry import ToolRegistry  # noqa: E402


def _executor(allow_client_pub, scope=("scanme.nmap.org",)):
    return RelayExecutor(
        server_key=KeyPair.generate(),
        allowed_clients={allow_client_pub},
        scope=set(scope),
        registry=ToolRegistry(offline=True),  # simulated tool output
        replay=ReplayGuard(window_seconds=60),
    )


def test_signed_request_roundtrips_and_verifies():
    client = KeyPair.generate()
    req = RelayRequest(tool="nmap", target="scanme.nmap.org").sign(client)
    again = RelayRequest.from_json(req.to_json())
    assert again.verify()
    assert again.client_pub == client.public_b64()


def test_tampered_request_fails_verification():
    client = KeyPair.generate()
    req = RelayRequest(tool="nmap", target="scanme.nmap.org").sign(client)
    req.target = "evil.test"  # tamper after signing
    assert req.verify() is False


def test_executor_runs_authorized_in_scope_request():
    client = KeyPair.generate()
    ex = _executor(client.public_b64())
    req = RelayRequest(tool="nmap", target="scanme.nmap.org").sign(client)
    resp = ex.handle(req)
    assert resp.error == "" and resp.simulated
    assert resp.verify(expected_server_pub=ex.server_key.public_b64())


def test_executor_blocks_out_of_scope_target():
    client = KeyPair.generate()
    ex = _executor(client.public_b64())
    req = RelayRequest(tool="nmap", target="evil.test").sign(client)
    resp = ex.handle(req)
    assert "out of authorized scope" in resp.error


def test_executor_rejects_unauthorized_client():
    authorized = KeyPair.generate()
    attacker = KeyPair.generate()
    ex = _executor(authorized.public_b64())
    req = RelayRequest(tool="nmap", target="scanme.nmap.org").sign(attacker)
    resp = ex.handle(req)
    assert "not authorized" in resp.error


def test_executor_rejects_nonce_replay():
    client = KeyPair.generate()
    ex = _executor(client.public_b64())
    req = RelayRequest(tool="nmap", target="scanme.nmap.org").sign(client)
    first = ex.handle(req)
    assert first.error == ""
    replayed = ex.handle(req)  # same nonce
    assert "replay" in replayed.error


def test_keypair_save_load_roundtrip(tmp_path):
    kp = KeyPair.generate()
    path = kp.save(tmp_path / "relay.key")
    loaded = KeyPair.load(path)
    assert loaded.public_b64() == kp.public_b64()
