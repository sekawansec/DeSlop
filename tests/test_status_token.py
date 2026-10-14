from datetime import UTC, datetime, timedelta

from deslop.web.status_token import (
    generate_token,
    hash_token,
    issue_token,
    token_is_valid,
)


def test_generate_token_has_enough_entropy():
    tokens = {generate_token() for _ in range(200)}
    assert len(tokens) == 200
    # 32 bytes base64url -> ~43 chars
    assert all(len(t) >= 43 for t in tokens)


def test_issue_token_returns_hash_not_plaintext():
    issued = issue_token(timedelta(days=1))
    assert issued.token_hash == hash_token(issued.token)
    assert issued.token != issued.token_hash
    assert len(issued.token_hash) == 64


def test_status_url_format():
    issued = issue_token()
    assert issued.status_url("https://vdp.example.test") == f"https://vdp.example.test/status/{issued.token}"


def test_token_valid_happy_path():
    issued = issue_token(timedelta(days=1))
    assert token_is_valid(
        token_hash=issued.token_hash,
        stored_hash=issued.token_hash,
        expires_at=issued.expires_at,
        revoked=False,
    )


def test_token_invalid_when_revoked():
    issued = issue_token()
    assert not token_is_valid(
        token_hash=issued.token_hash, stored_hash=issued.token_hash,
        expires_at=None, revoked=True,
    )


def test_token_invalid_when_expired():
    expired = datetime.now(UTC) - timedelta(seconds=1)
    token = generate_token()
    assert not token_is_valid(
        token_hash=hash_token(token), stored_hash=hash_token(token),
        expires_at=expired, revoked=False,
    )


def test_token_invalid_on_mismatch():
    a = issue_token()
    b = issue_token()
    assert not token_is_valid(
        token_hash=a.token_hash, stored_hash=b.token_hash, expires_at=None, revoked=False
    )


def test_token_invalid_when_missing():
    assert not token_is_valid(token_hash=None, stored_hash="x", expires_at=None, revoked=False)
    assert not token_is_valid(token_hash="x", stored_hash=None, expires_at=None, revoked=False)
