"""Proves ``services.TokenService``: issuing a token pair creates exactly one ``AuthSession`` row
and fires ``user_logged_in``; the three ``rotate_refresh`` outcomes (rotate / reuse / dead session)
— with the reuse test replaying an actually-rotated-away token, and proving the WHOLE session dies,
not just the replayed token; ``revoke_session``/``revoke_all_sessions`` are idempotent and never use
a raw queryset update; and access/refresh/pending-2FA tokens expire independently of each other.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from django.utils import timezone
from freezegun import freeze_time

from jwt_multiauth import conf, tokens
from jwt_multiauth.factories import UserFactory
from jwt_multiauth.models import AuthSession
from jwt_multiauth.services import (
    InvalidPendingToken,
    InvalidRefreshToken,
    RefreshReuseDetected,
    RequestMeta,
    TokenService,
)
from jwt_multiauth.signals import refresh_reuse_detected, session_revoked, user_logged_in
from tests.backend.conftest import captured

pytestmark = pytest.mark.django_db


def _request_meta(**overrides: str) -> RequestMeta:
    meta: RequestMeta = {
        "ip": "203.0.113.5",
        "method": "password",
        "user_agent": "pytest-ua",
        "device_label": "pytest-device",
    }
    meta.update(overrides)  # type: ignore[typeddict-item]
    return meta


# --------------------------------------------------------------------- issue_token_pair


def test_issue_token_pair_creates_exactly_one_session_and_fires_user_logged_in() -> None:
    user = UserFactory()

    with captured(user_logged_in) as received:
        pair = TokenService.issue_token_pair(user, request_meta=_request_meta())

    assert AuthSession.objects.filter(user=user).count() == 1
    session = AuthSession.objects.get(user=user)
    assert str(session.id) == pair.session_id
    assert session.ip_address == "203.0.113.5"
    assert session.user_agent == "pytest-ua"
    assert session.device_label == "pytest-device"
    assert session.remember_me is False

    refresh_claims = tokens.decode(pair.refresh, expected_typ=tokens.TYP_REFRESH)
    assert refresh_claims["jti"] == session.current_jti

    assert received == [
        {
            "sender": AuthSession,
            "user_id": user.pk,
            "session_id": pair.session_id,
            "method": "password",
        }
    ]


@pytest.mark.parametrize(
    ("remember_me", "setting_key"),
    [(False, "REFRESH_TTL_SECONDS"), (True, "REMEMBER_ME_TTL_SECONDS")],
)
def test_issue_token_pair_expiry_matches_remember_me(remember_me: bool, setting_key: str) -> None:
    user = UserFactory()
    with freeze_time("2026-01-01 00:00:00"):
        pair = TokenService.issue_token_pair(
            user, request_meta=_request_meta(), remember_me=remember_me
        )
        session = AuthSession.objects.get(pk=pair.session_id)
        expected_ttl = conf.get_setting("TOKENS")[setting_key]
        assert session.expires_at == session.created_at + timedelta(seconds=expected_ttl)
        assert session.remember_me is remember_me


def test_issue_token_pair_requires_ip_and_method() -> None:
    user = UserFactory()
    with pytest.raises(ValueError):
        TokenService.issue_token_pair(user, request_meta={"method": "password"})  # type: ignore[typeddict-item]
    with pytest.raises(ValueError):
        TokenService.issue_token_pair(user, request_meta={"ip": "203.0.113.5"})  # type: ignore[typeddict-item]


# ----------------------------------------------------------------------- rotate_refresh


def test_rotate_refresh_rotates_jti_and_keeps_session_id() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_request_meta())
    original_jti = AuthSession.objects.get(pk=pair.session_id).current_jti

    rotated = TokenService.rotate_refresh(pair.refresh, request_meta=_request_meta())

    session = AuthSession.objects.get(pk=pair.session_id)
    assert rotated.session_id == pair.session_id
    assert session.rotation_count == 1
    assert session.current_jti != original_jti
    rotated_claims = tokens.decode(rotated.refresh, expected_typ=tokens.TYP_REFRESH)
    assert rotated_claims["jti"] == session.current_jti


def test_rotate_refresh_reuse_revokes_the_whole_session() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_request_meta())
    # A real rotation must happen first — the reuse test replays the now-stale ORIGINAL token,
    # never a fabricated jti.
    rotated = TokenService.rotate_refresh(pair.refresh, request_meta=_request_meta())

    with (
        captured(refresh_reuse_detected) as received,
        pytest.raises(RefreshReuseDetected),
    ):
        TokenService.rotate_refresh(pair.refresh, request_meta=_request_meta(ip="198.51.100.9"))

    session = AuthSession.objects.get(pk=pair.session_id)
    assert session.revoked_at is not None
    assert session.revoked_reason == "reuse_detected"
    assert received == [
        {
            "sender": AuthSession,
            "user_id": user.pk,
            "session_id": pair.session_id,
            "ip": "198.51.100.9",
        }
    ]

    # The WHOLE session died — the freshly-rotated, legitimate token from the real rotation
    # above also fails now, proving this isn't just the replayed token being rejected.
    with pytest.raises(InvalidRefreshToken):
        TokenService.rotate_refresh(rotated.refresh, request_meta=_request_meta())


def test_rotate_refresh_rejects_an_already_revoked_session() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_request_meta())
    TokenService.revoke_session(pair.session_id, reason="user_logout")

    with captured(refresh_reuse_detected) as received, pytest.raises(InvalidRefreshToken):
        TokenService.rotate_refresh(pair.refresh, request_meta=_request_meta())
    assert received == []


def test_rotate_refresh_rejects_a_session_whose_own_expires_at_has_passed() -> None:
    """Distinct from a JWT-level expiry: the refresh JWT's own exp is still valid (it was clamped
    to the session's expiry at issue time), but the session ROW's expires_at has since moved into
    the past on its own — TokenService must reject based on the DB row, never trusting the JWT's
    self-reported exp alone.
    """
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_request_meta())
    session = AuthSession.objects.get(pk=pair.session_id)
    session.expires_at = timezone.now() - timedelta(seconds=1)
    session.save(update_fields=["expires_at"])

    with captured(refresh_reuse_detected) as received, pytest.raises(InvalidRefreshToken):
        TokenService.rotate_refresh(pair.refresh, request_meta=_request_meta())
    assert received == []


def test_rotate_refresh_rejects_a_malformed_token() -> None:
    with pytest.raises(InvalidRefreshToken):
        TokenService.rotate_refresh("not-a-jwt-at-all", request_meta=_request_meta())


def test_rotate_refresh_rejects_a_refresh_token_missing_its_sid_claim() -> None:
    # A signature-valid refresh token that never carries "sid" at all — tokens.decode()'s own
    # required-claims list doesn't cover this TokenService-specific claim, so TokenService must
    # guard it itself rather than let a bare KeyError leak.
    token = tokens.issue({"sub": "1"}, typ=tokens.TYP_REFRESH, ttl_seconds=60)
    with pytest.raises(InvalidRefreshToken):
        TokenService.rotate_refresh(token, request_meta=_request_meta())


def test_rotate_refresh_rejects_a_sid_that_does_not_resolve_to_any_session() -> None:
    token = tokens.issue(
        {"sub": "1", "sid": "00000000-0000-0000-0000-000000000000", "jti": "whatever"},
        typ=tokens.TYP_REFRESH,
        ttl_seconds=60,
    )
    with pytest.raises(InvalidRefreshToken):
        TokenService.rotate_refresh(token, request_meta=_request_meta())


def test_refresh_token_expires_after_its_own_ttl() -> None:
    refresh_ttl = conf.get_setting("TOKENS")["REFRESH_TTL_SECONDS"]
    user = UserFactory()
    with freeze_time("2026-01-01 00:00:00"):
        pair = TokenService.issue_token_pair(user, request_meta=_request_meta())

    with freeze_time(datetime(2026, 1, 1) + timedelta(seconds=refresh_ttl + 1)):
        with pytest.raises(InvalidRefreshToken):
            TokenService.rotate_refresh(pair.refresh, request_meta=_request_meta())


# --------------------------------------------------------------- revoke_session / revoke_all


def test_revoke_session_is_idempotent_and_fires_session_revoked_once() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_request_meta())

    with captured(session_revoked) as received:
        TokenService.revoke_session(pair.session_id, reason="user_logout")
        TokenService.revoke_session(pair.session_id, reason="user_logout")  # no-op, no 2nd signal

    assert received == [
        {
            "sender": AuthSession,
            "session_id": pair.session_id,
            "user_id": user.pk,
            "reason": "user_logout",
        }
    ]
    assert AuthSession.objects.get(pk=pair.session_id).revoked_reason == "user_logout"


def test_revoke_session_rejects_an_unknown_reason() -> None:
    with pytest.raises(ValueError):
        TokenService.revoke_session(
            "00000000-0000-0000-0000-000000000000", reason="not_a_real_reason"
        )


def test_revoke_session_on_a_missing_row_is_a_silent_no_op() -> None:
    with captured(session_revoked) as received:
        TokenService.revoke_session("00000000-0000-0000-0000-000000000000", reason="user_logout")
    assert received == []


def test_revoke_all_sessions_revokes_every_live_row_except_the_excepted_one() -> None:
    user = UserFactory()
    pair_1 = TokenService.issue_token_pair(user, request_meta=_request_meta())
    pair_2 = TokenService.issue_token_pair(user, request_meta=_request_meta())
    pair_3 = TokenService.issue_token_pair(user, request_meta=_request_meta())

    with captured(session_revoked) as received:
        count = TokenService.revoke_all_sessions(
            user, except_session_id=pair_2.session_id, reason="password_changed"
        )

    assert count == 2
    assert {row["session_id"] for row in received} == {pair_1.session_id, pair_3.session_id}
    assert all(row["reason"] == "password_changed" for row in received)

    assert AuthSession.objects.get(pk=pair_2.session_id).revoked_at is None
    for revoked_pair in (pair_1, pair_3):
        with pytest.raises(InvalidRefreshToken):
            TokenService.rotate_refresh(revoked_pair.refresh, request_meta=_request_meta())
    TokenService.rotate_refresh(pair_2.refresh, request_meta=_request_meta())  # still usable


# ---------------------------------------------------- verify_access_token / pending-2FA tokens


def test_verify_access_token_accepts_a_real_access_token() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_request_meta())
    claims = TokenService.verify_access_token(pair.access)
    assert claims["sub"] == str(user.pk)


def test_verify_access_token_rejects_a_refresh_token() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_request_meta())
    with pytest.raises(tokens.TokenTypeMismatch):
        TokenService.verify_access_token(pair.refresh)


def test_access_token_expires_independently_of_refresh() -> None:
    access_ttl = conf.get_setting("TOKENS")["ACCESS_TTL_SECONDS"]
    user = UserFactory()
    with freeze_time("2026-01-01 00:00:00"):
        pair = TokenService.issue_token_pair(user, request_meta=_request_meta())

    with freeze_time(datetime(2026, 1, 1) + timedelta(seconds=access_ttl + 1)):
        with pytest.raises(tokens.TokenExpired):
            TokenService.verify_access_token(pair.access)
        # the refresh token's own, much longer TTL is untouched by the access token's expiry.
        TokenService.rotate_refresh(pair.refresh, request_meta=_request_meta())


def test_pending_2fa_token_carries_primary_method() -> None:
    user = UserFactory()
    token = TokenService.issue_pending_2fa_token(
        user, primary_method="totp", request_meta=_request_meta()
    )
    claims = TokenService.verify_pending_2fa_token(token)
    assert claims["primary_method"] == "totp"
    assert claims["sub"] == str(user.pk)


def test_verify_pending_2fa_token_rejects_an_access_token() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_request_meta())
    with pytest.raises(InvalidPendingToken):
        TokenService.verify_pending_2fa_token(pair.access)


def test_pending_2fa_token_expires_independently() -> None:
    pending_ttl = conf.get_setting("TWO_FACTOR")["PENDING_TOKEN_TTL_SECONDS"]
    user = UserFactory()
    with freeze_time("2026-01-01 00:00:00"):
        token = TokenService.issue_pending_2fa_token(
            user, primary_method="totp", request_meta=_request_meta()
        )

    with freeze_time(datetime(2026, 1, 1) + timedelta(seconds=pending_ttl + 1)):
        with pytest.raises(InvalidPendingToken):
            TokenService.verify_pending_2fa_token(token)
