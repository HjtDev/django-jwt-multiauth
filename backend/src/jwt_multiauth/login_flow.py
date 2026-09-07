"""The single shared login-response helper, used by BOTH ``views_password.LoginView`` and
``views_otp.OtpVerifyView`` (``docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md`` Phase 6: "a single
helper, not two copies"). Lives in its own module rather than inside ``views_password.py``
because ``views_otp.py`` importing from ``views_password.py`` would be a backwards dependency,
and because Phase 7 adds a ``TrustedDevice`` cookie check here ("wire this in this phase, not by
reopening Phase 6's file structure from scratch").

Not named anywhere in ``docs/CONTRACT.md`` — a deviation recorded in its §11 register.
"""

from __future__ import annotations

from typing import Any

from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response

from jwt_multiauth import conf
from jwt_multiauth.services import RequestMeta, TokenService, TwoFactorService


def login_response(
    user: Any,
    *,
    request_meta: RequestMeta,
    remember_me: bool,
    created: bool,
    used_primary_channel: str,
    primary_method: str,
) -> Response:
    """Builds the shared login-response body (``docs/CONTRACT.md`` §5's ``/login/``/
    ``/otp/verify/`` rows) for an already-authenticated ``user``.

    Args:
        request_meta: passed straight through to ``TokenService``.
        remember_me: extends the issued refresh token's TTL — ignored entirely when tokens
            aren't issued (the pending_2fa branch has no refresh token yet).
        created: ``True`` only when THIS request's own OTP verify just auto-provisioned
            ``user`` (``OtpVerifyResult.created``) — ``False`` unconditionally from
            ``views_password.LoginView``, since password never auto-provisions
            (``docs/CONTRACT.md`` §11 item 19). ``True`` short-circuits straight to issuing real
            tokens, skipping the 2FA check entirely — the §10 2FA-bootstrap carve-out: a user
            provisioned in this same request has no enrolled factor to be unavailable FOR.
        used_primary_channel: ``"password"``, ``"email"``, or ``"phone"`` — what the
            different-channel rule compares a candidate second factor's channel against.
        primary_method: ``"password"``, ``"email_otp"``, or ``"phone_otp"`` — passed to
            ``TokenService.issue_pending_2fa_token`` as ``primary_method``.

    Raises:
        AuthenticationFailed: ``details.code="two_factor_unavailable"`` — 2FA is required by
            ``TWO_FACTOR["POLICY"]`` and the intersection of enrolled methods, the allowlist, and
            the different-channel rule came up empty. This app never degrades to single-factor
            in this case (this repo's ``CLAUDE.md`` rule 3).
    """
    if not created:
        policy = conf.get_setting("TWO_FACTOR")["POLICY"]
        if policy != "off":
            eligible = TwoFactorService.eligible_methods(
                user, used_primary_channel=used_primary_channel
            )
            if eligible:
                pending_token = TokenService.issue_pending_2fa_token(
                    user, primary_method=primary_method, request_meta=request_meta
                )
                return Response({"pending_token": pending_token, "eligible_methods": eligible})

            two_factor_required = policy == "required" or (
                policy == "staff_only" and getattr(user, "is_staff", False)
            )
            if two_factor_required:
                raise AuthenticationFailed({"code": "two_factor_unavailable"})

    return _tokens_response(
        user, request_meta=request_meta, remember_me=remember_me, created=created
    )


def _tokens_response(
    user: Any, *, request_meta: RequestMeta, remember_me: bool, created: bool
) -> Response:
    pair = TokenService.issue_token_pair(user, request_meta=request_meta, remember_me=remember_me)
    body: dict[str, Any] = {
        "access": pair.access,
        "session_id": pair.session_id,
        "created": created,
    }

    cookie_conf = conf.get_setting("REFRESH_COOKIE")
    if cookie_conf["TRANSPORT"] == "body":
        body["refresh"] = pair.refresh
        return Response(body)

    tokens_conf = conf.get_setting("TOKENS")
    max_age = (
        tokens_conf["REMEMBER_ME_TTL_SECONDS"]
        if remember_me
        else tokens_conf["REFRESH_TTL_SECONDS"]
    )
    response = Response(body)
    response.set_cookie(
        cookie_conf["NAME"],
        pair.refresh,
        max_age=max_age,
        httponly=True,
        secure=cookie_conf["SECURE"],
        samesite=cookie_conf["SAMESITE"],
        path="/",
    )
    return response
