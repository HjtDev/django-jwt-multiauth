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

from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request
from rest_framework.response import Response

from jwt_multiauth import conf, keys, otp
from jwt_multiauth.models import TrustedDevice
from jwt_multiauth.services import RequestMeta, TokenService, TwoFactorService


def login_response(
    user: Any,
    *,
    request: Request,
    request_meta: RequestMeta,
    remember_me: bool,
    created: bool,
    used_primary_channel: str,
    primary_method: str,
) -> Response:
    """Builds the shared login-response body (``docs/CONTRACT.md`` §5's ``/login/``/
    ``/otp/verify/`` rows) for an already-authenticated ``user``.

    Args:
        request: the raw DRF request — read ONLY for its trusted-device cookie (§10's one
            documented, revocable bypass of "no token before 2FA"). Added in Phase 7; both
            existing call sites (``views_password.LoginView``, ``views_otp.OtpVerifyView``)
            already have a ``request`` in hand, so this is a pure addition, not a signature
            change either call site struggled to satisfy.
        request_meta: passed straight through to ``TokenService``.
        remember_me: extends the issued refresh token's TTL — ignored entirely when tokens
            aren't issued (the pending_2fa branch has no refresh token yet).
        created: ``True`` only when THIS request's own OTP verify just auto-provisioned
            ``user`` (``OtpVerifyResult.created``) — ``False`` unconditionally from
            ``views_password.LoginView``, since password never auto-provisions
            (``docs/CONTRACT.md`` §11 item 19). ``True`` short-circuits straight to issuing real
            tokens, skipping the 2FA check (and the trusted-device check) entirely — the §10
            2FA-bootstrap carve-out: a user provisioned in this same request has no enrolled
            factor to be unavailable FOR, and no trusted-device cookie of their own yet either.
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
        two_factor_conf = conf.get_setting("TWO_FACTOR")
        trusted_device_conf = two_factor_conf["TRUSTED_DEVICE"]
        if trusted_device_conf["ENABLED"] and _trusted_device_skips_2fa(
            user, request, cookie_name=trusted_device_conf["COOKIE_NAME"]
        ):
            return tokens_response(
                user, request_meta=request_meta, remember_me=remember_me, created=created
            )

        policy = two_factor_conf["POLICY"]
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

    return tokens_response(
        user, request_meta=request_meta, remember_me=remember_me, created=created
    )


def _trusted_device_skips_2fa(user: Any, request: Request, *, cookie_name: str) -> bool:
    """Checked BEFORE 2FA is even offered (``docs/CONTRACT.md`` §10's one documented, revocable
    bypass of "no token before 2FA"): does ``request`` carry ``cookie_name`` matching one of
    THIS user's own live (unrevoked, unexpired) ``TrustedDevice`` rows? A missing, foreign,
    stale, or revoked cookie is simply ignored, never an error — this app never lets an invalid
    trusted-device cookie downgrade or block an otherwise-normal login. Bumps ``last_used_at`` on
    a match (``TrustedDevice.last_used_at`` is ``auto_now_add=True`` — only an explicit save on
    use actually advances it, per the model's own docstring).
    """
    raw_token = request.COOKIES.get(cookie_name)
    if not raw_token:
        return False

    token_hash = otp.hash_secret(raw_token, pepper=keys.get_otp_pepper())
    try:
        device = TrustedDevice.objects.get(
            user=user, token_hash=token_hash, revoked_at__isnull=True
        )
    except TrustedDevice.DoesNotExist:
        return False

    if device.expires_at <= timezone.now():
        return False

    device.last_used_at = timezone.now()
    device.save(update_fields=["last_used_at"])
    return True


def tokens_response(
    user: Any, *, request_meta: RequestMeta, remember_me: bool, created: bool
) -> Response:
    """Issues a BRAND-NEW token pair for ``user`` and builds the HTTP response for it. The
    ordinary login-success tail — every call site here has a ``user`` but no pair yet.
    """
    pair = TokenService.issue_token_pair(user, request_meta=request_meta, remember_me=remember_me)
    return pair_response(pair, remember_me=remember_me, created=created)


def _set_refresh_cookie(response: Response, refresh: str, *, remember_me: bool) -> None:
    """Sets the refresh cookie on ``response`` with this app's fixed attributes (``httponly=True``,
    ``path="/"``) plus the host's configured ``SECURE``/``SAMESITE`` — factored out (Phase 8) so
    :func:`pair_response` (a fresh login/2FA-verify pair) and :func:`refresh_response`
    (``POST /token/refresh/``) can never drift on cookie attributes between the two response paths.
    """
    cookie_conf = conf.get_setting("REFRESH_COOKIE")
    tokens_conf = conf.get_setting("TOKENS")
    max_age = (
        tokens_conf["REMEMBER_ME_TTL_SECONDS"]
        if remember_me
        else tokens_conf["REFRESH_TTL_SECONDS"]
    )
    response.set_cookie(
        cookie_conf["NAME"],
        refresh,
        max_age=max_age,
        httponly=True,
        secure=cookie_conf["SECURE"],
        samesite=cookie_conf["SAMESITE"],
        path="/",
    )


def pair_response(pair: Any, *, remember_me: bool, created: bool) -> Response:
    """Builds the HTTP response (body + refresh cookie, per ``REFRESH_COOKIE["TRANSPORT"]``) for
    an ALREADY-ISSUED token pair — the shared tail of :func:`tokens_response` (a brand-new pair,
    above) and ``views_twofactor.TwoFactorVerifyView`` (a pair
    ``TwoFactorService.verify_second_factor`` already issued internally; calling
    :func:`tokens_response` there would mint a SECOND, redundant session for the same login).

    Also sets the trusted-device cookie when ``pair`` carries one
    (``services.TwoFactorTokenPair.trusted_device_token``) — read via ``getattr`` so this
    function stays agnostic of that subclass and needs no import of it.
    """
    body: dict[str, Any] = {
        "access": pair.access,
        "session_id": pair.session_id,
        "created": created,
    }

    cookie_conf = conf.get_setting("REFRESH_COOKIE")
    if cookie_conf["TRANSPORT"] == "body":
        body["refresh"] = pair.refresh
        response = Response(body)
    else:
        response = Response(body)
        _set_refresh_cookie(response, pair.refresh, remember_me=remember_me)

    trusted_device_token = getattr(pair, "trusted_device_token", None)
    if trusted_device_token:
        trusted_device_conf = conf.get_setting("TWO_FACTOR")["TRUSTED_DEVICE"]
        response.set_cookie(
            trusted_device_conf["COOKIE_NAME"],
            trusted_device_token,
            max_age=trusted_device_conf["TTL_SECONDS"],
            httponly=True,
            secure=cookie_conf["SECURE"],
            samesite=cookie_conf["SAMESITE"],
            path="/",
        )

    return response


def read_refresh_token(request: Request) -> str | None:
    """Reads the refresh token per ``REFRESH_COOKIE["TRANSPORT"]`` (Phase 8,
    ``POST /token/refresh/``) — the cookie under the default ``"cookie"`` transport,
    ``request.data["refresh"]`` under ``"body"``. Returns ``None`` for a missing, empty, or
    non-string value either way; never raises — a missing refresh token is
    ``views_token.TokenRefreshView``'s own ``401`` (the same shape as any other
    ``InvalidRefreshToken``), not a distinguishable ``400``.
    """
    cookie_conf = conf.get_setting("REFRESH_COOKIE")
    if cookie_conf["TRANSPORT"] == "body":
        # request.data is typed dict[str, Any] | list[Any] — DRF only ever populates a list for
        # a bulk-list body shape, never for this app's own single-object serializers, but the
        # isinstance check keeps this honest for mypy strict rather than asserting it away.
        data = request.data
        token = data.get("refresh") if isinstance(data, dict) else None
        return token if isinstance(token, str) and token else None
    token = request.COOKIES.get(cookie_conf["NAME"])
    return token or None


def refresh_response(pair: Any, *, remember_me: bool) -> Response:
    """Builds the ``POST /token/refresh/`` response (``docs/CONTRACT.md`` §5: ``200 {access,
    session_id}``, re-sets the cookie) — a separate function from :func:`pair_response` rather
    than threading a ``created`` parameter through it, since a refresh is never a fresh login and
    has no meaningful value for ``created`` to report at all (the contract's own row for this
    endpoint lists no ``created`` key).
    """
    body: dict[str, Any] = {"access": pair.access, "session_id": pair.session_id}

    cookie_conf = conf.get_setting("REFRESH_COOKIE")
    if cookie_conf["TRANSPORT"] == "body":
        body["refresh"] = pair.refresh
        response = Response(body)
    else:
        response = Response(body)
        _set_refresh_cookie(response, pair.refresh, remember_me=remember_me)

    return response


def clear_auth_cookies(response: Response) -> None:
    """Clears both the refresh cookie and the trusted-device cookie (``docs/CONTRACT.md`` §5:
    ``POST /logout/`` "clears cookies", plural) — matching the ``path="/"`` every set-cookie call
    above uses, or the browser never actually deletes them. Safe to call unconditionally: deleting
    a cookie the client never set (e.g. under ``REFRESH_COOKIE["TRANSPORT"] == "body"``, or a
    caller who never opted into a trusted device) is a harmless no-op.
    """
    cookie_conf = conf.get_setting("REFRESH_COOKIE")
    trusted_device_conf = conf.get_setting("TWO_FACTOR")["TRUSTED_DEVICE"]
    response.delete_cookie(cookie_conf["NAME"], path="/", samesite=cookie_conf["SAMESITE"])
    response.delete_cookie(
        trusted_device_conf["COOKIE_NAME"], path="/", samesite=cookie_conf["SAMESITE"]
    )
