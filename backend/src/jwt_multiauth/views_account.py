"""Self-service contact-verification views: request/confirm.

Phase 8 implements the views backing ``urls.py``'s ``/account/verify-contact/request/``,
``/account/verify-contact/confirm/`` routes (basePath ``/api/v1/auth``), per ``docs/CONTRACT.md``
§5 — proving a caller controls an email/phone value, distinct from that value being used to log in.
``VerificationService`` (``services.py``, Phase 5) does the actual verification-challenge
lifecycle; this module only translates HTTP <-> service calls.
"""

from __future__ import annotations

from typing import Any

from django.core.exceptions import ImproperlyConfigured
from django.core.exceptions import ValidationError as DjangoValidationError
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import generics
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from jwt_multiauth import throttling
from jwt_multiauth.authentication import JWTAuthentication
from jwt_multiauth.serializers import (
    OtpRequestResponseSerializer,
    VerifyContactConfirmSerializer,
    VerifyContactRequestSerializer,
)
from jwt_multiauth.services import ChallengeInvalid, VerificationService


class VerifyContactRequestView(generics.GenericAPIView[Any]):
    """``POST /account/verify-contact/request/``. No decoy path — the caller is already
    authenticated, so the identifier being verified always resolves (to themselves).
    """

    serializer_class = VerifyContactRequestSerializer
    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.VERIFY_CONTACT_REQUEST

    @extend_schema(
        summary="Request an OTP challenge to verify the caller's own email or phone",
        request=VerifyContactRequestSerializer,
        responses={
            200: OtpRequestResponseSerializer,
            400: OpenApiResponse(
                description="field isn't configured on this host, or the caller has no current "
                "value for it."
            ),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        field = serializer.validated_data["field"]
        try:
            result = VerificationService.request_contact_verification(request.user, field=field)
        except ImproperlyConfigured as exc:
            raise ValidationError({"code": "field_not_configured"}) from exc
        except DjangoValidationError as exc:
            raise ValidationError(
                {"code": getattr(exc, "code", None) or "no_contact_value"}
            ) from exc
        return Response(
            {
                "challenge_id": result.challenge_id,
                "expires_at": result.expires_at,
                "resend_available_at": result.resend_available_at,
            }
        )


class VerifyContactConfirmView(generics.GenericAPIView[Any]):
    """``POST /account/verify-contact/confirm/``. An unresolved/expired/wrong-purpose challenge,
    and one verified by a different user than the caller, all produce the identical
    ``otp_challenge_invalid`` shape — same rule ``OtpVerifyView`` applies to its own challenges.
    """

    serializer_class = VerifyContactConfirmSerializer
    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.VERIFY_CONTACT_CONFIRM

    @extend_schema(
        summary="Confirm a contact-verification OTP challenge",
        request=VerifyContactConfirmSerializer,
        responses={
            204: None,
            400: OpenApiResponse(description="Invalid, expired, or wrong-purpose challenge."),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            VerificationService.confirm(request.user, data["challenge_id"], code=data["code"])
        except ChallengeInvalid as exc:
            raise ValidationError({"code": "otp_challenge_invalid"}) from exc
        return Response(status=204)
