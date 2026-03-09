from __future__ import annotations

from base64 import b64decode
from json import loads
from logging import Logger
from types import MethodType
from typing import Any

from tplinkrouterc6u.client.deco import TPLinkDecoClient
from tplinkrouterc6u.common.exception import ClientError

_WLAN_ENDPOINT = "admin/wireless?form=wlan"
_PATCH_FLAG = "_ha_tplink_router_deco_wlan_patch"


def patch_deco_wlan_response(router: Any, logger: Logger) -> None:
    """Patch Deco request parsing for firmware that returns raw encrypted WLAN responses."""
    if not isinstance(router, TPLinkDecoClient):
        return
    if getattr(router, _PATCH_FLAG, False):
        return

    original_request = router.request

    def _patched_request(
        self: TPLinkDecoClient,
        path: str,
        data: str,
        ignore_response: bool = False,
        ignore_errors: bool = False,
    ) -> dict | None:
        trace_wlan = path == _WLAN_ENDPOINT
        if trace_wlan:
            logger.debug(
                "TplinkRouter deco compat - endpoint=%s payload=%s ignore_response=%s ignore_errors=%s",
                path,
                data,
                ignore_response,
                ignore_errors,
            )

        try:
            response = original_request(path, data, ignore_response, ignore_errors)
            if trace_wlan and not ignore_response:
                logger.debug(
                    "TplinkRouter deco compat - parsed response endpoint=%s response=%s",
                    path,
                    response,
                )
            return response
        except ClientError as err:
            if not trace_wlan or "An unknown response" not in str(err):
                raise

            logger.debug(
                "TplinkRouter deco compat - parse exception endpoint=%s payload=%s exception=%s",
                path,
                data,
                err,
                exc_info=True,
            )

            raw_response = _extract_raw_response(str(err))
            if not raw_response:
                raise
            logger.debug(
                "TplinkRouter deco compat - raw response endpoint=%s response=%s",
                path,
                raw_response,
            )

            decoded_response = _decode_response(self, raw_response, logger)
            if decoded_response is None:
                raise
            logger.debug(
                "TplinkRouter deco compat - decoded response endpoint=%s response=%s",
                path,
                decoded_response,
            )

            if self._is_valid_response(decoded_response):
                return decoded_response.get(self._data_block)
            if ignore_errors:
                return decoded_response

            error = (
                "TplinkRouter - {} - Response with error; Request {} - Response {}"
                .format(self.__class__.__name__, path, decoded_response)
            )
            logger.debug(error)
            raise ClientError(error) from err

    router.request = MethodType(_patched_request, router)
    setattr(router, _PATCH_FLAG, True)

    logger.debug(
        "TplinkRouter deco compat - enabled raw WLAN response fallback for %s",
        router.__class__.__name__,
    )


def _extract_raw_response(error_message: str) -> str | None:
    marker = " - Response "
    if marker not in error_message:
        return None
    return error_message.split(marker, 1)[1].strip()


def _decode_response(router: TPLinkDecoClient, raw_response: str, logger: Logger) -> dict | None:
    try:
        return loads(raw_response)
    except Exception as err:
        logger.debug(
            "TplinkRouter deco compat - json parse failed for raw response: %s",
            err,
            exc_info=True,
        )

    try:
        decrypted = router._encryption.aes_decrypt(raw_response)
        logger.debug(
            "TplinkRouter deco compat - response after AES decrypt: %s",
            decrypted,
        )
        return loads(decrypted)
    except Exception as err:
        logger.debug(
            "TplinkRouter deco compat - AES decrypt/parse failed: %s",
            err,
            exc_info=True,
        )

    try:
        decoded = b64decode(raw_response).decode("utf-8")
        logger.debug(
            "TplinkRouter deco compat - response after base64 decode: %s",
            decoded,
        )
        return loads(decoded)
    except Exception as err:
        logger.debug(
            "TplinkRouter deco compat - base64 decode/parse failed: %s",
            err,
            exc_info=True,
        )

    return None
