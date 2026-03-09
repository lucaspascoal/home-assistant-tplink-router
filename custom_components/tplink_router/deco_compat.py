from __future__ import annotations

from base64 import b64decode
from json import dumps, loads
from logging import Logger
from time import sleep
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
        is_wlan_write = trace_wlan and _is_wlan_write_request(data)
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
            unknown_response = "An unknown response" in str(err)
            if not unknown_response:
                raise

            if trace_wlan:
                logger.debug(
                    "TplinkRouter deco compat - parse exception endpoint=%s payload=%s exception=%s",
                    path,
                    data,
                    err,
                    exc_info=True,
                )
            else:
                logger.debug(
                    "TplinkRouter deco compat - parse exception endpoint=%s exception=%s",
                    path,
                    err,
                    exc_info=True,
                )

            raw_response = _extract_raw_response(str(err))
            if not raw_response:
                raise
            if trace_wlan:
                logger.debug(
                    "TplinkRouter deco compat - raw response endpoint=%s response=%s",
                    path,
                    raw_response,
                )
            else:
                logger.debug("TplinkRouter deco compat - raw response endpoint=%s", path)

            decoded_response = _decode_response(self, raw_response, logger)
            if decoded_response is None:
                if is_wlan_write:
                    if _verify_wlan_write_applied(original_request, path, data, logger):
                        return None
                    error = (
                        "TplinkRouter - {} - WLAN write was sent but no state change was observed; "
                        "response could not be decoded. Request {} - Response {}"
                        .format(self.__class__.__name__, path, raw_response)
                    )
                    logger.warning(error)
                    raise ClientError(error) from err
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
            if is_wlan_write and not _contains_explicit_error(decoded_response):
                if _verify_wlan_write_applied(original_request, path, data, logger):
                    return None
                error = (
                    "TplinkRouter - {} - WLAN write returned unexpected schema and no state change was observed; "
                    "Request {} - Response {}"
                    .format(self.__class__.__name__, path, decoded_response)
                )
                logger.warning(error)
                raise ClientError(error) from err

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


def _is_wlan_write_request(payload: str) -> bool:
    try:
        body = loads(payload)
        return body.get("operation") == "write"
    except Exception:
        return False


def _verify_wlan_write_applied(
    original_request: Any,
    path: str,
    payload: str,
    logger: Logger,
) -> bool:
    targets = _extract_wlan_targets(payload)
    if not targets:
        logger.debug("TplinkRouter deco compat - cannot verify WLAN write: no target fields in payload")
        return False

    # Some Deco firmwares return non-JSON payloads for write calls.
    # Verify state with a read call instead of trusting write response format.
    if _poll_wlan_state_matches(original_request, targets, logger):
        logger.debug("TplinkRouter deco compat - WLAN write verified after initial write")
        return True

    state = _read_wlan_state(original_request, logger)
    for retry_payload in _build_wlan_retry_payloads(payload, state, targets, logger):
        if retry_payload == payload:
            continue
        logger.debug("TplinkRouter deco compat - retrying WLAN write with payload=%s", retry_payload)
        try:
            original_request(path, retry_payload, False, False)
        except Exception as err:
            logger.debug(
                "TplinkRouter deco compat - WLAN write retry failed: %s",
                err,
                exc_info=True,
            )
            if "Not authorised" in str(err):
                # Authorization may be invalidated by overlapping requests.
                # Abort retries gracefully and let caller handle the original write error.
                return False

        if _poll_wlan_state_matches(original_request, targets, logger):
            logger.debug("TplinkRouter deco compat - WLAN write verified after retry payload")
            return True

    logger.debug("TplinkRouter deco compat - WLAN write verification failed, state unchanged")
    return False


def _extract_wlan_targets(payload: str) -> list[tuple[tuple[str, str, str], bool]]:
    try:
        body = loads(payload)
    except Exception:
        return []

    if body.get("operation") != "write":
        return []

    params = body.get("params")
    if not isinstance(params, dict):
        return []

    targets: list[tuple[tuple[str, str, str], bool]] = []
    for band, band_cfg in params.items():
        if not isinstance(band_cfg, dict):
            continue
        for net in ("guest", "host", "iot"):
            net_cfg = band_cfg.get(net)
            if not isinstance(net_cfg, dict) or "enable" not in net_cfg:
                continue
            targets.append(((str(band), net, "enable"), _to_bool(net_cfg.get("enable"))))
    return targets


def _guest_only_targets(targets: list[tuple[tuple[str, str, str], bool]]) -> bool:
    return bool(targets) and all(target[0][1] == "guest" for target in targets)


def _poll_wlan_state_matches(original_request: Any, targets: list[tuple[tuple[str, str, str], bool]],
                             logger: Logger, attempts: int = 3) -> bool:
    for attempt in range(1, attempts + 1):
        state = _read_wlan_state(original_request, logger)
        if state is not None and _wlan_state_matches(state, targets):
            return True
        if attempt < attempts:
            sleep(0.35)
    return False


def _read_wlan_state(original_request: Any, logger: Logger) -> dict | None:
    try:
        data = original_request(_WLAN_ENDPOINT, dumps({"operation": "read"}), False, False)
        if isinstance(data, dict):
            logger.debug("TplinkRouter deco compat - WLAN state read for verification: %s", data)
            return data
    except Exception as err:
        logger.debug(
            "TplinkRouter deco compat - failed to read WLAN state for verification: %s",
            err,
            exc_info=True,
        )
    return None


def _wlan_state_matches(state: dict, targets: list[tuple[tuple[str, str, str], bool]]) -> bool:
    matched = 0
    for path, desired in targets:
        current = _get_nested(state, list(path))
        if current is None:
            continue
        matched += 1
        if _to_bool(current) != desired:
            return False
    return matched > 0


def _build_wlan_retry_payloads(
    original_payload: str,
    state: dict | None,
    targets: list[tuple[tuple[str, str, str], bool]],
    logger: Logger,
) -> list[str]:
    try:
        body = loads(original_payload)
    except Exception:
        return []
    if body.get("operation") != "write":
        return []

    params = body.get("params")
    if not isinstance(params, dict):
        return []

    candidates: list[dict] = []

    # Candidate 1: same shape, but with string on/off values.
    candidates.append({"operation": "write", "params": _transform_enable_values(params, lambda b: "on" if b else "off")})

    # Candidate 2: same shape, but with 1/0 values.
    candidates.append({"operation": "write", "params": _transform_enable_values(params, lambda b: 1 if b else 0)})

    if _guest_only_targets(targets):
        desired = targets[0][1]
        guest_bands = _collect_guest_bands(state)
        if not guest_bands:
            guest_bands = ["band2_4", "band5_1", "band6"]

        params_all_bands = {band: {"guest": {"enable": desired}} for band in guest_bands}
        candidates.append({"operation": "write", "params": params_all_bands})
        candidates.append({
            "operation": "write",
            "params": _transform_enable_values(params_all_bands, lambda b: "on" if b else "off"),
        })

        # Candidate 5: full guest objects from read-state, preserving other guest fields.
        if isinstance(state, dict):
            params_from_state: dict[str, Any] = {}
            params_full_state: dict[str, Any] = {}
            for band in guest_bands:
                band_cfg = state.get(band)
                if not isinstance(band_cfg, dict):
                    continue
                guest_cfg = band_cfg.get("guest")
                if not isinstance(guest_cfg, dict):
                    continue

                new_guest_cfg = dict(guest_cfg)
                new_guest_cfg["enable"] = desired
                params_from_state[band] = {"guest": new_guest_cfg}

                # Some Deco firmwares expect host fields in the same write call.
                full_band_cfg: dict[str, Any] = {"guest": new_guest_cfg}
                host_cfg = band_cfg.get("host")
                if isinstance(host_cfg, dict):
                    full_band_cfg["host"] = dict(host_cfg)
                iot_cfg = band_cfg.get("iot")
                if isinstance(iot_cfg, dict):
                    full_band_cfg["iot"] = dict(iot_cfg)
                params_full_state[band] = full_band_cfg

            # Preserve root keys that may be required by vendor handlers.
            for key in ("enable_2g", "enable_5g", "enable_5g2", "enable_6g", "enable_6g2", "host_isolation"):
                if key in state:
                    params_full_state[key] = state[key]

            if params_from_state:
                candidates.append({"operation": "write", "params": params_from_state})
                candidates.append({
                    "operation": "write",
                    "params": _transform_enable_values(params_from_state, lambda b: "on" if b else "off"),
                })
                candidates.append({
                    "operation": "write",
                    "params": _transform_enable_values(params_from_state, lambda b: 1 if b else 0),
                })

            # Candidate 6: full per-band objects from read-state (host+guest+iot).
            if params_full_state:
                candidates.append({"operation": "write", "params": params_full_state})
                candidates.append({
                    "operation": "write",
                    "params": _transform_enable_values(params_full_state, lambda b: "on" if b else "off"),
                })
                candidates.append({
                    "operation": "write",
                    "params": _transform_enable_values(params_full_state, lambda b: 1 if b else 0),
                })

            # Candidate 7+: if read-state has root guest controls, try those.
            for key, value in state.items():
                if not isinstance(value, dict):
                    continue
                if "guest" not in str(key).lower():
                    continue
                if "enable" in value:
                    root_params = {str(key): dict(value)}
                    root_params[str(key)]["enable"] = desired
                    candidates.append({"operation": "write", "params": root_params})
                    candidates.append({
                        "operation": "write",
                        "params": _transform_enable_values(root_params, lambda b: "on" if b else "off"),
                    })

    unique_payloads: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        payload = dumps(candidate)
        if payload in seen:
            continue
        seen.add(payload)
        unique_payloads.append(payload)

    logger.debug("TplinkRouter deco compat - generated %s WLAN retry payloads", len(unique_payloads))
    return unique_payloads


def _collect_guest_bands(state: dict | None) -> list[str]:
    if not isinstance(state, dict):
        return []
    bands: list[str] = []
    for band, band_cfg in state.items():
        if isinstance(band_cfg, dict) and isinstance(band_cfg.get("guest"), dict):
            bands.append(str(band))
    return bands


def _transform_enable_values(value: Any, transform: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key == "enable":
                result[key] = transform(_to_bool(item))
            else:
                result[key] = _transform_enable_values(item, transform)
        return result
    if isinstance(value, list):
        return [_transform_enable_values(item, transform) for item in value]
    return value


def _get_nested(data: dict, path: list[str]) -> Any:
    value: Any = data
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("on", "true", "1", "yes")
    return bool(value)


def _contains_explicit_error(decoded_response: dict) -> bool:
    if "error_code" in decoded_response and decoded_response["error_code"] != 0:
        return True
    if "success" in decoded_response and not decoded_response["success"]:
        return True
    result = decoded_response.get("result")
    if isinstance(result, dict) and "error_code" in result and result["error_code"] != 0:
        return True
    return False


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
