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
                    if _verify_wlan_write_applied(self, original_request, path, data, logger):
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
                if _verify_wlan_write_applied(self, original_request, path, data, logger):
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
    router: TPLinkDecoClient,
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
    if _poll_wlan_state_matches(router, original_request, targets, logger):
        logger.debug("TplinkRouter deco compat - WLAN write verified after initial write")
        return True

    state = _read_wlan_state(router, original_request, logger)
    for retry_path, retry_payload in _build_wlan_retry_requests(path, payload, state, targets, logger):
        if retry_path == path and retry_payload == payload:
            continue
        logger.debug(
            "TplinkRouter deco compat - retrying WLAN write endpoint=%s payload=%s",
            retry_path,
            retry_payload,
        )
        try:
            # Ignore response parsing on retries and rely on explicit state verification.
            original_request(retry_path, retry_payload, True, False)
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

        if _poll_wlan_state_matches(router, original_request, targets, logger):
            logger.debug("TplinkRouter deco compat - WLAN write verified after retry payload")
            return True

    logger.debug("TplinkRouter deco compat - WLAN write verification failed, state unchanged")
    return False


def _build_wlan_retry_requests(
    path: str,
    original_payload: str,
    state: dict | None,
    targets: list[tuple[tuple[str, str, str], bool]],
    logger: Logger,
) -> list[tuple[str, str]]:
    requests: list[tuple[str, str]] = []

    for payload in _build_wlan_retry_payloads(original_payload, state, targets, logger):
        requests.append((path, payload))

    if _guest_only_targets(targets):
        for endpoint in _guest_retry_endpoints(path):
            for params in _build_guest_retry_param_sets(state, targets):
                requests.append((endpoint, dumps({"operation": "write", "params": params})))
                requests.append((
                    endpoint,
                    dumps({"operation": "write", "params": _transform_enable_values(params, lambda b: "on" if b else "off")}),
                ))
                requests.append((
                    endpoint,
                    dumps({"operation": "write", "params": _transform_enable_values(params, lambda b: 1 if b else 0)}),
                ))

    unique_requests: list[tuple[str, str]] = []
    seen: set[str] = set()
    for retry_path, retry_payload in requests:
        key = f"{retry_path}||{retry_payload}"
        if key in seen:
            continue
        seen.add(key)
        unique_requests.append((retry_path, retry_payload))

    logger.debug("TplinkRouter deco compat - generated %s WLAN retry requests", len(unique_requests))
    return unique_requests


def _guest_retry_endpoints(default_path: str) -> list[str]:
    return [
        default_path,
        "admin/wireless?form=guest_network",
        "admin/wireless?form=guest",
        "admin/wireless?form=wlan_guest",
    ]


def _build_guest_retry_param_sets(
    state: dict | None,
    targets: list[tuple[tuple[str, str, str], bool]],
) -> list[dict[str, Any]]:
    guest_profile = _build_guest_profile(state, targets)
    if not guest_profile:
        return []

    host_profile = _build_host_profile(state)
    ext_guest_profile = _build_ext_guest_profile(state, guest_profile)

    params_sets: list[dict[str, Any]] = [
        {"guest": dict(guest_profile)},
        {"guest_network": dict(guest_profile)},
        {"guestNetwork": dict(guest_profile)},
    ]

    if ext_guest_profile:
        params_sets.append({"ext_guest": dict(ext_guest_profile)})
        params_sets.append({"guest": dict(guest_profile), "ext_guest": dict(ext_guest_profile)})

    if host_profile:
        params_sets.append({"host": dict(host_profile), "guest": dict(guest_profile)})
        params_sets.append({"hostNetwork": dict(host_profile), "guestNetwork": dict(guest_profile)})

    return params_sets


def _build_guest_profile(
    state: dict | None,
    targets: list[tuple[tuple[str, str, str], bool]],
) -> dict[str, Any]:
    band_to_enable_key = {
        "band2_4": "enable_2g",
        "band5_1": "enable_5g",
        "band5_2": "enable_5g2",
        "band6": "enable_6g",
        "band6_2": "enable_6g2",
    }

    profile: dict[str, Any] = {}
    if isinstance(state, dict):
        for band, enable_key in band_to_enable_key.items():
            current = _get_nested(state, [band, "guest", "enable"])
            if current is not None:
                profile[enable_key] = _to_bool(current)

        for key in ("guest", "guest_network", "guestNetwork"):
            value = state.get(key)
            if not isinstance(value, dict):
                continue
            for extra in (
                "ssid",
                "password",
                "enable_wpa3",
                "host_isolation",
                "bw_limit_enable",
                "enable",
                "guest_enable_6g2",
            ):
                if extra in value and extra not in profile:
                    profile[extra] = value[extra]

        if "host_isolation" in state and "host_isolation" not in profile:
            profile["host_isolation"] = state["host_isolation"]

    for target_path, desired in targets:
        band = target_path[0]
        enable_key = band_to_enable_key.get(band)
        if enable_key:
            profile[enable_key] = desired

    return profile


def _build_host_profile(state: dict | None) -> dict[str, Any]:
    band_to_enable_key = {
        "band2_4": "enable_2g",
        "band5_1": "enable_5g",
        "band5_2": "enable_5g2",
        "band6": "enable_6g",
        "band6_2": "enable_6g2",
    }
    profile: dict[str, Any] = {}
    if not isinstance(state, dict):
        return profile

    for band, enable_key in band_to_enable_key.items():
        current = _get_nested(state, [band, "host", "enable"])
        if current is not None:
            profile[enable_key] = _to_bool(current)
    return profile


def _build_ext_guest_profile(state: dict | None, guest_profile: dict[str, Any]) -> dict[str, Any]:
    profile: dict[str, Any] = {}
    if "enable_6g2" in guest_profile:
        profile["enable_6g2"] = guest_profile["enable_6g2"]
    if isinstance(state, dict) and "guest_enable_6g2" in state:
        profile["enable_6g2"] = state["guest_enable_6g2"]
    return profile


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


def _poll_wlan_state_matches(router: TPLinkDecoClient, original_request: Any,
                             targets: list[tuple[tuple[str, str, str], bool]], logger: Logger,
                             attempts: int = 6) -> bool:
    for attempt in range(1, attempts + 1):
        state = _read_wlan_state(router, original_request, logger)
        if state is not None and _wlan_state_matches(state, targets):
            return True
        if attempt < attempts:
            sleep(0.5)
    return False


def _read_wlan_state(router: TPLinkDecoClient, original_request: Any, logger: Logger) -> dict | None:
    try:
        data = original_request(_WLAN_ENDPOINT, dumps({"operation": "read"}), False, False)
        if isinstance(data, dict):
            logger.debug("TplinkRouter deco compat - WLAN state read for verification: %s", data)
            return data
    except ClientError as err:
        if "An unknown response" not in str(err):
            logger.debug(
                "TplinkRouter deco compat - failed to read WLAN state for verification: %s",
                err,
                exc_info=True,
            )
            return None

        raw_response = _extract_raw_response(str(err))
        if raw_response:
            decoded_response = _decode_response(router, raw_response, logger)
            if isinstance(decoded_response, dict):
                if router._is_valid_response(decoded_response):
                    data = decoded_response.get(router._data_block)
                    if isinstance(data, dict):
                        logger.debug(
                            "TplinkRouter deco compat - WLAN state read decoded for verification: %s",
                            data,
                        )
                        return data
                elif decoded_response:
                    # Some firmwares return data block directly without wrapper keys.
                    if _looks_like_wlan_state(decoded_response):
                        logger.debug(
                            "TplinkRouter deco compat - WLAN state direct decoded for verification: %s",
                            decoded_response,
                        )
                        return decoded_response
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


def _looks_like_wlan_state(data: dict[str, Any]) -> bool:
    for band in ("band2_4", "band5_1", "band5_2", "band6", "band6_2"):
        band_cfg = data.get(band)
        if isinstance(band_cfg, dict) and ("guest" in band_cfg or "host" in band_cfg):
            return True
    return False


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

            # Candidate N: keep the exact read schema and only patch target fields.
            params_from_full_state = _apply_targets_to_state(state, targets)
            if params_from_full_state:
                candidates.append({"operation": "write", "params": params_from_full_state})
                candidates.append({
                    "operation": "write",
                    "params": _transform_enable_values(params_from_full_state, lambda b: "on" if b else "off"),
                })
                candidates.append({
                    "operation": "write",
                    "params": _transform_enable_values(params_from_full_state, lambda b: 1 if b else 0),
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


def _apply_targets_to_state(
    state: dict | None,
    targets: list[tuple[tuple[str, str, str], bool]],
) -> dict[str, Any] | None:
    if not isinstance(state, dict):
        return None
    params = loads(dumps(state))
    changed = False
    for path, desired in targets:
        cursor: Any = params
        for key in path[:-1]:
            if not isinstance(cursor, dict):
                cursor = None
                break
            if key not in cursor:
                cursor = None
                break
            cursor = cursor[key]
        if isinstance(cursor, dict) and path[-1] in cursor:
            cursor[path[-1]] = desired
            changed = True
    return params if changed else None


def _transform_enable_values(value: Any, transform: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key == "enable" or str(key).startswith("enable_") or key == "guest_enable_6g2":
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
