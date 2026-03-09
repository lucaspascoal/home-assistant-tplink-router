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
_MAX_WLAN_RETRY_REQUESTS = 32
_RETRY_STATE_POLL_ATTEMPTS = 2


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

        if _poll_wlan_state_matches(
            router,
            original_request,
            targets,
            logger,
            attempts=_RETRY_STATE_POLL_ATTEMPTS,
        ):
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

    if _guest_only_targets(targets):
        # Prefer guest-specific endpoint/payload shapes first for Deco firmwares
        # that reject generic WLAN band objects on write.
        params_candidates: list[dict[str, Any]] = []
        params_candidates.extend(_build_guest_minimal_param_sets(state, targets))
        params_candidates.extend(_build_guest_retry_param_sets(state, targets))

        params_from_full_state = _apply_targets_to_state(state, targets)
        if params_from_full_state:
            params_candidates.append(params_from_full_state)

        guest_payloads: list[str] = []
        guest_payloads_seen: set[str] = set()
        for params in params_candidates:
            for params_variant in _build_enable_value_variants(params):
                payload = dumps({"operation": "write", "params": params_variant})
                if payload in guest_payloads_seen:
                    continue
                guest_payloads_seen.add(payload)
                guest_payloads.append(payload)

        # Round-robin payloads across guest endpoints so retry trimming does not
        # starve secondary endpoints.
        for payload in guest_payloads:
            for endpoint in _guest_retry_endpoints(path):
                requests.append((endpoint, payload))

    for payload in _build_wlan_retry_payloads(original_payload, state, targets, logger):
        requests.append((path, payload))

    unique_requests: list[tuple[str, str]] = []
    seen: set[str] = set()
    for retry_path, retry_payload in requests:
        key = f"{retry_path}||{retry_payload}"
        if key in seen:
            continue
        seen.add(key)
        unique_requests.append((retry_path, retry_payload))

    if len(unique_requests) > _MAX_WLAN_RETRY_REQUESTS:
        logger.debug(
            "TplinkRouter deco compat - trimming WLAN retry requests from %s to %s",
            len(unique_requests),
            _MAX_WLAN_RETRY_REQUESTS,
        )
        unique_requests = unique_requests[:_MAX_WLAN_RETRY_REQUESTS]

    logger.debug("TplinkRouter deco compat - generated %s WLAN retry requests", len(unique_requests))
    return unique_requests


def _guest_retry_endpoints(default_path: str) -> list[str]:
    return [
        "admin/wireless?form=guest_network",
        "admin/wireless?form=guest",
        "admin/wireless?form=wlan_guest",
        default_path,
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

    guest_profile_copy = dict(guest_profile)
    params_sets: list[dict[str, Any]] = []

    # Prioritize legacy Deco guest profile (2.4G/5G controls) first.
    legacy_guest_profile = _build_legacy_guest_profile(guest_profile_copy, targets)
    if legacy_guest_profile:
        params_sets.append({"guest": dict(legacy_guest_profile)})
        params_sets.append({"guest_network": dict(legacy_guest_profile)})
        params_sets.append({"guestNetwork": dict(legacy_guest_profile)})

    params_sets.extend([
        {"guest": dict(guest_profile_copy)},
        {"guest_network": dict(guest_profile_copy)},
        {"guestNetwork": dict(guest_profile_copy)},
    ])

    if ext_guest_profile:
        ext_guest_copy = dict(ext_guest_profile)
        params_sets.append({"ext_guest": dict(ext_guest_copy)})
        params_sets.append({"guest": dict(guest_profile_copy), "ext_guest": dict(ext_guest_copy)})
        params_sets.append({"guest_network": dict(guest_profile_copy), "ext_guest": dict(ext_guest_copy)})
        params_sets.append({"guestNetwork": dict(guest_profile_copy), "ext_guest": dict(ext_guest_copy)})

    if host_profile:
        host_profile_copy = dict(host_profile)
        params_sets.append({"host": dict(host_profile_copy), "guest": dict(guest_profile_copy)})
        params_sets.append({"host": dict(host_profile_copy), "guest_network": dict(guest_profile_copy)})
        params_sets.append({"hostNetwork": dict(host_profile_copy), "guestNetwork": dict(guest_profile_copy)})
        if ext_guest_profile:
            params_sets.append({
                "hostNetwork": dict(host_profile_copy),
                "guestNetwork": dict(guest_profile_copy),
                "ext_guest": dict(ext_guest_profile),
            })

    return params_sets


def _build_guest_minimal_param_sets(
    state: dict | None,
    targets: list[tuple[tuple[str, str, str], bool]],
) -> list[dict[str, Any]]:
    if not targets:
        return []

    all_same_desired = len({desired for _, desired in targets}) == 1
    desired = targets[0][1] if all_same_desired else None
    band_to_enable_key = {
        "band2_4": "enable_2g",
        "band5_1": "enable_5g",
        "band5_2": "enable_5g2",
        "band6": "enable_6g",
        "band6_2": "enable_6g2",
    }

    per_band_enable: dict[str, Any] = {}
    if isinstance(state, dict):
        for band, enable_key in band_to_enable_key.items():
            current = _get_nested(state, [band, "guest", "enable"])
            if current is not None:
                per_band_enable[enable_key] = _to_bool(current)

    for path, value in targets:
        band = path[0]
        enable_key = band_to_enable_key.get(band)
        if enable_key:
            per_band_enable[enable_key] = value

    # Deco guest UI often uses a unified 2.4/5G switch.
    if desired is not None and any(path[0] in ("band2_4", "band5_1") for path, _ in targets):
        per_band_enable["enable_2g"] = desired
        per_band_enable["enable_5g"] = desired

    minimal_profiles: list[dict[str, Any]] = []
    if desired is not None:
        minimal_profiles.append({"enable": desired})

    profile_2g5g: dict[str, Any] = {}
    for key in ("enable_2g", "enable_5g"):
        if key in per_band_enable:
            profile_2g5g[key] = per_band_enable[key]
    if desired is not None:
        profile_2g5g["enable"] = desired
    if profile_2g5g:
        minimal_profiles.append(profile_2g5g)

    if per_band_enable:
        full_enable_profile = dict(per_band_enable)
        if desired is not None:
            full_enable_profile["enable"] = desired
        minimal_profiles.append(full_enable_profile)

    params_sets: list[dict[str, Any]] = []
    for profile in minimal_profiles:
        params_sets.append({"guest": dict(profile)})
        params_sets.append({"guest_network": dict(profile)})
        params_sets.append({"guestNetwork": dict(profile)})

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
            for extra_key, extra_value in value.items():
                if extra_key not in profile:
                    profile[extra_key] = extra_value

        for root_key in (
            "host_isolation",
            "guest_enable_6g2",
            "enable_6g2",
            "enable",
            "vlan_enable",
            "vlan_id",
            "need_set_vlan",
            "access_duration",
            "bandwidth_limit",
            "bw_limit_enable",
            "bw_limit_down",
            "bw_limit_up",
            "downstream_bandwidth",
            "upstream_bandwidth",
            "start_time",
        ):
            if root_key in state and root_key not in profile:
                profile[root_key] = state[root_key]

    for target_path, desired in targets:
        band = target_path[0]
        enable_key = band_to_enable_key.get(band)
        if enable_key:
            profile[enable_key] = desired

    if "guest_enable_6g2" in profile and "enable_6g2" not in profile:
        profile["enable_6g2"] = profile["guest_enable_6g2"]
    if "enable_6g2" in profile and "guest_enable_6g2" not in profile:
        profile["guest_enable_6g2"] = profile["enable_6g2"]

    if "enable" not in profile and targets:
        unique_desired = {desired for _, desired in targets}
        if len(unique_desired) == 1:
            profile["enable"] = next(iter(unique_desired))

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
    if isinstance(state, dict):
        ext_guest = state.get("ext_guest")
        if isinstance(ext_guest, dict):
            profile.update(ext_guest)
        for key in ("guest_enable_6g2", "enable_6g2"):
            if key in state and key not in profile:
                profile[key] = state[key]

    for key in ("guest_enable_6g2", "enable_6g2"):
        if key in guest_profile and key not in profile:
            profile[key] = guest_profile[key]

    if "enable_6g2" in profile and "guest_enable_6g2" not in profile:
        profile["guest_enable_6g2"] = profile["enable_6g2"]
    if "guest_enable_6g2" in profile and "enable_6g2" not in profile:
        profile["enable_6g2"] = profile["guest_enable_6g2"]

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

    _append_write_candidates(candidates, params)

    if _guest_only_targets(targets):
        desired = targets[0][1]
        control_bands = _collect_guest_control_bands(state)
        params_control_bands = {band: {"guest": {"enable": desired}} for band in control_bands}
        _append_write_candidates(candidates, params_control_bands)

        guest_bands = _collect_guest_bands(state)
        if not guest_bands:
            guest_bands = ["band2_4", "band5_1", "band6"]

        params_all_bands = {band: {"guest": {"enable": desired}} for band in guest_bands}
        if params_all_bands != params_control_bands:
            _append_write_candidates(candidates, params_all_bands)

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
                _append_write_candidates(candidates, params_from_state)

            # Candidate 6: full per-band objects from read-state (host+guest+iot).
            if params_full_state:
                _append_write_candidates(candidates, params_full_state)

            # Candidate 7+: if read-state has root guest controls, try those.
            for key, value in state.items():
                if not isinstance(value, dict):
                    continue
                if "guest" not in str(key).lower():
                    continue
                if "enable" in value:
                    root_params = {str(key): dict(value)}
                    root_params[str(key)]["enable"] = desired
                    _append_write_candidates(candidates, root_params)

            # Candidate N: keep the exact read schema and only patch target fields.
            params_from_full_state = _apply_targets_to_state(state, targets)
            if params_from_full_state:
                _append_write_candidates(candidates, params_from_full_state)

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


def _collect_guest_control_bands(state: dict | None) -> list[str]:
    preferred = ["band2_4", "band5_1"]
    if not isinstance(state, dict):
        return preferred

    result = [
        band for band in preferred
        if isinstance(state.get(band), dict) and isinstance(state.get(band, {}).get("guest"), dict)
    ]
    return result or preferred


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
            key_text = str(key)
            if (
                key_text == "enable"
                or key_text.startswith("enable_")
                or key_text.endswith("_enable")
                or key_text.startswith("guest_enable")
            ):
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


def _build_legacy_guest_profile(
    guest_profile: dict[str, Any],
    targets: list[tuple[tuple[str, str, str], bool]],
) -> dict[str, Any]:
    desired_values = {desired for _, desired in targets}
    desired = next(iter(desired_values)) if len(desired_values) == 1 else None

    profile: dict[str, Any] = {}
    for key in (
        "enable",
        "enable_2g",
        "enable_5g",
        "enable_5g2",
        "enable_6g",
        "enable_6g2",
        "guest_enable_6g2",
    ):
        if key in guest_profile:
            profile[key] = guest_profile[key]

    # For firmwares where guest is a single network switch, force 2.4/5G enables together.
    if desired is not None:
        profile["enable"] = desired
        profile["enable_2g"] = desired
        profile["enable_5g"] = desired

    return profile


def _build_enable_value_variants(params: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        params,
        _transform_enable_values(params, lambda b: "on" if b else "off"),
        _transform_enable_values(params, lambda b: 1 if b else 0),
        _transform_enable_values(params, lambda b: "1" if b else "0"),
    ]


def _append_write_candidates(candidates: list[dict[str, Any]], params: dict[str, Any]) -> None:
    for params_variant in _build_enable_value_variants(params):
        candidates.append({"operation": "write", "params": params_variant})


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
