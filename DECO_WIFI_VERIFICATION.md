# Verified Deco Wi-Fi control

This development branch consumes the companion library's verified Deco Wi-Fi API. Existing `tplink_router` configuration entries, device identities, switch keys, and automation references remain in place.

For classic Deco clients, the coordinator serializes the session, requests one write, and applies only values returned by subsequent Wi-Fi reads. The switch displays those observed values. Router rejection and unavailable verification remain visible as errors, without asserting that firmware policy blocked the operation.

SG and E4R clients retain their previous control behavior. Other router families and non-Wi-Fi switches retain their existing paths.

## Optional local app control

Classic Deco clients can configure `deco_tmp_username` and `deco_tmp_host_key_sha256` together. The first value is the app account's SHA1 identifier; the second is its previously verified SSH server fingerprint in OpenSSH `SHA256:` format. The existing account password is reused. The web session name `admin` is independent from the app account identity.

When both values are valid, setup configures the existing client locally without opening a new connection. Guest-band writes then use the app's local TMP-over-SSH channel. The router fingerprint is checked before one password authentication attempt. A fresh already matching state avoids a redundant command; otherwise one guest-only command is followed by bounded readback. A disconnected app channel permits read-only confirmation on the already authorized HTTP session. Neither an error nor a missing acknowledgement causes an automatic repeated write or an HTTP write fallback.

Both app fields are optional. Missing or unsupported partial configuration is rejected explicitly. Options changes preserve existing app settings; clearing both app fields disables the optional transport. No additional device or entity is created for this control path.

## Development installation

The manifest and test requirements pin the companion library, including its optional `deco-tmp` dependency group, to commit `10ffd1de61f9f36499d3ee0cfa2435aea33651db`. The two files reference the same immutable revision for reproducible installation and testing.

HACS is configured to allow repository archive downloads rather than requiring a release ZIP. Select the development revision containing this change. Installing the older default branch does not install the verified control path. Back up the existing custom integration and retain its configuration entry when replacing its files.

## Validation status

The upstream integration base is `2.48.0`, commit `7cde7769a8f7e86888793a81c3e257c24098f936`. Unit tests exercise the coordinator, switches, session serialization, error snapshots, transport selection, and entity identity.

Successful unit tests do not prove guest Wi-Fi compatibility with a real BE65. A separate guest-only hardware test is required before treating this branch as a functional firmware workaround.
