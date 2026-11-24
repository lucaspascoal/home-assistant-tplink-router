# Verified Deco Wi-Fi control

This development branch consumes the companion library's verified Deco Wi-Fi API. Existing `tplink_router` configuration entries, device identities, switch keys, and automation references remain in place.

For classic Deco clients, the coordinator serializes the session, requests one write, and applies only values returned by subsequent Wi-Fi reads. The switch displays those observed values. Router rejection and unavailable verification remain visible as errors, without asserting that firmware policy blocked the operation.

SG and E4R clients retain their previous control behavior. Other router families and non-Wi-Fi switches retain their existing paths.

## Development installation

The manifest and test requirements pin the companion library to commit `353e1b3d7d81a3ed880d1e604a6f2fbae2c28ae8`. The two files reference the same immutable revision for reproducible installation and testing.

HACS is configured to allow repository archive downloads rather than requiring a release ZIP. Select the development revision containing this change. Installing the older default branch does not install the verified control path. Back up the existing custom integration and retain its configuration entry when replacing its files.

## Validation status

The upstream integration base is `2.48.0`, commit `7cde7769a8f7e86888793a81c3e257c24098f936`. Unit tests exercise the coordinator, switches, session serialization, error snapshots, transport selection, and entity identity.

Successful unit tests do not prove guest Wi-Fi compatibility with a real BE65. A separate guest-only hardware test is required before treating this branch as a functional firmware workaround.
