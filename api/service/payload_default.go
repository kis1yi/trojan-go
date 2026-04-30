//go:build !apidebug

package service

// payloadCaptureCompiled reports whether this binary was built with the
// `apidebug` build tag. Without that tag, the gRPC API never streams raw
// payload bytes through `GetRecords` regardless of the request flag or the
// `api.allow_payload_capture` config option. See P0-4 in
// docs/WORKPLAN-2026-security-hardening.md.
const payloadCaptureCompiled = false
