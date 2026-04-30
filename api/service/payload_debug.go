//go:build apidebug

package service

// payloadCaptureCompiled is true when the binary is built with the
// `apidebug` build tag. Even then, raw payload streaming through
// `GetRecords` still requires the `api.allow_payload_capture` config flag.
// See P0-4 in docs/WORKPLAN-2026-security-hardening.md.
const payloadCaptureCompiled = true
