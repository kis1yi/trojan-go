package log

// RedactHash returns a redacted form of the given hash/password/secret string.
// Strings of length 8 or more are returned with the first 4 and last 4
// characters preserved, separated by an ellipsis. Anything shorter is fully
// masked. The helper is intentionally conservative so that log lines containing
// authentication material never leak useful prefix/suffix information when the
// secret is short.
func RedactHash(s string) string {
	const ellipsis = "\u2026"
	if len(s) >= 8 {
		return s[:4] + ellipsis + s[len(s)-4:]
	}
	return "***"
}
