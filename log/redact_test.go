package log

import "testing"

func TestRedactHash(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "***"},
		{"abc", "***"},
		{"abcdefg", "***"},
		{"abcdefgh", "abcd\u2026efgh"},
		{"abcd1234wxyz", "abcd\u2026wxyz"},
	}
	for _, c := range cases {
		if got := RedactHash(c.in); got != c.want {
			t.Errorf("RedactHash(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
