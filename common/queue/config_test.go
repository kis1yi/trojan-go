package queue

import "testing"

func TestResolveAcceptQueueSizeDefault(t *testing.T) {
	c := QueueConfig{}
	if got := c.ResolveAcceptQueueSize(); got != DefaultAcceptQueueSize {
		t.Fatalf("default queue size: got %d, want %d", got, DefaultAcceptQueueSize)
	}
}

func TestResolveAcceptQueueSizeOverride(t *testing.T) {
	c := QueueConfig{AcceptQueueSize: 8}
	if got := c.ResolveAcceptQueueSize(); got != 8 {
		t.Fatalf("override queue size: got %d, want 8", got)
	}
}

func TestResolveAcceptQueueSizeDisabledClampsToOne(t *testing.T) {
	c := QueueConfig{AcceptQueueSize: -1}
	if got := c.ResolveAcceptQueueSize(); got != 1 {
		t.Fatalf("-1 queue size: got %d, want 1", got)
	}
}

func TestResolveMaxConnPerUserDefault(t *testing.T) {
	c := QueueConfig{}
	if got := c.ResolveMaxConnPerUser(); got != 0 {
		t.Fatalf("default max conn per user: got %d, want 0 (unlimited)", got)
	}
}

func TestResolveMaxConnPerUserNegativeIsUnlimited(t *testing.T) {
	c := QueueConfig{MaxConnPerUser: -5}
	if got := c.ResolveMaxConnPerUser(); got != 0 {
		t.Fatalf("negative max conn per user: got %d, want 0 (unlimited)", got)
	}
}

func TestResolveMaxConnPerUserPositive(t *testing.T) {
	c := QueueConfig{MaxConnPerUser: 12}
	if got := c.ResolveMaxConnPerUser(); got != 12 {
		t.Fatalf("positive max conn per user: got %d, want 12", got)
	}
}
