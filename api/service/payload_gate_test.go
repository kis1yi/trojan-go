package service

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/recorder"
	"github.com/kis1yi/trojan-go/statistic/memory"
)

// TestServerAPIPayloadCaptureGate verifies the P0-4 gate on
// `GetRecords.IncludePayload`. The gate has three outcomes which depend on
// both the build tag (`payloadCaptureCompiled`, set at compile time via the
// `apidebug` tag) and the `api.allow_payload_capture` config flag:
//
//  1. Default build (`!payloadCaptureCompiled`): IncludePayload=true MUST be
//     silently downgraded to metadata-only streaming. The stream stays open
//     and yields records whose Payload is nil.
//  2. apidebug build, allow_payload_capture=false: IncludePayload=true MUST
//     be rejected with `codes.PermissionDenied`.
//  3. apidebug build, allow_payload_capture=true: payloads stream through
//     unchanged.
//
// We can only directly assert the outcome that matches the current build. We
// also assert outcome (1) is reachable on every build (when the operator
// explicitly leaves IncludePayload=false, payloads must always be nil) so
// the test catches accidental leaks of payload bytes regardless of tag.
func TestServerAPIPayloadCaptureGate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = config.WithConfig(ctx, memory.Name, &memory.Config{Passwords: []string{}})
	port := common.PickPort("tcp", "127.0.0.1")
	ctx = config.WithConfig(ctx, Name, &Config{
		APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
			// Opt the operator into payload capture; the build tag still
			// has to be set for it to take effect.
			AllowPayloadCapture: true,
		},
	})
	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go RunServerAPI(ctx, auth)
	time.Sleep(time.Second * 2)

	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	common.Must(err)
	defer conn.Close()
	client := NewTrojanServerServiceClient(conn)

	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()
	stream, err := client.GetRecords(streamCtx, &GetRecordsRequest{IncludePayload: true})
	common.Must(err)

	// Poke the recorder so the subscriber receives one event. We retry a few
	// times because Subscribe runs on the server goroutine and may race the
	// first publish.
	clientAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
	targetAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80}
	publish := func() {
		recorder.Add("hash", clientAddr, targetAddr, "tcp", []byte("secret-payload"))
	}

	switch {
	case !payloadCaptureCompiled:
		// Default build: server must downgrade. Stream must yield a record
		// with no payload.
		go func() {
			for i := 0; i < 5; i++ {
				publish()
				time.Sleep(100 * time.Millisecond)
			}
		}()
		recv := make(chan *GetRecordsResponse, 1)
		go func() {
			r, _ := stream.Recv()
			recv <- r
		}()
		select {
		case r := <-recv:
			if r == nil {
				t.Fatal("expected a record on default build, got nil")
			}
			if len(r.Payload) != 0 {
				t.Fatalf("default build leaked payload bytes (%d): %q", len(r.Payload), r.Payload)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for downgraded record on default build")
		}
	case payloadCaptureCompiled && true:
		// apidebug build, allow_payload_capture=true: payload should stream
		// through. We set the flag above. Verify the stream yields the raw
		// payload.
		go func() {
			for i := 0; i < 5; i++ {
				publish()
				time.Sleep(100 * time.Millisecond)
			}
		}()
		recv := make(chan *GetRecordsResponse, 1)
		go func() {
			r, _ := stream.Recv()
			recv <- r
		}()
		select {
		case r := <-recv:
			if r == nil {
				t.Fatal("expected a record on apidebug build, got nil")
			}
			if string(r.Payload) != "secret-payload" {
				t.Fatalf("apidebug build did not pass through payload, got %q", r.Payload)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for payload-bearing record on apidebug build")
		}
	}
}

// TestServerAPIPayloadCaptureDeniedWithoutFlag exercises the
// `PermissionDenied` branch which only triggers on apidebug builds. On
// default builds we still validate the simpler invariant: even with
// allow_payload_capture=false, a request that does not ask for payload must
// succeed (no spurious denials for metadata-only callers).
func TestServerAPIPayloadCaptureDeniedWithoutFlag(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = config.WithConfig(ctx, memory.Name, &memory.Config{Passwords: []string{}})
	port := common.PickPort("tcp", "127.0.0.1")
	ctx = config.WithConfig(ctx, Name, &Config{
		APIConfig{
			Enabled:             true,
			APIHost:             "127.0.0.1",
			APIPort:             port,
			AllowPayloadCapture: false, // operator did NOT opt in
		},
	})
	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go RunServerAPI(ctx, auth)
	time.Sleep(time.Second * 2)

	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	common.Must(err)
	defer conn.Close()
	client := NewTrojanServerServiceClient(conn)

	// Always-valid case: metadata-only request must be accepted on every
	// build configuration.
	{
		streamCtx, streamCancel := context.WithCancel(ctx)
		stream, err := client.GetRecords(streamCtx, &GetRecordsRequest{IncludePayload: false})
		common.Must(err)
		clientAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
		targetAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80}
		go func() {
			for i := 0; i < 5; i++ {
				recorder.Add("hash", clientAddr, targetAddr, "tcp", []byte("ignored"))
				time.Sleep(100 * time.Millisecond)
			}
		}()
		recv := make(chan *GetRecordsResponse, 1)
		go func() {
			r, _ := stream.Recv()
			recv <- r
		}()
		select {
		case r := <-recv:
			if r == nil {
				t.Fatal("metadata-only stream returned nil record")
			}
			if len(r.Payload) != 0 {
				t.Fatalf("metadata-only stream leaked payload bytes: %q", r.Payload)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for metadata-only record")
		}
		streamCancel()
	}

	// PermissionDenied case is only reachable on apidebug builds.
	if !payloadCaptureCompiled {
		t.Skip("payload capture not compiled in; PermissionDenied path requires the `apidebug` build tag")
	}
	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()
	stream, err := client.GetRecords(streamCtx, &GetRecordsRequest{IncludePayload: true})
	common.Must(err)
	_, err = stream.Recv()
	if err == nil {
		t.Fatal("expected PermissionDenied, got nil error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %s: %s", st.Code(), st.Message())
	}
}
