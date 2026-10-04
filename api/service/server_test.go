package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/statistic/memory"
)

func TestServerAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = config.WithConfig(ctx, memory.Name,
		&memory.Config{
			Passwords: []string{},
		})
	port := common.PickPort("tcp", "127.0.0.1")
	ctx = config.WithConfig(ctx, Name, &Config{
		APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
		},
	})
	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go RunServerAPI(ctx, auth)
	time.Sleep(time.Second * 3)
	common.Must(auth.AddUser("hash1234"))
	_, user := auth.AuthUser("hash1234")
	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	common.Must(err)
	server := NewTrojanServerServiceClient(conn)
	stream1, err := server.ListUsers(ctx, &ListUsersRequest{})
	common.Must(err)
	for {
		resp, err := stream1.Recv()
		if err != nil {
			break
		}
		fmt.Println(resp.Status.User.Hash)
		if resp.Status.User.Hash != "hash1234" {
			t.Fail()
		}
		fmt.Println(resp.Status.SpeedCurrent)
		fmt.Println(resp.Status.SpeedLimit)
	}
	stream1.CloseSend()
	user.AddSentTraffic(1234)
	user.AddRecvTraffic(5678)
	time.Sleep(time.Second * 1)
	stream2, err := server.GetUsers(ctx)
	common.Must(err)
	stream2.Send(&GetUsersRequest{
		User: &User{
			Hash: "hash1234",
		},
	})
	resp2, err := stream2.Recv()
	common.Must(err)
	if resp2.Status.TrafficTotal.DownloadTraffic != 1234 || resp2.Status.TrafficTotal.UploadTraffic != 5678 {
		t.Fatal("wrong traffic")
	}

	stream3, err := server.SetUsers(ctx)
	common.Must(err)
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: "hash1234",
			},
		},
		Operation: SetUsersRequest_Delete,
	})
	resp3, err := stream3.Recv()
	if err != nil || !resp3.Success {
		t.Fatal("user not exists")
	}
	valid, _ := auth.AuthUser("hash1234")
	if valid {
		t.Fatal("failed to auth")
	}
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: "newhash",
			},
		},
		Operation: SetUsersRequest_Add,
	})
	resp3, err = stream3.Recv()
	if err != nil || !resp3.Success {
		t.Fatal("failed to read")
	}
	valid, user = auth.AuthUser("newhash")
	if !valid {
		t.Fatal("failed to auth 2")
	}
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: "newhash",
			},
			SpeedLimit: &Speed{
				DownloadSpeed: 5000,
				UploadSpeed:   3000,
			},
			TrafficTotal: &Traffic{
				DownloadTraffic: 1,
				UploadTraffic:   1,
			},
		},
		Operation: SetUsersRequest_Modify,
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			user.AddSentTraffic(200)
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			user.AddRecvTraffic(300)
		}
	}()
	time.Sleep(time.Second * 3)
	for i := 0; i < 3; i++ {
		stream2.Send(&GetUsersRequest{
			User: &User{
				Hash: "newhash",
			},
		})
		resp2, err = stream2.Recv()
		common.Must(err)
		fmt.Println(resp2.Status.SpeedCurrent)
		fmt.Println(resp2.Status.SpeedLimit)
		time.Sleep(time.Second)
	}
	stream2.CloseSend()
	cancel()
}

func TestTLSRSA(t *testing.T) {
	serverCertPath, serverKeyPath := newTestTLSCertificate(t, x509.RSA, x509.ExtKeyUsageServerAuth)
	clientCertPath, clientKeyPath := newTestTLSCertificate(t, x509.RSA, x509.ExtKeyUsageClientAuth)
	port := common.PickPort("tcp", "127.0.0.1")
	cfg := &Config{
		API: APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
			SSL: SSLConfig{
				Enabled:        true,
				CertPath:       serverCertPath,
				KeyPath:        serverKeyPath,
				VerifyClient:   false,
				ClientCertPath: []string{clientCertPath},
			},
		},
	}

	ctx := config.WithConfig(context.Background(), Name, cfg)
	ctx = config.WithConfig(ctx, memory.Name,
		&memory.Config{
			Passwords: []string{},
		})

	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go func() {
		common.Must(RunServerAPI(ctx, auth))
	}()
	time.Sleep(time.Second)
	pool := x509.NewCertPool()
	certBytes, err := os.ReadFile(serverCertPath)
	common.Must(err)
	pool.AppendCertsFromPEM(certBytes)

	certificate, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	common.Must(err)
	creds := credentials.NewTLS(&tls.Config{
		ServerName:   "localhost",
		RootCAs:      pool,
		Certificates: []tls.Certificate{certificate},
	})
	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(creds))
	common.Must(err)
	server := NewTrojanServerServiceClient(conn)
	stream, err := server.ListUsers(ctx, &ListUsersRequest{})
	common.Must(err)
	stream.CloseSend()
	conn.Close()
}

func TestTLSECC(t *testing.T) {
	serverCertPath, serverKeyPath := newTestTLSCertificate(t, x509.ECDSA, x509.ExtKeyUsageServerAuth)
	clientCertPath, clientKeyPath := newTestTLSCertificate(t, x509.ECDSA, x509.ExtKeyUsageClientAuth)
	port := common.PickPort("tcp", "127.0.0.1")
	cfg := &Config{
		API: APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
			SSL: SSLConfig{
				Enabled:        true,
				CertPath:       serverCertPath,
				KeyPath:        serverKeyPath,
				VerifyClient:   false,
				ClientCertPath: []string{clientCertPath},
			},
		},
	}

	ctx := config.WithConfig(context.Background(), Name, cfg)
	ctx = config.WithConfig(ctx, memory.Name,
		&memory.Config{
			Passwords: []string{},
		})

	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go func() {
		common.Must(RunServerAPI(ctx, auth))
	}()
	time.Sleep(time.Second)
	pool := x509.NewCertPool()
	certBytes, err := os.ReadFile(serverCertPath)
	common.Must(err)
	pool.AppendCertsFromPEM(certBytes)

	certificate, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	common.Must(err)
	creds := credentials.NewTLS(&tls.Config{
		ServerName:   "localhost",
		RootCAs:      pool,
		Certificates: []tls.Certificate{certificate},
	})
	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(creds))
	common.Must(err)
	server := NewTrojanServerServiceClient(conn)
	stream, err := server.ListUsers(ctx, &ListUsersRequest{})
	common.Must(err)
	stream.CloseSend()
	conn.Close()
}

// TestServerAPIQuota verifies that quota values are propagated correctly
// through the gRPC API: SetUsers (Add with quota, Modify quota), ListUsers
// (returns quota), and GetUsers (returns quota).
func TestServerAPIQuota(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = config.WithConfig(ctx, memory.Name, &memory.Config{Passwords: []string{}})
	port := common.PickPort("tcp", "127.0.0.1")
	ctx = config.WithConfig(ctx, Name, &Config{
		APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
		},
	})
	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go RunServerAPI(ctx, auth)
	time.Sleep(time.Second * 3)

	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	common.Must(err)
	defer conn.Close()
	client := NewTrojanServerServiceClient(conn)

	// Add a user with a quota value.
	setStream, err := client.SetUsers(ctx)
	common.Must(err)
	err = setStream.Send(&SetUsersRequest{
		Status: &UserStatus{
			User:  &User{Hash: "quotahash"},
			Quota: proto.Int64(5000),
		},
		Operation: SetUsersRequest_Add,
	})
	common.Must(err)
	addResp, err := setStream.Recv()
	if err != nil || !addResp.Success {
		t.Fatalf("SetUsers Add with quota failed: err=%v success=%v", err, addResp.GetSuccess())
	}

	// ListUsers should include the quota field.
	listStream, err := client.ListUsers(ctx, &ListUsersRequest{})
	common.Must(err)
	foundInList := false
	for {
		listResp, err := listStream.Recv()
		if err != nil {
			break
		}
		if listResp.Status.User.Hash == "quotahash" {
			foundInList = true
			if listResp.Status.GetQuota() != 5000 {
				t.Fatalf("ListUsers: expected quota 5000, got %d", listResp.Status.GetQuota())
			}
		}
	}
	if !foundInList {
		t.Fatal("quotahash not found in ListUsers response")
	}

	// GetUsers should also return the quota field.
	getStream, err := client.GetUsers(ctx)
	common.Must(err)
	err = getStream.Send(&GetUsersRequest{User: &User{Hash: "quotahash"}})
	common.Must(err)
	getResp, err := getStream.Recv()
	if err != nil {
		t.Fatalf("GetUsers: %v", err)
	}
	if getResp.Status.GetQuota() != 5000 {
		t.Fatalf("GetUsers: expected quota 5000, got %d", getResp.Status.GetQuota())
	}
	getStream.CloseSend()

	// Modify the quota via SetUsers.
	err = setStream.Send(&SetUsersRequest{
		Status: &UserStatus{
			User:  &User{Hash: "quotahash"},
			Quota: proto.Int64(9999),
		},
		Operation: SetUsersRequest_Modify,
	})
	common.Must(err)
	modResp, err := setStream.Recv()
	if err != nil || !modResp.Success {
		t.Fatalf("SetUsers Modify quota failed: err=%v success=%v", err, modResp.GetSuccess())
	}
	setStream.CloseSend()

	// Verify the updated quota via GetUsers.
	getStream2, err := client.GetUsers(ctx)
	common.Must(err)
	err = getStream2.Send(&GetUsersRequest{User: &User{Hash: "quotahash"}})
	common.Must(err)
	getResp2, err := getStream2.Recv()
	if err != nil {
		t.Fatalf("GetUsers after Modify: %v", err)
	}
	if getResp2.Status.GetQuota() != 9999 {
		t.Fatalf("GetUsers after Modify: expected quota 9999, got %d", getResp2.Status.GetQuota())
	}
	getStream2.CloseSend()
}

// TestServerAPIQuotaPresenceAware is the P0-3c regression test. With the
// proto3 `optional` quota field, the server MUST distinguish three cases:
//
//  1. Quota field absent on Add  → keep the User.quota default (-1).
//  2. Quota field absent on Modify → preserve the existing per-user value.
//  3. Quota field present (any value, including 0) → honour exactly.
//
// Before P0-3c, the server treated `Quota == 0` as "not set" and silently
// wiped any positive quota on every Modify call that did not echo the
// previous value. Conversely, an Add call that intended to disable
// enforcement by sending 0 was ignored.
func TestServerAPIQuotaPresenceAware(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = config.WithConfig(ctx, memory.Name, &memory.Config{Passwords: []string{}})
	port := common.PickPort("tcp", "127.0.0.1")
	ctx = config.WithConfig(ctx, Name, &Config{
		APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
		},
	})
	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go RunServerAPI(ctx, auth)
	time.Sleep(time.Second * 3)

	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	common.Must(err)
	defer conn.Close()
	client := NewTrojanServerServiceClient(conn)

	getQuota := func(hash string) int64 {
		gs, err := client.GetUsers(ctx)
		common.Must(err)
		defer gs.CloseSend()
		common.Must(gs.Send(&GetUsersRequest{User: &User{Hash: hash}}))
		resp, err := gs.Recv()
		common.Must(err)
		return resp.Status.GetQuota()
	}

	setStream, err := client.SetUsers(ctx)
	common.Must(err)
	defer setStream.CloseSend()
	send := func(hash string, op SetUsersRequest_Operation, quota *int64) {
		t.Helper()
		common.Must(setStream.Send(&SetUsersRequest{
			Status:    &UserStatus{User: &User{Hash: hash}, Quota: quota},
			Operation: op,
		}))
		resp, err := setStream.Recv()
		common.Must(err)
		if !resp.Success {
			t.Fatalf("op %v hash %s: %s", op, hash, resp.Info)
		}
	}

	// Case 1: Add without quota → default -1 preserved.
	send("noquota", SetUsersRequest_Add, nil)
	if got := getQuota("noquota"); got != -1 {
		t.Fatalf("Add without quota: User.quota = %d, want -1 (P0-3a default)", got)
	}

	// Case 3a: Add with explicit 0 → enforcement disabled (value 0 honoured).
	send("zeroquota", SetUsersRequest_Add, proto.Int64(0))
	if got := getQuota("zeroquota"); got != 0 {
		t.Fatalf("Add with quota=0: User.quota = %d, want 0", got)
	}

	// Seed a user with a positive quota, then Modify without quota → preserved.
	send("preserve", SetUsersRequest_Add, proto.Int64(7777))
	if got := getQuota("preserve"); got != 7777 {
		t.Fatalf("Add with quota=7777: got %d", got)
	}
	send("preserve", SetUsersRequest_Modify, nil)
	if got := getQuota("preserve"); got != 7777 {
		t.Fatalf("Modify without quota wiped value: got %d, want 7777", got)
	}

	// Case 3b: Modify with explicit 0 → honoured.
	send("preserve", SetUsersRequest_Modify, proto.Int64(0))
	if got := getQuota("preserve"); got != 0 {
		t.Fatalf("Modify with quota=0: got %d, want 0", got)
	}
}
