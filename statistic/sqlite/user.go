package sqlite

import (
	"encoding/binary"
)

type User struct {
	Hash string `gorm:"primary_key"`
	// uint64 = 8 byte binary
	Sent      []byte `gorm:"type:TEXT"`
	Recv      []byte `gorm:"type:TEXT"`
	MaxIPNum  int
	SendLimit int
	RecvLimit int
	Quota     int64
}

func (u *User) setSent(sent uint64) {
	binary.BigEndian.PutUint64(u.Sent, sent)
}
func (u *User) getSent() uint64 {
	return binary.BigEndian.Uint64(u.Sent)
}

func (u *User) setRecv(recv uint64) {
	binary.BigEndian.PutUint64(u.Recv, recv)
}
func (u *User) getRecv() uint64 {
	return binary.BigEndian.Uint64(u.Recv)
}

func (u *User) GetHash() string {
	return u.Hash
}

func (u *User) GetTraffic() (sent, recv uint64) {
	return u.getSent(), u.getRecv()
}

func (u *User) GetSpeedLimit() (sent, recv int) {
	return u.SendLimit, u.RecvLimit
}

func (u *User) GetIPLimit() int {
	return u.MaxIPNum
}

func (u *User) GetQuota() int64 {
	return u.Quota
}

// Done satisfies statistic.Metadata. The SQLite user record is a passive
// snapshot used only for persistence (SaveUser/LoadUser/ListUser); it has
// no live runtime to cancel, so the channel is never closed. The returned
// nil channel blocks forever in a select, which is the documented "no
// cutoff signal" behaviour.
func (u *User) Done() <-chan struct{} {
	return nil
}
