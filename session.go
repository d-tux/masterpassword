package masterpassword

import (
	"bytes"
	"code.google.com/p/go.crypto/scrypt"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

const n int = 32768
const r int = 8
const p int = 2
const dkLen int = 64

// Session is an encryption session and holds the master key, as well as the user name.
// Note that the password is not stored.
type Session struct {
	Key  []byte
	Name string
}

// NewSession creates a new session for given username and password.
// This involves deriving the master key, which can be a little time consuming.
func NewSession(name string, password string) *Session {
	saltBuffer := bytes.NewBuffer(nil)
	saltBuffer.WriteString(prefix)
	binary.Write(saltBuffer, binary.BigEndian, uint32(len(name)))
	saltBuffer.WriteString(name)

	key, err := scrypt.Key([]byte(password), saltBuffer.Bytes(), n, r, p, dkLen)
	if nil != err {
		panic(err)
	}

	return &Session{
		Key:  key,
		Name: name,
	}
}

// NewSite initializes a new site in this session, with a counter value of 1
func (session *Session) NewSite(name string) *Site {
	return session.NewSiteWithCounter(name, 1)
}

// NewSiteWithCounter initializes a new site in this session, with a custom counter value.
func (session *Session) NewSiteWithCounter(name string, counter int) *Site {
	hash := hmac.New(sha256.New, session.Key)
	seedBuffer := bytes.NewBuffer(nil)
	seedBuffer.WriteString(prefix)
	binary.Write(seedBuffer, binary.BigEndian, uint32(len(name)))
	seedBuffer.WriteString(name)
	binary.Write(seedBuffer, binary.BigEndian, uint32(counter))
	hash.Write(seedBuffer.Bytes())
	return &Site{
		Seed:    hash.Sum(nil),
		Session: session,
		Name:    name,
		Counter: counter,
	}
}
