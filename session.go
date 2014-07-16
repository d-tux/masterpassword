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

// Session is an encryption session
type Session struct {
	Key  []byte
	Name string
}

// NewSession creates a new session for given username and password
func NewSession(name string, password string) *Session {
	saltBuffer := bytes.NewBuffer(nil)
	saltBuffer.WriteString(Prefix)
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

func (session *Session) NewSiteWithCounter(name string, counter int) *Site {
	hash := hmac.New(sha256.New, session.Key)
	seedBuffer := bytes.NewBuffer(nil)
	seedBuffer.WriteString(Prefix)
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
