package onionbalance

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"strings"
)

type TorNode struct {
	microdescriptor MicroDescriptor
	routerstatus    *RouterStatus
}

func NewNode(microdescriptor MicroDescriptor, routerstatus *RouterStatus) *TorNode {
	logrus.Debugf("Initializing node with fpr %s", routerstatus.Fingerprint)

	n := &TorNode{}
	n.microdescriptor = microdescriptor
	n.routerstatus = routerstatus
	return n
}

func (n *TorNode) GetHexFingerprint() Fingerprint {
	return n.routerstatus.Fingerprint
}

var ErrNoHSDir = errors.New("NoHSDir")
var ErrNoEd25519Identity = errors.New("NoEd25519Identity")

// GetHsdirIndex get the HSDir index for this node:
//
//    hsdir_index(node) = H("node-idx" | node_identity |
//                          shared_random_value |
//                          INT_8(period_num) |
//                          INT_8(period_length) )
//
// Raises NoHSDir or NoEd25519Identity in case of errors.
func (n *TorNode) GetHsdirIndex(srv []byte, period_num int64, consensus *Consensus) ([]byte, error) {
	// See if this node can be an HSDir (it needs to be supported both in
	// protover and in flags)
	//arr, found := n.routerstatus.Protocols["HSDir"]
	//if !found {
	//	panic("NoHSDir")
	//}
	//found = false
	//for _, el := range arr {
	//	if 2 == el {
	//		found = true
	//		break
	//	}
	//}
	//if !found {
	//	panic("NoHSDir")
	//}
	if !n.routerstatus.Flags.HSDir {
		return nil, ErrNoHSDir
	}

	// See if ed25519 identity is supported for this node
	if _, found := n.microdescriptor.Identifiers["ed25519"]; !found {
		return nil, ErrNoEd25519Identity
	}

	// In stem the ed25519 identity is a base64 string and we need to add
	// the missing padding so that the python base64 module can successfully
	// decode it.
	// TODO: Abstract this into its own function...
	ed25519NodeIdentityB64 := n.microdescriptor.Identifiers["ed25519"]
	missingPadding := len(ed25519NodeIdentityB64) % 4
	ed25519NodeIdentityB64 += strings.Repeat("=", missingPadding)
	ed25519NodeIdentity, _ := base64.StdEncoding.DecodeString(ed25519NodeIdentityB64)

	periodNumInt8 := make([]byte, 8)
	binary.BigEndian.PutUint64(periodNumInt8[len(periodNumInt8)-8:], uint64(period_num))
	periodLength := consensus.Consensus().GetTimePeriodLength()
	periodLengthInt8 := make([]byte, 8)
	binary.BigEndian.PutUint64(periodLengthInt8[len(periodLengthInt8)-8:], uint64(periodLength))

	hashBody := "node-idx" + string(ed25519NodeIdentity) + string(srv) + string(periodNumInt8) + string(periodLengthInt8)
	hsdirIndex := sha3.Sum256([]byte(hashBody))

	return hsdirIndex[:], nil
}
