package ed25519

import (
	"crypto/ed25519"

	"github.com/ChainSafe/chainbridge-utils/crypto"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/icpfans-xyz/agent-go/agent"
	"github.com/icpfans-xyz/agent-go/identity"
)

var _ crypto.Keypair = &Keypair{}

const PrivateKeyLength = 32

type Keypair struct {
	private ed25519.PrivateKey
}

func GenerateKeypair() (*Keypair, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return NewKeypair(priv), nil
}

func NewKeypairFromPrivateKey(priv []byte) (*Keypair, error) {
	pk := ed25519.NewKeyFromSeed(priv)
	return &Keypair{
		private: pk,
	}, nil
}

func NewKeypair(pk ed25519.PrivateKey) *Keypair {
	return &Keypair{
		private: pk,
	}
}

// Encode dumps the private key as bytes
func (kp *Keypair) Encode() []byte {
	return kp.private.Seed()
}

// Decode initializes the keypair using the input
func (kp *Keypair) Decode(in []byte) error {
	key := ed25519.NewKeyFromSeed(in)
	kp.private = key
	return nil
}

// Address returns the Ethereum address format
func (kp *Keypair) Address() string {
	identify := identity.NewEd25519Identity(kp.Encode())
	signIdentify := agent.NewSignIdentity(identify, nil)
	return signIdentify.GetPrincipal().ToString()
}

// PublicKey returns the public key hex encoded
func (kp *Keypair) PublicKey() string {
	pub := kp.private.Public()
	return hexutil.Encode(pub.(ed25519.PublicKey))
}

// PrivateKey returns the keypair's private key
func (kp *Keypair) PrivateKey() ed25519.PrivateKey {
	return kp.private
}
