package dh_go

import (
	"crypto/rand"
	"log"
	"math/big"
)

type DH struct {
	G         *big.Int
	P         *big.Int
	Secret    *big.Int
	Public    *big.Int
	Sh_secret *big.Int
}

func (dh *DH) GenSecret() {
	rand_bytes := [32]byte{}
	_, err := rand.Read(rand_bytes[:])

	if err != nil {
		log.Fatal(err)
		return
	}

	dh.Secret = new(big.Int).SetBytes(rand_bytes[:])
}

func (dh *DH) CalcPublic() {
	// func (DH)
	r := big.NewInt(0)
	r.Exp(dh.G, dh.Secret, dh.P)
	dh.Public = r
}

func (dh *DH) CalcSahredSecret(peer_public string) {
	peer_public_n, _ := new(big.Int).SetString(peer_public, 10)
	r := big.NewInt(0)

	// if err != nil {
	// 	log.Fatal(err)
	// }

	r.Exp(peer_public_n, dh.Secret, dh.P)

	dh.Sh_secret = r
}

func New(g string, p string) *DH {
	g_val, _ := new(big.Int).SetString(g, 10)
	p_val, _ := new(big.Int).SetString(p, 10)

	dh := new(DH)
	dh.G = g_val
	dh.P = p_val
	dh.Secret = nil
	dh.Public = nil
	dh.Sh_secret = nil

	return dh
}

// login
