// Package deploy coordinates durable local deployments independently of ACME
// and DNS. Platform-specific plans live in adapter subpackages.
package deploy

import (
	"encoding/pem"
	"fmt"

	"github.com/kernaxis/xcertm/internal/domain"
	"github.com/kernaxis/xcertm/internal/state"
)

type Material struct {
	Certificate, Chain, Fullchain, PrivateKey []byte
	Fingerprint                               string
}

func Render(g domain.Generation) (Material, error) {
	if g.ID() == "" || g.CertificateID() == "" {
		return Material{}, fmt.Errorf("generation is uninitialized")
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.CertificateDER()})
	var chain []byte
	for _, der := range g.ChainDER() {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: g.PrivateKeyPKCS8()})
	full := append(append([]byte(nil), cert...), chain...)
	return Material{cert, chain, full, key, state.Digest([]byte(state.Digest(cert) + state.Digest(chain) + state.Digest(key)))}, nil
}
