package ecc

import (
    "crypto/elliptic"
    "sync"
)

type Curve struct {
    Id uint8
    Name string
    Aliases []string
    Description string
    Curve func() elliptic.Curve
}

var Curves = []*Curve {
    {
	Id: 1,
	Name: "P-224",
	Aliases: []string{"secp224r1"},
	Description: "P-224 (FIPS 186-3, section D.2.2)",
	Curve: elliptic.P224,
    },
    {
	Id: 2,
	Name: "P-256",
	Aliases: []string{"secp256r1", "prime256v1"},
	Description: "NIST P-256 (FIPS 186-3, section D.2.3)",
	Curve: elliptic.P256,
    },
    {
	Id: 3,
	Name: "P-384",
	Aliases: []string{"secp384r1"},
	Description: "NIST P-384 (FIPS 186-3, section D.2.4)",
	Curve: elliptic.P384,
    },
    {
	Id: 4,
	Name: "P-521",
	Aliases: []string{"secp521r1"},
	Description: "NIST P-521 (FIPS 186-3, section D.2.5)",
	Curve: elliptic.P521,
    },
}

var curvesIndexMutex sync.Mutex
var curvesIndex map[string]*Curve

// LookupCurve finds Curve by specified name.
func LookupCurve(name string) *Curve {
    curvesIndexMutex.Lock()
    if curvesIndex == nil {
	curvesIndex = make(map[string]*Curve)
	for _, curve := range Curves {
	    curvesIndex[curve.Name] = curve
	    for _, alias := range curve.Aliases {
		curvesIndex[alias] = curve
	    }
	}
    }
    curvesIndexMutex.Unlock()
    if curve, ok := curvesIndex[name]; ok {
	return curve
    }
    return nil
}

func IdentifyCurve(c elliptic.Curve) *Curve {
    curveName := c.Params().Name
    for _, curve := range Curves {
	if curve.Name == curveName {
	    return curve
	}
    }
    return nil
}
