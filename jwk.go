package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
)

const (
	HeaderKid                                 = "kid"
	JWKStrategyModulusAndExponent JWKStrategy = iota
	JWKStrategyCertificateURL
	JWKStrategyCertificatePEM
	JWKStrategyUnknown
)

type JWKStrategy int

var (
	ErrMissingKid    = errors.New("No kid found")
	ErrMissingKey    = errors.New("No key found")
	ErrNoKeyStrategy = errors.New("Could not determine a strategy for retreiving a key")
)

type WebKey struct {
	Kty     string `json:"kty"`
	Use     string `json:"use"`
	KeyOps  string `json:"key-ops"`
	Alg     string `json:"alg"`
	Kid     string `json:"kid"`
	X5U     string `json:"x5u"`
	X5C     string `json:"x5c"`
	X5T     string `json:"x5t"`
	X5TS256 string `json:"x5t#S256"`
	N       string `json:"n"`
	E       string `json:"e"`
}

func (wks WebKey) keyRetrievalStrategy() JWKStrategy {
	switch {
	case wks.E != "" && wks.N != "":
		return JWKStrategyModulusAndExponent
	case wks.X5C != "":
		return JWKStrategyCertificatePEM
	case wks.X5U != "":
		return JWKStrategyCertificateURL
	default:
		return JWKStrategyUnknown
	}
}

type strategyTable map[JWKStrategy]func(WebKey) (interface{}, error)

var strategies = strategyTable{
	JWKStrategyModulusAndExponent: func(w WebKey) (interface{}, error) {
		modBytes, err := DecodeSegment(w.N)
		if err != nil {
			return nil, err
		}

		expBytes, err := DecodeSegment(w.E)
		if err != nil {
			return nil, err
		}

		modInt := new(big.Int)
		modInt.SetBytes(modBytes)

		expInt := new(big.Int)
		expInt.SetBytes(expBytes)

		rsaKey := new(rsa.PublicKey)
		rsaKey.N = modInt
		rsaKey.E = int(expInt.Int64())
		return rsaKey, nil
	},
	JWKStrategyCertificatePEM: func(w WebKey) (interface{}, error) {
		key, err := DecodeSegment(w.X5C)
		if err != nil {
			return nil, err
		}
		return key, nil
	},
	JWKStrategyCertificateURL: func(w WebKey) (interface{}, error) {
		res, err := http.Get(w.X5U)
		if err != nil {
			return nil, err
		}
		key, err := ioutil.ReadAll(res.Body())
		if err != nil {
			return nil, err
		}
		return key, nil
	},
}

func (wks WebKey) Key() (interface{}, error) {
	strategy := wks.keyRetrievalStrategy()
	if strategy == JWKStrategyUnknown {
		return nil, ErrNoKeyStrategy
	}

	return strategies[strategy](wks)
}

type WebKeySet []WebKey

type webKeyHTTPError struct {
	url     string
	message string
}

func (m webKeyHTTPError) Error() string {
	msg := fmt.Sprintf("Failed to fetch a JSON Web Key Set from %s.", m.url)
	if m.message != "" {
		msg += fmt.Sprintf(" The server returned a message of \"%s\".", m.message)
	}
	return msg
}

func GetWebKeySetFromURL(url string) (WebKeySet, error) {
	res, err := http.Get(url)

	defer func() {
		if res != nil && res.Body != nil {
			res.Body.Close()
		}
	}()

	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		webError := &webKeyHTTPError{
			url: url,
		}
		serverMsg, _ := ioutil.ReadAll(res.Body)
		if serverMsg != nil && len(serverMsg) > 0 {
			webError.message = string(serverMsg)
		}
		return nil, webError
	}

	return GetWebKeySetFromReader(res.Body)
}

func GetWebKeySetFromReader(reader io.Reader) (WebKeySet, error) {
	dec := json.NewDecoder(reader)
	out := struct {
		Keys WebKeySet `json:"keys"`
	}{}

	err := dec.Decode(&out)

	if err != nil {
		return nil, err
	}

	return out.Keys, nil
}

func (wks WebKeySet) KeyFunc(t *Token) (interface{}, error) {
	kid := t.Kid()

	if kid == "" {
		return nil, ErrMissingKid
	}

	for _, wk := range wks {
		if wk.Kid == kid {
			return wk.Key()
		}
	}

	return nil, ErrMissingKey
}
