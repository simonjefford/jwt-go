package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

const (
	HeaderKid = "kid"
)

var (
	ErrMissingKid = errors.New("No kid found")
	ErrMissingKey = errors.New("No key found")
)

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

type WebKeySet []WebKey

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

func (wks WebKey) retrieveKey() (interface{}, error) {
	return nil, nil
}

func (wks WebKeySet) KeyFunc(t *Token) (interface{}, error) {
	kid := t.Kid()

	if kid == "" {
		return nil, ErrMissingKid
	}

	for _, wk := range wks {
		if wk.Kid == kid {
			return wk.retrieveKey()
		}
	}

	return nil, ErrMissingKey
}
