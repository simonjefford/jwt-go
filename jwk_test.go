package jwt

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func Test_FromReader(t *testing.T) {
	f, err := os.Open("test/sample_jwks.json")
	defer f.Close()

	wks, err := GetWebKeySetFromReader(f)
	if err != nil {
		t.Fatal(err)
	}

	verifyWKS(t, wks)
}

func verifyWKS(t *testing.T, wks WebKeySet) {
	keyCount := len(wks)
	if keyCount != 2 {
		t.Fatal("Unexpected number of web keys read:", keyCount)
	}
}

func testHandler(fileName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		f, err := os.Open(fileName)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, err)
			return
		}

		defer f.Close()

		io.Copy(w, f)
	})
}

func testFailingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Failed to get JWK")
	})
}

func Test_FromURL(t *testing.T) {
	ts := httptest.NewServer(testHandler("test/sample_jwks.json"))

	defer ts.Close()

	wks, err := GetWebKeySetFromURL(ts.URL)

	if err != nil {
		t.Fatal(err)
	}

	verifyWKS(t, wks)
}

func Test_FromURLFail(t *testing.T) {
	ts := httptest.NewServer(testFailingHandler())
	defer ts.Close()

	_, err := GetWebKeySetFromURL(ts.URL)

	t.Log(err)
}
