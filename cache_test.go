package oidc

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestFileCredentialCache(t *testing.T) {
	cases := []struct {
		// Description is a human-readable description of the test scenario
		Description string

		// Test is a function that, given a FileCredentialCache, runs a scenario
		// and returns a (*oauth2.Token, error) tuple. The test passes if the token is
		// equal to the ExpectedToken.
		Test          func(cache *FileCredentialCache) (*oauth2.Token, error)
		ExpectedToken *oauth2.Token
	}{
		{
			Description: "Cache miss",
			Test: func(cache *FileCredentialCache) (*oauth2.Token, error) {
				return cache.Get("https://issuer.example", "clientID")
			},
			ExpectedToken: nil,
		},
		{
			Description: "Cache hit",
			Test: func(cache *FileCredentialCache) (*oauth2.Token, error) {
				err := cache.Set("https://issuer.example", "clientID", &oauth2.Token{AccessToken: "hello world", Expiry: time.Now().Add(1 * time.Hour)})
				if err != nil {
					return nil, err
				}

				return cache.Get("https://issuer.example", "clientID")
			},
			ExpectedToken: &oauth2.Token{AccessToken: "hello world"},
		},
		{
			Description: "Miss for a different client ID",
			Test: func(cache *FileCredentialCache) (*oauth2.Token, error) {
				err := cache.Set("https://issuer.example", "clientID", &oauth2.Token{AccessToken: "hello world", Expiry: time.Now().Add(1 * time.Hour)})
				if err != nil {
					return nil, err
				}

				return cache.Get("https://issuer.example", "otherClientID")
			},
			ExpectedToken: nil,
		},
		{
			Description: "Expired token causes a miss",
			Test: func(cache *FileCredentialCache) (*oauth2.Token, error) {
				err := cache.Set("https://issuer.example", "clientID", &oauth2.Token{AccessToken: "hello world", Expiry: time.Now().Add(-1 * time.Hour)})
				if err != nil {
					return nil, err
				}

				return cache.Get("https://issuer.example", "clientID")
			},
			ExpectedToken: nil,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()

			f, err := ioutil.TempFile("", "cache")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(f.Name())

			cache := &FileCredentialCache{Path: f.Name()}
			token, err := tc.Test(cache)
			if err != nil {
				t.Fatal(err)
			}

			if tc.ExpectedToken == nil || token == nil {
				if tc.ExpectedToken != token {
					t.Errorf("token: got %v, expected %v", token, tc.ExpectedToken)
				}
			} else if tc.ExpectedToken.AccessToken != token.AccessToken {
				t.Errorf("token: got %v, expected %v", token, tc.ExpectedToken)
			}
		})
	}
}
