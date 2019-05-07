package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/coreos/go-oidc"
	gooidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

// Templates
var (
	tmplError = template.Must(template.New("").Parse(`
	  <h1>Error</h1>
		<hr>
		{{.}}
	`))

	tmplTokenIssued = template.Must(template.New("").Parse(`
	  <h1>Success</h1>
		<hr>
		Return to the terminal to continue.
	`))
)

// TokenSource is our take on oauth2.TokenSource, but context-aware. It's a
// pity we can't use oauth2.TokenSource directly, but we really need the
// context passed down so we can timeout our interactive token fetching flow
// easily.
type TokenSource interface {
	// Token returns a token or an error
	// The returned Token must not be modified
	Token(ctx context.Context) (*oauth2.Token, error)
}

type TokenFetcher struct {
	provider     *oidc.Provider
	clientID     string
	clientSecret string

	// ApprovalForce forces the user to view the consent dialog and confirm the
	// permissions request, even if they have already done so.
	ApprovalForce bool

	// Opener is used to open URLs. By default, the best system opener we can
	// detect is used.
	Opener

	// Groups indicates if we should request the "group" scope to return
	// information about the groups the requestor is a member of
	Groups bool

	// Cache is used to lookup and store tokens in a cache. If a non-expired
	// token is present in the cache, it is returned without reaching out to the
	// OIDC provider. By default, DefaultCache is used. Set to nil to disable
	// caching.
	CredentialCache
}

var _ TokenSource = (*TokenFetcher)(nil)

// NewTokenFetcher creates a token fetcher that command line (CLI) programs can
// use to fetch tokens from Runtime ID (dex) for use in authenticating clients
// to other systems (e.g., Kubernetes clusters, Docker registries, etc.)
//
// Example:
//     ctx := context.TODO()
//
//     provider, err := gooidc.NewProvider(ctx, StagingURL)
//     if err != nil {
//       // handle err
//     }
//     tf := NewTokenFetcher(provider, clientID, clientSecret)
//
//     token, err := tf.Token(ctx)
//     if err != nil {
//       // handle error
//     }
//
//     // use token
func NewTokenFetcher(provider *gooidc.Provider, clientID string, clientSecret string) *TokenFetcher {
	return &TokenFetcher{
		provider:     provider,
		clientID:     clientID,
		clientSecret: clientSecret,

		Opener:          DetectOpener(),
		CredentialCache: DefaultCache,
	}
}

// Token attempts to a fetch a token. The user will be required to open a URL
// in their browser and authenticate to the upstream IdP.
func (f *TokenFetcher) Token(ctx context.Context) (*oauth2.Token, error) {
	cache := f.CredentialCache
	if cache != nil {
		if token, _ := cache.Get(f.provider.Endpoint().AuthURL, f.clientID); token != nil {
			return token, nil
		}
	}

	state, err := randomStateValue()
	if err != nil {
		return nil, err
	}

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)

	mux := http.NewServeMux()

	var calls int32
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if errMsg := r.FormValue("error"); errMsg != "" {
			err := fmt.Errorf("%s: %s", errMsg, r.FormValue("error_description"))
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = tmplError.Execute(w, err.Error())
			return
		}

		code := r.FormValue("code")
		if code == "" {
			err := xerrors.New("no code in request")
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = tmplError.Execute(w, err.Error())
			return
		}

		gotState := r.FormValue("state")
		if gotState == "" || gotState != state {
			err := xerrors.New("bad state")
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = tmplError.Execute(w, err.Error())
			return
		}

		if atomic.AddInt32(&calls, 1) > 1 {
			// Callback has been invoked multiple times, which should not happen.
			// Bomb out to avoid a blocking channel write and to float this as a bug.
			w.WriteHeader(http.StatusBadRequest)
			_ = tmplError.Execute(w, "callback invoked multiple times")
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = tmplTokenIssued.Execute(w, nil)

		resultCh <- result{code: code}
	})
	httpSrv := &http.Server{
		Addr:    "127.0.0.1:0", // let OS choose an open port for us
		Handler: mux,
	}

	ln, err := net.Listen("tcp", httpSrv.Addr)
	if err != nil {
		return nil, xerrors.Errorf("failed to bind socket: %w", err)
	}
	defer func() { _ = ln.Close() }()
	tcpAddr := ln.Addr().(*net.TCPAddr)

	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Shutdown(ctx) }()

	sc := []string{"openid", "profile", "email", "offline_access", "federated:id"}
	if f.Groups {
		sc = append(sc, "groups")
	}

	oauth2Config := &oauth2.Config{
		ClientID:     f.clientID,
		ClientSecret: f.clientSecret,
		Endpoint:     f.provider.Endpoint(),
		Scopes:       sc,
		RedirectURL:  fmt.Sprintf("http://localhost:%d/callback", tcpAddr.Port),
	}

	authCodeOptions := []oauth2.AuthCodeOption{}
	if f.ApprovalForce {
		authCodeOptions = append(authCodeOptions, oauth2.ApprovalForce)
	}

	if err := f.Opener.Open(ctx, oauth2Config.AuthCodeURL(state, authCodeOptions...)); err != nil {
		return nil, xerrors.Errorf("failed to open URL: %w", err)
	}

	var res result
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res = <-resultCh:
		// continue
	}

	if res.err != nil {
		return nil, res.err
	}

	oAuth2Token, err := oauth2Config.Exchange(ctx, res.code)
	if err != nil {
		return nil, err
	}

	rawIDToken, ok := oAuth2Token.Extra("id_token").(string)
	if !ok {
		return nil, xerrors.New("no id_token in token response")
	}

	verifier := f.provider.Verifier(&oidc.Config{ClientID: f.clientID})
	_, err = verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	// Re-create token with the id_token as the access_token. This is a little
	// weird, but because we use the JWT as our Bearer token, it makes sense. An
	// *oauth2.Token is accepted in more places than a custom type we create.
	token := &oauth2.Token{
		AccessToken:  rawIDToken,
		TokenType:    "Bearer",
		RefreshToken: oAuth2Token.RefreshToken,
		Expiry:       oAuth2Token.Expiry,
	}

	if cache != nil {
		_ = cache.Set(f.provider.Endpoint().AuthURL, f.clientID, token)
	}

	return token, nil
}

func randomStateValue() (string, error) {
	const numBytes = 16

	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawStdEncoding.EncodeToString(b), nil
}
