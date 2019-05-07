package oidc

import (
	"encoding/json"
	"io"
	"os"
	"path"
	"sync"
	"syscall"
	"time"

	homedir "github.com/mitchellh/go-homedir"
	"golang.org/x/oauth2"
)

var DefaultCache CredentialCache = &FileCredentialCache{}

// CredentialCache is capable of caching and retrieving OpenID Connect tokens.
type CredentialCache interface {
	// Get returns a token from cache for the given issuer and clientID. Cache
	// misses are _not_ considered an error, so a cache miss will be returned as
	// `(nil, nil)`
	Get(issuer string, clientID string) (*oauth2.Token, error)
	// Set sets a token in the cache for the given issuer and clientID.
	Set(issuer string, clientID string, token *oauth2.Token) error
}

// FileCredentialCache implements a credential cache by storing a file in the
// user's home directory.
//
// A FileCredentialCache is goroutine-safe and may be shared.
type FileCredentialCache struct {
	sync.Mutex

	// Path is the path where the credentials will be saved. If empty, defaults
	// to $HOME/.pardot/oid-credentials.json
	Path string
}

var _ CredentialCache = &FileCredentialCache{}

func (c *FileCredentialCache) Get(issuer string, clientID string) (*oauth2.Token, error) {
	filePath, err := c.path()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(filePath)
	if err != nil && os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH)
	if err != nil {
		return nil, err
	}

	var cache fileCache
	if err := json.NewDecoder(f).Decode(&cache); err != nil && err != io.EOF {
		return nil, err
	}

	entry := cache.Get(issuer, clientID)
	if entry == nil {
		return nil, nil
	}

	if time.Now().After(entry.Token.Expiry) {
		// Expired
		return nil, nil
	}

	return entry.Token, nil
}

func (c *FileCredentialCache) Set(issuer string, clientID string, token *oauth2.Token) error {
	c.Lock()
	defer c.Unlock()

	filePath, err := c.path()
	if err != nil {
		return err
	}

	err = os.MkdirAll(path.Dir(filePath), 0700)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// Grab an exclusive lock on the file so we can read+write back to it without
	// running over any other process
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
	if err != nil {
		return err
	}

	var cache fileCache
	if err := json.NewDecoder(f).Decode(&cache); err != nil && err != io.EOF {
		return err
	}
	cache.Set(issuer, clientID, &clientIDCacheEntry{Token: token})

	// Move cursor to beginning and truncate
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}

	if err := cache.EncodeTo(f); err != nil {
		return err
	}

	return nil
}

func (c *FileCredentialCache) path() (string, error) {
	if c.Path != "" {
		return c.Path, nil
	}

	homeDir, err := homedir.Dir()
	if err != nil {
		return "", err
	}

	return path.Join(homeDir, ".pardot", "oid-credentials.json"), nil
}

// fileCache is the used for serializing and de-serializing an entire cache
// to/from a file
type fileCache struct {
	// issuers is a map of issuer URL to a cache of all the tokens cached for
	// that issuer
	Issuers map[string]*issuerCacheEntry `json:"issuers"`
}

// issuerCache is map of clientID to a token cached for that clientID
type issuerCacheEntry struct {
	ClientIDs map[string]*clientIDCacheEntry `json:"client_ids"`
}

type clientIDCacheEntry struct {
	Token *oauth2.Token `json:"token"`
}

func (fc *fileCache) Get(issuer string, clientID string) *clientIDCacheEntry {
	issuers := fc.Issuers
	if issuers == nil {
		return nil
	}

	issuerEntry := issuers[issuer]
	if issuerEntry == nil {
		return nil
	}

	clientIDs := issuerEntry.ClientIDs
	if clientIDs == nil {
		return nil
	}

	return clientIDs[clientID]
}

func (fc *fileCache) Set(issuer string, clientID string, entry *clientIDCacheEntry) {
	issuers := fc.Issuers
	if issuers == nil {
		issuers = make(map[string]*issuerCacheEntry)
		fc.Issuers = issuers
	}

	issuerEntry := issuers[issuer]
	if issuerEntry == nil {
		issuerEntry = &issuerCacheEntry{}
		issuers[issuer] = issuerEntry
	}

	clientIDs := issuerEntry.ClientIDs
	if clientIDs == nil {
		clientIDs = make(map[string]*clientIDCacheEntry)
		issuerEntry.ClientIDs = clientIDs
	}

	clientIDs[clientID] = entry
}

func (fc *fileCache) EncodeTo(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	return encoder.Encode(fc)
}
