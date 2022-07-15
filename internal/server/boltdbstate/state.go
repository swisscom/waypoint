// Package state manages the state that the singleprocess server has, providing
// operations to mutate that state safely as needed.
package boltdbstate

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"reflect"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-memdb"
	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"

	pb "github.com/hashicorp/waypoint/pkg/server/gen"
	"github.com/hashicorp/waypoint/pkg/serverstate"
)

// It is very important we implement both of these.
var (
	_ serverstate.Interface = (*State)(nil)
	_ serverstate.Pruner    = (*State)(nil)
)

// The global variables below can be set by init() functions of other
// files in this package to setup the database state for the server.
var (
	// schemas is used to register schemas with the state store. Other files should
	// use the init() callback to append to this.
	schemas []schemaFn

	// dbBuckets is the list of buckets that should be created by dbInit.
	// Various components should use init() funcs to append to this.
	dbBuckets [][]byte

	// dbIndexers is the list of functions to call to initialize the
	// in-memory indexes from the persisted db. These can also be used to
	// upgrade data if there are upgrades necessary.
	dbIndexers []indexFn

	// pruneFns is the list of prune functions to call for appOperation types
	// when performing state prune.
	pruneFns []func(memTxn *memdb.Txn) (string, int, error)
)

// State is the primary API for state mutation for the server.
type State struct {
	// inmem is our in-memory database that stores ephemeral data in an
	// easier-to-query way. Some of this data may be periodically persisted
	// but most of this data is meant to be lost when the process restarts.
	inmem *memdb.MemDB

	// db is our persisted on-disk database. This stores the bulk of data
	// and supports a transactional model for safe concurrent access.
	// inmem is used alongside db to store in-memory indexing information
	// for more efficient lookups into db. This index is built online at
	// boot.
	db *bolt.DB

	// hmacKeyNotEmpty is flipped to 1 when an hmac entry is set. This is
	// used to determine if we're in a bootstrap state and can create a
	// bootstrap token.
	hmacKeyNotEmpty uint32

	// indexers is used to track whether an indexer was called. This is
	// initialized during New and set to nil at the end of New.
	indexers map[uintptr]struct{}

	// Where to log to
	log hclog.Logger

	// indexedJobs indicates how many job records we are tracking in memory
	indexedJobs int

	// Used to track indexedJobs and prune records
	pruneMu sync.Mutex
}

const (
	// tokenMagic is used as a byte sequence prepended to the encoded TokenTransport to identify
	// the token as valid before attempting to decode it. This is mostly a nicity to improve
	// understanding of the token data and error messages.
	tokenMagic = "wp24"
)

// Hashes token in OSS with HMAC
func (s *State) TokenEncrypt(token []byte, keyId string, metadata map[string]string) (ciphertext []byte, err error) {
	// hmacKeySize is the size in bytes that the HMAC keys should be. Each key will contain this number of bytes
	// of data from rand.Reader
	var hmacKeySize = 32

	// Get the key material
	key, err := s.HMACKeyCreateIfNotExist(keyId, hmacKeySize)
	if err != nil {
		return nil, err
	}

	// Sign it
	h, err := blake2b.New256(key.Key)
	if err != nil {
		return nil, err
	}
	h.Write(token)

	// Build our wrapper which is not signed or encrypted.
	var tt pb.TokenTransport
	tt.Body = token
	tt.KeyId = keyId
	tt.Metadata = metadata
	tt.Signature = h.Sum(nil)

	// Marshal the wrapper.
	ttData, err := proto.Marshal(&tt)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.WriteString(tokenMagic)
	buf.Write(ttData)

	return buf.Bytes(), nil
}

func (s *State) TokenDecrypt(ciphertext []byte) (*pb.TokenTransport, *pb.Token, error) {
	var err error
	if subtle.ConstantTimeCompare(ciphertext[:len(tokenMagic)], []byte(tokenMagic)) != 1 {
		return nil, nil, errors.Wrapf(err, "bad magic")
	}

	var tt pb.TokenTransport
	err = proto.Unmarshal(ciphertext, &tt)
	if err != nil {
		return nil, nil, err
	}

	key, err := s.HMACKeyGet(tt.KeyId)
	if err != nil || key == nil {
		return nil, nil, errors.Wrapf(err, "unknown key")
	}

	// Hash the token body using the HMAC key so that we can compare
	// with our signature to ensure this hasn't been tampered with.
	h, err := blake2b.New256(key.Key)
	if err != nil {
		return nil, nil, err
	}

	h.Write(tt.Body)
	sum := h.Sum(nil)
	if subtle.ConstantTimeCompare(sum, tt.Signature) != 1 {
		return nil, nil, errors.Wrapf(err, "bad signature")
	}

	// Decode the actual token structure
	var body pb.Token
	err = proto.Unmarshal(tt.Body, &body)
	if err != nil {
		return nil, nil, err
	}

	return &tt, &body, nil
}

// New initializes a new State store.
func New(log hclog.Logger, db *bolt.DB) (*State, error) {
	// Restore DB if necessary
	db, err := finalizeRestore(log, db)
	if err != nil {
		return nil, err
	}

	// Create the in-memory DB.
	inmem, err := memdb.NewMemDB(stateStoreSchema())
	if err != nil {
		return nil, fmt.Errorf("Failed setting up state store: %s", err)
	}

	// Initialize and validate our on-disk format.
	if err := dbInit(db); err != nil {
		return nil, err
	}

	s := &State{inmem: inmem, db: db, log: log}

	// Initialize our set that'll track what memdb indexers we call.
	// When we're done we always clear this out since it is never used
	// again.
	s.indexers = make(map[uintptr]struct{})
	defer func() { s.indexers = nil }()

	// Initialize our in-memory indexes. We also make this a write transaction
	// for the DB because we allow the indexers to update their own data for
	// upgrades and so on.
	memTxn := s.inmem.Txn(true)
	defer memTxn.Abort()
	err = s.db.Update(func(dbTxn *bolt.Tx) error {
		for _, indexer := range dbIndexers {
			// TODO: this should use callIndexer but it's broken as it prevents the multiple op indexers
			// from properly running.
			if err := indexer(s, dbTxn, memTxn); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	memTxn.Commit()

	return s, nil
}

// callIndexer calls the specified indexer exactly once. If it has been called
// before this returns no error. This must not be called concurrently. This
// can be used from indexers to ensure other data is indexed first.
func (s *State) callIndexer(fn indexFn, dbTxn *bolt.Tx, memTxn *memdb.Txn) error {
	fnptr := reflect.ValueOf(fn).Pointer()
	if _, ok := s.indexers[fnptr]; ok {
		return nil
	}
	s.indexers[fnptr] = struct{}{}

	return fn(s, dbTxn, memTxn)
}

// Close should be called to gracefully close any resources.
func (s *State) Close() error {
	return s.db.Close()
}

// Prune should be called in a on a regular interval to allow State
// to prune out old data.
func (s *State) Prune() error {
	memTxn := s.inmem.Txn(true)
	defer memTxn.Abort()

	jobs, err := s.jobsPruneOld(memTxn, maximumJobsIndexed)
	if err != nil {
		return err
	}

	var records int

	for _, f := range pruneFns {
		tbl, cnt, err := f(memTxn)
		if err != nil {
			return err
		}

		s.log.Debug("Pruning table index data", "table", tbl, "removed-records", cnt)
		records += cnt
	}

	s.log.Debug("Finished pruning data",
		"removed-jobs", jobs,
		"removed-records", records,
		"op-tables", len(pruneFns),
	)

	memTxn.Commit()

	return nil
}

// schemaFn is an interface function used to create and return new memdb schema
// structs for constructing an in-memory db.
type schemaFn func() *memdb.TableSchema

// stateStoreSchema is used to return the combined schema for the state store.
func stateStoreSchema() *memdb.DBSchema {
	// Create the root DB schema
	db := &memdb.DBSchema{
		Tables: make(map[string]*memdb.TableSchema),
	}

	// Add the tables to the root schema
	for _, fn := range schemas {
		schema := fn()
		if _, ok := db.Tables[schema.Name]; ok {
			panic(fmt.Sprintf("duplicate table name: %s", schema.Name))
		}

		db.Tables[schema.Name] = schema
	}

	return db
}

// indexFn is the function type for initializing in-memory indexes from
// persisted data. This is usually specified as a method handle to a
// *State method.
//
// The bolt.Tx is read-only while the memdb.Txn is a write transaction.
type indexFn func(*State, *bolt.Tx, *memdb.Txn) error
