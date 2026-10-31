// Package auditlog appends security events to a hash chain. Each row's hash covers the
// previous row's hash plus its own fields, so editing, deleting or reordering a row
// breaks verification from that point on.
//
// # What the chain does and does not prove
//
// The hash is unkeyed, and a chain says nothing about rows that should come after it.
// Verifying the chain alone detects an edit, a deletion in the middle or a reordering
// that was not followed by rewriting everything after it. It CANNOT detect tail
// truncation: deleting the newest rows, or all of them, leaves a valid shorter chain. Nor
// can it detect someone who rewrites the table and recomputes every hash.
//
// Detecting those takes a checkpoint: the id and hash of a recent row, kept somewhere the
// database's writers cannot modify, and passed to VerifyStored. Storing it is the
// operator's job; nothing here exports it. Rows newer than the checkpoint remain
// truncatable, so take checkpoints as often as that gap matters.
//
// # One writer at a time, across all instances
//
// If two appends read the same head, both new rows point at it and the chain becomes a
// tree, which looks exactly like tampering to a verifier. An in-process mutex cannot stop
// that between instances, so production uses NewGormRecorder, which takes a Postgres
// advisory lock and reads the head and inserts within a single transaction. NewRecorder
// guards with a local mutex instead and is not meant for more than one instance.
//
// # Secrets stay out of the trail
//
// See Entry.Detail.
package auditlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

// CurrentChainVersion identifies which fields RecomputeHash covers for new rows. A new
// hashed field means a new version number; a version in use keeps its field list forever.
const CurrentChainVersion = 1

// chainLockKey names the advisory lock every instance contends on.
const chainLockKey = "audit_log_chain"

// recordTimeout bounds an append. See Record for why it does not inherit the caller's.
const recordTimeout = 5 * time.Second

const (
	// redacted replaces the value of a Detail key that looks sensitive.
	redacted = "[redacted]"
	// unencodable replaces a Detail value that cannot be marshalled. Its contents are
	// unknown, so it is dropped rather than stored some other way.
	unencodable = "[unencodable]"
)

// sensitiveKeyParts are looked for anywhere in a Detail key, ignoring case and word
// separators, so backup_code, backupCode and backup-code all match. A backstop for the
// rule on Entry.Detail, not a substitute for it: it cannot recognize a secret stored
// under an innocent name.
var sensitiveKeyParts = []string{
	"password", "passwd", "pwd", "secret", "token", "totp", "backupcode", "recovery",
	"apikey", "authorization", "cookie", "credential",
}

// sensitiveKeyWords must match a whole word of the key. As a substring, otp would
// redact a field like hotpot.
var sensitiveKeyWords = map[string]bool{"otp": true}

type impersonatorKey struct{}

// ContextWithImpersonator stores the impersonator's user id on ctx. Record reads it back,
// so each row written during the request names them even when the call site says nothing;
// relying on an argument would let one omission pin an action on the impersonated user.
func ContextWithImpersonator(ctx context.Context, userID uint) context.Context {
	if userID == 0 {
		return ctx
	}
	return context.WithValue(ctx, impersonatorKey{}, userID)
}

func impersonatorFrom(ctx context.Context) *uint {
	if id, ok := ctx.Value(impersonatorKey{}).(uint); ok && id != 0 {
		return &id
	}
	return nil
}

// Entry is what a caller records.
type Entry struct {
	Event       string
	ActorUserID *uint
	// ImpersonatorUserID wins over the context value when set.
	ImpersonatorUserID *uint
	IP                 string
	// Detail is free-form context. It is part of the hash and visible to every reader of
	// the audit log, so it must NEVER hold a password, token, one-time code or other secret.
	// Say that a value changed without saying what it is: a trail that leaks secrets would
	// hand its readers a way past the very controls it watches.
	Detail map[string]any
}

// appender reads the chain head and inserts the next row as one atomic step. Whatever row
// build returns gets written; build is given the head's hash, which is "" for a new chain.
type appender interface {
	append(ctx context.Context, build func(prevHash string) *audit.Log) error
}

// Recorder writes audit events as new links of the hash chain.
type Recorder struct {
	appender appender
	log      zerolog.Logger
}

// NewRecorder guards appends with a mutex local to this process, so it suits unit tests and
// deployments of exactly one instance. Run two against one table and the chain forks.
func NewRecorder(r repo.Repo[audit.Log], log zerolog.Logger) *Recorder {
	return &Recorder{appender: &mutexAppender{repo: r}, log: log}
}

// NewGormRecorder returns the recorder for production, whose advisory lock spans instances.
func NewGormRecorder(db *gorm.DB, log zerolog.Logger) *Recorder {
	return &Recorder{appender: &pgAppender{db: db, lock: acquireChainLock}, log: log}
}

// Record appends an entry. Inside store.WithTx the row joins that transaction, so it
// commits or rolls back with the change it describes.
//
// It deliberately outlives the request's cancellation: a client that drops the connection
// mid-login must not be able to erase the record of the attempt.
func (r *Recorder) Record(ctx context.Context, e Entry) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()

	detail, err := encodeDetail(e.Detail)
	if err != nil {
		// Generic JSON should never get here. If it does, an event with no detail is better
		// than no event, so the row is still written.
		r.log.Warn().Err(err).Str("event", e.Event).Msg("audit: dropped detail that could not be encoded")
		detail = ""
	}

	impersonator := e.ImpersonatorUserID
	if impersonator == nil {
		impersonator = impersonatorFrom(ctx)
	}

	nextLink := func(prevHash string) *audit.Log {
		row := &audit.Log{
			ChainVersion: CurrentChainVersion,
			PrevHash:     prevHash,
			// Postgres keeps microseconds. Without truncating, the stored value differs from
			// the hashed one and the row fails verification the moment it is read back.
			CreatedAt:          time.Now().UTC().Truncate(time.Microsecond),
			Event:              e.Event,
			ActorUserID:        e.ActorUserID,
			ImpersonatorUserID: impersonator,
			IP:                 e.IP,
			Detail:             detail,
		}
		row.Hash = RecomputeHash(row)
		return row
	}
	if err := r.appender.append(ctx, nextLink); err != nil {
		r.log.Error().Err(err).Str("event", e.Event).Msg("audit: failed to record event")
		return err
	}

	// The row is invisible to alerting; this line is not. It carries ids only, never Detail.
	line := r.log.Info().Str("audit_event", e.Event)
	if e.ActorUserID != nil {
		line = line.Uint("actor_user_id", *e.ActorUserID)
	}
	if impersonator != nil {
		line = line.Uint("impersonator_user_id", *impersonator)
	}
	if e.IP != "" {
		line = line.Str("ip", e.IP)
	}
	line.Msg("audit event")
	return nil
}

// encodeDetail returns detail as redacted JSON. Each value is first normalized to generic
// JSON, because a secret can sit in a struct, a typed map or a slice as easily as in a
// map[string]any, and only the JSON form shows every key that would be stored. Values are
// handled one at a time so an unencodable one costs only itself.
func encodeDetail(detail map[string]any) (string, error) {
	if len(detail) == 0 {
		return "", nil
	}
	safe := make(map[string]any, len(detail))
	for k, v := range detail {
		if isSensitiveKey(k) {
			safe[k] = redacted
			continue
		}
		generic, err := toGenericJSON(v)
		if err != nil {
			safe[k] = unencodable
			continue
		}
		safe[k] = redact(generic)
	}
	b, err := json.Marshal(safe)
	if err != nil {
		return "", fmt.Errorf("audit: marshal detail: %w", err)
	}
	return string(b), nil
}

// toGenericJSON keeps numbers as written, so a large id does not become a float.
func toGenericJSON(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// redact walks generic JSON, replacing the value of every sensitive key at any depth.
func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isSensitiveKey(k) {
				out[k] = redacted
				continue
			}
			out[k] = redact(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redact(val)
		}
		return out
	}
	return v
}

func isSensitiveKey(k string) bool {
	words := keyWords(k)
	joined := strings.Join(words, "")
	for _, part := range sensitiveKeyParts {
		if strings.Contains(joined, part) {
			return true
		}
	}
	for _, w := range words {
		if sensitiveKeyWords[w] {
			return true
		}
	}
	return false
}

// keyWords splits a key into lowercase words at separators and camelCase humps, so
// userOTP, OTPCode and otp_code each yield the word otp while hotpot stays one word.
func keyWords(k string) []string {
	runes := []rune(k)
	var words []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			words = append(words, cur.String())
			cur.Reset()
		}
	}
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur.WriteRune(unicode.ToLower(r))
	}
	flush()
	return words
}

// RecomputeHash derives a row's hash from the fields stored on it. Every field is written
// as "<length>:<value>|", so bytes cannot shift from one field into the next unnoticed.
func RecomputeHash(rec *audit.Log) string {
	h := sha256.New()
	for _, f := range []string{
		strconv.Itoa(rec.ChainVersion),
		rec.PrevHash,
		rec.CreatedAt.UTC().Format(time.RFC3339Nano),
		rec.Event,
		formatUserID(rec.ActorUserID),
		formatUserID(rec.ImpersonatorUserID),
		rec.IP,
		rec.Detail,
	} {
		_, _ = fmt.Fprintf(h, "%d:%s|", len(f), f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func formatUserID(id *uint) string {
	if id == nil {
		return ""
	}
	return strconv.FormatUint(uint64(*id), 10)
}

// VerifyChain expects the whole chain, oldest row first. It stops at the first row that
// fails and returns its id with false; a clean run returns (0, true).
func VerifyChain(rows []audit.Log) (badID uint, ok bool) {
	badID, _, ok = verifyFrom("", rows)
	return badID, ok
}

// verifyFrom recomputes each row's hash to expose edits, and compares its PrevHash with the
// row before it to expose rows that were removed, moved or written on a fork.
func verifyFrom(prev string, rows []audit.Log) (badID uint, head string, ok bool) {
	for i := range rows {
		row := &rows[i]
		if row.PrevHash != prev || row.ChainVersion != CurrentChainVersion || RecomputeHash(row) != row.Hash {
			return row.ID, prev, false
		}
		prev = row.Hash
	}
	return 0, prev, true
}

// Reasons a verification failed.
const (
	ReasonChainBroken        = "chain_broken"
	ReasonCheckpointMissing  = "checkpoint_missing"
	ReasonCheckpointMismatch = "checkpoint_mismatch"
)

// Checkpoint is a row's id and hash recorded earlier, kept where the database's writers
// cannot modify it.
type Checkpoint struct {
	ID   uint
	Hash string
}

// VerifyResult is the outcome of walking the stored chain.
type VerifyResult struct {
	OK bool `json:"ok"`
	// CheckpointVerified says a trusted checkpoint was matched. Without it, OK says nothing
	// about rows deleted from the tail: an empty table verifies.
	CheckpointVerified bool   `json:"checkpoint_verified"`
	Checked            int64  `json:"checked"`
	Reason             string `json:"reason,omitempty"`
	FirstBadID         uint   `json:"first_bad_id,omitempty"`
	// HeadID and Head identify the last verified row: the values to store as a checkpoint.
	HeadID uint   `json:"head_id,omitempty"`
	Head   string `json:"head,omitempty"`
}

// VerifyStored walks the whole chain in batches and is linear in the table's size. With a
// checkpoint, it also fails when that row is missing or its hash differs. See the package
// comment for what passing without one does not prove.
func VerifyStored(ctx context.Context, db *gorm.DB, checkpoint *Checkpoint) (VerifyResult, error) {
	const batch = 1000
	var (
		res    VerifyResult
		lastID uint
		prev   string
	)
	for {
		var rows []audit.Log
		if err := db.WithContext(ctx).Where("id > ?", lastID).Order("id ASC").Limit(batch).Find(&rows).Error; err != nil {
			return res, err
		}
		badID, head, ok := verifyFrom(prev, rows)
		if !ok {
			res.Reason = ReasonChainBroken
			res.FirstBadID = badID
			return res, nil
		}
		for i := range rows {
			if checkpoint != nil && rows[i].ID == checkpoint.ID {
				if rows[i].Hash != checkpoint.Hash {
					res.Reason = ReasonCheckpointMismatch
					res.FirstBadID = rows[i].ID
					return res, nil
				}
				res.CheckpointVerified = true
			}
		}
		res.Checked += int64(len(rows))
		if len(rows) > 0 {
			lastID = rows[len(rows)-1].ID
			res.HeadID = lastID
			res.Head = head
			prev = head
		}
		if len(rows) < batch {
			break
		}
	}
	if checkpoint != nil && !res.CheckpointVerified {
		res.Reason = ReasonCheckpointMissing
		return res, nil
	}
	res.OK = true
	return res, nil
}

// headHash turns the outcome of reading the newest row into the hash the next row links
// to. Only a missing row means an empty chain. Any other read failure is returned, because
// treating it as empty would start a second root.
func headHash(newest *audit.Log, readErr error) (string, error) {
	if errors.Is(readErr, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if readErr != nil {
		return "", readErr
	}
	return newest.Hash, nil
}

// mutexAppender guards the chain with a process-local mutex, so it holds within one
// instance only.
type mutexAppender struct {
	mu   sync.Mutex
	repo repo.Repo[audit.Log]
}

func (a *mutexAppender) append(ctx context.Context, build func(prevHash string) *audit.Log) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	newest, readErr := a.repo.GetOne(ctx, store.QueryOpts{Sort: []store.SortField{{Field: "id", Desc: true}}})
	prevHash, err := headHash(newest, readErr)
	if err != nil {
		return err
	}
	return a.repo.Create(ctx, build(prevHash))
}

// pgAppender guards the chain with a Postgres advisory lock, so it holds for every instance.
//
// Taking the lock at transaction scope means a commit, a rollback or a dead process all
// release it, where a leaked session-scoped lock would block every other instance for good.
type pgAppender struct {
	db *gorm.DB
	// lock is injected so tests can run the transactional path on sqlite, which lacks
	// advisory locks. Any error from it stops the append, since writing without the lock
	// risks the very fork it is there to rule out.
	lock func(tx *gorm.DB) error
}

func acquireChainLock(tx *gorm.DB) error {
	return tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?))`, chainLockKey).Error
}

func (a *pgAppender) append(ctx context.Context, build func(prevHash string) *audit.Log) error {
	conn := a.db
	if tx, ok := store.TxFromContext(ctx); ok {
		conn = tx
	}
	return conn.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := a.lock(tx); err != nil {
			return err
		}
		// The head is read under the lock, or the fork window stays open.
		var newest audit.Log
		readErr := tx.Order("id DESC").Limit(1).Take(&newest).Error
		prevHash, err := headHash(&newest, readErr)
		if err != nil {
			return err
		}
		return tx.Create(build(prevHash)).Error
	})
}
