package store

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketMembers         = []byte("members")
	bucketMemberUsernames = []byte("member_usernames")
	bucketBadBots         = []byte("bad_bots")
	bucketAuditLogs       = []byte("audit_logs")
)

// MemberRecord represents a tracked member's join state in a specific chat.
type MemberRecord struct {
	ChatID    int64     `json:"chat_id"`
	UserID    int64     `json:"user_id"`
	Username  string    `json:"username"`
	IsBot     bool      `json:"is_bot"`
	IsLegacy  bool      `json:"is_legacy"`
	InChat    bool      `json:"in_chat"`
	JoinedAt  time.Time `json:"joined_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditEntry represents a recorded moderation action for audit logging and 1-click unban.
type AuditEntry struct {
	ID             int64     `json:"id"`
	ChatID         int64     `json:"chat_id"`
	ChatTitle      string    `json:"chat_title"`
	TargetUserID   int64     `json:"target_user_id"`
	SenderChatID   int64     `json:"sender_chat_id"`
	TargetName     string    `json:"target_name"`
	TargetUsername string    `json:"target_username"`
	Reason         string    `json:"reason"`
	Snippet        string    `json:"snippet"`
	UnbannedBy     int64     `json:"unbanned_by"`
	UnbannedAt     time.Time `json:"unbanned_at"`
	CreatedAt      time.Time `json:"created_at"`
}

// Store wraps embedded bbolt ACID storage and an in-memory cache of known bad bot usernames.
type Store struct {
	db *bolt.DB

	mu      sync.RWMutex
	badBots map[string]struct{}
}

// Open opens (or creates) the embedded BoltDB database at dbPath and warms caches.
func Open(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create db dir %s: %w", dir, err)
		}
	}

	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt %s: %w", dbPath, err)
	}

	s := &Store{
		db:      db,
		badBots: make(map[string]struct{}),
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketMembers, bucketMemberUsernames, bucketBadBots, bucketAuditLogs} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init buckets: %w", err)
	}

	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBadBots)
		return b.ForEach(func(k, _ []byte) error {
			s.badBots[string(k)] = struct{}{}
			return nil
		})
	}); err != nil {
		_ = db.Close()
		return nil, err
	}

	return s, nil
}

// Close closes the underlying BoltDB file.
func (s *Store) Close() error {
	return s.db.Close()
}

func memberKey(chatID, userID int64) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], uint64(chatID))
	binary.BigEndian.PutUint64(buf[8:16], uint64(userID))
	return buf
}

func usernameIndexKey(chatID int64, uname string) []byte {
	return []byte(fmt.Sprintf("%d:%s", chatID, uname))
}

func u64Bytes(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}

// RecordMemberJoin records a user newly joining a chat.
func (s *Store) RecordMemberJoin(_ context.Context, chatID, userID int64, username string, isBot bool, now time.Time) error {
	uname := strings.ToLower(strings.TrimPrefix(username, "@"))
	rec := MemberRecord{
		ChatID:    chatID,
		UserID:    userID,
		Username:  uname,
		IsBot:     isBot,
		IsLegacy:  false,
		InChat:    true,
		JoinedAt:  now,
		UpdatedAt: now,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketMembers).Put(memberKey(chatID, userID), raw); err != nil {
			return err
		}
		if uname != "" {
			if err := tx.Bucket(bucketMemberUsernames).Put(usernameIndexKey(chatID, uname), u64Bytes(uint64(userID))); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpdateMemberUsername updates a tracked member's username without resetting JoinedAt.
func (s *Store) UpdateMemberUsername(_ context.Context, chatID, userID int64, username string, isBot bool, now time.Time) error {
	uname := strings.ToLower(strings.TrimPrefix(username, "@"))
	if uname == "" {
		return nil
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		mb := tx.Bucket(bucketMembers)
		key := memberKey(chatID, userID)
		val := mb.Get(key)
		if val == nil {
			return nil
		}
		var rec MemberRecord
		if err := json.Unmarshal(val, &rec); err != nil {
			return err
		}
		rec.Username = uname
		rec.IsBot = isBot
		rec.UpdatedAt = now
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := mb.Put(key, raw); err != nil {
			return err
		}
		return tx.Bucket(bucketMemberUsernames).Put(usernameIndexKey(chatID, uname), u64Bytes(uint64(userID)))
	})
}

// RecordMemberLeave marks a member as having left or been kicked from the chat.
func (s *Store) RecordMemberLeave(_ context.Context, chatID, userID int64, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		mb := tx.Bucket(bucketMembers)
		key := memberKey(chatID, userID)
		val := mb.Get(key)
		if val == nil {
			return nil
		}
		var rec MemberRecord
		if err := json.Unmarshal(val, &rec); err != nil {
			return err
		}
		rec.InChat = false
		rec.IsLegacy = false
		rec.UpdatedAt = now
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return mb.Put(key, raw)
	})
}

// MarkLegacyVeteran records a pre-existing group member so they are exempted without future API calls.
func (s *Store) MarkLegacyVeteran(_ context.Context, chatID, userID int64, username string, now time.Time) error {
	uname := strings.ToLower(strings.TrimPrefix(username, "@"))
	return s.db.Update(func(tx *bolt.Tx) error {
		mb := tx.Bucket(bucketMembers)
		key := memberKey(chatID, userID)
		var rec MemberRecord
		if val := mb.Get(key); val != nil {
			_ = json.Unmarshal(val, &rec)
		}
		rec.ChatID = chatID
		rec.UserID = userID
		if uname != "" {
			rec.Username = uname
		}
		rec.IsLegacy = true
		rec.InChat = true
		rec.UpdatedAt = now
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := mb.Put(key, raw); err != nil {
			return err
		}
		if rec.Username != "" {
			_ = tx.Bucket(bucketMemberUsernames).Put(usernameIndexKey(chatID, rec.Username), u64Bytes(uint64(userID)))
		}
		return nil
	})
}

// GetMember returns the MemberRecord for (chatID, userID), or (nil, nil) if not found.
func (s *Store) GetMember(_ context.Context, chatID, userID int64) (*MemberRecord, error) {
	var out *MemberRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		val := tx.Bucket(bucketMembers).Get(memberKey(chatID, userID))
		if val == nil {
			return nil
		}
		var rec MemberRecord
		if err := json.Unmarshal(val, &rec); err != nil {
			return err
		}
		out = &rec
		return nil
	})
	return out, err
}

// FindMembersByUsernames finds active members currently in chatID matching any of the given usernames.
func (s *Store) FindMembersByUsernames(_ context.Context, chatID int64, usernames []string) ([]MemberRecord, error) {
	if len(usernames) == 0 {
		return nil, nil
	}
	var out []MemberRecord
	seen := make(map[int64]struct{})

	err := s.db.View(func(tx *bolt.Tx) error {
		ub := tx.Bucket(bucketMemberUsernames)
		mb := tx.Bucket(bucketMembers)
		for _, rawU := range usernames {
			clean := strings.ToLower(strings.TrimPrefix(rawU, "@"))
			if clean == "" {
				continue
			}
			uidBytes := ub.Get(usernameIndexKey(chatID, clean))
			if len(uidBytes) != 8 {
				continue
			}
			uid := int64(binary.BigEndian.Uint64(uidBytes))
			if _, dup := seen[uid]; dup {
				continue
			}
			val := mb.Get(memberKey(chatID, uid))
			if val == nil {
				continue
			}
			var rec MemberRecord
			if err := json.Unmarshal(val, &rec); err != nil {
				continue
			}
			if rec.InChat && rec.Username == clean {
				seen[uid] = struct{}{}
				out = append(out, rec)
			}
		}
		return nil
	})
	return out, err
}

// AddBadBotsMemory immediately adds bot usernames to the in-memory bad-bot set (0ms latency)
// to eliminate any race window while HTTP calls are in flight.
func (s *Store) AddBadBotsMemory(usernames []string) {
	if len(usernames) == 0 {
		return
	}
	s.mu.Lock()
	for _, raw := range usernames {
		uname := strings.ToLower(strings.TrimPrefix(raw, "@"))
		if uname != "" {
			s.badBots[uname] = struct{}{}
		}
	}
	s.mu.Unlock()
}

// AddBadBots records malicious bot usernames in BoltDB and updates the in-memory set.
func (s *Store) AddBadBots(_ context.Context, chatID int64, usernames []string, now time.Time) error {
	if len(usernames) == 0 {
		return nil
	}
	meta := []byte(fmt.Sprintf("%d:%d", chatID, now.Unix()))
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBadBots)
		for _, raw := range usernames {
			uname := strings.ToLower(strings.TrimPrefix(raw, "@"))
			if uname == "" {
				continue
			}
			if b.Get([]byte(uname)) == nil {
				if err := b.Put([]byte(uname), meta); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.mu.Lock()
	for _, raw := range usernames {
		uname := strings.ToLower(strings.TrimPrefix(raw, "@"))
		if uname != "" {
			s.badBots[uname] = struct{}{}
		}
	}
	s.mu.Unlock()
	return nil
}

// IsKnownBadBot checks the in-memory bad-bot cache in O(1) without DB I/O.
func (s *Store) IsKnownBadBot(username string) bool {
	uname := strings.ToLower(strings.TrimPrefix(username, "@"))
	if uname == "" {
		return false
	}
	s.mu.RLock()
	_, ok := s.badBots[uname]
	s.mu.RUnlock()
	return ok
}

// InsertAuditLog stores an audit entry and returns its auto-incremented ID.
func (s *Store) InsertAuditLog(_ context.Context, entry *AuditEntry) (int64, error) {
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}
	var assignedID int64
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAuditLogs)
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		assignedID = int64(seq)
		entry.ID = assignedID
		raw, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put(u64Bytes(seq), raw)
	})
	return assignedID, err
}

// GetAuditLog retrieves an AuditEntry by ID.
func (s *Store) GetAuditLog(_ context.Context, id int64) (*AuditEntry, error) {
	if id <= 0 {
		return nil, nil
	}
	var out *AuditEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		val := tx.Bucket(bucketAuditLogs).Get(u64Bytes(uint64(id)))
		if val == nil {
			return nil
		}
		var e AuditEntry
		if err := json.Unmarshal(val, &e); err != nil {
			return err
		}
		out = &e
		return nil
	})
	return out, err
}

// MarkAuditUnbanned marks an audit entry as unbanned by adminID.
func (s *Store) MarkAuditUnbanned(_ context.Context, id, adminID int64, now time.Time) error {
	if id <= 0 {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAuditLogs)
		key := u64Bytes(uint64(id))
		val := b.Get(key)
		if val == nil {
			return nil
		}
		var e AuditEntry
		if err := json.Unmarshal(val, &e); err != nil {
			return err
		}
		e.UnbannedBy = adminID
		e.UnbannedAt = now
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return b.Put(key, raw)
	})
}
