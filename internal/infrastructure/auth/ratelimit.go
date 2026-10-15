package auth

import (
	"container/list"
	"sync"
	"time"
)

// maxTrackedKeys is the default cap on tracked keys (emails and IPs together).
// Past it, the least recently touched key is evicted to make room. Eviction is
// preferred over refusing new keys: refusing would let an attacker fill the
// table and lock every other user out. Evicting a victim's counter instead
// costs an attacker about 10k fresh keys first, at least 500 IPs at 20
// attempts per IP per window, and buys them only 5 more guesses at that email.
const maxTrackedKeys = 10000

// LoginLimiter throttles password guessing. It counts login attempts per
// email and per client IP in a sliding window; once a key reaches its limit,
// attempts for that key are refused until old ones age out. A successful
// login clears its email and takes exactly its own attempt back from the IP,
// so only failures count in the end. State is in memory, so limits apply per
// process, and at most maxKeys keys are tracked at once.
type LoginLimiter struct {
	mu       sync.Mutex
	now      func() time.Time
	window   time.Duration
	maxEmail int
	maxIP    int
	maxKeys  int
	attempts map[string]*list.Element // values are *tracked
	lru      *list.List               // front is the most recently touched key
}

// tracked is the attempt history of one key, in chronological order.
type tracked struct {
	key string
	ts  []time.Time
}

// NewLoginLimiter allows 5 failures per email and 20 per IP in 15 minutes.
func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		now:      time.Now,
		window:   15 * time.Minute,
		maxEmail: 5,
		maxIP:    20,
		maxKeys:  maxTrackedKeys,
		attempts: make(map[string]*list.Element),
		lru:      list.New(),
	}
}

// Attempt reports whether a login for email from ip may proceed and, if not,
// how long until it may. An allowed attempt is recorded for both keys under
// the same lock as the check, so concurrent requests cannot all slip through
// before any of them is counted. It returns the timestamp it recorded (zero
// when refused); pass that to Success once the login succeeds.
func (l *LoginLimiter) Attempt(email, ip string) (at time.Time, ok bool, wait time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	emailKey, ipKey := "email:"+email, "ip:"+ip
	for _, k := range []struct {
		key   string
		limit int
	}{{emailKey, l.maxEmail}, {ipKey, l.maxIP}} {
		recent := l.prune(k.key, now)
		if len(recent) < k.limit {
			continue
		}
		// The attempt that must expire before the key drops below its limit.
		if w := recent[len(recent)-k.limit].Add(l.window).Sub(now); w > wait {
			wait = w
		}
	}
	if wait > 0 {
		return time.Time{}, false, wait
	}
	for _, key := range []string{emailKey, ipKey} {
		l.record(key, now)
	}
	return now, true, 0
}

// Success clears the history of email after a correct password and removes the
// IP entry recorded at at (the value Attempt returned), so successful logins
// never count toward the IP limit. It never removes any other entry, so
// interleaved failures from the same IP stay counted. Entries with an identical
// timestamp are interchangeable; if none matches, nothing is removed.
func (l *LoginLimiter) Success(email, ip string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.remove("email:" + email)
	el, found := l.attempts["ip:"+ip]
	if !found {
		return
	}
	entry := el.Value.(*tracked)
	for i, t := range entry.ts {
		if !t.Equal(at) {
			continue
		}
		entry.ts = append(entry.ts[:i:i], entry.ts[i+1:]...)
		break
	}
	if len(entry.ts) == 0 {
		l.remove(entry.key)
	}
}

// prune drops attempts of key older than the window and returns the rest. A
// key that still has attempts counts as touched; one left empty is removed.
func (l *LoginLimiter) prune(key string, now time.Time) []time.Time {
	el, found := l.attempts[key]
	if !found {
		return nil
	}
	entry := el.Value.(*tracked)
	cutoff := now.Add(-l.window)
	i := 0
	for i < len(entry.ts) && !entry.ts[i].After(cutoff) {
		i++
	}
	entry.ts = entry.ts[i:]
	if len(entry.ts) == 0 {
		l.remove(key)
		return nil
	}
	l.lru.MoveToFront(el)
	return entry.ts
}

// record appends an attempt at now to key and marks it most recently touched.
// A new key evicts the least recently touched one once the cap is exceeded;
// with a cap of at least two, both keys of the current attempt are never evicted.
func (l *LoginLimiter) record(key string, now time.Time) {
	if el, found := l.attempts[key]; found {
		entry := el.Value.(*tracked)
		entry.ts = append(entry.ts, now)
		l.lru.MoveToFront(el)
		return
	}
	l.attempts[key] = l.lru.PushFront(&tracked{key: key, ts: []time.Time{now}})
	if len(l.attempts) > l.maxKeys {
		l.remove(l.lru.Back().Value.(*tracked).key)
	}
}

// remove stops tracking key, if it is tracked.
func (l *LoginLimiter) remove(key string) {
	if el, found := l.attempts[key]; found {
		l.lru.Remove(el)
		delete(l.attempts, key)
	}
}
