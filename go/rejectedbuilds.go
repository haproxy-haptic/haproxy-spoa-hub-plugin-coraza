package main

import (
	"crypto/sha256"
	"encoding/binary"
	"io/fs"
	"strings"
	"sync"
)

// coraza.NewWAF does not release the memoized patterns of a WAF it rejects, and
// returns nothing that could be closed, so every attempt leaks. Replaying the
// remembered rejection bounds that leak by distinct inputs instead of attempts.
const maxRejectedBuilds = 64

type rejectedBuilds[T any] struct {
	mu      sync.Mutex
	entries map[[32]byte]rejectedBuild[T]
	order   [][32]byte
}

type rejectedBuild[T any] struct {
	reads  []observedRead
	result T
	err    error
}

type observedRead struct {
	glob bool
	name string
	sum  [32]byte
}

func newRejectedBuilds[T any]() *rejectedBuilds[T] {
	return &rejectedBuilds[T]{entries: make(map[[32]byte]rejectedBuild[T])}
}

// build replays the rejection remembered for key while root still serves the
// bytes that attempt read; otherwise it runs construct over a recording view of root.
func (r *rejectedBuilds[T]) build(key [32]byte, root fs.FS, construct func(fs.FS) (T, error)) (T, error) {
	r.mu.Lock()
	entry, rejected := r.entries[key]
	r.mu.Unlock()
	if rejected && rereads(root, entry.reads) {
		return entry.result, entry.err
	}

	recorder := &recordingFS{inner: root}
	result, err := construct(recorder)

	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil || recorder.opened {
		r.forgetLocked(key)
		return result, err
	}
	if _, ok := r.entries[key]; !ok {
		r.order = append(r.order, key)
	}
	r.entries[key] = rejectedBuild[T]{reads: recorder.reads, result: result, err: err}
	if len(r.order) > maxRejectedBuilds {
		delete(r.entries, r.order[0])
		r.order = r.order[1:]
	}
	return result, err
}

func (r *rejectedBuilds[T]) forgetLocked(key [32]byte) {
	if _, ok := r.entries[key]; !ok {
		return
	}
	delete(r.entries, key)
	for i, k := range r.order {
		if k == key {
			r.order = append(r.order[:i], r.order[i+1:]...)
			return
		}
	}
}

func (r *rejectedBuilds[T]) remembered() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

func rereads(root fs.FS, reads []observedRead) bool {
	for _, read := range reads {
		if observe(root, read.glob, read.name) != read.sum {
			return false
		}
	}
	return true
}

func observe(root fs.FS, glob bool, name string) [32]byte {
	if glob {
		matches, err := fs.Glob(root, name)
		return outcomeSum([]byte(strings.Join(matches, "\x00")), err)
	}
	content, err := fs.ReadFile(root, name)
	return outcomeSum(content, err)
}

func outcomeSum(content []byte, err error) [32]byte {
	if err != nil {
		return inputKey("error", err.Error())
	}
	return inputKey("ok", string(content))
}

// inputKey hashes length-prefixed parts, so no two part lists collide by concatenation.
func inputKey(parts ...string) [32]byte {
	h := sha256.New()
	var size [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		h.Write(size[:])
		h.Write([]byte(part))
	}
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// recordingFS hashes every result Coraza reads, as it reads it: re-reading after
// a rejection could see a newer file than the one that was rejected.
type recordingFS struct {
	inner  fs.FS
	reads  []observedRead
	opened bool
}

// Open hands out a file whose content is not observed here, so the attempt
// cannot be replayed.
func (r *recordingFS) Open(name string) (fs.File, error) {
	r.opened = true
	return r.inner.Open(name)
}

func (r *recordingFS) ReadFile(name string) ([]byte, error) {
	content, err := fs.ReadFile(r.inner, name)
	r.reads = append(r.reads, observedRead{name: name, sum: outcomeSum(content, err)})
	return content, err
}

func (r *recordingFS) Glob(pattern string) ([]string, error) {
	matches, err := fs.Glob(r.inner, pattern)
	r.reads = append(r.reads, observedRead{
		glob: true,
		name: pattern,
		sum:  outcomeSum([]byte(strings.Join(matches, "\x00")), err),
	})
	return matches, err
}
