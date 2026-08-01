package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"testing/fstest"
	"time"
)

// stagedFS serves files the validator was handed over the wire, so a
// `directives` block that Includes a path off the HAProxy pod's disk can be
// compiled by a validator that has no such disk.
//
// It exists because absolute paths and io/fs do not mix: `fs.ValidPath`
// rejects a leading `/`, but the paths in an operator's directives are exactly
// that (`Include /etc/haproxy/general/crs/*.conf`). Lookups are normalised to
// unrooted form, while Glob answers in the caller's own spelling so the names
// Coraza reads back round-trip through the same normalisation.
//
// Nothing touches the filesystem. That removes the whole class of temp-dir
// bugs — cleanup on panic, collisions between concurrent requests, traversal
// out of the staging root — from a path that runs on every admission.
type stagedFS struct {
	// byNormalised maps the unrooted lookup key to content.
	byNormalised fstest.MapFS
	// originals lists the caller's spellings, sorted, for Glob results.
	originals []string
}

// normaliseStagedPath converts any spelling of a path into the unrooted form
// io/fs requires. Cleaning against "/" also collapses any `..`, so a staged
// name cannot address anything outside the set it was given.
func normaliseStagedPath(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

// newStagedFS builds the filesystem from path → content.
func newStagedFS(files map[string]string) *stagedFS {
	mapfs := make(fstest.MapFS, len(files))
	originals := make([]string, 0, len(files))
	for name, content := range files {
		normalised := normaliseStagedPath(name)
		if normalised == "" || normalised == "." {
			continue
		}
		mapfs[normalised] = &fstest.MapFile{
			Data:    []byte(content),
			Mode:    0o400,
			ModTime: time.Unix(0, 0),
		}
		originals = append(originals, name)
	}
	sort.Strings(originals)
	return &stagedFS{byNormalised: mapfs, originals: originals}
}

func (s *stagedFS) Open(name string) (fs.File, error) {
	return s.byNormalised.Open(normaliseStagedPath(name))
}

func (s *stagedFS) ReadFile(name string) ([]byte, error) {
	return s.byNormalised.ReadFile(normaliseStagedPath(name))
}

func (s *stagedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return s.byNormalised.ReadDir(normaliseStagedPath(name))
}

// Glob matches the caller's spellings and answers in them, so an absolute
// pattern yields absolute names. Returning the normalised form instead would
// still work — ReadFile normalises either way — but it would put paths in
// Coraza's diagnostics that appear nowhere in the operator's config.
func (s *stagedFS) Glob(pattern string) ([]string, error) {
	normalisedPattern := normaliseStagedPath(pattern)
	var matches []string
	for _, original := range s.originals {
		matched, err := path.Match(normalisedPattern, normaliseStagedPath(original))
		if err != nil {
			return nil, err
		}
		if matched {
			matches = append(matches, original)
		}
	}
	return matches, nil
}

// parseStagedFiles decodes the path → content JSON object the hub's validator
// passes through. An empty or absent payload yields no files, which is the
// ordinary case for a config that includes nothing off disk.
func parseStagedFiles(payload string) (map[string]string, error) {
	if strings.TrimSpace(payload) == "" {
		return nil, nil
	}
	var files map[string]string
	if err := json.Unmarshal([]byte(payload), &files); err != nil {
		return nil, fmt.Errorf("parsing staged files: %w", err)
	}
	return files, nil
}
