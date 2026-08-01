package main

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/jcchavezs/mergefs"
	osfs "github.com/jcchavezs/mergefs/io"
)

// The whole reason stagedFS exists: io/fs rejects a leading slash, but an
// operator's directives address files exactly that way.
func TestStagedFS_ServesAbsolutePaths(t *testing.T) {
	sfs := newStagedFS(map[string]string{
		"/etc/haproxy/general/crs/REQUEST-901-INIT.conf": "SecAction id:901000\n",
	})

	content, err := sfs.ReadFile("/etc/haproxy/general/crs/REQUEST-901-INIT.conf")
	if err != nil {
		t.Fatalf("absolute ReadFile failed: %v", err)
	}
	if string(content) != "SecAction id:901000\n" {
		t.Fatalf("unexpected content %q", content)
	}

	// The same file must also be reachable by the unrooted spelling, because
	// Coraza normalises paths on its own in some code paths.
	if _, err := sfs.ReadFile("etc/haproxy/general/crs/REQUEST-901-INIT.conf"); err != nil {
		t.Fatalf("unrooted ReadFile failed: %v", err)
	}
}

// Glob answers in the caller's spelling so the names Coraza reads back — and
// prints in diagnostics — are the ones the operator wrote.
func TestStagedFS_GlobRoundTrips(t *testing.T) {
	sfs := newStagedFS(map[string]string{
		"/etc/haproxy/general/crs/REQUEST-901-INIT.conf":   "a",
		"/etc/haproxy/general/crs/REQUEST-905-COMMON.conf": "b",
		"/etc/haproxy/general/crs/lfi-os-files.data":       "c",
		"/etc/haproxy/general/503.http":                    "d",
	})

	matches, err := sfs.Glob("/etc/haproxy/general/crs/*.conf")
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}

	want := []string{
		"/etc/haproxy/general/crs/REQUEST-901-INIT.conf",
		"/etc/haproxy/general/crs/REQUEST-905-COMMON.conf",
	}
	if len(matches) != len(want) {
		t.Fatalf("got %v, want %v", matches, want)
	}
	for i, m := range matches {
		if m != want[i] {
			t.Fatalf("got %v, want %v", matches, want)
		}
		// Every name Glob returns must be readable as returned.
		if _, err := sfs.ReadFile(m); err != nil {
			t.Fatalf("glob result %q is not readable: %v", m, err)
		}
	}
}

func TestParseStagedFiles(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    int
		wantErr bool
	}{
		{name: "empty payload is not an error", payload: "", want: 0},
		{name: "blank payload is not an error", payload: "   ", want: 0},
		{name: "object", payload: `{"/a.conf":"x","/b.conf":"y"}`, want: 2},
		{name: "malformed json", payload: `{"a":`, wantErr: true},
		{name: "wrong shape", payload: `["a","b"]`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := parseStagedFiles(tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(files) != tt.want {
				t.Fatalf("got %d files, want %d", len(files), tt.want)
			}
		})
	}
}

// Cleaning against "/" collapses traversal, so a staged name cannot address
// anything outside the set the request supplied.
func TestNormaliseStagedPath_CollapsesTraversal(t *testing.T) {
	tests := map[string]string{
		"/etc/haproxy/general/a.conf":     "etc/haproxy/general/a.conf",
		"etc/haproxy/general/a.conf":      "etc/haproxy/general/a.conf",
		"/etc/../../../../etc/passwd":     "etc/passwd",
		"../../etc/passwd":                "etc/passwd",
		"/etc/haproxy/./general/./a.conf": "etc/haproxy/general/a.conf",
	}
	for in, want := range tests {
		if got := normaliseStagedPath(in); got != want {
			t.Errorf("normaliseStagedPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// The end-to-end shape this feature exists for: directives that Include a
// ruleset by absolute path compile against the staged content, with the
// embedded CRS deliberately not referenced.
func TestCreateWAF_ValidatesAgainstStagedFiles(t *testing.T) {
	staged := map[string]string{
		"/etc/haproxy/general/crs/10-first.conf":  `SecRule REQUEST_URI "@streq /one" "id:900001,phase:1,deny,status:403"` + "\n",
		"/etc/haproxy/general/crs/20-second.conf": `SecRule REQUEST_URI "@streq /two" "id:900002,phase:1,deny,status:403"` + "\n",
	}
	directives := "Include @coraza.conf-recommended\n" +
		"Include /etc/haproxy/general/crs/*.conf\n" +
		"SecRuleEngine On\n"

	payload, err := json.Marshal(staged)
	if err != nil {
		t.Fatal(err)
	}
	diags := validateDirectives(directives, string(payload))

	for _, d := range diags {
		if d.Severity == "error" {
			t.Fatalf("staged ruleset failed to validate: %+v", diags)
		}
	}
}

// Counterpart to the test above, and the reason it proves anything: without
// the staged files the same Include resolves to nothing — and that is now an
// ERROR, so admission refuses a config whose ruleset did not arrive.
//
// Coraza itself only warns. A rule-count check would not catch this either:
// @coraza.conf-recommended contributes rules on its own, so the count stays
// non-zero with the entire ruleset missing. The empty glob is the only signal
// that distinguishes "ruleset arrived" from "ruleset absent".
func TestCreateWAF_WithoutStagedFilesIncludeIsAnError(t *testing.T) {
	directives := "Include @coraza.conf-recommended\n" +
		"Include /etc/haproxy/general/crs/definitely-absent-*.conf\n" +
		"SecRuleEngine On\n"

	diags := validateDirectives(directives, "")

	found := false
	for _, d := range diags {
		if d.Severity == "error" && strings.Contains(d.Message, corazaEmptyGlobMessage) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an error for an Include that matched nothing, got %+v", diags)
	}
}

// The promotion matches Coraza's message by text, because Coraza attaches no
// structured field naming the pattern. This test fails if an upgrade changes
// the wording — at which point the promotion silently stops firing and the
// gate goes back to fail-open, so it must fail loudly here instead.
func TestPromoteEmptyGlobs_MatchesCorazaWording(t *testing.T) {
	// Drive Coraza directly with a glob that cannot match, and assert the raw
	// wording before promotion is the constant we key on.
	raw := validateDirectivesRaw("Include /nonexistent-dir-for-wording-check/*.conf\n", "")

	found := false
	for _, d := range raw {
		if d.Message == corazaEmptyGlobMessage {
			found = true
		}
	}
	if !found {
		t.Fatalf("Coraza no longer logs %q for an empty glob — promoteEmptyGlobs is now a no-op "+
			"and an absent ruleset would validate clean; got %+v", corazaEmptyGlobMessage, raw)
	}
}

// A ruleset that IS present must not trip the gate.
func TestCreateWAF_StagedFilesDoNotTripTheEmptyGlobGate(t *testing.T) {
	staged := map[string]string{
		"/etc/haproxy/general/crs/10-first.conf": `SecRule REQUEST_URI "@streq /one" "id:900021,phase:1,deny,status:403"` + "\n",
	}
	payload, err := json.Marshal(staged)
	if err != nil {
		t.Fatal(err)
	}
	directives := "Include @coraza.conf-recommended\n" +
		"Include /etc/haproxy/general/crs/*.conf\n" +
		"SecRuleEngine On\n"

	for _, d := range validateDirectives(directives, string(payload)) {
		if d.Severity == "error" {
			t.Fatalf("a present ruleset must not error: %+v", d)
		}
	}
}

// mergefs only exposes Glob on the merged filesystem when *every* layer
// implements it, so stagedFS.Glob is reachable only as long as the other two
// layers keep theirs. They do: coreruleset.FS satisfies it through wrapFS
// embedding the subFS interface (whose concrete value is fs.Sub's result), and
// mergefs's own OSFS wraps filepath.Glob.
//
// If a dependency ever drops it, fs.Glob silently falls back to walking
// ReadDir. That still finds the files — but through MapFS's normalised keys,
// so Coraza would resolve and report them unrooted while the operator wrote
// absolute paths. The failure is cosmetic in diagnostics and invisible in
// tests that only assert compilation succeeds, which is why it is asserted
// here rather than left to be noticed.
func TestStagedFS_GlobIsReachableThroughTheMergedFS(t *testing.T) {
	type globber interface {
		Glob(string) ([]string, error)
	}

	merged := mergefs.Merge(
		coreruleset.FS,
		newStagedFS(map[string]string{"/etc/haproxy/general/crs/a.conf": "SecAction id:1"}),
		osfs.OSFS,
	)

	if _, ok := merged.(globber); !ok {
		t.Fatal("merged FS no longer exposes Glob; stagedFS.Glob is dead and paths will resolve unrooted")
	}

	matches, err := fs.Glob(merged, "/etc/haproxy/general/crs/*.conf")
	if err != nil {
		t.Fatalf("glob through the merged FS failed: %v", err)
	}
	if len(matches) != 1 || matches[0] != "/etc/haproxy/general/crs/a.conf" {
		t.Fatalf("glob must answer in the caller's absolute spelling, got %v", matches)
	}
}
