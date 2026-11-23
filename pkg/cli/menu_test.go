package cli

import (
	"testing"

	"ctunnel/pkg/catalog"
)

func TestMethodMenuListsEveryActiveMethodOnceAndHidesLegacy(t *testing.T) {
	seen := map[string]int{}
	for _, f := range methodMenu {
		for _, g := range f.groups {
			for _, n := range g.methods {
				m, ok := catalog.LookupMethod(n)
				if !ok || m.Family != f.family || m.Legacy {
					t.Fatalf("%s in %s/%s: unknown, legacy, or in the wrong family", n, f.title, g.title)
				}
				seen[n]++
			}
		}
	}
	for _, m := range catalog.Methods {
		want := 1
		if m.Legacy {
			want = 0
		}
		if seen[m.Name] != want {
			t.Errorf("%s (legacy=%v) is in the menu %d times, want %d", m.Name, m.Legacy, seen[m.Name], want)
		}
	}
}

// The update runs the repository in a shell command: only owner/name passes.
func TestRepoSlugRefusesShell(t *testing.T) {
	for _, ok := range []string{"CIAUB/C-Tunnel", "a_b/c.d-e"} {
		if !repoSlugRe.MatchString(ok) {
			t.Errorf("refused %q", ok)
		}
	}
	for _, bad := range []string{"$(id)/x", "a/b;id", "a/b`id`", "a/b c", "a/../../b", "a", "a/b\n"} {
		if repoSlugRe.MatchString(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}
