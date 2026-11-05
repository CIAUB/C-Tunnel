package cli

import (
	"testing"

	"ctunnel/pkg/catalog"
)

func TestMethodMenuListsEveryMethodOnce(t *testing.T) {
	seen := map[string]int{}
	for _, f := range methodMenu {
		for _, g := range f.groups {
			for _, n := range g.methods {
				m, ok := catalog.LookupMethod(n)
				if !ok || m.Family != f.family {
					t.Fatalf("%s in %s/%s: unknown or in the wrong family", n, f.title, g.title)
				}
				seen[n]++
			}
		}
	}
	for _, m := range catalog.Methods {
		if seen[m.Name] != 1 {
			t.Errorf("%s is in the menu %d times", m.Name, seen[m.Name])
		}
	}
}
