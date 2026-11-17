package identity

import "testing"

func TestSourceAndFindingIDsAreStableAndScoped(t *testing.T) {
	first := SourceEventID("boot-a", "audit", "process.exec", "42")
	if retry := SourceEventID("boot-a", "audit", "process.exec", "42"); retry != first {
		t.Fatalf("source event ID changed: %q != %q", retry, first)
	}
	if otherBoot := SourceEventID("boot-b", "audit", "process.exec", "42"); otherBoot == first {
		t.Fatal("source event ID was reused across boots")
	}
	finding := FindingID("rule", "1", first)
	if retry := FindingID("rule", "1", first); retry != finding {
		t.Fatalf("finding ID changed: %q != %q", retry, finding)
	}
	if otherVersion := FindingID("rule", "2", first); otherVersion == finding {
		t.Fatal("finding ID was reused across rule versions")
	}
}
