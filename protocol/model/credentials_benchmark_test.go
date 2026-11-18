package model

import (
	"sort"
	"testing"
)

var credentialBenchmarkErr error
var credentialBenchmarkBool bool

func benchmarkCredentialSnapshot(unsorted bool) *CredentialSnapshot {
	names := []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE"}
	sort.Strings(names)
	if unsorted {
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
	}
	s := completeCredential(0)
	s.Capabilities.Effective = append([]string{}, names...)
	s.Capabilities.Permitted = append([]string{}, names...)
	return s
}
func BenchmarkCredentialSnapshotValidate(b *testing.B) {
	for _, test := range []struct {
		name     string
		snapshot *CredentialSnapshot
	}{
		{"Sorted41", benchmarkCredentialSnapshot(false)},
		{"Unsorted41", benchmarkCredentialSnapshot(true)},
		{"Empty", completeCredential(0)},
	} {
		for _, baseline := range []bool{true, false} {
			name := test.name + "/Current"
			if baseline {
				name = test.name + "/Legacy"
			}
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if baseline {
						credentialBenchmarkErr = legacyCredentialValidate(test.snapshot)
					} else {
						credentialBenchmarkErr = test.snapshot.Validate()
					}
				}
			})
		}
	}
}
func BenchmarkCredentialSnapshotComplete(b *testing.B) {
	partial := benchmarkCredentialSnapshot(false)
	partial.EUID = nil
	for _, test := range []struct {
		name     string
		snapshot *CredentialSnapshot
	}{{"Sorted41", benchmarkCredentialSnapshot(false)}, {"Partial", partial}} {
		for _, baseline := range []bool{true, false} {
			name := test.name + "/Current"
			if baseline {
				name = test.name + "/Legacy"
			}
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if baseline {
						credentialBenchmarkBool = legacyCredentialComplete(test.snapshot)
					} else {
						credentialBenchmarkBool = test.snapshot.Complete()
					}
				}
			})
		}
	}
}
func BenchmarkCredentialObservationValidate(b *testing.B) {
	zero := int64(0)
	o := &CredentialObservation{Before: benchmarkCredentialSnapshot(false), After: benchmarkCredentialSnapshot(false), TGID: 12, TID: 14, TaskStartTimeNS: 90, Evidence: CredentialEvidence, PolicyName: CredentialPolicyName, Function: "commit_creds", ReturnValue: &zero, Outcome: "applied"}
	for _, baseline := range []bool{true, false} {
		name := "Current"
		if baseline {
			name = "Legacy"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if baseline {
					credentialBenchmarkErr = legacyCredentialObservationValidate(o)
				} else {
					credentialBenchmarkErr = o.Validate()
				}
			}
		})
	}
}
func BenchmarkCredentialSnapshotEqual(b *testing.B) {
	s := benchmarkCredentialSnapshot(false)
	other := s.Clone()
	for _, baseline := range []bool{true, false} {
		name := "Current"
		if baseline {
			name = "Legacy"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if baseline {
					credentialBenchmarkBool = legacyCredentialEqual(s, other)
				} else {
					credentialBenchmarkBool = s.Equal(other)
				}
			}
		})
	}
}
