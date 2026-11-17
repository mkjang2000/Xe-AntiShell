package buildinfo

import "testing"

func TestRunningPackageIdentitySeparatesEpochAndSourceBuild(t *testing.T) {
	oldEpoch, oldVersion, oldRelease, oldArch := PackageEpoch, PackageVersion, PackageRelease, PackageArch
	defer func() {
		PackageEpoch, PackageVersion, PackageRelease, PackageArch = oldEpoch, oldVersion, oldRelease, oldArch
	}()
	for _, test := range []struct{ epoch, version, release, arch, want string }{
		{"0", "0.1.0-dev", "", "", "0.1.0-dev"},
		{"0", "0.1.0", "23.el9", "x86_64", "0.1.0-23.el9.x86_64"},
		{"2", "0.1.0", "23.el9", "x86_64", "2:0.1.0-23.el9.x86_64"},
		{"invalid", "0.1.0", "23.el9", "x86_64", "unknown"},
	} {
		PackageEpoch, PackageVersion, PackageRelease, PackageArch = test.epoch, test.version, test.release, test.arch
		if got := RunningVersion(); got != test.want {
			t.Fatalf("running identity %q, want %q", got, test.want)
		}
	}
}
