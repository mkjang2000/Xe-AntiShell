// Package buildinfo identifies the running binary independently of RPM's
// installed-package database. RPM builds inject the three package variables.
package buildinfo

import "strconv"

var (
	PackageEpoch   = "0"
	PackageVersion = "0.1.0-dev"
	PackageRelease = ""
	PackageArch    = ""
)

func RunningVersion() string {
	if PackageRelease == "" || PackageArch == "" {
		return PackageVersion
	}
	version := PackageVersion + "-" + PackageRelease + "." + PackageArch
	epoch, err := strconv.ParseUint(PackageEpoch, 10, 32)
	if err != nil {
		return "unknown"
	}
	if epoch != 0 {
		version = strconv.FormatUint(epoch, 10) + ":" + version
	}
	return version
}
