# Install from a published RPM

Allow a standalone copy of install.sh to start the existing terminal wizard.
The wizard continues to prefer a compatible local RPM and retains manual and
source-build choices. If it has neither a local match nor a source checkout,
it prepares the pinned published RPM for Rocky Linux 9 or 10 on x86_64.

The downloaded script serves as the trust anchor. Pin the release and both RPM
SHA-256 values in it, together with the immutable source revision and digests
of any missing wizard and Tetragon installer helpers. Fetch over HTTPS into a
private temporary directory and check each digest before using the file. Check
the RPM package name, version, release, epoch and architecture before offering
it to the wizard. Keep host changes behind the existing confirmation.

The explicit local RPM and source-build paths retain their existing behavior.
The standalone copy fetches the optional Tetragon helpers only when opted in.
Unsupported OS/architecture combinations retain the manual RPM choice. A
network or digest failure stops before RPM installation. The install trap
removes downloaded material and restores the terminal on exit.

Exercise OS selection, hash/metadata rejection, local RPM priority, cleanup,
and the normal wizard flow with mocked host commands.
