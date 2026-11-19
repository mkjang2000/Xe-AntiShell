Name:           xe-antishell
Version:        0.1.0
Release:        37%{?dist}
Summary:        Standalone Linux host security monitoring agent
License:        MIT AND Apache-2.0 AND BSD-3-Clause AND BSD-2-Clause AND BSD-1-Clause AND SunPro
URL:            https://github.com/mkjang2000/Xe-AntiShell
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  golang >= 1.22
BuildRequires:  make
BuildRequires:  systemd
Requires(pre):  shadow-utils

%global debug_package %{nil}

%description
Xe-AntiShell discovers host observation capabilities, consumes supported local
security event sources, builds process lineage, and performs local detection.

%prep
%autosetup

%build
GOWORK=off GOTOOLCHAIN=local %{__make} static PACKAGE_EPOCH=%{?epoch}%{!?epoch:0} PACKAGE_VERSION=%{version} PACKAGE_RELEASE=%{release} PACKAGE_ARCH=%{_arch}

%install
install -D -m 0750 build/sentineld %{buildroot}%{_sbindir}/sentineld
install -D -m 0755 build/sentinel %{buildroot}%{_bindir}/sentinel
install -D -m 0755 build/sentinel-web %{buildroot}%{_sbindir}/sentinel-web
install -D -m 0750 build/sentinel-updater %{buildroot}%{_sbindir}/sentinel-updater
install -D -m 0640 configs/sentineld.yaml %{buildroot}%{_sysconfdir}/xe-antishell/sentineld.yaml
install -D -m 0644 packaging/systemd/sentineld.service %{buildroot}%{_unitdir}/sentineld.service
install -D -m 0644 packaging/systemd/sentinel-web.service %{buildroot}%{_unitdir}/sentinel-web.service
install -D -m 0644 packaging/systemd/sentinel-updater.service %{buildroot}%{_unitdir}/sentinel-updater.service
install -D -m 0644 packaging/audit/xe-antishell.conf %{buildroot}%{_datadir}/xe-antishell/audit/xe-antishell.conf
install -D -m 0644 packaging/audit/90-xe-antishell.rules %{buildroot}%{_datadir}/xe-antishell/audit/90-xe-antishell.rules
install -d -m 0750 %{buildroot}%{_localstatedir}/lib/xe-antishell

%files
%doc README.md
%license LICENSE THIRD_PARTY_NOTICES.md third_party/licenses
%{_sbindir}/sentineld
%{_bindir}/sentinel
%{_sbindir}/sentinel-web
%{_sbindir}/sentinel-updater
%config(noreplace) %{_sysconfdir}/xe-antishell/sentineld.yaml
%dir %{_datadir}/xe-antishell
%dir %{_datadir}/xe-antishell/audit
%{_datadir}/xe-antishell/audit/xe-antishell.conf
%{_datadir}/xe-antishell/audit/90-xe-antishell.rules
%{_unitdir}/sentineld.service
%{_unitdir}/sentinel-web.service
%{_unitdir}/sentinel-updater.service
%dir %{_localstatedir}/lib/xe-antishell

%pre
getent group xe-antishell >/dev/null || groupadd -r xe-antishell
getent passwd xe-antishell-web >/dev/null || useradd -r -g xe-antishell -d / -s /sbin/nologin -c "Xe-AntiShell web panel" xe-antishell-web

%post
%systemd_post sentineld.service

%preun
if [ "$1" -eq 0 ]; then
    # A managed removal must journal authorization before services stop.
    /usr/bin/sentinel managed removal-check >/dev/null || exit 1
fi
%systemd_preun sentineld.service sentinel-web.service sentinel-updater.service

%postun
%systemd_postun_with_restart sentineld.service
%systemd_postun_with_restart sentinel-web.service

%changelog
* Thu Nov 19 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-37
- Evaluate signed application policies for verified systemd services
- Report policy receipts and application provenance to Central

* Thu Nov 19 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-36
- Apply signed rule controls and expiring exceptions per service
- Measure approved agent files and policy in a bounded background worker
- Compare managed policy candidates against a local observation sample

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-35
- Apply signed service observation scopes and report the effective scope source

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-34
- Detect writes to protected directories and unexpected TCP destinations for configured services
- Advance observation cleanup through retained evidence in bounded batches

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-33
- Permit the normal SELinux RPM scriptlet transition in the signed package updater

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-32
- Store and deliver compact observations while preserving source identity and detection evidence
- Apply a one-hour observation history default to existing RPM deployments with no explicit setting

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-31
- Use the boot and stream sequence index at startup on hosts with large event history

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-30
- Reduce database maintenance contention with incoming observations on busy hosts

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-29
- Recover interrupted Tetragon subscriptions and report confirmed collection gaps
- Expose built-in rule status, offline comparisons and service-scoped file/TCP samples
- Measure daily event storage, delivery backlog, loss and acknowledgement recovery

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-28
- Reduce credential validation and Tetragon conversion allocation costs without changing evidence
- Keep strict input checks, mutable ownership and unknown credential semantics
- Accept eight-character composed local passwords while preserving legacy login

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-27
- Accept the upstream canonical empty policy list when attaching the first sensor
- Drain acknowledged central delivery backlog in bounded batches with fair yields
- Preserve idle pacing, cancellation, ordered ACKs and exponential failure backoff

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-26
- Add opt-in global root-execution and same-hook credential transition detection
- Reconcile one fixed monitor-only kernel policy with receipt-based capability evidence
- Keep new findings detection-only and show paired proof in Korean history details

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-25
- Serialize SQLite access and retry transient observation writer reservation
- Recover operation-specific storage errors after successful evidence persistence
- Stagger startup work and defer bounded retention without delaying collection

* Wed Nov 18 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-24
- Require an independent build-publisher signature before remote installation
- Verify live execution collection after restart and report explicit outcomes
- Include the managed updater bootstrap and complete RPM build identities

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-23
- Add enrollment-bound signed RPM update staging and a separate updater service
- Report running build and installed package identities independently

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-22
- Strengthen detection-only direct execution and interpreter evidence
- Add bounded monitor-only file writes and TCP initiation observations
- Preserve operation source metadata and process lifecycle across delayed events

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-21
- Separate local process observation times from source lifecycle timestamps
- Preserve valid observation bounds and idempotence for delayed Tetragon events

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-20
- Probe the configured collector executable instead of unrelated PATH candidates
- Present live collection separately from passive diagnostic mismatches

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-19
- Offer opt-in pinned Tetragon setup and collector-only installation
- Verify actual process observation before switching collectors; restore on failure

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-18
- Report safe enrollment failure stages and transport categories in status and journal
- Preserve pending identity, recovery credentials and transport sentinel compatibility

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-17
- Add step-by-step terminal setup while retaining scripted installation options
- Enroll from a single installation code with pinned CA and automatic local recovery preparation
* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-16
- Package only the host agent, local CLI and local monitoring panel
- Transfer central binaries and service ownership to xe-antishell-central
- Keep existing central state intact for coordinated package migration

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-15
- Add opt-in web-origin process behavior rules and bounded risk explanations
- Keep extended findings detection-only with signed-policy compatibility
- Validate exact audit arguments and provide isolated detection scenarios

* Tue Nov 17 2026 mkjang2000 and Xe-AntiShell contributors - 0.1.0-14
- License project code under MIT and set the public repository URL
- Include upstream dependency notices in source and binary distributions

* Mon Nov 16 2026 Xe-AntiShell contributors - 0.1.0-13
- Add source-build installation and credential-preserving preflight checks
- Prepare source hygiene checks, repeatable build commands and CI
- Ship audit templates outside live configuration for explicit activation

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-12
- Reorganize monitoring for operators with compact Korean status and evidence rows
- Add retained-history summaries, self-test filtering, and Korean finding search

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-11
- Restore the diagonal-cut XE mark and use angular panel controls
- Default to an accessible light palette with an optional persisted dark theme

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-10
- Add authenticated central delivery, signed policy, one-use removal authorization
- Add host resource monitoring and accessible grouped, paginated history panel

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-9
- Add runtime capability evidence and collapsed unimplemented monitoring menu
- Validate Tetragon credentials, ancestry, and bounded candidate persistence

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-8
- Allow opaque browser origins only over a loopback forwarding path

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-7
- Permit an explicitly configured non-loopback web listener

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-6
- Accept equivalent loopback host names in web login origin checks

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-5
- Bound concurrent password hashing during local panel login

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-4
- Add authenticated loopback-only monitoring web panel

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-3
- Bound audit evidence to configured detection origins on busy hosts

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-2
- Add monitor-only audit packaging, live lineage bootstrap, and runtime fixes

* Mon Nov 16 2026 Xe-AntiShell Developers <security@example.invalid> - 0.1.0-1
- Initial standalone MVP package skeleton
