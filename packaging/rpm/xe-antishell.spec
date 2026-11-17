Name:           xe-antishell
Version:        0.1.0
Release:        19%{?dist}
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
GOWORK=off GOTOOLCHAIN=local %{__make} static

%install
install -D -m 0750 build/sentineld %{buildroot}%{_sbindir}/sentineld
install -D -m 0755 build/sentinel %{buildroot}%{_bindir}/sentinel
install -D -m 0755 build/sentinel-web %{buildroot}%{_sbindir}/sentinel-web
install -D -m 0640 configs/sentineld.yaml %{buildroot}%{_sysconfdir}/xe-antishell/sentineld.yaml
install -D -m 0644 packaging/systemd/sentineld.service %{buildroot}%{_unitdir}/sentineld.service
install -D -m 0644 packaging/systemd/sentinel-web.service %{buildroot}%{_unitdir}/sentinel-web.service
install -D -m 0644 packaging/audit/xe-antishell.conf %{buildroot}%{_datadir}/xe-antishell/audit/xe-antishell.conf
install -D -m 0644 packaging/audit/90-xe-antishell.rules %{buildroot}%{_datadir}/xe-antishell/audit/90-xe-antishell.rules
install -d -m 0750 %{buildroot}%{_localstatedir}/lib/xe-antishell

%files
%doc README.md
%license LICENSE THIRD_PARTY_NOTICES.md third_party/licenses
%{_sbindir}/sentineld
%{_bindir}/sentinel
%{_sbindir}/sentinel-web
%config(noreplace) %{_sysconfdir}/xe-antishell/sentineld.yaml
%dir %{_datadir}/xe-antishell
%dir %{_datadir}/xe-antishell/audit
%{_datadir}/xe-antishell/audit/xe-antishell.conf
%{_datadir}/xe-antishell/audit/90-xe-antishell.rules
%{_unitdir}/sentineld.service
%{_unitdir}/sentinel-web.service
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
%systemd_preun sentineld.service sentinel-web.service

%postun
%systemd_postun_with_restart sentineld.service
%systemd_postun_with_restart sentinel-web.service

%changelog
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
