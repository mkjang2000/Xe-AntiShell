# Operator Monitoring Workflow

## Purpose

Restructure the panel for server operators and security staff with intermediate
security knowledge. Lead with collection health, reviewable findings, effective
response mode and operational exceptions. Increase useful desktop density through
compact rows/tables and reduced whitespace while retaining readable type, angular
branding, light default, optional dark mode and keyboard/touch accessibility.

## Information Design

- Operations: four compact metrics, actual operational issues, recent real
  findings, service history and resource snapshot in two desktop columns.
- Review findings: Korean behavior titles, severity and response results, ten
  records per page grouped by service, technical evidence under disclosure.
- Execution history: searchable retained evidence, plain-language event types,
  original paths/IDs/raw descriptions in details.
- System and collection: concise feature rows with exactly one primary status;
  alternate collectors are '사용 안함', verified active collection overrides a
  merely passive 'limited' prerequisite. Genuine contradictions/errors remain
  explicit. Kernel/probe metadata and original English reasons stay in details.

Do not infer prevention from process observation, pidfd availability, or a
signed policy alone. Show the effective detection/response mode from agent state.
Keep integrity verification and planned features clearly separate from currently
implemented collection. Technical detail remains available to security analysts.

## Data and Compatibility

Add a read-only summary computed from all retained records instead of counting
only the most recent 100 findings. Include rolling-24-hour totals, open finding
counts, separate self-test counts, recent real findings, and effective response
mode. Known self-test service history is hidden by default in the findings UI
with an explicit inclusion control and separate count. API defaults preserve
existing all-history behavior. Cursors include the new filter in their scope.

Do not add case-resolution mutations, new detector rules, enforcement changes or
resource alarm thresholds. Unknown/missing summary values are unavailable, never
silently zero. Raw values are rendered with textContent, never HTML.

## Modules and Validation

Separate shared labels, operator overview and feature presentation from polling
and navigation. Preserve history cursors, group expansion, refresh, process
pagination, theme preference, login and origin behavior. Test real count windows,
self-test grouping/filter scope, capability precedence, missing/error values,
Korean presentation and safe raw disclosures. Run relevant Go tests/race/vet,
static/RPM build and real Chrome tests for both themes, mobile, keyboard,
information density and automated accessibility. Deploy release 12 to this host
with existing policy and credentials preserved.

## Completed Validation

Release 12 is installed on the validation host. Real retained records were
cross-checked: 10 operational findings plus 8 self-test findings matched the
original 18 records. These are a validation snapshot, not fixed counts. The
effective response mode is observe; central enrollment and policy revision 1
remain active.

Full Go tests/race/vet and static RPM build passed. Real Chrome checks passed
for all four tabs in light/dark, Korean finding search, self-test exclusion and
inclusion, cursor paging, recent-finding navigation/filter reset, focus retention,
375px/720px layouts and expanded record/action placement. Axe reported no
violations in the eight tab/theme scans; Lighthouse accessibility scored 100.

At the same 1440px desktop width the complete operations view measured 1125px
high, compared with 2027px for the preceding layout (about 44% less vertical
scroll content). Metadata remains at least 12px, body 16px and interactive
targets at least 44px; the decorative logo lettering retains its original size.
Screenshots and ephemeral browser summaries are in `/tmp/xeas-web-qa/`.
