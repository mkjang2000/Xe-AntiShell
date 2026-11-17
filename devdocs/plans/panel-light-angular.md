# Light Default and Angular Monitoring Panel

## Purpose and Acceptance

Restore the earlier XE mark with diagonal top-left/bottom-right cuts. Prefer
straight edges and restrained 2px corners over rounded cards/pills. Use a light
default with white panels, pale neutral canvas and deep teal accents. Retain
the existing dark palette as an explicit user choice. Preserve readable type,
keyboard controls, history grouping/pagination and monitoring functionality.

## Scope and Design

Only embedded panel assets, appearance checks and the package release change.
Keep backend/authentication/detection/central policy behavior unchanged. Use
semantic CSS tokens for both palettes, including disabled controls, placeholder
text, neutral/status badges and primary-button text. All controls keep their
existing 44px minimum height and visible keyboard focus.

Light applies without JavaScript, without stored preferences and regardless of
the OS preference. A small shared head script restores an explicitly stored
light/dark choice before paint; buttons on login/dashboard expose pressed state.
Unknown/denied browser storage falls back to light and does not break navigation.
The preference contains no credentials or monitoring data.

## Validation and Deployment

Validate actual token contrast in both themes, preference behavior, existing
web-panel tests and static compilation. Check real Chrome login, all tabs,
theme persistence, keyboard use and 375px layouts with axe/Lighthouse. Ship RPM
release 11 and restart the web panel on the current validation server. Preserve
host configuration, policy, monitoring data and credentials.

## Validation Results

Both themes passed real Chrome axe checks for login and all four monitoring
tabs (zero violations), persisted selection across reload/login, and fit 375px
without document overflow or JavaScript errors. The light-default Lighthouse
accessibility score is 100. Text/control contrast minima are 4.58/3.50 in light
and 6.97/3.41 in dark. Relevant Go tests, race checks, vet and static RPM build
passed. The former diagonal-cut logo and 2px panel/control corners were also
inspected in desktop/mobile screenshots.
