# Changelog

All notable changes to this project are documented in this file.

## v1.0.2 - 2026-03-04

### Added
- Dedicated password reset prompt screen (no dashboard navigation shown while reset is required).
- Admin-first-login enforcement hardening:
  - login with `admin/admin` forces DB-level `must_reset_password=1`
  - redirect to reset prompt happens before dashboard access.
- Session security improvements:
  - unique session ID per login
  - session destroyed on logout
  - automatic session invalidation after 15 minutes of inactivity.
- Cache clear workflow:
  - `Clear Cache` UI action
  - no-cache headers across HTML, redirects, and downloads.
- Instance drill-down page:
  - clickable `Total Instances` in components view
  - detailed per-scan/per-project instance breakdown.

### Changed
- UI visual refresh for more enterprise/professional styling (navigation, cards, tables, controls, buttons).
- Excel export formatting in UI improved to table-like structure with:
  - ordered columns
  - fixed column widths
  - wrapped text and borders
  - numeric typing for count columns
  - cleaner values for versions/source files/detection methods.

## v1.0.1 - 2026-03-04

### Added
- UI now shows active link in scanner output when UI is running (`ai-sbom.py` reads UI status metadata).
- Improved filter UX in UI with category dropdown, search, quick category chips, reset action, and summary stats.
- Admin security controls:
  - Admin can reset credentials for any user.
  - Admin can delete users (with safeguards to keep at least one admin).
  - Mandatory admin password reset on first login.
- Password complexity policy for reset/add-user flows:
  - minimum 8 characters
  - at least one uppercase letter
  - at least one number
  - at least one special character

### Changed
- Scanner/UI DB handling updated to align with active DB link usage (`ai_sbom_active_db.txt`) and current scan flow.
- UI scan trigger updated to call scanner with supported DB arguments only.

### UI/Report Enhancements
- Category-wise color highlighting added across:
  - UI category chips and category badges in findings/components tables
  - HTML report sections and instance badges
  - Excel exports (scanner and UI) with category-based styling
- UI pages now present clearer findings totals and per-category counts for better readability.

### Fixed
- Improved compatibility between `ai-sbom-ui.py` and `ai-sbom.py` CLI argument changes.

