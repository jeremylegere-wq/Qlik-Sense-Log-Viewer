# Changelog

## 5.1.1 (2026-11-21)
- **Fixed: Reload failures and Reloads showed unreadable error text, and the Excel export failed because of it.** A reload
  log can hold control characters (NULs, terminal colour codes, bell) in an error line, or end in a run of NUL padding.
  The error text then showed as garbage, and Excel refused the cell (`IllegalCharacterError`), which stopped the whole
  summary workbook. Reload logs padded with NULs were also read as "running" with no error.
  - Control characters are now taken out when the logs are read (reload logs and the free-text columns of the Scheduler
    and engine logs) and again when the failures table is built.
  - NUL padding at the end of a reload log is skipped, so the real last lines and error are found.
  - The Excel export cleans every sheet and drops time zones (Excel can't store them). If a sheet still can't be written it
    is left out and named on the page, instead of the whole workbook failing.
  - Tests cover each case (reload logs in UTF-8 and UTF-16, NUL padding, the failures table, the export).

## 5.1.0 (2026-11-13)
- **Log setup guide** (new page under Share): how to set up Qlik Sense logging so history can be pulled. The QMC engine
  logging settings to check (with Qlik's defaults), which log types each page needs, the folder layout, retention
  starting points, why reload script logs need their own copy, and a move-not-delete archive script
  (robocopy `/MOV /MINAGE`, dry run by default, downloadable) built from your source and history folders.
- **History check**: from the archive listing, shows how many days each log type goes back, how long since the newest
  file, the biggest gap, log types missing altogether, and a size estimate for the days you want to keep.
- **Where your logs come from**: the Load logs panel now starts with a choice of Qlik server share, Local folder or
  Upload files, and shows only the boxes for the one you pick.

## 5.0.0 (2026-11-12)
First public release.

- Events from the Qlik Sense logs (request storms, CPU, memory, reload pile-ups, failures and time-outs, login and
  proxy problems, engine restarts) with status, owner, ticket and notes kept between runs.
- Reported issues: register, coverage check, timeline, ranked likely causes with evidence, incident note, Jira Rovo
  prompt, trends and bulk import.
- Engine restart detection from the performance log, restart causes and restart history; the engine's own restart
  reason (watchdog line), stuck requests and core dumps read from the engine system log.
- Qlik Community search on events, restarts, reported issues, reload failures and its own page, with site detail
  taken out of every search.
- Apps (QMC export), Storage (share scan), Reload failures with reasons, Logins & proxy, Server CPU, Reloads,
  Requests and engine views; CSV and Excel export.
- All site settings in `site_config.py`.
