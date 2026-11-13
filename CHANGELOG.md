# Changelog

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
