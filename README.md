# Incident Response: TrojanClicker:Win32/Doplik (ChromeLoader-style) Infection

Personal incident response exercise — full investigation, forensic verification, and remediation of a real ISO-delivered trojan detected on a Windows device, documented start to finish.

## Summary

On 9/23/2026, Windows Defender flagged multiple `TrojanClicker:Win32/Doplik` and `Trojan:BAT/Starter.G!lnk` detections tied to ISO files downloaded from an untrustworthy anime streaming/download site. Rather than relying solely on antivirus remediation, I ran a full manual investigation and used OS-level forensic artifacts to independently verify whether the malicious payload had actually executed — not just whether it existed on disk.

**Result:** two independent AV scans (offline + full) returned 0 threats, every known persistence mechanism for this malware family was checked and ruled out by hand, and forensic artifact analysis (Prefetch, Amcache) confirmed the payload was written to disk but never executed as a process — real-time protection intercepted the infection chain before it could run.

## What's in this repo

- [`incident-report-doplik-chromeloader.md`](./incident-report-doplik-chromeloader.md) — full write-up: detection timeline, infection chain diagram, investigation checklist, forensic execution analysis, findings, and sources

## Methodology

- Reconstructed a full detection timeline from Windows Security's Protection History
- Mapped the infection chain: ISO → disguised shortcut (`.lnk`) → hidden batch script → dropped payload
- Manually checked every known persistence mechanism for this malware family:
  - Registry Run keys (`HKCU` and `HKLM`, including the `WOW6432Node` mirror)
  - Task Scheduler
  - Common drop locations in `%APPDATA%` / `%LOCALAPPDATA%`
  - Browser extensions (Chrome, Edge, Opera GX)
- Ran independent AV verification: Microsoft Defender offline scan, full scan, and Malwarebytes
- Used OS-level forensic artifacts — Prefetch and Amcache (parsed with AmcacheParser) — to verify actual process execution, distinguishing "written to disk" from "ran as a process"
- Cross-referenced published threat research to identify the likely malware family and its known distribution pattern

## Tools used

- Windows Security / Microsoft Defender (Protection History, offline scan, full scan)
- Registry Editor
- Task Scheduler
- Malwarebytes
- AmcacheParser (Eric Zimmerman's forensic tooling)
- Windows Prefetch analysis

## Key takeaway

Detection isn't the same as compromise. The most useful part of this investigation wasn't confirming Defender caught something — it was independently proving, through artifacts outside Defender's own reporting, that the payload never actually ran.

## Disclaimer

This was a real infection on a personal device, documented as a practical exercise. Identifying details (usernames, device-specific file paths) have been generalized or omitted where not relevant to the technical findings.
