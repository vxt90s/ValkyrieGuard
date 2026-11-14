# ValkyrieGuard

A Windows desktop tool that combines two scanners in one dark-themed window:

| Part | What it does | Engine |
|---|---|---|
| **System Audit** | Read-only check of this PC: Defender, firewall, UAC, accounts, listening ports, auto-start items, risky programs (signature + SHA-256), shares, failed logins. Results are written in plain English. | PowerShell script (`valkyrieguard/resources/security_audit.ps1`) |
| **Network Scan** | Multi-threaded TCP port scan, banner grabbing, service detection and CVE-pattern matching. | Pure Python (`valkyrieguard/scanner.py`) |

Both feed one **Dashboard** (verdict + severity cards) and one combined **HTML / JSON report**.

> Only scan systems you own or have written permission to test.

## Quick start

Pick **one** way. All of them end with the ValkyrieGuard window opening.

**A. Download from GitHub (git)**
```
git clone https://github.com/vxt90s/ValkyrieGuard.git
cd ValkyrieGuard
python main.py
```

**B. Download the ZIP**
1. Right-click the zip > **Extract All** (Windows creates the folder for you).
2. Open the extracted folder. You must see `main.py` in it. If you only see another folder, open that one.
3. Click the address bar of the folder window, type `powershell`, press Enter, then run `python main.py`.

**C. Double-click** `run_valkyrieguard.bat` - it works from any location, no terminal needed.

**D. Install it once, run it from anywhere**
```
pip install .
valkyrieguard-gui
```
(`valkyrieguard` starts the same window with a console.)

Other commands (run them inside the project folder):
```
python -m valkyrieguard        # same as main.py
python main.py --selftest      # run all 17 tests
```

> **Check you are in the right folder:** `dir main.py` (Windows) or `ls main.py` (Linux/macOS) must list the file.
> `can't open file main.py` or `No module named valkyrieguard` always means you are one folder too high or too low.

Requirements: Python 3.9+ (standard library only). On Windows keep "tcl/tk and IDLE" ticked in the Python installer.
For the full audit click **Restart as Administrator** (top right); Windows shows its normal UAC permission pop-up.

## Folder structure

```
ValkyrieGuard/
├── main.py                      launcher
├── pyproject.toml               makes `pip install .` and the valkyrieguard-gui command work
├── .gitattributes               keeps .bat/.ps1 line endings correct on GitHub
├── run_valkyrieguard.bat        Windows double-click launcher
├── requirements.txt             (stdlib only)
├── data/
│   └── vulns.example.json       copy to vulns.json to override the built-in CVE signatures
├── valkyrieguard/
│   ├── cli.py                   entry point (GUI or --selftest)
│   ├── config.py                paths, ports, notes, built-in CVE signatures, levels
│   ├── models.py                Vulnerability / ScanResult + severity helpers
│   ├── vuln_db.py               regex signature database
│   ├── scanner.py               port parsing, banner grabbing, PortScanner (threads)
│   ├── intel.py                 optional Shodan InternetDB lookup
│   ├── audit.py                 AuditRunner: runs the PowerShell audit, reads JSON + report
│   ├── report.py                combined HTML report (all values escaped)
│   ├── system.py                is_admin() and UAC elevation (ShellExecuteW "runas")
│   ├── resources/
│   │   └── security_audit.ps1   the Windows audit (also runs stand-alone)
│   └── gui/
│       ├── base.py              typed declarations shared by the tabs (keeps Pylance happy)
│       ├── theme.py             colours, ttk style, widget factories
│       ├── main_window.py       App: wiring, header, queue pump, shutdown
│       ├── dashboard_tab.py     verdict, cards, full scan, exports
│       ├── audit_tab.py         System Audit tab
│       ├── scan_tab.py          Network Scan tab
│       └── log_tab.py           Log tab
└── tests/
    ├── test_core.py             signatures, parsing, live scan, HTML escaping, script contract
    ├── test_audit.py            runs the real audit script (skipped without PowerShell)
    └── test_gui_smoke.py        drives the real window (skipped without a display)
```

## How the pieces talk

```
GUI thread (Tk)  <──queue.Queue──  worker threads
   App._poll() every 100 ms          AuditRunner.run()  ── powershell -File security_audit.ps1 -JsonOut -ReportOut -NoOpen
   App._handle(message)              PortScanner.run()  ── ThreadPoolExecutor
```

Worker threads never touch widgets; they only put tuples on the queue, and the GUI thread applies them.

## Using the audit script on its own

```
powershell -ExecutionPolicy Bypass -File valkyrieguard\resources\security_audit.ps1
```
It saves `Security_Audit_Report_<date>.txt` on the Desktop and opens it. Extra switches used by the GUI:
`-JsonOut <file>`, `-ReportOut <file>`, `-NoOpen`.

## Custom CVE signatures

Copy `data/vulns.example.json` to `data/vulns.json` and edit it. Format:
`{"ssh": [{"version_pattern": "regex", "cve": "CVE-...", "severity": "HIGH", "description": "..."}]}`

Matches are based on version text only, so treat them as "possible" and confirm before acting.

## Troubleshooting

| Problem | Fix |
|---|---|
| "The audit script finished but wrote no results" | The message includes the last lines of PowerShell output. Run the script on its own (see above) to see the error. |
| System Audit says Windows only | The audit uses PowerShell/Windows cmdlets. The Network Scan works on any OS. |
| `can't open file main.py` / `No module named valkyrieguard` | Wrong folder (usually a zip extracted inside a same-named folder). Run `dir main.py`; if it is missing, `cd` into the folder that contains it. Or use `run_valkyrieguard.bat`, or `pip install .` and run `valkyrieguard-gui`. |
| Many checks say "limited" | Click **Restart as Administrator**. |
| "Open File - Security Warning" | Normal for downloaded files: right-click > Properties > Unblock. |
| Non-local target refused | Tick the permission box (only if you really may scan it). |

## Development checks

```
python -m pyflakes .
python -m pyright .
python main.py --selftest
```
