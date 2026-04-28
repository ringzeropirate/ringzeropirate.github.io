---
title: "Il tuo primo hook eBPF: monitoraggio syscall con bpftrace in 30 minuti"
translationKey: "ebpf-first-hook-bpftrace"
date: 2026-04-28
author: "Michele Piccinni aka RZP"
tags: ["ebpf", "bpftrace", "syscall", "threat-detection", "linux", "security-engineering", "devsecops", "sre", "mitre-attack"]
categories: ["Deep Technical Lab", "eBPF Security & Observability"]
description: "Lab completo per scrivere il tuo primo hook eBPF con bpftrace: monitoraggio in tempo reale di sys_execve, sys_openat e sys_connect con output JSON per SIEM. Dalla teoria alla pipeline funzionante in 30 minuti, con mapping MITRE ATT&CK T1059, T1027 e T1071."
draft: false
series: "eBPF Security & Observability"
series_order: 1
---
**Tempo di lettura:** 15 minuti | **Tempo lab:** 30 minuti

# Il tuo primo hook eBPF: monitoraggio syscall con bpftrace in 30 minuti

> **Serie:** eBPF Security & Observability — Settimana 1, Giovedì  
> **Tipo:** Deep Technical Lab  
> **Strumento principale:** bpftrace  
> **Target:** Developer, Security Engineer, SRE  
> **Tempo di lettura:** ~15 minuti  
> **Tempo lab:** 30 minuti  

---

![Copertina sudo](/images/eBpf/primo_hook.png)

---

Hai mai voluto sapere esattamente cosa sta facendo il tuo sistema operativo in questo preciso momento — quali processi si stanno avviando, quali file vengono aperti, quali connessioni di rete vengono stabilite — senza installare agenti pesanti, senza riavviare nulla, senza modificare una riga di codice delle tue applicazioni?

Questo articolo ti mostra come farlo in 30 minuti usando **bpftrace**, uno degli strumenti più potenti e sottovalutati nell'arsenale di un security engineer o SRE. Alla fine avrai un sistema di monitoraggio delle syscall funzionante, con output JSON pronto per essere ingerito da qualsiasi SIEM.

---

## Cos'è bpftrace e perché dovresti impararlo adesso

bpftrace è un linguaggio di scripting ad alto livello per scrivere programmi eBPF senza dover gestire la complessità del C o del linker del kernel. Pensa a esso come a `awk` per il kernel Linux: espressivo, compatto, immediatamente eseguibile.

La sua caratteristica più importante dal punto di vista della sicurezza è questa: opera direttamente nel kernel, a livello di syscall, **prima che qualsiasi layer di astrazione possa modificare o sopprimere gli eventi**. Un malware che cerca di nascondersi manipolando i log di sistema, i file in `/proc` o gli hook userspace non ha scampo contro un probe bpftrace attaccato alla tracepoint corretta.

Nel 2024, strumenti come Falco e Tetragon — di cui parleremo nelle prossime settimane — usano eBPF sotto il cofano esattamente per questo motivo. Capire bpftrace ti dà le fondamenta per comprendere come funzionano quegli strumenti a livello architetturale, e ti permette di scrivere detector personalizzati per casi d'uso che nessun tool preconfezionato copre.

---

## Setup dell'ambiente

Il lab è testato su **Ubuntu 24.04 LTS** con kernel 6.08 o superiore. Se usi una versione diversa di Linux, bpftrace funziona su qualsiasi kernel ≥ 4.9, ma alcune tracepoint potrebbero avere nomi leggermente diversi.

### Installazione

```bash
sudo apt update
sudo apt install -y bpftrace linux-headers-$(uname -r)
```

Verifica che l'installazione sia andata a buon fine:

```bash
bpftrace --version
```

Output atteso:

```
bpftrace v0.20.0
```

Verifica che le tracepoint del kernel siano disponibili:

```bash
sudo bpftrace -l 'tracepoint:syscalls:*' | head -20
```

Output atteso (prime 20 righe):

```
tracepoint:syscalls:sys_enter_accept
tracepoint:syscalls:sys_enter_accept4
tracepoint:syscalls:sys_enter_access
tracepoint:syscalls:sys_enter_acct
tracepoint:syscalls:sys_enter_add_key
...
```

Se vedi questa lista, sei pronto. Se ricevi un errore di permessi, assicurati di eseguire i comandi con `sudo`.

---

## Il tuo primo programma bpftrace: tracciare sys_execve

`sys_execve` è la syscall che il kernel esegue ogni volta che un processo ne lancia un altro. È il punto di ingresso di qualsiasi esecuzione di comando nel sistema — e uno dei vettori più monitorati nel framework MITRE ATT&CK (tecnica **T1059: Command and Scripting Interpreter**).

Inizia con la versione più semplice possibile:

```bash
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_execve {
  printf("PID: %d | COMM: %s | CMD: %s\n",
    pid,
    comm,
    str(args->filename));
}'
```

Apri un altro terminale e digita qualsiasi comando, ad esempio `ls -la`. Tornerai nel terminale bpftrace e vedrai qualcosa di simile:

```
PID: 12847 | COMM: bash | CMD: /usr/bin/ls
PID: 12848 | COMM: ls   | CMD: /bin/uname
```

Quello che stai vedendo è ogni processo che viene eseguito sul sistema, in tempo reale, con il suo PID, il nome del processo padre (`comm`) e il path del binario eseguito. **Questo accade a livello kernel, prima che qualsiasi sistema di logging userspace possa intervenire.**

---

## Aggiungere sys_openat: vedere quali file vengono aperti

`sys_openat` viene chiamata ogni volta che un processo apre un file. Per la threat detection, questo è fondamentale: ransomware che cifra file, esfiltrazione di dati sensibili, accesso a credenziali in `/etc/passwd` — tutto passa da questa syscall.

```bash
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_openat {
  printf("PID: %d | COMM: %s | FILE: %s\n",
    pid,
    comm,
    str(args->filename));
}' 2>/dev/null | grep -v "^$"
```

L'output sarà molto verboso. Aggiungere un filtro per un processo specifico rende il risultato più leggibile:

```bash
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_openat
/comm == "python3"/
{
  printf("FILE: %s\n", str(args->filename));
}'
```

Il blocco `/comm == "python3"/` è una **filter expression**: il programma eBPF eseguirà il corpo solo se la condizione è vera. Questo filtro avviene a livello kernel — non stai filtrando l'output in userspace, stai riducendo il carico prima ancora che l'evento arrivi al tuo terminale.

---

## Monitorare le connessioni di rete: sys_connect

`sys_connect` è la syscall che stabilisce una connessione TCP o UDP. Ogni processo che apre una connessione verso l'esterno passa da qui — inclusi i malware che cercano di contattare server C2 (Command and Control), mappati nella tecnica MITRE ATT&CK **T1071: Application Layer Protocol**.

```bash
sudo bpftrace -e '
#include <linux/socket.h>

tracepoint:syscalls:sys_enter_connect {
  printf("PID: %d | COMM: %s | FD: %d\n",
    pid,
    comm,
    args->fd);
}'
```

Per vedere gli indirizzi IP di destinazione in modo leggibile è necessario un approccio con `kprobe` invece delle tracepoint — lo affronteremo in un articolo dedicato al networking eBPF. Per ora, questo hook ti dà visibilità su *quali processi* stanno aprendo connessioni.

---

## Mettere tutto insieme: script multi-probe con output JSON

Ora costruiamo qualcosa di realmente utile per la produzione: uno script bpftrace che monitora tutte e tre le syscall contemporaneamente e produce output in formato **JSON Lines (JSONL)**, pronto per essere ingerito da un SIEM come Elasticsearch, Splunk o qualsiasi sistema che accetti log strutturati.

Crea un file chiamato `syscall_monitor.bt`:

```bash
cat > syscall_monitor.bt << 'EOF'
#!/usr/bin/env bpftrace

BEGIN {
  printf("MONITOR_START\n");
}

tracepoint:syscalls:sys_enter_execve {
  printf("{\"ts\":%lld,\"type\":\"exec\",\"pid\":%d,\"ppid\":%d,\"comm\":\"%s\",\"file\":\"%s\"}\n",
    nsecs,
    pid,
    curtask->real_parent->tgid,
    comm,
    str(args->filename));
}

tracepoint:syscalls:sys_enter_openat
/args->flags & 1 || args->flags & 2/
{
  printf("{\"ts\":%lld,\"type\":\"open_write\",\"pid\":%d,\"comm\":\"%s\",\"file\":\"%s\"}\n",
    nsecs,
    pid,
    comm,
    str(args->filename));
}

tracepoint:syscalls:sys_enter_connect {
  printf("{\"ts\":%lld,\"type\":\"connect\",\"pid\":%d,\"comm\":\"%s\",\"fd\":%d}\n",
    nsecs,
    pid,
    comm,
    args->fd);
}

END {
  printf("MONITOR_END\n");
}
EOF
```

Esegui lo script e reindirizza l'output verso un file di log:

```bash
sudo bpftrace syscall_monitor.bt 2>/dev/null | awk 'NR > 2' | tee /tmp/ebpf_events.jsonl
```

Il flag `2>/dev/null` sopprime i messaggi di debug di bpftrace. L'output sarà un file JSONL — un evento per riga — che puoi processare con `jq`:

```bash
# Tutti gli eventi exec
cat /tmp/ebpf_events.jsonl | jq 'select(.type == "exec")'

# Processi che hanno aperto file in modalità scrittura — per frequenza
cat /tmp/ebpf_events.jsonl | jq 'select(.type == "open_write") | .comm' \
  | sort | uniq -c | sort -rn
```

Output di esempio del secondo comando:

```
     47 "python3"
     23 "bash"
      8 "vim"
      3 "curl"
      1 "nc"
```

Se vedi `nc` (netcat) o `curl` nella lista dei processi che scrivono su file, vale la pena investigare ulteriormente.

---

## 5 minuti di analisi pratica

Prima di chiudere questo lab, esegui lo script per 5 minuti sul tuo sistema — anche su una macchina di sviluppo — e rispondi a queste domande:

**1. Quanti processi distinti compaiono nella lista `exec`?**  
Se il numero è superiore a quello che ti aspettavi, ci sono daemon o script che si avviano silenziosamente in background.

**2. Ci sono processi che aprono file in write mode in path inaspettati?**  
Path come `/tmp`, `/dev/shm` o sottodirectory di `/proc` sono indicatori di comportamento anomalo.

**3. Quali processi aprono connessioni di rete?**  
Un processo come `python3` o `bash` nella lista `connect` merita attenzione immediata.

---

## Repository GitHub

Il codice completo è disponibile nel repository GitHub del progetto.  
Contiene:

- `syscall_monitor.bt` — lo script bpftrace con 4 hook
- `scripts/process_events.py` — processor Python con anomaly detection
- `examples/sample_output.jsonl` — output di esempio per testare offline
- `run.sh` — quick start con modalità live, report e file

```bash
git clone https://github.com/ringzeropirate/ringzeropirate.github.io/tree/main/scripts/Ebpf/Primo%20Hook
cd ebpf-syscall-monitor
sudo bash run.sh
```

---

## Prossimi passi della serie

| Settimana | Articolo |
|---|---|
| Settimana 2 — Technical | Syscall monitor con **Rust Aya**: programma eBPF type-safe da zero |
| Settimana 4 — Technical | Lab: deploy di **Tetragon** in Kubernetes per runtime policy enforcement |
| Settimana 8 — Technical | Lab: **MITRE ATT&CK mapper** real-time con bpftrace e Python |

---

## MITRE ATT&CK Coverage

| Hook | Syscall | Tecnica |
|---|---|---|
| exec | `sys_execve` | T1059 — Command and Scripting Interpreter |
| open_write | `sys_openat` | T1027 — Obfuscated Files or Information |
| connect | `sys_connect` | T1071 — Application Layer Protocol (C2) |

---

*Prova il lab adesso e dimmi: quanti processi inaspettati hai trovato sul tuo sistema in 5 minuti di trace? Se hai trovato qualcosa di interessante, tagga qualcuno del tuo team che dovrebbe vedere questo output — la maggior parte dei developer non ha mai visto cosa succede davvero sotto le loro applicazioni. 👇*

---

**Tag:** `#eBPF` `#bpftrace` `#Linux` `#ThreatDetection` `#DevSecOps` `#CloudNativeSecurity`
