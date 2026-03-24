---
title: "Q-Day: Perché la crittografia attuale non è pronta per un avversario quantistico"
date: 2026-01-27
draft: false
tags: ["CyberSecurity, QuantumComputing, Cryptography, Infosec, TechnologyStrategy, Engineeringlinux"]
---

## Overview

L’evoluzione del calcolo quantistico pone una minaccia diretta agli algoritmi crittografici attualmente più diffusi, come RSA e Diffie-Hellman, che costituiscono la base della sicurezza delle comunicazioni moderne, poiché non sono progettati per resistere ad avversari dotati di capacità quantistiche sufficientemente avanzate. Per affrontare questo scenario stanno emergendo la Crittografia Post-Quantistica e la Quantum Key Distribution.

Nel lavoro quotidiano sulla sicurezza, una parte significativa delle attività è dedicata alla mitigazione di vulnerabilità note; un’altra è rivolta a rischi che non si sono ancora materializzati, ma che devono essere considerati in fase di pianificazione. La cosiddetta minaccia quantistica rientra in questa seconda categoria, con una caratteristica distintiva: le condizioni che la rendono rilevante sono già presenti, anche se gli effetti concreti si manifesteranno in futuro.

Non si tratta di uno scenario ipotetico o speculativo, ma di un problema di gestione del rischio a lungo termine. L’elemento critico non è il momento in cui i computer quantistici diventeranno operativi su larga scala, ma il fatto che dati cifrati oggi possano essere raccolti e conservati per essere decifrati in seguito, secondo il modello noto come “Harvest Now, Decrypt Later“. In questo contesto, la finestra temporale di esposizione è già aperta.

L’evoluzione del calcolo quantistico pone una minaccia diretta agli algoritmi crittografici attualmente più diffusi. Schemi come RSA, ECDSA e Diffie-Hellman, che costituiscono la base della sicurezza delle comunicazioni moderne, non sono progettati per resistere ad avversari dotati di capacità quantistiche sufficientemente avanzate. Per affrontare questo scenario stanno emergendo due approcci distinti: la Crittografia Post-Quantistica (PQC) e la Quantum Key Distribution (QKD). Entrambi mirano a garantire la riservatezza delle comunicazioni in un contesto post-quantistico, ma si basano su presupposti tecnici diversi e presentano implicazioni operative differenti.

In questo quadro, la crittografia non può più essere considerata un meccanismo limitato alla protezione delle credenziali o delle transazioni commerciali. È un componente strutturale della sicurezza nazionale, delle infrastrutture critiche e delle relazioni geopolitiche. La durata nel tempo del valore informativo dei dati diventa quindi un fattore centrale.

Se un’informazione deve rimanere riservata per periodi di dieci, venti o più anni (come nel caso di dati sanitari, industriali o governativi) l’adozione esclusiva di schemi crittografici non resistenti a un avversario quantistico rappresenta già oggi un rischio che deve essere valutato e gestito.

## Deep Dive Tecnico: PQC vs QKD e Algoritmi a Rischio

Prima di valutare le contromisure, è necessario chiarire il modello di minaccia. Su un computer quantistico sufficientemente potente, l’algoritmo di Shor consente di fattorizzare numeri interi e risolvere il problema del logaritmo discreto in tempo polinomiale. Questo rende insicuri gli schemi crittografici a chiave pubblica oggi più diffusi, che basano la propria sicurezza proprio sulla difficoltà computazionale di questi problemi.

Anche la crittografia simmetrica risente dell’impatto del calcolo quantistico, sebbene in modo diverso. L’algoritmo di Grover permette di accelerare la ricerca esaustiva delle chiavi, riducendo di fatto il livello di sicurezza offerto da una chiave simmetrica. Per compensare questo effetto, è necessario aumentare la dimensione delle chiavi al fine di mantenere un livello di protezione equivalente.

Ecco una tabella rapida per capire l’impatto sugli algoritmi che usiamo ogni giorno:

| **Algoritmo** | **Tipo** | **Vulnerabilità Quantistica**  | **Sicurezza** |
| :--- | :--- | :--- | :--- |
| **RSA** | Asimmetrico | Totale (Shor) | Compromesso; andrà sostituito completamente. |
| **ECC / ECDH** | Asimmettrico | Totale (Shor) | Compromesso; andrà sostituito completamente. |
| **AES** | Simmetrico | Parziale (Grover) | Vulnerabile, la sicurezza si dimezza. AES-128 diventa insicuro, bisogna passare ad AES-256. |
| **SHA-2/SHA-3** | Hashing | Parziale | Sicuro, aumentare la dimensione dell’output (es. SHA-384) è sufficiente. |

Il NIST ha pubblicato i suoi principali standard PQC (definiti Federal Information Processing Standards o FIPS), specificando gli schemi di istituzione delle chiavi e di firma digitale basati sui candidati valutati e selezionati attraverso un processo pluriennale: FIPS-203, FIPS-204, FIPS-205 .
Con il rilascio dei primi tre standard PQC definitivi, le organizzazioni dovrebbero iniziare a migrare i propri sistemi verso la crittografia quantistica.

Il NIST prevede che i due standard di firma digitale (ML-DSA e SLH-DSA) e lo standard del meccanismo di incapsulamento delle chiavi (ML-KEM) forniranno la base per la maggior parte delle implementazioni della crittografia post-quantistica. Possono e devono essere utilizzati fin da ora. (Rif. https://csrc.nist.gov/projects/post-quantum-cryptography#pqc-standards)

## Post-Quantum Cryptography (PQC) – La soluzione software

La **PQC** si basa su algoritmi progettati per girare su computer attuali, ma strutturati su problemi matematici così complessi da resistere anche alla potenza di calcolo di un futuro computer quantistico.

**Famiglie di Algoritmi Standardizzati (NIST)**
- **Basata su Reticoli (Lattice-based):** È la famiglia più promettente. Include ML-KEM (ex Kyber) per lo scambio di chiavi e ML-DSA (ex Dilithium) per le firme. Si fondano su problemi come il Shortest Vector Problem.
- **Basata su Codici (Code-based):** Deriva dal sistema McEliece. Estremamente sicura e studiata, ma soffre di chiavi pubbliche molto grandi.
- **Basata su Hash (Hash-based):** Utilizzata per le firme digitali (es. SLH-DSA/SPHINCS+). La sicurezza dipende esclusivamente dalla robustezza delle funzioni hash, rendendola molto affidabile.
- **Basata su Isogenie (Isogeny-based):** Sfrutta le proprietà delle curve ellittiche. Nonostante l’efficienza, il recente cracking dell’algoritmo SIKE ha invitato alla massima cautela.

**Pro e Contro della PQC**

| **Vantaggi** | **Limitazioni** |
| :--- | :--- |
| **Compatibilità:** Funziona su hardware e internet esistenti. | **Dimensioni:** Chiavi e firme sono più pesanti (maggior traffico dati). |
| **Costi Contenuti:** Richiede solo aggiornamenti software. | **Performance:** Alcuni calcoli sono più lenti dei classici RSA/ECC. |
| **Scalabilità:** Implementabile globalmente in tempi brevi. | **Sicurezza Teorica:** Si basa su ipotesi matematiche, non leggi fisiche. |

## Quantum Key Distribution (QKD) – La soluzione fisica

A differenza della **PQC**, la **QKD** non usa la matematica, ma le leggi della meccanica quantistica per distribuire chiavi crittografiche. Il protocollo principe è il **BB84**.

**Principi Quantistici Fondamentali**
+ **Indeterminazione di Heisenberg:** Misurare un sistema quantistico lo altera inevitabilmente.
+ **Teorema di No-cloning:** È impossibile copiare uno stato quantistico ignoto senza distruggerlo.
**Risultato:** Se un hacker tenta di intercettare la chiave durante la trasmissione, le particelle (fotoni) cambiano stato, rivelando immediatamente l’intrusione.

**Limiti della QKD**

Nonostante la sicurezza “teoricamente perfetta”, la QKD richiede **infrastrutture dedicate** (fibra ottica speciale o satelliti) e ha una **distanza limitata** (circa 200 km) a causa della perdita di segnale. Inoltre, non gestisce l’autenticazione, richiedendo comunque algoritmi classici o PQC per identificare le parti.

**Analisi Comparativa**

- **Modello di Sicurezza:** La PQC è “computazionale” (difficile da rompere), la QKD è “informatica-teoretica” (impossibile da rompere per leggi fisiche).
- **Implementazione:** La PQC è Software-defined (patch e aggiornamenti); la QKD è Hardware-defined (nuove reti fisiche).
- **Casi d’uso:** La PQC è la soluzione per il mass-market (web, banche, IoT). La QKD è riservata ad altissima sicurezza (militare, infrastrutture critiche, comunicazioni governative).
La Soluzione con Approccio Ibrido

La strategia vincente, definita Defense in Depth, prevede l’uso combinato di:

Algoritmi Classici + PQC: Per garantire la sicurezza oggi e domani durante la transizione.
PQC + QKD: Per i dati ultra-sensibili, dove la matematica della PQC protegge l’autenticazione e la fisica della QKD protegge la riservatezza della chiave.
A questo punta lasciamo la teoria per sporcarci le mani direttamente sulla shell. Di seguito vedremo come costruire un lab per negoziare la prima connessione post-quantistica della vostra vita.

Ma prima dobbiamo porci una domanda, quanto siamo esposti oggi? Mostriamo uno snippet che ce lo dice chiaramente; a titolo di esempio è stato preso il sito google.com :
![curl](/images/curl.png)

Osservando questo output, un analista può osservare la “data di scadenza” della propria infrastruttura. Nonostante l’uso di protocolli moderni come **TLS 1.2**, l’impiego di rsaEncryption e ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) espone il fianco a due minacce quantistiche immediate:

+ **L’Algoritmo di Shor:** In grado di risolvere il logaritmo discreto e la fattorizzazione, rendendo nulle le attuali chiavi pubbliche.
+ **L’instabilità della PKI:** Se la firma della CA è RSA, l’intera catena di fiducia crolla.

## Lab in a Box

Giunti a questo punto, la sfida si sposta sulla resilienza operativa: quali architetture crittografiche dobbiamo adottare fin da subito per garantire che i dati esfiltrati oggi restino indecifrabili anche nell’era del calcolo quantistico?  Come indicato dal Nist la soluzione adottabile nell’immediato è l’adozione di una soluzione ibrida utilizzando algoritmi classici + PQC .

In questa sessione di laboratorio, approfondiremo l’implementazione di un server **Nginx** configurato con algoritmi **Post-Quantum (PQ)**. Per l’esercitazione utilizzeremo il framework **OpenQuantumSafe (OQS)** all’interno di un ambiente containerizzato Docker Desktop su Windows.

Utilizzeremo l’ecosistema **liboqs**, una libreria C open source per algoritmi crittografici resistenti ai quantistici, integrata in Nginx tramite una versione modificata di OpenSSL.

**Prerequisiti:**
Assicurarsi di aver installato ed avviato Docker Desktop (Backend WSL2) sul proprio pc.

**Stack tecnologico:**

+ **Server:** Immagine Docker openquantumsafe/nginx.
+ **Client:** Immagine Docker openquantumsafe/curl.
+ **Protocollo:** **TLS 1.3** con scambio chiavi Post-Quantum .

**Step 1: Preparazione dell’ambiente**

Assicuratevi che Docker Desktop sia avviato sul vostro sistema Windows. Aprite il terminale (PowerShell).

Scarichiamo le immagini necessarie dal repository ufficiale di OpenQuantumSafe:
![curl](/images/pull_nginx.png)
![curl](/images/pull_curl.png)
Verifichiamo le immagini scaricate:
![curl](/images/ls.png)
A questo punto creiamo una network in modo tale da porter far dialogare i container :
![curl](/images/ntw.png)

**Step 2: Configurazione e Avvio del Server Nginx**

L’immagine openquantumsafe/nginx è pre-configurata con OpenSSL abilitato per la PQC. Per impostazione predefinita, il server è pronto ad accettare connessioni su una porta specifica utilizzando algoritmi ibridi o puramente quantistici.
Affinchè possiamo constatare che tipo di  negoziazione siamo stabilendo, sono state inserite nel file di configurazione nginx.conf le seguenti righe per consentire di loggare le informazioni necessarie:
```bash
# --- LA DIRETTIVA VA DENTRO HTTP ---
    log_format pqc_logs '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$ssl_protocol" "$ssl_cipher" "$ssl_curve"';
# --- LA DIRETTIVA VA DENTRO SERVER ---
access_log  /opt/nginx/logs/access.log pqc_logs pqc_logs;
```
# test