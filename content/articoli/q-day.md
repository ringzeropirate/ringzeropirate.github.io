---
title: "Q-Day: Perché la crittografia attuale non è pronta per un avversario quantistico"
date: 2026-01-17
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
| **SHA-2 / SHA-3** | Hashing | Parziale | Sicuro, aumentare la dimensione dell’output (es. SHA-384) è sufficiente. |

Il NIST ha pubblicato i suoi principali standard PQC (definiti Federal Information Processing Standards o FIPS), specificando gli schemi di istituzione delle chiavi e di firma digitale basati sui candidati valutati e selezionati attraverso un processo pluriennale: FIPS-203, FIPS-204, FIPS-205 .
Con il rilascio dei primi tre standard PQC definitivi, le organizzazioni dovrebbero iniziare a migrare i propri sistemi verso la crittografia quantistica.

Il NIST prevede che i due standard di firma digitale (ML-DSA e SLH-DSA) e lo standard del meccanismo di incapsulamento delle chiavi (ML-KEM) forniranno la base per la maggior parte delle implementazioni della crittografia post-quantistica. Possono e devono essere utilizzati fin da ora. (Rif. https://csrc.nist.gov/projects/post-quantum-cryptography#pqc-standards)

## Post-Quantum Cryptography (PQC) – La soluzione software
```
Vantaggi	Limitazioni
Compatibilità: Funziona su hardware e internet esistenti.	Dimensioni: Chiavi e firme sono più pesanti (maggior traffico dati).
Costi Contenuti: Richiede solo aggiornamenti software.	Performance: Alcuni calcoli sono più lenti dei classici RSA/ECC.
Scalabilità: Implementabile globalmente in tempi brevi.	Sicurezza Teorica: Si basa su ipotesi matematiche, non leggi fisiche.
```