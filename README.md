# Ring Zero Pirate 🏴‍☠️

> `kernel.ring0 — root or nothing`

Blog tecnico di cybersecurity — exploit research, kernel internals, red team chronicles.

## Stack

- [Hugo](https://gohugo.io/) static site generator
- Theme custom: `ringzero` (cyberpunk terminal brutalismo)
- Hosted su GitHub Pages

## Struttura

```
ringzero-pirate/
├── hugo.toml                    # Config principale
├── content/
│   └── articoli/                # Post in Markdown
│       └── example.md
└── themes/
    └── ringzero/
        ├── theme.toml
        ├── layouts/
        │   ├── _default/
        │   │   └── baseof.html  # Base template
        │   ├── index.html       # Homepage con glitch
        │   └── articoli/
        │       ├── list.html    # Lista articoli
        │       └── single.html  # Singolo post
        └── static/
            ├── css/main.css     # Tutti gli stili
            └── js/main.js       # Nav + typing effect
```

## Setup

```bash
# 1. Installa Hugo
brew install hugo          # macOS
apt install hugo           # Debian/Ubuntu

# 2. Clona e avvia
git clone https://github.com/tuousername/ringzero-pirate
cd ringzero-pirate
hugo server -D

# 3. Nuovo articolo
hugo new articoli/nome-articolo.md
```

## Front Matter degli articoli

```yaml
---
title: "Titolo Articolo"
date: 2026-01-15
tags: ["linux", "exploit", "kernel"]
severity: "high"       # critical | high | medium | low | info
cve: "CVE-2026-XXXX"   # opzionale
summary: "Breve descrizione per la card in homepage."
---
```

## Deploy su GitHub Pages

```bash
# Nel repository Settings → Pages → Source: GitHub Actions
# oppure con hugo --minify → gh-pages branch

hugo --minify
# Push su main → GitHub Action pubblica automaticamente
```

## Colori tema

| Variabile       | Valore    | Uso                    |
|-----------------|-----------|------------------------|
| `--green`       | `#00ff41` | Accento principale     |
| `--cyan`        | `#00d4ff` | Link, tag              |
| `--red`         | `#ff0040` | Severity critical      |
| `--yellow`      | `#ffd700` | Severity high, CVE     |
| `--purple`      | `#bf00ff` | Blockquote, severity info |
| `--bg`          | `#030305` | Background corpo       |

---

`// EOF — ring zero pirate 2026`
