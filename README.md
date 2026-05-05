# 🕵️ STALKER MODE ULTRA v4.0 — OSINT Console Extended

> Console OSINT graphique multi-sources, asynchrone, avec interface PyQt6 et visualisation de graphes.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![OSINT](https://img.shields.io/badge/OSINT-Research-red)

---

## ⚠️ Avertissement légal

Cet outil est conçu **exclusivement à des fins de recherche en cybersécurité, d'audit légal et d'investigation OSINT éthique**. Son utilisation doit respecter les lois en vigueur dans votre pays (RGPD, CFAA, etc.) ainsi que les conditions d'utilisation des services interrogés. L'auteur décline toute responsabilité en cas d'usage abusif ou illicite.

---

## 📋 Description

**STALKER MODE ULTRA v4.0** est une application desktop OSINT (Open Source Intelligence) dotée d'une interface graphique sombre style cyberpunk. Elle permet d'agréger en quelques secondes des informations publiquement disponibles sur une cible à partir de **plus de 20 sources** simultanées, de façon entièrement asynchrone.

### Types de cibles supportés

| Type | Exemple |
|------|---------|
| Nom d'utilisateur | `johndoe` |
| Adresse e-mail | `john@example.com` |
| Nom de domaine | `example.com` |
| Adresse IP | `1.2.3.4` |
| Adresse crypto | `0xABC...` / `bc1q...` |
| Domaine ENS / Web3 | `vitalik.eth` |

---

## 🔍 Sources & modules

### Identité & réseaux sociaux
- **GitHub** — profil, dépôts, gists, clés SSH/GPG, e-mails extraits des commits
- **GitLab** — profil, projets publics
- **HuggingFace** — profil, modèles, datasets, Spaces publiés
- **Reddit** — profil, karma, subreddits actifs, posts et commentaires récents
- **Mastodon** — recherche fédérée sur les instances publiques
- **Keybase** — identités vérifiées et clés cryptographiques
- **Gravatar** — avatar et profil associés à un e-mail

### Développement & packages
- **npm** — packages publiés, profil développeur
- **PyPI** — packages Python associés
- **Docker Hub** — images publiées

### Domaine & infrastructure
- **WHOIS** — registrar, dates, contacts
- **DNS avancé** — enregistrements A, AAAA, MX, TXT, NS, SOA, CAA, SRV, DMARC, SPF
- **Certificate Transparency (crt.sh)** — sous-domaines, e-mails dans les certificats
- **Shodan** *(clé API)* — ports ouverts, bannières, CVE
- **Censys** *(clé API)* — infrastructure exposée
- **Cloud providers** — détection AWS, GCP, Azure, Cloudflare

### Sécurité & fuites
- **Have I Been Pwned** *(clé API)* — fuites de données associées à un e-mail
- **LeakIX / Pastebin** — pastes et fuites indexées
- **VirusTotal** *(clé API, mode passif)* — réputation IP/domaine

### Crypto & Web3
- **ENS** — résolution de noms Ethereum, lookup inversé, multi-chaînes (BTC, SOL, MATIC…)
- **Unstoppable Domains** — résolution de domaines Web3
- **Blockscout / Mempool.space** — soldes et transactions ETH, BTC, SOL, TRON
- **Hunter.io / FullContact** *(clés API)* — enrichissement e-mail et contacts

### Autres
- **PGP** — recherche sur keys.openpgp.org et MIT keyserver
- **Archive.org** — historique de captures du domaine
- **Visualisation de graphes** — graphe interactif HTML (pyvis) des relations entre entités

---

## 🖥️ Interface

L'interface graphique (PyQt6, thème cyberpunk) propose :
- **Saisie multi-cibles** (une cible par ligne) ou import depuis un fichier `.txt`
- **Flux système en temps réel** avec horodatage
- **Panneau JSON** pour explorer les résultats structurés
- **Barre de progression** par source
- **Graphe interactif** (ouverture dans le navigateur)
- **Export JSON** des résultats

---

## ⚙️ Installation

### Prérequis
- Python 3.10+
- pip

### Dépendances obligatoires

```bash
pip install PyQt6 aiohttp dnspython python-whois pyvis web3 py-ens requests
```

### Dépendances optionnelles (selon les modules utilisés)

```bash
pip install web3 py-ens  # ENS / Ethereum
```

---

## 🔑 Clés API

Les clés API sont lues depuis les **variables d'environnement** — ne les codez jamais en dur dans le source.

| Variable | Service | Lien |
|----------|---------|------|
| `SHODAN_API_KEY` | Shodan | https://shodan.io |
| `VT_API_KEY` | VirusTotal | https://virustotal.com |
| `CENSYS_ID` + `CENSYS_SECRET` | Censys | https://censys.io |
| `HIBP_API_KEY` | Have I Been Pwned | https://haveibeenpwned.com/API/Key |
| `HUNTER_API_KEY` | Hunter.io | https://hunter.io |
| `FULLCONTACT_API_KEY` | FullContact | https://fullcontact.com |

### Exemple de configuration (Linux / macOS)

```bash
export SHODAN_API_KEY="votre_clé"
export HIBP_API_KEY="votre_clé"
export VT_API_KEY="votre_clé"
```

### Exemple de configuration (Windows PowerShell)

```powershell
$env:SHODAN_API_KEY = "votre_clé"
$env:HIBP_API_KEY  = "votre_clé"
```

> Les modules sans clé API fonctionnent avec les sources publiques uniquement.

---

## 🚀 Utilisation

```bash
python ultra5a.py
```

1. Saisissez une ou plusieurs cibles (une par ligne) dans le champ de saisie
2. Cliquez sur **▶ LANCER SCAN**
3. Suivez les résultats en temps réel dans le panneau de droite
4. Ouvrez le **🌐 GRAPHE** pour visualiser les relations
5. Exportez via **💾 EXPORT JSON**

### Import en lot

Cliquez sur **📂 IMPORTER** pour charger un fichier `.txt` contenant une cible par ligne.

---

## 📁 Structure des sorties

```
results/
  ├── johndoe_20250101_120000.json
  ├── example.com_20250101_120100.json
  └── ...
```

Chaque fichier JSON contient l'ensemble des données collectées pour la cible, organisées par source.

---

## 🏗️ Architecture technique

- **Asyncio + aiohttp** : toutes les requêtes réseau sont effectuées en parallèle
- **PyQt6 + QThread** : l'interface reste réactive pendant les scans
- **pyvis** : génération de graphes de relations au format HTML interactif
- **web3.py / py-ens** : résolution des identités ENS on-chain

---

## 🤝 Contribution

Les contributions sont bienvenues. Merci de :
1. Forker le dépôt
2. Créer une branche (`git checkout -b feature/nouvelle-source`)
3. Commiter vos changements
4. Ouvrir une Pull Request

---

## 📄 Licence

Ce projet est distribué sous licence **MIT**. Voir le fichier `LICENSE` pour plus de détails.
