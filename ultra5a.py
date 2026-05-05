#!/usr/bin/env python3
"""
STALKER MODE ULTRA v4.0 — OSINT Console Extended
Nouvelles sources : HuggingFace, Reddit, Cloud (AWS/GCP/Azure/Cloudflare),
Shodan, GitLab, npm, PyPI, Mastodon, Pastebin/LeakIX, Docker Hub,
Keybase, Gravatar, Archive.org, VirusTotal (passive), Censys, Have I Been Pwned (HIBP).

Dépendances pip :
    pip install PyQt6 aiohttp dnspython python-whois pyvis web3 py-ens requests

Optionnel (clés API) :
    SHODAN_API_KEY     → https://shodan.io
    VT_API_KEY         → https://virustotal.com
    CENSYS_ID / CENSYS_SECRET → https://censys.io
    HIBP_API_KEY       → https://haveibeenpwned.com/API/Key
    HUNTER_API_KEY     → https://hunter.io
    FULLCONTACT_API_KEY→ https://fullcontact.com
"""

import sys, re, json, asyncio, aiohttp, os, webbrowser, hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# ──────────────────────────────────────────────────────────────────────────────
# Clés API (depuis variables d'environnement — ne jamais les hardcoder)
# ──────────────────────────────────────────────────────────────────────────────
SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY", "")
VT_API_KEY        = os.getenv("VT_API_KEY", "")
CENSYS_ID         = os.getenv("CENSYS_ID", "")
CENSYS_SECRET     = os.getenv("CENSYS_SECRET", "")
HIBP_API_KEY      = os.getenv("HIBP_API_KEY", "")
HUNTER_API_KEY    = os.getenv("HUNTER_API_KEY", "")
FULLCONTACT_KEY   = os.getenv("FULLCONTACT_API_KEY", "")

ETH_RPC_URL = "https://cloudflare-eth.com"
UD_API_BASE  = "https://resolve.unstoppabledomains.com/domains"

# ──────────────────────────────────────────────────────────────────────────────
# Utilitaires
# ──────────────────────────────────────────────────────────────────────────────
def normalize_name(identifier: str) -> str:
    identifier = identifier.strip().lower()
    identifier = re.sub(r"^https?://", "", identifier)
    identifier = re.sub(r"^www\.", "", identifier)
    return identifier.rstrip("/")

def save_json(data: dict, filename: str) -> str:
    Path("results").mkdir(exist_ok=True)
    filepath = Path("results") / filename
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return str(filepath)

def is_email(s: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", s))

def is_domain(s: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", s))

def is_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))

def extract_username(name: str) -> str:
    return name.split("@")[-1].split(".")[0] if "@" in name else name.split(".")[0]

def md5_email(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode()).hexdigest()

# ──────────────────────────────────────────────────────────────────────────────
# SESSION FACTORY
# ──────────────────────────────────────────────────────────────────────────────
def make_session(timeout: int = 12, headers: dict = None) -> aiohttp.ClientSession:
    h = {"User-Agent": "Mozilla/5.0 (compatible; OSINTBot/4.0)"}
    if headers:
        h.update(headers)
    return aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=timeout),
        headers=h,
        connector=aiohttp.TCPConnector(ssl=False)
    )

# ══════════════════════════════════════════════════════════════════════════════
#  SOURCES EXISTANTES (reprises et améliorées)
# ══════════════════════════════════════════════════════════════════════════════

async def lookup_ens(name: str) -> Dict:
    try:
        from web3 import Web3
        from ens import ENS
        w3 = Web3(Web3.HTTPProvider(ETH_RPC_URL))
        if not w3.is_connected():
            return {"error": "RPC non connecté"}
        ns = ENS.from_web3(w3)
        results = {}
        eth_addr = ns.address(name)
        if eth_addr:
            results["ETH"] = eth_addr
        coin_map = {"BTC": 0, "SOL": 501, "MATIC": 966, "BNB": 714, "DOT": 354, "LTC": 2}
        for coin, cid in coin_map.items():
            try:
                addr = ns.address(name, coin_type=cid)
                if addr:
                    results[coin] = addr
            except:
                pass
        # Reverse lookup
        try:
            reverse = ns.name(eth_addr) if eth_addr else None
            if reverse:
                results["reverse_ens"] = reverse
        except:
            pass
        return results
    except ImportError:
        return {"error": "web3/ens non installé"}
    except Exception as e:
        return {"error": str(e)}


async def lookup_unstoppable(name: str) -> Dict:
    try:
        async with make_session(10) as session:
            async with session.get(f"{UD_API_BASE}/{name}") as resp:
                if resp.status == 404:
                    return {}
                if resp.status != 200:
                    return {"error": f"HTTP {resp.status}"}
                data = await resp.json()
                records = data.get("records", {})
                return {k.split(".")[1].upper(): v
                        for k, v in records.items()
                        if k.endswith(".address") and v}
    except Exception as e:
        return {"error": str(e)}


async def lookup_pgp(identifier: str) -> Dict:
    results = {}
    urls = [f"https://keys.openpgp.org/vks/v1/by-email/{identifier}"]
    if re.match(r"^[0-9A-Fa-f]{8,40}$", identifier.replace(" ", "")):
        urls.append(f"https://keys.openpgp.org/vks/v1/by-fingerprint/{identifier.replace(' ', '').upper()}")
    async with make_session(10) as session:
        for url in urls:
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        results = {"status": "found", "source": "keys.openpgp.org",
                                   "raw_preview": text[:2000]}
                        break
            except:
                continue
    # MIT PGP keyserver fallback
    if not results and is_email(identifier):
        try:
            async with make_session(8) as session:
                async with session.get(f"https://pgp.mit.edu/pks/lookup?op=vindex&search={identifier}") as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "pub" in text.lower():
                            results = {"status": "found_mit", "raw_preview": text[:800]}
        except:
            pass
    return results


async def lookup_github(username: str) -> Dict:
    username = extract_username(username)
    if not username or len(username) < 2 or "." in username:
        return {}
    results = {}
    async with make_session(10) as session:
        try:
            async with session.get(f"https://api.github.com/users/{username}") as resp:
                if resp.status == 200:
                    d = await resp.json()
                    results["profile"] = {k: d.get(k) for k in [
                        "login", "name", "bio", "blog", "twitter_username",
                        "location", "public_repos", "public_gists",
                        "followers", "following", "created_at", "updated_at",
                        "company", "hireable", "email"
                    ]}
        except:
            pass
        # SSH + GPG keys
        try:
            async with session.get(f"https://github.com/{username}.keys") as resp:
                if resp.status == 200:
                    results["ssh_keys"] = [k.strip() for k in (await resp.text()).split("\n") if k.strip()][:8]
        except:
            pass
        try:
            async with session.get(f"https://api.github.com/users/{username}/gpg_keys") as resp:
                if resp.status == 200:
                    gpg = await resp.json()
                    results["gpg_keys"] = [{"id": g.get("key_id"), "emails": [e.get("email") for e in g.get("emails", [])]} for g in gpg[:5]]
        except:
            pass
        # Repos récents
        try:
            async with session.get(f"https://api.github.com/users/{username}/repos?sort=pushed&per_page=10") as resp:
                if resp.status == 200:
                    repos = await resp.json()
                    results["recent_repos"] = [{"name": r.get("name"), "lang": r.get("language"),
                                                 "stars": r.get("stargazers_count"),
                                                 "description": r.get("description"),
                                                 "topics": r.get("topics", [])} for r in repos]
        except:
            pass
        # Gists
        try:
            async with session.get(f"https://api.github.com/users/{username}/gists?per_page=5") as resp:
                if resp.status == 200:
                    gists = await resp.json()
                    results["gists"] = [{"desc": g.get("description"), "files": list(g.get("files", {}).keys())[:5],
                                          "public": g.get("public"), "url": g.get("html_url")} for g in gists]
        except:
            pass
        # Events (commits récents)
        try:
            async with session.get(f"https://api.github.com/users/{username}/events/public?per_page=15") as resp:
                if resp.status == 200:
                    events = await resp.json()
                    commit_emails = set()
                    for ev in events:
                        if ev.get("type") == "PushEvent":
                            for commit in ev.get("payload", {}).get("commits", []):
                                email = commit.get("author", {}).get("email", "")
                                if email and "noreply" not in email:
                                    commit_emails.add(email)
                    if commit_emails:
                        results["leaked_commit_emails"] = list(commit_emails)
        except:
            pass
    return results


async def lookup_gitlab(username: str) -> Dict:
    """GitLab public API."""
    username = extract_username(username)
    if not username or len(username) < 2:
        return {}
    results = {}
    async with make_session(10) as session:
        try:
            async with session.get(f"https://gitlab.com/api/v4/users?username={username}") as resp:
                if resp.status == 200:
                    users = await resp.json()
                    if users:
                        u = users[0]
                        results["profile"] = {k: u.get(k) for k in [
                            "id", "name", "username", "bio", "location",
                            "website_url", "organization", "job_title",
                            "twitter", "linkedin", "created_at", "public_email"
                        ]}
                        uid = u.get("id")
                        # Projets
                        async with session.get(f"https://gitlab.com/api/v4/users/{uid}/projects?per_page=8&order_by=last_activity_at") as r2:
                            if r2.status == 200:
                                projs = await r2.json()
                                results["projects"] = [{"name": p.get("name"), "lang": p.get("predominant_language"),
                                                         "stars": p.get("star_count"), "forks": p.get("forks_count"),
                                                         "visibility": p.get("visibility")} for p in projs]
        except Exception as e:
            results["error"] = str(e)
    return results


async def lookup_ct_logs(domain: str) -> Dict:
    try:
        async with make_session(15) as session:
            async with session.get(f"https://crt.sh/?q=%25.{domain}&output=json") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    emails = {line.strip() for e in data[:50]
                              for line in str(e.get("name_value", "")).splitlines()
                              if "@" in line}
                    subdomains = {san.strip() for e in data[:100]
                                  for san in str(e.get("name_value", "")).splitlines()
                                  if san.strip().endswith(f".{domain}")}
                    issuers = list({e.get("issuer_ca_id") for e in data[:30] if e.get("issuer_ca_id")})[:5]
                    return {"certificates_total": len(data), "emails": list(emails)[:20],
                            "subdomains": sorted(subdomains)[:30], "ca_ids": issuers}
    except:
        pass
    return {}


async def lookup_whois(domain: str) -> Dict:
    def _sync():
        import whois
        w = whois.whois(domain)
        return {
            "registrar": getattr(w, "registrar", None),
            "creation_date": str(getattr(w, "creation_date", None)),
            "expiration_date": str(getattr(w, "expiration_date", None)),
            "updated_date": str(getattr(w, "updated_date", None)),
            "emails": getattr(w, "emails", None),
            "name_servers": getattr(w, "name_servers", None),
            "status": getattr(w, "status", None),
            "country": getattr(w, "country", None),
            "org": getattr(w, "org", None),
            "registrant_name": getattr(w, "name", None),
        }
    try:
        return await asyncio.to_thread(_sync)
    except:
        return {}


async def advanced_dns(domain: str) -> Dict:
    def _sync():
        import dns.resolver
        results = {}
        for rtype in ["A", "AAAA", "TXT", "MX", "NS", "CNAME", "SOA", "CAA", "SRV"]:
            try:
                results[rtype] = [str(r) for r in dns.resolver.resolve(domain, rtype, lifetime=5)]
            except:
                pass
        # DMARC / SPF / DKIM hints
        for sub in [f"_dmarc.{domain}", f"_domainkey.{domain}", f"_dnslink.{domain}"]:
            try:
                txts = [str(r) for r in dns.resolver.resolve(sub, "TXT", lifetime=5)]
                results[sub] = txts
            except:
                pass
        return results
    try:
        return await asyncio.to_thread(_sync)
    except ImportError:
        return {"error": "dnspython non installé"}
    except:
        return {}


async def lookup_crypto_address(address: str) -> Dict:
    address = address.strip()
    patterns = {
        "EVM/Ethereum": r"^0x[a-fA-F0-9]{40}$",
        "Bitcoin":      r"^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$",
        "Solana":       r"^[1-9A-HJ-NP-Za-km-z]{32,44}$",
        "TRON":         r"^T[a-zA-HJ-NP-Z0-9]{33}$",
        "Litecoin":     r"^[LM3][a-km-zA-HJ-NP-Z1-9]{25,34}$",
        "Monero":       r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$",
    }
    chain = next((c for c, pat in patterns.items() if re.match(pat, address)), None)
    if not chain:
        return {}

    results = {"chain": chain, "address": address, "data": {}}
    try:
        async with make_session(15) as session:
            if "Ethereum" in chain:
                async with session.get(f"https://eth.blockscout.com/api/v2/addresses/{address}") as resp:
                    if resp.status == 200:
                        d = await resp.json()
                        bal = int(d.get("coin_balance", "0") or "0")
                        results["data"].update({
                            "balance_eth": f"{bal/1e18:.6f}",
                            "tx_count": d.get("transactions_count"),
                            "is_contract": d.get("is_contract", False),
                            "ens": d.get("ens_domain_name"),
                            "tags": d.get("tags", []),
                            "token_transfers": d.get("token_transfers_count"),
                        })
            elif "Bitcoin" in chain:
                async with session.get(f"https://blockchain.info/rawaddr/{address}") as resp:
                    if resp.status == 200:
                        d = await resp.json()
                        results["data"].update({
                            "balance_btc": d.get("final_balance", 0) / 1e8,
                            "tx_count": d.get("n_tx"),
                            "total_received": d.get("total_received", 0) / 1e8,
                            "total_sent": d.get("total_sent", 0) / 1e8,
                        })
            elif "Solana" in chain:
                async with session.post("https://api.mainnet-beta.solana.com",
                                        json={"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [address]}) as resp:
                    if resp.status == 200:
                        val = (await resp.json()).get("result", {}).get("value", 0)
                        results["data"]["balance_sol"] = f"{val / 1e9:.4f}"
            elif "TRON" in chain:
                async with session.get(f"https://apilist.tronscanapi.com/api/accountv2?address={address}") as resp:
                    if resp.status == 200:
                        d = await resp.json()
                        results["data"].update({
                            "balance_trx": f"{d.get('balance', 0) / 1e6:.2f}",
                            "tx_count": d.get("totalTransactionCount"),
                        })
    except Exception as e:
        results["error"] = str(e)
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  NOUVELLES SOURCES v4.0
# ══════════════════════════════════════════════════════════════════════════════

async def lookup_telegram(username: str) -> Dict:
    """Telegram : récupération profil public via preview."""
    username = extract_username(username)
    if not username:
        return {}

    results = {}
    async with make_session(10) as session:
        try:
            url = f"https://t.me/{username}"
            async with session.get(url) as resp:
                if resp.status == 200:
                    html = await resp.text()

                    import re
                    name = re.search(r'<meta property="og:title" content="([^"]+)"', html)
                    desc = re.search(r'<meta property="og:description" content="([^"]+)"', html)
                    img = re.search(r'<meta property="og:image" content="([^"]+)"', html)

                    results = {
                        "username": username,
                        "exists": True,
                        "display_name": name.group(1) if name else None,
                        "bio": desc.group(1) if desc else None,
                        "avatar": img.group(1) if img else None,
                        "url": url
                    }
        except Exception as e:
            results["error"] = str(e)

    return results

async def lookup_discord(username: str) -> Dict:
    """
    Discord OSINT passif :
    Vérifie présence via services publics (pas d’API officielle ouverte).
    """
    username = extract_username(username)
    if not username:
        return {}

    results = {"username": username}

    async with make_session(10) as session:
        try:
            # Recherche via disboard (heuristique)
            async with session.get(f"https://disboard.org/search?keyword={username}") as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if username.lower() in text.lower():
                        results["possible_presence"] = True

        except Exception as e:
            results["error"] = str(e)

    return results

async def lookup_arkham(address: str) -> Dict:
    """Arkham Intelligence (scraping léger public)."""
    if not address.startswith("0x"):
        return {}

    results = {}

    async with make_session(12) as session:
        try:
            url = f"https://platform.arkhamintelligence.com/explorer/address/{address}"
            async with session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()

                    # Extraction basique
                    if "entity" in text.lower():
                        results["entity_detected"] = True

                    results["url"] = url

        except Exception as e:
            results["error"] = str(e)

    return results

async def lookup_debank(address: str) -> Dict:
    """DeBank : portfolio DeFi."""
    if not address.startswith("0x"):
        return {}

    results = {}

    async with make_session(12) as session:
        try:
            async with session.get(f"https://api.debank.com/user/total_balance?id={address}") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results["total_usd_value"] = data.get("total_usd_value")

            async with session.get(f"https://api.debank.com/user/token_list?id={address}&is_all=true") as resp:
                if resp.status == 200:
                    tokens = await resp.json()
                    results["tokens"] = [{
                        "symbol": t.get("symbol"),
                        "amount": t.get("amount"),
                        "price": t.get("price"),
                    } for t in tokens[:10]]

        except Exception as e:
            results["error"] = str(e)

    return results

async def lookup_huggingface(username: str) -> Dict:
    """HuggingFace : profil, modèles, datasets, spaces."""
    username = extract_username(username)
    if not username or len(username) < 2:
        return {}
    results = {}
    async with make_session(12) as session:
        try:
            async with session.get(f"https://huggingface.co/api/users/{username}") as resp:
                if resp.status == 200:
                    d = await resp.json()
                    results["profile"] = {
                        "fullname": d.get("fullname"),
                        "email": d.get("email"),
                        "website": d.get("website"),
                        "twitter": d.get("twitter"),
                        "location": d.get("location"),
                        "orgs": [o.get("name") for o in d.get("orgs", [])][:10],
                        "is_pro": d.get("isPro"),
                        "followers": d.get("numLikes"),
                        "created_at": d.get("createdAt"),
                    }
        except:
            pass
        # Modèles publiés
        try:
            async with session.get(f"https://huggingface.co/api/models?author={username}&limit=10&sort=downloads") as resp:
                if resp.status == 200:
                    models = await resp.json()
                    results["models"] = [{"id": m.get("id"), "downloads": m.get("downloads"),
                                           "likes": m.get("likes"), "tags": m.get("tags", [])[:5],
                                           "pipeline": m.get("pipeline_tag")} for m in models]
        except:
            pass
        # Datasets
        try:
            async with session.get(f"https://huggingface.co/api/datasets?author={username}&limit=10") as resp:
                if resp.status == 200:
                    datasets = await resp.json()
                    results["datasets"] = [{"id": d.get("id"), "downloads": d.get("downloads"),
                                             "likes": d.get("likes"), "tags": d.get("tags", [])[:5]} for d in datasets]
        except:
            pass
        # Spaces
        try:
            async with session.get(f"https://huggingface.co/api/spaces?author={username}&limit=10") as resp:
                if resp.status == 200:
                    spaces = await resp.json()
                    results["spaces"] = [{"id": s.get("id"), "sdk": s.get("sdk"),
                                           "likes": s.get("likes"), "runtime": s.get("runtime")} for s in spaces]
        except:
            pass
    return results


async def lookup_reddit(username: str) -> Dict:
    """Reddit : profil, subreddits actifs, posts récents."""
    username = extract_username(username)
    if not username or len(username) < 2:
        return {}
    results = {}
    hdr = {"User-Agent": "OSINT-Tool/4.0 (research)"}
    async with make_session(12, hdr) as session:
        try:
            async with session.get(f"https://www.reddit.com/user/{username}/about.json") as resp:
                if resp.status == 200:
                    d = (await resp.json()).get("data", {})
                    results["profile"] = {
                        "name": d.get("name"),
                        "created_utc": datetime.utcfromtimestamp(d.get("created_utc", 0)).isoformat(),
                        "link_karma": d.get("link_karma"),
                        "comment_karma": d.get("comment_karma"),
                        "total_karma": d.get("total_karma"),
                        "is_gold": d.get("is_gold"),
                        "is_mod": d.get("is_mod"),
                        "icon_img": d.get("icon_img"),
                        "verified": d.get("verified"),
                        "has_verified_email": d.get("has_verified_email"),
                    }
        except:
            pass
        # Posts récents
        try:
            async with session.get(f"https://www.reddit.com/user/{username}/submitted.json?limit=15") as resp:
                if resp.status == 200:
                    posts = (await resp.json()).get("data", {}).get("children", [])
                    subreddits = list({p["data"].get("subreddit") for p in posts if p.get("data")})[:15]
                    results["recent_posts"] = [{"title": p["data"].get("title")[:80],
                                                 "subreddit": p["data"].get("subreddit"),
                                                 "score": p["data"].get("score"),
                                                 "url": p["data"].get("url")} for p in posts[:8]]
                    results["active_subreddits"] = subreddits
        except:
            pass
        # Commentaires récents
        try:
            async with session.get(f"https://www.reddit.com/user/{username}/comments.json?limit=10") as resp:
                if resp.status == 200:
                    comments = (await resp.json()).get("data", {}).get("children", [])
                    comment_subs = list({c["data"].get("subreddit") for c in comments if c.get("data")})[:10]
                    results["comment_subreddits"] = comment_subs
        except:
            pass
    return results


async def lookup_npm(username: str) -> Dict:
    """npm : packages publiés par l'auteur."""
    username = extract_username(username)
    if not username:
        return {}
    results = {}
    async with make_session(10) as session:
        try:
            async with session.get(f"https://registry.npmjs.org/-/v1/search?text=author:{username}&size=15") as resp:
                if resp.status == 200:
                    d = await resp.json()
                    pkgs = d.get("objects", [])
                    results["packages"] = [{
                        "name": p["package"].get("name"),
                        "version": p["package"].get("version"),
                        "description": p["package"].get("description"),
                        "date": p["package"].get("date"),
                        "links": p["package"].get("links", {}),
                        "keywords": p["package"].get("keywords", [])[:5],
                        "downloads_score": p.get("score", {}).get("detail", {}).get("popularity"),
                    } for p in pkgs]
                    results["total_packages"] = d.get("total", 0)
        except Exception as e:
            results["error"] = str(e)
        # Profil npm
        try:
            async with session.get(f"https://registry.npmjs.org/-/user/org.couchdb.user:{username}") as resp:
                if resp.status == 200:
                    u = await resp.json()
                    results["profile"] = {k: u.get(k) for k in ["name", "email", "github", "twitter", "created"]}
        except:
            pass
    return results


async def lookup_pypi(username: str) -> Dict:
    """PyPI : packages publiés via l'API JSON et le flux RSS."""
    username = extract_username(username)
    if not username:
        return {}
    results = {}
    async with make_session(10) as session:
        # Recherche via le moteur PyPI
        try:
            async with session.get(f"https://pypi.org/search/?o=&q={username}&c=&format=json") as resp:
                pass  # PyPI n'expose pas d'API search publique JSON facilement
        except:
            pass
        # Utilisation de l'API BigQuery via PyPI JSON
        try:
            async with session.get(f"https://pypi.org/pypi/{username}/json") as resp:
                if resp.status == 200:
                    d = await resp.json()
                    info = d.get("info", {})
                    results["package"] = {
                        "name": info.get("name"),
                        "author": info.get("author"),
                        "author_email": info.get("author_email"),
                        "home_page": info.get("home_page"),
                        "license": info.get("license"),
                        "summary": info.get("summary"),
                        "version": info.get("version"),
                        "project_urls": info.get("project_urls"),
                        "classifiers": info.get("classifiers", [])[:8],
                        "requires_python": info.get("requires_python"),
                    }
        except:
            pass
    return results


async def lookup_dockerhub(username: str) -> Dict:
    """Docker Hub : images publiées."""
    username = extract_username(username)
    if not username:
        return {}
    results = {}
    async with make_session(10) as session:
        try:
            async with session.get(f"https://hub.docker.com/v2/repositories/{username}/?page_size=15&ordering=last_updated") as resp:
                if resp.status == 200:
                    d = await resp.json()
                    results["repositories"] = [{
                        "name": r.get("name"),
                        "pulls": r.get("pull_count"),
                        "stars": r.get("star_count"),
                        "is_private": r.get("is_private"),
                        "description": r.get("description"),
                        "last_updated": r.get("last_updated"),
                    } for r in d.get("results", [])]
                    results["total_images"] = d.get("count", 0)
        except Exception as e:
            results["error"] = str(e)
        # Profil utilisateur
        try:
            async with session.get(f"https://hub.docker.com/v2/users/{username}") as resp:
                if resp.status == 200:
                    u = await resp.json()
                    results["profile"] = {k: u.get(k) for k in [
                        "username", "full_name", "location", "company",
                        "profile_url", "date_joined", "gravatar_email"
                    ]}
        except:
            pass
    return results


async def lookup_mastodon(username: str) -> Dict:
    """Mastodon : recherche sur plusieurs instances populaires."""
    uname = extract_username(username)
    if not uname:
        return {}
    instances = [
        "mastodon.social", "fosstodon.org", "infosec.exchange",
        "hachyderm.io", "chaos.social", "tech.lgbt", "sigmoid.social",
        "mastodon.online", "indieweb.social", "mastodon.gamedev.place"
    ]
    results = {"found": []}
    async with make_session(10) as session:
        for instance in instances:
            try:
                async with session.get(f"https://{instance}/api/v1/accounts/lookup?acct={uname}") as resp:
                    if resp.status == 200:
                        d = await resp.json()
                        results["found"].append({
                            "instance": instance,
                            "display_name": d.get("display_name"),
                            "acct": d.get("acct"),
                            "url": d.get("url"),
                            "followers": d.get("followers_count"),
                            "following": d.get("following_count"),
                            "statuses": d.get("statuses_count"),
                            "note_preview": re.sub(r"<[^>]+>", "", d.get("note", ""))[:200],
                            "fields": [{f.get("name"): f.get("value")} for f in d.get("fields", [])],
                            "created_at": d.get("created_at"),
                        })
            except:
                continue
    return results if results["found"] else {}


async def lookup_shodan(query: str) -> Dict:
    """Shodan : recherche sur IP ou domaine (nécessite clé API)."""
    if not SHODAN_API_KEY:
        return {"note": "SHODAN_API_KEY non défini"}
    results = {}
    async with make_session(15) as session:
        try:
            url = (f"https://api.shodan.io/shodan/host/{query}?key={SHODAN_API_KEY}"
                   if is_ip(query)
                   else f"https://api.shodan.io/dns/resolve?hostnames={query}&key={SHODAN_API_KEY}")
            async with session.get(url) as resp:
                if resp.status == 200:
                    d = await resp.json()
                    if is_ip(query):
                        results = {
                            "ip": d.get("ip_str"),
                            "org": d.get("org"),
                            "isp": d.get("isp"),
                            "country": d.get("country_name"),
                            "city": d.get("city"),
                            "os": d.get("os"),
                            "ports": d.get("ports", [])[:20],
                            "vulns": list(d.get("vulns", {}).keys())[:10],
                            "tags": d.get("tags", []),
                            "hostnames": d.get("hostnames", [])[:10],
                            "last_update": d.get("last_update"),
                            "services": [{
                                "port": s.get("port"),
                                "transport": s.get("transport"),
                                "product": s.get("product"),
                                "version": s.get("version"),
                                "cpe": s.get("cpe", []),
                            } for s in d.get("data", [])[:10]],
                        }
                    else:
                        results = {"resolved_ips": d}
        except Exception as e:
            results["error"] = str(e)
    return results


async def lookup_virustotal(query: str) -> Dict:
    """VirusTotal : analyse passive domaine/IP/hash (nécessite clé API)."""
    if not VT_API_KEY:
        return {"note": "VT_API_KEY non défini"}
    headers = {"x-apikey": VT_API_KEY}
    results = {}
    async with make_session(15, headers) as session:
        try:
            if is_ip(query):
                endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
            elif is_domain(query):
                endpoint = f"https://www.virustotal.com/api/v3/domains/{query}"
            else:
                endpoint = f"https://www.virustotal.com/api/v3/files/{query}"

            async with session.get(endpoint) as resp:
                if resp.status == 200:
                    d = (await resp.json()).get("data", {}).get("attributes", {})
                    stats = d.get("last_analysis_stats", {})
                    results = {
                        "reputation": d.get("reputation"),
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "categories": d.get("categories", {}),
                        "registrar": d.get("registrar"),
                        "whois": d.get("whois", "")[:500],
                        "tags": d.get("tags", []),
                        "total_votes": d.get("total_votes", {}),
                    }
        except Exception as e:
            results["error"] = str(e)
    return results


async def lookup_hibp(email: str) -> Dict:
    """Have I Been Pwned : vérification des fuites de données."""
    if not is_email(email):
        return {}
    headers = {"hibp-api-key": HIBP_API_KEY, "user-agent": "OSINT-Tool/4.0"} if HIBP_API_KEY else {"user-agent": "OSINT-Tool/4.0"}
    results = {}
    async with make_session(12, headers) as session:
        try:
            async with session.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false") as resp:
                if resp.status == 200:
                    breaches = await resp.json()
                    results["breaches"] = [{
                        "name": b.get("Name"),
                        "domain": b.get("Domain"),
                        "date": b.get("BreachDate"),
                        "pwn_count": b.get("PwnCount"),
                        "data_classes": b.get("DataClasses", []),
                        "is_verified": b.get("IsVerified"),
                        "is_sensitive": b.get("IsSensitive"),
                    } for b in breaches]
                    results["total_breaches"] = len(breaches)
                elif resp.status == 404:
                    results["status"] = "not found in any breach"
                elif resp.status == 401:
                    results["error"] = "HIBP_API_KEY requis"
        except Exception as e:
            results["error"] = str(e)
        # Pastes
        try:
            async with session.get(f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}") as resp:
                if resp.status == 200:
                    pastes = await resp.json()
                    results["pastes"] = [{"source": p.get("Source"), "id": p.get("Id"),
                                           "date": p.get("Date"), "email_count": p.get("EmailCount")} for p in pastes[:10]]
        except:
            pass
    return results


async def lookup_gravatar(email: str) -> Dict:
    """Gravatar : profil associé à un email."""
    if not is_email(email):
        return {}
    h = md5_email(email)
    results = {"hash": h, "avatar_url": f"https://www.gravatar.com/avatar/{h}?d=404"}
    async with make_session(8) as session:
        try:
            async with session.get(f"https://www.gravatar.com/{h}.json") as resp:
                if resp.status == 200:
                    d = (await resp.json()).get("entry", [{}])[0]
                    results["profile"] = {
                        "display_name": d.get("displayName"),
                        "preferred_username": d.get("preferredUsername"),
                        "about_me": d.get("aboutMe"),
                        "location": d.get("currentLocation"),
                        "urls": [u.get("value") for u in d.get("urls", [])][:5],
                        "accounts": [{a.get("shortname"): a.get("url")} for a in d.get("accounts", [])][:10],
                    }
        except:
            pass
    return results


async def lookup_keybase(username: str) -> Dict:
    """Keybase : profil et preuves de comptes liés."""
    username = extract_username(username)
    if not username:
        return {}
    results = {}
    async with make_session(10) as session:
        try:
            async with session.get(f"https://keybase.io/_/api/1.0/user/lookup.json?username={username}&fields=basics,profile,proofs_summary,cryptocurrency_addresses,stellar") as resp:
                if resp.status == 200:
                    d = (await resp.json()).get("them", {})
                    basics = d.get("basics", {})
                    profile = d.get("profile", {})
                    results["basics"] = {k: basics.get(k) for k in ["username", "ctime", "uid"]}
                    results["profile"] = {k: profile.get(k) for k in ["full_name", "location", "bio"]}
                    proofs = d.get("proofs_summary", {}).get("all", [])
                    results["proofs"] = [{"type": p.get("proof_type"), "state": p.get("state"),
                                           "username": p.get("nametag"), "url": p.get("proof_url")} for p in proofs]
                    crypto = d.get("cryptocurrency_addresses", {})
                    if crypto:
                        results["crypto_addresses"] = crypto
        except Exception as e:
            results["error"] = str(e)
    return results


async def lookup_archive_org(query: str) -> Dict:
    """Wayback Machine : captures historiques."""
    async with make_session(12) as session:
        try:
            async with session.get(f"https://archive.org/wayback/available?url={query}") as resp:
                if resp.status == 200:
                    d = await resp.json()
                    snap = d.get("archived_snapshots", {}).get("closest", {})
                    results = {
                        "available": snap.get("available", False),
                        "url": snap.get("url"),
                        "timestamp": snap.get("timestamp"),
                        "status": snap.get("status"),
                    }
                    # Nombre total de captures
            async with session.get(f"https://web.archive.org/cdx/search/cdx?url={query}&output=json&limit=1&fl=timestamp,statuscode&collapse=urlkey") as resp:
                if resp.status == 200:
                    rows = await resp.json()
                    results["sample_snapshot"] = rows[1] if len(rows) > 1 else None
            async with session.get(f"https://web.archive.org/cdx/search/cdx?url={query}&output=json&limit=0&fl=timestamp") as resp:
                if resp.status == 200:
                    text = await resp.text()
                    results["total_captures"] = text.count("\"") // 2 - 1
            return results
        except Exception as e:
            return {"error": str(e)}


async def lookup_leakix(domain: str) -> Dict:
    """LeakIX : fuites et expositions indexées (sans clé = résultats limités)."""
    if not is_domain(domain):
        return {}
    results = {}
    async with make_session(12) as session:
        try:
            async with session.get(f"https://leakix.net/api/host/{domain}",
                                    headers={"Accept": "application/json"}) as resp:
                if resp.status == 200:
                    d = await resp.json()
                    results["services"] = [{
                        "protocol": s.get("protocol"),
                        "port": s.get("port"),
                        "ip": s.get("ip"),
                        "leak": s.get("leak", {}),
                        "tags": s.get("tags", []),
                    } for s in (d if isinstance(d, list) else [])[:10]]
        except Exception as e:
            results["error"] = str(e)
    return results


async def lookup_pastebin_search(query: str) -> Dict:
    """Recherche via PasteHunter/Google dorks pour Pastebin (heuristique)."""
    results = {}
    # psbdmp.ws est une archive publique de pastes
    async with make_session(10) as session:
        try:
            async with session.get(f"https://psbdmp.ws/api/v3/search/{query}") as resp:
                if resp.status == 200:
                    d = await resp.json()
                    pastes = d.get("data", [])
                    results["psbdmp_pastes"] = [{
                        "id": p.get("id"),
                        "tags": p.get("tags", []),
                        "date": p.get("time"),
                        "url": f"https://pastebin.com/{p.get('id')}",
                    } for p in pastes[:10]]
                    results["psbdmp_total"] = d.get("count", 0)
        except Exception as e:
            results["error"] = str(e)
    return results


async def lookup_cloud_exposure(domain: str) -> Dict:
    """
    Détection d'actifs cloud exposés :
    - Buckets S3 AWS (formats courants)
    - Buckets GCS Google
    - Azure Blob Storage
    - Cloudflare Workers / Pages
    - Subdomains cloud via DNS
    """
    if not is_domain(domain):
        return {}
    base = domain.replace(".", "-").replace("_", "-")
    short = domain.split(".")[0]
    results = {}

    async with make_session(8) as session:
        # ─── AWS S3 ───────────────────────────────────────────────────────────
        s3_candidates = [
            f"{short}.s3.amazonaws.com",
            f"{base}.s3.amazonaws.com",
            f"assets.{domain}",
            f"static.{domain}",
            f"media.{domain}",
            f"backup.{domain}",
        ]
        aws_found = []
        for bucket in s3_candidates:
            try:
                async with session.get(f"https://{bucket}", allow_redirects=False) as resp:
                    if resp.status in (200, 403, 301):
                        aws_found.append({
                            "url": f"https://{bucket}",
                            "status": resp.status,
                            "accessible": resp.status == 200,
                            "forbidden_but_exists": resp.status == 403,
                        })
            except:
                pass
        if aws_found:
            results["aws_s3"] = aws_found

        # ─── Google Cloud Storage ─────────────────────────────────────────────
        gcs_candidates = [
            f"https://storage.googleapis.com/{short}",
            f"https://storage.googleapis.com/{base}",
            f"https://storage.googleapis.com/{domain}",
        ]
        gcs_found = []
        for url in gcs_candidates:
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status in (200, 403):
                        gcs_found.append({"url": url, "status": resp.status, "accessible": resp.status == 200})
            except:
                pass
        if gcs_found:
            results["gcp_storage"] = gcs_found

        # ─── Azure Blob Storage ───────────────────────────────────────────────
        az_candidates = [
            f"https://{short}.blob.core.windows.net",
            f"https://{base}.blob.core.windows.net",
        ]
        az_found = []
        for url in az_candidates:
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status in (200, 400, 403, 404):
                        az_found.append({"url": url, "status": resp.status,
                                          "exists": resp.status != 404})
            except:
                pass
        if az_found:
            results["azure_blob"] = az_found

        # ─── Cloudflare Workers / Pages ───────────────────────────────────────
        cf_candidates = [
            f"https://{short}.workers.dev",
            f"https://{short}.pages.dev",
            f"https://{base}.workers.dev",
        ]
        cf_found = []
        for url in cf_candidates:
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        cf_found.append({"url": url, "status": resp.status})
            except:
                pass
        if cf_found:
            results["cloudflare"] = cf_found

        # ─── Firebase / Supabase ──────────────────────────────────────────────
        fb_candidates = [
            f"https://{short}.firebaseapp.com",
            f"https://{short}-default-rtdb.firebaseio.com/.json",
            f"https://{short}.supabase.co",
        ]
        fb_found = []
        for url in fb_candidates:
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status in (200, 401, 403):
                        fb_found.append({"url": url, "status": resp.status,
                                          "open": resp.status == 200})
            except:
                pass
        if fb_found:
            results["firebase_supabase"] = fb_found

        # ─── Vercel / Netlify / Render ────────────────────────────────────────
        srv_candidates = [
            f"https://{short}.vercel.app",
            f"https://{short}.netlify.app",
            f"https://{short}.onrender.com",
            f"https://{short}.fly.dev",
            f"https://{short}.railway.app",
        ]
        srv_found = []
        for url in srv_candidates:
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        srv_found.append({"url": url, "status": resp.status})
            except:
                pass
        if srv_found:
            results["cloud_hosting"] = srv_found

    return results


async def lookup_gravatar_by_username(username: str) -> Dict:
    """Tentative Gravatar via username (approximation de l'email)."""
    # On ne peut pas MD5 d'un username directement, on renvoie juste l'URL avatar
    h = md5_email(username)
    results = {"gravatar_attempt_url": f"https://www.gravatar.com/avatar/{h}?d=404"}
    return results


async def lookup_censys(query: str) -> Dict:
    """Censys : recherche d'hôtes indexés (nécessite clé API)."""
    if not CENSYS_ID or not CENSYS_SECRET:
        return {"note": "CENSYS_ID / CENSYS_SECRET non définis"}
    import base64
    token = base64.b64encode(f"{CENSYS_ID}:{CENSYS_SECRET}".encode()).decode()
    headers = {"Authorization": f"Basic {token}", "Content-Type": "application/json"}
    results = {}
    async with make_session(15, headers) as session:
        try:
            payload = {"q": query, "per_page": 10}
            async with session.post("https://search.censys.io/api/v2/hosts/search", json=payload) as resp:
                if resp.status == 200:
                    d = await resp.json()
                    hits = d.get("result", {}).get("hits", [])
                    results["hosts"] = [{
                        "ip": h.get("ip"),
                        "services": [{"port": s.get("port"), "name": s.get("service_name")} for s in h.get("services", [])[:5]],
                        "labels": h.get("labels", []),
                        "country": h.get("location", {}).get("country"),
                    } for h in hits]
                    results["total"] = d.get("result", {}).get("total", {}).get("value", 0)
        except Exception as e:
            results["error"] = str(e)
    return results


async def lookup_hunter(domain: str) -> Dict:
    """Hunter.io : emails professionnels associés à un domaine (nécessite clé)."""
    if not HUNTER_API_KEY:
        return {"note": "HUNTER_API_KEY non défini"}
    results = {}
    async with make_session(12) as session:
        try:
            async with session.get(f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_API_KEY}&limit=20") as resp:
                if resp.status == 200:
                    d = (await resp.json()).get("data", {})
                    results["organization"] = d.get("organization")
                    results["pattern"] = d.get("pattern")
                    results["emails"] = [{
                        "value": e.get("value"),
                        "type": e.get("type"),
                        "confidence": e.get("confidence"),
                        "first_name": e.get("first_name"),
                        "last_name": e.get("last_name"),
                        "position": e.get("position"),
                        "linkedin": e.get("linkedin"),
                        "twitter": e.get("twitter"),
                        "sources": [s.get("domain") for s in e.get("sources", [])[:3]],
                    } for e in d.get("emails", [])[:15]]
                    results["email_count"] = d.get("total")
        except Exception as e:
            results["error"] = str(e)
    return results


async def lookup_social_extended(name: str) -> Dict:
    """Vérification de disponibilité sur plusieurs plateformes via HEAD requests."""
    username = extract_username(name)
    if not username or len(username) < 2:
        return {}
    platforms = {
        "Twitter/X":    f"https://twitter.com/{username}",
        "Instagram":    f"https://www.instagram.com/{username}/",
        "TikTok":       f"https://www.tiktok.com/@{username}",
        "LinkedIn":     f"https://www.linkedin.com/in/{username}",
        "Pinterest":    f"https://www.pinterest.com/{username}/",
        "Twitch":       f"https://www.twitch.tv/{username}",
        "YouTube":      f"https://www.youtube.com/@{username}",
        "Medium":       f"https://medium.com/@{username}",
        "Dev.to":       f"https://dev.to/{username}",
        "Hashnode":     f"https://{username}.hashnode.dev",
        "Substack":     f"https://{username}.substack.com",
        "Behance":      f"https://www.behance.net/{username}",
        "Dribbble":     f"https://dribbble.com/{username}",
        "ProductHunt":  f"https://www.producthunt.com/@{username}",
        "Kaggle":       f"https://www.kaggle.com/{username}",
        "Leetcode":     f"https://leetcode.com/{username}",
        "Codepen":      f"https://codepen.io/{username}",
        "Replit":       f"https://replit.com/@{username}",
        "Stackoverflow": f"https://stackoverflow.com/users/?tab=users&q={username}",
    }
    found = []
    possible = []
    async with make_session(8) as session:
        for platform, url in platforms.items():
            try:
                async with session.head(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        found.append({"platform": platform, "url": url, "status": "EXISTS"})
                    elif resp.status == 404:
                        pass
                    else:
                        possible.append({"platform": platform, "url": url, "status": resp.status})
            except:
                pass
    return {"confirmed": found, "possible": possible,
            "generated_usernames": [username, f"{username}eth", f"{username}_dev", f"{username}ai"]}


# ──────────────────────────────────────────────────────────────────────────────
# Graphe visuel
# ──────────────────────────────────────────────────────────────────────────────
def generate_visual_graph(all_data: dict, identifier: str) -> str:
    try:
        from pyvis.network import Network
        net = Network(height="900px", width="100%", directed=False, notebook=False,
                      bgcolor="#0a0a12", font_color="#e0e0ff")
        net.add_node("central", label=identifier, title=f"Cible : {identifier}",
                     color="#FF00FF", size=45, shape="star")
        # Couleurs par catégorie
        cat_colors = {
            "ENS": "#FFD700", "UnstoppableDomains": "#FF8C00",
            "GitHub": "#6e40c9", "GitLab": "#FC6D26",
            "HuggingFace": "#FFD21E", "Reddit": "#FF4500",
            "npm": "#CB3837", "PyPI": "#3775A9",
            "DockerHub": "#2496ED", "Mastodon": "#6364FF",
            "Keybase": "#FF6F21", "Gravatar": "#1E8CBE",
            "Social": "#00BFFF", "WHOIS": "#7FFF00",
            "DNS": "#00FA9A", "CT_Logs": "#00CED1",
            "Shodan": "#FF4040", "VirusTotal": "#394EFF",
            "HIBP": "#DD2727", "Censys": "#FF7F50",
            "Hunter": "#F4B942", "Archive": "#A9A9A9",
            "Cloud": "#00FFFF", "CryptoAddress": "#F7931A",
            "LeakIX": "#FF1493", "Pastebin": "#02A79A",
            "PGP": "#80FF00",
        }
        node_counter = 1
        for source_name, data in all_data.get("sources", {}).items():
            if not data or (isinstance(data, dict) and "error" in data and len(data) == 1):
                continue
            color = cat_colors.get(source_name, "#3399FF")
            source_id = f"source_{source_name}"
            net.add_node(source_id, label=source_name[:20], title=str(data)[:500],
                         color=color, size=30, shape="ellipse")
            net.add_edge("central", source_id, color="#555555")
            if isinstance(data, dict):
                for key, value in list(data.items())[:12]:
                    if not value:
                        continue
                    val_str = str(value)[:220] if isinstance(value, (str, list, dict)) else str(value)
                    detail_id = f"d_{node_counter}"
                    net.add_node(detail_id, label=f"{key[:20]}",
                                 title=f"{key}\n{val_str}", color="#22FFAA", size=18)
                    net.add_edge(source_id, detail_id, color="#336644")
                    node_counter += 1
        net.set_options(json.dumps({
            "physics": {"barnesHut": {"gravitationalConstant": -14000, "centralGravity": 0.3, "springLength": 180},
                        "stabilization": {"iterations": 1500}},
            "nodes": {"font": {"size": 13}},
            "edges": {"smooth": {"type": "continuous"}},
            "interaction": {"hover": True, "tooltipDelay": 150}
        }))
        out = f"results/graph_{identifier.replace('.', '_').replace('/', '_').replace('@', '_')}.html"
        net.save_graph(out)
        return out
    except ImportError:
        return "Pyvis non installé"
    except Exception as e:
        return f"Erreur graph: {e}"


# ══════════════════════════════════════════════════════════════════════════════
#  Worker Qt
# ══════════════════════════════════════════════════════════════════════════════
class StalkerWorker(QThread):
    log_signal      = pyqtSignal(str)
    status_signal   = pyqtSignal(str, str)
    result_signal   = pyqtSignal(str, dict)
    graph_signal    = pyqtSignal(str, str)
    progress_signal = pyqtSignal(int, int)
    finished_signal = pyqtSignal()

    def __init__(self, targets: List[str]):
        super().__init__()
        self.targets = [t.strip() for t in targets if t.strip()]

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run_batch())
        finally:
            loop.close()
            self.finished_signal.emit()

    async def _run_batch(self):
        total = len(self.targets)
        self.log_signal.emit(f"[SYS] BATCH v4.0 → {total} CIBLE(S) — {datetime.utcnow().isoformat()} UTC")
        for idx, target in enumerate(self.targets, 1):
            self.progress_signal.emit(idx, total)
            self.log_signal.emit(f"{'─'*45}\n▶ [{idx}/{total}] {target}")
            try:
                res = await self._process_single(target)
                self.result_signal.emit(target, res)
                self.log_signal.emit("[✓] Traitement terminé.")
            except Exception as e:
                self.log_signal.emit(f"[✗] Erreur critique: {e}")
            await asyncio.sleep(0.5)

    async def _process_single(self, target: str):
        name = normalize_name(target)
        username = extract_username(name)
        results = {
            "input": name,
            "timestamp": datetime.utcnow().isoformat(),
            "sources": {}
        }

        # ── Détermination du type de cible ────────────────────────────────────
        target_is_email  = is_email(name)
        target_is_domain = is_domain(name)
        target_is_ip_val = is_ip(name)

        # ── Construction dynamique des tâches selon le type de cible ──────────
        tasks = {}

        # Identité numérique généraliste
        tasks["GitHub"]     = lookup_github(username)
        tasks["GitLab"]     = lookup_gitlab(username)
        tasks["HuggingFace"]= lookup_huggingface(username)
        tasks["Reddit"]     = lookup_reddit(username)
        tasks["npm"]        = lookup_npm(username)
        tasks["PyPI"]       = lookup_pypi(username)
        tasks["DockerHub"]  = lookup_dockerhub(username)
        tasks["Mastodon"]   = lookup_mastodon(name)
        tasks["Keybase"]    = lookup_keybase(username)
        tasks["Social"]     = lookup_social_extended(name)
        tasks["Archive"]    = lookup_archive_org(name)
        tasks["Pastebin"]   = lookup_pastebin_search(name)
        # ── SOCIAL MESSAGING ──
        tasks["Telegram"] = lookup_telegram(name)
        tasks["Discord"]  = lookup_discord(name)

        if target_is_email:
            tasks["PGP"]      = lookup_pgp(name)
            tasks["Gravatar"] = lookup_gravatar(name)
            tasks["HIBP"]     = lookup_hibp(name)

        if target_is_domain or target_is_ip_val:
            tasks["WHOIS"]   = lookup_whois(name)
            tasks["DNS"]     = advanced_dns(name)
            tasks["CT_Logs"] = lookup_ct_logs(name)
            tasks["Shodan"]  = lookup_shodan(name)
            tasks["VirusTotal"] = lookup_virustotal(name)
            tasks["Censys"]  = lookup_censys(name)
            tasks["Hunter"]  = lookup_hunter(name)
            tasks["Cloud"]   = lookup_cloud_exposure(name)
            tasks["LeakIX"]  = lookup_leakix(name)

        # ENS / Unstoppable si ça ressemble à un domaine Web3
        if name.endswith((".eth", ".crypto", ".nft", ".wallet", ".dao", ".x")):
            tasks["ENS"]               = lookup_ens(name)
            tasks["UnstoppableDomains"]= lookup_unstoppable(name)

        # Crypto address
        tasks["CryptoAddress"] = lookup_crypto_address(name)

        if name.startswith("0x"):
            tasks["Arkham"] = lookup_arkham(name)
            tasks["DeBank"] = lookup_debank(name)

        # ── Exécution parallèle ───────────────────────────────────────────────
        self.status_signal.emit("global", "running")
        self.log_signal.emit(f"[SYS] {len(tasks)} modules actifs")

        coros = {src: asyncio.create_task(t) for src, t in tasks.items()}
        for src, task in coros.items():
            try:
                res = await task
                if asyncio.iscoroutine(res):
                    res = await res
                results["sources"][src] = res
                ok = isinstance(res, dict) and "error" not in res and bool(res)
                icon = "✓" if ok else "·"
                self.log_signal.emit(f"  [{icon}] {src}")
                self.status_signal.emit(src, "success" if ok else "error")
            except Exception as e:
                results["sources"][src] = {"error": str(e)}
                self.log_signal.emit(f"  [✗] {src}: {e}")

        # Sauvegarde JSON
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^\w\-]", "_", name)
        filepath = save_json(results, f"stalker_{safe}_{ts}.json")
        self.log_signal.emit(f"[SAVE] → {filepath}")

        # Génération graphe
        self.log_signal.emit("[GRAPH] Génération du graphe...")
        graph_path = await asyncio.to_thread(generate_visual_graph, results, name)
        self.graph_signal.emit(name, graph_path)
        self.status_signal.emit("global", "idle")
        return results


# ══════════════════════════════════════════════════════════════════════════════
#  Interface Qt
# ══════════════════════════════════════════════════════════════════════════════
CINEMATIC_QSS = """
QMainWindow { background: #05050a; }
QWidget { background: transparent; }
QLineEdit, QTextEdit, QPlainTextEdit, QTreeWidget {
    background: #080810; color: #00ffcc;
    font-family: 'JetBrains Mono', 'Consolas', 'Courier New', monospace;
    border: 1px solid #1a1a30; selection-background-color: #00ffcc;
    selection-color: #000; padding: 5px;
}
QPlainTextEdit { border: none; background: #030308; }
QScrollBar:vertical { background: #0a0a14; width: 6px; border: none; }
QScrollBar::handle:vertical { background: #00ffcc; min-height: 20px; border-radius: 3px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #00ccaa, stop:1 #007755);
    color: #000; font-weight: bold; font-family: 'Consolas', monospace;
    border: none; padding: 7px 16px; border-radius: 4px; letter-spacing: 1px;
}
QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #00ffdd, stop:1 #00aa77); }
QPushButton:pressed { background: #005544; }
QPushButton:disabled { background: #1a1a2e; color: #333; }
QLabel { color: #00ffcc; font-family: 'Consolas', monospace; }
QProgressBar { border: 1px solid #1a1a2e; background: #0a0a14; border-radius: 4px;
               text-align: center; color: #00ffcc; }
QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
    stop:0 #00ffcc, stop:0.5 #ff00ff, stop:1 #0088ff); border-radius: 3px; }
QStatusBar { background: #030308; color: #00ffcc; border-top: 1px solid #1a1a2e;
             font-family: 'Consolas', monospace; }
QTabWidget::pane { border: 1px solid #1a1a2e; }
QTabBar::tab { background: #0a0a14; color: #00ffcc; padding: 6px 14px; border: 1px solid #1a1a2e; }
QTabBar::tab:selected { background: #1a1a30; color: #ff00ff; border-bottom: 2px solid #ff00ff; }
"""


class StalkerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("STALKER MODE ULTRA v4.0 // OSINT CONSOLE EXTENDED")
        self.resize(1400, 900)
        self.setStyleSheet(CINEMATIC_QSS)
        self._setup_ui()
        self.worker = None
        self.graph_paths = {}

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main = QVBoxLayout(central)
        main.setContentsMargins(10, 10, 10, 8)
        main.setSpacing(7)

        # ── Header ─────────────────────────────────────────────────────────────
        hdr = QHBoxLayout()
        title = QLabel("STALKER MODE ULTRA v4.0")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff00ff; letter-spacing: 2px;")
        hdr.addWidget(title)
        hdr.addStretch()
        api_info = QLabel("APIs: GitHub·GitLab·HF·Reddit·npm·PyPI·Docker·Mastodon·Keybase·Gravatar·Cloud·Shodan·VT·HIBP·Censys·Hunter·LeakIX·Archive")
        api_info.setStyleSheet("color: #446655; font-size: 9px;")
        hdr.addWidget(api_info)
        hdr.addSpacing(16)
        self.lbl_status = QLabel("● IDLE")
        self.lbl_status.setStyleSheet("color: #888; font-size: 14px;")
        hdr.addWidget(self.lbl_status)
        main.addLayout(hdr)

        # ── Input bar ──────────────────────────────────────────────────────────
        self.txt_input = QPlainTextEdit()
        self.txt_input.setPlaceholderText(
            "Entrez une cible par ligne :\n"
            "  • Nom d'utilisateur     ex: johndoe\n"
            "  • Email                 ex: john@example.com\n"
            "  • Domaine               ex: example.com\n"
            "  • Adresse IP            ex: 1.2.3.4\n"
            "  • Adresse crypto        ex: 0xABC...\n"
            "  • Domaine ENS/Web3      ex: vitalik.eth"
        )
        self.txt_input.setMaximumHeight(115)

        inp_bar = QHBoxLayout()
        btn_file = QPushButton("📂 IMPORTER")
        btn_file.clicked.connect(self.load_file)
        btn_launch = QPushButton("▶ LANCER SCAN")
        btn_launch.clicked.connect(self.start_scan)
        btn_stop = QPushButton("■ STOP")
        btn_stop.clicked.connect(self.stop_scan)
        self.btn_graph = QPushButton("🌐 GRAPHE")
        self.btn_graph.clicked.connect(self.open_last_graph)
        self.btn_graph.setEnabled(False)
        btn_export = QPushButton("💾 EXPORT JSON")
        btn_export.clicked.connect(self.export_json)

        inp_bar.addWidget(self.txt_input, 1)
        for b in [btn_file, btn_launch, btn_stop, self.btn_graph, btn_export]:
            inp_bar.addWidget(b)
        main.addLayout(inp_bar)

        # ── Progress ───────────────────────────────────────────────────────────
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setTextVisible(False)
        self.progress.hide()
        main.addWidget(self.progress)

        # ── Splitter : log | résultats ─────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)

        log_w = QWidget()
        log_l = QVBoxLayout(log_w)
        log_l.setContentsMargins(0, 0, 0, 0)
        log_l.addWidget(QLabel("► FLUX SYSTÈME"))
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        log_l.addWidget(self.txt_log)
        splitter.addWidget(log_w)

        res_w = QWidget()
        res_l = QVBoxLayout(res_w)
        res_l.setContentsMargins(0, 0, 0, 0)
        res_l.addWidget(QLabel("► RÉSULTATS (JSON)"))
        self.txt_result = QTextEdit()
        self.txt_result.setReadOnly(True)
        self.txt_result.setStyleSheet("font-size: 11px; color: #aaffcc;")
        res_l.addWidget(self.txt_result)
        splitter.addWidget(res_w)

        splitter.setSizes([400, 900])
        main.addWidget(splitter, 1)

        self.statusBar().showMessage("PRÊT — v4.0 EXTENDED // EN ATTENTE DE CIBLE(S)")

    def log(self, msg: str):
        self.txt_log.appendPlainText(f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} {msg}")
        self.txt_log.verticalScrollBar().setValue(self.txt_log.verticalScrollBar().maximum())

    def load_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Importer liste", "", "Text files (*.txt)")
        if path:
            with open(path, "r", encoding="utf-8") as f:
                self.txt_input.setPlainText(f.read())
            self.log(f"[FILE] {Path(path).name} chargé")

    def update_status(self, source: str, status: str):
        if source == "global":
            colors = {"running": "#ffaa00", "idle": "#00ff00"}
            self.lbl_status.setText(f"● {status.upper()}")
            self.lbl_status.setStyleSheet(f"color: {colors.get(status, '#888')}; font-size: 14px;")

    def update_progress(self, curr: int, total: int):
        self.progress.show()
        self.progress.setMaximum(total)
        self.progress.setValue(curr)

    def handle_result(self, target: str, data: dict):
        self.txt_result.setPlainText(json.dumps(data, indent=2, ensure_ascii=False))
        self.log(f"[DATA] Résultats '{target}' — {len(data.get('sources', {}))} sources traitées")

    def handle_graph(self, target: str, path: str):
        self.graph_paths[target] = path
        if path and os.path.exists(path):
            self.btn_graph.setEnabled(True)
            self.log(f"[GRAPH] → {path}")

    def on_finished(self):
        self.progress.hide()
        self.statusBar().showMessage("ANALYSE TERMINÉE // RÉSULTATS DANS /results/")

    def start_scan(self):
        raw = self.txt_input.toPlainText().strip()
        if not raw:
            self.log("[ERR] AUCUNE CIBLE.")
            return
        targets = [t for t in raw.splitlines() if t.strip()]
        self.txt_log.clear()
        self.txt_result.clear()
        self.graph_paths.clear()
        self.btn_graph.setEnabled(False)
        self.progress.show()
        self.log(f"[SYS] INITIALISATION → {len(targets)} CIBLE(S)")
        self.worker = StalkerWorker(targets)
        self.worker.log_signal.connect(self.log)
        self.worker.status_signal.connect(self.update_status)
        self.worker.result_signal.connect(self.handle_result)
        self.worker.graph_signal.connect(self.handle_graph)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.start()

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.log("[SYS] SCAN INTERROMPU PAR L'UTILISATEUR")
            self.progress.hide()

    def open_last_graph(self):
        if self.graph_paths:
            _, path = list(self.graph_paths.items())[-1]
            if os.path.exists(path):
                webbrowser.open(f"file://{os.path.abspath(path)}")

    def export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Exporter JSON", "osint_export.json", "JSON (*.json)")
        if path:
            text = self.txt_result.toPlainText()
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self.log(f"[EXPORT] → {path}")


# ══════════════════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    try:
        app.setFont(QFont("JetBrains Mono", 10))
    except:
        app.setFont(QFont("Consolas", 10))
    window = StalkerGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
