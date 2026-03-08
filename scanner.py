import subprocess
import json
import nvdlib
import time
import sys
import re
import os
import urllib.parse
import xml.etree.ElementTree as ET

from Wappalyzer import Wappalyzer, WebPage
import requests
import warnings

# Suppress noisy warnings from python-Wappalyzer / requests
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Configuration
GHDB_PATH = "ghdb.xml"

# IGNORE LIST (applied to both WhatWeb and Wappalyzer results)
IGNORE_PLUGINS = [
    "Country", "IP", "Title", "HTTPServer", "RedirectLocation",
    "Http-Headers", "Frame", "Script", "X-Powered-By", "Email",
    "MetaGenerator", "Cookies", "X-Frame-Options", "X-XSS-Protection",
    "Strict-Transport-Security", "JQuery", "Google-Analytics", "HTML5",
    "UA-Compatible"
]

# ---------------------------------------------------------------------------
# Version Helpers
# ---------------------------------------------------------------------------

def parse_version(v_str):
    """Converts a version string into a tuple of integers for accurate semantic comparison."""
    if not v_str:
        return ()
    match = re.search(r'^(\d+(?:\.\d+)*)', str(v_str))
    if not match:
        return ()
    return tuple(map(int, match.group(1).split('.')))


def compare_versions(v1_tuple, operator, v2_str):
    """Pads tuples to equal length and compares them mathematically."""
    if not v1_tuple or not v2_str:
        return False
    v2_tuple = parse_version(v2_str)
    if not v2_tuple:
        return False

    length = max(len(v1_tuple), len(v2_tuple))
    t1 = v1_tuple + (0,) * (length - len(v1_tuple))
    t2 = v2_tuple + (0,) * (length - len(v2_tuple))

    if operator == '<':  return t1 < t2
    if operator == '<=': return t1 <= t2
    if operator == '>':  return t1 > t2
    if operator == '>=': return t1 >= t2
    if operator == '==': return t1 == t2
    return False


def clean_version(version_string):
    if not version_string:
        return None
    match = re.search(r'(\d+\.\d+)', version_string)
    if match:
        return match.group(1)
    return version_string

# ---------------------------------------------------------------------------
# CPE / NVD Helpers
# ---------------------------------------------------------------------------

def check_cpe_match(technology, target_version, cpe_match):
    """Evaluates NVD JSON boundaries and vendor data to eliminate false positives."""
    criteria = getattr(cpe_match, 'criteria', "")
    if not criteria:
        return False

    parts = criteria.split(':')
    if len(parts) < 6:
        return False

    vendor = parts[3].lower()
    product = parts[4].lower()
    cpe_version = parts[5]

    tech_lower = technology.lower()
    if tech_lower != product:
        return False

    target_v = parse_version(target_version)
    if not target_v:
        return False

    v_start_inc = getattr(cpe_match, 'versionStartIncluding', None)
    v_start_exc = getattr(cpe_match, 'versionStartExcluding', None)
    v_end_inc   = getattr(cpe_match, 'versionEndIncluding', None)
    v_end_exc   = getattr(cpe_match, 'versionEndExcluding', None)

    # 1. Evaluate Explicit API Boundaries
    if v_start_inc or v_start_exc or v_end_inc or v_end_exc:
        match = True
        if v_start_inc and not compare_versions(target_v, '>=', v_start_inc): match = False
        if v_start_exc and not compare_versions(target_v, '>',  v_start_exc): match = False
        if v_end_inc   and not compare_versions(target_v, '<=', v_end_inc):   match = False
        if v_end_exc   and not compare_versions(target_v, '<',  v_end_exc):   match = False
        return match

    # 2. Evaluate Exact Version Match
    if cpe_version not in ['*', '-', '']:
        if compare_versions(target_v, '==', cpe_version):
            return True

    # 3. Wildcard Evaluation
    if cpe_version == '*' and not (v_start_inc or v_start_exc or v_end_inc or v_end_exc):
        return True

    return False


def fetch_cves(name, version_raw):
    clean_ver = clean_version(version_raw) or "Unknown"
    name = name.lower()

    print(f"    [*] Querying NVD for: {name} (Targeting v{version_raw})...", end=" ", flush=True)
    try:
        valid_cves = []

        # 1. DIRECT CPE QUERY
        try:
            cpe_string = f"cpe:2.3:a:*:{name}:{clean_ver}:*:*:*:*:*:*:*"
            cpe_results = nvdlib.searchCVE(virtualMatchString=cpe_string, limit=100)
            for cve in cpe_results:
                valid_cves.append(cve)
        except Exception:
            pass

        # 2. HYBRID FALLBACK
        if not valid_cves:
            fallback_results = nvdlib.searchCVE(keywordSearch=name, limit=300)
            for cve in fallback_results:
                is_vulnerable = False
                if hasattr(cve, 'configurations') and cve.configurations:
                    for config in cve.configurations:
                        nodes = getattr(config, 'nodes', [])
                        for node in nodes:
                            for m in getattr(node, 'cpeMatch', []):
                                if getattr(m, 'vulnerable', False) and check_cpe_match(name, version_raw, m):
                                    is_vulnerable = True
                                    break
                            if is_vulnerable: break
                        if is_vulnerable: break
                if is_vulnerable:
                    valid_cves.append(cve)

        # Deduplicate
        unique_cves = {c.id: c for c in valid_cves}
        final_cves = list(unique_cves.values())

        print(f"Found {len(final_cves)} matches!" if final_cves else "No hits.")
        return final_cves
    except Exception as e:
        print(f"Error connecting to NVD: {e}")
        return []

# ---------------------------------------------------------------------------
# GHDB Search
# ---------------------------------------------------------------------------

def search_local_ghdb(technology, version=None):
    if not os.path.exists(GHDB_PATH):
        return []

    # Build a list of version strings to try for strict matching
    version_candidates = set()
    if version and version != "Unknown":
        version_candidates.add(version.strip().lower())          # full raw e.g. "1.19.0"
    clean_ver = clean_version(version)
    if clean_ver and clean_ver != "Unknown":
        version_candidates.add(clean_ver.lower())                # trimmed e.g. "1.19"
        # Also try major.minor only (first two parts)
        parts = clean_ver.split(".")
        if len(parts) >= 2:
            version_candidates.add(".".join(parts[:2]).lower()) # e.g. "1.19"
        if len(parts) >= 3:
            version_candidates.add(".".join(parts[:3]).lower()) # e.g. "1.19.0"

    print(f"    [*] Searching GHDB for '{technology}'...", end=" ")

    strict_matches = []
    generic_matches = []

    try:
        tree = ET.parse(GHDB_PATH)
        root = tree.getroot()

        for entry in root.findall('entry'):
            query_elem = entry.find('query')
            desc_elem  = entry.find('short_description')
            query = query_elem.text if query_elem is not None and query_elem.text else ""
            desc  = desc_elem.text  if desc_elem  is not None and desc_elem.text  else ""
            combined_text = (query + " " + desc).lower()

            if technology.lower() in combined_text:
                # Check any version candidate against the combined text
                version_hit = any(v in combined_text for v in version_candidates) if version_candidates else False

                if version_hit:
                    strict_matches.append({'query': query, 'desc': desc, 'type': 'ver'})
                else:
                    generic_matches.append({'query': query, 'desc': desc, 'type': 'gen'})

        if strict_matches:
            print(f"Found {len(strict_matches)} VERSION-SPECIFIC dorks!")
            return strict_matches
        elif generic_matches:
            print(f"No version matches. Found {len(generic_matches)} generic dorks.")
            return generic_matches[:3]
        else:
            print("No dorks found.")
            return []
    except Exception as e:
        print(f"Error: {e}")
        return []

# ---------------------------------------------------------------------------
# Fingerprinting: WhatWeb
# ---------------------------------------------------------------------------

def run_whatweb(url):
    """Run WhatWeb and return a unified tech dict: {name: version_or_None}"""
    print(f"[*] WhatWeb: Fingerprinting {url} passively...")
    techs = {}
    try:
        result = subprocess.run(
            ["whatweb", "--log-json=-", "-a", "1", "-q", url],
            capture_output=True, text=True, check=True
        )
        clean_text = result.stdout.strip().replace("][", "]|||[").replace("]\n[", "]|||[")
        chunks = clean_text.split("|||")

        for chunk in chunks:
            try:
                data = json.loads(chunk)
                pages = data if isinstance(data, list) else [data]
                for page in pages:
                    plugins = page.get("plugins", {})
                    for name, details in plugins.items():
                        if name in IGNORE_PLUGINS:
                            continue
                        version_list = details.get("version", [])
                        version_raw = version_list[0] if version_list else None
                        # Keep the more specific (versioned) entry if duplicate
                        if name not in techs or (version_raw and not techs[name]):
                            techs[name] = version_raw
            except Exception:
                pass
    except FileNotFoundError:
        print("    [!] WhatWeb not installed – skipping. Install with: sudo apt install whatweb")
    except Exception as e:
        print(f"    [!] WhatWeb error: {e}")
    return techs

# ---------------------------------------------------------------------------
# Fingerprinting: Wappalyzer
# ---------------------------------------------------------------------------

def run_wappalyzer(url):
    """Run python-Wappalyzer and return a unified tech dict: {name: version_or_None}"""
    print(f"[*] Wappalyzer: Fingerprinting {url}...")
    techs = {}
    try:
        wappalyzer = Wappalyzer.latest()
        session = requests.Session()
        session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        })
        resp = session.get(url, timeout=15, verify=True, allow_redirects=True)
        webpage = WebPage.new_from_response(resp)

        # analyze_with_versions returns {tech_name: {'versions': [...], 'categories': [...]}}
        results = wappalyzer.analyze_with_versions_and_categories(webpage)

        for tech_name, info in results.items():
            if tech_name in IGNORE_PLUGINS:
                continue
            versions = info.get("versions", [])
            version = versions[0] if versions else None
            # Keep the more specific (versioned) entry if duplicate
            if tech_name not in techs or (version and not techs[tech_name]):
                techs[tech_name] = version
    except ImportError:
        print("    [!] python-Wappalyzer not installed – skipping.")
        print("    [!] Install with: pip install python-Wappalyzer")
    except Exception as e:
        print(f"    [!] Wappalyzer error: {e}")
    return techs

# ---------------------------------------------------------------------------
# Merge results from both engines
# ---------------------------------------------------------------------------

def merge_tech_results(whatweb_techs, wappalyzer_techs):
    """
    Merge two {name: version} dicts.  For overlapping names prefer the entry
    that has a version string.  Matching is case-insensitive but we preserve
    the casing from whichever source we keep.
    """
    merged = {}  # lowercase key -> (display_name, version, sources)

    for name, ver in whatweb_techs.items():
        key = name.lower()
        merged[key] = (name, ver, ["WhatWeb"])

    for name, ver in wappalyzer_techs.items():
        key = name.lower()
        if key in merged:
            existing_name, existing_ver, sources = merged[key]
            sources.append("Wappalyzer")
            # Prefer whichever has a version
            if ver and not existing_ver:
                merged[key] = (name, ver, sources)
            else:
                merged[key] = (existing_name, existing_ver, sources)
        else:
            merged[key] = (name, ver, ["Wappalyzer"])

    return merged

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <url>")
        return
    target = sys.argv[1]

    # ---------- Fingerprinting ----------
    whatweb_techs    = run_whatweb(target)
    wappalyzer_techs = run_wappalyzer(target)
    merged           = merge_tech_results(whatweb_techs, wappalyzer_techs)

    if not merged:
        print("[!] No technologies detected.")
        return

    # ---------- Report ----------
    print("\n" + "=" * 60)
    print(f"VULNSENTRY REPORT: {target}")
    print("=" * 60)

    for key, (name, version_raw, sources) in sorted(merged.items()):
        source_tag = " + ".join(sources)
        print(f"\n[+] {name} {f'(v{version_raw})' if version_raw else ''} [{source_tag}]")

        if version_raw:
            vulns = fetch_cves(name, version_raw)
            if vulns:
                print(f"    [!] CRITICAL: Found {len(vulns)} CVEs:")
                for v in vulns:
                    link = f"https://nvd.nist.gov/vuln/detail/{v.id}"
                    desc = (
                        v.descriptions[0].value
                        if hasattr(v, 'descriptions') and v.descriptions
                        else "No description available."
                    )
                    print(f"        - {v.id} [LINK]: {link}")
                    print(f"          SUMMARY: {desc}\n")

        dorks = search_local_ghdb(name, version_raw)
        if dorks:
            print("    [G] RELEVANT DORKS:")
            for dork in dorks:
                tag = "[STRICT]" if dork['type'] == 'ver' else "[GENERIC]"
                query_encoded = urllib.parse.quote(dork['query'])
                google_link = f"https://www.google.com/search?q={query_encoded}"
                print(f"        {tag} {dork['desc']}")
                print(f"          Query: {dork['query']}")
                print(f"          [LINK]: {google_link}\n")

        time.sleep(2)


if __name__ == "__main__":
    main()