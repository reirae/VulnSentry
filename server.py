from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from scanner import run_whatweb, run_wappalyzer, merge_tech_results, fetch_cves, clean_version, search_local_ghdb, IGNORE_PLUGINS
import json
import queue
import threading
import urllib.parse

app = Flask(__name__)
CORS(app)  # Allow requests from Chrome extension

def scan_and_stream(url, q):
    """Runs the full scan and puts log/result events into the queue."""

    def log(msg):
        q.put({"type": "log", "message": msg})

    log(f"[*] Starting scan for: {url}")

    # 1. Fingerprinting with WhatWeb + Wappalyzer
    log(f"[*] Fingerprinting {url} with WhatWeb...")
    whatweb_results = run_whatweb(url)
    log(f"[+] WhatWeb complete. Found {len(whatweb_results)} plugins.")

    log(f"[*] Fingerprinting {url} with Wappalyzer...")
    wappalyzer_results = run_wappalyzer(url)
    log(f"[+] Wappalyzer complete. Found {len(wappalyzer_results)} plugins.")

    merged = merge_tech_results(whatweb_results, wappalyzer_results)

    if not merged:
        log("[!] No technologies detected by either scanner.")
        q.put({"type": "done", "data": []})
        return

    log(f"[+] Merged results: {len(merged)} unique technologies.")

    processed_data = []

    for key, (name, version_raw, sources) in merged.items():
            if name in IGNORE_PLUGINS:
                continue

            if version_raw is None:
                version_raw = "Unknown"
            clean_ver = clean_version(version_raw)

            log(f"\n[+] Technology: {name} {'(v' + version_raw + ')' if version_raw != 'Unknown' else '(no version)'}")

            # 2. CVE Lookup
            cves = []
            if clean_ver and clean_ver != "Unknown":
                log(f"    [*] Querying NVD for: {name} {clean_ver}...")
                try:
                    nvd_results = fetch_cves(name, clean_ver)
                    if nvd_results:
                        log(f"    [!] Found {len(nvd_results)} CVE(s):")
                        for x in nvd_results:
                            log(f"        - {x.id}")
                            cves.append({
                                "id": x.id,
                                "desc": x.descriptions[0].value,
                                "link": f"https://nvd.nist.gov/vuln/detail/{x.id}"
                            })
                    else:
                        log(f"    [ ] No CVEs found for {name} {clean_ver}.")
                except Exception as e:
                    log(f"    [!] NVD query error: {e}")
            else:
                log(f"    [-] Skipping CVE lookup (no version detected).")

            # 3. GHDB Search
            log(f"    [*] Searching GHDB for '{name}'...")
            try:
                dorks = search_local_ghdb(name, version_raw)
                enriched_dorks = []
                if dorks:
                    log(f"    [G] Found {len(dorks)} relevant dork(s):")
                    for dork in dorks:
                        tag = "[STRICT]" if dork['type'] == 'ver' else "[GENERIC]"
                        # Use query as fallback if desc is missing/empty
                        display_desc = dork['desc'].strip() if dork.get('desc', '').strip() else dork['query']
                        google_link = f"https://www.google.com/search?q={urllib.parse.quote(dork['query'])}"
                        log(f"        {tag} {display_desc}")
                        log(f"          Query: {dork['query']}")
                        log(f"          Link:  {google_link}")
                        enriched_dorks.append({
                            "type": dork['type'],
                            "desc": display_desc,
                            "query": dork['query'],
                            "link": google_link
                        })
                else:
                    log(f"    [ ] No GHDB dorks found for {name}.")
                dorks = enriched_dorks
            except Exception as e:
                log(f"    [!] GHDB search error: {e}")
                dorks = []

            processed_data.append({
                "technology": name,
                "version": clean_ver,
                "sources": sources,
                "cves": cves,
                "dorks": dorks
            })

    log(f"\n[*] Scan complete. {len(processed_data)} technologies processed.")
    q.put({"type": "done", "data": processed_data})


@app.route('/scan', methods=['POST'])
def scan_endpoint():
    data = request.json
    url = data.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    print(f"\n[*] Request received for: {url}")

    q = queue.Queue()

    # Run scan in background thread so we can stream output
    thread = threading.Thread(target=scan_and_stream, args=(url, q))
    thread.start()

    def generate():
        while True:
            event = q.get()
            # SSE format: each message is "data: <json>\n\n"
            yield f"data: {json.dumps(event)}\n\n"
            if event["type"] == "done":
                break

    return Response(generate(), mimetype='text/event-stream',
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, threaded=True)