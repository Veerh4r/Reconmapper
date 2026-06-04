#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║                    ReconMapper v1.0                      ║
║    Bug Bounty - URL Map & Key Extraction Tool            ║
╚══════════════════════════════════════════════════════════╝
Author  :  Birdao
Usage   : python3 recon_mapper.py -u https://target.com
"""

import re
import sys
import json
import time
import argparse
import urllib.parse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# ─────────────────────────────────────────────
#  DETECTION SIGNATURES
# ─────────────────────────────────────────────

MAP_SERVICES = {
    "Google Maps": {
        "urls": ["maps.googleapis.com", "maps.google.com", "mapsplatform.google.com"],
        "scripts": ["maps.googleapis.com/maps/api", "maps.google.com/maps/api"],
        "patterns": [r"new\s+google\.maps", r"google\.maps\.Map", r"initMap\s*\("],
        "key_pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "key_name": "Google API Key",
    },
    "Mapbox": {
        "urls": ["api.mapbox.com", "events.mapbox.com", "tiles.mapbox.com"],
        "scripts": ["api.mapbox.com/mapbox-gl-js", "mapbox-gl.js"],
        "patterns": [r"mapboxgl\.", r"new\s+mapboxgl\.Map", r"mapbox\.Map"],
        "key_pattern": r"pk\.[A-Za-z0-9]{60,}",
        "key_name": "Mapbox Public Token",
    },
    "Leaflet": {
        "urls": ["unpkg.com/leaflet", "cdnjs.cloudflare.com/ajax/libs/leaflet"],
        "scripts": ["leaflet.js", "leaflet-src.js"],
        "patterns": [r"L\.map\(", r"L\.tileLayer\(", r"new L\.Map"],
        "key_pattern": None,
        "key_name": None,
    },
    "OpenLayers": {
        "urls": ["openlayers.org", "cdn.jsdelivr.net/npm/ol"],
        "scripts": ["ol.js", "openlayers"],
        "patterns": [r"new\s+ol\.Map", r"ol\.layer\.Tile", r"from\s+['\"]ol['\"]"],
        "key_pattern": None,
        "key_name": None,
    },
    "HERE Maps": {
        "urls": ["js.api.here.com", "maps.ls.hereapi.com"],
        "scripts": ["js.api.here.com/v3"],
        "patterns": [r"new\s+H\.Map", r"H\.service\.Platform", r"hereApiKey"],
        "key_pattern": r"[A-Za-z0-9_\-]{43}",
        "key_name": "HERE API Key",
    },
    "Bing Maps": {
        "urls": ["dev.virtualearth.net", "ecn.dev.virtualearth.net"],
        "scripts": ["bing.com/maps", "microsoft.com/maps"],
        "patterns": [r"Microsoft\.Maps\.Map", r"new\s+Microsoft\.Maps"],
        "key_pattern": r"A[kK][a-zA-Z0-9\-_]{60,}",
        "key_name": "Bing Maps Key",
    },
    "TomTom": {
        "urls": ["api.tomtom.com", "maps.tomtom.com"],
        "scripts": ["api.tomtom.com/maps-sdk"],
        "patterns": [r"tt\.map\(", r"tomtom\.map"],
        "key_pattern": r"[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}",
        "key_name": "TomTom API Key",
    },
    "Cesium": {
        "urls": ["cesium.com", "ion.cesium.com"],
        "scripts": ["cesium.js", "Cesium.js"],
        "patterns": [r"new\s+Cesium\.Viewer", r"Cesium\.Ion\.defaultAccessToken"],
        "key_pattern": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        "key_name": "Cesium Ion Token",
    },
    "ArcGIS": {
        "urls": ["js.arcgis.com", "arcgisonline.com", "esri.com"],
        "scripts": ["js.arcgis.com/4", "esri/Map"],
        "patterns": [r"esri/Map", r"new\s+Map\(\{basemap", r"require\(['\"]esri"],
        "key_pattern": None,
        "key_name": None,
    },
}

GENERIC_KEY_PATTERNS = {
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Stripe Secret Key":    r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Public Key":    r"pk_live_[0-9a-zA-Z]{24,}",
    "Twilio Auth Token":    r"SK[0-9a-fA-F]{32}",
    "Mailgun API Key":      r"key-[0-9a-zA-Z]{32}",
    "SendGrid API Key":     r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}",
    "Firebase DB URL":      r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Mapbox Token":         r"pk\.[A-Za-z0-9]{60,}",
    "Github Token":         r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "JWT Token":            r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*",
    "Slack Token":          r"xox[baprs]\-[0-9A-Za-z\-]{10,}",
    "Private Key Block":    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
    "Basic Auth URL":       r"https?://[^:/@\s]+:[^@\s]+@[^\s]+",
    "Generic Secret":       r"(?i)(secret|api_key|apikey|access_token|auth_token)\s*[=:]\s*['\"][A-Za-z0-9\-_\.]{12,}['\"]",
    "Password in URL/Code": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
}

# ─────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    PURPLE = "\033[95m"
    GRAY   = "\033[90m"
    WHITE  = "\033[97m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════╗
║       Hexa ReconMapper v1.0  🗺️                           
║  Map Service Detector + Key Extractor  |  Bug Bounty     
╚══════════════════════════════════════════════════════════╝{C.RESET}
""")

def info(msg):  print(f"  {C.CYAN}[*]{C.RESET} {msg}")
def ok(msg):    print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):  print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):   print(f"  {C.RED}[x]{C.RESET} {msg}")
def section(t): print(f"\n{C.PURPLE}{C.BOLD}{'─'*10} {t} {'─'*10}{C.RESET}")

# ─────────────────────────────────────────────
#  SESSION
# ─────────────────────────────────────────────

def make_session(proxy=None):
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
        s.verify = False  # Burp / ZAP
    return s

# ─────────────────────────────────────────────
#  FETCH & PARSE
# ─────────────────────────────────────────────

def fetch_page(url, session):
    try:
        resp = session.get(url, timeout=15, allow_redirects=True)
        info(f"HTTP {resp.status_code}  [{url}]")
        if resp.status_code in (401, 407):
            warn("Authentication required — analysis limited to headers.")
        return resp  # Return even on 403/4xx — HTML body still useful
    except Exception as e:
        err(f"Fetch failed: {e}")
        return None

def extract_all_urls(html, base_url):
    """Pull every src/href/url() reference from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    found = set()

    # Standard tags
    for tag, attr in [("script","src"),("link","href"),("img","src"),
                      ("iframe","src"),("a","href"),("source","src")]:
        for el in soup.find_all(tag):
            val = el.get(attr, "")
            if val:
                found.add(urllib.parse.urljoin(base_url, val))

    # Inline JS strings that look like URLs
    for text in [s.string or "" for s in soup.find_all("script")]:
        for m in re.findall(r"['\"]((https?|//)[^\s'\"<>{}|\\^`\[\]]{10,})['\"]", text):
            found.add(urllib.parse.urljoin(base_url, m[0]))

    # CSS url()
    for style in soup.find_all("style"):
        for m in re.findall(r'url\(["\']?(https?[^)"\'\s]+)', style.string or ""):
            found.add(m)

    return found

def get_all_js_content(urls, session):
    """Download JS files and return combined content with URL markers."""
    js_content = ""
    for u in urls:
        if not re.search(r"\.js(\?.*)?$", u, re.I):
            continue
        try:
            r = session.get(u, timeout=10)
            if "javascript" in r.headers.get("content-type","") or ".js" in u:
                js_content += f"\n/* === {u} === */\n" + r.text + "\n"
        except Exception:
            pass
    return js_content

# ─────────────────────────────────────────────
#  MAP SERVICE DETECTION
# ─────────────────────────────────────────────

def detect_map_services(html, urls, js_content, response_headers):
    detected = []
    all_text = html + js_content

    for service, sig in MAP_SERVICES.items():
        score = 0
        evidence = []

        # URL match
        for u in urls:
            for domain in sig["urls"]:
                if domain in u:
                    score += 3
                    evidence.append(f"URL: {u[:80]}")
                    break

        # Script src match
        soup = BeautifulSoup(html, "html.parser")
        for script in soup.find_all("script", src=True):
            for s in sig["scripts"]:
                if s in script["src"]:
                    score += 3
                    evidence.append(f"Script src: {script['src'][:80]}")

        # JS pattern match
        for pat in sig["patterns"]:
            m = re.search(pat, all_text)
            if m:
                score += 2
                snippet = all_text[max(0, m.start()-20):m.end()+20].replace("\n"," ")
                evidence.append(f"Code: ...{snippet.strip()}...")

        if score >= 2:
            detected.append({
                "service": service,
                "score": score,
                "evidence": evidence[:4],  # top 4
            })

    detected.sort(key=lambda x: x["score"], reverse=True)
    return detected

# ─────────────────────────────────────────────
#  KEY EXTRACTION
# ─────────────────────────────────────────────

def extract_keys(html, js_content, urls, map_services, js_url_map=None):
    """
    js_url_map: dict { "/* === URL === */\n...content..." marker offset -> url }
    We rebuild it from js_content markers to track which JS file a match came from.
    """
    findings = []

    # Build source index: list of (start_offset, end_offset, source_label)
    sources = []
    # HTML is first
    sources.append((0, len(html), "HTML (inline)"))
    offset = len(html) + 1  # +1 for the \n separator

    # Parse JS content markers inserted by get_all_js_content
    for m in re.finditer(r"/\* === (https?://[^\s]+) === \*/", js_content):
        url = m.group(1)
        # find next marker or end
        next_m = re.search(r"/\* === https?://", js_content[m.end():])
        end = m.end() + next_m.start() if next_m else len(js_content)
        sources.append((offset + m.start(), offset + end, url))

    searchable = html + "\n" + js_content

    def find_source(pos):
        for (s, e, label) in sources:
            if s <= pos < e:
                return label
        return "Unknown"

    # Generic patterns
    for name, pattern in GENERIC_KEY_PATTERNS.items():
        for m in re.finditer(pattern, searchable):
            val = m.group(0)
            if not any(f["value"] == val for f in findings):
                ctx_start = max(0, m.start() - 60)
                ctx_end   = min(len(searchable), m.end() + 60)
                context   = searchable[ctx_start:ctx_end].replace("\n", " ").strip()
                source    = find_source(m.start())
                line_num  = searchable[:m.start()].count("\n") + 1
                findings.append({
                    "type":     name,
                    "value":    val,
                    "context":  context,
                    "source":   source,
                    "line":     line_num,
                    "severity": _severity(name),
                })

    # Map-service-specific keys
    for svc in map_services:
        kp = MAP_SERVICES[svc["service"]].get("key_pattern")
        kn = MAP_SERVICES[svc["service"]].get("key_name")
        if not kp:
            continue
        for m in re.finditer(kp, searchable):
            val = m.group(0)
            if not any(f["value"] == val for f in findings):
                source   = find_source(m.start())
                line_num = searchable[:m.start()].count("\n") + 1
                findings.append({
                    "type":     f"{kn} ({svc['service']})",
                    "value":    val,
                    "context":  "",
                    "source":   source,
                    "line":     line_num,
                    "severity": "HIGH",
                })

    findings.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["severity"],4))
    return findings

def _severity(name):
    critical = ["AWS Access Key","AWS Secret Key","Stripe Secret Key","Private Key Block","Twilio Auth Token","SendGrid API Key"]
    high     = ["Google API Key","Mapbox Token","Github Token","Slack Token","Firebase DB URL","Mailgun API Key"]
    medium   = ["JWT Token","Generic Secret","Password in URL/Code","Basic Auth URL"]
    if name in critical: return "CRITICAL"
    if name in high:     return "HIGH"
    if name in medium:   return "MEDIUM"
    return "LOW"

def _sev_color(sev):
    return {
        "CRITICAL": C.RED + C.BOLD,
        "HIGH":     C.YELLOW + C.BOLD,
        "MEDIUM":   C.CYAN,
        "LOW":      C.GRAY,
    }.get(sev, C.RESET)

# ─────────────────────────────────────────────
#  REQUEST/RESPONSE MAP
# ─────────────────────────────────────────────

def categorize_url(url):
    u = url.lower()
    if any(x in u for x in ["maps.", "tiles.", "geocod", "routing", "directions"]): return "🗺️  Map/Geo"
    if re.search(r"\.(js|jsx|ts|tsx)(\?|$)", u):  return "📜 JavaScript"
    if re.search(r"\.(css)(\?|$)", u):             return "🎨 Stylesheet"
    if re.search(r"\.(png|jpg|gif|svg|ico|webp)(\?|$)", u): return "🖼️  Image"
    if re.search(r"\.(woff2?|ttf|eot)(\?|$)", u): return "🔤 Font"
    if re.search(r"(api|graphql|rest|v\d+/)", u):  return "🔌 API Endpoint"
    if re.search(r"\.(json|xml|csv)(\?|$)", u):    return "📦 Data File"
    if any(x in u for x in ["cdn.", "static.", "assets.", "media."]):return "🏎️  CDN/Static"
    if re.search(r"\.(html?|php|asp|jsp)(\?|$)", u): return "📄 Page"
    return "🔗 Other"

# ─────────────────────────────────────────────
#  SELENIUM MODE (dynamic JS sites)
# ─────────────────────────────────────────────

def selenium_capture(url, proxy=None):
    if not SELENIUM_AVAILABLE:
        warn("Selenium not installed — skipping dynamic capture.")
        warn("Install with: pip3 install selenium")
        return None, []

    info("Starting headless browser for dynamic JS rendering...")
    caps = DesiredCapabilities.CHROME
    caps["goog:loggingPrefs"] = {"performance": "ALL"}

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1280,800")
    if proxy:
        opts.add_argument(f"--proxy-server={proxy}")

    try:
        driver = webdriver.Chrome(options=opts, desired_capabilities=caps)
        driver.get(url)
        time.sleep(4)  # Let JS execute
        html = driver.page_source

        network_log = []
        for entry in driver.get_log("performance"):
            try:
                msg = json.loads(entry["message"])["message"]
                if msg.get("method") == "Network.requestWillBeSent":
                    req = msg["params"].get("request", {})
                    network_log.append({
                        "url": req.get("url",""),
                        "method": req.get("method","GET"),
                        "type": msg["params"].get("type",""),
                        "headers": req.get("headers", {}),
                    })
            except Exception:
                pass

        driver.quit()
        ok(f"Selenium captured {len(network_log)} network requests")
        return html, network_log
    except Exception as e:
        err(f"Selenium failed: {e}")
        return None, []

# ─────────────────────────────────────────────
#  OUTPUT & REPORT
# ─────────────────────────────────────────────

def print_url_map(urls_by_cat):
    section("REQUEST/RESPONSE URL MAP")
    total = sum(len(v) for v in urls_by_cat.values())
    info(f"Total unique URLs found: {C.BOLD}{total}{C.RESET}")
    for cat, items in sorted(urls_by_cat.items()):
        print(f"\n  {C.CYAN}{cat}{C.RESET}  ({len(items)})")
        for u in sorted(items)[:20]:
            print(f"    {C.GRAY}{u[:110]}{C.RESET}")
        if len(items) > 20:
            print(f"    {C.GRAY}... and {len(items)-20} more{C.RESET}")

def print_map_detection(detected):
    section("MAP SERVICE DETECTION")
    if not detected:
        warn("No map services detected.")
        return
    for d in detected:
        score_bar = "█" * min(d["score"], 10)
        print(f"\n  {C.GREEN}{C.BOLD}✔  {d['service']}{C.RESET}  [{C.YELLOW}{score_bar}{C.RESET}  score={d['score']}]")
        for ev in d["evidence"]:
            print(f"    {C.GRAY}↳ {ev[:100]}{C.RESET}")

def print_keys(findings):
    section("SENSITIVE KEY / SECRET EXTRACTION")
    if not findings:
        ok("No secrets found (or well hidden).")
        return
    warn(f"Found {len(findings)} potential secret(s)!")
    for f in findings:
        sev_col = _sev_color(f["severity"])
        print(f"\n  {sev_col}[{f['severity']}]{C.RESET}  {C.BOLD}{f['type']}{C.RESET}")
        val = f["value"]
        display_val = val if len(val) <= 20 else val[:8] + "..." + val[-8:]
        print(f"    Value   : {C.YELLOW}{display_val}{C.RESET}")
        print(f"    Source  : {C.GREEN}{f.get('source','Unknown')}{C.RESET}")
        print(f"    Line    : {C.CYAN}~{f.get('line','?')}{C.RESET}")
        if f["context"]:
            print(f"    Context : {C.GRAY}{f['context'][:120]}{C.RESET}")

def save_report(target_url, urls_by_cat, map_services, findings, network_log, out_dir):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = re.sub(r"[^\w]", "_", urllib.parse.urlparse(target_url).netloc)
    fname  = Path(out_dir) / f"recon_{domain}_{ts}.json"
    Path(out_dir).mkdir(exist_ok=True)

    report = {
        "tool": "HexStrike ReconMapper v1.0",
        "target": target_url,
        "timestamp": ts,
        "url_map": {k: list(v) for k, v in urls_by_cat.items()},
        "map_services": map_services,
        "secrets": findings,
        "dynamic_requests": network_log[:200],
    }

    with open(fname, "w") as f:
        json.dump(report, f, indent=2)
    ok(f"Report saved → {fname}")
    return str(fname)

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="recon_mapper",
        description="HexStrike ReconMapper — Bug Bounty URL + Map + Key Recon Tool",
    )
    parser.add_argument("-u", "--url",      required=True,  help="Target URL (e.g. https://target.com)")
    parser.add_argument("-p", "--proxy",    default=None,   help="Proxy (e.g. http://127.0.0.1:8080 for Burp)")
    parser.add_argument("-d", "--dynamic",  action="store_true", help="Enable Selenium for JS-heavy sites")
    parser.add_argument("-o", "--output",   default="./recon_reports", help="Output directory for JSON report")
    parser.add_argument("--no-color",       action="store_true", help="Disable colored output")
    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith("_"):
                setattr(C, attr, "")

    banner()
    info(f"Target  : {C.BOLD}{args.url}{C.RESET}")
    info(f"Proxy   : {args.proxy or 'None'}")
    info(f"Dynamic : {'Yes (Selenium)' if args.dynamic else 'No'}")
    info(f"Output  : {args.output}\n")

    session      = make_session(proxy=args.proxy)
    dynamic_html = None
    network_log  = []

    # ── 1. Static fetch
    resp = fetch_page(args.url, session)
    if resp is None:
        err("Cannot reach target (connection error). Exiting.")
        sys.exit(1)

    html      = resp.text
    req_hdrs  = dict(resp.request.headers)
    resp_hdrs = dict(resp.headers)

    section("HTTP HEADERS")
    interesting = ["server","x-powered-by","x-frame-options","strict-transport-security",
                   "content-security-policy","x-content-type-options","set-cookie","location"]
    for k,v in resp_hdrs.items():
        if k.lower() in interesting:
            print(f"  {C.CYAN}{k}{C.RESET}: {v[:150]}")

    # ── 2. Dynamic capture (optional)
    if args.dynamic:
        dynamic_html, network_log = selenium_capture(args.url, proxy=args.proxy)
        if dynamic_html:
            html = dynamic_html

    # ── 3. URL extraction
    section("URL EXTRACTION")
    all_urls = extract_all_urls(html, args.url)

    # Add dynamic network URLs
    for req in network_log:
        if req.get("url"):
            all_urls.add(req["url"])

    ok(f"Extracted {len(all_urls)} unique URLs")

    urls_by_cat = defaultdict(set)
    for u in all_urls:
        urls_by_cat[categorize_url(u)].add(u)

    print_url_map(urls_by_cat)

    # ── 4. JS content fetch
    section("JAVASCRIPT ANALYSIS")
    info("Fetching external JS files for deep analysis...")
    js_content = get_all_js_content(all_urls, session)
    ok(f"Fetched ~{len(js_content)//1024} KB of JS content")

    # ── 5. Map service detection
    detected = detect_map_services(html, all_urls, js_content, resp_hdrs)
    print_map_detection(detected)

    # ── 6. Key extraction
    findings = extract_keys(html, js_content, all_urls, detected, js_url_map=None)
    print_keys(findings)

    # ── 7. Report
    section("REPORT")
    save_report(args.url, urls_by_cat, detected, findings, network_log, args.output)

    print(f"\n{C.GREEN}{C.BOLD}{'═'*55}{C.RESET}")
    print(f"  {C.GREEN}✔  Scan complete!{C.RESET}")
    print(f"  Map services  : {C.BOLD}{len(detected)}{C.RESET} detected")
    print(f"  URLs found    : {C.BOLD}{len(all_urls)}{C.RESET}")
    print(f"  Secrets found : {C.BOLD}{C.RED if findings else C.GREEN}{len(findings)}{C.RESET}")
    print(f"{C.GREEN}{C.BOLD}{'═'*55}{C.RESET}\n")

if __name__ == "__main__":
    main()
    
    
    