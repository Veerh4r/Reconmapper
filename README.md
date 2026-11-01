#  ReconMapper 🗺️
Map target URLs, detect map services, and extract hardcoded 
API keys from JavaScript bundles for bug bounty hunting.

📖 About • 🏗️ Installation • ⛏️ Usage• 🚀 Examples

## About

`recon_mapper` fetches and analyzes all JavaScript bundles
loaded by a target website. It detects hardcoded API keys
and secrets directly from client-side JS — showing the
exact source file, line number, and code context for
every finding so you can report fast.

## Installation

git clone https://github.com/B5970/Reconmapper.git
cd ReconMapper
pip install requests beautifulsoup4

## Usage

python recon_mapper.py -u https://target.com

## Examples

Scan a target:
python recon_mapper.py -u https://target.com

With Burp Suite proxy:
python recon_mapper.py -u https://target.com -p http://127.0.0.1:8080

Selenium mode for JS-heavy sites:
python recon_mapper.py -u https://target.com -d

Custom output folder:
python recon_mapper.py -u https://target.com -o ./reports

## Features

- Detects 9 map services (Google Maps, Mapbox, Leaflet,
  OpenLayers, HERE, Bing, TomTom, Cesium, ArcGIS)
- Extracts 15+ secret patterns (Google API Keys, AWS,
  Stripe, JWT, Firebase, GitHub, Slack and more)
- Exact source file + line number per finding
- Severity rating: CRITICAL / HIGH / MEDIUM / LOW
- Proxy + Selenium support
- JSON report export

## Disclaimer

For authorized security testing and bug bounty hunting
only. Use only on targets you have permission to test.
The author is not responsible for any misuse.
