A Chrome extension that detects and blocks phishing attempts in real-time using Google Safe Browsing API and heuristic analysis.
# PhishShield Chrome Extension

A Chrome extension that detects and blocks phishing attempts in real-time using Google Safe Browsing API and heuristic analysis.

## Features

- Real-time URL scanning for phishing detection
- Heuristic-based analysis (IP address detection, suspicious subdomains, typosquatting detection)
- Integration with Google Safe Browsing API
- Visual alerts when phishing is detected
- Detailed information about why a site was flagged

## Installation

### Option 1: Install from Chrome Web Store (Coming Soon)

1. Visit the Chrome Web Store (link to be added when published)
2. Click "Add to Chrome"
3. Confirm the installation

### Option 2: Install as Developer (Unpacked Extension)

1. Clone this repository or download it as a ZIP file and extract it
  
2. Open Chrome and navigate to `chrome://extensions/`

3. Enable "Developer mode" by toggling the switch in the top-right corner

4. Click "Load unpacked" and select the directory containing the extension files

5. The PhishShield extension should now appear in your extensions list and be active

## Configuration

### Google Safe Browsing API Key

The extension uses Google Safe Browsing API to check URLs against known phishing sites. To use your own API key:

1. Get a Google Safe Browsing API key from the [Google Cloud Console](https://console.cloud.google.com/)
- Create a new project
- Enable the Safe Browsing API
- Create credentials (API key)

2. Open `background.js` and replace the placeholder API key with your own:
const GOOGLE_SAFEBROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_API_KEY_HERE";

## Usage
1. After installation, the PhishShield icon will appear in your Chrome toolbar
2. Browse the web normally - PhishShield works in the background to analyze URLs
3. If a potentially malicious site is detected:
   
   - A warning badge will appear on the extension icon
   - Click the icon to see details about why the site was flagged
   - You can choose to go back to safety or proceed with caution
4. For safe sites, no alerts will be shown

## How It Works
PhishShield uses multiple detection methods:

1. Heuristic Analysis :
   
   - Checks for IP addresses in URLs
   - Identifies excessive subdomains
   - Detects typosquatting of popular brands
   - Identifies suspicious URL patterns
2. Google Safe Browsing API :
   
   - Checks URLs against Google's database of known malicious sites
