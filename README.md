# PhishGuard DeepSea - Firefox Extension

A powerful phishing detection extension for Firefox that uses advanced heuristics, typosquatting detection, and threat database integration to protect users from malicious websites.

## Features

### Core Protection
- **Real-time URL Analysis**: Automatically scans every website you visit
- **Typosquatting Detection**: Identifies domains that impersonate legitimate brands
- **Threat Database Integration**: Supports PhishTank and Google Safe Browsing APIs
- **URL Shortener Detection**: Expands and analyzes shortened URLs
- **IDN Homograph Detection**: Detects international domain name attacks
- **Smart Blocking**: Configurable threat threshold for automatic blocking

### User Interface
- **Beautiful Deep Sea Theme**: Immersive underwater-themed UI
- **Radar/Sonar Visualization**: Real-time threat scanning animation
- **Detailed Threat Reports**: See exactly why a site is flagged
- **Statistics Tracking**: Monitor protection effectiveness
- **Whitelist/Blacklist**: Customize protection for trusted/known bad sites

### Advanced Features
- **Performance Caching**: Analysis results cached for faster performance
- **Configurable Settings**: Adjust protection levels and notifications
- **Export/Import Data**: Backup your settings and lists
- **Comprehensive Logging**: Debug mode for troubleshooting

## Installation

### From Source
1. Clone or download this repository
2. Open Firefox and navigate to `about:debugging`
3. Click "This Firefox" in the sidebar
4. Click "Load Temporary Add-on"
5. Select the `manifest.json` file from this directory

### From ZIP
1. Download the extension as a ZIP file
2. Extract it to a folder
3. Follow steps 2-5 above

## Configuration

### API Keys (Optional but Recommended)
For enhanced protection, you can add API keys:

1. **PhishTank**: Get a free API key from [phishtank.com](https://www.phishtank.com/api_register.php)
2. **Google Safe Browsing**: Get an API key from [Google Cloud Console](https://console.cloud.google.com/)

To add API keys:
1. Click the extension icon
2. Click the settings/options button (or right-click extension → Options)
3. Enter your API keys in the "API Integration" section
4. Click "Save Settings"

### Threat Threshold
Adjust the blocking threshold (0-100):
- **0-24**: Very lenient (only blocks confirmed threats)
- **25-49**: Balanced (recommended)
- **50-74**: Strict (blocks suspicious sites)
- **75-100**: Very strict (may have false positives)

## How It Works

### Detection Methods

1. **Typosquatting Analysis**
   - Compares domain names to known legitimate brands
   - Uses Levenshtein distance algorithm
   - Detects character substitutions, additions, deletions

2. **URL Pattern Analysis**
   - Checks for suspicious TLDs (.tk, .ml, .ga, etc.)
   - Detects excessive subdomains
   - Flags long or random-looking domains
   - Identifies suspicious keywords

3. **Security Checks**
   - HTTP vs HTTPS detection
   - IP address usage
   - Port number validation
   - Certificate validation (future)

4. **Threat Database Lookup**
   - PhishTank database (if API key provided)
   - Google Safe Browsing (if API key provided)

5. **URL Shortener Expansion**
   - Detects common URL shortening services
   - Expands URLs to reveal final destination
   - Analyzes both original and expanded URLs

### Scoring System

Each threat indicator adds points to a risk score (0-100):
- **0-24**: Safe (green)
- **25-49**: Suspicious (orange)
- **50-74**: Dangerous (red)
- **75-100**: Critical (red, blocked)

## File Structure

```
phishguard/
├── manifest.json          # Extension manifest
├── background.js          # Background service worker
├── content.js            # Content script for page analysis
├── popup.js              # Popup UI logic
├── popup.html            # Popup UI
├── options.js             # Settings page logic
├── options.html           # Settings page
├── warning.js            # Warning page logic
├── warning.html           # Warning page
├── utils.js               # Utility functions
├── rules.json             # Detection rules and configuration
├── icons/                 # Extension icons
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── ml-training/           # ML model training (optional)
    ├── train_model.py
    └── dataset_phishing.csv
```

## Development

### Prerequisites
- Firefox 91.0 or later
- Basic knowledge of JavaScript

### Building
No build process required - the extension uses vanilla JavaScript.

### Testing
1. Load the extension in Firefox (see Installation)
2. Visit test phishing sites (use safe test URLs)
3. Check browser console for debug logs
4. Verify blocking and notifications work

### Debugging
Enable debug mode in `background.js`:
```javascript
CONFIG.DEBUG = true;
```

## Known Issues

- **Missing Icons**: The manifest references `icon16.png` and `icon48.png` which need to be created from `icon128.png`
- **ML Model**: Training script exists but model integration is not yet implemented

## Future Improvements

- [ ] ML model integration for enhanced detection
- [ ] SSL certificate validation
- [ ] Real-time threat database updates
- [ ] Browser history analysis
- [ ] Email link scanning
- [ ] Community threat reporting

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Security

- All API keys are stored securely in browser storage
- No data is sent to external servers except threat databases (with your API keys)
- All analysis happens locally in your browser
- Open source - you can audit the code

## Support

For issues, questions, or feature requests, please open an issue on the repository.

## Credits

- PhishTank for providing phishing database API
- Google Safe Browsing for threat intelligence
- All contributors and testers

---

**Stay Safe Online! 🛡️**
