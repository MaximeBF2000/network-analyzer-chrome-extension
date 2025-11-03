# Network Analyzer Chrome Extension

![Network Analyzer Screenshot](public/assets/screenshot_readme.png)

A powerful Chrome extension for analyzing network traffic directly in the browser's DevTools. This extension provides advanced filtering, search capabilities, and detailed request/response inspection tools designed for web reverse engineering and API debugging.

## Overview

Network Analyzer extends Chrome's native DevTools with a dedicated panel that captures and analyzes all network requests made by web pages. Unlike the standard Network tab, this extension offers:

- **Advanced filtering** with regex support
- **Comprehensive search** across URLs, headers, and bodies
- **Export capabilities** to cURL, JavaScript Fetch, and Python
- **Response body inspection** with search functionality
- **Dark mode** support
- **LLM-friendly formatting** for easy AI analysis

## Features

### 🎯 Request Capture

- Captures all network requests (XHR, Fetch, Document, Script, Stylesheet, Image, Media, etc.)
- Real-time request monitoring
- Request/response headers capture
- Request body capture (form data, JSON, raw data)
- Response body capture (when available)
- Status code and timing information

### 🔍 Advanced Filtering

- **Method Filter**: Filter by HTTP method (GET, POST, PUT, DELETE, PATCH)
- **Status Filter**: Filter by status code ranges (2xx, 3xx, 4xx, 5xx)
- **Type Filter**: Filter by resource type (XHR/Fetch, Document, Script, etc.)
- **URL Filter**: Filter by URL or domain pattern
- **Regex Search**: Full regex support for searching across URLs, headers, and bodies

### 🔎 Powerful Search

- Search across multiple fields:
  - URLs
  - Request headers
  - Response headers
  - Request bodies
  - Response bodies
- Regex pattern matching
- Case-insensitive search
- In-response search with match highlighting and navigation

### 📋 Request Details

Each captured request provides detailed information in multiple tabs:

- **Request Tab**:

  - Full URL
  - Query parameters (parsed)
  - Request headers

- **Response Tab**:

  - Status code and status line
  - Response headers
  - Response body (formatted JSON when applicable)
  - Search functionality within response body

- **cURL Tab**:

  - Ready-to-use cURL command
  - JavaScript Fetch code
  - Python Requests code
  - One-click copy functionality

- **LLM Details Tab**:
  - Formatted request/response details optimized for LLM analysis
  - Easy copy-paste format for ChatGPT and other AI tools

### 🎨 User Experience

- **Dark Mode**: Toggle between light and dark themes
- **Keyboard Shortcuts**:
  - `/` - Focus search input
  - `Esc` - Clear all filters
  - `Tab` - Navigate between search matches (in response body)
  - `Ctrl/Cmd + F` - Focus search in response body
- **Visual Indicators**: Color-coded status codes and HTTP methods
- **One-click Copy**: Copy URLs, headers, bodies, and code snippets

## Installation

### From Source

1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode** (toggle in the top right)
4. Click **Load unpacked**
5. Select the extension directory

The Network Analyzer panel will appear in Chrome DevTools after installation.

### Usage

1. Open Chrome DevTools (`F12` or `Cmd+Option+I` on Mac / `Ctrl+Shift+I` on Windows/Linux)
2. Navigate to the **Network Analyzer** tab
3. Browse to any website - requests will be captured automatically
4. Use filters and search to find specific requests
5. Click on any request to view detailed information

### Capturing Requests

- **Start/Stop Capture**: Use the "Capture" / "Stop Capture" button to control when requests are recorded
- **Clear**: Use the "Clear" button to remove all captured requests

## Technical Details

### Architecture

- **Manifest V3**: Built using Chrome Extension Manifest V3
- **Service Worker**: `background.js` runs as a service worker to capture network requests
- **DevTools Panel**: `panel.html/js` provides the main UI in Chrome DevTools
- **WebRequest API**: Uses Chrome's `webRequest` API to intercept and log network traffic
- **DevTools Network API**: Uses `chrome.devtools.network` API to capture response bodies

### Permissions

- `webRequest`: Required to intercept network requests
- `tabs`: Required to communicate with content scripts
- `storage`: Required to save user preferences (dark mode)
- `<all_urls>`: Required to monitor network requests from all websites

### Data Flow

1. Background script (`background.js`) listens to `webRequest` events
2. Request data is captured at multiple stages:
   - `onBeforeRequest`: Captures request body
   - `onBeforeSendHeaders`: Captures request headers
   - `onHeadersReceived`: Captures response headers
   - `onCompleted`/`onErrorOccurred`: Finalizes request data
3. Data is sent to DevTools panel via `chrome.runtime` messaging
4. DevTools panel (`panel.js`) displays and manages the UI
5. Response bodies are captured via `chrome.devtools.network.onRequestFinished`

### Limitations

- **Response Bodies**: Some response bodies may not be available due to CORS restrictions or binary content
- **Cross-Origin Requests**: Some request details may be limited for cross-origin requests
- **Performance**: Very high request volumes (1000+ requests) may impact performance

## File Structure

```
network_analyzer_extension/
├── manifest.json          # Extension manifest (Manifest V3)
├── background.js           # Service worker for request capture
├── devtools.html          # DevTools page entry point
├── devtools.js            # DevTools panel creation
├── panel.html             # Main UI HTML
├── panel.js               # Main UI logic and request handling
├── README.md              # This file
├── REQUIREMENTS.md        # Detailed requirements and specifications
└── public/
    └── assets/
        └── screenshot_readme.png  # Screenshot of the extension
```

## Development

### Testing

1. Load the extension in Chrome as described in Installation
2. Open DevTools and navigate to the Network Analyzer tab
3. Visit various websites to test request capture
4. Test filtering, search, and export features

### Debugging

- Check the background script console: Right-click the extension icon → "Inspect popup" (or use the service worker inspection)
- Check the panel console: DevTools → Network Analyzer tab → Right-click → "Inspect"

## Use Cases

- **Web Reverse Engineering**: Analyze API calls made by web applications
- **API Debugging**: Inspect request/response details for API development
- **Security Research**: Examine network traffic for security analysis
- **Performance Analysis**: Monitor network requests and their timing
- **Learning**: Understand how web applications communicate with servers

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is open source and available for use and modification.

---

**Note**: This extension is designed for development and debugging purposes. Always respect website terms of service and privacy policies when analyzing network traffic.
