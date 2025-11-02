# Network Analyzer - Requirements & UI/UX Specs

## Purpose

Advanced network traffic analyzer optimized for web reverse engineering, providing superior filtering, search, and visualization compared to Chrome DevTools Network tab.

## Core Requirements

### 1. Data Capture

- Capture all network requests (XHR, Fetch, Document, Script, Stylesheet, Image, etc.)
- Capture request headers, response headers, request body, status codes
- Capture timing information (when available)
- Store request history with timestamps

### 2. Filtering System

- **Quick Filters**:
  - Method (GET, POST, PUT, DELETE, etc.)
  - Status code ranges (2xx, 3xx, 4xx, 5xx)
  - Resource type (XHR/Fetch, Document, Script, Image, etc.)
  - Domain/URL pattern matching
  - MIME type filtering
- **Advanced Filters**:
  - Regex pattern matching on URLs
  - Header-based filtering (e.g., requests with specific headers)
  - Body content filtering (for JSON, form data, etc.)
  - Response time filtering
  - Combine multiple filters with AND/OR logic
  - Save filter presets

### 3. Search System

- Full-text search across:
  - URLs
  - Request headers (names and values)
  - Response headers (names and values)
  - Request bodies (formatted JSON, form data, etc.)
  - Response bodies (when available)
- Regex search support
- Case-sensitive/insensitive toggle
- Highlight search matches
- Search history

### 4. Views & Visualization

- **Table View**: Sortable columns (Method, URL, Status, Type, Time, Size)
- **Timeline View**: Visual timeline of requests with waterfall display
- **Grouped View**: Group by domain, endpoint pattern, or status code
- **Request Detail Panel**: Expandable row showing full request/response details
  - Formatted JSON viewer
  - Syntax highlighting for code
  - Pretty-print for HTML/XML
  - Copy individual header/value pairs
  - Copy full request as cURL command
  - Copy full request as JavaScript fetch()

### 5. Reverse Engineering Features

- **Export Options**:
  - Export as cURL commands
  - Export as JavaScript fetch() code
  - Export as Python requests code
  - Export as HAR file
  - Export selected requests only
- **Request Analysis**:
  - Highlight unusual patterns (large payloads, suspicious headers)
  - Show request chains/dependencies
  - Compare similar requests side-by-side
  - Detect API endpoints (auto-detect REST patterns)
  - Extract authentication tokens/headers
- **Request Manipulation** (Future):
  - Replay requests
  - Modify and resend
  - Save request templates

### 6. UI/UX Design Principles

- **Clean & Modern**: Dark theme (matching DevTools), minimal clutter
- **Keyboard Shortcuts**: Power user features
  - `/` to focus search
  - `Esc` to clear filters
  - `Ctrl/Cmd + F` for search
  - Arrow keys to navigate requests
- **Performance**:
  - Virtual scrolling for large request lists (1000+ requests)
  - Debounced search/filtering
  - Lazy loading of request bodies
- **Accessibility**:
  - Clear visual hierarchy
  - Color coding (status codes, resource types)
  - Tooltips for icons
  - Responsive layout

## Technical Implementation

### Architecture

- **DevTools Panel**: Main UI in Chrome DevTools
- **Background Script**: Captures network data via webRequest API
- **Message Passing**: Background → DevTools panel for real-time updates

### Data Storage

- In-memory storage (cleared on panel close)
- Optional: Export to file for persistence

### Limitations

- Response bodies: webRequest API doesn't capture response bodies directly. Users can use Chrome DevTools Network tab for this, or we note this limitation.
- Request bodies: Can be captured with `requestBody` option in `onBeforeRequest` listener.
