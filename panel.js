// Network Analyzer Panel Script
class NetworkAnalyzer {
  constructor() {
    this.requests = new Map()
    this.selectedRequestId = null
    this.inspectedTabId = null
    this.isCapturing = true // Start capturing by default
    this.filters = {
      search: '',
      method: '',
      status: '',
      type: '',
      url: ''
    }

    // Response body search state
    this.responseSearchState = {
      searchTerm: '',
      matches: [],
      currentMatchIndex: -1,
      originalText: ''
    }

    this.init()
  }

  init() {
    // Connect to background script
    this.port = chrome.runtime.connect({ name: 'network-analyzer' })

    // Map to match devtools network requests with webRequest data
    // Key: URL + method + timestamp (rounded to nearest second)
    this.pendingResponseBodies = new Map()

    // Listen to chrome.devtools.network for response bodies
    chrome.devtools.network.onRequestFinished.addListener(harRequest => {
      this.captureResponseBody(harRequest)
    })

    // Get the inspected tab ID to filter requests by tab
    // Note: chrome.devtools.inspectedWindow.tabId might not be available in all Chrome versions
    // We'll use a different approach: show all requests and let the user filter if needed
    // The key change is removing origin-based filtering which was too restrictive
    this.inspectedTabId = null

    // Get the inspected tab's URL (for reference, but we won't filter by origin)
    chrome.devtools.inspectedWindow.eval(
      'window.location.href',
      inspectedUrl => {
        this.inspectedUrl = inspectedUrl || ''

        // Panel is ready, no need to send INIT since we'll receive all requests

        // Also listen for URL changes
        chrome.devtools.network.onNavigated.addListener(url => {
          this.inspectedUrl = url
          // Clear requests on navigation (optional)
          // this.requests.clear()
          // this.render()
        })
      }
    )

    this.port.onMessage.addListener(msg => {
      // Only process requests if capturing is enabled
      if (!this.isCapturing) {
        return
      }

      if (msg.type === 'NETWORK_REQUEST') {
        // Filter requests by matching URL domain
        if (this.shouldShowRequest(msg.data)) {
          this.addRequest(msg.data)
        }
      } else if (msg.type === 'NETWORK_REQUEST_UPDATE') {
        if (this.shouldShowRequest(msg.data)) {
          this.updateRequest(msg.requestId, msg.data)
        }
      } else if (msg.type === 'NETWORK_REQUEST_COMPLETE') {
        if (this.shouldShowRequest(msg.data)) {
          this.completeRequest(msg.requestId, msg.data)
        }
      }
    })

    this.setupUI()
    this.setupKeyboardShortcuts()

    // Initialize dark mode after a small delay to ensure DOM is ready
    // This is especially important in devtools panels
    setTimeout(() => {
      this.initDarkMode()
      this.updateCaptureButton() // Initialize capture button state
    }, 100)
  }

  captureResponseBody(harRequest) {
    // Get response body
    harRequest.getContent(body => {
      // Check for various failure cases
      if (
        body === null ||
        body === undefined ||
        (typeof body === 'string' &&
          body.length === 0 &&
          harRequest.response.status !== 204)
      ) {
        // Response body not available (might be blocked by CORS, etc.)
        // Store as "not available" marker
        this.storeResponseBodyUnavailable(harRequest)
        return
      }

      // Normalize URLs for matching (remove trailing slashes, handle encoding)
      const harUrl = this.normalizeUrl(harRequest.request.url)
      const harMethod = (harRequest.request.method || 'GET').toUpperCase()

      // Try to find matching request in our data
      let matchedRequest = null
      let matchedRequestId = null

      // Search through requests to find a match
      for (const [requestId, req] of this.requests.entries()) {
        if (this.matchesRequest(req, harUrl, harMethod, harRequest)) {
          matchedRequest = req
          matchedRequestId = requestId
          break
        }
      }

      if (matchedRequest) {
        // Update the request with response body
        matchedRequest.responseBody = body
        matchedRequest.responseBodyMimeType =
          harRequest.response.content?.mimeType || ''

        // Update the display if this request is selected
        if (this.selectedRequestId === matchedRequestId) {
          const activeTab =
            document.querySelector('.detail-tab.active')?.dataset.tab
          if (activeTab === 'response') {
            this.renderDetailPanel('response')
          }
        }

        this.render()
      } else {
        // Store for later - request might come from webRequest later
        // Use a more flexible key (URL + method only, no timestamp)
        const key = `${harUrl}::${harMethod}`
        this.pendingResponseBodies.set(key, {
          body: body,
          mimeType: harRequest.response.content?.mimeType || '',
          harRequest: harRequest,
          timestamp: Date.now() // Store when we captured it
        })

        // Also try to match later (in case request comes in after)
        setTimeout(() => {
          this.tryMatchPendingResponse(key)
        }, 500)
        setTimeout(() => {
          this.tryMatchPendingResponse(key)
        }, 2000)
      }
    })
  }

  storeResponseBodyUnavailable(harRequest) {
    // Mark that we tried to get the response body but it's not available
    const harUrl = this.normalizeUrl(harRequest.request.url)
    const harMethod = (harRequest.request.method || 'GET').toUpperCase()
    const key = `${harUrl}::${harMethod}`

    // Find matching request and mark response body as unavailable
    for (const [requestId, req] of this.requests.entries()) {
      const reqUrl = this.normalizeUrl(req.url)
      const reqMethod = (req.method || 'GET').toUpperCase()

      if (reqUrl === harUrl && reqMethod === harMethod) {
        if (req.responseBody === undefined) {
          req.responseBodyUnavailable = true

          if (this.selectedRequestId === requestId) {
            const activeTab =
              document.querySelector('.detail-tab.active')?.dataset.tab
            if (activeTab === 'response') {
              this.renderDetailPanel('response')
            }
          }
        }
        break
      }
    }
  }

  normalizeUrl(url) {
    try {
      const urlObj = new URL(url)
      // Remove trailing slash for matching
      let path = urlObj.pathname
      if (path !== '/' && path.endsWith('/')) {
        path = path.slice(0, -1)
      }
      return urlObj.origin + path + urlObj.search
    } catch (e) {
      return url
    }
  }

  matchesRequest(webRequest, harUrl, harMethod, harRequest) {
    // Normalize webRequest URL
    const webUrl = this.normalizeUrl(webRequest.url)
    const webMethod = (webRequest.method || 'GET').toUpperCase()

    // Match by URL and method
    if (webUrl !== harUrl) return false
    if (webMethod !== harMethod) return false

    // Timestamp matching (within 10 seconds for more tolerance)
    const webRequestTime = webRequest.timeStamp || webRequest.timestamp || 0
    const harRequestTime = harRequest.time * 1000 // Convert to milliseconds
    const timeDiff = Math.abs(webRequestTime - harRequestTime)

    return timeDiff < 10000 // 10 second tolerance
  }

  tryMatchPendingResponse(key) {
    const pending = this.pendingResponseBodies.get(key)
    if (!pending) return

    // Try to find matching request
    // Key format: URL::METHOD or URL::METHOD::TIMESTAMP
    const parts = key.split('::')
    const url = parts[0]
    const method = parts[1]
    const normalizedUrl = this.normalizeUrl(url)
    const normalizedMethod = method.toUpperCase()

    for (const [requestId, req] of this.requests.entries()) {
      const reqUrl = this.normalizeUrl(req.url)
      const reqMethod = (req.method || 'GET').toUpperCase()

      if (reqUrl === normalizedUrl && reqMethod === normalizedMethod) {
        if (
          !req.hasOwnProperty('responseBody') ||
          req.responseBody === undefined
        ) {
          req.responseBody = pending.body
          req.responseBodyMimeType = pending.mimeType

          if (this.selectedRequestId === requestId) {
            const activeTab =
              document.querySelector('.detail-tab.active')?.dataset.tab
            if (activeTab === 'response') {
              this.renderDetailPanel('response')
            }
          }

          this.render()
        }

        this.pendingResponseBodies.delete(key)
        break
      }
    }
  }

  createRequestKey(url, method, time) {
    // Round time to nearest second for matching
    const roundedTime = Math.floor(time)
    return `${url}::${method}::${roundedTime}`
  }

  shouldShowRequest(req) {
    // Show all requests - don't filter by origin or tab
    // The native Network tab shows all requests regardless of origin,
    // so we should do the same. Users can filter using the search/filter UI if needed.

    // Only exclude requests that are clearly not from the inspected context:
    // - Requests with tabId === -1 that are from other tabs (but we can't easily detect this)
    // For now, show everything and let users filter manually

    return true
  }

  setupUI() {
    // Search input
    const searchInput = document.getElementById('searchInput')
    searchInput.addEventListener('input', e => {
      this.filters.search = e.target.value
      this.render()
    })

    // Filters
    document.getElementById('methodFilter').addEventListener('change', e => {
      this.filters.method = e.target.value
      this.render()
    })

    document.getElementById('statusFilter').addEventListener('change', e => {
      this.filters.status = e.target.value
      this.render()
    })

    document.getElementById('typeFilter').addEventListener('change', e => {
      this.filters.type = e.target.value
      this.render()
    })

    document.getElementById('urlFilter').addEventListener('input', e => {
      this.filters.url = e.target.value
      this.render()
    })

    // Capture toggle button
    document.getElementById('captureBtn').addEventListener('click', () => {
      this.toggleCapture()
    })

    // Clear button
    document.getElementById('clearBtn').addEventListener('click', () => {
      this.requests.clear()
      this.selectedRequestId = null
      this.render()
      this.closeDetailPanel()
    })

    // Tab switching
    document.querySelectorAll('.detail-tab').forEach(tab => {
      tab.addEventListener('click', e => {
        if (e.target.id === 'detailCloseBtn') return // Don't process close button as tab
        document
          .querySelectorAll('.detail-tab')
          .forEach(t => t.classList.remove('active'))
        e.target.classList.add('active')
        const tabName = e.target.dataset.tab || 'headers'
        this.renderDetailPanel(tabName)
      })
    })

    // Close button
    document.getElementById('detailCloseBtn').addEventListener('click', () => {
      this.closeDetailPanel()
    })

    // Dark mode toggle
    document.getElementById('darkModeToggle').addEventListener('click', () => {
      this.toggleDarkMode()
    })
  }

  initDarkMode() {
    // Load dark mode preference from chrome.storage.local
    // Ensure DOM is ready before accessing elements
    chrome.storage.local.get(['darkMode'], result => {
      if (chrome.runtime.lastError) {
        console.warn(
          'Error loading dark mode preference:',
          chrome.runtime.lastError
        )
        return
      }

      // Check if darkMode exists and is explicitly true (handles undefined, null, false)
      const isDarkMode = result.darkMode === true

      // Use setTimeout to ensure DOM elements are ready
      setTimeout(() => {
        this.setDarkMode(isDarkMode)
      }, 0)
    })
  }

  toggleDarkMode() {
    const isDarkMode = document.body.classList.contains('dark-mode')
    const newDarkMode = !isDarkMode
    this.setDarkMode(newDarkMode)

    // Save preference to chrome.storage.local with error handling and verification
    chrome.storage.local.set({ darkMode: newDarkMode }, () => {
      if (chrome.runtime.lastError) {
        console.error(
          'Error saving dark mode preference:',
          chrome.runtime.lastError
        )
        // Try to save again or use fallback
        return
      }

      // Verify the save worked by reading it back
      chrome.storage.local.get(['darkMode'], result => {
        if (result.darkMode !== newDarkMode) {
          console.error(
            'Dark mode preference verification failed. Expected:',
            newDarkMode,
            'Got:',
            result.darkMode
          )
        }
      })
    })
  }

  toggleCapture() {
    this.isCapturing = !this.isCapturing
    this.updateCaptureButton()
  }

  updateCaptureButton() {
    const captureBtn = document.getElementById('captureBtn')
    if (!captureBtn) return

    if (this.isCapturing) {
      captureBtn.textContent = 'Stop Capture'
      captureBtn.title = 'Stop capturing new network requests'
    } else {
      captureBtn.textContent = 'Capture'
      captureBtn.title = 'Start capturing new network requests'
    }
  }

  setDarkMode(enabled) {
    const body = document.body
    const toggleText = document.getElementById('darkModeToggleText')
    const toggleIcon = document.querySelector('#darkModeToggle svg')

    // Guard against missing elements
    if (!body || !toggleText || !toggleIcon) {
      console.warn('Dark mode elements not ready yet')
      return
    }

    if (enabled) {
      body.classList.add('dark-mode')
      toggleText.textContent = 'Light'
      // Moon icon for dark mode
      toggleIcon.innerHTML =
        '<path d="M9.528 1.718a.75.75 0 01.162.819A8.97 8.97 0 009 6a9 9 0 009 9 8.97 8.97 0 003.463-.69.75.75 0 01.981.98 10.503 10.503 0 01-9.694 6.46c-5.799 0-10.5-4.701-10.5-10.5 0-4.368 2.667-8.112 6.46-9.694a.75.75 0 01.818.162z"/>'
    } else {
      body.classList.remove('dark-mode')
      toggleText.textContent = 'Dark'
      // Sun icon for light mode
      toggleIcon.innerHTML =
        '<path d="M12 2.25a.75.75 0 01.75.75v2.25a.75.75 0 01-1.5 0V3a.75.75 0 01.75-.75zM7.5 12a4.5 4.5 0 119 0 4.5 4.5 0 01-9 0zM18.894 6.166a.75.75 0 00-1.06-1.06l-1.591 1.59a.75.75 0 101.06 1.061l1.591-1.59zM21.75 12a.75.75 0 01-.75.75h-2.25a.75.75 0 010-1.5H21a.75.75 0 01.75.75zM17.834 18.894a.75.75 0 001.06-1.06l-1.59-1.591a.75.75 0 10-1.061 1.06l1.59 1.591zM12 18a.75.75 0 01.75.75V21a.75.75 0 01-1.5 0v-2.25A.75.75 0 0112 18zM7.758 17.303a.75.75 0 00-1.061-1.06l-1.591 1.59a.75.75 0 001.06 1.061l1.591-1.59zM6 12a.75.75 0 01-.75.75H3a.75.75 0 010-1.5h2.25A.75.75 0 016 12zM6.697 7.757a.75.75 0 001.06-1.06l-1.59-1.591a.75.75 0 00-1.061 1.06l1.59 1.591z"/>'
    }
  }

  setupKeyboardShortcuts() {
    document.addEventListener('keydown', e => {
      if (e.key === '/' && e.target.tagName !== 'INPUT') {
        e.preventDefault()
        document.getElementById('searchInput').focus()
      }
      if (e.key === 'Escape') {
        this.clearFilters()
      }
    })
  }

  addRequest(data) {
    if (!this.requests.has(data.requestId)) {
      const request = { ...data, timestamp: data.timeStamp || Date.now() }

      // Check if we have a pending response body for this request
      // Try multiple key formats to find a match
      const normalizedUrl = this.normalizeUrl(data.url)
      const normalizedMethod = (data.method || 'GET').toUpperCase()

      // Try URL + Method only (simpler matching)
      const simpleKey = `${normalizedUrl}::${normalizedMethod}`
      let pendingResponse = this.pendingResponseBodies.get(simpleKey)

      // If not found, try searching all pending responses
      if (!pendingResponse) {
        for (const [
          pendingKey,
          pending
        ] of this.pendingResponseBodies.entries()) {
          const parts = pendingKey.split('::')
          const pendingUrl = this.normalizeUrl(parts[0])
          const pendingMethod = parts[1].toUpperCase()

          if (
            pendingUrl === normalizedUrl &&
            pendingMethod === normalizedMethod
          ) {
            pendingResponse = pending
            this.pendingResponseBodies.delete(pendingKey)
            break
          }
        }
      } else {
        this.pendingResponseBodies.delete(simpleKey)
      }

      if (pendingResponse) {
        request.responseBody = pendingResponse.body
        request.responseBodyMimeType = pendingResponse.mimeType
      }

      this.requests.set(data.requestId, request)
      this.render()
    }
  }

  updateRequest(requestId, data) {
    if (this.requests.has(requestId)) {
      const existing = this.requests.get(requestId)
      this.requests.set(requestId, { ...existing, ...data })
      if (this.selectedRequestId === requestId) {
        this.renderDetailPanel()
      }
    }
  }

  completeRequest(requestId, data) {
    const existing = this.requests.get(requestId) || {}
    const updated = { ...existing, ...data, completed: true }

    // Check if we have a pending response body for this request
    if (
      !updated.hasOwnProperty('responseBody') ||
      updated.responseBody === undefined
    ) {
      const normalizedUrl = this.normalizeUrl(data.url)
      const normalizedMethod = (data.method || 'GET').toUpperCase()

      // Try URL + Method only (simpler matching)
      const simpleKey = `${normalizedUrl}::${normalizedMethod}`
      let pendingResponse = this.pendingResponseBodies.get(simpleKey)

      // If not found, try searching all pending responses by URL and method
      if (!pendingResponse) {
        for (const [
          pendingKey,
          pending
        ] of this.pendingResponseBodies.entries()) {
          const parts = pendingKey.split('::')
          const pendingUrl = this.normalizeUrl(parts[0])
          const pendingMethod = parts[1].toUpperCase()

          if (
            pendingUrl === normalizedUrl &&
            pendingMethod === normalizedMethod
          ) {
            pendingResponse = pending
            this.pendingResponseBodies.delete(pendingKey)
            break
          }
        }
      } else {
        this.pendingResponseBodies.delete(simpleKey)
      }

      if (pendingResponse) {
        updated.responseBody = pendingResponse.body
        updated.responseBodyMimeType = pendingResponse.mimeType
      }
    }

    this.requests.set(requestId, updated)
    this.render()
    if (this.selectedRequestId === requestId) {
      this.renderDetailPanel()
    }
  }

  getFilteredRequests() {
    const requests = Array.from(this.requests.values())

    return requests
      .filter(req => {
        // Method filter
        if (this.filters.method && req.method !== this.filters.method) {
          return false
        }

        // Status filter
        if (this.filters.status) {
          const status = req.statusCode || 0
          const range = this.filters.status[0]
          if (range === '2' && (status < 200 || status >= 300)) return false
          if (range === '3' && (status < 300 || status >= 400)) return false
          if (range === '4' && (status < 400 || status >= 500)) return false
          if (range === '5' && status < 500) return false
        }

        // Type filter
        if (this.filters.type && req.type !== this.filters.type) {
          return false
        }

        // URL filter
        if (
          this.filters.url &&
          !req.url.toLowerCase().includes(this.filters.url.toLowerCase())
        ) {
          return false
        }

        // Search filter (regex supported)
        if (this.filters.search) {
          try {
            const regex = new RegExp(this.filters.search, 'i')
            const searchable = [
              req.url,
              JSON.stringify(req.requestHeaders || []),
              JSON.stringify(req.responseHeaders || []),
              this.formatRequestBody(req.requestBody || {}),
              req.responseBody || ''
            ].join(' ')

            if (!regex.test(searchable)) {
              return false
            }
          } catch (e) {
            // Invalid regex, fallback to simple string search
            const searchable = [
              req.url,
              JSON.stringify(req.requestHeaders || []),
              JSON.stringify(req.responseHeaders || []),
              this.formatRequestBody(req.requestBody || {}),
              req.responseBody || ''
            ].join(' ')

            if (
              !searchable
                .toLowerCase()
                .includes(this.filters.search.toLowerCase())
            ) {
              return false
            }
          }
        }

        return true
      })
      .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
  }

  render() {
    const filtered = this.getFilteredRequests()
    const list = document.getElementById('requestList')

    if (filtered.length === 0) {
      list.innerHTML =
        '<div class="empty-state">No requests match the current filters.</div>'
      return
    }

    list.innerHTML = filtered
      .map(req => {
        const url = new URL(req.url)
        const status = req.statusCode || (req.error ? 'ERR' : '—')
        const statusClass =
          req.error || status >= 400
            ? 'error'
            : status >= 200 && status < 300
            ? 'success'
            : ''
        const selected =
          this.selectedRequestId === req.requestId ? 'selected' : ''
        const method = (req.method || 'GET').toLowerCase()

        return `
        <div class="request-row ${statusClass} ${selected}" data-request-id="${
          req.requestId
        }">
          <div class="method ${method}">${req.method || 'GET'}</div>
          <div class="status">${status}</div>
          <div class="type">${req.type || ''}</div>
          <div class="url">
            <span class="url-domain">${url.hostname}</span>${url.pathname}${
          url.search
        }
          </div>
          <div class="time">${this.formatTime(req.timestamp)}</div>
        </div>
      `
      })
      .join('')

    // Attach click handlers
    list.querySelectorAll('.request-row').forEach(row => {
      row.addEventListener('click', () => {
        const requestId = row.dataset.requestId
        // If clicking the same request that's already selected, close the detail panel
        if (this.selectedRequestId === requestId) {
          this.closeDetailPanel()
        } else {
          this.selectRequest(requestId)
        }
      })
    })
  }

  selectRequest(requestId) {
    this.selectedRequestId = requestId
    this.render()
    this.showDetailPanel()
    this.resetDetailTabs()
    this.renderDetailPanel('headers')
  }

  resetDetailTabs() {
    // Reset all tabs and activate the first one (Request/Headers)
    document.querySelectorAll('.detail-tab').forEach((tab, index) => {
      tab.classList.remove('active')
      if (index === 0) {
        tab.classList.add('active')
      }
    })
  }

  closeDetailPanel() {
    this.selectedRequestId = null
    this.render()
    this.hideDetailPanel()
  }

  showDetailPanel() {
    document.getElementById('detailPanel').classList.add('active')
  }

  hideDetailPanel() {
    document.getElementById('detailPanel').classList.remove('active')
  }

  renderDetailPanel(tab = 'headers') {
    if (!this.selectedRequestId || !this.requests.has(this.selectedRequestId)) {
      return
    }

    const req = this.requests.get(this.selectedRequestId)
    const content = document.getElementById('detailContent')

    // Reset search state when switching requests or tabs
    this.responseSearchState.searchTerm = ''
    this.responseSearchState.matches = []
    this.responseSearchState.currentMatchIndex = -1
    this.responseSearchState.originalText = ''

    switch (tab) {
      case 'headers':
        content.innerHTML = this.renderHeadersAndRequest(req)
        break
      case 'response':
        content.innerHTML = this.renderResponse(req)
        break
      case 'curl':
        content.innerHTML = this.renderCurl(req)
        break
    }

    // Attach copy button event listeners
    this.attachCopyButtons(content)

    // Setup response body search if response tab is active
    if (tab === 'response') {
      this.setupResponseSearch(content)
    }
  }

  setupResponseSearch(content) {
    const searchInput = content.querySelector('.response-search-input')
    const codeBlock = content.querySelector(
      '.code-block[id^="copy-response-body-"]'
    )

    if (!searchInput || !codeBlock) {
      return // No response body to search
    }

    const requestId = searchInput.id.replace('response-search-', '')
    const searchCount = content.querySelector(
      `#response-search-count-${requestId}`
    )

    // Initialize search state for this request
    this.responseSearchState.searchTerm = ''
    this.responseSearchState.matches = []
    this.responseSearchState.currentMatchIndex = -1

    // Search input handler
    searchInput.addEventListener('input', e => {
      const searchTerm = e.target.value
      this.performResponseSearch(searchTerm, codeBlock, searchCount)
    })

    // Tab navigation handler for code block
    codeBlock.addEventListener('keydown', e => {
      if (
        e.key === 'Tab' &&
        !e.shiftKey &&
        this.responseSearchState.matches.length > 0
      ) {
        e.preventDefault()
        this.navigateToNextMatch(codeBlock)
      } else if (
        e.key === 'Tab' &&
        e.shiftKey &&
        this.responseSearchState.matches.length > 0
      ) {
        e.preventDefault()
        this.navigateToPreviousMatch(codeBlock)
      }
    })

    // Focus search input with Ctrl/Cmd + F
    codeBlock.addEventListener('keydown', e => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault()
        searchInput.focus()
        searchInput.select()
      }
    })
  }

  performResponseSearch(searchTerm, codeBlock, searchCount) {
    this.responseSearchState.searchTerm = searchTerm
    this.responseSearchState.currentMatchIndex = -1

    if (!searchTerm.trim()) {
      // Clear highlights
      this.clearHighlights(codeBlock)
      if (searchCount) {
        searchCount.textContent = ''
      }
      return
    }

    const originalText = this.responseSearchState.originalText
    const escapedTerm = this.escapeHtml(searchTerm)

    // Find all matches (case-insensitive)
    const regex = new RegExp(this.escapeRegex(searchTerm), 'gi')
    const matches = []
    let match

    // Reset regex lastIndex to avoid issues
    regex.lastIndex = 0

    while ((match = regex.exec(originalText)) !== null) {
      matches.push({
        index: match.index,
        length: match[0].length,
        text: match[0]
      })
    }

    this.responseSearchState.matches = matches

    // Update count
    if (searchCount) {
      if (matches.length > 0) {
        searchCount.textContent = `${matches.length} match${
          matches.length !== 1 ? 'es' : ''
        }`
      } else {
        searchCount.textContent = 'No matches'
      }
    }

    // Highlight matches
    this.highlightMatches(codeBlock, originalText, searchTerm)

    // Scroll to first match if any
    if (matches.length > 0) {
      this.navigateToMatch(codeBlock, 0)
    }
  }

  escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  }

  highlightMatches(codeBlock, originalText, searchTerm) {
    if (!searchTerm.trim()) {
      codeBlock.innerHTML = this.escapeHtml(originalText)
      return
    }

    const regex = new RegExp(this.escapeRegex(searchTerm), 'gi')
    let highlightedText = ''
    let lastIndex = 0
    let match

    regex.lastIndex = 0

    while ((match = regex.exec(originalText)) !== null) {
      // Add text before match
      highlightedText += this.escapeHtml(
        originalText.substring(lastIndex, match.index)
      )

      // Add highlighted match
      const matchText = this.escapeHtml(match[0])
      highlightedText += `<mark class="search-highlight">${matchText}</mark>`

      lastIndex = match.index + match[0].length
    }

    // Add remaining text
    highlightedText += this.escapeHtml(originalText.substring(lastIndex))

    codeBlock.innerHTML = highlightedText

    // Update active highlight
    this.updateActiveHighlight(codeBlock)
  }

  clearHighlights(codeBlock) {
    const originalText = this.responseSearchState.originalText
    codeBlock.innerHTML = this.escapeHtml(originalText)
    this.responseSearchState.matches = []
    this.responseSearchState.currentMatchIndex = -1
  }

  navigateToNextMatch(codeBlock) {
    if (this.responseSearchState.matches.length === 0) return

    this.responseSearchState.currentMatchIndex =
      (this.responseSearchState.currentMatchIndex + 1) %
      this.responseSearchState.matches.length

    this.navigateToMatch(codeBlock, this.responseSearchState.currentMatchIndex)
  }

  navigateToPreviousMatch(codeBlock) {
    if (this.responseSearchState.matches.length === 0) return

    this.responseSearchState.currentMatchIndex =
      this.responseSearchState.currentMatchIndex <= 0
        ? this.responseSearchState.matches.length - 1
        : this.responseSearchState.currentMatchIndex - 1

    this.navigateToMatch(codeBlock, this.responseSearchState.currentMatchIndex)
  }

  navigateToMatch(codeBlock, matchIndex) {
    if (matchIndex < 0 || matchIndex >= this.responseSearchState.matches.length)
      return

    this.responseSearchState.currentMatchIndex = matchIndex
    this.updateActiveHighlight(codeBlock)

    // Scroll to the active match
    const highlights = codeBlock.querySelectorAll('.search-highlight')
    if (highlights[matchIndex]) {
      highlights[matchIndex].scrollIntoView({
        behavior: 'smooth',
        block: 'center',
        inline: 'nearest'
      })
    }
  }

  updateActiveHighlight(codeBlock) {
    const highlights = codeBlock.querySelectorAll('.search-highlight')
    highlights.forEach((highlight, index) => {
      if (index === this.responseSearchState.currentMatchIndex) {
        highlight.classList.add('active')
      } else {
        highlight.classList.remove('active')
      }
    })
  }

  attachCopyButtons(container) {
    container.querySelectorAll('.code-copy-btn').forEach(btn => {
      btn.addEventListener('click', e => {
        const copyId = btn.getAttribute('data-copy-id')
        const targetElement = document.getElementById(copyId)
        if (targetElement) {
          const textToCopy =
            targetElement.textContent || targetElement.innerText
          this.copyToClipboard(textToCopy, btn)
        }
      })
    })
  }

  renderHeadersAndRequest(req) {
    let html = ''

    // URL section with copy button
    const urlId = 'copy-url-' + req.requestId
    html +=
      '<div class="detail-section"><h3>URL</h3><div class="code-block-wrapper">' +
      '<button class="code-copy-btn" data-copy-id="' +
      urlId +
      '" title="Copy URL">' +
      this.getCopyIconSVG() +
      '</button>' +
      '<div class="code-block" id="' +
      urlId +
      '">' +
      this.escapeHtml(req.url) +
      '</div></div></div>'

    // Query Parameters
    const queryParams = this.extractQueryParams(req.url)
    if (queryParams && queryParams.length > 0) {
      html += `
        <div class="detail-section">
          <h3>Query Parameters</h3>
          <table class="headers-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              ${queryParams
                .map(
                  param => `
                  <tr>
                    <td>${this.escapeHtml(param.name)}</td>
                    <td>${this.escapeHtml(param.value)}</td>
                  </tr>
                `
                )
                .join('')}
            </tbody>
          </table>
        </div>
      `
    }

    // Request Headers
    if (req.requestHeaders && req.requestHeaders.length > 0) {
      html += `
        <div class="detail-section">
          <h3>Request Headers</h3>
          <table class="headers-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              ${req.requestHeaders
                .map(
                  h => `
                  <tr>
                    <td>${this.escapeHtml(h.name)}</td>
                    <td>${this.escapeHtml(h.value)}</td>
                  </tr>
                `
                )
                .join('')}
            </tbody>
          </table>
        </div>
      `
    }

    return html || '<div class="empty-state">No request details available</div>'
  }

  renderResponse(req) {
    let html = ''

    if (req.statusCode) {
      const statusText = `${req.statusCode} ${req.statusLine || ''}`
      const statusId = 'copy-status-' + req.requestId
      html +=
        '<div class="detail-section"><h3>Status</h3><div class="code-block-wrapper">'
      html +=
        '<button class="code-copy-btn" data-copy-id="' +
        statusId +
        '" title="Copy status">' +
        this.getCopyIconSVG() +
        '</button>'
      html +=
        '<div class="code-block" id="' +
        statusId +
        '">' +
        this.escapeHtml(statusText) +
        '</div>'
      html += '</div></div>'
    }

    // Response Headers
    if (req.responseHeaders && req.responseHeaders.length > 0) {
      html += `
        <div class="detail-section">
          <h3>Response Headers</h3>
          <table class="headers-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              ${req.responseHeaders
                .map(
                  h => `
                  <tr>
                    <td>${this.escapeHtml(h.name)}</td>
                    <td>${this.escapeHtml(h.value)}</td>
                  </tr>
                `
                )
                .join('')}
            </tbody>
          </table>
        </div>
      `
    }

    // Check if response body exists (could be empty string, null, or undefined)
    const hasResponseBody =
      req.hasOwnProperty('responseBody') &&
      req.responseBody !== null &&
      req.responseBody !== undefined

    if (hasResponseBody) {
      html += '<div class="detail-section"><h3>Response Body</h3>'

      // Try to format JSON if it's JSON
      let formattedBody = String(req.responseBody)
      const mimeType = req.responseBodyMimeType || ''

      if (
        mimeType.includes('json') ||
        (formattedBody.trim().startsWith('{') &&
          formattedBody.trim().endsWith('}')) ||
        (formattedBody.trim().startsWith('[') &&
          formattedBody.trim().endsWith(']'))
      ) {
        try {
          const parsed = JSON.parse(formattedBody)
          formattedBody = JSON.stringify(parsed, null, 2)
        } catch (e) {
          // Not valid JSON, use as-is
        }
      }

      // Store original text for search
      this.responseSearchState.originalText = formattedBody

      const responseBodyId = 'copy-response-body-' + req.requestId
      const searchInputId = 'response-search-' + req.requestId

      // Add search input
      html += '<div class="response-search-container">'
      html +=
        '<input type="text" class="response-search-input" id="' +
        searchInputId +
        '" placeholder="Search in response body..." />'
      html +=
        '<span class="response-search-count" id="response-search-count-' +
        req.requestId +
        '"></span>'
      html += '</div>'

      html += '<div class="code-block-wrapper">'
      html +=
        '<button class="code-copy-btn" data-copy-id="' +
        responseBodyId +
        '" title="Copy response body">' +
        this.getCopyIconSVG() +
        '</button>'
      html +=
        '<div class="code-block" id="' +
        responseBodyId +
        '" tabindex="0">' +
        this.escapeHtml(formattedBody) +
        '</div>'
      html += '</div>'
      html += '</div>'
    } else if (req.responseBodyUnavailable) {
      html +=
        '<div class="detail-section"><h3>Response Body</h3><p style="color: #999; font-style: italic;">Response body not available. This may be due to CORS restrictions, binary content, or the response being blocked.</p></div>'
    } else {
      // Try to trigger a match attempt
      this.attemptResponseBodyMatch(req)

      html +=
        '<div class="detail-section"><h3>Response Body</h3><p style="color: #999; font-style: italic;">Loading response body...</p><p style="color: #999; font-size: 11px; margin-top: 8px;">If this persists, the response body may not be available (CORS restrictions, binary content, etc.)</p></div>'
    }

    return html
  }

  attemptResponseBodyMatch(req) {
    // Try to find a matching response body in pending responses
    const normalizedUrl = this.normalizeUrl(req.url)
    const normalizedMethod = (req.method || 'GET').toUpperCase()

    for (const [pendingKey, pending] of this.pendingResponseBodies.entries()) {
      const [pendingUrl, pendingMethod] = pendingKey.split('::')
      if (
        this.normalizeUrl(pendingUrl) === normalizedUrl &&
        pendingMethod.toUpperCase() === normalizedMethod
      ) {
        // Found a match!
        req.responseBody = pending.body
        req.responseBodyMimeType = pending.mimeType

        // Update display if this is the selected request
        if (this.selectedRequestId === req.requestId) {
          const activeTab =
            document.querySelector('.detail-tab.active')?.dataset.tab
          if (activeTab === 'response') {
            this.renderDetailPanel('response')
          }
        }

        this.pendingResponseBodies.delete(pendingKey)
        break
      }
    }
  }

  renderCurl(req) {
    const curl = this.generateCurl(req)
    const fetchCode = this.generateFetch(req)
    const pythonCode = this.generatePython(req)

    const curlId = 'copy-curl-' + req.requestId
    const fetchId = 'copy-fetch-' + req.requestId
    const pythonId = 'copy-python-' + req.requestId

    let html = ''

    // cURL Command
    html += '<div class="detail-section">'
    html += '<h3>cURL Command</h3>'
    html += '<div class="code-block-wrapper">'
    html +=
      '<button class="code-copy-btn" data-copy-id="' +
      curlId +
      '" title="Copy cURL command">'
    html += this.getCopyIconSVG()
    html += '</button>'
    html += '<div class="code-block" id="' + curlId + '">'
    html += this.escapeHtml(curl)
    html += '</div>'
    html += '</div>'
    html += '</div>'

    // JavaScript Fetch
    html += '<div class="detail-section">'
    html += '<h3>JavaScript Fetch</h3>'
    html += '<div class="code-block-wrapper">'
    html +=
      '<button class="code-copy-btn" data-copy-id="' +
      fetchId +
      '" title="Copy fetch code">'
    html += this.getCopyIconSVG()
    html += '</button>'
    html += '<div class="code-block" id="' + fetchId + '">'
    html += this.escapeHtml(fetchCode)
    html += '</div>'
    html += '</div>'
    html += '</div>'

    // Python Requests
    html += '<div class="detail-section">'
    html += '<h3>Python Requests</h3>'
    html += '<div class="code-block-wrapper">'
    html +=
      '<button class="code-copy-btn" data-copy-id="' +
      pythonId +
      '" title="Copy Python code">'
    html += this.getCopyIconSVG()
    html += '</button>'
    html += '<div class="code-block" id="' + pythonId + '">'
    html += this.escapeHtml(pythonCode)
    html += '</div>'
    html += '</div>'
    html += '</div>'

    return html
  }

  extractQueryParams(url) {
    try {
      const urlObj = new URL(url)
      const params = []

      // URL.searchParams returns a URLSearchParams object
      urlObj.searchParams.forEach((value, name) => {
        params.push({ name, value })
      })

      return params
    } catch (e) {
      // If URL parsing fails, try manual parsing
      try {
        const params = []
        const queryString = url.split('?')[1]
        if (!queryString) return []

        // Also handle hash fragments
        const queryPart = queryString.split('#')[0]
        if (!queryPart) return []

        const pairs = queryPart.split('&')
        for (const pair of pairs) {
          const [name, value] = pair
            .split('=')
            .map(part => decodeURIComponent(part || ''))
          if (name) {
            params.push({ name, value: value || '' })
          }
        }

        return params
      } catch (e2) {
        return []
      }
    }
  }

  formatRequestBody(requestBody) {
    if (!requestBody) return ''

    if (requestBody.formData) {
      return JSON.stringify(requestBody.formData, null, 2)
    }
    if (requestBody.raw) {
      // Decode base64 or handle raw data
      try {
        const decoder = new TextDecoder('utf-8')
        const data = requestBody.raw[0]?.bytes
        if (data) {
          const bytes = new Uint8Array(data)
          return decoder.decode(bytes)
        }
      } catch (e) {
        return JSON.stringify(requestBody.raw)
      }
    }

    return JSON.stringify(requestBody, null, 2)
  }

  generateCurl(req) {
    let curl = `curl '${req.url}'`

    if (req.method && req.method !== 'GET') {
      curl += ` -X ${req.method}`
    }

    if (req.requestHeaders) {
      req.requestHeaders.forEach(header => {
        curl += ` \\\n  -H '${header.name}: ${header.value}'`
      })
    }

    if (req.requestBody) {
      const body = this.formatRequestBody(req.requestBody)
      if (body) {
        curl += ` \\\n  -d '${body.replace(/'/g, "'\\''")}'`
      }
    }

    return curl
  }

  generateFetch(req) {
    const headers = {}
    if (req.requestHeaders) {
      req.requestHeaders.forEach(h => {
        headers[h.name] = h.value
      })
    }

    const options = {
      method: req.method || 'GET',
      headers: headers
    }

    if (req.requestBody) {
      const body = this.formatRequestBody(req.requestBody)
      if (body) {
        try {
          JSON.parse(body)
          options.body = body
          headers['Content-Type'] =
            headers['Content-Type'] || 'application/json'
        } catch {
          options.body = body
        }
      }
    }

    return `fetch('${req.url}', ${JSON.stringify(options, null, 2)})`
  }

  generatePython(req) {
    let python = 'import requests\n\n'

    // Build headers
    const headers = {}
    if (req.requestHeaders) {
      req.requestHeaders.forEach(h => {
        headers[h.name] = h.value
      })
    }

    // Build params (query parameters)
    const queryParams = this.extractQueryParams(req.url)
    const params = {}
    if (queryParams && queryParams.length > 0) {
      queryParams.forEach(param => {
        params[param.name] = param.value
      })
    }

    // Get URL without query string
    let url = req.url
    try {
      const urlObj = new URL(req.url)
      url = urlObj.origin + urlObj.pathname
    } catch (e) {
      // If URL parsing fails, try to remove query string manually
      const urlParts = url.split('?')
      url = urlParts[0]
    }

    const method = (req.method || 'GET').toLowerCase()

    // Build the request
    if (Object.keys(params).length > 0) {
      python += `params = ${JSON.stringify(params, null, 2)}\n`
    }

    if (Object.keys(headers).length > 0) {
      python += `headers = ${JSON.stringify(headers, null, 2)}\n`
    }

    if (req.requestBody) {
      const body = this.formatRequestBody(req.requestBody)
      if (body) {
        try {
          // Try to parse as JSON
          const parsed = JSON.parse(body)
          python += `json_data = ${JSON.stringify(parsed, null, 2)}\n`
          python += `\nresponse = requests.${method}('${url}'`
          if (Object.keys(params).length > 0) {
            python += `, params=params`
          }
          if (Object.keys(headers).length > 0) {
            python += `, headers=headers`
          }
          python += `, json=json_data)`
        } catch {
          // Not JSON, use data parameter
          python += `data = ${JSON.stringify(body)}\n`
          python += `\nresponse = requests.${method}('${url}'`
          if (Object.keys(params).length > 0) {
            python += `, params=params`
          }
          if (Object.keys(headers).length > 0) {
            python += `, headers=headers`
          }
          python += `, data=data)`
        }
      } else {
        python += `\nresponse = requests.${method}('${url}'`
        if (Object.keys(params).length > 0) {
          python += `, params=params`
        }
        if (Object.keys(headers).length > 0) {
          python += `, headers=headers`
        }
        python += `)`
      }
    } else {
      python += `\nresponse = requests.${method}('${url}'`
      if (Object.keys(params).length > 0) {
        python += `, params=params`
      }
      if (Object.keys(headers).length > 0) {
        python += `, headers=headers`
      }
      python += `)`
    }

    return python
  }

  formatTime(timestamp) {
    if (!timestamp) return ''
    const date = new Date(timestamp)
    return (
      date.toLocaleTimeString() +
      '.' +
      date.getMilliseconds().toString().padStart(3, '0')
    )
  }

  escapeHtml(text) {
    const div = document.createElement('div')
    div.textContent = text
    return div.innerHTML
  }

  clearFilters() {
    this.filters = {
      search: '',
      method: '',
      status: '',
      type: '',
      url: ''
    }
    document.getElementById('searchInput').value = ''
    document.getElementById('methodFilter').value = ''
    document.getElementById('statusFilter').value = ''
    document.getElementById('typeFilter').value = ''
    document.getElementById('urlFilter').value = ''
    this.render()
  }

  getCopyIconSVG() {
    return `
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
        <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
      </svg>
    `
  }

  copyToClipboard(text, buttonElement) {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        // Show visual feedback
        const originalHTML = buttonElement.innerHTML
        buttonElement.classList.add('copied')
        buttonElement.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" style="width: 14px; height: 14px; fill: #4caf50;">
          <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
        </svg>
      `

        setTimeout(() => {
          buttonElement.classList.remove('copied')
          buttonElement.innerHTML = originalHTML
        }, 2000)
      })
      .catch(err => {
        console.error('Failed to copy:', err)
        // Fallback for older browsers
        try {
          const textarea = document.createElement('textarea')
          textarea.value = text
          textarea.style.position = 'fixed'
          textarea.style.opacity = '0'
          document.body.appendChild(textarea)
          textarea.select()
          document.execCommand('copy')
          document.body.removeChild(textarea)

          // Show success feedback even with fallback
          const originalHTML = buttonElement.innerHTML
          buttonElement.classList.add('copied')
          buttonElement.innerHTML = `
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" style="width: 14px; height: 14px; fill: #4caf50;">
            <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
          </svg>
        `
          setTimeout(() => {
            buttonElement.classList.remove('copied')
            buttonElement.innerHTML = originalHTML
          }, 2000)
        } catch (fallbackErr) {
          console.error('Fallback copy also failed:', fallbackErr)
          alert('Failed to copy to clipboard')
        }
      })
  }
}

// Global copy to clipboard function
window.copyToClipboard = function (text, buttonElement) {
  // Decode the escaped text
  const decodedText = text.replace(/\\n/g, '\n').replace(/\\'/g, "'")

  navigator.clipboard
    .writeText(decodedText)
    .then(() => {
      // Show visual feedback
      const originalText = buttonElement.innerHTML
      buttonElement.classList.add('copied')
      buttonElement.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" style="width: 14px; height: 14px; fill: #4caf50;">
        <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
      </svg>
    `

      setTimeout(() => {
        buttonElement.classList.remove('copied')
        buttonElement.innerHTML = originalText
      }, 2000)
    })
    .catch(err => {
      console.error('Failed to copy:', err)
      // Fallback for older browsers
      const textarea = document.createElement('textarea')
      textarea.value = decodedText
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
    })
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new NetworkAnalyzer()
  })
} else {
  new NetworkAnalyzer()
}
