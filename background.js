// Store request details
const requestData = new Map()

// Store all devtools connections (send all requests to all panels, let panels filter)
const allDevtoolsConnections = []

// Handle devtools panel connections
chrome.runtime.onConnect.addListener(port => {
  if (port.name === 'network-analyzer') {
    allDevtoolsConnections.push(port)

    // Send existing requests
    const existingRequests = Array.from(requestData.values())
    existingRequests.forEach(req => {
      port.postMessage({ type: 'NETWORK_REQUEST', data: req })
    })

    port.onDisconnect.addListener(() => {
      const index = allDevtoolsConnections.indexOf(port)
      if (index > -1) {
        allDevtoolsConnections.splice(index, 1)
      }
    })
  }
})

// Helper to send to all devtools panels
function sendToDevtools(message) {
  allDevtoolsConnections.forEach(port => {
    try {
      port.postMessage(message)
    } catch (e) {
      // Connection closed
    }
  })
}

// Listen to request start (capture request body)
chrome.webRequest.onBeforeRequest.addListener(
  details => {
    requestData.set(details.requestId, { ...details })

    // Send immediately to devtools
    sendToDevtools({
      type: 'NETWORK_REQUEST',
      data: { ...details }
    })
  },
  { urls: ['<all_urls>'] },
  ['requestBody']
)

// Capture request headers
chrome.webRequest.onBeforeSendHeaders.addListener(
  details => {
    if (requestData.has(details.requestId)) {
      const existing = requestData.get(details.requestId)
      const updated = { ...existing, ...details }
      requestData.set(details.requestId, updated)

      // Send update to devtools
      sendToDevtools({
        type: 'NETWORK_REQUEST_UPDATE',
        requestId: details.requestId,
        data: updated
      })
    }
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders']
)

// Capture response headers
chrome.webRequest.onHeadersReceived.addListener(
  details => {
    if (requestData.has(details.requestId)) {
      const existing = requestData.get(details.requestId)
      const updated = { ...existing, ...details }
      requestData.set(details.requestId, updated)

      // Send update to devtools
      sendToDevtools({
        type: 'NETWORK_REQUEST_UPDATE',
        requestId: details.requestId,
        data: updated
      })
    }
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
)

// Send completed request data
chrome.webRequest.onCompleted.addListener(
  details => {
    if (requestData.has(details.requestId)) {
      const data = requestData.get(details.requestId)
      const completeData = { ...data, ...details }

      // Send to devtools
      sendToDevtools({
        type: 'NETWORK_REQUEST_COMPLETE',
        requestId: details.requestId,
        data: completeData
      })

      // Also send to content script
      if (details.tabId !== -1) {
        chrome.tabs
          .sendMessage(details.tabId, {
            type: 'NETWORK_REQUEST',
            data: completeData
          })
          .catch(() => {
            // Ignore errors if content script isn't ready or tab is closed
          })
      }

      // Clean up
      requestData.delete(details.requestId)
    }
  },
  { urls: ['<all_urls>'] }
)

// Also handle errors
chrome.webRequest.onErrorOccurred.addListener(
  details => {
    if (requestData.has(details.requestId)) {
      const data = requestData.get(details.requestId)
      const completeData = { ...data, ...details, error: true }

      sendToDevtools({
        type: 'NETWORK_REQUEST_COMPLETE',
        requestId: details.requestId,
        data: completeData
      })

      if (details.tabId !== -1) {
        chrome.tabs
          .sendMessage(details.tabId, {
            type: 'NETWORK_REQUEST',
            data: completeData
          })
          .catch(() => {
            // Ignore errors
          })
      }

      requestData.delete(details.requestId)
    }
  },
  { urls: ['<all_urls>'] }
)
