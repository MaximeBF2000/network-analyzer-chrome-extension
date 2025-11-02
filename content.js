// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'NETWORK_REQUEST') {
    console.log('Network Request:', message.data)
  }
  return true
})
