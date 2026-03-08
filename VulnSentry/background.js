// This will eventually listen for HTTP headers
chrome.runtime.onInstalled.addListener(() => {
  console.log("VulnSentry Installed and watching...");
});

// Placeholder for the header analysis logic you need later
/* chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    // This is where you will capture "Server", "X-Powered-By", etc.
    console.log("Headers received for: " + details.url);
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);
*/