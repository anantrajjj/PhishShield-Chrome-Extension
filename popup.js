// PhishShield Popup Script

document.addEventListener('DOMContentLoaded', async () => {
  // Get UI elements
  const safeBanner = document.getElementById('status-safe');
  const warningBanner = document.getElementById('status-warning');
  const flaggedUrl = document.getElementById('flagged-url');
  const reasonsList = document.getElementById('reasons-list');
  const backButton = document.getElementById('back-button');
  const proceedButton = document.getElementById('proceed-button');

  // Get current tab information
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const currentTab = tabs[0];
  const currentUrl = currentTab.url;

  // Skip analysis for browser internal pages
  if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('chrome-extension://')) {
    safeBanner.classList.remove('hidden');
    warningBanner.classList.add('hidden');
    return;
  }

  // Check if this URL has been flagged
  chrome.storage.local.get(['phishingDetected', 'phishingUrl', 'phishingReasons', 'timestamp'], (data) => {
    // Check if we have a recent detection for this URL
    const isRecentDetection = data.timestamp && (Date.now() - data.timestamp < 5 * 60 * 1000); // 5 minutes
    const isCurrentUrlFlagged = data.phishingUrl === currentUrl;
    
    if (data.phishingDetected && isCurrentUrlFlagged && isRecentDetection) {
      // Show warning
      safeBanner.classList.add('hidden');
      warningBanner.classList.remove('hidden');
      
      // Display the flagged URL
      flaggedUrl.textContent = data.phishingUrl;
      
      // Display reasons
      if (data.phishingReasons && data.phishingReasons.length > 0) {
        reasonsList.innerHTML = '';
        data.phishingReasons.forEach(reason => {
          const li = document.createElement('li');
          li.textContent = reason;
          reasonsList.appendChild(li);
        });
      } else {
        const li = document.createElement('li');
        li.textContent = 'This URL matches known phishing patterns';
        reasonsList.appendChild(li);
      }
    } else {
      // Show safe banner
      safeBanner.classList.remove('hidden');
      warningBanner.classList.add('hidden');
    }
  });

  // Set up button actions
  backButton.addEventListener('click', () => {
    chrome.tabs.goBack(currentTab.id);
    window.close();
  });

  proceedButton.addEventListener('click', () => {
    // User wants to proceed despite warning
    // We'll just close the popup but could add additional logging here
    window.close();
  });
});