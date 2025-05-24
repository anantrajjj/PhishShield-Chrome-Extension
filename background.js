// PhishShield Background Script

// Constants for API endpoints
//const PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"; // You'll need to register for an API key
const GOOGLE_SAFEBROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyDQ77fQJdKtLVR3Zl_R9B3OvSYMHVuMIts"; // You'll need an API key

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishShield extension installed");
});

// Listen for tab updates to check URLs
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only analyze when the URL changes and has completed loading
  if (changeInfo.status === "complete" && tab.url) {
    analyzeUrl(tab.url, tabId);
  }
});

// Main function to analyze URLs for phishing indicators
async function analyzeUrl(url, tabId) {
  try {
    // Skip analysis for browser internal pages and extensions
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
      return;
    }

    // Parse the URL
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    // 1. Check using heuristic rules
    const heuristicResult = checkHeuristics(url, domain);
    
    // 2. Check using API-based threat intelligence
    const apiResults = await Promise.all([
      // checkPhishTank(url),  // Comment this out since you're not using PhishTank
      checkGoogleSafeBrowsing(url)
    ]);

    // Combine results
    const isPhishing = heuristicResult.isPhishing || apiResults.some(result => result.isPhishing);
    
    // If phishing is detected, alert the user
    if (isPhishing) {
      // Collect all reasons why this was flagged
      const reasons = [
        ...heuristicResult.reasons,
        ...apiResults.flatMap(result => result.reasons)
      ].filter(Boolean);

      // Send alert to the popup
      chrome.storage.local.set({
        'phishingDetected': true,
        'phishingUrl': url,
        'phishingReasons': reasons,
        'timestamp': Date.now()
      });

      // Show warning to user
      chrome.action.setBadgeText({ text: "⚠️", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId });
      
      // Optional: You could redirect to a warning page
      // chrome.tabs.update(tabId, { url: chrome.runtime.getURL("warning.html") });
    } else {
      // Reset badge if site is safe
      chrome.action.setBadgeText({ text: "", tabId });
    }
  } catch (error) {
    console.error("Error analyzing URL:", error);
  }
}

// Heuristic-based checks
function checkHeuristics(url, domain) {
  const result = {
    isPhishing: false,
    reasons: []
  };

  // Check for suspicious URL characteristics
  
  // 1. Check for IP address in URL
  const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  if (ipPattern.test(domain)) {
    result.isPhishing = true;
    result.reasons.push("URL contains an IP address instead of a domain name");
  }

  // 2. Check for excessive subdomains
  const subdomains = domain.split(".").length;
  if (subdomains > 5) {
    result.isPhishing = true;
    result.reasons.push("URL contains an unusual number of subdomains");
  }

  // 3. Check for common brands in domain (potential typosquatting)
  const commonBrands = ["paypal", "apple", "microsoft", "amazon", "facebook", "google", "netflix"];
  const domainWithoutTLD = domain.split(".").slice(0, -1).join(".");
  
  for (const brand of commonBrands) {
    // Check for brand name with slight misspellings
    if (domainWithoutTLD.includes(brand) && domainWithoutTLD !== brand) {
      // Check for typosquatting (e.g., "paypa1" instead of "paypal")
      const levenshteinDistance = calculateLevenshteinDistance(domainWithoutTLD, brand);
      if (levenshteinDistance > 0 && levenshteinDistance <= 2) {
        result.isPhishing = true;
        result.reasons.push(`Domain appears to be typosquatting ${brand}`);
      }
    }
  }

  // 4. Check for suspicious URL patterns
  const suspiciousPatterns = [
    "secure", "login", "signin", "verify", "account", "update", "confirm",
    "banking", "password", "verification"
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (url.toLowerCase().includes(pattern)) {
      // This alone isn't enough to flag as phishing, but adds to suspicion
      result.reasons.push(`URL contains suspicious term: ${pattern}`);
    }
  }

  // If we have multiple suspicious indicators, mark as potential phishing
  if (result.reasons.length >= 3 && !result.isPhishing) {
    result.isPhishing = true;
    result.reasons.push("Multiple suspicious URL characteristics detected");
  }

  return result;
}

// API-based checks
async function checkPhishTank(url) {
  // In a real implementation, you would call the PhishTank API
  // This is a placeholder - you'll need to register for an API key
  
  // Simulated response for demonstration
  return {
    isPhishing: false,
    reasons: []
  };
  
  /* Real implementation would be something like:
  try {
    const response = await fetch(`${PHISHTANK_API_URL}?url=${encodeURIComponent(url)}&format=json&app_key=YOUR_API_KEY`);
    const data = await response.json();
    
    if (data.results.in_database && data.results.verified) {
      return {
        isPhishing: true,
        reasons: ["URL found in PhishTank database"]
      };
    }
    
    return {
      isPhishing: false,
      reasons: []
    };
  } catch (error) {
    console.error("PhishTank API error:", error);
    return {
      isPhishing: false,
      reasons: []
    };
  }
  */
}

async function checkGoogleSafeBrowsing(url) {
  try {
    const requestBody = {
      client: {
        clientId: "PhishShield",
        clientVersion: "1.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    
    const response = await fetch(
      GOOGLE_SAFEBROWSING_API_URL,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      }
    );
    
    const data = await response.json();
    console.log("Google Safe Browsing API response:", data);
    
    if (data.matches && data.matches.length > 0) {
      return {
        isPhishing: true,
        reasons: data.matches.map(match => `Google Safe Browsing: ${match.threatType}`)
      };
    }
    
    return {
      isPhishing: false,
      reasons: []
    };
  } catch (error) {
    console.error("Google Safe Browsing API error:", error);
    return {
      isPhishing: false,
      reasons: []
    };
  }
}

// Utility function to calculate Levenshtein distance for typosquatting detection
function calculateLevenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];

  // Initialize matrix
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  // Fill matrix
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }

  return matrix[b.length][a.length];
}