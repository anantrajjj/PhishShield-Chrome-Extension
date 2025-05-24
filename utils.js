// PhishShield Utility Functions

/**
 * Extracts the domain from a URL
 * @param {string} url - The URL to extract domain from
 * @returns {string} The domain name
 */
function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (error) {
    console.error("Invalid URL:", url);
    return "";
  }
}

/**
 * Checks if a domain is likely a typosquat of a popular domain
 * @param {string} domain - The domain to check
 * @param {Array<string>} popularDomains - List of popular domains to check against
 * @param {number} threshold - Levenshtein distance threshold (default: 2)
 * @returns {Object} Result with isTyposquat and targetDomain if found
 */
function checkForTyposquatting(domain, popularDomains, threshold = 2) {
  // Remove TLD for comparison
  const domainWithoutTLD = domain.split(".").slice(0, -1).join(".");
  
  for (const popularDomain of popularDomains) {
    const popularWithoutTLD = popularDomain.split(".").slice(0, -1).join(".");
    
    // Skip if exact match (not a typosquat)
    if (domainWithoutTLD === popularWithoutTLD) {
      continue;
    }
    
    // Check if domain contains the popular domain name (potential typosquat)
    if (domainWithoutTLD.includes(popularWithoutTLD)) {
      const distance = calculateLevenshteinDistance(domainWithoutTLD, popularWithoutTLD);
      
      if (distance > 0 && distance <= threshold) {
        return {
          isTyposquat: true,
          targetDomain: popularDomain,
          distance: distance
        };
      }
    }
  }
  
  return { isTyposquat: false };
}

/**
 * Checks for suspicious URL patterns
 * @param {string} url - The URL to check
 * @returns {Array<string>} List of suspicious patterns found
 */
function checkSuspiciousPatterns(url) {
  const suspiciousPatterns = [
    { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, description: "IP address in URL" },
    { pattern: /^https?:\/\/[^\/]+\/@/, description: "@ symbol in URL (potential user deception)" },
    { pattern: /^https?:\/\/[^\/]+\/[^\/]+\.[^\/]+\//, description: "Domain-like path segment" },
    { pattern: /\.(tk|ml|ga|cf|gq)\/?$/, description: "Free TLD often used in phishing" },
    { pattern: /(secure|login|signin|verify|account|update|confirm|banking|password)/, description: "Sensitive terms in URL" }
  ];
  
  const findings = [];
  
  for (const { pattern, description } of suspiciousPatterns) {
    if (pattern.test(url)) {
      findings.push(description);
    }
  }
  
  return findings;
}

/**
 * Formats a URL for display by highlighting suspicious parts
 * @param {string} url - The URL to format
 * @returns {string} HTML string with highlighted suspicious parts
 */
function formatUrlForDisplay(url) {
  // This is a simplified version - a real implementation would be more complex
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    // Check for IP address
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
    if (ipPattern.test(domain)) {
      return url.replace(domain, `<span class="suspicious">${domain}</span>`);
    }
    
    // Check for deceptive subdomains
    const domainParts = domain.split(".");
    if (domainParts.length > 2) {
      // Highlight subdomains in a multi-part domain
      const mainDomain = domainParts.slice(-2).join(".");
      const subdomains = domainParts.slice(0, -2).join(".");
      return url.replace(domain, `<span class="suspicious">${subdomains}</span>.${mainDomain}`);
    }
    
    return url;
  } catch (error) {
    return url;
  }
}

// Export functions if using modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    extractDomain,
    checkForTyposquatting,
    checkSuspiciousPatterns,
    formatUrlForDisplay
  };
}