"""
Cyber Analysis Module for Phishing Detection
Authors: Karen & Vahe
"""

def analyze_email_headers(headers):
    """
    Analyze email headers for phishing indicators
    """
    # Placeholder for header analysis logic
    issues = []
    
    # Check for common header issues
    if 'From' not in headers:
        issues.append("Missing sender information")
    
    if 'SPF' not in headers.get('Received', ''):
        issues.append("SPF validation missing")
        
    return issues

def check_links(links):
    """
    Check links for malicious indicators
    """
    # Placeholder for link analysis logic
    suspicious_links = []
    
    for link in links:
        if "bit.ly" in link or "tinyurl" in link:
            suspicious_links.append(link)
            
    return suspicious_links

def detect_phishing_patterns(content):
    """
    Detect phishing patterns using regex
    """
    # Placeholder for regex pattern detection
    patterns = []
    
    # Example patterns to detect
    if "click here" in content.lower():
        patterns.append("Generic greeting and call to action")
        
    if "account will be closed" in content.lower():
        patterns.append("Threat of account suspension")
        
    return patterns

# Example usage:
if __name__ == "__main__":
    sample_headers = {
        "From": "noreply@example.com",
        "Received": "from unknown-server (no SPF)"
    }
    
    sample_links = [
        "https://bit.ly/suspicious-link",
        "https://secure.bank.com/login"
    ]
    
    sample_content = "Click here to verify your account. Your account will be closed if you don't act now."
    
    header_issues = analyze_email_headers(sample_headers)
    suspicious_links = check_links(sample_links)
    phishing_patterns = detect_phishing_patterns(sample_content)
    
    print(f"Header Issues: {header_issues}")
    print(f"Suspicious Links: {suspicious_links}")
    print(f"Phishing Patterns: {phishing_patterns}")