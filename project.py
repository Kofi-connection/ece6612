import time
import csv
import ssl, socket
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities


TOP_SITES_URL = "https://tranco-list.eu/download/4QY5X/10"
def get_top_sites():
    url = TOP_SITES_URL  # Replace with the latest list URL
    response = requests.get(url)
    sites = [line.split(',')[1] for line in response.text.split('\n')[1:1001] if line]
    return sites


# --- Setup Selenium webDriver
def setup_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run headless
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--ignore-certificate-errors")

    caps = DesiredCapabilities.CHROME.copy()
    caps["goog:loggingPrefs"] = {"performance": "ALL"}  # Enable network logs

    service = Service()  # Update the path to your ChromeDriver
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver

# --- Step 3: Extract Security Headers and TLS Info ---
def get_tls_info(url):
    try:
        response = requests.get(f"https://{url}", timeout=5)
        # Note: requests does not give detailed TLS info directly.
        # We use a placeholder value here. Advanced implementations might use libraries like ssl.
        return response.raw.version_string 
    except requests.exceptions.RequestException:
        return "Failed"

def get_tls_details(host, port=443):
    context = ssl.create_default_context()
    # Customize context to see allowed protocols if needed
    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Getting version and cipher information:
                tls_version = ssock.version()
                cipher = ssock.cipher()
                return tls_version, cipher
    except socket.error:
        return "Failed", "Failed"

def get_csp_header(url):
    try:
        response = requests.get(f"https://{url}", timeout=5)
        return response.headers.get("Content-Security-Policy", "Not Found")
    except requests.exceptions.RequestException:
        return "Failed"

def get_sri_attributes(driver, url):
    try:
        driver.get(f"https://{url}")
        time.sleep(3)  # Allow page to load

        scripts = driver.find_elements(By.TAG_NAME, "script")
        styles = driver.find_elements(By.TAG_NAME, "link")

        sri_missing = 0
        sri_total = 0

        for script in scripts:
            if script.get_attribute("src"):
                sri_total += 1
                if not script.get_attribute("integrity"):
                    sri_missing += 1

        for style in styles:
            if style.get_attribute("rel") == "stylesheet":
                sri_total += 1
                if not style.get_attribute("integrity"):
                    sri_missing += 1

        return f"{sri_missing}/{sri_total} missing SRI"

    except Exception:
        return "Failed"

# --- Step 4: Analyze CSP Misconfigurations ---
def analyze_csp(csp):
    issues = []
    if csp in ["Not Found", "Failed"]:
        issues.append("CSP header not found")
        return issues

    # Split directives by ';' and remove empty ones
    directives = [directive.strip() for directive in csp.split(";") if directive.strip()]
    directive_map = {}
    for directive in directives:
        if " " in directive:
            key, values = directive.split(" ", 1)
            # Values are space separated
            directive_map[key.lower()] = values.split()
        else:
            directive_map[directive.lower()] = []

    # Check for default-src
    if "default-src" not in directive_map:
        issues.append("Missing default-src directive")
    else:
        default_src = directive_map["default-src"]
        if "*" in default_src:
            issues.append("default-src contains wildcard (*)")
        if "'unsafe-inline'" in default_src or "'unsafe-eval'" in default_src:
            issues.append("default-src contains unsafe directives (unsafe-inline/unsafe-eval)")

    # Check for script-src if available, else fallback to default-src
    if "script-src" in directive_map:
        script_src = directive_map["script-src"]
        if "*" in script_src:
            issues.append("script-src contains wildcard (*)")
        if "'unsafe-inline'" in script_src or "'unsafe-eval'" in script_src:
            issues.append("script-src contains unsafe directives (unsafe-inline/unsafe-eval)")
    else:
        issues.append("script-src not specified; falling back to default-src may be too permissive")

    # Optionally, add checks for style-src or other directives if needed
    return issues if issues else ["CSP appears to be well-configured"]

# --- Step 5: Run Analysis and Save Results ---
def analyze_websites():
    driver = setup_driver()
    results = []
    top_sites = get_top_sites()

    for site in top_sites:
        site = site.strip()
        print(site)
        print(f"Analyzing {site}...")

        tls_info = get_tls_info(site)
        tls_details, cipher = get_tls_details(site)
        csp_header = get_csp_header(site)
        csp_analysis = "; ".join(analyze_csp(csp_header))
        sri_info = get_sri_attributes(driver, site)

        results.append([site, tls_details, cipher, csp_header, csp_analysis, sri_info])

    driver.quit()

    # Save to CSV
    with open("web_security_analysis.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Website", "TLS Version", "Cipher", "CSP Header", "CSP Analysis", "SRI Status"])
        writer.writerows(results)

    print("Analysis complete. Results saved to web_security_analysis.csv.")

analyze_websites()

if __name__ == "__main__":
    analyze_websites()



