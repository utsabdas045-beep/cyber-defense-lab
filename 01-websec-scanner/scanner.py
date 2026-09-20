from __future__ import annotations 

import argparse # Command-line argument parsing
import ipaddress # Checking if an IP address is local/private
import json # JSON serialization
import math # Math functions for the score formula
import re # Regular expression
import secrets # Generating random tokens for probing
import socket # Network address resolution
import sys # System-specific parameters and functions
import time # Delays or time related functions
from dataclasses import asdict, dataclass # A shortcut for creating data classes
from datetime import datetime, timezone # Date and time handling
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse # URL parsing and manipulation

import requests # Sends HTTP requests
import urllib3 # Handles HTTP connections and warnings
from bs4 import BeautifulSoup # Parses HTML and XML documents

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Silences the certificate warnings because the scanner sets verify=False for test apps that use self-signed certs.

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] # Sorting order for severity levels, from most to least severe
SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0} # Weights for calculating the overall score of the scan, based on the severity
ALL_CHECKS = ["headers", "cookies", "methods", "directories", "forms", "inputs"] # List of all available checks that the scanner can perform on the target application


class ScopeError(Exception): # Custom exception type for scope violations
    """Raised when a target is outside the allowed scanning scope.""" # Empty classes used as custom exceptions to signal specific error conditions in the scanner.


class ScanLimit(Exception): # Custom exception type for the request budget
    """Raised when the request budget is exhausted."""



# Scope guard------------------------------------------------------------------------------------------

def is_local_target(url: str) -> bool: # Decides whether the URL points at a local/private machine
    """True if the host is localhost or resolves only to private/loopback addresses."""
    host = urlparse(url).hostname # Extracts the hostname from the provided URL using urlparse.
    if not host: # If no hostname could be extracted...
        return False # ...it cannot be treated as local
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"): # Checks if it is localhost or a local-only domain name
        return True # These names are always considered local
    try: # DNS lookups can fail, so they are wrapped in try/except
        addrs = {ai[4][0].split("%")[0] for ai in socket.getaddrinfo(host, None)} # Does a DNS lookup to get the IP addresses of the host; ai[4][0] is the IP string, and split("%")[0] strips any IPv6 zone id like %eth0
    except socket.gaierror: # Raised when the hostname cannot be resolved
        return False # Unresolvable hosts are treated as NOT local (the safe default)
    return bool(addrs) and all(ipaddress.ip_address(a).is_private for a in addrs) # True only if at least one address was found AND every address is private/loopback


def normalize_target(target: str) -> str: # Cleans up the target URL and guarantees it is a valid http(s) URL
    target = target.strip() # Removes spaces and newlines from both ends
    if not re.match(r"^https?://", target, re.I): # Checks if the target starts with http:// or https:// (case-insensitive)
        target = "http://" + target # If not, add http:// in front
    parsed = urlparse(target) # Splits the URL into scheme, netloc, path, etc.
    if parsed.scheme not in ("http", "https") or not parsed.netloc: # The scheme must be http/https and a host must be present
        raise ValueError("Enter a valid http:// or https:// URL.") # Reject anything else with a clear message
    return target # Return the cleaned URL



# Data classes----------------------------------------------------------------------------------------------

@dataclass # Auto-generates __init__, __repr__, etc. from the fields below
class Finding: # Represents one security finding identified during the scan
    id: str # Short machine-friendly identifier, e.g. "HDR-CSP-MISSING"
    title: str # Human-readable title of the issue
    severity: str # One of critical / high / medium / low / info
    category: str # Group the finding belongs to, e.g. "Headers" or "Cookies"
    url: str # The URL where the issue was found
    description: str # Explanation of why this is a problem
    evidence: str # Concrete proof observed by the scanner
    fix: str # Recommended remediation


@dataclass # Same shortcut for the Page class
class Page: # Represents a web page that has been crawled during the scan
    url: str # Final URL of the page (after redirects)
    status: int # HTTP status code returned
    forms: list # List of form dictionaries found on the page



# Knowledge tables-------------------------------------------------------------------------------------------------

# (path, severity, title, description, must-match regex or None, report 401/403?)
SENSITIVE_PATHS = [ # Paths the scanner probes; each tuple follows the layout in the comment above
    ("/.env", "high", "Environment file exposed", # Path, severity, title
     "A .env file is publicly readable. These usually hold secret keys and database credentials.", # Description
     r"(?m)^[A-Za-z0-9_]+\s*=", False), # Content must look like KEY=value lines; don't report 401/403
    ("/.git/HEAD", "high", "Git repository exposed", # Git metadata file
     "The .git directory is reachable, which can let anyone download the application's source code and history.", # Description
     r"^ref:", False), # A real .git/HEAD starts with "ref:"
    ("/.svn/entries", "medium", "Subversion metadata exposed", # Old SVN metadata
     "Version-control metadata is reachable and can leak source code and file structure.", None, False), # No content check needed
    ("/.DS_Store", "low", "macOS .DS_Store file exposed", # Finder metadata file
     "This file leaks directory and file names that were never meant to be public.", None, False), # No content check needed
    ("/phpinfo.php", "medium", "phpinfo() page exposed", # PHP diagnostic page
     "phpinfo output reveals PHP configuration, paths, and environment details.", r"phpinfo\(\)|PHP Version", False), # Content must mention phpinfo/PHP Version
    ("/server-status", "medium", "Apache server-status exposed", # Apache status module page
     "Live server status can reveal internal URLs, client IPs and load.", r"Apache Server Status", False), # Content must contain the Apache heading
    ("/console", "high", "Debug console reachable", # Werkzeug/other debug console
     "An interactive debug console (for example Werkzeug) allows code execution if reachable.", # Description
     r"(?i)console|werkzeug", False), # Content must mention console or werkzeug
    ("/debug", "medium", "Debug endpoint reachable", # Generic debug endpoint
     "Debug endpoints often expose internals and should not exist in production.", None, False), # No content check needed
    ("/admin", "info", "Admin path present", # Admin path without trailing slash
     "An administration area exists at this path. Confirm it requires strong authentication.", None, True), # True = also report when 401/403 is returned
    ("/admin/", "medium", "Admin panel accessible without authentication", # Admin path with trailing slash
     "An administration area responded with HTTP 200 without any credentials.", None, True), # True = also report when 401/403 is returned
    ("/backup/", "medium", "Backup directory accessible", # Backup folder
     "A backup directory is reachable and may contain database dumps or archived source.", None, False), # No content check needed
    ("/backups/", "medium", "Backup directory accessible", # Plural variant of the backup folder
     "A backup directory is reachable and may contain database dumps or archived source.", None, False), # No content check needed
    ("/backup.zip", "high", "Backup archive exposed", # Downloadable backup archive
     "A downloadable backup archive was found.", None, False), # No content check needed
    ("/database.sql", "high", "Database dump exposed", # SQL dump file
     "A SQL dump is downloadable.", None, False), # No content check needed
    ("/db.sqlite", "high", "Database file exposed", # SQLite database file
     "A database file is downloadable.", None, False), # No content check needed
    ("/config.php", "medium", "Configuration file reachable", # PHP config file
     "A configuration file responded with HTTP 200.", None, False), # No content check needed
    ("/config/", "low", "Config directory reachable", # Config folder
     "A config directory responded with HTTP 200.", None, False), # No content check needed
    ("/logs/", "medium", "Log directory accessible", # Log folder
     "Log files can contain session IDs, internal paths, and personal data.", None, False), # No content check needed
    ("/uploads/", "low", "Uploads directory accessible", # Upload folder
     "An uploads directory is reachable. Check that listing is off and uploads cannot be executed.", None, False), # No content check needed
    ("/swagger.json", "info", "API description exposed", # OpenAPI/Swagger spec
     "An API specification is public. This is fine for public APIs but maps every endpoint for attackers.", None, False), # No content check needed
    ("/api/docs", "info", "API docs exposed", # API documentation page
     "API documentation is public. Confirm this is intended.", None, False), # No content check needed
] # End of the sensitive paths list

DB_ERROR_PATTERNS = [ # Regex patterns that identify database error messages in a response
    r"you have an error in your sql syntax", # MySQL syntax error
    r"sqlite3?\.(operational|programming)error", # Python sqlite3 errors
    r"unrecognized token", # SQLite tokenizer error
    r"unclosed quotation mark", # SQL Server error
    r"ORA-\d{5}", # Oracle error codes
    r"psycopg2?\.", # PostgreSQL Python driver errors
    r"SQLSTATE\[", # PDO/SQL standard error state
    r"mysql_fetch|mysqli?_", # PHP MySQL function names leaked in errors
    r"syntax error at or near", # PostgreSQL syntax error
] # End of the DB error patterns
DEBUG_PATTERNS = [ # Regex patterns that identify stack traces / debug output in a response
    r"Traceback \(most recent call last\)", # Python traceback header
    r"Werkzeug Debugger", # Flask/Werkzeug debugger page
    r"at [\w.$]+\([\w]+\.java:\d+\)", # Java stack trace line
    r"System\.\w+Exception", # .NET exception name
    r"Fatal error:.*on line \d+", # PHP fatal error message
] # End of the debug patterns
SESSION_NAME = re.compile(r"sess|sid|token|auth|jwt|login|remember", re.I) # Pattern used to guess whether a cookie name looks like a session/auth cookie
CSRF_NAME = re.compile(r"csrf|xsrf|token|nonce|authenticity", re.I) # Pattern used to guess whether a hidden form field name is an anti-CSRF token
SKIP_EXT = re.compile(r"\.(png|jpe?g|gif|svg|ico|css|js|woff2?|ttf|pdf|zip|gz|mp4|mp3|webp)$", re.I) # File extensions the crawler skips (static assets)
SKIP_PATH = re.compile(r"logout|signout|delete|remove", re.I) # Paths the crawler skips so it never triggers logout/delete actions
TEXT_INPUT_TYPES = {"text", "search", "textarea", "url", "email", "tel"} # Input types treated as free-text and therefore worth probing


# Helpers -------------------------------------------------------------------------------------------------------

def _set_cookie_headers(resp: requests.Response) -> list[str]: # Returns ALL Set-Cookie headers of a response as a list
    raw = getattr(resp, "raw", None) # Gets the low-level urllib3 response (or None)
    headers = getattr(raw, "headers", None) # Gets its headers object (or None)
    if headers is not None and hasattr(headers, "getlist"): # urllib3's header object can return multiple values for the same header
        return list(headers.getlist("Set-Cookie")) # Return every Set-Cookie header
    value = resp.headers.get("Set-Cookie") # Fallback: requests merges duplicates into one string
    return [value] if value else [] # Wrap it in a list, or return an empty list if absent


def parse_set_cookie(raw: str): # Splits a raw Set-Cookie header into name, value and attributes
    parts = [p.strip() for p in raw.split(";")] # Cookie parts are separated by semicolons
    name, _, value = parts[0].partition("=") # The first part is always name=value
    attrs = {} # Dictionary that will hold attributes like httponly, secure, samesite
    for p in parts[1:]: # Loop over every attribute after the name=value pair
        k, _, v = p.partition("=") # Split "Key=Value" (flags such as HttpOnly have no value)
        attrs[k.strip().lower()] = v.strip() # Store the key in lowercase so lookups are consistent
    return name.strip(), value, attrs # Return the parsed pieces


def _redact_env(text: str) -> str: # Hides secret values from an exposed .env file before putting it in the report
    lines = [] # Collects the redacted lines
    for line in text.splitlines()[:6]: # Only the first six lines are shown
        lines.append(re.sub(r"=.*", "=<redacted>", line)) # Replace everything after "=" with a placeholder
    return "\n".join(lines) # Join back into a single string


def _snippet(text: str, needle: str, width: int = 70) -> str: # Returns a short piece of text around a match, for use as evidence
    i = text.find(needle) # Position of the first occurrence of the needle
    if i < 0: # -1 means it was not found
        return "" # Nothing to show
    s = text[max(0, i - width): i + len(needle) + width] # Slice `width` characters before and after the needle (never before index 0)
    return re.sub(r"\s+", " ", s).strip() # Collapse whitespace runs into single spaces and trim



# Scanner ---------------------------------------------------------------------------------------------------

class Scanner: # Main class that crawls the target and runs all security checks
    USER_AGENT = "WebSecScanner/1.0 (educational; non-intrusive)" # Identifies the scanner honestly in server logs
    MAX_REQUESTS = 400 # Hard cap on the number of requests per scan

    def __init__(self, target, max_pages=15, delay=0.2, timeout=6,
                 checks=None, test_post=False): # Sets up the scanner's configuration and internal state
        self.target = normalize_target(target) # Normalizes the target URL to ensure it is a valid HTTP or HTTPS URL.
        self.max_pages = max(1, min(int(max_pages), 50)) # Keeps the page limit between 1 and 50
        self.delay = max(0.0, float(delay)) # Ensures the delay between requests is never negative
        self.timeout = timeout # Seconds to wait for each HTTP response
        self.checks = [c for c in (checks or ALL_CHECKS) if c in ALL_CHECKS] # Keeps only valid check names; defaults to all checks
        self.test_post = test_post # Whether POST forms may be submitted during input testing

        self.session = requests.Session() # One session gives connection pooling and cookie persistence
        self.session.headers["User-Agent"] = self.USER_AGENT # Sends the scanner's User-Agent on every request
        self.session.verify = False  # test apps often use self-signed certificates

        self.findings: list[Finding] = [] # Stores every finding discovered
        self._seen: set = set() # Keys of findings already recorded, used to avoid duplicates
        self.request_count = 0 # Number of requests sent so far (compared against MAX_REQUESTS)
        self.cookie_headers: dict[str, tuple[str, str]] = {} # cookie name -> (URL where it was set, raw Set-Cookie header)
        self.notes: list[str] = [] # Informational messages (failed requests, early stop) included in the report

    # ------------------------------------------------------------------ #
    def _req(self, method, url, **kw): # Central place for ALL HTTP requests, enforcing the budget and delay
        if self.request_count >= self.MAX_REQUESTS: # Budget check: stop if the limit is reached
            raise ScanLimit("Request budget reached") # Aborts the scan via the custom exception
        if self.request_count: # Skip the delay before the very first request
            time.sleep(self.delay) # Pause so the target is never hammered with rapid requests
        self.request_count += 1 # Count this request
        kw.setdefault("timeout", self.timeout) # Use the default timeout unless the caller supplied one
        try: # Network calls can fail in many ways
            resp = self.session.request(method, url, **kw) # Actually sends the HTTP request
        except requests.RequestException as exc: # Covers timeouts, connection errors, bad redirects, etc.
            self.notes.append(f"{method} {url} failed: {type(exc).__name__}") # Log the failure in the report notes
            return None # Callers treat None as "no response"
        for raw in _set_cookie_headers(resp): # Look at every Set-Cookie header in the response
            name, _, _ = parse_set_cookie(raw) # Only the cookie name is needed here
            self.cookie_headers.setdefault(name, (resp.url, raw)) # Remember the first time each cookie was seen, for check_cookies() later
        return resp # Hand the response back to the caller

    def _add(self, fid, title, severity, category, url, description, evidence, fix, key=None): # Records a finding unless an identical one exists
        k = key or (fid, url, evidence) # Deduplication key; defaults to id + URL + evidence
        if k in self._seen: # Already recorded?
            return # Then skip it
        self._seen.add(k) # Mark this key as seen
        self.findings.append(Finding(fid, title, severity, category, url, description, evidence, fix)) # Build the Finding and store it

    # ------------------------------------------------------------------ #
    def run(self) -> dict: # Orchestrates the whole scan and returns the result dictionary
        started = datetime.now(timezone.utc) # Wall-clock start time (UTC) for the report
        t0 = time.time() # High-resolution start marker for measuring duration
        pages: list[Page] = [] # Will hold the crawled pages
        try: # A ScanLimit raised anywhere inside is caught at the bottom
            home = self._req("GET", self.target) # Fetch the home page
            if home is None: # Request failed completely
                raise ConnectionError(f"Could not reach {self.target}. Is the application running?") # Early exit with a helpful message

            pages = self._crawl(home) # Crawl same-origin links starting from the home page

            if "headers" in self.checks: # Header/transport checks requested?
                self.check_transport(home) # Is the site on plain HTTP?
                self.check_headers(home) # Security headers and information disclosure
            if "methods" in self.checks: # HTTP method checks requested?
                self.check_methods(home.url) # Looks at advertised methods and TRACE
            if "directories" in self.checks: # Exposed files/directories checks requested?
                self.check_directories(home.url) # Probes the sensitive path list
            if "forms" in self.checks: # Form checks requested?
                self.check_forms(pages) # CSRF tokens and password-over-HTTP
            if "inputs" in self.checks: # Input handling checks requested?
                self.check_inputs(pages) # Reflection and error-handling probes
            if "cookies" in self.checks: # Cookie checks requested?
                self.check_cookies() # Analyses the cookies collected during the scan
        except ScanLimit: # The request budget ran out mid-scan
            self.notes.append(f"Stopped early: request limit of {self.MAX_REQUESTS} reached.") # Tell the user the scan was cut short so partial results aren't mistaken for a full scan

        return self._result(started, time.time() - t0, len(pages)) # Build the final report (start time, duration, pages crawled)

   
    # Crawl-----------------------------------------------------------------------------------------------------
   
    def _crawl(self, home) -> list[Page]: # Breadth-first crawl of same-origin HTML pages
        origin = urlparse(home.url).netloc # Host[:port] of the target; links to other hosts are ignored
        queue, seen, pages = [home.url], {home.url}, [] # URLs to visit, URLs already queued, pages collected
        while queue and len(pages) < self.max_pages: # Continue until the queue is empty or the page limit is hit
            url = queue.pop(0) # Take the next URL (FIFO = breadth-first)
            resp = home if url == home.url else self._req("GET", url) # Reuse the home response instead of requesting it twice
            if resp is None or "html" not in resp.headers.get("Content-Type", "").lower(): # Skip failures and non-HTML responses
                continue # Move on to the next URL
            soup = BeautifulSoup(resp.text, "html.parser") # Parse the HTML
            pages.append(Page(resp.url, resp.status_code, self._extract_forms(soup, resp.url))) # Save the page together with its forms
            for a in soup.find_all("a", href=True): # Look at every link that has an href
                link = urljoin(resp.url, a["href"]).split("#")[0] # Make it absolute and drop the #fragment
                p = urlparse(link) # Split the link into parts
                if p.scheme not in ("http", "https") or p.netloc != origin: # Ignore mailto:, javascript:, and other sites
                    continue # Skip this link
                if SKIP_EXT.search(p.path) or SKIP_PATH.search(p.path): # Ignore static files and dangerous actions like logout/delete
                    continue # Skip this link
                if link not in seen: # Only queue new URLs
                    seen.add(link) # Remember it
                    queue.append(link) # Add it to the end of the queue
        return pages # Return every crawled page

    @staticmethod # Does not need `self`
    def _extract_forms(soup, base): # Collects every form on a page into simple dictionaries
        forms = [] # Result list
        for f in soup.find_all("form"): # Loop over every <form> tag
            inputs = [] # Fields belonging to this form
            for el in f.find_all(["input", "textarea", "select"]): # Every field-like element
                name = el.get("name") # The field's name attribute
                if not name: # Fields without a name are not submitted by browsers
                    continue # Skip them
                typ = (el.get("type") or ("textarea" if el.name == "textarea" else "text")).lower() # Field type; textarea/none default sensibly
                inputs.append({"name": name, "type": typ, "value": el.get("value", "") or ""}) # Store name, type and default value
            forms.append({ # Add a dictionary describing the form
                "page": base, # The page the form was found on
                "action": urljoin(base, f.get("action") or base), # Absolute submit URL (blank action = same page)
                "method": (f.get("method") or "get").lower(), # HTTP method, default GET like browsers
                "inputs": inputs, # The fields collected above
            }) # End of the form dictionary
        return forms # Return all forms of the page

    
    # Transport + headers----------------------------------------------------------------------------------------
   
    def check_transport(self, resp): # Flags sites served over unencrypted HTTP
        if resp.url.startswith("http://"): # Only relevant if the final URL is plain HTTP
            local = is_local_target(resp.url) # Local test apps get a softer severity
            self._add( # Record the finding
                "TLS-NONE", "Site is served over plain HTTP", # Id and title
                "info" if local else "medium", "Transport", resp.url, # Severity depends on locality; category; URL
                "Traffic, including cookies and form data, can be read or modified by anyone on the network path.", # Description
                f"Scheme of {resp.url} is http://" # Evidence part 1
                + (" (acceptable for a local test app)" if local else ""), # Evidence part 2: extra note for local targets
                "Serve the site over HTTPS, redirect HTTP to HTTPS, and enable HSTS.", # Fix
            ) # End of _add call

    def check_headers(self, resp): # Checks security headers and information-disclosure headers
        url, h = resp.url, resp.headers # Shortcuts for the URL and the header dictionary
        https = url.startswith("https://") # HSTS only makes sense over HTTPS
        csp = h.get("Content-Security-Policy", "") # The CSP header value, or an empty string

        # Content-Security-Policy
        if not csp: # No CSP at all
            self._add("HDR-CSP-MISSING", "Content-Security-Policy header missing", "medium", "Headers", url, # Id, title, severity, category, URL
                      "CSP limits which scripts, styles and frames the browser may load, and is the strongest " # Description part 1
                      "defence-in-depth against cross-site scripting.", # Description part 2
                      "Header not present in response.", # Evidence
                      "Add a policy such as: Content-Security-Policy: default-src 'self'; object-src 'none'; " # Fix part 1
                      "frame-ancestors 'self'. Start in report-only mode if unsure.") # Fix part 2
        else: # A CSP exists, so inspect it for weaknesses
            d = {} # Will map directive name -> list of sources
            for part in csp.split(";"): # Directives are separated by semicolons
                bits = part.strip().split() # First word = directive, rest = sources
                if bits: # Ignore empty pieces
                    d[bits[0].lower()] = bits[1:] # Store the directive and its sources
            script_src = d.get("script-src", d.get("default-src", [])) # script-src falls back to default-src if missing
            if "'unsafe-inline'" in script_src: # Inline scripts allowed
                self._add("HDR-CSP-UNSAFE-INLINE", "CSP allows inline scripts", "medium", "Headers", url, # Id, title, severity, category, URL
                          "'unsafe-inline' in script-src largely cancels CSP's protection against XSS.", # Description
                          f"Content-Security-Policy: {csp}", # Evidence: the full header
                          "Remove 'unsafe-inline'; use nonces or hashes for the scripts you need.") # Fix
            if "'unsafe-eval'" in script_src: # eval() allowed
                self._add("HDR-CSP-UNSAFE-EVAL", "CSP allows eval()", "low", "Headers", url, # Id, title, severity, category, URL
                          "'unsafe-eval' lets string-to-code functions run, widening the XSS attack surface.", # Description
                          f"Content-Security-Policy: {csp}", # Evidence
                          "Remove 'unsafe-eval' and refactor code that depends on eval().") # Fix
            if "*" in script_src or "http:" in script_src: # Overly broad script sources
                self._add("HDR-CSP-WILDCARD", "CSP script source is too broad", "medium", "Headers", url, # Id, title, severity, category, URL
                          "A wildcard or plain http: script source allows scripts from almost anywhere.", # Description
                          f"Content-Security-Policy: {csp}", # Evidence
                          "List only the specific origins you trust for scripts.") # Fix

        # HSTS
        if https: # Only check HSTS on HTTPS sites
            hsts = h.get("Strict-Transport-Security") # Read the header (None if absent)
            if not hsts: # Header missing
                self._add("HDR-HSTS-MISSING", "Strict-Transport-Security header missing", "medium", "Headers", url, # Id, title, severity, category, URL
                          "Without HSTS, browsers may connect over HTTP first, enabling downgrade and " # Description part 1
                          "man-in-the-middle attacks.", # Description part 2
                          "Header not present in response.", # Evidence
                          "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains") # Fix
            else: # Header present, so check its lifetime
                m = re.search(r"max-age=(\d+)", hsts, re.I) # Extract the max-age number
                if not m or int(m.group(1)) < 15552000: # Missing, or shorter than 180 days
                    self._add("HDR-HSTS-WEAK", "HSTS max-age is short", "low", "Headers", url, # Id, title, severity, category, URL
                              "A short max-age gives only brief protection after the last visit.", # Description
                              f"Strict-Transport-Security: {hsts}", # Evidence
                              "Use max-age of at least 15552000 (180 days); 31536000 is common.") # Fix

        # Clickjacking
        xfo = h.get("X-Frame-Options") # Read X-Frame-Options (None if absent)
        if not xfo and "frame-ancestors" not in csp: # Neither protection is present
            self._add("HDR-XFO-MISSING", "Clickjacking protection missing", "medium", "Headers", url, # Id, title, severity, category, URL
                      "Without X-Frame-Options or CSP frame-ancestors, other sites can embed this page in a " # Description part 1
                      "frame and trick users into clicking hidden controls.", # Description part 2
                      "Neither X-Frame-Options nor CSP frame-ancestors present.", # Evidence
                      "Add X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'none'.") # Fix
        elif xfo and xfo.strip().upper() not in ("DENY", "SAMEORIGIN"): # Header exists but has an unsupported value
            self._add("HDR-XFO-WEAK", "X-Frame-Options has an unsupported value", "low", "Headers", url, # Id, title, severity, category, URL
                      "Only DENY and SAMEORIGIN are reliably honoured by browsers.", # Description
                      f"X-Frame-Options: {xfo}", "Use DENY or SAMEORIGIN.") # Evidence, fix

        # MIME sniffing
        if h.get("X-Content-Type-Options", "").strip().lower() != "nosniff": # Header missing or not "nosniff"
            self._add("HDR-XCTO-MISSING", "X-Content-Type-Options header missing", "low", "Headers", url, # Id, title, severity, category, URL
                      "Browsers may guess a file's type and execute content that was served as something harmless.", # Description
                      f"X-Content-Type-Options: {h.get('X-Content-Type-Options', '(absent)')}", # Evidence: actual value or "(absent)"
                      "Add: X-Content-Type-Options: nosniff") # Fix

        if not h.get("Referrer-Policy"): # No Referrer-Policy header
            self._add("HDR-REFERRER-MISSING", "Referrer-Policy header missing", "low", "Headers", url, # Id, title, severity, category, URL
                      "Full URLs, including query strings, may be sent to other sites when users follow links.", # Description
                      "Header not present in response.", # Evidence
                      "Add: Referrer-Policy: strict-origin-when-cross-origin") # Fix

        if not h.get("Permissions-Policy"): # No Permissions-Policy header
            self._add("HDR-PERMISSIONS-MISSING", "Permissions-Policy header missing", "info", "Headers", url, # Id, title, severity, category, URL
                      "This header restricts powerful browser features (camera, geolocation, etc.) for the page " # Description part 1
                      "and any embedded content.", # Description part 2
                      "Header not present in response.", # Evidence
                      "Add a restrictive policy, e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()") # Fix

        # Information disclosure
        server = h.get("Server", "") # Server header, or empty string
        if re.search(r"\d", server): # A digit in the value usually means a version number
            self._add("HDR-SERVER-VERSION", "Server header discloses version", "low", "Information disclosure", url, # Id, title, severity, category, URL
                      "Exact software versions help attackers look up known vulnerabilities.", # Description
                      f"Server: {server}", # Evidence
                      "Configure the web server to send a generic or empty Server header.") # Fix
        if h.get("X-Powered-By"): # Header reveals the framework/language
            self._add("HDR-POWERED-BY", "X-Powered-By header discloses technology", "low", # Id, title, severity
                      "Information disclosure", url, # Category, URL
                      "Reveals the framework or language in use.", # Description
                      f"X-Powered-By: {h['X-Powered-By']}", # Evidence
                      "Remove the header (e.g. app.disable('x-powered-by') in Express, expose_php=Off in PHP).") # Fix

        if h.get("Access-Control-Allow-Origin") == "*": # CORS allows every origin
            self._add("HDR-CORS-WILDCARD", "CORS allows any origin", "low", "Headers", url, # Id, title, severity, category, URL
                      "Any website can read responses from this endpoint. Harmless for public data, " # Description part 1
                      "risky if the response is user-specific.", # Description part 2
                      "Access-Control-Allow-Origin: *", # Evidence
                      "Restrict to the specific origins that need access.") # Fix

    
    # Cookies-----------------------------------------------------------------------------------------------
    
    def check_cookies(self): # Checks security attributes of every cookie seen during the scan
        for name, (url, raw) in self.cookie_headers.items(): # Loop over each cookie: name, (URL, raw header)
            _, _, attrs = parse_set_cookie(raw) # Get the attributes dictionary (httponly, secure, samesite, ...)
            session_like = bool(SESSION_NAME.search(name)) # True if the name looks like a session/auth cookie
            https = url.startswith("https://") # Was the cookie set over HTTPS?
            safe_raw = re.sub(r"^([^=]+)=[^;]*", r"\1=<value>", raw) # Replace the cookie value with a placeholder so secrets never enter the report

            if "httponly" not in attrs: # HttpOnly flag missing
                self._add("CKE-HTTPONLY", f"Cookie '{name}' missing HttpOnly", "medium" if session_like else "low", # Id, title, severity (higher for session cookies)
                          "Cookies", url, # Category, URL
                          "Without HttpOnly, any injected script can read this cookie and steal the session.", # Description
                          f"Set-Cookie: {safe_raw}", # Evidence with the value redacted
                          "Add the HttpOnly attribute to the cookie.", key=("CKE-HTTPONLY", name)) # Fix; dedupe per cookie name
            if "secure" not in attrs: # Secure flag missing
                sev = ("medium" if session_like else "low") if https else "low" # Only rate higher if the site uses HTTPS
                note = "" if https else " (site is on HTTP, so Secure cannot take effect until HTTPS is enabled)" # Explanation for HTTP sites
                self._add("CKE-SECURE", f"Cookie '{name}' missing Secure", sev, "Cookies", url, # Id, title, severity, category, URL
                          "Without Secure, the cookie is also sent over unencrypted HTTP connections." # Description part 1
                          + note, # Description part 2: optional note
                          f"Set-Cookie: {safe_raw}", # Evidence
                          "Add the Secure attribute and serve the whole site over HTTPS.", # Fix
                          key=("CKE-SECURE", name)) # Dedupe per cookie name
            samesite = attrs.get("samesite", "").lower() # SameSite value in lowercase, or empty
            if not samesite: # SameSite attribute missing
                self._add("CKE-SAMESITE", f"Cookie '{name}' missing SameSite", "low", "Cookies", url, # Id, title, severity, category, URL
                          "SameSite limits cross-site sending of the cookie and reduces CSRF risk.", # Description
                          f"Set-Cookie: {safe_raw}", # Evidence
                          "Add SameSite=Lax (or Strict where possible).", key=("CKE-SAMESITE", name)) # Fix; dedupe per cookie
            elif samesite == "none" and "secure" not in attrs: # SameSite=None requires Secure
                self._add("CKE-SAMESITE-NONE", f"Cookie '{name}' uses SameSite=None without Secure", "medium", # Id, title, severity
                          "Cookies", url, # Category, URL
                          "Browsers reject or downgrade SameSite=None cookies that are not Secure.", # Description
                          f"Set-Cookie: {safe_raw}", # Evidence
                          "Add Secure, or use SameSite=Lax.", key=("CKE-SAMESITE-NONE", name)) # Fix; dedupe per cookie

   
    # HTTP methods-------------------------------------------------------------------------------------------------
    
    def check_methods(self, url): # Checks which HTTP methods the server advertises or allows
        resp = self._req("OPTIONS", url) # OPTIONS asks the server which methods it supports
        if resp is not None: # Only continue if a response came back
            allow = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods") or "" # Read the allowed methods from either header
            methods = {m.strip().upper() for m in allow.split(",") if m.strip()} # Turn "GET, POST" into a clean uppercase set
            for m, sev, why in [ # Risky methods to look for, with severity and explanation
                ("PUT", "medium", "PUT can create or overwrite resources."), # PUT
                ("DELETE", "medium", "DELETE can remove resources."), # DELETE
                ("TRACE", "low", "TRACE echoes requests back and can aid cross-site tracing attacks."), # TRACE
                ("CONNECT", "low", "CONNECT can let the server be used as a proxy."), # CONNECT
            ]: # End of the risky methods list
                if m in methods: # Method is advertised
                    self._add(f"MTH-{m}", f"HTTP {m} method advertised", sev, "HTTP methods", url, # Id, title, severity, category, URL
                              why + " The scanner did not send this method; it only read the Allow header.", # Description
                              f"Allow: {allow}", # Evidence: the raw header value
                              f"Disable {m} unless the application needs it, and require authentication and " # Fix part 1
                              "authorisation when it does.") # Fix part 2

        probe = secrets.token_hex(4) # Random marker used to detect echoing
        tr = self._req("TRACE", url, headers={"X-WebSec-Probe": probe}) # Sends a harmless TRACE request with a custom header
        if tr is not None and tr.status_code == 200 and probe in tr.text: # Server answered 200 and reflected our marker back
            self._add("MTH-TRACE-ACTIVE", "TRACE method is enabled and echoes requests", "medium", # Id, title, severity
                      "HTTP methods", url, # Category, URL
                      "The server reflects the full request, including headers, back to the sender.", # Description
                      f"TRACE {url} returned HTTP 200 and echoed the probe header.", # Evidence
                      "Disable TRACE in the web server configuration.") # Fix

    
    # Exposed directories / files----------------------------------------------------------------------------------------
    
    def check_directories(self, url): # Probes for sensitive files/directories that should not be public
        p = urlparse(url) # Split the URL into parts
        root = f"{p.scheme}://{p.netloc}" # Site root, e.g. http://127.0.0.1:5001

        # Baseline for servers that answer 200 to everything ("soft 404")
        base = self._req("GET", f"{root}/{secrets.token_hex(8)}", allow_redirects=False) # Request a random path that cannot exist
        base_status = base.status_code if base is not None else None # Status of that "not found" page
        base_len = len(base.content) if base is not None else None # Size of that "not found" page

        # robots.txt hints
        rb = self._req("GET", f"{root}/robots.txt", allow_redirects=False) # Fetch robots.txt
        if rb is not None and rb.status_code == 200 and "text" in rb.headers.get("Content-Type", "text"): # Must be a successful text response
            dis = [ln.split(":", 1)[1].strip() for ln in rb.text.splitlines() # Extract the value of each line...
                   if ln.lower().startswith("disallow:") and ln.split(":", 1)[1].strip()] # ...that is a non-empty Disallow rule
            if dis: # At least one hidden path is listed
                self._add("DIR-ROBOTS", "robots.txt lists hidden paths", "info", "Exposure", f"{root}/robots.txt", # Id, title, severity, category, URL
                          "robots.txt is public. Listing sensitive paths there advertises them to anyone reading it.", # Description
                          "Disallow: " + ", ".join(dis[:8]), # Evidence: first eight paths
                          "Protect sensitive paths with authentication; do not rely on robots.txt to hide them.") # Fix

        for path, sev, title, desc, must, report_denied in SENSITIVE_PATHS: # Go through every entry of the knowledge table
            full = f"{root}{path}" # Complete URL to test
            r = self._req("GET", full, allow_redirects=False) # Request it without following redirects
            if r is None: # Request failed
                continue # Skip this path
            if r.status_code in (401, 403): # Access control answered
                if report_denied: # Only some paths (like /admin) are worth reporting when protected
                    self._add("DIR-PROTECTED", f"{title.split(' ')[0]} path exists but is protected", "info", # Id, title, severity
                              "Exposure", full, "The path exists and access control responded. Good.", # Category, URL, description
                              f"GET {path} returned HTTP {r.status_code}", # Evidence
                              "Keep strong authentication and consider restricting by IP or VPN.") # Fix
                continue # Nothing more to do for protected paths
            if r.status_code != 200: # Anything other than 200 means the file is not exposed
                continue # Skip
            if base_status == 200 and base_len is not None and abs(len(r.content) - base_len) < 20: # Same size as the "not found" page
                continue  # soft 404
            if must and not re.search(must, r.text[:4000]): # Content check failed (e.g. no KEY=value lines in a .env)
                continue # Likely a false positive, so skip

            evidence = f"GET {path} returned HTTP 200 ({len(r.content)} bytes)." # Base evidence text
            if path == "/.env": # Special handling to avoid leaking secrets
                evidence += "\n" + _redact_env(r.text) # Add a redacted preview of the file
            self._add("DIR-" + re.sub(r"\W+", "-", path).strip("-").upper(), title, sev, "Exposure", full, # Id built from the path (e.g. DIR-ENV), title, severity, category, URL
                      desc, evidence, # Description and evidence
                      "Remove it from the web root or block it in the web server config. If it ever held " # Fix part 1
                      "secrets, rotate them.") # Fix part 2

            if re.search(r"<title>\s*Index of|Directory listing for", r.text[:2000], re.I): # Response looks like an auto-generated file index
                self._add("DIR-LISTING", "Directory listing enabled", "medium", "Exposure", full, # Id, title, severity, category, URL
                          "The server lists the contents of a directory, letting visitors browse files that " # Description part 1
                          "were never linked.", # Description part 2
                          f"Response for {path} looks like an auto-generated index page.", # Evidence
                          "Disable auto-indexing (Options -Indexes in Apache, autoindex off in nginx).", # Fix
                          key=("DIR-LISTING", full)) # Dedupe per URL

   
    # Forms------------------------------------------------------------------------------------------------------

    def check_forms(self, pages): # Checks forms for password-over-HTTP and missing CSRF tokens
        for page in pages: # Every crawled page
            for f in page.forms: # Every form on that page
                has_pw = any(i["type"] == "password" for i in f["inputs"]) # Does the form contain a password field?
                insecure = f["action"].startswith("http://") # Does it submit to a plain HTTP URL?
                if has_pw and insecure: # Password sent over HTTP
                    local = is_local_target(f["action"]) # Local test apps get a lower severity
                    self._add("FRM-PASSWORD-HTTP", "Password form submits over plain HTTP", # Id, title
                              "low" if local else "high", "Forms", f["action"], # Severity, category, URL
                              "Passwords sent over HTTP can be read by anyone on the network." # Description part 1
                              + (" (Low here only because the target is a local test app.)" if local else ""), # Description part 2
                              f"Form on {f['page']} posts to {f['action']} and contains a password field.", # Evidence
                              "Serve the form and its action over HTTPS.", # Fix
                              key=("FRM-PASSWORD-HTTP", f["action"])) # Dedupe per form action
                if f["method"] == "post": # CSRF matters for state-changing (POST) forms
                    hidden_names = [i["name"] for i in f["inputs"] if i["type"] == "hidden"] # Names of all hidden fields
                    if not any(CSRF_NAME.search(n) for n in hidden_names): # None of them look like a CSRF token
                        self._add("FRM-CSRF", "POST form without an anti-CSRF token", "medium", "Forms", # Id, title, severity, category
                                  f["action"], # URL
                                  "Without a per-session token, another site may be able to make a logged-in " # Description part 1
                                  "user's browser submit this form.", # Description part 2
                                  f"Form on {f['page']} (POST to {f['action']}) has no hidden field " # Evidence part 1
                                  "resembling csrf/token/nonce.", # Evidence part 2
                                  "Add a random per-session CSRF token to the form and verify it on the server " # Fix part 1
                                  "(most frameworks include this).", # Fix part 2
                                  key=("FRM-CSRF", f["action"])) # Dedupe per form action

    
    # Input handling (identification only)-----------------------------------------------------------------------

    def _input_targets(self, pages): # Builds the list of URLs/forms whose inputs will be probed
        targets, seen = [], set() # Result list and a set to avoid testing the same target twice
        for page in pages: # Every crawled page
            p = urlparse(page.url) # Split the page URL
            q = parse_qsl(p.query, keep_blank_values=True) # Query-string parameters as (key, value) pairs
            if q: # Page has GET parameters
                base = urlunparse(p._replace(query="")) # URL without its query string
                key = ("get", base, tuple(sorted(k for k, _ in q))) # Unique key: method + URL + parameter names
                if key not in seen: # Not tested before
                    seen.add(key) # Remember it
                    targets.append(("get", base, dict(q), [k for k, _ in q])) # (method, url, all fields, testable fields)
            for f in page.forms: # Every form on the page
                if f["method"] == "post" and not self.test_post: # POST probing must be enabled with --test-post
                    continue # Skip POST forms otherwise
                if any(i["type"] in ("password", "file") for i in f["inputs"]): # Never touch login or upload forms
                    continue # Skip them
                fields = {i["name"]: i["value"] for i in f["inputs"] # Map of field name -> default value...
                          if i["type"] not in ("submit", "button", "image", "reset")} # ...excluding buttons
                testable = [i["name"] for i in f["inputs"] if i["type"] in TEXT_INPUT_TYPES] # Only free-text fields are probed
                key = (f["method"], f["action"], tuple(sorted(fields))) # Unique key for this form
                if testable and key not in seen: # Has testable fields and is new
                    seen.add(key) # Remember it
                    targets.append((f["method"], f["action"], fields, testable)) # Add to the target list
        return targets # Return everything to probe

    def _send(self, method, url, params): # Sends a probe as either GET or POST
        if method == "get": # GET puts parameters in the query string
            return self._req("GET", url, params=params) # Send GET
        return self._req("POST", url, data=params) # Otherwise send parameters as the POST body

    def check_inputs(self, pages): # Sends harmless probes to find reflection and error-handling problems
        for method, url, fields, testable in self._input_targets(pages): # Loop over each target found above
            base_fields = {k: (v if v else "test") for k, v in fields.items()} # Fill empty fields with "test" so the form is valid
            baseline = self._send(method, url, base_fields) # Normal request used for comparison
            base_status = baseline.status_code if baseline is not None else 200 # Baseline status (assume 200 if it failed)

            for param in testable: # Test one field at a time
                # 1) Reflection of a harmless marker
                tok = secrets.token_hex(3) # Random token so the marker is unique
                marker = f"wsc{tok}<b>" # Marker containing an HTML character (<b>) to see if it is encoded
                r = self._send(method, url, {**base_fields, param: marker + '"\''}) # Send the marker plus quote characters in this field
                if r is not None and "html" in r.headers.get("Content-Type", "").lower() and marker in r.text: # HTML response that contains the marker unencoded
                    self._add("INP-REFLECT", "Input reflected without HTML encoding (possible reflected XSS)", # Id, title
                              "high", "Input handling", url, # Severity, category, URL
                              f"The value of '{param}' is placed into the page with HTML characters intact. " # Description part 1
                              "If a script tag can be reflected this way, an attacker can run JavaScript in a " # Description part 2
                              "victim's browser by sending them a crafted link.", # Description part 3
                              f"{method.upper()} parameter '{param}': marker '<b>' returned unencoded.\n" # Evidence part 1
                              f"Context: …{_snippet(r.text, marker)}…", # Evidence part 2: text around the reflection
                              "Encode output for its context (HTML-escape by default, use auto-escaping " # Fix part 1
                              "templates), validate input against an allow-list, and add a Content-Security-Policy.", # Fix part 2
                              key=("INP-REFLECT", url, param)) # Dedupe per URL + parameter

                # 2) A stray quote - does the app leak errors or crash?
                r2 = self._send(method, url, {**base_fields, param: "test'"}) # Send a single stray quote in the field
                if r2 is None: # No response
                    continue # Move on to the next parameter
                body = r2.text[:20000] # Only examine the first 20,000 characters
                db_hit = next((pat for pat in DB_ERROR_PATTERNS if re.search(pat, body, re.I)), None) # First DB error pattern that matches, or None
                dbg_hit = next((pat for pat in DEBUG_PATTERNS if re.search(pat, body, re.I)), None) # First debug pattern that matches, or None
                if db_hit: # A database error message appeared
                    m = re.search(db_hit, body, re.I) # Re-run the match to get the exact text
                    self._add("INP-DBERROR", "Database error shown for malformed input (possible SQL injection)", # Id, title
                              "high", "Input handling", url, # Severity, category, URL
                              f"A single quote in '{param}' produced a database error message. This usually " # Description part 1
                              "means the value is being concatenated into a SQL query.", # Description part 2
                              f"{method.upper()} parameter '{param}' = test' → HTTP {r2.status_code}, " # Evidence part 1
                              f"response contains: “{m.group(0)}”", # Evidence part 2: the matched error text
                              "Use parameterised queries / prepared statements everywhere, validate types " # Fix part 1
                              "(e.g. integer IDs), and show generic error pages to users.", # Fix part 2
                              key=("INP-DBERROR", url, param)) # Dedupe per URL + parameter
                elif dbg_hit: # No DB error, but debug output/stack trace appeared
                    self._add("INP-DEBUG", "Stack trace or debug output shown for malformed input", "medium", # Id, title, severity
                              "Input handling", url, # Category, URL
                              "Detailed errors expose file paths, code and library versions.", # Description
                              f"{method.upper()} parameter '{param}' = test' → HTTP {r2.status_code} with debug output.", # Evidence
                              "Turn off debug mode in production and return a generic error page.", # Fix
                              key=("INP-DEBUG", url, param)) # Dedupe per URL + parameter
                elif r2.status_code >= 500 and base_status < 500: # The probe turned a normal response into a server error
                    self._add("INP-500", "Server error on unexpected input", "medium", "Input handling", url, # Id, title, severity, category, URL
                              f"Adding a stray quote to '{param}' turned a normal response into an HTTP " # Description part 1
                              f"{r2.status_code}. The input is not being validated or handled safely.", # Description part 2
                              f"{method.upper()} parameter '{param}' = test' → HTTP {r2.status_code} " # Evidence part 1
                              f"(baseline HTTP {base_status}).", # Evidence part 2
                              "Validate and sanitise input, handle exceptions, and return 400 for bad input.", # Fix
                              key=("INP-500", url, param)) # Dedupe per URL + parameter

    # ------------------------------------------------------------------ #
    def _result(self, started, duration, pages_crawled) -> dict: # Builds the final report dictionary
        findings = sorted(self.findings, # Sort findings...
                          key=lambda f: (SEVERITY_ORDER.index(f.severity), f.category, f.title)) # ...by severity (most severe first), then category, then title
        counts = {s: 0 for s in SEVERITY_ORDER} # Start every severity count at zero
        for f in findings: # Loop over the sorted findings
            counts[f.severity] += 1 # Count each finding under its severity
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings) # Total penalty points from all findings
        score = round(100 * math.exp(-penalty / 60))  # smooth decay: never a flat 0 until truly bad
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F" # Converts the score into a letter grade
        return { # The complete report as a plain dictionary
            "target": self.target, # The URL that was scanned
            "started": started.isoformat(timespec="seconds"), # Start time as an ISO-8601 string
            "duration_seconds": round(duration, 1), # How long the scan took
            "pages_crawled": pages_crawled, # Number of pages visited
            "requests_made": self.request_count, # Number of HTTP requests sent
            "checks": self.checks, # Which checks were run
            "score": score, # Numeric score 0-100
            "grade": grade, # Letter grade A-F
            "counts": counts, # Findings per severity
            "findings": [asdict(f) for f in findings], # Findings converted from dataclasses to dictionaries
            "notes": self.notes, # Informational notes collected during the scan
        } # End of the report dictionary



# CLI------------------------------------------------------------------------------------------------------------

def main(argv=None): # Command-line entry point; argv can be passed in for testing
    ap = argparse.ArgumentParser(description="Lightweight, non-exploitative web security scanner") # Creates the argument parser
    ap.add_argument("target", help="URL of the test application, e.g. http://127.0.0.1:5001") # Required positional argument: the URL
    ap.add_argument("--max-pages", type=int, default=15) # Maximum number of pages to crawl
    ap.add_argument("--delay", type=float, default=0.2, help="seconds between requests") # Pause between requests
    ap.add_argument("--checks", nargs="+", choices=ALL_CHECKS, default=ALL_CHECKS) # Which checks to run (one or more)
    ap.add_argument("--test-post", action="store_true", help="also probe POST forms (sends form submissions)") # Flag: allow POST probing
    ap.add_argument("--json", metavar="FILE", help="write the full report to FILE") # Optional JSON report path
    ap.add_argument("--i-have-permission", action="store_true", # Flag required for non-local targets
                    help="required to scan anything that is not localhost / a private address") # Help text for that flag
    args = ap.parse_args(argv) # Parse the command line (or argv if provided)

    try: # Catch expected errors and print them cleanly
        target = normalize_target(args.target) # Validate and clean the URL
        if not is_local_target(target) and not args.i_have_permission: # Non-local targets need explicit confirmation
            raise ScopeError("Target is not local. Re-run with --i-have-permission only if you own it " # Refuse to scan and explain why
                             "or have written authorisation to test it.") # Second half of the message
        result = Scanner(target, args.max_pages, args.delay, checks=args.checks, # Create the scanner with the chosen options...
                         test_post=args.test_post).run() # ...and run the scan
    except (ScopeError, ValueError, ConnectionError) as exc: # Expected failure types
        print(f"error: {exc}", file=sys.stderr) # Print the error to stderr
        return 2 # Non-zero exit code signals failure

    print(f"\nTarget: {result['target']}") # Show the scanned URL
    print(f"Score:  {result['score']}/100  (grade {result['grade']})   " # Show score and grade...
          f"{result['pages_crawled']} pages, {result['requests_made']} requests, {result['duration_seconds']}s\n") # ...plus scan statistics
    for f in result["findings"]: # Print each finding
        print(f"[{f['severity']:<8}] {f['title']}\n           {f['url']}") # Severity (padded to 8 chars), title, and URL on the next line
    print("\nCounts:", ", ".join(f"{k}={v}" for k, v in result["counts"].items())) # Summary of findings per severity
    if args.json: # Only if --json was given
        with open(args.json, "w", encoding="utf-8") as fh: # Open the output file for writing
            json.dump(result, fh, indent=2) # Write the full report as pretty-printed JSON
        print(f"Report written to {args.json}") # Confirm where it was saved
    return 0 # Zero exit code means success


if __name__ == "__main__": # Runs only when the file is executed directly, not when imported
    sys.exit(main()) # Run main() and use its return value as the process exit code