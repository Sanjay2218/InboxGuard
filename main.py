```python
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from email import policy
from email.parser import BytesParser

from urllib.parse import urlparse

import os
import re
import ipaddress
import requests


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="InboxGuard",
    version="5.0"
)


# ============================================================
# STATIC FILES
# This makes:
# /static/index.html
# /static/favicon.png
# available to the browser.
# ============================================================

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


APP_VERSION = "5.0"

MAX_FILE_SIZE = 5 * 1024 * 1024

PHISHTANK_APP_KEY = os.getenv(
    "PHISHTANK_APP_KEY",
    ""
)

URLHAUS_AUTH_KEY = os.getenv(
    "URLHAUS_AUTH_KEY",
    ""
)


# ============================================================
# HOME PAGE
# ============================================================

@app.get("/")
def home():

    return FileResponse(
        "static/index.html"
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health():

    return {
        "status": "ok",
        "service": "InboxGuard",
        "version": APP_VERSION
    }


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):

    if not text:
        return []

    pattern = r'https?://[^\s<>"\'\]\)]+'

    urls = re.findall(
        pattern,
        text
    )

    cleaned = []

    for url in urls:

        url = url.rstrip(
            ".,;:"
        )

        if url not in cleaned:

            cleaned.append(url)

    return cleaned


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url):

    reasons = []

    score = 0

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname


        if not hostname:

            return {
                "url": url,
                "score": 0,
                "reasons": [
                    "Invalid URL"
                ]
            }


        # HTTPS

        if parsed.scheme.lower() != "https":

            reasons.append(
                "URL does not use HTTPS"
            )

            score += 8


        # Direct IP address

        try:

            ipaddress.ip_address(
                hostname
            )

            reasons.append(
                "URL uses a direct IP address"
            )

            score += 15

        except ValueError:

            pass


        # @ symbol

        if "@" in parsed.netloc:

            reasons.append(
                "URL contains @ in the authority section"
            )

            score += 15


        # Suspicious words

        suspicious_words = [

            "login",
            "verify",
            "verification",
            "secure",
            "account",
            "password",
            "update",
            "confirm",
            "bank",
            "wallet",
            "signin",
            "authenticate"

        ]


        lower_url = url.lower()


        matches = [

            word

            for word in suspicious_words

            if word in lower_url

        ]


        if matches:

            reasons.append(
                "Contains account/security-related terms: "
                + ", ".join(matches[:5])
            )

            score += min(
                12,
                len(matches) * 3
            )


        # Long URL

        if len(url) > 180:

            reasons.append(
                "Unusually long URL"
            )

            score += 8


        # Deep subdomain

        if hostname.count(".") >= 4:

            reasons.append(
                "Unusually deep subdomain structure"
            )

            score += 8


        # Unicode domain

        try:

            hostname.encode(
                "ascii"
            )

        except UnicodeEncodeError:

            reasons.append(
                "Domain contains non-ASCII characters"
            )

            score += 12


        return {

            "url": url,

            "score": min(
                score,
                40
            ),

            "reasons": reasons

        }


    except Exception:

        return {

            "url": url,

            "score": 0,

            "reasons": [
                "Unable to analyze URL"
            ]

        }


# ============================================================
# HEADER ANALYSIS
# ============================================================

def analyze_headers(message):

    reasons = []

    score = 0


    sender = str(
        message.get(
            "From",
            ""
        )
    )


    reply_to = str(
        message.get(
            "Reply-To",
            ""
        )
    )


    subject = str(
        message.get(
            "Subject",
            ""
        )
    )


    # --------------------------------------------------------
    # FROM / REPLY-TO
    # --------------------------------------------------------

    if sender and reply_to:

        sender_domain = re.search(
            r'@([A-Za-z0-9.-]+)',
            sender
        )


        reply_domain = re.search(
            r'@([A-Za-z0-9.-]+)',
            reply_to
        )


        if (
            sender_domain
            and
            reply_domain
        ):

            if (
                sender_domain.group(1).lower()
                !=
                reply_domain.group(1).lower()
            ):

                reasons.append(
                    "From and Reply-To domains do not match"
                )

                score += 20


    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    auth_headers = []


    for key in [

        "Authentication-Results",
        "Received-SPF",
        "DKIM-Signature"

    ]:

        values = message.get_all(
            key,
            []
        )


        for value in values:

            auth_headers.append(
                str(value)
            )


    auth_text = " ".join(
        auth_headers
    ).lower()


    if "dmarc=fail" in auth_text:

        reasons.append(
            "DMARC authentication failed"
        )

        score += 20


    if "spf=fail" in auth_text:

        reasons.append(
            "SPF authentication failed"
        )

        score += 15


    if "dkim=fail" in auth_text:

        reasons.append(
            "DKIM authentication failed"
        )

        score += 15


    # --------------------------------------------------------
    # URGENCY
    # --------------------------------------------------------

    urgent_words = [

        "urgent",
        "immediately",
        "action required",
        "account suspended",
        "verify your account",
        "payment failed"

    ]


    subject_lower = subject.lower()


    found_urgent = [

        word

        for word in urgent_words

        if word in subject_lower

    ]


    if found_urgent:

        reasons.append(
            "Subject contains urgency/account-pressure language"
        )

        score += min(
            10,
            len(found_urgent) * 3
        )


    return {

        "score": min(
            score,
            40
        ),

        "reasons": reasons

    }


# ============================================================
# ATTACHMENT ANALYSIS
# ============================================================

def analyze_attachments(message):

    reasons = []

    score = 0

    attachments = []


    dangerous_extensions = {

        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".js",
        ".vbs",
        ".vbe",
        ".ps1",
        ".msi",
        ".jar",
        ".hta"

    }


    for part in message.walk():

        if (
            part.get_content_disposition()
            !=
            "attachment"
        ):

            continue


        filename = part.get_filename()


        if not filename:

            continue


        attachments.append(
            filename
        )


        lower_name = filename.lower()


        for extension in dangerous_extensions:

            if lower_name.endswith(
                extension
            ):

                reasons.append(
                    f"Potentially dangerous attachment: {filename}"
                )

                score += 25

                break


    return {

        "score": min(
            score,
            40
        ),

        "reasons": reasons,

        "attachments": attachments

    }


# ============================================================
# PHISHTANK
# ============================================================

def check_phishtank(url):

    if not PHISHTANK_APP_KEY:

        return {

            "status": "not_configured",

            "match": False

        }


    try:

        response = requests.post(

            "https://checkurl.phishtank.com/checkurl/",

            data={

                "url": url,

                "format": "json",

                "app_key":
                    PHISHTANK_APP_KEY

            },

            timeout=6

        )


        if response.status_code != 200:

            return {

                "status": "unavailable",

                "match": False

            }


        data = response.json()


        results = data.get(
            "results",
            {}
        )


        return {

            "status": "checked",

            "match": bool(
                results.get(
                    "in_database"
                )
            ),

            "verified": bool(
                results.get(
                    "verified"
                )
            ),

            "phish_id":
                results.get(
                    "phish_id"
                )

        }


    except Exception:

        return {

            "status": "unavailable",

            "match": False

        }


# ============================================================
# URLHAUS
# ============================================================

def check_urlhaus(url):

    if not URLHAUS_AUTH_KEY:

        return {

            "status": "not_configured",

            "match": False

        }


    try:

        response = requests.post(

            "https://urlhaus-api.abuse.ch/v1/url/",

            data={
                "url": url
            },

            headers={

                "Auth-Key":
                    URLHAUS_AUTH_KEY

            },

            timeout=6

        )


        if response.status_code != 200:

            return {

                "status": "unavailable",

                "match": False

            }


        data = response.json()


        return {

            "status": "checked",

            "match":
                data.get(
                    "query_status"
                ) == "ok",

            "threat":
                data.get(
                    "threat"
                ),

            "url_status":
                data.get(
                    "url_status"
                )

        }


    except Exception:

        return {

            "status": "unavailable",

            "match": False

        }


# ============================================================
# MAIN ANALYZER
# ============================================================

@app.post("/api/analyze")
async def analyze_email(
    file: UploadFile = File(...)
):

    # --------------------------------------------------------
    # Validate file
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No file selected"
        )


    if not file.filename.lower().endswith(
        ".eml"
    ):

        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported"
        )


    content = await file.read()


    if len(content) > MAX_FILE_SIZE:

        raise HTTPException(
            status_code=413,
            detail="File is too large. Maximum size is 5 MB."
        )


    # --------------------------------------------------------
    # Parse email
    # --------------------------------------------------------

    try:

        message = BytesParser(
            policy=policy.default
        ).parsebytes(
            content
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Unable to parse this email file"
        )


    sender = str(
        message.get(
            "From",
            ""
        )
    )


    reply_to = str(
        message.get(
            "Reply-To",
            ""
        )
    )


    recipient = str(
        message.get(
            "To",
            ""
        )
    )


    subject = str(
        message.get(
            "Subject",
            ""
        )
    )


    # --------------------------------------------------------
    # Extract body
    # --------------------------------------------------------

    body_parts = []


    if message.is_multipart():

        for part in message.walk():

            if (
                part.get_content_type()
                ==
                "text/plain"
            ):

                try:

                    body_parts.append(
                        part.get_content()
                    )

                except Exception:

                    pass

    else:

        try:

            body_parts.append(
                message.get_content()
            )

        except Exception:

            pass


    body = "\n".join(
        body_parts
    )


    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    urls = extract_urls(
        body
    )


    url_results = [

        analyze_url(url)

        for url in urls

    ]


    url_score = sum(

        result["score"]

        for result in url_results

    )


    url_score = min(
        url_score,
        40
    )


    # --------------------------------------------------------
    # Headers
    # --------------------------------------------------------

    header_result = analyze_headers(
        message
    )


    header_score = header_result[
        "score"
    ]


    # --------------------------------------------------------
    # Attachments
    # --------------------------------------------------------

    attachment_result = (
        analyze_attachments(
            message
        )
    )


    attachment_score = (
        attachment_result[
            "score"
        ]
    )


    # --------------------------------------------------------
    # Threat intelligence
    # --------------------------------------------------------

    threat_intelligence = []

    threat_score = 0


    for url in urls:

        phishtank = check_phishtank(
            url
        )

        urlhaus = check_urlhaus(
            url
        )


        if phishtank.get(
            "match"
        ):

            threat_score += 40


        if urlhaus.get(
            "match"
        ):

            threat_score += 40


        threat_intelligence.append({

            "url": url,

            "phishtank":
                phishtank,

            "urlhaus":
                urlhaus

        })


    threat_score = min(
        threat_score,
        60
    )


    # --------------------------------------------------------
    # FINAL RISK SCORE
    # --------------------------------------------------------

    total_score = min(

        100,

        url_score
        +
        header_score
        +
        attachment_score
        +
        threat_score

    )


    # --------------------------------------------------------
    # VERDICT
    # --------------------------------------------------------

    if total_score >= 70:

        verdict = "HIGH RISK"

    elif total_score >= 40:

        verdict = "SUSPICIOUS"

    else:

        verdict = "LOW RISK"


    # --------------------------------------------------------
    # REASONS
    # --------------------------------------------------------

    reasons = []


    for result in url_results:

        reasons.extend(
            result["reasons"]
        )


    reasons.extend(
        header_result["reasons"]
    )


    reasons.extend(
        attachment_result["reasons"]
    )


    for item in threat_intelligence:

        if item["phishtank"].get(
            "match"
        ):

            reasons.append(
                "URL matched a PhishTank phishing record"
            )


        if item["urlhaus"].get(
            "match"
        ):

            reasons.append(
                "URL matched a URLhaus malicious URL record"
            )


    # ========================================================
    # FINAL RESPONSE
    #
    # IMPORTANT:
    # "score" is included because index.html uses data.score
    # ========================================================

    return {

        "success": True,

        "score": total_score,

        "risk_score": total_score,

        "verdict": verdict,


        "email": {

            "filename":
                file.filename,

            "subject":
                subject,

            "from":
                sender,

            "to":
                recipient,

            "reply_to":
                reply_to

        },


        "urls":
            url_results,


        "attachments":
            attachment_result[
                "attachments"
            ],


        "threat_intelligence":
            threat_intelligence,


        "reasons":
            reasons,


        "score_breakdown": {

            "url_score":
                url_score,

            "header_score":
                header_score,

            "attachment_score":
                attachment_score,

            "threat_intelligence_score":
                threat_score

        },


        "analysis_method":
            "Evidence-based heuristic analysis with optional external threat intelligence.",


        "limitations":
            "The score is an evidence-based risk score, not a calibrated probability. A LOW RISK result does not guarantee that an email is safe. Newly created malicious infrastructure may not yet appear in threat intelligence databases."

    }
```
