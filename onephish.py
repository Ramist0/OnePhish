#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
import sys

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse, quote

import requests


# ============================================================
# Configuration
# ============================================================

VT_API_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = 30


# ============================================================
# Helpers
# ============================================================

def sha256_bytes(data):
    """Calculate SHA-256."""
    return hashlib.sha256(data).hexdigest()


def get_header(msg, header_name):
    """Get an email header."""
    value = msg.get(header_name)

    if value:
        return str(value).strip()

    return None


# ============================================================
# Email headers
# ============================================================

def extract_originating_ip(msg):
    """Extract X-Originating-IP."""

    value = get_header(
        msg,
        "X-Originating-IP"
    )

    if not value:
        return None

    # IPv4
    match = re.search(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        value
    )

    if match:
        return match.group(0)

    # IPv6
    match = re.search(
        r"\b[0-9a-fA-F:]{2,}\b",
        value
    )

    if match:
        return match.group(0)

    return value


def extract_received_headers(msg):
    """Extract Received headers."""

    headers = msg.get_all(
        "Received",
        []
    )

    results = []

    for index, header in enumerate(
        headers,
        1
    ):

        raw = str(header).strip()

        match = re.search(
            r"\bfrom\s+(.+?)(?:\s+by\s+|\s+with\s+|\s+id\s+|\s*;)",
            raw,
            re.IGNORECASE
        )

        relay = (
            match.group(1).strip()
            if match
            else None
        )

        results.append({
            "hop": index,
            "relay": relay,
            "raw": raw
        })

    return results


def extract_authentication_results(msg):
    """Extract Authentication-Results headers."""

    headers = msg.get_all(
        "Authentication-Results",
        []
    )

    return [
        str(header).strip()
        for header in headers
    ]


def extract_spf(msg):
    """Extract SPF result."""

    headers = extract_authentication_results(
        msg
    )

    results = []

    for header in headers:

        matches = re.findall(
            r"\bspf\s*=\s*([a-zA-Z0-9_-]+)",
            header,
            re.IGNORECASE
        )

        for result in matches:

            results.append({
                "result": result.lower(),
                "header": header
            })

    return results


# ============================================================
# URL extraction
# ============================================================

def clean_url(url):
    """
    Clean common trailing punctuation from URLs.
    """

    return url.rstrip(
        ".,;:!?)]}>\"'"
    )


def extract_urls(msg):
    """
    Extract URLs from:
      - HTML href
      - HTML body
      - plain text body
    """

    urls = set()

    for part in msg.walk():

        if part.get_content_maintype() == "multipart":
            continue

        content_type = part.get_content_type()

        try:
            content = part.get_content()
        except Exception:
            continue

        if not content:
            continue

        # ----------------------------------------------------
        # HTML
        # ----------------------------------------------------

        if content_type == "text/html":

            hrefs = re.findall(
                r"""href\s*=\s*["']([^"']+)["']""",
                content,
                re.IGNORECASE
            )

            for url in hrefs:

                if url.lower().startswith(
                    (
                        "http://",
                        "https://"
                    )
                ):

                    urls.add(
                        clean_url(url)
                    )

            # URLs visibles dans le HTML
            raw_urls = re.findall(
                r"https?://[^\s<>'\"]+",
                content,
                re.IGNORECASE
            )

            for url in raw_urls:
                urls.add(
                    clean_url(url)
                )

        # ----------------------------------------------------
        # Plain text
        # ----------------------------------------------------

        elif content_type == "text/plain":

            raw_urls = re.findall(
                r"https?://[^\s<>'\"]+",
                content,
                re.IGNORECASE
            )

            for url in raw_urls:
                urls.add(
                    clean_url(url)
                )

    return sorted(urls)


def extract_domains(urls):
    """Extract domains from URLs."""

    domains = set()

    for url in urls:

        try:

            parsed = urlparse(url)

            if parsed.hostname:

                domains.add(
                    parsed.hostname.lower()
                )

        except Exception:
            pass

    return sorted(domains)


# ============================================================
# Attachments
# ============================================================

def extract_attachments(
    msg,
    output_dir
):
    """
    Extract attachments.

    IMPORTANT:
    Files are NEVER uploaded to VirusTotal.
    """

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    attachments = []

    for part in msg.walk():

        filename = part.get_filename()

        if not filename:
            continue

        disposition = part.get(
            "Content-Disposition",
            ""
        )

        if "attachment" not in disposition.lower():
            continue

        try:
            payload = part.get_payload(
                decode=True
            )
        except Exception:
            payload = None

        if payload is None:
            continue

        # Prevent path traversal
        safe_filename = Path(
            filename
        ).name

        output_path = (
            output_dir /
            safe_filename
        )

        # Avoid overwriting
        counter = 1

        while output_path.exists():

            output_path = (
                output_dir /
                f"{Path(safe_filename).stem}"
                f"_{counter}"
                f"{Path(safe_filename).suffix}"
            )

            counter += 1

        output_path.write_bytes(
            payload
        )

        attachments.append({

            "filename": safe_filename,

            "path": str(
                output_path
            ),

            "size": len(payload),

            "sha256": sha256_bytes(
                payload
            ),

            "content_type":
                part.get_content_type(),

            "content_disposition":
                disposition
        })

    return attachments


# ============================================================
# VirusTotal Client
# ============================================================

class VirusTotalClient:

    def __init__(
        self,
        api_key,
        timeout=DEFAULT_TIMEOUT
    ):

        if not api_key:
            raise ValueError(
                "VirusTotal API key is missing."
            )

        self.api_key = api_key
        self.timeout = timeout

        self.session = requests.Session()

        self.session.headers.update({
            "x-apikey": self.api_key
        })

    # ========================================================
    # Generic GET
    # ========================================================

    def _get(self, endpoint):

        response = self.session.get(
            f"{VT_API_BASE}{endpoint}",
            timeout=self.timeout
        )

        if response.status_code == 404:
            return None

        response.raise_for_status()

        return response.json()

    # ========================================================
    # FILE
    # ========================================================

    def get_file_report(
        self,
        sha256
    ):
        """
        Search a file by SHA-256.

        NO FILE UPLOAD.
        """

        return self._get(
            f"/files/{sha256}"
        )

    def analyze_attachment(
        self,
        attachment
    ):
        """
        Analyze attachment only by SHA-256.

        No upload is ever performed.
        """

        sha256 = attachment[
            "sha256"
        ]

        result = {

            "sha256": sha256,

            "status": None,

            "stats": None,

            "detections": [],

            "vt_url":
                "https://www.virustotal.com/gui/file/"
                + sha256,

            "error": None
        }

        try:

            report = self.get_file_report(
                sha256
            )

        except requests.RequestException as e:

            result["status"] = "ERROR"

            result["error"] = str(e)

            return result

        # ----------------------------------------------------
        # Unknown
        # ----------------------------------------------------

        if not report:

            result["status"] = (
                "NOT_FOUND"
            )

            return result

        # ----------------------------------------------------
        # Found
        # ----------------------------------------------------

        attributes = (
            report
            .get("data", {})
            .get("attributes", {})
        )

        result["status"] = "FOUND"

        result["stats"] = (
            attributes.get(
                "last_analysis_stats"
            )
        )

        result["detections"] = (
            self._extract_detections(
                attributes
            )
        )

        return result

    # ========================================================
    # URL
    # ========================================================

    @staticmethod
    def url_id(url):
        """
        VirusTotal URL object IDs are generated
        from the URL using URL-safe base64 without '='.
        """

        import base64

        encoded = base64.urlsafe_b64encode(
            url.encode()
        ).decode()

        return encoded.rstrip("=")

    def get_url_report(
        self,
        url
    ):
        """
        Search an exact URL in VirusTotal.
        """

        url_id = self.url_id(
            url
        )

        return self._get(
            f"/urls/{url_id}"
        )

    def analyze_url(
        self,
        url
    ):
        """
        Analyze an URL using existing
        VirusTotal data.

        No URL submission/upload.
        """

        result = {

            "url": url,

            "status": None,

            "stats": None,

            "detections": [],

            "vt_url":
                "https://www.virustotal.com/gui/url/"
                + self.url_id(url),

            "error": None
        }

        try:

            report = self.get_url_report(
                url
            )

        except requests.RequestException as e:

            result["status"] = "ERROR"

            result["error"] = str(e)

            return result

        if not report:

            result["status"] = (
                "NOT_FOUND"
            )

            return result

        attributes = (
            report
            .get("data", {})
            .get("attributes", {})
        )

        result["status"] = "FOUND"

        result["stats"] = (
            attributes.get(
                "last_analysis_stats"
            )
        )

        result["detections"] = (
            self._extract_detections(
                attributes
            )
        )

        # Informations supplémentaires
        result["final_url"] = (
            attributes.get(
                "last_final_url"
            )
        )

        result["title"] = (
            attributes.get(
                "title"
            )
        )

        return result

    # ========================================================
    # DOMAIN
    # ========================================================

    def get_domain_report(
        self,
        domain
    ):
        """Search a domain in VirusTotal."""

        return self._get(
            f"/domains/{quote(domain, safe='')}"
        )

    def analyze_domain(
        self,
        domain
    ):
        """Analyze domain reputation."""

        result = {

            "domain": domain,

            "status": None,

            "stats": None,

            "reputation": None,

            "categories": {},

            "registrar": None,

            "creation_date": None,

            "vt_url":
                "https://www.virustotal.com/gui/domain/"
                + domain,

            "error": None
        }

        try:

            report = self.get_domain_report(
                domain
            )

        except requests.RequestException as e:

            result["status"] = "ERROR"

            result["error"] = str(e)

            return result

        if not report:

            result["status"] = (
                "NOT_FOUND"
            )

            return result

        attributes = (
            report
            .get("data", {})
            .get("attributes", {})
        )

        result["status"] = "FOUND"

        result["reputation"] = (
            attributes.get(
                "reputation"
            )
        )

        result["categories"] = (
            attributes.get(
                "categories",
                {}
            )
        )

        result["registrar"] = (
            attributes.get(
                "registrar"
            )
        )

        result["creation_date"] = (
            attributes.get(
                "creation_date"
            )
        )

        result["stats"] = (
            attributes.get(
                "last_analysis_stats"
            )
        )

        return result

    # ========================================================
    # Detection extraction
    # ========================================================

    @staticmethod
    def _extract_detections(
        attributes
    ):

        results = attributes.get(
            "last_analysis_results",
            {}
        )

        detections = []

        for engine, data in results.items():

            category = data.get(
                "category"
            )

            if category in (
                "malicious",
                "suspicious"
            ):

                detections.append({

                    "engine": engine,

                    "category": category,

                    "result":
                        data.get("result"),

                    "method":
                        data.get("method")
                })

        return detections

# ============================================================
# Main
# ============================================================

def analyze_eml(
    eml_path,
    attachment_dir,
    vt_client=None
):

    eml_path = Path(
        eml_path
    )

    if not eml_path.exists():

        raise FileNotFoundError(
            f"File not found: {eml_path}"
        )

    # --------------------------------------------------------
    # Parse EML
    # --------------------------------------------------------

    with open(
        eml_path,
        "rb"
    ) as f:

        msg = BytesParser(
            policy=policy.default
        ).parse(f)

    # --------------------------------------------------------
    # Sender
    # --------------------------------------------------------

    from_header = get_header(
        msg,
        "From"
    )

    sender_name, sender_email = parseaddr(
        from_header or ""
    )

    reply_to = get_header(
        msg,
        "Reply-To"
    )

    # --------------------------------------------------------
    # Headers
    # --------------------------------------------------------

    originating_ip = (
        extract_originating_ip(msg)
    )

    received = (
        extract_received_headers(msg)
    )

    authentication_results = (
        extract_authentication_results(
            msg
        )
    )

    spf = extract_spf(
        msg
    )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    urls = extract_urls(
        msg
    )

    domains = extract_domains(
        urls
    )

    # --------------------------------------------------------
    # Attachments
    # --------------------------------------------------------

    attachments = extract_attachments(
        msg,
        Path(attachment_dir)
    )

    # --------------------------------------------------------
    # VirusTotal
    # --------------------------------------------------------

    vt_urls = []
    vt_domains = []

    if vt_client:

        # ----------------------------------------------------
        # Attachments — HASH ONLY
        # ----------------------------------------------------

        for attachment in attachments:

            attachment[
                "virustotal"
            ] = vt_client.analyze_attachment(
                attachment
            )

        # ----------------------------------------------------
        # URLs
        # ----------------------------------------------------

        for url in urls:

            vt_urls.append(
                vt_client.analyze_url(
                    url
                )
            )

        # ----------------------------------------------------
        # Domains
        # ----------------------------------------------------

        for domain in domains:

            vt_domains.append(
                vt_client.analyze_domain(
                    domain
                )
            )

    # --------------------------------------------------------
    # Report
    # --------------------------------------------------------

    return {

        "file": str(
            eml_path
        ),

        "email": {

            "subject":
                get_header(
                    msg,
                    "Subject"
                ),

            "date":
                get_header(
                    msg,
                    "Date"
                ),

            "from": {

                "raw":
                    from_header,

                "name":
                    sender_name,

                "email":
                    sender_email
            },

            "reply_to":
                reply_to,

            "originating_ip":
                originating_ip,

            "received":
                received,

            "authentication_results":
                authentication_results,

            "spf":
                spf
        },

        "urls":
            urls,

        "phishing_domains":
            domains,

        "virustotal": {

            "urls":
                vt_urls,

            "domains":
                vt_domains
        },

        "attachments":
            attachments
    }


# ============================================================
# Report display
# ============================================================

def print_stats(
    stats,
    indent="  "
):

    if not stats:
        return

    print(
        f"{indent}Malicious : "
        f"{stats.get('malicious', 0)}"
    )

    print(
        f"{indent}Suspicious: "
        f"{stats.get('suspicious', 0)}"
    )

    print(
        f"{indent}Harmless  : "
        f"{stats.get('harmless', 0)}"
    )

    print(
        f"{indent}Undetected: "
        f"{stats.get('undetected', 0)}"
    )


def get_verdict(stats):

    if not stats:
        return "UNKNOWN"

    if stats.get(
        "malicious",
        0
    ) > 0:

        return "MALICIOUS"

    if stats.get(
        "suspicious",
        0
    ) > 0:

        return "SUSPICIOUS"

    return "NO_MALICIOUS_DETECTION"


def print_report(
    report
):

    print()
    print("=" * 80)
    print("PHISHING EMAIL ANALYSIS")
    print("=" * 80)

    # ========================================================
    # EMAIL
    # ========================================================

    print()
    print("[ --- EMAIL --- ]")

    print(
        f"File       : "
        f"{report['file']}"
    )

    print(
        f"Subject    : "
        f"{report['email']['subject'] or 'N/A'}"
    )

    print(
        f"Date       : "
        f"{report['email']['date'] or 'N/A'}"
    )

    # ========================================================
    # SENDER
    # ========================================================

    print()
    print("[ --- SENDER --- ]")

    print(
        f"From       : "
        f"{report['email']['from']['raw'] or 'N/A'}"
    )

    print(
        f"Email      : "
        f"{report['email']['from']['email'] or 'N/A'}"
    )

    # ========================================================
    # ORIGINATING IP
    # ========================================================

    print()
    print("[ --- X-ORIGINATING-IP --- ]")

    print(
        f"Origin IP  : "
        f"{report['email']['originating_ip'] or 'N/A'}"
    )

    # ========================================================
    # REPLY TO
    # ========================================================

    print()
    print("[ --- REPLY-TO --- ]")

    print(
        f"Reply-To   : "
        f"{report['email']['reply_to'] or 'N/A'}"
    )

    # ========================================================
    # RECEIVED
    # ========================================================

    print()
    print("[ --- RECEIVED/RELAY --- ]")

    if report["email"]["received"]:

        for hop in report[
            "email"
        ]["received"]:

            print()
            print(
                f"Hop {hop['hop']}"
            )

            print(
                f"Relay      : "
                f"{hop['relay'] or 'N/A'}"
            )

            print(
                f"Raw        : "
                f"{hop['raw']}"
            )

    else:

        print(
            "No Received headers found."
        )

    # ========================================================
    # SPF
    # ========================================================

    print()
    print("[ --- SPF --- ]")

    if report["email"]["spf"]:

        for spf in report[
            "email"
        ]["spf"]:

            print(
                f"SPF        : "
                f"{spf['result']}"
            )

    else:

        print(
            "No SPF result found."
        )

    # ========================================================
    # URLS
    # ========================================================

    print()
    print("[ --- PHISHING URLS --- ]")

    if report["urls"]:

        for url in report[
            "urls"
        ]:

            print(
                f"URL        : "
                f"{url}"
            )

    else:

        print(
            "No HTTP/HTTPS URLs found."
        )

    # ========================================================
    # DOMAINS
    # ========================================================

    print()
    print("[ --- DOMAINS --- ]")

    if report[
        "phishing_domains"
    ]:

        for domain in report[
            "phishing_domains"
        ]:

            print(
                f"Domain     : "
                f"{domain}"
            )

    else:

        print(
            "No domains found."
        )

    # ========================================================
    # VIRUSTOTAL URL
    # ========================================================

    print()
    print("[ --- VIRUSTOTAL/URLs --- ]")

    vt_urls = report[
        "virustotal"
    ]["urls"]

    if not vt_urls:

        print(
            "VirusTotal URL analysis disabled."
        )

    for result in vt_urls:

        print()
        print(
            f"URL        : "
            f"{result['url']}"
        )

        print(
            f"Status     : "
            f"{result['status']}"
        )

        if result.get(
            "stats"
        ):

            print_stats(
                result["stats"]
            )

            print(
                f"  Verdict  : "
                f"{get_verdict(result['stats'])}"
            )

        if result.get(
            "final_url"
        ):

            print(
                f"Final URL  : "
                f"{result['final_url']}"
            )

        if result.get(
            "title"
        ):

            print(
                f"Title      : "
                f"{result['title']}"
            )

        print(
            f"VT Report  : "
            f"{result['vt_url']}"
        )

        if result.get(
            "detections"
        ):

            print(
                "Detections:"
            )

            for detection in result[
                "detections"
            ]:

                print(
                    f"  - "
                    f"{detection['engine']}: "
                    f"{detection['category']} "
                    f"({detection['result']})"
                )

        if result.get(
            "error"
        ):

            print(
                f"Error      : "
                f"{result['error']}"
            )

    # ========================================================
    # VIRUSTOTAL DOMAINS
    # ========================================================

    print()
    print("[ --- VIRUSTOTAL/DOMAINS --- ]")

    vt_domains = report[
        "virustotal"
    ]["domains"]

    if not vt_domains:

        print(
            "VirusTotal domain analysis disabled."
        )

    for result in vt_domains:

        print()
        print(
            f"Domain     : "
            f"{result['domain']}"
        )

        print(
            f"Status     : "
            f"{result['status']}"
        )

        if result.get(
            "reputation"
        ) is not None:

            print(
                f"Reputation : "
                f"{result['reputation']}"
            )

        if result.get(
            "stats"
        ):

            print_stats(
                result["stats"]
            )

            print(
                f"  Verdict  : "
                f"{get_verdict(result['stats'])}"
            )

        if result.get(
            "registrar"
        ):

            print(
                f"Registrar  : "
                f"{result['registrar']}"
            )

        if result.get(
            "creation_date"
        ):

            print(
                f"Created    : "
                f"{result['creation_date']}"
            )

        categories = result.get(
            "categories"
        )

        if categories:

            print(
                "Categories:"
            )

            for vendor, category in (
                categories.items()
            ):

                print(
                    f"  - "
                    f"{vendor}: "
                    f"{category}"
                )

        print(
            f"VT Report  : "
            f"{result['vt_url']}"
        )

        if result.get(
            "error"
        ):

            print(
                f"Error      : "
                f"{result['error']}"
            )

    # ========================================================
    # ATTACHMENTS
    # ========================================================

    print()
    print("[ --- ATTACHMENTS --- ]")

    if not report[
        "attachments"
    ]:

        print(
            "No attachments found."
        )

    for attachment in report[
        "attachments"
    ]:

        print()
        print(
            f"Filename   : "
            f"{attachment['filename']}"
        )

        print(
            f"Size       : "
            f"{attachment['size']} bytes"
        )

        print(
            f"Type       : "
            f"{attachment['content_type']}"
        )

        print(
            f"SHA-256    : "
            f"{attachment['sha256']}"
        )

        print(
            f"Extracted  : "
            f"{attachment['path']}"
        )

        vt = attachment.get(
            "virustotal"
        )

        if vt:

            print()
            print(
                "[ --- VirusTotal/HASH ONLY --- ]"
            )

            print(
                f"Status   : "
                f"{vt['status']}"
            )

            if vt.get(
                "stats"
            ):

                print_stats(
                    vt["stats"],
                    indent="  "
                )

                print(
                    f"Verdict  : "
                    f"{get_verdict(vt['stats'])}"
                )

            print(
                f"VT Report: "
                f"{vt['vt_url']}"
            )

            if vt.get(
                "status"
            ) == "NOT_FOUND":

                print(
                    "  Note     : "
                    "SHA-256 not found in VirusTotal. "
                    "File was NOT uploaded."
                )

            if vt.get(
                "error"
            ):

                print(
                    f"Error    : "
                    f"{vt['error']}"
                )

# ============================================================
# Main
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Analyze phishing EML files "
            "with VirusTotal lookups."
        )
    )

    parser.add_argument(
        "eml",
        help="Path to the .eml file"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="extracted_attachments",
        help=(
            "Directory where attachments "
            "are extracted."
        )
    )

    parser.add_argument(
        "--virustotal",
        action="store_true",
        help=(
            "Enable VirusTotal analysis."
        )
    )

    parser.add_argument(
        "--vt-api-key",
        help=(
            "VirusTotal API key. "
            "Prefer VT_API_KEY environment variable."
        )
    )

    parser.add_argument(
        "--json",
        dest="json_output",
        help=(
            "Save report to JSON."
        )
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # VirusTotal
    # --------------------------------------------------------

    api_key = (
        args.vt_api_key
        or os.environ.get(
            "VT_API_KEY"
        )
    )

    vt_client = None

    if args.virustotal:

        if not api_key:

            print(
                "[ERROR] VirusTotal API key not found."
            )

            print(
                "Set VT_API_KEY or use --vt-api-key."
            )

            sys.exit(1)

        vt_client = VirusTotalClient(
            api_key
        )

    # --------------------------------------------------------
    # Analyze
    # --------------------------------------------------------

    try:

        report = analyze_eml(
            args.eml,
            args.output,
            vt_client=vt_client
        )

    except Exception as e:

        print(
            f"[ERROR] {e}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Console
    # --------------------------------------------------------

    print_report(
        report
    )

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    if args.json_output:

        output_path = Path(
            args.json_output
        )

        output_path.write_text(
            json.dumps(
                report,
                indent=4,
                ensure_ascii=False
            ),
            encoding="utf-8"
        )

        print()
        print(
            f"[+] JSON report written to: "
            f"{output_path}"
        )


if __name__ == "__main__":
    main()
