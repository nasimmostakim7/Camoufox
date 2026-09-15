"""
Identify a WAF / bot-defense product and classify its response to a request.

An audit is only useful if it says *what* the defense did, not merely that a
request failed. "Blocked" and "challenged" call for completely different fixes:
a block means the request never reached the app, a challenge means the defense
was unsure and offered the client a way to prove itself. Reporting them as one
thing ("it failed") hides the finding.

Classification reads three independent sources -- status line, headers, and body
-- because vendors disagree about which one carries the tell. A vendor that
returns 200-with-a-challenge-page is common, so trusting the status code alone
would score a challenge as a successful visit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

__all__ = [
    "Verdict",
    "WafDetection",
    "classify_response",
    "detect_vendor",
    "VENDOR_SIGNATURES",
]


class Verdict:
    """What the defense decided about a request."""

    ALLOWED = "allowed"
    CHALLENGED = "challenged"
    RATE_LIMITED = "rate_limited"
    BLOCKED = "blocked"
    ERROR = "error"

    ALL = (ALLOWED, CHALLENGED, RATE_LIMITED, BLOCKED, ERROR)

    #: A refusal is a *successful* audit outcome: the defense worked.
    DETECTED = (CHALLENGED, RATE_LIMITED, BLOCKED)


# ---------------------------------------------------------------------------
# Vendor signatures
# ---------------------------------------------------------------------------
#
# Each entry: vendor name -> {header markers, body markers, cookie markers}.
# Markers are matched case-insensitively as substrings. Order matters only for
# reporting preference; a request can carry more than one vendor's tells.

VENDOR_SIGNATURES: Dict[str, Dict[str, List[str]]] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-mitigated", "server: cloudflare"],
        "body": ["just a moment", "cf-chl-", "attention required! | cloudflare",
                 "__cf_chl", "cf_chl_opt", "checking your browser"],
        "cookies": ["__cf_bm", "cf_clearance", "__cfduid"],
    },
    "Akamai": {
        "headers": ["akamai", "x-akamai", "akamai-grn", "x-check-cacheable"],
        "body": ["reference #18.", "reference&#32;&#35;18", "akamai bot manager",
                 "_abck", "ak_bmsc"],
        "cookies": ["_abck", "bm_sz", "ak_bmsc", "bm_sv"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amzn-errortype"],
        "body": ["awswaf", "captcha.awswaf.com", "challenge.js", "aws-waf-token"],
        "cookies": ["aws-waf-token"],
    },
    "Imperva": {
        "headers": ["x-iinfo", "x-cdn: imperva", "x-cdn: incapsula"],
        "body": ["incapsula", "_incap_ses", "visid_incap", "imperva"],
        "cookies": ["incap_ses_", "visid_incap_", "nlbi_"],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-wa-info", "bigipserver"],
        "body": ["the requested url was rejected", "your support id is"],
        "cookies": ["ts01", "bigipserver", "f5_cspm"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
        "body": ["sucuri website firewall", "access denied - sucuri"],
        "cookies": [],
    },
    "Fastly": {
        "headers": ["x-fastly", "fastly-io-info", "x-served-by"],
        "body": [],
        "cookies": [],
    },
    "DataDome": {
        "headers": ["x-datadome", "x-dd-b"],
        "body": ["datadome", "geo.captcha-delivery.com", "dd_cookie_test"],
        "cookies": ["datadome", "dd_cookie_test"],
    },
    "HUMAN / PerimeterX": {
        "headers": ["x-px", "x-px-block"],
        "body": ["px-captcha", "perimeterx", "pxhd", "access to this page has been denied"],
        "cookies": ["_px", "pxhd", "_pxhd"],
    },
    "Kasada": {
        "headers": ["x-kasada", "x-kpsdk-ct"],
        "body": ["kasada", "kpsdk", "ips.js"],
        "cookies": ["kpsdk-"],
    },
    "Vercel": {
        "headers": ["x-vercel-mitigated", "x-vercel-challenge-token"],
        "body": [],
        "cookies": ["_vercel_challenge"],
    },
    "Google reCAPTCHA": {
        "headers": [],
        "body": ["g-recaptcha", "recaptcha/api.js", "www.google.com/recaptcha"],
        "cookies": [],
    },
    "hCaptcha": {
        "headers": [],
        "body": ["hcaptcha.com", "h-captcha", "new-hcaptcha"],
        "cookies": [],
    },
    "Cloudflare Turnstile": {
        "headers": [],
        "body": ["challenges.cloudflare.com/turnstile", "cf-turnstile"],
        "cookies": [],
    },
}


@dataclass
class WafDetection:
    """What the audit learned from a single response."""

    verdict: str
    vendors: List[str] = field(default_factory=list)
    reason: str = ""
    evidence: List[str] = field(default_factory=list)
    status: Optional[int] = None

    @property
    def detected(self) -> bool:
        """True when the defense refused, throttled, or challenged us."""
        return self.verdict in Verdict.DETECTED

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "vendors": list(self.vendors),
            "reason": self.reason,
            "evidence": list(self.evidence),
            "status": self.status,
        }


# Status codes that unambiguously mean "refused" when returned to a browser
# navigation (as opposed to an API call, where some are normal).
_BLOCK_STATUSES = {
    401: "authentication demanded",
    403: "forbidden",
    406: "not acceptable",
    451: "unavailable for legal reasons",
}

_RATE_STATUSES = {
    429: "too many requests",
    420: "enhance your calm (rate limit)",
    503: "service unavailable (often a throttle or shield)",
    509: "bandwidth limit exceeded",
}

# Statuses that look successful but frequently carry a challenge page instead.
_SOFT_CHALLENGE_STATUSES = {200, 202, 203}

_CHALLENGE_BODY_MARKERS = [
    "just a moment",
    "checking your browser",
    "verifying you are human",
    "enable javascript and cookies to continue",
    "please wait while we verify",
    "one more step",
    "are you a robot",
    "unusual traffic",
    "verify you are a human",
    "dd_cookie_test",
    "px-captcha",
    "cf-challenge",
    "challenge-platform",
    "cf_chl_opt",
    "cf-chl-",
]

#: Bodies that are a refusal, not an invitation to prove yourself. Kept separate
#: from the challenge markers because conflating the two misreports a hard block
#: as a challenge -- and those call for opposite fixes.
_BLOCK_BODY_MARKERS = [
    "attention required",
    "access denied",
    "the requested url was rejected",
    "your support id is",
    "you have been blocked",
    "request blocked",
    "blocked by",
    "web application firewall",
    "sucuri website firewall",
    "access to this page has been denied",
]

_CHALLENGE_HEADERS = [
    "cf-mitigated",
    "x-vercel-challenge-token",
    "x-px-block",
    "x-datadome",
]


def _lower_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    if not headers:
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def detect_vendor(
    status: Optional[int],
    headers: Optional[Dict[str, str]],
    body: str,
) -> List[str]:
    """Return every vendor whose tells appear in the response, best-effort."""
    hdr = _lower_headers(headers)
    header_blob = " ".join(f"{k}: {v}" for k, v in hdr.items()).lower()
    # Cookies are set via Set-Cookie, so that header is part of the header blob.
    body_lower = (body or "").lower()[:200_000]

    found: List[str] = []
    for vendor, sig in VENDOR_SIGNATURES.items():
        for marker in sig.get("headers", []):
            if marker in header_blob:
                found.append(vendor)
                break
        else:
            for marker in sig.get("cookies", []):
                if marker in header_blob:
                    found.append(vendor)
                    break
            else:
                for marker in sig.get("body", []):
                    if marker in body_lower:
                        found.append(vendor)
                        break
    return found


def classify_response(
    status: Optional[int],
    headers: Optional[Dict[str, str]],
    body: str = "",
) -> WafDetection:
    """
    Decide what the defense did with this response.

    Order is deliberate. An explicit challenge tell outranks a bare status code,
    because vendors return challenges with 200 and blocks with 403 and mixing
    those up loses the whole point of the audit.
    """
    hdr = _lower_headers(headers)
    body_lower = (body or "").lower()
    vendors = detect_vendor(status, headers, body)
    evidence: List[str] = []

    if status is None:
        return WafDetection(
            verdict=Verdict.ERROR,
            vendors=vendors,
            reason="no response (connection failed, timed out, or was reset)",
            evidence=evidence,
        )

    # 1. An explicit challenge header is the strongest signal.
    for marker in _CHALLENGE_HEADERS:
        if marker in hdr:
            evidence.append(f"header {marker}: {hdr[marker]!r}")
            return WafDetection(
                verdict=Verdict.CHALLENGED,
                vendors=vendors,
                reason=f"challenge issued via {marker} header",
                evidence=evidence,
                status=status,
            )

    # 2. A body marker. Which kind of refusal it is depends on the status code,
    #    because "Attention Required!" is a block when served with 403 and can be
    #    a challenge when served with 200. The status decides; the body only says
    #    that a defense page was served rather than the site.
    block_body = next((m for m in _BLOCK_BODY_MARKERS if m in body_lower), None)
    challenge_body = next((m for m in _CHALLENGE_BODY_MARKERS if m in body_lower), None)

    if block_body:
        if status >= 400:
            evidence.append(f"body contains {block_body!r}")
            return WafDetection(
                verdict=Verdict.BLOCKED,
                vendors=vendors,
                reason=f"block page served (matched {block_body!r})",
                evidence=evidence,
                status=status,
            )
        # A block marker on a 2xx means the site was never reached, even though
        # the transport succeeded. Reporting that as "allowed" would score a
        # refusal as a bypass and inflate the bypass rate.
        evidence.append(f"body contains {block_body!r} despite status {status}")
        return WafDetection(
            verdict=Verdict.CHALLENGED,
            vendors=vendors,
            reason=f"refusal served with {status} (matched {block_body!r})",
            evidence=evidence,
            status=status,
        )

    if challenge_body:
        evidence.append(f"body contains {challenge_body!r}")
        return WafDetection(
            verdict=Verdict.CHALLENGED,
            vendors=vendors,
            reason=f"challenge page served (matched {challenge_body!r})",
            evidence=evidence,
            status=status,
        )

    # 3. Rate limiting.
    if status in _RATE_STATUSES:
        retry_after = hdr.get("retry-after")
        if retry_after:
            evidence.append(f"Retry-After: {retry_after}")
        return WafDetection(
            verdict=Verdict.RATE_LIMITED,
            vendors=vendors,
            reason=f"rate limited ({status} {_RATE_STATUSES[status]})",
            evidence=evidence,
            status=status,
        )

    # 4. Hard blocks by status code.
    if status in _BLOCK_STATUSES:
        if block_body:
            evidence.append(f"body contains {block_body!r}")
        return WafDetection(
            verdict=Verdict.BLOCKED,
            vendors=vendors,
            reason=f"blocked ({status} {_BLOCK_STATUSES[status]})",
            evidence=evidence,
            status=status,
        )

    # 5. Server errors: report as an error, not as a successful visit.
    if status >= 500:
        return WafDetection(
            verdict=Verdict.ERROR,
            vendors=vendors,
            reason=f"server error ({status})",
            evidence=evidence,
            status=status,
        )

    # 6. 4xx we did not classify: the request reached the app but was rejected.
    if 400 <= status < 500:
        return WafDetection(
            verdict=Verdict.BLOCKED,
            vendors=vendors,
            reason=f"request rejected ({status})",
            evidence=evidence,
            status=status,
        )

    # 7. Redirects to a challenge host are a challenge.
    location = hdr.get("location", "")
    if location and any(m in location.lower() for m in ("captcha", "challenge", "verify")):
        evidence.append(f"redirect to {location!r}")
        return WafDetection(
            verdict=Verdict.CHALLENGED,
            vendors=vendors,
            reason="redirected to a challenge endpoint",
            evidence=evidence,
            status=status,
        )

    # 8. Nothing matched: the defense let us through.
    return WafDetection(
        verdict=Verdict.ALLOWED,
        vendors=vendors,
        reason="request served",
        evidence=evidence,
        status=status,
    )