"""
Phishing detection engine with explainable risk indicators.

The analyzer is intentionally self contained (no network calls) so that it can
run in constrained environments while still surfacing rich indicators that
mirror production-grade checks (headers, content, URLs, attachments).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from email.utils import parseaddr, parsedate_to_datetime
from html import unescape
from typing import Dict, List, Optional
from urllib.parse import urlparse

# Terms and patterns are kept lightweight for offline execution
URGENT_TERMS = [
    "urgent",
    "immediately",
    "asap",
    "act now",
    "important",
    "verify now",
    "attention",
]

CREDENTIAL_TERMS = [
    "password",
    "login",
    "credential",
    "ssn",
    "pin",
    "verify account",
    "update account",
    "reset",
]

FINANCIAL_TERMS = [
    "invoice",
    "payment",
    "wire",
    "bank",
    "transfer",
    "bitcoin",
    "crypto",
]

THREAT_TERMS = [
    "suspended",
    "locked",
    "closed",
    "deactivated",
    "penalty",
    "lawsuit",
]

SHORTENERS = [
    "bit.ly",
    "tinyurl",
    "t.co",
    "ow.ly",
    "goo.gl",
    "buff.ly",
    "is.gd",
]

SUSPICIOUS_TLDS = {"zip", "ru", "su", "tk", "cn", "click", "work", "monster"}
RISKY_ATTACHMENTS = {
    "exe",
    "js",
    "scr",
    "bat",
    "cmd",
    "vbs",
    "jar",
    "ps1",
    "zip",
    "rar",
    "7z",
    "docm",
    "xlsm",
}


@dataclass
class ParsedEmail:
    subject: str = ""
    from_address: str = ""
    reply_to: str = ""
    date: Optional[datetime] = None
    headers: Dict[str, str] = field(default_factory=dict)
    text_body: str = ""
    html_body: str = ""
    attachments: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)


@dataclass
class Indicator:
    name: str
    value: str
    score: float
    description: str
    category: str
    severity: str
    importance: float = 0.0


class EmailRiskAnalyzer:
    """Offline-friendly phishing analyzer with explainable outputs."""

    def analyze(self, raw_email: str, filename: Optional[str] = None) -> Dict:
        parsed = self._parse_email(raw_email)

        indicators: List[Indicator] = []
        indicators.extend(self._header_indicators(parsed))
        indicators.extend(self._body_indicators(parsed))
        indicators.extend(self._url_indicators(parsed))
        indicators.extend(self._attachment_indicators(parsed))
        indicators = [ind for ind in indicators if ind.score > 0]

        total_score = sum(ind.score for ind in indicators)
        risk_score = min(100.0, round(total_score, 2))
        label = "phishing" if risk_score >= 60 else "legit"

        # Normalize indicator importance after clamping the score
        denom = total_score or 1.0
        for ind in indicators:
            ind.importance = round((ind.score / denom) * 100, 2)

        sorted_inds = sorted(indicators, key=lambda x: x.score, reverse=True)
        display_features = self._display_features(sorted_inds, parsed)

        return {
            "label": label,
            "risk_score": risk_score,
            "risk_score_normalized": round(risk_score / 100, 4),
            "indicators": [ind.__dict__ for ind in sorted_inds],
            "meta": {
                "subject": parsed.subject,
                "from": parsed.from_address,
                "reply_to": parsed.reply_to,
                "date": parsed.date.isoformat() if parsed.date else None,
                "urls": parsed.urls,
                "attachments": parsed.attachments,
                "filename": filename,
            },
            "display_features": display_features,
        }

    def _parse_email(self, raw_email: str) -> ParsedEmail:
        """Parse EML/plain text content into structured parts."""
        parsed = ParsedEmail()
        if not raw_email:
            return parsed

        try:
            message = Parser(policy=policy.default).parsestr(raw_email)
        except Exception:
            message = None

        if message:
            parsed.subject = message.get("Subject", "") or ""
            parsed.from_address = parseaddr(message.get("From", ""))[1]
            parsed.reply_to = parseaddr(message.get("Reply-To", ""))[1]
            parsed.headers = {k.lower(): v for k, v in message.items()}
            parsed.date = self._parse_date_header(message.get("Date"))

            for part in message.walk():
                content_disposition = part.get_content_disposition()
                content_type = part.get_content_type()

                if content_disposition == "attachment":
                    filename = part.get_filename() or "attachment"
                    parsed.attachments.append(filename)
                    continue

                # Capture bodies
                if content_type == "text/plain" and not parsed.text_body:
                    try:
                        parsed.text_body = part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True) or b""
                        parsed.text_body = payload.decode(errors="ignore")
                elif content_type == "text/html" and not parsed.html_body:
                    try:
                        parsed.html_body = part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True) or b""
                        parsed.html_body = payload.decode(errors="ignore")
        else:
            # Fallback for plain text
            parsed.text_body = raw_email

        joined_text = " ".join([parsed.subject, parsed.text_body, self._strip_html(parsed.html_body)])
        parsed.urls = self._extract_urls(parsed.text_body + " " + parsed.html_body + " " + joined_text)
        return parsed

    @staticmethod
    def _parse_date_header(date_str: Optional[str]) -> Optional[datetime]:
        if not date_str:
            return None
        try:
            dt = parsedate_to_datetime(date_str)
            if dt and not dt.tzinfo:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    @staticmethod
    def _strip_html(html_text: str) -> str:
        if not html_text:
            return ""
        clean = re.sub(r"<[^>]+>", " ", html_text)
        clean = re.sub(r"\s+", " ", clean)
        return unescape(clean).strip()

    def _header_indicators(self, parsed: ParsedEmail) -> List[Indicator]:
        indicators: List[Indicator] = []

        from_domain = self._domain_from_email(parsed.from_address)
        reply_domain = self._domain_from_email(parsed.reply_to)

        # From/Reply-To mismatch
        if parsed.reply_to and from_domain and reply_domain and from_domain != reply_domain:
            indicators.append(
                self._indicator(
                    name="From/Reply-To mismatch",
                    value=f"{from_domain} -> {reply_domain}",
                    score=14,
                    description="Sender and reply-to domains differ, often used to redirect responses.",
                    category="header",
                    severity="high",
                )
            )

        # Suspicious sender domain
        if from_domain:
            tld = from_domain.split(".")[-1]
            if tld in SUSPICIOUS_TLDS:
                indicators.append(
                    self._indicator(
                        name="Low reputation TLD",
                        value=from_domain,
                        score=8,
                        description="Sender domain uses a high-risk or disposable TLD.",
                        category="header",
                        severity="medium",
                    )
                )
            if self._looks_idn(from_domain):
                indicators.append(
                    self._indicator(
                        name="IDN/homograph domain",
                        value=from_domain,
                        score=10,
                        description="Internationalized domain may attempt to visually spoof a trusted brand.",
                        category="header",
                        severity="high",
                    )
                )
            if self._has_odd_tokens(from_domain):
                indicators.append(
                    self._indicator(
                        name="Suspicious domain pattern",
                        value=from_domain,
                        score=6,
                        description="Domain contains excessive separators or numbers typical of throwaway domains.",
                        category="header",
                        severity="medium",
                    )
                )

        auth_results = parsed.headers.get("authentication-results", "")
        received_spf = parsed.headers.get("received-spf", "")
        auth_blob = " ".join([auth_results.lower(), received_spf.lower()])

        def auth_signal(label: str, token: str, score_fail: int, score_none: int) -> Optional[Indicator]:
            if token + "=fail" in auth_blob or token + "=softfail" in auth_blob:
                return self._indicator(
                    name=f"{label} failed",
                    value=auth_results or "missing authentication-results",
                    score=score_fail,
                    description=f"{label} validation failed in headers.",
                    category="header",
                    severity="high",
                )
            if token not in auth_blob:
                return self._indicator(
                    name=f"{label} missing",
                    value="No authentication result present",
                    score=score_none,
                    description=f"{label} result not present; cannot verify sender authenticity.",
                    category="header",
                    severity="medium",
                )
            if token + "=pass" in auth_blob:
                return self._indicator(
                    name=f"{label} pass",
                    value="pass",
                    score=0,
                    description=f"{label} succeeded.",
                    category="header",
                    severity="info",
                )
            return None

        for label, token, fail_score, none_score in [
            ("SPF", "spf", 12, 6),
            ("DKIM", "dkim", 10, 5),
            ("DMARC", "dmarc", 8, 4),
        ]:
            ind = auth_signal(label, token, fail_score, none_score)
            if ind:
                indicators.append(ind)

        # Date anomalies
        if not parsed.date:
            indicators.append(
                self._indicator(
                    name="Missing/invalid date",
                    value="Date header absent or unparseable",
                    score=6,
                    description="Missing or malformed Date header is common in crafted phishing emails.",
                    category="header",
                    severity="medium",
                )
            )
        else:
            now = datetime.now(timezone.utc)
            delta_days = abs((now - parsed.date).days)
            if delta_days > 90:
                indicators.append(
                    self._indicator(
                        name="Timestamp anomaly",
                        value=f"{delta_days} days offset",
                        score=5,
                        description="Email timestamp is far from current time, which can indicate spoofing.",
                        category="header",
                        severity="low",
                    )
                )

        return indicators

    def _body_indicators(self, parsed: ParsedEmail) -> List[Indicator]:
        indicators: List[Indicator] = []

        normalized_body = " ".join(
            [parsed.subject.lower(), parsed.text_body.lower(), self._strip_html(parsed.html_body).lower()]
        )

        def term_score(terms: List[str], weight: float, label: str, description: str, severity: str) -> Optional[Indicator]:
            matches = sum(normalized_body.count(term) for term in terms)
            if matches:
                return self._indicator(
                    name=label,
                    value=f"{matches} hit(s)",
                    score=min(weight * matches, weight * 3),
                    description=description,
                    category="body",
                    severity=severity,
                )
            return None

        urgency = term_score(
            URGENT_TERMS,
            weight=6,
            label="Urgency and pressure",
            description="Language pushing immediate action is a common phishing tactic.",
            severity="high",
        )
        if urgency:
            indicators.append(urgency)

        credential = term_score(
            CREDENTIAL_TERMS,
            weight=5,
            label="Credential harvest language",
            description="Requests for credentials or verification appear in the content.",
            severity="high",
        )
        if credential:
            indicators.append(credential)

        financial = term_score(
            FINANCIAL_TERMS,
            weight=4,
            label="Financial request language",
            description="Financial or payment-related terms present.",
            severity="medium",
        )
        if financial:
            indicators.append(financial)

        threats = term_score(
            THREAT_TERMS,
            weight=4,
            label="Threat-based language",
            description="Consequences or account lock threats appear in the message.",
            severity="high",
        )
        if threats:
            indicators.append(threats)

        exclamation_count = parsed.text_body.count("!") + parsed.html_body.count("!")
        uppercase_ratio = self._uppercase_ratio(parsed.text_body + parsed.subject)

        if exclamation_count > 3:
            indicators.append(
                self._indicator(
                    name="Excessive punctuation",
                    value=f"{exclamation_count} exclamation marks",
                    score=min(6, 1.5 * (exclamation_count - 3)),
                    description="Overuse of punctuation is often used to inject urgency.",
                    category="body",
                    severity="low",
                )
            )

        if uppercase_ratio > 0.25:
            indicators.append(
                self._indicator(
                    name="Shouting text",
                    value=f"{round(uppercase_ratio * 100, 1)}% uppercase",
                    score=min(8, uppercase_ratio * 20),
                    description="High uppercase ratio indicates attention-grabbing tactics.",
                    category="body",
                    severity="medium",
                )
            )

        # HTML structure checks
        form_hits = len(re.findall(r"<form", parsed.html_body, flags=re.I))
        if form_hits:
            indicators.append(
                self._indicator(
                    name="HTML form present",
                    value=f"{form_hits} form element(s)",
                    score=min(12, 6 * form_hits),
                    description="Forms embedded in emails can capture credentials.",
                    category="body",
                    severity="high",
                )
            )

        return indicators

    def _url_indicators(self, parsed: ParsedEmail) -> List[Indicator]:
        indicators: List[Indicator] = []
        if not parsed.urls and not parsed.html_body:
            return indicators

        url_hosts = [urlparse(u).hostname or "" for u in parsed.urls]
        shorteners = [u for u in parsed.urls if any(short in u for short in SHORTENERS)]

        if shorteners:
            indicators.append(
                self._indicator(
                    name="URL shortener detected",
                    value=f"{len(shorteners)} link(s)",
                    score=min(10, 5 * len(shorteners)),
                    description="Shortened URLs hide the true destination.",
                    category="url",
                    severity="medium",
                )
            )

        ip_links = [h for h in url_hosts if self._is_ip(h)]
        if ip_links:
            indicators.append(
                self._indicator(
                    name="Link to IP address",
                    value=f"{len(ip_links)} link(s)",
                    score=min(12, 6 * len(ip_links)),
                    description="Using raw IPs instead of domains is suspicious.",
                    category="url",
                    severity="high",
                )
            )

        # Anchor text mismatch (spoofed link labels)
        anchor_mismatches = self._anchor_mismatches(parsed.html_body)
        if anchor_mismatches:
            indicators.append(
                self._indicator(
                    name="Mismatched anchor text",
                    value=f"{len(anchor_mismatches)} instance(s)",
                    score=min(12, 6 * len(anchor_mismatches)),
                    description="Visible link text does not match the destination domain.",
                    category="url",
                    severity="high",
                )
            )

        # Links pointing away from sender domain
        sender_domain = self._domain_from_email(parsed.from_address)
        if sender_domain:
            cross_domain = [h for h in url_hosts if h and sender_domain not in h]
            if cross_domain and len(cross_domain) == len([h for h in url_hosts if h]):
                indicators.append(
                    self._indicator(
                        name="Links outside sender domain",
                        value=f"{len(cross_domain)} of {len(url_hosts)} links",
                        score=min(10, 3 * len(cross_domain)),
                        description="All links go to domains unrelated to the sender.",
                        category="url",
                        severity="medium",
                    )
                )

        idn_links = [h for h in url_hosts if self._looks_idn(h)]
        if idn_links:
            indicators.append(
                self._indicator(
                    name="IDN/homograph link",
                    value=f"{len(idn_links)} link(s)",
                    score=min(10, 5 * len(idn_links)),
                    description="Internationalized domains in links can spoof brand names.",
                    category="url",
                    severity="high",
                )
            )

        return indicators

    def _attachment_indicators(self, parsed: ParsedEmail) -> List[Indicator]:
        indicators: List[Indicator] = []
        if not parsed.attachments:
            return indicators

        risky = [name for name in parsed.attachments if name.split(".")[-1].lower() in RISKY_ATTACHMENTS]
        if risky:
            indicators.append(
                self._indicator(
                    name="Risky attachment type",
                    value=", ".join(risky),
                    score=min(18, 9 * len(risky)),
                    description="Attachments carry executable or macro-enabled payloads.",
                    category="attachment",
                    severity="high",
                )
            )

        if len(parsed.attachments) > len(risky):
            indicators.append(
                self._indicator(
                    name="Attachments present",
                    value=f"{len(parsed.attachments)} attachment(s)",
                    score=min(6, 2 * len(parsed.attachments)),
                    description="Unexpected attachments warrant caution.",
                    category="attachment",
                    severity="low",
                )
            )

        return indicators

    @staticmethod
    def _extract_urls(text: str) -> List[str]:
        pattern = re.compile(r"https?://[^\s\"'>)]+", flags=re.I)
        urls = pattern.findall(text or "")
        # Preserve order but deduplicate
        seen = set()
        unique_urls = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)
        return unique_urls

    @staticmethod
    def _anchor_mismatches(html_body: str) -> List[str]:
        if not html_body:
            return []
        pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', flags=re.I | re.S)
        mismatches = []
        for href, label in pattern.findall(html_body):
            href_host = urlparse(href).hostname or ""
            label_host = urlparse(label.strip()).hostname or ""
            label_text = re.sub(r"<[^>]+>", "", label)
            label_text = label_text.strip()
            if label_host and href_host and href_host != label_host:
                mismatches.append(f"{label_host} -> {href_host}")
            elif label_text and href_host and label_text not in href_host:
                mismatches.append(f"{label_text} -> {href_host}")
        return mismatches

    @staticmethod
    def _uppercase_ratio(text: str) -> float:
        if not text:
            return 0.0
        uppercase = sum(1 for c in text if c.isupper())
        return uppercase / max(len(text), 1)

    @staticmethod
    def _domain_from_email(address: str) -> str:
        if not address or "@" not in address:
            return ""
        return address.split("@")[-1].lower().strip()

    @staticmethod
    def _looks_idn(domain: str) -> bool:
        return bool(domain and (domain.startswith("xn--") or any(ord(ch) > 127 for ch in domain)))

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except Exception:
            return False

    @staticmethod
    def _has_odd_tokens(domain: str) -> bool:
        if not domain:
            return False
        tokens = re.split(r"[.-]", domain)
        long_numbers = any(token.isdigit() and len(token) > 3 for token in tokens)
        many_tokens = len(tokens) > 4
        return long_numbers or many_tokens

    def _indicator(
        self, name: str, value: str, score: float, description: str, category: str, severity: str
    ) -> Indicator:
        severity = severity if severity in {"info", "low", "medium", "high"} else "medium"
        return Indicator(
            name=name,
            value=value,
            score=round(score, 2),
            description=description,
            category=category,
            severity=severity,
        )

    def _display_features(self, indicators: List[Indicator], parsed: ParsedEmail) -> List[Dict]:
        """Create a concise feature list for UI consumption."""
        top = indicators[:8]
        features = [{"name": ind.name, "value": ind.value} for ind in top]

        # Always surface core metadata as part of the explainability payload
        if parsed.subject:
            features.append({"name": "Subject", "value": parsed.subject})
        if parsed.from_address:
            features.append({"name": "From", "value": parsed.from_address})
        if parsed.reply_to:
            features.append({"name": "Reply-To", "value": parsed.reply_to})
        if parsed.urls:
            features.append({"name": "URLs Detected", "value": len(parsed.urls)})

        return features

