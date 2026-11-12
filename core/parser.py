"""
parser.py - turn raw input into one EmailData object.   [Member 1]

  parse_pasted(...)  fields typed into the form
  parse_eml(bytes)   an uploaded .eml file, read with Python's email library

Everything after this step only sees EmailData.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from bs4 import BeautifulSoup

URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\"'()]+", re.IGNORECASE)


@dataclass
class Link:
    url: str            # real destination
    text: str = ""      # visible text of an HTML <a> link


@dataclass
class Attachment:
    filename: str
    content: bytes | None = None    # None when only the name was typed


@dataclass
class EmailData:
    subject: str = ""
    from_name: str = ""
    from_email: str = ""
    reply_to: str = ""
    return_path: str = ""
    auth_results: str = ""          # Authentication-Results header (SPF/DKIM/DMARC)
    received: list = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    raw: bytes | None = None        # original .eml bytes, kept for hashing


def html_to_text(html: str) -> str:
    return BeautifulSoup(html, "html.parser").get_text(" ", strip=True) if html else ""


def extract_links(text: str, html: str) -> list:
    """<a href> links (with their visible text) + plain-text URLs, without duplicates."""
    links, seen = [], set()
    if html:
        for a in BeautifulSoup(html, "html.parser").find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("http", "www")) and href not in seen:
                seen.add(href)
                links.append(Link(href, a.get_text(" ", strip=True)))
    for url in URL_REGEX.findall(text):
        url = url.rstrip(".,;:!?)")          # "visit x.com." -> drop the full stop
        if url not in seen:
            seen.add(url)
            links.append(Link(url))
    return links


def parse_pasted(subject="", from_name="", from_email="", reply_to="", body="",
                 attachment_names="", return_path="", auth_results="") -> EmailData:
    is_html = re.search(r"<\s*(html|a|p|div|br)\b", body, re.IGNORECASE)
    html = body if is_html else ""
    text = html_to_text(body) if is_html else body
    return EmailData(
        subject=subject.strip(), from_name=from_name.strip(), from_email=from_email.strip(" <>"),
        reply_to=parseaddr(reply_to)[1], return_path=return_path.strip(" <>"), auth_results=auth_results,
        body_text=text, body_html=html, links=extract_links("" if is_html else text, html),
        attachments=[Attachment(n.strip()) for n in re.split(r"[,;\n]", attachment_names) if n.strip()],
    )


def parse_eml(data: bytes) -> EmailData:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    text, html, attachments = "", "", []
    for part in msg.walk():                                  # every MIME part
        if part.is_multipart():
            continue
        if part.get_filename():
            attachments.append(Attachment(part.get_filename(), part.get_payload(decode=True) or b""))
        elif part.get_content_type() == "text/plain":
            text += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "replace")
        elif part.get_content_type() == "text/html":
            html += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "replace")

    from_name, from_email = parseaddr(str(msg.get("From", "")))
    return EmailData(
        subject=str(msg.get("Subject", "")), from_name=from_name, from_email=from_email,
        reply_to=parseaddr(str(msg.get("Reply-To", "")))[1],
        return_path=parseaddr(str(msg.get("Return-Path", "")))[1],
        auth_results=" ".join(str(h) for h in msg.get_all("Authentication-Results", [])),
        received=[str(h) for h in msg.get_all("Received", [])],
        body_text=text or html_to_text(html), body_html=html,
        links=extract_links(text, html), attachments=attachments, raw=data,
    )


def parse_file(path) -> EmailData:
    """Samples (.eml and .txt) use the same header + blank line + body format."""
    with open(path, "rb") as fh:
        return parse_eml(fh.read())
