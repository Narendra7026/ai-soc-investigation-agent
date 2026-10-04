import re


def extract_ipv4(text: str):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return list(set(re.findall(pattern, text)))


def extract_urls(text: str):
    pattern = r"https?://[^\s]+"
    return list(set(re.findall(pattern, text)))


def extract_md5(text: str):
    pattern = r"\b[a-fA-F0-9]{32}\b"
    return list(set(re.findall(pattern, text)))


def extract_sha1(text: str):
    pattern = r"\b[a-fA-F0-9]{40}\b"
    return list(set(re.findall(pattern, text)))


def extract_sha256(text: str):
    pattern = r"\b[a-fA-F0-9]{64}\b"
    return list(set(re.findall(pattern, text)))


def extract_emails(text: str):
    pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    return list(set(re.findall(pattern, text)))


def extract_iocs(text: str):

    return {
        "ipv4": extract_ipv4(text),
        "urls": extract_urls(text),
        "md5": extract_md5(text),
        "sha1": extract_sha1(text),
        "sha256": extract_sha256(text),
        "emails": extract_emails(text)
    }