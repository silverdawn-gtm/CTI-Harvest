"""Regex patterns for pattern-shaped entity types.

match_token(token) -> type or None   single-token indicators (URLs, IPs, domains, hashes,
                                     file names, CVE / MS bulletin IDs, ATT&CK technique IDs)
find_times(tokens) -> [(start, end)] dates, months and years, possibly over several tokens
"""
import re

DOT = r"(?:\.|\[\.\]|\(\.\)|\[dot\]|\(dot\))"
OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "me", "tv", "cc", "ws", "pw", "tk", "top", "xyz", "online",
    "site", "club", "live", "space", "tech", "website", "store", "icu", "cloud", "app", "dev", "link", "gov",
    "edu", "mil", "int", "ru", "su", "cn", "hk", "tw", "jp", "kr", "kp", "ir", "iq", "sy", "tr", "ua", "by",
    "kz", "uz", "in", "pk", "af", "vn", "th", "my", "sg", "id", "ph", "au", "nz", "uk", "de", "fr", "it", "es",
    "nl", "be", "ch", "at", "pl", "cz", "ro", "bg", "hu", "gr", "se", "no", "fi", "dk", "eu", "us", "ca", "mx",
    "br", "ar", "cl", "za", "ng", "eg", "sa", "ae", "qa", "il", "lb", "jo", "ge", "am", "az", "onion",
}
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk",
    "msi", "jar", "apk", "elf", "sh", "py", "doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "ppt",
    "pptx", "pptm", "rtf", "pdf", "zip", "rar", "7z", "iso", "img", "cab", "tmp", "dat", "bin", "chm", "dmg",
}
NOT_FILES = {"node.js", "vue.js", "react.js", "next.js", "angular.js", "d3.js", "three.js", "express.js"}

URL = re.compile(r"(?:h[tx]{2}ps?|ftp|fxp)(?::|\[:\])//\S+", re.I)
HASH = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
IPV4 = re.compile(rf"{OCTET}(?:{DOT}{OCTET}){{3}}(?::\d{{1,5}})?")
FILE = re.compile(r"[\w\-~$]+\.([A-Za-z0-9]{1,5})")
DOMAIN = re.compile(rf"((?:[A-Za-z0-9-]+{DOT})+)([a-z]{{2,7}})(?::\d{{1,5}})?(?:/\S*)?")
CVE = re.compile(r"CVE-\d{4}-\d{4,7}|MS\d{2}-\d{3}", re.I)
TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?")


def match_token(token):
    if URL.fullmatch(token):
        return "NetworkInfra"
    if HASH.fullmatch(token):
        return "FileHash"
    if IPV4.fullmatch(token):
        return "NetworkInfra"
    file = FILE.fullmatch(token)
    if file and file.group(1).lower() in FILE_EXTENSIONS and token.lower() not in NOT_FILES:
        return "FileHash"
    domain = DOMAIN.fullmatch(token)
    if domain and domain.group(2) in TLDS and not domain.group(1)[:-1].replace(".", "").isdigit():
        return "NetworkInfra"
    if CVE.fullmatch(token):
        return "Vulnerability"
    if TECHNIQUE.fullmatch(token):
        return "AttackTechnique"
    return None


MONTHS = {"january", "february", "march", "april", "may", "june", "july", "august", "september",
          "october", "november", "december"}
MONTH_ABBR = {"jan.", "feb.", "mar.", "apr.", "jun.", "jul.", "aug.", "sep.", "sept.", "oct.", "nov.", "dec."}
YEAR = re.compile(r"19[89]\d|20[0-4]\d")
DAY = re.compile(r"(?:[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19[89]\d|20[0-4]\d)[-–](?:19[89]\d|20[0-4]\d)")
NOT_BEFORE_YEAR = {"windows", "server", "office", "word", "excel", "outlook", "powerpoint", "exchange",
                   "studio", "visual", "sql", "port", "version", "v", "build"}


def _is_month(token):
    return token[:1].isupper() and (token.lower() in MONTHS or token.lower() in MONTH_ABBR)


def find_times(tokens):
    found, i, n = [], 0, len(tokens)
    while i < n:
        token = tokens[i]
        if _is_month(token):
            start = i - 1 if i > 0 and DAY.fullmatch(tokens[i - 1]) else i
            j = i + 1
            if j < n and DAY.fullmatch(tokens[j]):
                j += 1
            if j + 1 < n and tokens[j] == "," and YEAR.fullmatch(tokens[j + 1]):
                j += 2
            elif j < n and YEAR.fullmatch(tokens[j]):
                j += 1
            # "May" and "Jan." on their own are too ambiguous
            if j - start > 1 or token.lower() not in {"may"} | MONTH_ABBR:
                found.append((start, j))
                i = j
                continue
        elif DATE.fullmatch(token):
            found.append((i, i + 1))
        elif YEAR.fullmatch(token) and not (i > 0 and tokens[i - 1].lower() in NOT_BEFORE_YEAR):
            found.append((i, i + 1))
        i += 1
    return found
