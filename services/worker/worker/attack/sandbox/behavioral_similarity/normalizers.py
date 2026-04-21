import re

_USER_PATH_RE = re.compile(r'[a-z]:/users/[^/]+/', re.IGNORECASE)

_PATH_REPLACEMENTS = [
    (re.compile(r'%(?:systemroot|windir)%|[a-z]:/windows(?:/|$)', re.IGNORECASE), '<windir>/'),
    (re.compile(r'%programfiles(?:\(x86\))?%|[a-z]:/program files(?: \(x86\))?', re.IGNORECASE), '<programfiles>'),
    (re.compile(r'%appdata%', re.IGNORECASE), '<appdata>'),
    (re.compile(r'%(?:temp|tmp)%|[a-z]:/(?:windows/)?temp(?:/|$)', re.IGNORECASE), '<temp>/'),
    (re.compile(r'%userprofile%', re.IGNORECASE), '<userprofile>'),
]

_HIVE_MAP = [
    ('hklm/', 'hkey_local_machine/'),
    ('hkcu/', 'hkey_current_user/'),
    ('hkcr/', 'hkey_classes_root/'),
    ('hku/',  'hkey_users/'),
]


def normalize_path(s: str) -> str:
    if not s:
        return ''
    s = s.lower().replace('\\', '/').strip()
    s = _USER_PATH_RE.sub('<userprofile>/', s)
    for pattern, replacement in _PATH_REPLACEMENTS:
        s = pattern.sub(replacement, s)
    return s


def normalize_registry(s: str) -> str:
    s = normalize_path(s)
    for abbrev, full in _HIVE_MAP:
        if s.startswith(abbrev):
            return full + s[len(abbrev):]
    return s


def normalize_string(s: str) -> str:
    return str(s).lower().strip()


def normalize_url(s: str) -> str:
    return str(s).lower().strip()
