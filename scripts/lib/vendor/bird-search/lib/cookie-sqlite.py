#!/usr/bin/env python3
"""
Read browser cookies from SQLite databases.

Returns JSON on stdout: {"cookies": [...], "encrypted_key": "...", "warnings": [...]}
Each cookie has: name, value (plaintext or base64-encoded encrypted), domain, encrypted (bool)

Usage:
    python3 cookie-sqlite.py --browser chrome [--profile Default]
    python3 cookie-sqlite.py --browser firefox [--profile default-release]

Requires only Python stdlib (sqlite3, json, struct, os, sys).
"""

import argparse
import base64
import json
import os
import platform
import shutil
import sqlite3
import struct
import sys
import tempfile
from pathlib import Path


TWITTER_DOMAINS = ['.x.com', 'x.com', '.twitter.com', 'twitter.com']
COOKIE_NAMES = ['auth_token', 'ct0']


def get_chrome_user_data_dir():
    system = platform.system()
    if system == 'Windows':
        return Path(os.environ.get('LOCALAPPDATA', '')) / 'Google' / 'Chrome' / 'User Data'
    elif system == 'Darwin':
        return Path.home() / 'Library' / 'Application Support' / 'Google' / 'Chrome'
    else:  # Linux
        return Path.home() / '.config' / 'google-chrome'


def get_firefox_profiles_dir():
    system = platform.system()
    if system == 'Windows':
        return Path(os.environ.get('APPDATA', '')) / 'Mozilla' / 'Firefox' / 'Profiles'
    elif system == 'Darwin':
        return Path.home() / 'Library' / 'Application Support' / 'Firefox' / 'Profiles'
    else:  # Linux
        return Path.home() / '.mozilla' / 'firefox'


def find_firefox_profile(profile_hint=None):
    """Find Firefox profile directory."""
    profiles_dir = get_firefox_profiles_dir()
    if not profiles_dir.exists():
        return None

    if profile_hint:
        # Exact match
        exact = profiles_dir / profile_hint
        if exact.exists():
            return exact
        # Suffix match (e.g., "default-release" matches "abc123.default-release")
        for p in profiles_dir.iterdir():
            if p.is_dir() and p.name.endswith(f'.{profile_hint}'):
                return p

    # Default: look for default-release, then default, then any profile
    for suffix in ['default-release', 'default']:
        for p in profiles_dir.iterdir():
            if p.is_dir() and p.name.endswith(f'.{suffix}'):
                return p

    # Fallback: first profile directory
    for p in profiles_dir.iterdir():
        if p.is_dir() and (p / 'cookies.sqlite').exists():
            return p

    return None


def copy_db_to_temp(db_path):
    """Copy SQLite DB (and WAL files) to temp dir to avoid lock issues."""
    tmp_dir = tempfile.mkdtemp(prefix='cookie-reader-')
    db_copy = Path(tmp_dir) / 'cookies.db'
    shutil.copy2(db_path, db_copy)
    for suffix in ['-wal', '-shm']:
        wal = Path(str(db_path) + suffix)
        if wal.exists():
            shutil.copy2(wal, Path(tmp_dir) / f'cookies.db{suffix}')
    return tmp_dir, db_copy


def read_chrome_cookies(profile='Default'):
    """Read Chrome cookies for Twitter domains. Returns encrypted values."""
    warnings = []
    cookies = []
    encrypted_key = None

    user_data = get_chrome_user_data_dir()
    if not user_data.exists():
        return {'cookies': [], 'encrypted_key': None, 'warnings': ['Chrome user data directory not found']}

    # Read encrypted master key from Local State
    local_state_path = user_data / 'Local State'
    if local_state_path.exists():
        try:
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            key_b64 = local_state.get('os_crypt', {}).get('encrypted_key', '')
            if key_b64:
                encrypted_key = key_b64  # base64-encoded, DPAPI-wrapped
        except Exception as e:
            warnings.append(f'Failed to read Local State: {e}')

    # Find cookie database
    cookie_db = user_data / profile / 'Network' / 'Cookies'
    if not cookie_db.exists():
        cookie_db = user_data / profile / 'Cookies'
    if not cookie_db.exists():
        warnings.append(f'Chrome cookie database not found for profile "{profile}"')
        return {'cookies': [], 'encrypted_key': encrypted_key, 'warnings': warnings}

    # Copy to temp and query
    tmp_dir = None
    try:
        tmp_dir, db_copy = copy_db_to_temp(cookie_db)
        conn = sqlite3.connect(str(db_copy))
        conn.row_factory = sqlite3.Row

        placeholders = ','.join('?' * len(TWITTER_DOMAINS))
        name_placeholders = ','.join('?' * len(COOKIE_NAMES))
        query = f"""
            SELECT name, encrypted_value, host_key, path, expires_utc, is_secure, is_httponly
            FROM cookies
            WHERE host_key IN ({placeholders})
            AND name IN ({name_placeholders})
        """
        rows = conn.execute(query, TWITTER_DOMAINS + COOKIE_NAMES).fetchall()
        conn.close()

        for row in rows:
            enc_value = row['encrypted_value']
            cookies.append({
                'name': row['name'],
                'value': base64.b64encode(bytes(enc_value)).decode() if enc_value else '',
                'domain': row['host_key'].lstrip('.'),
                'path': row['path'],
                'encrypted': True,
                'secure': bool(row['is_secure']),
                'httpOnly': bool(row['is_httponly']),
            })
    except Exception as e:
        warnings.append(f'Failed to read Chrome cookies: {e}')
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return {'cookies': cookies, 'encrypted_key': encrypted_key, 'warnings': warnings}


def read_firefox_cookies(profile_hint=None):
    """Read Firefox cookies for Twitter domains. Returns plaintext values."""
    warnings = []
    cookies = []

    profile_dir = find_firefox_profile(profile_hint)
    if not profile_dir:
        return {'cookies': [], 'encrypted_key': None, 'warnings': ['Firefox profile not found']}

    cookie_db = profile_dir / 'cookies.sqlite'
    if not cookie_db.exists():
        warnings.append(f'Firefox cookies.sqlite not found in {profile_dir}')
        return {'cookies': [], 'encrypted_key': None, 'warnings': warnings}

    tmp_dir = None
    try:
        tmp_dir, db_copy = copy_db_to_temp(cookie_db)
        conn = sqlite3.connect(str(db_copy))
        conn.row_factory = sqlite3.Row

        placeholders = ','.join('?' * len(TWITTER_DOMAINS))
        name_placeholders = ','.join('?' * len(COOKIE_NAMES))
        query = f"""
            SELECT name, value, host, path, expiry, isSecure, isHttpOnly
            FROM moz_cookies
            WHERE host IN ({placeholders})
            AND name IN ({name_placeholders})
        """
        rows = conn.execute(query, TWITTER_DOMAINS + COOKIE_NAMES).fetchall()
        conn.close()

        for row in rows:
            cookies.append({
                'name': row['name'],
                'value': row['value'],  # Firefox stores plaintext
                'domain': row['host'].lstrip('.'),
                'path': row['path'],
                'encrypted': False,
                'secure': bool(row['isSecure']),
                'httpOnly': bool(row['isHttpOnly']),
            })
    except Exception as e:
        warnings.append(f'Failed to read Firefox cookies: {e}')
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return {'cookies': cookies, 'encrypted_key': None, 'warnings': warnings}


def read_safari_cookies():
    """Read Safari cookies from Cookies.binarycookies (macOS only)."""
    if platform.system() != 'Darwin':
        return {'cookies': [], 'encrypted_key': None, 'warnings': ['Safari is macOS-only']}

    warnings = []
    cookies = []

    # Find cookie file
    cookie_paths = [
        Path.home() / 'Library' / 'Cookies' / 'Cookies.binarycookies',
        Path.home() / 'Library' / 'Containers' / 'com.apple.Safari' / 'Data' / 'Library' / 'Cookies' / 'Cookies.binarycookies',
    ]
    cookie_file = None
    for p in cookie_paths:
        if p.exists():
            cookie_file = p
            break

    if not cookie_file:
        return {'cookies': [], 'encrypted_key': None, 'warnings': ['Safari Cookies.binarycookies not found']}

    # Mac epoch: 2001-01-01 in Unix time
    MAC_EPOCH_DELTA = 978307200

    try:
        with open(cookie_file, 'rb') as f:
            magic = f.read(4)
            if magic != b'cook':
                warnings.append('Invalid Safari cookie file magic')
                return {'cookies': [], 'encrypted_key': None, 'warnings': warnings}

            num_pages = struct.unpack('>I', f.read(4))[0]
            page_sizes = [struct.unpack('>I', f.read(4))[0] for _ in range(num_pages)]

            for page_size in page_sizes:
                page_data = f.read(page_size)
                if len(page_data) < 8:
                    continue

                # Page header: 4 bytes magic (0x00000100), 4 bytes cookie count
                _page_magic = struct.unpack('<I', page_data[0:4])[0]
                num_cookies = struct.unpack('<I', page_data[4:8])[0]
                cookie_offsets = [struct.unpack('<I', page_data[8 + i*4:12 + i*4])[0] for i in range(num_cookies)]

                for offset in cookie_offsets:
                    try:
                        cookie = _parse_safari_cookie(page_data, offset, MAC_EPOCH_DELTA)
                        if cookie and cookie['name'] in COOKIE_NAMES:
                            domain = cookie.get('domain', '')
                            if any(domain.endswith(d.lstrip('.')) for d in TWITTER_DOMAINS):
                                cookies.append(cookie)
                    except Exception:
                        continue

    except Exception as e:
        warnings.append(f'Failed to read Safari cookies: {e}')

    return {'cookies': cookies, 'encrypted_key': None, 'warnings': warnings}


def _parse_safari_cookie(page_data, offset, mac_epoch_delta):
    """Parse a single cookie from Safari binary cookie page data."""
    if offset + 44 > len(page_data):
        return None

    size = struct.unpack('<I', page_data[offset:offset+4])[0]
    if offset + size > len(page_data):
        return None

    flags = struct.unpack('<I', page_data[offset+8:offset+12])[0]
    url_offset = struct.unpack('<I', page_data[offset+16:offset+20])[0]
    name_offset = struct.unpack('<I', page_data[offset+20:offset+24])[0]
    path_offset = struct.unpack('<I', page_data[offset+24:offset+28])[0]
    value_offset = struct.unpack('<I', page_data[offset+28:offset+32])[0]

    def read_str(off):
        if off == 0:
            return ''
        abs_off = offset + off
        end = page_data.index(b'\x00', abs_off)
        return page_data[abs_off:end].decode('utf-8', errors='replace')

    name = read_str(name_offset)
    value = read_str(value_offset)
    domain = read_str(url_offset)
    path = read_str(path_offset)

    return {
        'name': name,
        'value': value,  # Safari stores plaintext
        'domain': domain.lstrip('.'),
        'path': path,
        'encrypted': False,
        'secure': bool(flags & 1),
        'httpOnly': bool(flags & 4),
    }


def main():
    parser = argparse.ArgumentParser(description='Extract browser cookies for Twitter/X')
    parser.add_argument('--browser', required=True, choices=['chrome', 'firefox', 'safari'])
    parser.add_argument('--profile', default=None, help='Browser profile name')
    args = parser.parse_args()

    if args.browser == 'chrome':
        result = read_chrome_cookies(args.profile or 'Default')
    elif args.browser == 'firefox':
        result = read_firefox_cookies(args.profile)
    elif args.browser == 'safari':
        result = read_safari_cookies()
    else:
        result = {'cookies': [], 'encrypted_key': None, 'warnings': [f'Unknown browser: {args.browser}']}

    json.dump(result, sys.stdout)


if __name__ == '__main__':
    main()
