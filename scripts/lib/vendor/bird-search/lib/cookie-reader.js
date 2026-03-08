/**
 * Browser cookie extraction — replaces @steipete/sweet-cookie.
 *
 * Uses Python sqlite3 (stdlib) for database reads and Node.js crypto (built-in)
 * for decryption. Zero third-party dependencies.
 *
 * Supports: Chrome (Windows/macOS/Linux), Firefox (all), Safari (macOS).
 */
import { execSync } from 'child_process';
import { createDecipheriv, pbkdf2Sync } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SQLITE_HELPER = join(__dirname, 'cookie-sqlite.py');

/**
 * Decrypt Chrome master key using Windows DPAPI via PowerShell.
 * @param {string} encKeyB64 - Base64-encoded DPAPI-wrapped key (from Local State)
 * @returns {Buffer} Decrypted AES master key
 */
function dpapiDecryptKey(encKeyB64) {
    const raw = Buffer.from(encKeyB64, 'base64');
    // Strip 'DPAPI' prefix (5 bytes)
    const dpapiBlob = raw.slice(5);
    const blobB64 = dpapiBlob.toString('base64');

    // PowerShell DPAPI decryption — single-line to avoid quoting issues
    const ps = `Add-Type -AssemblyName System.Security; $d=[System.Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String('${blobB64}'),$null,'CurrentUser'); [Convert]::ToBase64String($d)`;
    const result = execSync(`powershell -NoProfile -Command "${ps}"`, {
        encoding: 'utf8',
        timeout: 10000,
        windowsHide: true,
    });
    return Buffer.from(result.trim(), 'base64');
}

/**
 * Derive Chrome decryption key on macOS using Keychain password + PBKDF2.
 * @returns {Buffer} 16-byte AES-128-CBC key
 */
function deriveChromeMacKey() {
    const password = execSync(
        'security find-generic-password -w -a "Chrome" -s "Chrome Safe Storage" 2>/dev/null',
        { encoding: 'utf8', timeout: 5000 }
    ).trim();
    return pbkdf2Sync(password, 'saltysalt', 1003, 16, 'sha1');
}

/**
 * Derive Chrome decryption key on Linux using PBKDF2 with default password.
 * @returns {Buffer} 16-byte AES-128-CBC key
 */
function deriveLinuxChromeKey() {
    // Linux Chrome uses 'peanuts' as default password (or tries keyring)
    // Try keyring first, fall back to default
    let password = 'peanuts';
    try {
        const keyringPass = execSync(
            'secret-tool lookup application chrome 2>/dev/null || echo peanuts',
            { encoding: 'utf8', timeout: 5000 }
        ).trim();
        if (keyringPass) password = keyringPass;
    } catch {
        // Fall back to default
    }
    return pbkdf2Sync(password, 'saltysalt', 1, 16, 'sha1');
}

/**
 * Decrypt a Chrome cookie value using AES-256-GCM (Windows, Chrome 80+).
 * @param {Buffer} encrypted - Raw encrypted cookie bytes
 * @param {Buffer} key - 32-byte AES key
 * @returns {string|null} Decrypted cookie value
 */
function decryptAes256Gcm(encrypted, key) {
    if (!encrypted || encrypted.length < 31) return null;
    const prefix = encrypted.slice(0, 3).toString('utf8');
    if (prefix !== 'v10' && prefix !== 'v20') {
        // Not AES-GCM encrypted, try as plaintext
        return encrypted.toString('utf8');
    }
    const nonce = encrypted.slice(3, 15);      // 12 bytes
    const ciphertext = encrypted.slice(15, -16); // between nonce and tag
    const tag = encrypted.slice(-16);            // last 16 bytes
    try {
        const decipher = createDecipheriv('aes-256-gcm', key, nonce);
        decipher.setAuthTag(tag);
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return decrypted.toString('utf8');
    } catch {
        return null;
    }
}

/**
 * Decrypt a Chrome cookie value using AES-128-CBC (macOS/Linux).
 * @param {Buffer} encrypted - Raw encrypted cookie bytes
 * @param {Buffer} key - 16-byte AES key
 * @returns {string|null} Decrypted cookie value
 */
function decryptAes128Cbc(encrypted, key) {
    if (!encrypted || encrypted.length < 4) return null;
    const prefix = encrypted.slice(0, 3).toString('utf8');
    if (prefix !== 'v10' && prefix !== 'v11') {
        return encrypted.toString('utf8');
    }
    const data = encrypted.slice(3); // Strip version prefix
    const iv = Buffer.alloc(16, 0x20); // 16 space characters
    try {
        const decipher = createDecipheriv('aes-128-cbc', key, iv);
        const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
        // Strip PKCS#7 padding and optional 32-byte hash prefix
        let result = decrypted.toString('utf8');
        // Chromium >= 24 prepends a 32-byte hex hash; detect and strip
        if (result.length > 32 && /^[0-9a-f]{32}/.test(result)) {
            result = result.slice(32);
        }
        return result;
    } catch {
        return null;
    }
}

/**
 * Call the Python SQLite helper to read cookies from a browser.
 * @param {string} browser - 'chrome', 'firefox', or 'safari'
 * @param {string} [profile] - Browser profile name
 * @returns {{ cookies: Array, encrypted_key: string|null, warnings: string[] }}
 */
function readCookiesViaPython(browser, profile) {
    const args = ['python3', SQLITE_HELPER, '--browser', browser];
    if (profile) {
        args.push('--profile', profile);
    }
    try {
        const output = execSync(args.join(' '), {
            encoding: 'utf8',
            timeout: 15000,
            windowsHide: true,
        });
        return JSON.parse(output.trim());
    } catch (err) {
        return {
            cookies: [],
            encrypted_key: null,
            warnings: [`Failed to read ${browser} cookies: ${err.message}`],
        };
    }
}

/**
 * Drop-in replacement for sweet-cookie's getCookies().
 *
 * @param {object} options
 * @param {string} options.url - Not used (we hardcode Twitter domains in Python)
 * @param {string[]} [options.origins] - Not used
 * @param {string[]} [options.names] - Not used (hardcoded to auth_token, ct0)
 * @param {string[]} [options.browsers] - Which browsers to try: ['chrome'], ['firefox'], ['safari']
 * @param {string} [options.mode] - Not used (always merge)
 * @param {string} [options.chromeProfile] - Chrome profile name
 * @param {string} [options.firefoxProfile] - Firefox profile name
 * @param {number} [options.timeoutMs] - Not used (Python helper has own timeout)
 * @returns {Promise<{cookies: Array<{name: string, value: string, domain: string}>, warnings: string[]}>}
 */
export async function getCookies(options = {}) {
    const browsers = options.browsers || ['chrome', 'firefox', 'safari'];
    const allCookies = [];
    const allWarnings = [];

    for (const browser of browsers) {
        const profile = browser === 'chrome' ? options.chromeProfile
            : browser === 'firefox' ? options.firefoxProfile
            : undefined;

        const result = readCookiesViaPython(browser, profile);
        allWarnings.push(...result.warnings);

        if (result.cookies.length === 0) continue;

        // Decrypt Chrome cookies if needed
        if (browser === 'chrome' && result.cookies.some(c => c.encrypted)) {
            let decryptionKey = null;

            if (process.platform === 'win32' && result.encrypted_key) {
                try {
                    decryptionKey = dpapiDecryptKey(result.encrypted_key);
                } catch (err) {
                    allWarnings.push(`DPAPI decryption failed: ${err.message}`);
                }
            } else if (process.platform === 'darwin') {
                try {
                    decryptionKey = deriveChromeMacKey();
                } catch (err) {
                    allWarnings.push(`Keychain access failed: ${err.message}`);
                }
            } else if (process.platform === 'linux') {
                try {
                    decryptionKey = deriveLinuxChromeKey();
                } catch (err) {
                    allWarnings.push(`Keyring access failed: ${err.message}`);
                }
            }

            for (const cookie of result.cookies) {
                if (cookie.encrypted && decryptionKey) {
                    const raw = Buffer.from(cookie.value, 'base64');
                    const decrypted = process.platform === 'win32'
                        ? decryptAes256Gcm(raw, decryptionKey)
                        : decryptAes128Cbc(raw, decryptionKey);
                    if (decrypted) {
                        cookie.value = decrypted;
                        cookie.encrypted = false;
                    } else {
                        allWarnings.push(`Failed to decrypt cookie: ${cookie.name}`);
                    }
                }
            }
        }

        // Only include successfully decrypted cookies
        for (const cookie of result.cookies) {
            if (!cookie.encrypted) {
                allCookies.push({
                    name: cookie.name,
                    value: cookie.value,
                    domain: cookie.domain,
                    path: cookie.path || '/',
                    secure: cookie.secure,
                    httpOnly: cookie.httpOnly,
                });
            }
        }
    }

    return { cookies: allCookies, warnings: allWarnings };
}
