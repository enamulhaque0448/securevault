/**
 * Password strength scoring, two generator modes (random-character and
 * Diceware-style passphrase), and a live breach check against Have I Been
 * Pwned using k-Anonymity - only the first 5 characters of the SHA-1 hash
 * ever leave the browser, so HIBP never sees the actual password.
 */
const PasswordUtils = {

  COMMON_WEAK: ['password', '12345678', 'qwerty', 'letmein', 'admin123', 'password1'],

  // A short curated word list for passphrase mode. Real Diceware uses a
  // 7776-word list keyed by 5-digit dice rolls; this smaller list keeps the
  // file lightweight while demonstrating the same idea: several random
  // dictionary words beat a short string of random characters for a
  // human to actually remember, at equal or better entropy.
  WORDLIST: [
    'anchor','basalt','canyon','desert','ember','forge','glacier','harbor','island','jungle',
    'kettle','lantern','meadow','nectar','oracle','pebble','quartz','ribbon','summit','tundra',
    'umbrella','velvet','willow','xenon','yonder','zephyr','amber','birch','cedar','driftwood',
    'echo','falcon','granite','hollow','ivory','jasper','knoll','lagoon','marble','nimbus',
    'onyx','prairie','quiver','ridge','shale','thicket','undertow','violet','wharf','yarrow',
  ],

  score(password) {
    if (!password) return { score: 0, label: 'Empty', percent: 0 };

    let points = 0;
    const lower = password.toLowerCase();

    if (password.length >= 8) points += 1;
    if (password.length >= 12) points += 1;
    if (password.length >= 16) points += 1;
    if (/[a-z]/.test(password)) points += 1;
    if (/[A-Z]/.test(password)) points += 1;
    if (/[0-9]/.test(password)) points += 1;
    if (/[^A-Za-z0-9]/.test(password)) points += 1;

    if (this.COMMON_WEAK.some(weak => lower.includes(weak))) {
      points = Math.max(0, points - 3);
    }

    const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'];
    const clamped = Math.min(points, 5);
    return { score: clamped, label: labels[clamped], percent: (clamped / 5) * 100 };
  },

  generateRandom(length = 16) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+';
    const values = new Uint32Array(length);
    crypto.getRandomValues(values);
    return Array.from(values, v => charset[v % charset.length]).join('');
  },

  generatePassphrase(wordCount = 5) {
    const values = new Uint32Array(wordCount);
    crypto.getRandomValues(values);
    const words = Array.from(values, v => this.WORDLIST[v % this.WORDLIST.length]);
    const separatorIndex = new Uint32Array(1);
    crypto.getRandomValues(separatorIndex);
    words[separatorIndex[0] % words.length] += (100 + (separatorIndex[0] % 900));
    return words.join('-');
  },

  /** SHA-1 hex digest using the browser's native SubtleCrypto - needed for the HIBP k-Anonymity check. */
  async sha1Hex(text) {
    const data = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  },

  /**
   * k-Anonymity breach check: we send only the first 5 hex chars of the
   * SHA-1 hash to HIBP. It returns every suffix that shares that prefix
   * (thousands of them) - we match locally, so the full password hash
   * never leaves the browser, let alone the plaintext password.
   */
  async checkBreached(password) {
    const hash = await this.sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!res.ok) throw new Error('Breach check unavailable right now');

    const text = await res.text();
    const match = text.split('\n').find(line => line.startsWith(suffix));
    return match ? parseInt(match.split(':')[1].trim(), 10) : 0;
  },
};
