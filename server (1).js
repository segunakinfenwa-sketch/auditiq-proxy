const express = require('express');
const cors = require('cors');
const https = require('https');
const http = require('http');
const dns = require('dns');
const net = require('net');
const zlib = require('zlib');

const app = express();
const PORT = process.env.PORT || 3000;
const VERSION = '3.0.0';

app.use(cors({ origin: '*', methods: ['POST', 'GET'], allowedHeaders: ['Content-Type'] }));
app.use(express.json({ limit: '200kb' }));

// Clean API key — strip ALL whitespace and non-printable characters
function getCleanKey() {
  const raw = process.env.ANTHROPIC_API_KEY || '';
  return raw.replace(/[^\x20-\x7E]/g, '').trim();
}

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'AuditIQ API Proxy', version: VERSION });
});

/* ═══════════════════════════════════════════════════════════════════════
   WEBSITE SCANNER
   Visits the real website and records what is actually there.
   ═══════════════════════════════════════════════════════════════════════ */

// Test-only switch. Never set this on Railway.
const ALLOW_PRIVATE = process.env.SCAN_ALLOW_PRIVATE === '1';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
const MAX_BYTES = 3 * 1024 * 1024;
const REQ_TIMEOUT = 12000;

// Block internal/private addresses so the scanner cannot be pointed at Railway's own network
function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
      p[0] >= 224;
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l.startsWith('::ffff:')) return isPrivateIP(l.slice(7));
    return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80');
  }
  return true;
}

function safeLookup(hostname, options, callback) {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);
    const list = Array.isArray(address) ? address.map(a => a.address) : [address];
    if (!ALLOW_PRIVATE && list.some(isPrivateIP)) {
      return callback(new Error('Blocked: address is private or internal'));
    }
    callback(null, address, family);
  });
}

// Fetch one URL, following redirects and collecting cookies set along the way
function fetchPage(startUrl, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    const cookies = [];
    const go = (urlStr, hops) => {
      let u;
      try { u = new URL(urlStr); } catch { return reject(new Error('Invalid URL')); }
      if (!['http:', 'https:'].includes(u.protocol)) return reject(new Error('Only http and https are supported'));
      // Raw IP addresses skip DNS lookup, so check them directly
      const host = u.hostname.replace(/^\[|\]$/g, '');
      if (net.isIP(host) && !ALLOW_PRIVATE && isPrivateIP(host)) return reject(new Error('Blocked: address is private or internal'));
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.request(u, {
        method: 'GET',
        lookup: safeLookup,
        headers: {
          'User-Agent': UA,
          'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-GB,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate, br'
        }
      }, (res) => {
        const sc = res.headers['set-cookie'];
        if (sc) cookies.push(...sc);
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          res.resume();
          if (hops >= maxRedirects) return reject(new Error('Too many redirects'));
          return go(new URL(res.headers.location, urlStr).toString(), hops + 1);
        }
        let stream = res;
        const enc = (res.headers['content-encoding'] || '').toLowerCase();
        if (enc === 'gzip') stream = res.pipe(zlib.createGunzip());
        else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
        else if (enc === 'br') stream = res.pipe(zlib.createBrotliDecompress());
        const chunks = []; let size = 0;
        stream.on('data', c => {
          size += c.length;
          if (size > MAX_BYTES) { req.destroy(); return; }
          chunks.push(c);
        });
        stream.on('end', () => resolve({
          status: res.statusCode, finalUrl: urlStr, cookies,
          contentType: res.headers['content-type'] || '',
          body: Buffer.concat(chunks).toString('utf8')
        }));
        stream.on('error', reject);
      });
      req.setTimeout(REQ_TIMEOUT, () => req.destroy(new Error('Timed out')));
      req.on('error', reject);
      req.end();
    };
    go(startUrl, 0);
  });
}

// Strip anything that could be interpreted as HTML when shown in the report
const clean = (s, max = 200) => String(s == null ? '' : s).replace(/[<>"'`]/g, '').replace(/\s+/g, ' ').trim().slice(0, max);

function htmlToText(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&#39;|&rsquo;/g, "'")
    .replace(/\s+/g, ' ');
}

// Known tracking and third-party services
const TRACKERS = [
  { name: 'Google Analytics', category: 'Analytics', re: /google-analytics\.com|googletagmanager\.com\/gtag\/js|gtag\(\s*['"]config['"]\s*,\s*['"](G|UA)-/i },
  { name: 'Google Tag Manager', category: 'Tag manager', re: /googletagmanager\.com\/gtm\.js|['"]GTM-[A-Z0-9]+['"]/i },
  { name: 'Google Ads / DoubleClick', category: 'Marketing', re: /googleadservices\.com|doubleclick\.net|googlesyndication\.com|gtag\(\s*['"]config['"]\s*,\s*['"]AW-/i },
  { name: 'Meta (Facebook) Pixel', category: 'Marketing', re: /connect\.facebook\.net|fbq\(\s*['"]init/i },
  { name: 'LinkedIn Insight Tag', category: 'Marketing', re: /snap\.licdn\.com|_linkedin_partner_id/i },
  { name: 'TikTok Pixel', category: 'Marketing', re: /analytics\.tiktok\.com/i },
  { name: 'X (Twitter) Pixel', category: 'Marketing', re: /static\.ads-twitter\.com|analytics\.twitter\.com/i },
  { name: 'Microsoft Advertising (Bing)', category: 'Marketing', re: /bat\.bing\.com/i },
  { name: 'Pinterest Tag', category: 'Marketing', re: /s\.pinimg\.com\/ct/i },
  { name: 'Hotjar', category: 'Analytics', re: /static\.hotjar\.com|hotjar\.com\/c\/hotjar/i },
  { name: 'Microsoft Clarity', category: 'Analytics', re: /clarity\.ms/i },
  { name: 'Matomo', category: 'Analytics', re: /matomo\.js|piwik\.js|matomo\.cloud/i },
  { name: 'Plausible (cookieless)', category: 'Analytics', re: /plausible\.io\/js/i },
  { name: 'Fathom (cookieless)', category: 'Analytics', re: /usefathom\.com/i },
  { name: 'HubSpot', category: 'Marketing', re: /js\.hs-scripts\.com|js\.hsforms\.net|js\.hs-analytics\.net/i },
  { name: 'Mailchimp', category: 'Marketing', re: /chimpstatic\.com|list-manage\.com/i },
  { name: 'Intercom', category: 'Functional', re: /widget\.intercom\.io|js\.intercomcdn\.com/i },
  { name: 'Tawk.to live chat', category: 'Functional', re: /embed\.tawk\.to/i },
  { name: 'Zendesk', category: 'Functional', re: /static\.zdassets\.com/i },
  { name: 'LiveChat', category: 'Functional', re: /cdn\.livechatinc\.com/i },
  { name: 'Crisp chat', category: 'Functional', re: /client\.crisp\.chat/i },
  { name: 'YouTube embed', category: 'Embedded content', re: /youtube\.com\/embed|youtube\.com\/iframe_api/i },
  { name: 'YouTube (privacy-enhanced mode)', category: 'Embedded content', re: /youtube-nocookie\.com/i },
  { name: 'Vimeo embed', category: 'Embedded content', re: /player\.vimeo\.com/i },
  { name: 'Google Maps embed', category: 'Embedded content', re: /google\.com\/maps\/embed|maps\.googleapis\.com/i },
  { name: 'Google Fonts', category: 'Functional', re: /fonts\.googleapis\.com|fonts\.gstatic\.com/i },
  { name: 'Google reCAPTCHA', category: 'Functional', re: /google\.com\/recaptcha|recaptcha\.net/i },
  { name: 'AddThis', category: 'Marketing', re: /addthis\.com/i },
  { name: 'ShareThis', category: 'Marketing', re: /sharethis\.com/i },
  { name: 'JustGiving', category: 'Fundraising', re: /justgiving\.com/i },
  { name: 'Enthuse', category: 'Fundraising', re: /enthuse\.com/i },
  { name: 'Donorbox', category: 'Fundraising', re: /donorbox\.org/i },
  { name: 'Givebutter', category: 'Fundraising', re: /givebutter\.com/i },
  { name: 'Blackbaud', category: 'Fundraising', re: /blackbaud\.com|blackbaudcdn\.net/i },
  { name: 'Stripe', category: 'Payments', re: /js\.stripe\.com/i },
  { name: 'PayPal', category: 'Payments', re: /paypal\.com\/sdk|paypalobjects\.com/i }
];

// Known consent management platforms
const CMPS = [
  { name: 'OneTrust', re: /cdn\.cookielaw\.org|optanon|onetrust/i },
  { name: 'Cookiebot', re: /consent\.cookiebot\.com|cookiebot/i },
  { name: 'CookieYes', re: /cdn-cookieyes\.com|cookieyes/i },
  { name: 'Civic Cookie Control', re: /cc\.cdn\.civiccomputing\.com|CookieControl\.load/i },
  { name: 'Termly', re: /app\.termly\.io/i },
  { name: 'Iubenda', re: /cdn\.iubenda\.com/i },
  { name: 'Quantcast Choice', re: /quantcast\.mgr\.consensu\.org|cmp\.quantcast\.com/i },
  { name: 'Didomi', re: /sdk\.privacy-center\.org|didomi/i },
  { name: 'Usercentrics', re: /usercentrics/i },
  { name: 'Osano', re: /cmp\.osano\.com/i },
  { name: 'TrustArc', re: /consent\.trustarc\.com|truste\.com/i },
  { name: 'Sourcepoint', re: /sourcepoint|sp-prod\.net/i },
  { name: 'Complianz', re: /complianz|cmplz/i },
  { name: 'CookieFirst', re: /consent\.cookiefirst\.com/i },
  { name: 'Cookie Law Info (WordPress)', re: /cookie-law-info|cookieyes-/i },
  { name: 'Cookie Notice (WordPress)', re: /cookie-notice/i },
  { name: 'Klaro', re: /klaro/i },
  { name: 'Axeptio', re: /axeptio/i },
  { name: 'consentmanager', re: /consentmanager\.net/i }
];

function classifyCookie(name) {
  const n = name.toLowerCase();
  if (/^(_ga|_gid|_gat|__utm|_hj|_clck|_clsk|mp_|ajs_|_pk_)/.test(n)) return 'Analytics';
  if (/^(_fbp|_fbc|fr$|_gcl|ide$|test_cookie|_uet|li_|bcookie|_tt_|_pin)/.test(n)) return 'Marketing';
  if (/sess|csrf|xsrf|token|^__cf|cf_clearance|awsalb|awselb|__host-|__secure-|consent|cookie_?law|cookieyes|optanon|cookiecontrol|wordpress_test|wp-settings/.test(n)) return 'Strictly necessary (likely)';
  return 'Unclassified';
}

function parseCookie(str) {
  const parts = str.split(';').map(s => s.trim());
  const [nameVal] = parts;
  const name = nameVal.split('=')[0];
  const attrs = parts.slice(1).map(a => a.toLowerCase());
  return {
    name: clean(name, 60),
    category: classifyCookie(name),
    persistent: attrs.some(a => a.startsWith('expires=') || a.startsWith('max-age=')),
    secure: attrs.includes('secure'),
    httpOnly: attrs.includes('httponly'),
    sameSite: (attrs.find(a => a.startsWith('samesite=')) || '').split('=')[1] || 'not set'
  };
}

function analyseHtml(html, baseUrl) {
  // Collect every place a tracker could live: scripts, iframes, links
  const items = [];
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = scriptRe.exec(html))) {
    const attrs = m[1] || '';
    const typeMatch = attrs.match(/\btype\s*=\s*["']?([^"'\s>]+)/i);
    const type = typeMatch ? typeMatch[1].toLowerCase() : '';
    if (/json|template|x-template/.test(type)) continue;
    const src = (attrs.match(/\bsrc\s*=\s*["']?([^"'\s>]+)/i) || [])[1] || '';
    const executes = !type || /javascript|module|ecmascript/.test(type);
    items.push({ kind: 'script', text: src + ' ' + (m[2] || '').slice(0, 20000), gated: !executes });
  }
  const iframeRe = /<iframe\b([^>]*)>/gi;
  while ((m = iframeRe.exec(html))) {
    const attrs = m[1];
    const src = (attrs.match(/\bsrc\s*=\s*["']([^"']+)/i) || [])[1] || '';
    const dataSrc = (attrs.match(/\bdata-(?:src|cookieblock-src)\s*=\s*["']([^"']+)/i) || [])[1] || '';
    items.push({ kind: 'iframe', text: src + ' ' + dataSrc, gated: !src || /^about:blank/i.test(src) });
  }
  const linkRe = /<link\b([^>]*)>/gi;
  while ((m = linkRe.exec(html))) {
    const href = (m[1].match(/\bhref\s*=\s*["']([^"']+)/i) || [])[1] || '';
    items.push({ kind: 'link', text: href, gated: false });
  }
  const noscriptRe = /<noscript>([\s\S]*?)<\/noscript>/gi;
  while ((m = noscriptRe.exec(html))) items.push({ kind: 'noscript', text: m[1], gated: true });

  const trackers = [];
  for (const t of TRACKERS) {
    const hits = items.filter(i => t.re.test(i.text));
    if (!hits.length) continue;
    const live = hits.filter(h => !h.gated);
    trackers.push({
      name: t.name,
      category: t.category,
      loadsWithoutConsentGate: live.length > 0,
      blockedInMarkup: live.length === 0,
      foundIn: [...new Set(hits.map(h => h.kind))].join(', ')
    });
  }

  let consentTool = null;
  for (const c of CMPS) { if (c.re.test(html)) { consentTool = c.name; break; } }
  const autoBlocking = /data-blockingmode\s*=\s*["']auto|otAutoBlock|cookieyes.*autoblock|data-cookieconsent/i.test(html);
  const tcfApi = /__tcfapi/.test(html);
  const bannerMarkup = /(class|id)\s*=\s*["'][^"']*(cookie[-_]?(banner|consent|notice|bar|popup|notification)|gdpr[-_]?(banner|consent)|consent[-_]?(banner|popup|modal|bar))/i.test(html);
  const consentModeDefault = /gtag\(\s*['"]consent['"]\s*,\s*['"]default['"]/i.test(html);
  const consentModeDenied = /gtag\(\s*['"]consent['"]\s*,\s*['"]default['"][\s\S]{0,400}?denied/i.test(html);

  // Policy links
  const links = [];
  const aRe = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  while ((m = aRe.exec(html))) {
    const text = htmlToText(m[2]).trim().toLowerCase();
    let abs; try { abs = new URL(m[1], baseUrl).toString(); } catch { continue; }
    if (!/^https?:/.test(abs)) continue;
    links.push({ text, href: abs, hrefLow: abs.toLowerCase() });
  }
  const pick = (re) => { const l = links.find(x => re.test(x.text) || re.test(x.hrefLow)); return l ? l.href : null; };
  const policyLinks = {
    privacy: pick(/privacy|data[-_ ]protection/),
    cookie: pick(/cookie/),
    terms: pick(/terms|conditions/),
    accessibility: pick(/accessibility/)
  };
  if (policyLinks.cookie && policyLinks.cookie === policyLinks.privacy) policyLinks.cookie = null;

  const title = clean((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '', 150);

  return { trackers, consentTool, autoBlocking, tcfApi, bannerMarkup, consentModeDefault, consentModeDenied, policyLinks, title };
}

function checkPolicyText(text) {
  const t = text.toLowerCase();
  const has = (re) => re.test(t);
  const updated = text.match(/(last\s+(?:updated|reviewed|modified|revised)|effective\s+(?:date|from))[:\s-]{0,5}([0-9]{1,2}(?:st|nd|rd|th)?\s+[A-Za-z]+\s+20\d\d|[A-Za-z]+\s+[0-9]{1,2},?\s+20\d\d|[A-Za-z]+\s+20\d\d|\d{1,2}[\/.-]\d{1,2}[\/.-]20\d\d)/i);
  return {
    mentionsRetention: has(/retention|retain|how long we (keep|hold|store)|kept for/),
    mentionsYourRights: has(/right (of|to) access|subject access|right to (erasure|be forgotten|rectification|object|restrict)|data portability|your rights/),
    mentionsIcoComplaint: has(/ico\.org\.uk|information commissioner/),
    mentionsDpoOrContact: has(/data protection officer|\bdpo\b|privacy@|dataprotection@|dpo@/),
    mentionsInternationalTransfers: has(/international transfer|transfer.{0,40}outside (the )?(uk|eea|european)|standard contractual|adequacy|idta|international data transfer/),
    mentionsLawfulBasis: has(/lawful basis|legal basis|legitimate interest|article 6/),
    mentionsCookies: has(/cookie/),
    mentionsChildrenData: has(/child|under (13|16|18)|pupil|student/),
    lastUpdated: updated ? clean(updated[2], 40) : null
  };
}

function findIcoNumber(text) {
  const m = text.match(/(?:ICO|Information Commissioner|registration|registered)[^.]{0,120}?\b(Z[A-Z]?\d{6,7})\b/i) ||
            text.match(/\b(Z[A-Z]?\d{6,7})\b[^.]{0,80}?(?:ICO|Information Commissioner|registration)/i);
  return m ? m[1].toUpperCase() : null;
}

app.post('/scan', async (req, res) => {
  const started = Date.now();
  let url = String((req.body && req.body.url) || '').trim();
  if (!url || url.length > 2000) return res.status(400).json({ ok: false, reason: 'Please provide a valid website address' });
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  try {
    const u = new URL(url);
    if (!u.hostname.includes('.') && !ALLOW_PRIVATE) throw new Error('bad host');
  } catch {
    return res.json({ ok: false, reason: 'That does not look like a valid website address' });
  }

  let page;
  try {
    page = await fetchPage(url);
  } catch (err) {
    return res.json({ ok: false, scannedUrl: clean(url), reason: 'We could not reach this website (' + clean(err.message, 80) + ')' });
  }
  if (page.status >= 400) {
    return res.json({ ok: false, scannedUrl: clean(url), reason: 'The website refused the automated scan (HTTP ' + page.status + '). Some sites block scanners.' });
  }
  if (!/html/i.test(page.contentType) && !/<html/i.test(page.body.slice(0, 2000))) {
    return res.json({ ok: false, scannedUrl: clean(url), reason: 'The address did not return a web page' });
  }

  const a = analyseHtml(page.body, page.finalUrl);
  const homeText = htmlToText(page.body);

  // Read the privacy policy (and cookie policy if separate), in parallel
  const toFetch = [a.policyLinks.privacy, a.policyLinks.cookie].filter(Boolean);
  const policyPages = await Promise.all(toFetch.map(p =>
    fetchPage(p).then(r => (r.status < 400 ? r : null)).catch(() => null)
  ));
  const privacyPage = a.policyLinks.privacy ? policyPages[0] : null;
  const cookiePage = a.policyLinks.cookie ? policyPages[policyPages.length - 1] : null;
  const privacyText = privacyPage ? htmlToText(privacyPage.body) : '';
  const cookieText = cookiePage ? htmlToText(cookiePage.body) : '';

  const cookieMap = new Map();
  page.cookies.map(parseCookie).forEach(c => { if (c.name) cookieMap.set(c.name, c); });

  const evidence = {
    ok: true,
    scannedUrl: clean(url),
    finalUrl: clean(page.finalUrl, 300),
    domain: clean(new URL(page.finalUrl).hostname.replace(/^www\./, ''), 120),
    pageTitle: a.title,
    pagesRead: [clean(page.finalUrl, 300), ...toFetch.filter((_, i) => policyPages[i]).map(p => clean(p, 300))],
    consent: {
      consentToolDetected: a.consentTool,
      autoBlockingDetected: a.autoBlocking,
      iabTcfFramework: a.tcfApi,
      bannerMarkupDetected: a.bannerMarkup,
      googleConsentMode: a.consentModeDefault ? (a.consentModeDenied ? 'present, defaults to denied' : 'present') : 'not found'
    },
    trackers: a.trackers,
    cookiesSetOnFirstVisit: [...cookieMap.values()].slice(0, 30),
    policyLinks: {
      privacyPolicy: a.policyLinks.privacy ? clean(a.policyLinks.privacy, 300) : null,
      cookiePolicy: a.policyLinks.cookie ? clean(a.policyLinks.cookie, 300) : null,
      terms: a.policyLinks.terms ? clean(a.policyLinks.terms, 300) : null,
      accessibility: a.policyLinks.accessibility ? clean(a.policyLinks.accessibility, 300) : null
    },
    privacyPolicyRead: !!privacyPage,
    privacyPolicyChecks: privacyPage ? checkPolicyText(privacyText) : null,
    cookiePolicyRead: !!cookiePage,
    cookiePolicyMentionsRetention: cookiePage ? /retention|expire|expiry|duration|how long/i.test(cookieText) : null,
    icoRegistrationNumberFound: findIcoNumber(homeText + ' ' + privacyText),
    scanSeconds: Math.round((Date.now() - started) / 100) / 10,
    limitations: [
      'Reads the page source as delivered by the server. Scripts added later by tag managers or after user interaction may not be visible.',
      'Cookies set by JavaScript in the browser are not captured, only cookies set by the server on first visit.',
      'Internal procedures (such as breach handling) cannot be verified from a public website.'
    ]
  };
  res.json(evidence);
});

/* ═══════════════════════════════════════════════════════════════════════
   AI ASSESSMENT PROXY
   ═══════════════════════════════════════════════════════════════════════ */

app.post('/audit', async (req, res) => {
  const { systemPrompt, userMessage } = req.body;

  if (!systemPrompt || !userMessage) {
    return res.status(400).json({ error: 'Missing systemPrompt or userMessage' });
  }

  const apiKey = getCleanKey();

  if (!apiKey || !apiKey.startsWith('sk-ant-')) {
    return res.status(500).json({ error: 'API key not configured correctly' });
  }

  const payload = JSON.stringify({
    model: 'claude-sonnet-4-5-20250929',
    max_tokens: 10000,
    system: systemPrompt,
    messages: [{ role: 'user', content: userMessage }]
  });

  try {
    const result = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.anthropic.com',
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        }
      };

      const request = https.request(options, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => resolve({ status: response.statusCode, body: data }));
      });

      request.on('error', reject);
      request.write(payload);
      request.end();
    });

    if (result.status !== 200) {
      console.error('Anthropic error:', result.status, result.body);
      return res.status(502).json({
        error: 'AI service error',
        status: result.status,
        detail: result.body
      });
    }

    return res.json(JSON.parse(result.body));

  } catch (err) {
    console.error('Proxy error:', err.message);
    return res.status(500).json({ error: 'Internal server error', detail: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`AuditIQ proxy v${VERSION} running on port ${PORT}`);
});
