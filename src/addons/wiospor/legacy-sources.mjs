import fs from 'node:fs';
import { createHash, createHmac, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36';
const DOMAIN_MANIFEST = 'https://raw.githubusercontent.com/Wiojelt/TurkSpor/main/domains.json';

const SOURCES = [
  { key: 'taraftarium24', name: 'Taraftarium24' },
  { key: 'ardaspor', name: 'ArdaSpor' },
  { key: 'mahsunsports', name: 'MahsunSports' },
  { key: 'crex', name: 'Crex' },
  { key: 'kralsportshd', name: 'KralSporHD' }
];

function norm(s) { return String(s || '').toLowerCase().replaceAll('ı','i').replaceAll('ğ','g').replaceAll('ü','u').replaceAll('ş','s').replaceAll('ö','o').replaceAll('ç','c').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/\b(?:1080p|720p|480p|360p|fhd|uhd|hd|sd|4k|50fps|60fps|7\/24|24\/7)\b/g, ' ').replace(/\bsports\b/g, 'sport').replace(/[^a-z0-9]+/g, ' ').trim(); }
function compact(s) { return norm(s).replace(/\s+/g, ''); }
function nums(s) { return [...norm(s).matchAll(/\b([0-9]+)\b/g)].map(x => x[1]); }
function channelBrand(value) {
  const combined = ` ${compact(value)} `;
  if (combined.includes('ssportplus') || combined.includes('ssport+')) return 'ssportplus';
  if (combined.includes('ssport') || combined.includes('mavispor') || combined.includes(' ss ') || combined.includes(' ss2 ')) return 'ssport';
  if (combined.includes('smartspor') || combined.includes('sporsmart')) return 'smartspor';
  if (combined.includes('bein') || combined.includes('morspor') || combined.includes('patron') || combined.includes('ligtv') || combined.includes(' bs1 ') || combined.includes(' b1 ')) return 'bein';
  if (combined.includes('tivibu') || combined.includes('turuncuspor') || combined.includes(' t1 ') || combined.includes(' t2 ')) return 'tivibu';
  if (combined.includes('tabii') || combined.includes('yesilspor') || combined.includes(' ex1 ')) return 'tabii';
  if (combined.includes('exxen') || combined.includes('sarispor')) return 'exxen';
  if (combined.includes('eurosport') || combined.includes(' eu1 ') || combined.includes(' eu2 ')) return 'eurosport';
  if (combined.includes('trtspor') || combined.includes('trt1') || combined.includes('trt')) return 'trt';
  if (combined.includes('aspor')) return 'aspor';
  return '';
}

function matches(channel, row) {
  const rowText = `${row?.title || ''} ${row?.id || ''} ${row?.name || ''}`;
  const targetBrand = channelBrand(`${channel?.standardTitle || ''} ${channel?.name || ''}`);
  const rowBrand = channelBrand(rowText);

  if (targetBrand && rowBrand && targetBrand !== rowBrand) return false;
  if (targetBrand === 'bein' && /tivibu|ssport|s sport|euro|tabii|exxen|smart|trt|aspor|t1|t2|ss|eu1/i.test(rowText)) return false;
  if (targetBrand === 'ssport' && /tivibu|bein|euro|tabii|exxen|smart|trt|aspor|t1|b1|ex1/i.test(rowText)) return false;
  if (targetBrand === 'tivibu' && /bein|ssport|s sport|euro|tabii|exxen|smart|trt|aspor|b1|ss|ex1/i.test(rowText)) return false;
  if (targetBrand === 'tabii' && /bein|ssport|s sport|euro|tivibu|exxen|smart|aspor|b1|ss|t1/i.test(rowText)) return false;
  if (targetBrand === 'exxen' && /bein|ssport|s sport|euro|tivibu|tabii|smart|aspor|b1|ss|t1/i.test(rowText)) return false;

  const candidates = [row?.title, row?.id, `${row?.title || ''} ${row?.id || ''}`].filter(Boolean);
  const targets = [channel?.standardTitle, ...(channel?.aliases || [])].filter(Boolean);

  for (const c of candidates) {
    const cc = compact(c); if (!cc) continue;
    const cnum = nums(c).at(-1);
    const isCandHaber = /haber/i.test(c);
    const isCandMax = /max/i.test(c);

    for (const t of targets) {
      const isTargetHaber = /haber/i.test(t);
      const isTargetMax = /max/i.test(t);
      if (isCandHaber !== isTargetHaber || isCandMax !== isTargetMax) continue;

      const tt = compact(t); if (!tt) continue;
      const tnum = nums(t).at(-1);

      if (tnum && cnum && tnum !== cnum) continue;
      if (tnum && !cnum && !/4k|uhd/i.test(c)) continue;
      if (!tnum && cnum && !['1', '24', '7'].includes(cnum)) continue;

      if (cc === tt) return true;
      if (Math.min(cc.length, tt.length) >= 4 && (tt.includes(cc) || cc.includes(tt))) return true;
    }
  }
  return false;
}

function decodeHtml(s) { return String(s || '').replace(/&amp;/gi, '&').replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'").replace(/&lt;/gi, '<').replace(/&gt;/gi, '>'); }
function stripTags(s) { return decodeHtml(String(s || '').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ').replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim(); }
function attr(raw, key) { const m = new RegExp(`${key}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(raw || ''); return decodeHtml(m ? (m[1] ?? m[2] ?? m[3] ?? '') : ''); }
function abs(value, base) { try { return new URL(value, base).toString(); } catch { return ''; } }
function http(value) { try { const u = new URL(value); return /^https?:$/.test(u.protocol) ? u.toString() : ''; } catch { return ''; } }
function origin(value) { try { const u = new URL(value); return `${u.protocol}//${u.host}`; } catch { return ''; } }
function q(url, key) { try { return new URL(url).searchParams.get(key) || ''; } catch { return ''; } }

async function text(url, referer = '', timeout = 10000) {
  const headers = { 'User-Agent': UA, Accept: '*/*' }; if (referer) headers.Referer = referer;
  const r = await fetch(url, { headers, redirect: 'follow', signal: AbortSignal.timeout(timeout) });
  return { code: r.status, url: r.url, text: await r.text(), headers: r.headers };
}

let manifestCache = null, manifestAt = 0;
async function domainManifest() {
  if (manifestCache && Date.now() - manifestAt < 120000) return manifestCache;
  try { const r = await text(DOMAIN_MANIFEST, '', 8000); manifestCache = r.code === 200 ? JSON.parse(r.text) : { sources: {} }; }
  catch { manifestCache = { sources: {} }; }
  manifestAt = Date.now(); return manifestCache;
}

function anchorRows(html, base) {
  const rows = [];
  for (const m of String(html || '').matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)) {
    const raw = m[1], body = m[2];
    const href = attr(raw, 'data-url') || attr(raw, 'data-streamx') || attr(raw, 'href'); if (!href) continue;
    const player = http(abs(href, base)); if (!player) continue;
    const nameMatch = /class\s*=\s*["'][^"']*(?:name|home|channel-name)[^"']*["'][^>]*>([\s\S]*?)<\//i.exec(body);
    const title = stripTags(nameMatch?.[1] || attr(/<img\b([^>]*)>/i.exec(body)?.[1] || '', 'alt') || body); if (!title) continue;
    rows.push({ id: q(player, 'id') || q(player, 'channel') || player.split('/').filter(Boolean).at(-1) || title, title, player });
  }
  return rows;
}

function extractPlayerUrls(html, playerUrl) {
  const out = [];
  function isPlayable(u) {
    if (!u) return false;
    const lower = u.toLowerCase();
    if (/\.(png|jpe?g|gif|webp|svg|css|js|ico)(\?.*)?$/i.test(lower)) return false;
    if (lower.includes('yandex.ru') || lower.includes('google-analytics') || lower.includes('googletagmanager')) return false;
    return lower.includes('.m3u8') || lower.includes('.mpd') || lower.includes('/playlist') || lower.includes('mono.m3u8') || lower.includes('/live/') || lower.includes('/hls/');
  }
  function add(v) {
    const url = http(decodeHtml(String(v || '').replace(/\\\//g, '/')));
    if (url && isPlayable(url) && !out.includes(url)) out.push(url);
  }
  for (const m of String(html || '').matchAll(/https?:\\?\/\\?\/[^'"\s<>]+?\.m3u8(?:\?[^'"\s<>]*)?/gi)) add(m[0]);
  for (const m of String(html || '').matchAll(/(?:file|source|src|streamUrl|hls)\s*[:=]\s*['"]([^'"]+)['"]/gi)) add(abs(m[1], playerUrl));
  const base = /this\.baseStreamUrl\s*=\s*['"](https?:\/\/[^'"]+)['"]/i.exec(html)?.[1];
  if (base) {
    const id = q(playerUrl, 'id');
    if (/privateStream\s*=\s*1\b/i.test(html)) add(base);
    else if (id && /\/playlist\.m3u8/i.test(html)) add(`${base.replace(/\/$/, '')}/${encodeURIComponent(id)}/playlist.m3u8`);
  }
  return out;
}

function stream(sourceName, title, url, referer, headers = {}) {
  const request = {};
  for (const [key, value] of Object.entries(headers || {})) {
    if (typeof value !== 'string' || !value || /[\r\n]/.test(value)) continue;
    if (['host', 'content-length'].includes(key.toLowerCase())) continue;
    request[key] = value;
  }
  if (!request['User-Agent']) request['User-Agent'] = UA;
  const ref = request.Referer || request.referer || referer || '';
  if (ref && !request.Referer && !request.referer) request.Referer = ref;
  if (!request.Origin && !request.origin && ref) {
    const org = origin(ref);
    if (org) request.Origin = org;
  }
  // webOS uyumluluğu için notWebReady false yapıldı
  return { 
    name: `WioSpor • ${sourceName}`, 
    title: `${title} • Auto`, 
    url, 
    behaviorHints: { 
      notWebReady: false, 
      proxyHeaders: { request } 
    } 
  };
}

async function genericSource(source, wioChannel) {
  const manifest = await domainManifest(); const entry = manifest?.sources?.[source.key] || {};
  const roots = [...(entry.candidates || []), ...(entry.gateways || [])].filter(Boolean).slice(0, 5);
  for (const root of roots) try {
    const home = await text(root, '', 9000); if (home.code !== 200) continue;
    const selected = anchorRows(home.text, home.url).filter(row => matches(wioChannel, row)).slice(0, 4); const found = [];
    for (const row of selected) try {
      const page = await text(row.player, home.url, 9000); if (page.code !== 200) continue;
      for (const url of extractPlayerUrls(page.text, page.url).slice(0, 5)) found.push(stream(source.name, row.title, url, origin(page.url) || home.url));
    } catch {}
    if (found.length) return found;
  } catch {}
  return [];
}

let cifd2mCatalog = null;
let cifd2mCatalogAt = 0;
async function getCifd2mCatalog() {
  if (cifd2mCatalog && Date.now() - cifd2mCatalogAt < 10 * 60_000) return cifd2mCatalog;
  try {
    const fsMod = await import('node:fs/promises');
    const localDbUrl = new URL('../../../config/cifd2m-channel-db.json', import.meta.url);
    const raw = await fsMod.readFile(localDbUrl, 'utf-8');
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed?.live_channels) && parsed.live_channels.length) {
      cifd2mCatalog = parsed.live_channels;
      cifd2mCatalogAt = Date.now();
      return cifd2mCatalog;
    }
  } catch {}
  const urls = [
    'https://raw.githubusercontent.com/Wiojelt/WioSpor/builds/cifd2m_live.json',
    'https://raw.githubusercontent.com/Wiojelt/WioSpor/main/cifd2m_live.json',
    'https://raw.githubusercontent.com/Wiojelt/WioSpor/builds/domino_live.json',
    'https://raw.githubusercontent.com/Wiojelt/WioSpor/main/domino_live.json'
  ];
  for (const u of urls) {
    try {
      const r = await fetch(u, { signal: AbortSignal.timeout(8000) });
      if (r.ok) {
        const json = await r.json();
        cifd2mCatalog = Array.isArray(json?.live_channels) ? json.live_channels : [];
        cifd2mCatalogAt = Date.now();
        return cifd2mCatalog;
      }
    } catch {}
  }
  return [];
}

function channelMatchScore(channelTitle, wioChannel) {
  const name = String(channelTitle || '').toLowerCase().trim();
  const st = String(wioChannel?.standardTitle || '').toLowerCase().trim();
  const tb = channelBrand(st);
  const cb = channelBrand(name);
  if (tb && cb && tb !== cb) return -1000;

  let pts = 0;
  if (st && (name === st || compact(name) === compact(st))) pts += 500;
  else if (st && (name.includes(st) || st.includes(name))) pts += 300;
  if (tb && cb && tb === cb) pts += 200;
  for (const a of (wioChannel?.aliases || [])) {
    const al = String(a).toLowerCase().trim();
    if (!al) continue;
    if (name === al || compact(name) === compact(al)) pts += 150;
    else if (al.length >= 4 && name.includes(al)) pts += 50;
  }
  return pts;
}

async function cifd2m(wioChannel) {
  try {
    const channels = await getCifd2mCatalog();
    const candidates = channels
      .filter(x => x?.active !== false && (x?.title || x?.name) && (x?.stream_url || (Array.isArray(x?.sources) && x.sources.length)) && matches(wioChannel, { id: String(x.id || ''), title: x.title || x.name }))
      .sort((a, b) => channelMatchScore(b.title || b.name, wioChannel) - channelMatchScore(a.title || a.name, wioChannel));
    const out = [];
    for (const ch of candidates.slice(0, 5)) {
      const headers = { 'User-Agent': ch.user_agent || UA, Referer: ch.referer || '', Origin: ch.origin || '' };
      const candidateUrls = [ch.stream_url, ...(Array.isArray(ch.alternative_stream_urls) ? ch.alternative_stream_urls : [])];
      if (Array.isArray(ch.sources)) {
        for (const s of ch.sources) if (s?.url) candidateUrls.push(s.url);
      }
      for (const u of candidateUrls) {
        if (http(u) && !u.includes('youtube.com')) out.push(stream('çifd2m', ch.title || ch.name, u, ch.referer || '', headers));
      }
    }
    return out;
  } catch { return []; }
}
const domino = cifd2m;

const DOMATES_IDENTITY = 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=';
const DOMATES_KEY = process.env.DOMATES_GOOGLE_API_KEY || '';
const DOMATES_DB = 'https://domates-tv-live-sports6.europe-west1.firebasedatabase.app/channels.json?auth=';
let domatesToken = '', domatesTokenAt = 0, domatesChannels = [], domatesAt = 0;

async function domatesList() {
  if (domatesChannels.length && Date.now() - domatesAt < 10 * 60_000) return domatesChannels;
  if (!domatesToken || Date.now() - domatesTokenAt > 45 * 60_000) {
    const auth = await fetch(DOMATES_IDENTITY + DOMATES_KEY, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Android-Package': 'com.tv.domates', 'X-Android-Cert': 'e0ec0ae65a2326db28b58bee83d0248bc1fc9ba2' },
      body: JSON.stringify({ returnSecureToken: true }),
      signal: AbortSignal.timeout(15000)
    });
    if (!auth.ok) return [];
    domatesToken = (await auth.json())?.idToken || ''; domatesTokenAt = Date.now(); if (!domatesToken) return [];
  }
  let r = await fetch(DOMATES_DB + encodeURIComponent(domatesToken), { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(20000) });
  if (r.status === 401) { domatesToken = ''; domatesTokenAt = 0; return []; }
  if (!r.ok) return [];
  const rows = await r.json(); domatesChannels = Array.isArray(rows) ? rows.filter(x => x?.name && x?.url) : []; domatesAt = Date.now(); return domatesChannels;
}
function domatesHeaders(ch, referer) {
  const type = String(ch.type || '').toLowerCase();
  const userAgent = type === 'kabloweb' ? 'Dalvik/2.1.0 (Linux; U; Android 12; Pixel 6 Build/SP2A.220505.002)' : type === 'sspr' ? 'com.ssportplus.dice/303 (Linux; U; Android 14; tr; Redfin; Build/FCB4.356145.001; Cronet/144.0.7509.3)' : UA;
  return { 'User-Agent': userAgent, Referer: referer || '', Origin: referer ? origin(referer) : '' };
}
async function domates(wioChannel) {
  try {
    const rows = await domatesList(); const selected = rows.filter(ch => matches(wioChannel, { id: ch.name, title: ch.name })).slice(0, 6); const out = [];
    for (const ch of selected) try {
      const parts = String(ch.url || '').split('::'); let url = http(parts[0]); let referer = http(parts[1] || ''); if (!url) continue;
      if (String(ch.type || '').toLowerCase() === 'yt') { out.push(stream('Domates TV', ch.name, `https://www.youtube.com/watch?v=${encodeURIComponent(parts[0])}`, '', domatesHeaders(ch, ''))); continue; }
      if (['custom', 'cdnlive'].includes(String(ch.type || '').toLowerCase())) {
        const headers = domatesHeaders(ch, referer); const r = await fetch(url, { headers, redirect: 'follow', signal: AbortSignal.timeout(12000) });
        if (r.ok) { const body = (await r.text()).replace(/\\\//g, '/'); const found = /https?:\/\/[^"'\s]+(?:m3u8|mpd)[^"'\s]*/i.exec(body)?.[0]; if (found) url = found; if (!referer) referer = r.url; }
      }
      out.push(stream('Domates TV', ch.name, url, referer, domatesHeaders(ch, referer)));
    } catch {}
    return out;
  } catch { return []; }
}
  
