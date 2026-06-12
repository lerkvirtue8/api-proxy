/**
 * api/index.js  —  Barrix Auth  (single-function master router)
 * All routes live here so Vercel Hobby (12-function limit) is never hit.
 */

import { createClient } from '@supabase/supabase-js';
import Stripe from 'stripe';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { Readable } from 'stream'; // Native stream adapter included

// ─────────────────────────────────────────────────────────────
// Clients & Configurations
// ─────────────────────────────────────────────────────────────
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL || 'https://placeholder-a.supabase.co',
  process.env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder-key',
  { auth: { persistSession: false } }
);

const supabaseAppsAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || 'https://placeholder-b.supabase.co',
  process.env.BARRIX_SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder-key',
  { auth: { persistSession: false } }
);

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-04-10' })
  : null;

const supabasePublicKey = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPERBASE_ANON_KEY || '';

const GEMINI_MODEL_MAPPING = {
  'GEMINI_FLASH_BARRIX': 'gemini-2.5-flash',
  'GEMINI_PRO_BARRIX': 'gemini-2.5-pro'
};

const CORS_HEADERS = {
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-Client-Info, apikey, X-Auth-Tier, X-App-Id',
  'Access-Control-Allow-Credentials': 'true',
};

let ALLOWED_ORIGINS = [
  'https://www.dustdelux.com',
  'https://dustdelux.com',
  'https://barrix.dustdelux.com',
  'https://crux.dustdelux.com',
  'http://localhost:3000'
];

function cors(req, res) {
  try {
    const origin = req.headers.origin || '';
    if (ALLOWED_ORIGINS.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    } else {
      res.setHeader('Access-Control-Allow-Origin', '*');
    }
    res.setHeader('Vary', 'Origin');
    
    // Fallback if CORS_HEADERS was accidentally stripped by previous agent tasks
    const fallbackHeaders = {
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-Client-Info, apikey, X-Auth-Tier, X-App-Id',
      'Access-Control-Allow-Credentials': 'true'
    };
    
    const headersToApply = typeof CORS_HEADERS !== 'undefined' ? CORS_HEADERS : fallbackHeaders;
    Object.entries(headersToApply).forEach(([k, v]) => res.setHeader(k, v));
  } catch (e) {
    console.error('[cors] Header injection failed:', e.message);
  }
}

function json(res, status, body) {
  res.status(status).json(body);
}

async function getUser(req) {
  try {
    const auth = req.headers.authorization || '';
    if (!auth) return null;
    const token = auth.replace(/^Bearer\s+/i, '').trim();
    if (!token || token === 'null' || token === 'undefined') return null;

    const authTier = req.headers['x-auth-tier'] || 'platform';
    const clientAnchor = authTier === 'subuser' ? supabaseAppsAdmin : supabaseAdmin;
    
    const { data: { user }, error } = await clientAnchor.auth.getUser(token);
    if (error) {
      console.warn(`[getUser] Supabase validation failed for tier ${authTier}:`, error.message);
      return null;
    }
    return user;
  } catch (err) {
    console.error('[getUser] Exception:', err.message);
    return null;
  }
}

function getCallbackUrl(req) {
  if (process.env.GITHUB_CALLBACK_URL) return process.env.GITHUB_CALLBACK_URL;
  if (process.env.GITHUB_OAUTH_REDIRECT_URI) return process.env.GITHUB_OAUTH_REDIRECT_URI;
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}/github/callback`;
}

function getRequestUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
  const rawUrl = req.headers['x-original-url'] || req.headers['x-rewrite-url'] || req.headers['x-forwarded-uri'] || req.url || '/';
  return new URL(rawUrl, `${proto}://${host}`);
}

function getRequestPath(req) {
  const hintedPath = req.headers['x-matched-path'] || req.headers['x-invoke-path'] || req.headers['x-vercel-rewritten-path'];
  const requestUrl = getRequestUrl(req);
  let resolvedPath = (hintedPath && !hintedPath.includes('index') ? new URL(hintedPath, requestUrl.origin) : requestUrl).pathname;
  
  // Collapse duplicate slashes and normalize prefixes completely
  resolvedPath = resolvedPath.replace(/\/+/g, '/');
  resolvedPath = resolvedPath.replace(/^\/api/, '');
  
  // Keep the exact leading slash for matching our dictionary literal keys
  if (!resolvedPath.startsWith('/')) {
    resolvedPath = '/' + resolvedPath;
  }
  
  // Strip a simple trailing slash unless it is the root path itself
  if (resolvedPath !== '/' && resolvedPath.endsWith('/')) {
    resolvedPath = resolvedPath.slice(0, -1);
  }
  
  if (resolvedPath === '/index' || resolvedPath === '/index.js' || resolvedPath === '/') {
    if (requestUrl.searchParams.has('code') && (requestUrl.searchParams.has('state') || requestUrl.searchParams.has('error'))) {
      return '/github/callback';
    }
    return '/';
  }
  return resolvedPath;
}

function getRequestQuery(req) {
  const query = {};
  const url = getRequestUrl(req);
  url.searchParams.forEach((value, key) => { query[key] = value; });
  if (req.query && typeof req.query === 'object') {
    Object.entries(req.query).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        query[key] = Array.isArray(value) ? value[0] : value;
      }
    });
  }
  return query;
}

function getStateSecret() { return process.env.GITHUB_OAUTH_STATE_SECRET || process.env.GITHUB_CLIENT_SECRET; }
function encodeState(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', getStateSecret()).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function decodeState(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) throw new Error('Missing or invalid OAuth state.');
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', getStateSecret()).update(body).digest('base64url');
  if (sig !== expected) throw new Error('OAuth state verification failed.');
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  const ageMs = Date.now() - Number(payload.ts || 0);
  if (!payload.ts || ageMs < 0 || ageMs > 10 * 60 * 1000) throw new Error('OAuth state expired.');
  return payload;
}

function buildPopupPage(payload) {
  const safePayload = JSON.stringify(payload).replace(/</g, '\\u003c');
  const title = payload.githubAccessToken ? 'GitHub connected' : 'GitHub connection failed';
  const body = payload.githubAccessToken ? 'You can close this window if it does not close automatically.' : (payload.error || 'Unknown GitHub OAuth error.');
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>${title}</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#101315;color:#ece2cc;font-family:system-ui,sans-serif}.card{width:min(420px,calc(100vw - 32px));padding:28px;border-radius:18px;background:rgba(21,25,28,.96);border:1px solid rgba(234,224,201,.12);box-shadow:0 20px 60px rgba(0,0,0,.35)}h1{margin:0 0 10px;font-size:20px}p{margin:0;color:#b8ab92;line-height:1.5}</style></head><body><div class="card"><h1>${title}</h1><p>${body}</p></div><script>(function(){var payload=${safePayload};try{if(window.opener&&!window.opener.closed){window.opener.postMessage(payload,window.location.origin)}}catch(e){}if(payload.githubAccessToken){setTimeout(function(){window.close()},150)}})();</script></body></html>`;
}

async function exchangeGitHubCode(req, code) {
  const response = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code, redirect_uri: getCallbackUrl(req) })
  });
  const data = await response.json();
  if (!response.ok || data.error || !data.access_token) throw new Error(data.error_description || data.error || 'GitHub token exchange failed.');
  return data.access_token;
}

async function fetchGitHubUser(accessToken) {
  const response = await fetch('https://api.github.com/user', { headers: { 'Accept': 'application/vnd.github+json', 'Authorization': `Bearer ${accessToken}`, 'X-GitHub-Api-Version': '2022-11-28' } });
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || 'Failed to fetch GitHub user.');
  return data;
}

function encryptGitHubToken(token) {
  const secret = process.env.GITHUB_TOKEN_ENCRYPTION_KEY;
  if (!secret) throw new Error('GITHUB_TOKEN_ENCRYPTION_KEY is not configured.');
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(token), 'utf8'), cipher.final()]);
  return { ciphertext: encrypted.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}

function rawBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => (data += chunk));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

const PLAN_SAVE_LIMITS    = { free: 0,    starter: 50, kickass: 200, superdeluxe: 9999 };
const PLAN_PROJECT_LIMITS = { free: 3,    starter: 25, kickass: 100, superdeluxe: 9999 };
const PLAN_STRIPE_PRICES  = () => ({ starter: process.env.STRIPE_PRICE_STARTER, kickass: process.env.STRIPE_PRICE_KICKASS, superdeluxe: process.env.STRIPE_PRICE_SUPERDELUXE });
const CRUX_STRIPE_PRICES = () => ({ starter: process.env.STRIPE_PRICE_CRUX_STARTER, kickass: process.env.STRIPE_PRICE_CRUX_KICKASS, superdeluxe: process.env.STRIPE_PRICE_CRUX_SUPERDELUXE });
function getPriceRoleMap() {
  const map = {};
  [PLAN_STRIPE_PRICES(), CRUX_STRIPE_PRICES()].forEach(set => { Object.entries(set).forEach(([role, price]) => { if (price) map[price] = role; }); });
  return map;
}

// ─────────────────────────────────────────────────────────────
// Route Mappings
// ─────────────────────────────────────────────────────────────
async function routeConfig(req, res) {
  try {
    if (req.method !== 'GET') return json(res, 405, { error: 'GET only' });
    const query = getRequestQuery(req);
    if ((query.client === 'app' || query.appId) && process.env.NEXT_PUBLIC_SUPABASE_URL) {
      const appAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || '';
      return json(res, 200, { SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL, SUPABASE_ANON_KEY: appAnonKey, SUPABASE_PUBLISHABLE_KEY: appAnonKey, APK_BUILD_API_URL: process.env.APK_BUILD_API_URL || '', APK_BUILD_API_TOKEN: process.env.APK_BUILD_API_TOKEN || '' });
    }
    return json(res, 200, { SUPABASE_URL: process.env.SUPABASE_URL || '', SUPABASE_ANON_KEY: supabasePublicKey, SUPABASE_PUBLISHABLE_KEY: supabasePublicKey, APK_BUILD_API_URL: process.env.APK_BUILD_API_URL || '', APK_BUILD_API_TOKEN: process.env.APK_BUILD_API_TOKEN || '' });
  } catch (err) {
    return json(res, 500, { error: err.message });
  }
}

async function routeProfile(req, res) {
  if (req.method !== 'GET') return json(res, 405, { error: 'GET only' });
  const user = await getUser(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const { data, error } = await supabaseAdmin.from('profiles').select('id, display_name, role, avatar_url').eq('id', user.id).single();
  if (error) return json(res, 200, { id: user.id, email: user.email, display_name: user.user_metadata?.display_name || user.email.split('@')[0], role: user.user_metadata?.role || 'free', avatar_url: null });
  return json(res, 200, { ...data, email: user.email });
}

async function routeUpdateProfile(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'POST only' });
  const user = await getUser(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const updates = {};
  ['avatar_url', 'display_name'].forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
  const { error } = await supabaseAdmin.from('profiles').update(updates).eq('id', user.id);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { success: true });
}

async function routeSaveProject(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'POST only' });
  const user = await getUser(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const { title, brx_data, file_count } = req.body;
  if (!title || !brx_data) return json(res, 400, { error: 'title and brx_data required' });

  const { data: profile } = await supabaseAdmin.from('profiles').select('role').eq('id', user.id).single();
  const role = profile?.role || 'free';
  if ((PLAN_SAVE_LIMITS[role] || 0) === 0) return json(res, 403, { error: 'Cloud saves require a paid plan.' });

  const { data: existing } = await supabaseAdmin.from('barrix_projects').select('id').eq('user_id', user.id).eq('title', title).single();
  if (existing) {
    const { error } = await supabaseAdmin.from('barrix_projects').update({ brx_data, file_count: file_count || 0, updated_at: new Date().toISOString() }).eq('id', existing.id);
    if (error) return json(res, 500, { error: error.message });
    return json(res, 200, { success: true, action: 'updated' });
  }

  const { count } = await supabaseAdmin.from('barrix_projects').select('id', { count: 'exact', head: true }).eq('user_id', user.id);
  if ((PLAN_PROJECT_LIMITS[role] || 3) !== 9999 && (count || 0) >= (PLAN_PROJECT_LIMITS[role] || 3)) return json(res, 403, { error: 'Project limit reached.' });

  const { error } = await supabaseAdmin.from('barrix_projects').insert({ user_id: user.id, title, brx_data, file_count: file_count || 0 });
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { success: true, action: 'created' });
}

async function routeListProjects(req, res) {
  if (req.method !== 'GET') return json(res, 405, { error: 'GET only' });
  const user = await getUser(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const { data, error } = await supabaseAdmin.from('barrix_projects').select('id, title, updated_at, file_count, brx_data').eq('user_id', user.id).order('updated_at', { ascending: false });
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, data || []);
}

async function routeDeleteProject(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'POST only' });
  const user = await getUser(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const { error } = await supabaseAdmin.from('barrix_projects').delete().eq('id', req.body.id).eq('user_id', user.id);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { success: true });
}

async function routeCheckout(req, res) {
  if (!stripe) return json(res, 500, { error: 'Stripe unconfigured' });
  const user = await getUser(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const price_id = req.body?.price_id || req.body?.priceId;
  const product = String(req.body?.product || '').toLowerCase();
  
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: price_id, quantity: 1 }],
      success_url: `${process.env.FRONTEND_URL || 'https://www.dustdelux.com'}${product.startsWith('crux_') ? '/crux/main.html?checkout=success' : '/barrix/barrix-dashboard.html?checkout=success'}`,
      cancel_url:  `${process.env.FRONTEND_URL || 'https://www.dustdelux.com'}${product.startsWith('crux_') ? '/crux/main.html?checkout=cancelled' : '/barrix/barrix-dashboard.html?checkout=cancelled'}`,
      client_reference_id: user.id, customer_email: user.email, metadata: { supabase_user_id: user.id, product: product || 'barrix' }
    });
    return json(res, 200, { url: session.url });
  } catch (err) { return json(res, 500, { error: err.message }); }
}

async function routeStripeWebhook(req, res) {
  if (!stripe) return json(res, 500, { error: 'Stripe unconfigured' });
  const sig = req.headers['stripe-signature'];
  const rawBodyText = await rawBody(req);
  let event;
  try { event = stripe.webhooks.constructEvent(rawBodyText, sig, process.env.STRIPE_WEBHOOK_SECRET); } catch (err) { return json(res, 400, { error: err.message }); }

  const priceToRole = getPriceRoleMap();
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata?.supabase_user_id || session.client_reference_id;
    let priceId = session.line_items?.data?.[0]?.price?.id || null;
    if (!priceId && session.id) {
      try { const full = await stripe.checkout.sessions.retrieve(session.id, { expand: ['line_items.data.price'] }); priceId = full.line_items?.data?.[0]?.price?.id || null; } catch (_) {}
    }
    const role = priceToRole[priceId];
    if (userId && role) await supabaseAdmin.from('profiles').update({ role }).eq('id', userId);
  }
  if (event.type === 'customer.subscription.deleted') {
    const userId = event.data.object.metadata?.supabase_user_id;
    if (userId) await supabaseAdmin.from('profiles').update({ role: 'free' }).eq('id', userId);
  }
  return json(res, 200, { received: true });
}

async function routeRegister(req, res) {
  const { email, password, display_name, heard_from } = req.body;
  const { data, error } = await supabaseAdmin.auth.admin.createUser({ email, password, email_confirm: false, user_metadata: { display_name: display_name || email.split('@')[0] } });
  if (error) return json(res, 400, { error: error.message });
  await supabaseAdmin.from('profiles').upsert({ id: data.user.id, display_name: display_name || email.split('@')[0], role: 'free', heard_from: heard_from || '' });
  return json(res, 200, { success: true, user: { id: data.user.id, email: data.user.email } });
}

async function routeUsage(req, res) {
  const user = await getUser(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const now = new Date();
  const monthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

  if (req.method === 'GET') {
    const { data } = await supabaseAdmin.from('barrix_usage').select('requests, saves, exports, publishes').eq('user_id', user.id).eq('month', monthKey).single();
    return json(res, 200, data || { requests: 0, saves: 0, exports: 0, publishes: 0, month: monthKey });
  }
  const col = { request: 'requests', save: 'saves', export: 'exports', publish: 'publishes' }[req.body?.action];
  if (!col) return json(res, 400, { error: 'Invalid action' });
  const { data: existing } = await supabaseAdmin.from('barrix_usage').select('id, ' + col).eq('user_id', user.id).eq('month', monthKey).single();
  if (existing) await supabaseAdmin.from('barrix_usage').update({ [col]: (existing[col] || 0) + 1 }).eq('id', existing.id);
  else await supabaseAdmin.from('barrix_usage').insert({ user_id: user.id, month: monthKey, [col]: 1 });
  return json(res, 200, { success: true });
}

async function routeGenerateImage(req, res) {
  const user = await getUser(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const authTier = req.headers['x-auth-tier'] || 'platform';
  if (authTier === 'subuser' && req.headers['x-app-id']) {
    const { data } = await supabaseAppsAdmin.from('app_users').select('role').eq('auth_user_id', user.id).eq('app_id', req.headers['x-app-id']).single();
    if (!data) return json(res, 403, { error: 'Access Denied' });
  }

  const { bot, prompt } = req.body;
  try {
    const proxyRes = await fetch(process.env.POE_PROXY_URL || 'https://enos.dustdelux.com/poe-proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Auth-Tier': authTier, 'X-App-Id': req.headers['x-app-id'] || '' },
      body: JSON.stringify({ bot, model: bot, message: prompt, messages: [{ role: 'user', content: prompt }], stream: false })
    });
    return json(res, proxyRes.status, await proxyRes.json());
  } catch(e) { return json(res, 500, { error: e.message }); }
}

async function routeAIProxy(req, res) {
  const user = await getUser(req);
  if (!user) return json(res, 401, { error: 'Security perimeter authorization failure.' });

  const authTier = req.headers['x-auth-tier'] || 'platform';
  const appId = req.headers['x-app-id'];
  if (authTier === 'subuser') {
    if (!appId) return json(res, 400, { error: 'Multi-tenant requests require an X-App-Id header signature.' });
    const { data } = await supabaseAppsAdmin.from('app_users').select('role').eq('auth_user_id', user.id).eq('app_id', appId).single();
    if (!data) return json(res, 403, { error: 'Access denied.' });
  }

  const currentPath = getRequestPath(req);
  const isGemini = currentPath.includes('gemini');
  let targetUrl = '';
  let upstreamHeaders = { 'Content-Type': 'application/json' };
  let requestPayload = '';

  if (isGemini) {
    if (!process.env.GEMINI_API_KEY) return json(res, 500, { error: 'GEMINI_API_KEY unconfigured.' });
    const mappedModel = GEMINI_MODEL_MAPPING[req.body.model] || req.body.model || 'gemini-2.5-flash';
    targetUrl = `https://generativelanguage.googleapis.com/v1beta/models/${mappedModel}:${req.body.stream ? 'streamGenerateContent' : 'generateContent'}?key=${process.env.GEMINI_API_KEY}${req.body.stream ? '&alt=sse' : ''}`;
    
    // POLYMORPHIC GEMINI CONTENT PARSER: Accept raw array parts or convert plain text payloads cleanly
    if (req.body.contents && Array.isArray(req.body.contents)) {
      requestPayload = JSON.stringify({ contents: req.body.contents, generationConfig: req.body.generationConfig || { temperature: 0.7, maxOutputTokens: 8192 } });
    } else {
      requestPayload = JSON.stringify({ contents: [{ parts: [{ text: req.body.message || req.body.prompt || '' }] }], generationConfig: { temperature: 0.7, maxOutputTokens: 8192 } });
    }
  } else {
    if (!process.env.POE_API_KEY) return json(res, 500, { error: 'POE_API_KEY unconfigured.' });
    targetUrl = 'https://api.poe.com/v1/chat/completions';
    upstreamHeaders['Authorization'] = `Bearer ${process.env.POE_API_KEY}`;
    requestPayload = JSON.stringify(req.body);
  }

  try {
    const proxyRes = await fetch(targetUrl, { method: 'POST', headers: upstreamHeaders, body: requestPayload });
    if (req.body.stream && proxyRes.body) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      Readable.fromWeb(proxyRes.body).pipe(res); // Streaming buffer node-adapted pipeline fixed
      return;
    }
    return json(res, proxyRes.status, await proxyRes.json());
  } catch (err) { return json(res, 500, { error: err.message }); }
}

async function routeGitHubAuth(req, res) {
  const state = encodeState({ ts: Date.now(), nonce: crypto.randomBytes(12).toString('hex') });
  const authUrl = new URL('https://github.com/login/oauth/authorize');
  authUrl.searchParams.set('client_id', process.env.GITHUB_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', getCallbackUrl(req));
  authUrl.searchParams.set('scope', process.env.GITHUB_OAUTH_SCOPE || 'repo read:user user:email');
  authUrl.searchParams.set('state', state);
  return json(res, 200, { url: authUrl.toString(), callbackOrigin: new URL(getCallbackUrl(req)).origin });
}

async function routeGitHubCallback(req, res) {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  try {
    const query = getRequestQuery(req);
    decodeState(query.state);
    const accessToken = await exchangeGitHubCode(req, query.code);
    const githubUser = await fetchGitHubUser(accessToken);
    return res.status(200).send(buildPopupPage({ githubAccessToken: accessToken, githubUser: githubUser?.login || null }));
  } catch (err) { return res.status(200).send(buildPopupPage({ error: err.message })); }
}

async function routeGitHubSaveToken(req, res) {
  const user = await getUser(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const githubAccessToken = req.body?.github_access_token;
  try {
    const githubUser = await fetchGitHubUser(githubAccessToken);
    const encrypted = encryptGitHubToken(githubAccessToken);
    await supabaseAdmin.from('github_connections').upsert({ user_id: user.id, github_login: githubUser.login || null, github_user_id: githubUser.id ? String(githubUser.id) : null, access_token_ciphertext: encrypted.ciphertext, access_token_iv: encrypted.iv, access_token_tag: encrypted.tag, scopes: process.env.GITHUB_OAUTH_SCOPE || null, updated_at: new Date().toISOString() }, { onConflict: 'user_id' });
    return json(res, 200, { success: true, github_login: githubUser.login || null });
  } catch (err) { return json(res, 500, { error: err.message }); }
}

async function routeEnableAuth(req, res) {
  const { appId, user_id } = req.body;
  const { error: userErr } = await supabaseAppsAdmin.from('app_users').upsert({ app_id: appId, auth_user_id: user_id, role: 'creator' }, { onConflict: 'app_id,auth_user_id' });
  if (userErr) return json(res, 500, { error: userErr.message });
  await supabaseAppsAdmin.from('gated_components').upsert({ app_id: appId, component_id: 'default', component_key: 'default', allowed_roles: ['creator', 'admin', 'user'] }, { onConflict: 'app_id,component_id' });
  return json(res, 200, { success: true });
}

async function routeAppSignup(req, res) {
  const { appId, email, password, username, avatar_url, appName, primaryColor, redirectTo } = req.body;
  try {
    const { data: userData, error: userErr } = await supabaseAppsAdmin.auth.admin.createUser({ email, password, email_confirm: false, user_metadata: { app_id: appId } });
    if (userErr) return json(res, 400, { error: userErr.message });
    const { count } = await supabaseAppsAdmin.from('app_users').select('id', { count: 'exact', head: true }).eq('app_id', appId);
    const role = count === 0 ? 'creator' : 'user';
    await supabaseAppsAdmin.from('app_users').insert({ app_id: appId, auth_user_id: userData.user.id, role, username: username || email.split('@')[0], avatar_url: avatar_url || '' });
    return json(res, 200, { success: true, user: { id: userData.user.id, email }, role });
  } catch (err) { return json(res, 500, { error: err.message }); }
}

async function routeGateComponent(req, res) {
  const { appId, component_key, component_id, allowed_roles } = req.body;
  const rolesArray = Array.isArray(allowed_roles) ? allowed_roles : (allowed_roles || 'creator,admin,user').split(',').map(r => r.trim());
  const { error } = await supabaseAppsAdmin.from('gated_components').upsert({ app_id: appId, component_id: component_id || component_key, component_key, allowed_roles: rolesArray, updated_at: new Date().toISOString() }, { onConflict: 'app_id,component_id' });
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { success: true });
}

async function routeGetGatedComponents(req, res) {
  const { data, error } = await supabaseAppsAdmin.from('gated_components').select('*').eq('app_id', getRequestQuery(req).appId);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, data || []);
}

async function routeHFGenerate(req, res) {
  const token = process.env.HF_TOKEN || process.env.HUGGINGFACE_API_KEY;
  const response = await fetch(`https://api-inference.huggingface.co/models/${req.body.model || 'black-forest-labs/FLUX.1-schnell'}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(token && { 'Authorization': `Bearer ${token}` }) }, body: JSON.stringify({ inputs: req.body.prompt }) });
  if (!response.ok) return json(res, response.status, { error: await response.text() });
  res.setHeader('Content-Type', response.headers.get('content-type') || 'image/jpeg');
  return res.send(Buffer.from(await response.arrayBuffer()));
}

async function routePoeAdapterScript(req, res) {
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  return res.status(200).send(`window.POE_ADAPTER_CONFIG={proxyUrl:'https://enos.dustdelux.com/poe-proxy',debug:false};`);
}

const ROUTES = {
  '/poe-adapter.js':      routePoeAdapterScript,
  '/config':              routeConfig,
  '/profile':             routeProfile,
  '/update-profile':      routeUpdateProfile,
  '/save-project':        routeSaveProject,
  '/list-projects':       routeListProjects,
  '/delete-project':      routeDeleteProject,
  '/checkout':            routeCheckout,
  '/stripe-webhook':      routeStripeWebhook,
  '/register':            routeRegister,
  '/usage':               routeUsage,
  '/generate-image':      routeGenerateImage,
  '/hf-generate':         routeHFGenerate,
  '/github/auth':         routeGitHubAuth,
  '/github/callback':     routeGitHubCallback,
  '/github/save-token':   routeGitHubSaveToken,
  '/poe-proxy':           routeAIProxy,
  '/gemini':              routeAIProxy,
  '/enable-auth':         routeEnableAuth,
  '/app-user/register':   routeAppSignup,
  '/gate-component':      routeGateComponent,
  '/gated-components':    routeGetGatedComponents,
};

// ─────────────────────────────────────────────────────────────
// Main Execution Interceptor
// ─────────────────────────────────────────────────────────────
export default async function handler(req, res) {
  try {
    // 1. ABSOLUTE TOP-LEVEL CORS - Pulls from Env Variable first, falls back to hardcoded list if missing
    const origin = req.headers.origin || '';
    const ALLOWED = process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',').map(url => url.trim())
      : [
          'https://www.dustdelux.com',
          'https://dustdelux.com',
          'https://barrix.dustdelux.com',
          'https://crux.dustdelux.com',
          'http://localhost:3000'
        ];
    // Overwrite the module-level list so downstream cors() uses the computed set
    ALLOWED_ORIGINS = ALLOWED;

    // 2. Protected CORS Injection
    cors(req, res);
    
    // 2. Handle Preflight Safely
    if (req.method === 'OPTIONS') {
      res.setHeader('Content-Length', '2');
      return res.status(200).send('OK');
    }

    // 3. Resolve Route
    const path = getRequestPath(req);
    const routeHandler = ROUTES[path];
    
    if (!routeHandler) {
      return res.status(404).json({ error: `Unknown route: ${path}` });
    }
    
    await routeHandler(req, res);
  } catch (err) {
    console.error('[barrix-api] FATAL PIPELINE CRASH:', err);
    // Explicitly fallback header injection in case of a deep crash
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    return res.status(500).json({ error: 'Internal pipeline error', message: err.message });
  }
}

export const config = { api: { bodyParser: { sizeLimit: '20mb' } } };