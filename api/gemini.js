/**
 * Barrix Gemini API Proxy — Vercel Edge Function
 *
 * Proxies requests to Google's Generative Language API and streams SSE back.
 * The response format is passed through as-is since the Barrix client already
 * parses Gemini-native SSE: candidates[0].content.parts[0].text
 *
 * Environment variables:
 *   GEMINI_API_KEY        — Required. Your Google AI / Gemini API key.
 *   SUPABASE_JWT_SECRET   — Optional. Verify Supabase JWTs.
 *   PROXY_SECRET          — Optional. Accept a static shared secret.
 *   ALLOWED_ORIGINS       — Optional. Comma-separated origins (default: *)
 */

export const config = {
  runtime: "edge",
  maxDuration: 300,
};

// ─── CORS ────────────────────────────────────────────────────────────────────

function getAllowedOrigin(req) {
  const allowed = (process.env.ALLOWED_ORIGINS || "*").trim();
  if (allowed === "*") return "*";
  const origin = req.headers.get("Origin") || "";
  const list = allowed.split(",").map((s) => s.trim());
  return list.includes(origin) ? origin : list[0];
}

function corsHeaders(req) {
  return {
    "Access-Control-Allow-Origin": getAllowedOrigin(req),
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Requested-With",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonRes(req, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(req), "Content-Type": "application/json" },
  });
}

// ─── Auth (mirrors poe-proxy.js) ────────────────────────────────────────────

async function verifyAuth(req) {
  if (!process.env.SUPABASE_JWT_SECRET && !process.env.PROXY_SECRET) {
    return { ok: true };
  }

  const hdr = req.headers.get("Authorization");
  if (!hdr || !hdr.startsWith("Bearer ")) {
    return { ok: false, err: "Missing Authorization header" };
  }
  const token = hdr.slice(7);

  if (process.env.PROXY_SECRET && token === process.env.PROXY_SECRET) {
    return { ok: true };
  }

  if (process.env.SUPABASE_JWT_SECRET) {
    try {
      const [hB64, pB64, sB64] = token.split(".");
      if (!hB64 || !pB64 || !sB64) {
        return { ok: false, err: "Malformed JWT" };
      }
      const payload = JSON.parse(decodeBase64Url(pB64));
      if (payload.exp && payload.exp < Date.now() / 1000) {
        return { ok: false, err: "Token expired" };
      }
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(process.env.SUPABASE_JWT_SECRET),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"],
      );
      const sigInput = new TextEncoder().encode(`${hB64}.${pB64}`);
      const sigBytes = base64UrlToUint8(sB64);
      const valid = await crypto.subtle.verify(
        "HMAC",
        key,
        sigBytes,
        sigInput,
      );
      return valid
        ? { ok: true, payload }
        : { ok: false, err: "Invalid JWT signature" };
    } catch (e) {
      return { ok: false, err: "JWT error: " + e.message };
    }
  }

  return { ok: false, err: "No valid auth method matched" };
}

function decodeBase64Url(str) {
  return atob(str.replace(/-/g, "+").replace(/_/g, "/"));
}

function base64UrlToUint8(str) {
  const bin = decodeBase64Url(str);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// ─── Main handler ────────────────────────────────────────────────────────────

export default async function handler(req) {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(req) });
  }
  if (req.method !== "POST") {
    return jsonRes(req, { error: "Method not allowed" }, 405);
  }

  const auth = await verifyAuth(req);
  if (!auth.ok) {
    return jsonRes(req, { error: auth.err }, 401);
  }

  let body;
  try {
    body = await req.json();
  } catch {
    return jsonRes(req, { error: "Invalid JSON body" }, 400);
  }

  const { model, message, stream } = body;
  const geminiModel = model || "gemini-2.5-flash";
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    return jsonRes(
      req,
      { error: "GEMINI_API_KEY not configured on server" },
      500,
    );
  }

  if (!message) {
    return jsonRes(req, { error: "Missing message parameter" }, 400);
  }

  // Truncate to safe limit (same as client-side 120 000 char cap)
  const MAX_CHARS = 120000;
  let text = message;
  if (text.length > MAX_CHARS) {
    text =
      text.slice(0, MAX_CHARS) + "\n\n[Content truncated due to size limits]";
  }

  // ── Build Gemini API URL ─────────────────────────────────────────────────
  const isStream = stream !== false;
  const action = isStream ? "streamGenerateContent" : "generateContent";
  const params = new URLSearchParams({ key: apiKey });
  if (isStream) params.set("alt", "sse");

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${geminiModel}:${action}?${params}`;

  // ── Build request body ───────────────────────────────────────────────────
  const geminiBody = {
    contents: [
      {
        parts: [{ text }],
      },
    ],
  };

  // Forward optional generation config
  if (body.generationConfig) {
    geminiBody.generationConfig = body.generationConfig;
  }
  if (body.safetySettings) {
    geminiBody.safetySettings = body.safetySettings;
  }
  // Support system instruction passthrough
  if (body.systemInstruction) {
    geminiBody.systemInstruction = body.systemInstruction;
  }

  // ── Call Gemini ──────────────────────────────────────────────────────────
  let gemRes;
  try {
    gemRes = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(geminiBody),
    });
  } catch (fetchErr) {
    return jsonRes(
      req,
      { error: "Upstream network error: " + fetchErr.message },
      502,
    );
  }

  if (!gemRes.ok) {
    const errText = await gemRes.text().catch(() => "");
    return jsonRes(
      req,
      { error: `Gemini API ${gemRes.status}: ${errText.slice(0, 500)}` },
      gemRes.status >= 400 && gemRes.status < 600 ? gemRes.status : 502,
    );
  }

  // ── Non-streaming ────────────────────────────────────────────────────────
  if (!isStream) {
    const data = await gemRes.json();
    return jsonRes(req, data);
  }

  // ── Streaming: passthrough SSE with CORS headers ─────────────────────────
  // Gemini returns SSE natively in the format the client already parses:
  //   data: {"candidates":[{"content":{"parts":[{"text":"..."}]}}]}
  return new Response(gemRes.body, {
    status: 200,
    headers: {
      ...corsHeaders(req),
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "X-Accel-Buffering": "no",
    },
  });
}
