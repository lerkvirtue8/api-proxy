/**
 * Barrix Poe API Proxy — Vercel Edge Function
 *
 * Proxies chat + image-generation requests to Poe's OpenAI-compatible API
 * and transforms responses into the SSE format that Barrix IDE expects:
 *
 *   data: {"text":"<accumulated>","content":"<delta>"}          (text bots)
 *   data: {"text":"","content":"","attachments":[{url,mimeType}]}  (image bots)
 *   data: [DONE]
 *
 * Environment variables (set in Vercel dashboard):
 *   POE_API_KEY          — Required. Your Poe API key.
 *   POE_API_BASE         — Optional. Override API base URL (default: https://api.poe.com)
 *   SUPABASE_JWT_SECRET  — Optional. If set, Bearer tokens are verified as Supabase JWTs.
 *   PROXY_SECRET         — Optional. If set, this static token is also accepted.
 *   ALLOWED_ORIGINS      — Optional. Comma-separated origins. Default: * (allow all).
 */

export const config = {
  runtime: "edge",
  // Pro plan: up to 300 s. Hobby: 30 s (streaming keeps it alive after first byte).
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
      "Content-Type, Authorization, X-Requested-With, X-Client-Info, apikey",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonRes(req, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(req), "Content-Type": "application/json" },
  });
}

// ─── Auth ────────────────────────────────────────────────────────────────────

async function verifyAuth(req) {
  // No secrets configured → open proxy (dev mode)
  if (!process.env.SUPABASE_JWT_SECRET && !process.env.PROXY_SECRET) {
    return { ok: true };
  }

  const hdr = req.headers.get("Authorization");
  if (!hdr || !hdr.startsWith("Bearer ")) {
    return { ok: false, err: "Missing Authorization header" };
  }
  const token = hdr.slice(7);

  // Static shared secret
  if (process.env.PROXY_SECRET && token === process.env.PROXY_SECRET) {
    return { ok: true };
  }

  // Supabase HS256 JWT verification (no SDK needed)
  if (process.env.SUPABASE_JWT_SECRET) {
    try {
      const [hB64, pB64, sB64] = token.split(".");
      if (!hB64 || !pB64 || !sB64) {
        return { ok: false, err: "Malformed JWT" };
      }

      // Decode payload
      const payload = JSON.parse(
        decodeBase64Url(pB64),
      );

      // Expiry check
      if (payload.exp && payload.exp < Date.now() / 1000) {
        return { ok: false, err: "Token expired" };
      }

      // HMAC-SHA256 signature verification
      let jwtSecretBytes;
      try {
        const padded = process.env.SUPABASE_JWT_SECRET.replace(/-/g, "+").replace(/_/g, "/");
        const bin = atob(padded);
        jwtSecretBytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      } catch (e) {
        jwtSecretBytes = new TextEncoder().encode(process.env.SUPABASE_JWT_SECRET);
      }
      const key = await crypto.subtle.importKey(
        "raw",
        jwtSecretBytes,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"],
      );
      const sigInput = new TextEncoder().encode(`${hB64}.${pB64}`);
      const sigBytes = base64UrlToUint8(sB64);
      const valid = await crypto.subtle.verify("HMAC", key, sigBytes, sigInput);

      return valid
        ? { ok: true, payload }
        : { ok: false, err: "Invalid JWT signature" };
    } catch (e) {
      return { ok: false, err: "JWT verification failed: " + e.message };
    }
  }

  return { ok: false, err: "No valid auth method matched" };
}

function decodeBase64Url(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  return atob(padded);
}

function base64UrlToUint8(str) {
  const bin = decodeBase64Url(str);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// ─── Main handler ────────────────────────────────────────────────────────────

export default async function handler(req) {
  // Preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(req) });
  }
  if (req.method !== "POST") {
    return jsonRes(req, { error: "Method not allowed" }, 405);
  }

  // Auth gate
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

  const { bot, model, message, messages, stream } = body;
  const botName = bot || model;

  if (!botName) {
    return jsonRes(req, { error: "Missing bot/model parameter" }, 400);
  }

  const msgArray =
    messages && messages.length > 0
      ? messages
      : [{ role: "user", content: message || "" }];

  const apiKey = process.env.POE_API_KEY;
  if (!apiKey) {
    return jsonRes(req, { error: "POE_API_KEY not configured on server" }, 500);
  }

  const poeBase = (process.env.POE_API_BASE || "https://api.poe.com").replace(
    /\/$/,
    "",
  );

  // ── Forward to Poe ───────────────────────────────────────────────────────
  let poeRes;
  try {
    poeRes = await fetch(`${poeBase}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: botName,
        messages: msgArray,
        stream: stream !== false,
        ...(body.temperature != null ? { temperature: body.temperature } : {}),
        ...(body.max_tokens != null ? { max_tokens: body.max_tokens } : {}),
      }),
    });
  } catch (fetchErr) {
    return jsonRes(
      req,
      { error: "Upstream network error: " + fetchErr.message },
      502,
    );
  }

  if (!poeRes.ok) {
    const errText = await poeRes.text().catch(() => "");
    return jsonRes(
      req,
      { error: `Poe API ${poeRes.status}: ${errText.slice(0, 500)}` },
      poeRes.status >= 400 && poeRes.status < 600 ? poeRes.status : 502,
    );
  }

  // ── Non-streaming ────────────────────────────────────────────────────────
  if (stream === false) {
    const data = await poeRes.json();
    const content =
      data.choices?.[0]?.message?.content ||
      data.text ||
      data.content ||
      "";
    const attachments = extractAttachments(content);
    return jsonRes(req, {
      text: content,
      content,
      ...(attachments.length ? { attachments } : {}),
    });
  }

  // ── Streaming: transform Poe SSE → Barrix SSE ────────────────────────────
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc = new TextEncoder();

  // Kick off background stream processing (don't await — it feeds readable)
  transformStream(poeRes.body, writer, enc).catch(async (err) => {
    try {
      await writer.write(
        enc.encode(`data: ${JSON.stringify({ error: err.message })}\n\n`),
      );
    } catch {
      /* closed */
    }
    try {
      await writer.close();
    } catch {
      /* already closed */
    }
  });

  return new Response(readable, {
    status: 200,
    headers: {
      ...corsHeaders(req),
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "X-Accel-Buffering": "no",
    },
  });
}

// ─── SSE Transform ──────────────────────────────────────────────────────────

async function transformStream(body, writer, enc) {
  const reader = body.getReader();
  const dec = new TextDecoder();
  let buffer = "";
  let accumulated = "";

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += dec.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const raw of lines) {
        const line = raw.trim();

        // Skip event: lines (Poe native format) and blank lines
        if (!line || line.startsWith("event:")) continue;

        if (!line.startsWith("data:")) continue;
        const payload = line.slice(5).trim();

        if (payload === "[DONE]") {
          // Final: check for images in accumulated text
          const att = extractAttachments(accumulated);
          if (att.length) {
            await writer.write(
              enc.encode(
                `data: ${JSON.stringify({ text: accumulated, content: "", attachments: att })}\n\n`,
              ),
            );
          }
          await writer.write(enc.encode("data: [DONE]\n\n"));
          continue;
        }

        if (!payload) continue;

        try {
          const parsed = JSON.parse(payload);
          let delta = "";

          // OpenAI chat.completion.chunk format
          if (parsed.choices?.[0]?.delta?.content != null) {
            delta = parsed.choices[0].delta.content;
          }
          // Poe native "text" event format ({"text":"..."})
          else if (parsed.text != null) {
            // Could be accumulated if length > current accumulated
            if (parsed.text.length >= accumulated.length) {
              delta = parsed.text.slice(accumulated.length);
              accumulated = parsed.text;
            } else {
              delta = parsed.text;
              accumulated += delta;
            }
            // Already handled accumulation — emit and continue
            await writer.write(
              enc.encode(
                `data: ${JSON.stringify({ text: accumulated, content: delta })}\n\n`,
              ),
            );
            continue;
          }
          // Generic "content" field
          else if (parsed.content != null) {
            delta = parsed.content;
          }

          // Accumulate and emit
          if (delta || parsed.attachments) {
            accumulated += delta;
            const chunk = {
              text: accumulated,
              content: delta,
            };
            if (parsed.attachments?.length) {
              chunk.attachments = parsed.attachments;
            }
            await writer.write(
              enc.encode(`data: ${JSON.stringify(chunk)}\n\n`),
            );
          }
        } catch {
          // Unparseable JSON — forward raw so client's fallback regex can try
          await writer.write(enc.encode(`data: ${payload}\n\n`));
        }
      }
    }

    // Flush remainder
    if (buffer.trim()) {
      const rem = buffer.trim();
      if (rem.startsWith("data:")) {
        const p = rem.slice(5).trim();
        if (p && p !== "[DONE]") {
          try {
            const parsed = JSON.parse(p);
            const delta =
              parsed.choices?.[0]?.delta?.content ||
              parsed.text ||
              parsed.content ||
              "";
            if (delta) {
              accumulated += delta;
              await writer.write(
                enc.encode(
                  `data: ${JSON.stringify({ text: accumulated, content: delta })}\n\n`,
                ),
              );
            }
          } catch {
            await writer.write(enc.encode(`data: ${p}\n\n`));
          }
        }
      }
    }

    // Final [DONE] in case upstream didn't send one
    const att = extractAttachments(accumulated);
    if (att.length) {
      await writer.write(
        enc.encode(
          `data: ${JSON.stringify({ text: accumulated, content: "", attachments: att })}\n\n`,
        ),
      );
    }
  } finally {
    try {
      await writer.close();
    } catch {
      /* already closed */
    }
  }
}

// ─── Attachment extraction ──────────────────────────────────────────────────

function extractAttachments(text) {
  if (!text) return [];
  const seen = new Set();
  const out = [];

  const mimeFor = (url) => {
    const ext = (url.split(".").pop() || "").split("?")[0].toLowerCase();
    const map = {
      png: "image/png",
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      gif: "image/gif",
      webp: "image/webp",
      svg: "image/svg+xml",
    };
    return map[ext] || "image/png";
  };

  // Markdown images: ![alt](url)
  for (const m of text.matchAll(/!\[([^\]]*)\]\((https?:\/\/[^)]+)\)/g)) {
    if (!seen.has(m[2])) {
      seen.add(m[2]);
      out.push({ url: m[2], mimeType: mimeFor(m[2]), name: m[1] || "image" });
    }
  }

  // Known image CDN URLs (poecdn, fal.media, imgur, unsplash, oaidalleapi)
  const cdnRe =
    /(https?:\/\/(?:pfst\.cf2\.poecdn\.net|v3\.fal\.media|i\.imgur\.com|images\.unsplash\.com|oaidalleapiprodscus[^\s"']*|replicate\.delivery)[^\s"')]+)/gi;
  for (const m of text.matchAll(cdnRe)) {
    if (!seen.has(m[1])) {
      seen.add(m[1]);
      out.push({ url: m[1], mimeType: mimeFor(m[1]), name: "image" });
    }
  }

  // Generic image-extension URLs
  const extRe =
    /(https?:\/\/[^\s"'<>]+\.(?:png|jpg|jpeg|gif|webp)(?:\?[^\s"'<>]*)?)/gi;
  for (const m of text.matchAll(extRe)) {
    if (!seen.has(m[1])) {
      seen.add(m[1]);
      out.push({ url: m[1], mimeType: mimeFor(m[1]), name: "image" });
    }
  }

  return out;
}
