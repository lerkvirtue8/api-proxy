/**
 * Health-check endpoint.
 * GET /api/health → {"status":"ok","timestamp":"...","services":{...}}
 */

export const config = { runtime: "edge" };

export default async function handler(req) {
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Requested-With",
  };

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  const body = {
    status: "ok",
    timestamp: new Date().toISOString(),
    services: {
      poe: !!process.env.POE_API_KEY,
      gemini: !!process.env.GEMINI_API_KEY,
      auth_supabase: !!process.env.SUPABASE_JWT_SECRET,
      auth_proxy_secret: !!process.env.PROXY_SECRET,
    },
  };

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}
