// functions/verify.js
export async function onRequestPost({ request, env }) {
  try {
    const { code } = await request.json();

    const input = normalize(code);
    const ACCESS_CODE = normalize(env.ACCESS_CODE || "0203"); // ✅ 放 env 更安全
    if (input !== ACCESS_CODE) {
      return json({ error: "Invalid access code." }, 401);
    }

    // ✅ 生成两段 token：payloadB64.sigB64
    const exp = Date.now() + 1000 * 60 * 60 * 24 * 7; // 7天
    const payload = { exp };
    const payloadB64 = base64url(JSON.stringify(payload));

    const sigB64 = await hmacSignB64url(payloadB64, env.SIGNING_KEY);
    const token = `${payloadB64}.${sigB64}`;

    const next = `/go?token=${encodeURIComponent(token)}`;

    return json({ token, next }, 200);
  } catch (e) {
    return json({ error: "Bad request." }, 400);
  }
}

function normalize(s) {
  return (s || "").toString().trim().toUpperCase().replace(/\s+/g, "");
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function base64url(str) {
  const b64 = btoa(unescape(encodeURIComponent(str)));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hmacSignB64url(message, signingKey) {
  if (!signingKey) throw new Error("Missing SIGNING_KEY");

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(signingKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  const bytes = new Uint8Array(sig);
  return toBase64url(bytes);
}

function toBase64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
