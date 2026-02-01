export async function onRequestPost({ request, env }) {
  try {
    const { code } = await request.json();

    const input = String(code || "").trim();
    const expected = String(env.ACCESS_CODE || "").trim();
    if (!expected) return new Response("Server not configured.", { status: 500 });

    if (input !== expected) return new Response("Invalid access code.", { status: 401 });

    // 10分钟有效 token
    const exp = Date.now() + 10 * 60 * 1000;
    const payload = JSON.stringify({ exp });
    const token = await signToken(payload, env.SIGNING_KEY);

    return new Response(JSON.stringify({ token }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response("Bad request.", { status: 400 });
  }
}

async function signToken(payloadJson, signingKey) {
  if (!signingKey) throw new Error("Missing SIGNING_KEY");

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(signingKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const payloadB64 = base64url(enc.encode(payloadJson));
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payloadB64));
  const sigB64 = base64url(new Uint8Array(sig));

  return `${payloadB64}.${sigB64}`;
}

function base64url(bytes) {
  let str = "";
  bytes.forEach((b) => (str += String.fromCharCode(b)));
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
