// functions/go.js
export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);

  const invite = url.searchParams.get("token") || url.searchParams.get("t");
  if (!invite) return new Response("Missing token", { status: 400 });

  const ok = await verifyToken(invite, env.SIGNING_KEY);
  if (!ok) return new Response("Invalid token", { status: 401 });

  const location = env.FORM_URL;
  if (!location) return new Response("Missing FORM_URL", { status: 500 });

  const headers = new Headers();
  headers.set("Location", location);

  headers.append(
    "Set-Cookie",
    `invite=${encodeURIComponent(invite)}; Path=/; Max-Age=604800; HttpOnly; Secure; SameSite=Lax`
  );

  headers.set("Cache-Control", "no-store");

  return new Response(null, { status: 302, headers });
}

// ====== 两段 token 校验：payloadB64.sigB64 ======
async function verifyToken(token, signingKey) {
  try {
    if (!token || token.indexOf(".") === -1) return false;
    if (!signingKey) return false;

    const [payloadB64, sigB64] = token.split(".");
    if (!payloadB64 || !sigB64) return false;

    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(signingKey),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const sigBytes = unbase64url(sigB64);
    const ok = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes.buffer,
      enc.encode(payloadB64)
    );
    if (!ok) return false;

    const payloadJson = new TextDecoder().decode(unbase64url(payloadB64));
    const payload = JSON.parse(payloadJson);
    if (!payload.exp || Date.now() > payload.exp) return false;

    return true;
  } catch (e) {
    return false;
  }
}

function unbase64url(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
  const str = atob(b64 + pad);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
}
