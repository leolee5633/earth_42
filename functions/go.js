export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  if (!token) return new Response("Missing token", { status: 400 });

  // 这里复用你现有的 token 校验逻辑（略）
  // 假设你已经有 verifyToken(token, env.SIGNING_KEY) -> payload or null
  const payload = await verifyToken(token, env.SIGNING_KEY);
  if (!payload) return new Response("Invalid token", { status: 401 });

  // ✅ 写 Cookie：HttpOnly + SameSite=Lax（允许从石墨跳回时携带）
  const cookie = [
    `invite=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=604800" // 7天
  ].join("; ");

  return Response.redirect(env.FORM_URL, 302, {
    headers: { "Set-Cookie": cookie }
  });
}

async function verifyToken(token, signingKey) {
  try {
    if (!token || token.indexOf(".") === -1) return false;
    if (!signingKey) return false;

    const [payloadB64, sigB64] = token.split(".");

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
