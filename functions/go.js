export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);

  // token 由 /verify 发放，存到 cookie 里，后续 /issue /status 都靠它
  const invite = url.searchParams.get("t") || url.searchParams.get("token");
  if (!invite) return new Response("Missing token", { status: 400 });

  const location = env.FORM_URL; // 你的石墨问卷链接（放 env，不要写前端）

  const headers = new Headers();
  headers.set("Location", location);

  // 关键：SameSite=Lax，Path=/，Secure（pages.dev 是 https）
  headers.append(
    "Set-Cookie",
    `invite=${encodeURIComponent(invite)}; Path=/; Max-Age=604800; HttpOnly; Secure; SameSite=Lax`
  );

  return new Response(null, { status: 302, headers });
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
