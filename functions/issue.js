export async function onRequestPost({ request, env }) {
  const token = getCookie(request, "invite");
  if (!token) return new Response("No invite cookie", { status: 401 });

  const payload = await verifyToken(token, env.SIGNING_KEY);
  if (!payload) return new Response("Invalid invite", { status: 401 });

  // 以 token 为“身份”，做幂等：同一个人多次回来拿到同一个个人密码
  const issuedKey = `issued:${hash(token)}`;
  let code = await env.PARTY_KV.get(issuedKey);

  if (!code) {
    code = genCode6(); // 个人密码
    const unlockAt = env.UNLOCK_AT || "2026-01-30T12:00:00+08:00";
    const location = env.LOCATION || "Location will be revealed.";

    // code -> 状态
    await env.PARTY_KV.put(`code:${code}`, JSON.stringify({
      unlockAt,
      location
    }), { expirationTtl: 60 * 60 * 24 * 14 }); // 14天可按需

    // token -> code（幂等）
    await env.PARTY_KV.put(issuedKey, code, { expirationTtl: 60 * 60 * 24 * 14 });
  }

  return json({ code });
}

function json(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return m ? decodeURIComponent(m[1]) : "";
}

/** 占位：用你现有 token 校验逻辑替换 */
async function verifyToken(token, signingKey) {
  return token && signingKey ? { ok: true } : null;
}

function genCode6() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < 6; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

// 轻量 hash：够用做 key（不追求密码学强度）
function hash(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16);
}
