function norm(s) {
  return (s || "").trim().toUpperCase().replace(/\s+/g, "");
}

function newToken() {
  const a = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(a).map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function onRequest({ request, env }) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  let body = {};
  try { body = await request.json(); } catch (_) {}

  const code = norm(body.code);
  const access = norm(env.ACCESS_CODE);

  if (!access || !env.FORM_URL) {
    return new Response("Missing env vars", { status: 500 });
  }
  if (!env.TOKENS) {
    return new Response("Missing KV binding TOKENS", { status: 500 });
  }

  if (code !== access) {
    return new Response(JSON.stringify({ ok: false }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const t = newToken();
  // 10 分钟有效期
  await env.TOKENS.put(`t:${t}`, "1", { expirationTtl: 600 });

  return new Response(JSON.stringify({ ok: true, next: `/go?t=${t}` }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
