export async function onRequestPost({ request, env }) {
  let body = {};
  try { body = await request.json(); } catch {}
  const code = (body.code || "").toUpperCase().trim();
  if (!code) return new Response("Missing code", { status: 400 });

  const raw = await env.PARTY_KV.get(`code:${code}`);
  if (!raw) return new Response("Invalid code", { status: 401 });

  const data = JSON.parse(raw);
  const unlockAt = new Date(data.unlockAt).getTime();
  const now = Date.now();
  const msLeft = unlockAt - now;

  const unlocked = msLeft <= 0;
  const daysLeft = Math.max(0, Math.ceil(msLeft / (1000 * 60 * 60 * 24)));

  return json({
    unlocked,
    daysLeft,
    unlockAt: data.unlockAt,
    location: unlocked ? data.location : null
  });
}

function json(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}
