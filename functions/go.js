export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const t = url.searchParams.get("t");

  if (!env.TOKENS || !env.FORM_URL) {
    return new Response("Missing bindings", { status: 500 });
  }
  if (!t) return new Response("Bad Request", { status: 400 });

  const key = `t:${t}`;
  const ok = await env.TOKENS.get(key);

  if (!ok) {
    return new Response("Expired or invalid token", { status: 403 });
  }

  // 一次性：用完即删
  await env.TOKENS.delete(key);

  return Response.redirect(env.FORM_URL, 302);
}
