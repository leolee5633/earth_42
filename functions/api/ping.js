export async function onRequest() {
  return new Response("PING_OK", { status: 200 });
}
