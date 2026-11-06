// Relays checks from pages to the local inspect server. Requests go from
// here rather than the content script so they carry the extension's origin,
// which the server requires, and so the token never touches the page.

const api = globalThis.browser ?? globalThis.chrome;

async function settings() {
  return api.storage.local.get({ port: 7878, token: "" });
}

async function call(path, body) {
  const { port, token } = await settings();
  if (!token) {
    return { error: "inspect isn't paired yet. Run `inspect serve` and paste its token into the inspect extension's popup." };
  }
  let res;
  try {
    res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: body ? "POST" : "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    return { error: `Can't reach inspect on port ${port}. Start it with: inspect serve` };
  }
  if (res.status === 401) {
    return { error: "inspect rejected the token. Paste the token printed by `inspect serve` into the popup." };
  }
  if (!res.ok) {
    return { error: `inspect answered ${res.status}: ${(await res.text()).trim()}` };
  }
  return res.json();
}

api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "check") {
    call("/v1/check", msg.payload).then(sendResponse);
    return true; // the answer is sent asynchronously
  }
  if (msg?.type === "status") {
    call("/v1/status", null).then(sendResponse);
    return true;
  }
  return false;
});
