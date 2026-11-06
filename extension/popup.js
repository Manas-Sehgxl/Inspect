const api = globalThis.browser ?? globalThis.chrome;

const token = document.getElementById("token");
const port = document.getElementById("port");
const status = document.getElementById("status");

function show(text, ok) {
  status.textContent = text;
  status.className = ok ? "ok" : "bad";
}

async function save() {
  const p = Number(port.value) || 7878;
  await api.storage.local.set({ token: token.value.trim(), port: p });
}

async function test() {
  await save();
  show("Checking…", true);
  const resp = await api.runtime.sendMessage({ type: "status" });
  if (resp?.ok) show("Connected to inspect.", true);
  else show(resp?.error || "No answer.", false);
}

api.storage.local.get({ token: "", port: 7878 }).then((s) => {
  token.value = s.token;
  port.value = s.port;
});

document.getElementById("save").addEventListener("click", async () => {
  await save();
  show("Saved.", true);
});
document.getElementById("test").addEventListener("click", test);
