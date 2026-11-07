// Finds commands on the page that pipe a download into a shell, adds a
// "Check with inspect" button next to them, and warns when one is copied.
// All UI lives in shadow roots so page styles can't reach it, and results
// are inserted as text only, never as HTML.

(() => {
  const api = globalThis.browser ?? globalThis.chrome;

  // A rough first filter, kept in step with internal/fetch/downloads.go.
  // The local server makes the real decision.
  const RUNS_REMOTE = new RegExp(
    [
      String.raw`\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+(-\S+\s+)*)?(env\s+\S+\s+)*(ba|z|da|k)?sh\b`,
      String.raw`\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(python3?|perl|ruby|node)\b`,
      String.raw`\b(ba|z)?sh\s+(-s\s+)?<\(\s*(curl|wget)\b`,
      String.raw`\b(ba|z)?sh\s+-c\s+["']?\$\(\s*(curl|wget)\b`,
      String.raw`\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\|\s*(iex|Invoke-Expression)\b`,
      String.raw`\biex\s*\(\s*(irm|iwr)\b`,
      // Downloaded to a file, then run: curl ... -o get-docker.sh; sh get-docker.sh
      String.raw`\b(curl|wget)\b[^\n]*\s-[a-zA-Z]*[oO]\s*\S+[\s\S]{0,400}?(\b(ba|z|da)?sh\s+|\bsource\s+|(^|\s)\.\/)\S`,
    ].join("|"),
    "i",
  );

  // Where pages put commands: code blocks, and elements named like them, as
  // in ohmyz.sh's <p class="code">.
  const COMMAND_SEL = [
    "pre", "code", "kbd", "samp",
    '[class*="code" i]', '[class*="command" i]', '[class*="cmd" i]',
    '[class*="terminal" i]', '[class*="shell" i]', '[class*="snippet" i]',
  ].join(",");

  const STYLE = `
    :host { all: initial; }
    * { box-sizing: border-box; }
    .wrap { font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: #1f2328; }
    .bar { display: flex; gap: 8px; align-items: center; margin: 4px 0 10px; }
    button {
      font: 600 12px/1 system-ui, sans-serif; cursor: pointer; border-radius: 999px; white-space: nowrap;
      padding: 5px 11px; border: 1px solid #d0d7de; background: #f6f8fa; color: #1f2328;
    }
    button:hover { background: #eef1f4; }
    button:disabled { cursor: progress; opacity: .7; }
    .panel { border: 1px solid #d0d7de; border-radius: 8px; padding: 10px 12px; background: #fff; margin: 0 0 12px; max-width: 920px; }
    .pill { display: inline-block; font-weight: 700; font-size: 11px; letter-spacing: .04em; padding: 2px 8px; border-radius: 999px; margin-right: 6px; }
    .pass { background: #dafbe1; color: #116329; }
    .warn { background: #fff8c5; color: #7d4e00; }
    .block { background: #ffebe9; color: #a40e26; }
    .headline { font-weight: 600; }
    .script { margin-top: 8px; }
    .src { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; word-break: break-all; }
    .muted { color: #59636e; }
    ul { margin: 4px 0 0; padding-left: 18px; }
    .lines { margin: 4px 0 0; padding: 0; list-style: none; }
    .lines li { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-word; padding: 1px 0; }
    .ln { color: #59636e; display: inline-block; min-width: 3.5em; }
    .by { color: #59636e; font-family: system-ui, sans-serif; font-size: 11px; margin-left: 6px; }
    .error { color: #a40e26; }
    .toast { position: fixed; right: 16px; bottom: 16px; z-index: 2147483647; width: min(440px, calc(100vw - 32px));
             max-height: 70vh; overflow: auto; box-shadow: 0 8px 24px rgba(0,0,0,.18); margin: 0; }
    @media (prefers-color-scheme: dark) {
      .wrap { color: #e6edf3; }
      button { background: #21262d; color: #e6edf3; border-color: #3d444d; }
      button:hover { background: #30363d; }
      .panel { background: #0d1117; border-color: #3d444d; }
      .muted, .ln, .by { color: #9198a1; }
      .pass { background: #12361f; color: #6fdd8b; }
      .warn { background: #3b2e00; color: #f2cc60; }
      .block { background: #4a1219; color: #ff8182; }
      .error { color: #ff8182; }
    }`;

  // h builds an element. Strings become text nodes, so page or server data
  // can never be parsed as HTML.
  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v);
    }
    for (const c of children.flat()) {
      if (c == null || c === false) continue;
      el.append(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return el;
  }

  function shadowHost(display) {
    const host = document.createElement("inspect-ui");
    host.style.display = display;
    const root = host.attachShadow({ mode: "closed" });
    root.append(h("style", {}, STYLE));
    const wrap = h("div", { class: "wrap" });
    root.append(wrap);
    return { host, wrap };
  }

  // cleanCommand drops shell prompts that docs often show before commands.
  function cleanCommand(text) {
    return text
      .split("\n")
      .map((l) => l.replace(/^\s*[$%]\s+/, ""))
      .join("\n")
      .trim();
  }

  function check(command) {
    return api.runtime.sendMessage({
      type: "check",
      payload: {
        command,
        page_url: location.href,
        page_text: (document.body?.innerText || "").slice(0, 100000),
      },
    });
  }

  const ADVICE = { pass: "No risks found.", warn: "Read the flagged lines before running this.", block: "Don't run this." };

  function pill(decision) {
    return h("span", { class: `pill ${decision}` }, decision.toUpperCase());
  }

  function renderResult(resp) {
    if (!resp) return h("div", { class: "error" }, "No answer from the inspect extension.");
    if (resp.error) return h("div", { class: "error" }, resp.error);
    if (!resp.ran) return h("div", { class: "muted" }, "This command doesn't run a script from the internet, so there was nothing to check.");

    const out = h("div", {}, h("div", {}, pill(resp.decision), h("span", { class: "headline" }, ADVICE[resp.decision] || "")));
    for (const p of resp.problems || []) out.append(h("div", { class: "muted" }, "• " + p));

    let credits = 0;
    for (const r of resp.results || []) {
      const v = r.view;
      credits += v.credits || 0;
      for (const s of v.scripts) {
        const box = h("div", { class: "script" },
          h("div", {}, pill(s.decision), h("span", { class: "src" }, s.source)),
          s.depth > 0 ? h("div", { class: "muted" }, "downloaded and run by the script above") : null,
          s.category ? h("div", { class: "muted" }, `Inspect: ${s.verdict} · ${s.category}`) : null,
        );
        if (s.flagged?.length) {
          box.append(
            h("ul", { class: "lines" }, s.flagged.slice(0, 8).map((f) =>
              h("li", {}, h("span", { class: "ln" }, f.line ? `L${f.line}` : ""), f.text, h("span", { class: "by" }, f.by)),
            )),
          );
        }
        if (s.changes?.length) {
          box.append(h("ul", { class: "lines" }, s.changes.slice(0, 10).map((c) => h("li", {}, c))));
        }
        if (s.reasons?.length) box.append(h("ul", {}, s.reasons.map((x) => h("li", {}, x))));
        out.append(box);
      }
      if (v.page) {
        const box = h("div", { class: "script" }, h("div", {}, pill(v.page.decision), h("span", { class: "headline" }, "This page")));
        for (const g of v.page.guard || []) box.append(h("div", { class: "muted" }, `Text aimed at AI agents: “${g}”`));
        if (v.page.reasons?.length) box.append(h("ul", {}, v.page.reasons.map((x) => h("li", {}, x))));
        else box.append(h("div", { class: "muted" }, "Nothing on this page contradicts the script."));
        out.append(box);
      }
    }
    out.append(h("div", { class: "muted", style: "margin-top:8px" }, `Checked by inspect with Clocked · ${credits} credits`));
    return out;
  }

  async function runCheck(command, button, target) {
    button.disabled = true;
    const label = button.textContent;
    button.textContent = "Checking…";
    target.replaceChildren(h("div", { class: "muted" }, "Downloading the script and checking it. This takes a few seconds."));
    let resp;
    try {
      resp = await check(command);
    } catch (e) {
      resp = { error: `The extension couldn't send the check: ${e?.message || e}` };
    }
    target.replaceChildren(renderResult(resp));
    button.textContent = label;
    button.disabled = false;
  }

  // Buttons next to code blocks.

  const done = new WeakSet();

  function attach(el) {
    done.add(el);
    const command = cleanCommand(el.innerText || el.textContent || "");
    const block = el.tagName === "PRE";
    const { host, wrap } = shadowHost(block ? "block" : "inline-block");
    const panel = h("div", { class: "panel", style: "display:none" });
    const button = h("button", {
      type: "button",
      title: "Check this command's script with inspect before you run it",
      onclick: () => {
        panel.style.display = "block";
        runCheck(command, button, panel);
      },
    }, "Check with inspect");
    wrap.append(h("div", { class: "bar" }, button), panel);
    anchor(el).after(host);
  }

  // anchor climbs out of wrappers that hold nothing but this command, such as
  // a scrolling highlight box around a <pre>, so the result isn't clipped
  // inside them.
  function anchor(el) {
    const text = (el.textContent || "").trim();
    let a = el;
    while (a.parentElement && a.parentElement !== document.body && (a.parentElement.textContent || "").trim() === text) {
      a = a.parentElement;
    }
    return a;
  }

  function matches(el) {
    const text = el.textContent || "";
    return text.length <= 20000 && RUNS_REMOTE.test(text);
  }

  function handled(el) {
    for (let p = el; p; p = p.parentElement) if (done.has(p)) return true;
    return false;
  }

  // scan adds a button to the innermost element holding each command, so a
  // terminal widget wrapping a <pre> wrapping a <code> gets one button.
  function scan() {
    let n = 0;
    for (const el of document.querySelectorAll(COMMAND_SEL)) {
      if (n >= 200) break;
      if (handled(el) || el.closest("inspect-ui") || el.isContentEditable) continue;
      if (el.tagName === "CODE" && el.closest("pre")) continue; // the <pre> keeps its layout
      if (!matches(el)) continue;
      const inner = [...el.querySelectorAll(COMMAND_SEL)].some((c) => c.tagName !== "CODE" && c !== el && matches(c));
      if (inner) continue; // a smaller element holds the command; it gets the button
      attach(el);
      n++;
    }
  }

  let pending = 0;
  new MutationObserver(() => {
    clearTimeout(pending);
    pending = setTimeout(scan, 500);
  }).observe(document.documentElement, { childList: true, subtree: true });
  scan();

  // A warning when such a command is copied.

  let toast = null;
  document.addEventListener("copy", () => {
    const text = cleanCommand(String(window.getSelection() || ""));
    if (!text || text.length > 20000 || !RUNS_REMOTE.test(text)) return;
    toast?.remove();

    const { host, wrap } = shadowHost("block");
    const body = h("div", {}, h("div", { class: "headline" }, "You copied a command that runs a script from the internet."));
    const close = h("button", { type: "button", onclick: () => host.remove() }, "Dismiss");
    const go = h("button", {
      type: "button",
      onclick: () => {
        clearTimeout(timer);
        runCheck(text, go, result);
      },
    }, "Check it first");
    const result = h("div", { style: "margin-top:8px" });
    wrap.append(h("div", { class: "panel toast" }, body, h("div", { class: "bar", style: "margin-top:8px" }, go, close), result));
    document.documentElement.append(host);
    toast = host;
    const timer = setTimeout(() => host.remove(), 15000);
  });
})();
