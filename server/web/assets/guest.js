(function () {
  const body = document.body;
  const guestToken = body.dataset.guestToken;
  const terminalEl = document.getElementById("terminal");
  const statusEl = document.getElementById("status");
  const approvalEl = document.getElementById("approval");
  const feedbackEl = document.getElementById("feedback");

  const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsURL = wsProtocol + "//" + window.location.host + "/ws/guest?guest_token=" + encodeURIComponent(guestToken);
  const ws = new WebSocket(wsURL);

  const term = new Terminal({
    cursorBlink: true,
    convertEol: false,
    fontSize: 14,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
    theme: {
      background: "#171a21",
      foreground: "#e8ecf3",
      cursor: "#7dd3fc",
      black: "#0f1115",
      brightBlack: "#5f6b7a"
    }
  });

  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(terminalEl);
  fitAddon.fit();

  function bytesToBase64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  ws.addEventListener("open", function () {
    statusEl.textContent = "connected";
    feedbackEl.textContent = "connected to host";
    feedbackEl.className = "ok";
    term.focus();
  });

  ws.addEventListener("message", function (event) {
    const msg = JSON.parse(event.data);
    switch (msg.type) {
      case "host_output":
        term.write(base64ToBytes(msg.data_b64));
        break;
      case "approval_state":
        approvalEl.textContent = [msg.decision, msg.reason, msg.risk].filter(Boolean).join(" · ");
        approvalEl.className = msg.decision === "require_approval" ? "warn" : "";
        break;
      case "feedback":
        feedbackEl.textContent = msg.message || "";
        feedbackEl.className = "ok";
        break;
      case "close":
        statusEl.textContent = "closed";
        feedbackEl.textContent = "session closed";
        break;
    }
  });

  ws.addEventListener("close", function () {
    statusEl.textContent = "closed";
  });

  ws.addEventListener("error", function () {
    statusEl.textContent = "error";
    feedbackEl.textContent = "websocket error";
  });

  term.onData(function (data) {
    if (ws.readyState !== WebSocket.OPEN) return;
    const bytes = new TextEncoder().encode(data);
    ws.send(JSON.stringify({ type: "guest_input", data_b64: bytesToBase64(bytes) }));
  });

  window.addEventListener("resize", function () {
    fitAddon.fit();
  });

  terminalEl.addEventListener("click", function () {
    term.focus();
  });

  term.focus();
})();
