(function () {
  "use strict";
  var form = document.getElementById("gate-form");
  var input = document.getElementById("license-key");
  var paste = document.getElementById("paste");
  var unlock = document.getElementById("unlock");
  var msg = document.getElementById("gate-msg");
  var device = DH.deviceId();
  var busy = false;

  function say(text, kind) {
    msg.textContent = text || "";
    msg.className = "msg" + (kind ? " " + kind : "");
  }

  function normalize(value) {
    return String(value || "")
      .toUpperCase()
      .replace(/[^A-Z0-9-]/g, "")
      .slice(0, 64);
  }

  input.addEventListener("input", function () {
    var clean = normalize(input.value);
    if (clean !== input.value) input.value = clean;
    if (msg.textContent) say("");
  });

  paste.addEventListener("click", async function () {
    if (navigator.clipboard && navigator.clipboard.readText && window.isSecureContext) {
      try {
        var text = await navigator.clipboard.readText();
        input.value = normalize(text);
        say("");
        return;
      } catch (err) {
        say("Clipboard blocked. Paste manually.", "err");
        input.focus();
        return;
      }
    }
    input.focus();
    say("Paste your key into the field.", "err");
  });

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (busy) return;
    var key = normalize(input.value);
    if (key.length < 6) {
      say("Enter your access key.", "err");
      input.focus();
      return;
    }
    busy = true;
    unlock.disabled = true;
    say("Checking key\u2026");
    try {
      var data = await DH.api("/api/activate", { json: { key: key, device: device } });
      say("Key accepted. Opening panel\u2026", "ok");
      location.replace(data.redirect || "/dashboard");
    } catch (err) {
      var message = (err.data && err.data.message) || "Key not accepted.";
      say(message, "err");
      if (err.data && err.data.error === "maintenance") {
        setTimeout(function () {
          location.reload();
        }, 1500);
      }
    } finally {
      busy = false;
      unlock.disabled = false;
    }
  });
})();
