(function () {
  "use strict";
  var root = document.getElementById("dashRoot");
  var timeEl = document.getElementById("timeLeft");
  var note = document.getElementById("dashNote");
  var connectBtn = document.getElementById("dashConnect");
  var statusPill = document.getElementById("dashStatus");
  var routePill = document.getElementById("routePill");
  var linkBox = document.getElementById("linkBox");
  var subLink = document.getElementById("subLink");
  var copyBtn = document.getElementById("copySub");
  var hideBtn = document.getElementById("hideSub");
  var copyDev = document.getElementById("dashCopy");
  var devEl = document.getElementById("dashDev");
  var outBtn = document.getElementById("dashOut");
  var expiryEl = document.getElementById("expiryLine");

  var remaining = parseInt(root.getAttribute("data-remaining"), 10) || 0;
  var maintenance = root.getAttribute("data-maintenance") === "1";
  var expiresAt = parseInt(root.getAttribute("data-expires"), 10) || 0;
  var deadline = Date.now() + remaining * 1000;
  var redirecting = false;

  function setExpiry(ts) {
    expiresAt = Number(ts) || 0;
    if (!expiresAt) {
      expiryEl.textContent = maintenance ? "TIMER PAUSED" : "";
      return;
    }
    var text = "EXPIRES " + new Date(expiresAt * 1000).toLocaleString();
    expiryEl.textContent = maintenance ? text + " \u00b7 PAUSED" : text;
  }
  setExpiry(expiresAt);

  function tick() {
    var left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
    timeEl.textContent = DH.duration(left);
    timeEl.classList.toggle("low", left > 0 && left <= 300);
    if (left <= 0 && !maintenance && !redirecting) {
      redirecting = true;
      location.replace("/activate?reason=expired");
    }
  }

  function setMaintenance(on) {
    maintenance = on;
    connectBtn.disabled = on;
    if (on) {
      note.textContent = "Maintenance is on. Timer is paused.";
    } else if (note.textContent.indexOf("Maintenance") === 0) {
      note.textContent = "";
    }
    setExpiry(expiresAt);
  }

  tick();
  setInterval(tick, 1000);

  copyDev.addEventListener("click", function () {
    DH.copy(devEl.textContent.trim(), function (ok) {
      copyDev.textContent = ok ? "Copied" : "Select";
      setTimeout(function () {
        copyDev.textContent = "Copy";
      }, 1400);
    });
  });

  connectBtn.addEventListener("click", async function () {
    if (connectBtn.disabled) return;
    connectBtn.disabled = true;
    note.textContent = "Opening Happ\u2026";
    statusPill.textContent = "\u25cf CONNECTING";
    statusPill.classList.remove("off");
    try {
      var data = await DH.api("/api/connect", { json: {} });
      subLink.value = data.subscription_url || "";
      linkBox.classList.add("show");
      routePill.textContent = "\u25cf ROUTE READY";
      routePill.classList.remove("off");
      statusPill.textContent = "\u25cf READY";
      statusPill.classList.remove("off");
      if (data.deeplink) {
        note.textContent = "Encrypted link ready. Opening Happ\u2026";
        window.location.href = data.deeplink;
      } else {
        note.textContent = "Link ready. Copy it and add it in Happ.";
      }
    } catch (err) {
      var message = (err.data && err.data.message) || "Could not connect.";
      note.textContent = message;
      statusPill.textContent = "\u25cf OFFLINE";
      statusPill.classList.add("off");
      if (err.status === 401) {
        location.replace("/");
        return;
      }
      if (err.data && err.data.error === "maintenance") {
        setTimeout(function () {
          location.reload();
        }, 1400);
      }
    } finally {
      connectBtn.disabled = maintenance;
    }
  });

  copyBtn.addEventListener("click", function () {
    DH.copy(subLink.value, function (ok) {
      copyBtn.textContent = ok ? "COPIED" : "SELECT";
      setTimeout(function () {
        copyBtn.textContent = "COPY LINK";
      }, 1400);
    });
  });

  hideBtn.addEventListener("click", function () {
    linkBox.classList.remove("show");
  });

  outBtn.addEventListener("click", async function () {
    outBtn.disabled = true;
    try {
      var data = await DH.api("/api/logout", { json: {} });
      location.replace(data.redirect || "/");
    } catch (err) {
      outBtn.disabled = false;
    }
  });

  async function refresh() {
    if (redirecting) return;
    try {
      var data = await DH.api("/api/status");
      if (data.state !== "active") {
        redirecting = true;
        location.replace("/activate?reason=" + encodeURIComponent(data.state || "expired"));
        return;
      }
      remaining = Number(data.remaining) || 0;
      deadline = Date.now() + remaining * 1000;
      if ((data.maintenance === true) !== maintenance) {
        location.reload();
        return;
      }
      setMaintenance(data.maintenance === true);
      setExpiry(data.expires_at);
    } catch (err) {
      if (err.status === 401) {
        redirecting = true;
        location.replace("/");
      }
    }
  }

  setInterval(refresh, 25000);
})();
