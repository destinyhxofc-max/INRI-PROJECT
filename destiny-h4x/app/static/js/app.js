(function () {
  "use strict";
  var DH = (window.DH = window.DH || {});

  DH.csrf = function () {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  };

  DH.esc = function (value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  };

  DH.api = async function (path, options) {
    options = options || {};
    var headers = { Accept: "application/json" };
    var method = options.method || (options.json !== undefined ? "POST" : "GET");
    if (options.json !== undefined) headers["Content-Type"] = "application/json";
    var token = DH.csrf();
    if (token) headers["X-CSRF-Token"] = token;
    var init = { method: method, credentials: "same-origin", headers: headers };
    if (options.json !== undefined) init.body = JSON.stringify(options.json);
    if (options.body !== undefined) init.body = options.body;
    var res = await fetch(path, init);
    var data = null;
    try {
      data = await res.json();
    } catch (err) {
      data = null;
    }
    if (!res.ok) {
      var error = new Error((data && data.message) || "Request failed");
      error.status = res.status;
      error.data = data || {};
      throw error;
    }
    return data || {};
  };

  DH.deviceId = function () {
    var match = document.cookie.match(/(?:^|;\s*)dh4x_dev=([^;]+)/);
    if (match) return decodeURIComponent(match[1]);
    var id;
    if (window.crypto && crypto.randomUUID) {
      id = crypto.randomUUID();
    } else {
      id = "dev-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 12);
    }
    var secure = location.protocol === "https:" ? "; Secure" : "";
    document.cookie = "dh4x_dev=" + encodeURIComponent(id) + "; path=/; max-age=31536000; SameSite=Lax" + secure;
    return id;
  };

  DH.duration = function (seconds) {
    var total = Math.max(0, Math.floor(Number(seconds) || 0));
    var days = Math.floor(total / 86400);
    var rest = total % 86400;
    var hours = Math.floor(rest / 3600);
    var minutes = Math.floor((rest % 3600) / 60);
    var secs = rest % 60;
    var pad = function (n) {
      return String(n).padStart(2, "0");
    };
    if (days > 0) return days + "d " + pad(hours) + ":" + pad(minutes) + ":" + pad(secs);
    return pad(hours) + ":" + pad(minutes) + ":" + pad(secs);
  };

  DH.copy = function (text, done) {
    var finish = function (ok) {
      if (typeof done === "function") done(ok);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(
        function () {
          finish(true);
        },
        function () {
          finish(false);
        }
      );
      return;
    }
    var area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (err) {
      ok = false;
    }
    document.body.removeChild(area);
    finish(ok);
  };

  function particles() {
    var canvas = document.getElementById("bgCanvas");
    if (!canvas || !canvas.getContext) return;
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var ctx = canvas.getContext("2d");
    var points = [];
    var width = 0;
    var height = 0;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);

    function resize() {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = width + "px";
      canvas.style.height = height + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      var count = Math.max(24, Math.min(90, Math.floor((width * height) / 22000)));
      points = [];
      for (var i = 0; i < count; i += 1) {
        points.push({
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * 0.25,
          vy: (Math.random() - 0.5) * 0.25,
          r: 0.6 + Math.random() * 1.4
        });
      }
    }

    function frame() {
      ctx.clearRect(0, 0, width, height);
      for (var i = 0; i < points.length; i += 1) {
        var p = points[i];
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < -10) p.x = width + 10;
        if (p.x > width + 10) p.x = -10;
        if (p.y < -10) p.y = height + 10;
        if (p.y > height + 10) p.y = -10;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0, 191, 255, 0.35)";
        ctx.fill();
        for (var j = i + 1; j < points.length; j += 1) {
          var q = points[j];
          var dx = p.x - q.x;
          var dy = p.y - q.y;
          var dist = dx * dx + dy * dy;
          if (dist < 12000) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(q.x, q.y);
            ctx.strokeStyle = "rgba(0, 191, 255, " + (0.08 * (1 - dist / 12000)).toFixed(3) + ")";
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }
      if (!reduce) requestAnimationFrame(frame);
    }

    resize();
    window.addEventListener("resize", resize);
    if (reduce) {
      frame();
    } else {
      requestAnimationFrame(frame);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", particles);
  } else {
    particles();
  }
})();
