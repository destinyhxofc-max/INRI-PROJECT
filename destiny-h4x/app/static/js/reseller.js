(function () {
  "use strict";
  var root = document.getElementById("resellerRoot");
  var maintenance = root.getAttribute("data-maint") === "1";
  var busy = false;

  function toast(text, bad) {
    var box = document.getElementById("toast");
    box.textContent = text;
    box.className = "toast show" + (bad ? " bad" : "");
    clearTimeout(box._timer);
    box._timer = setTimeout(function () {
      box.className = "toast";
    }, 2600);
  }

  function formatTime(seconds) {
    return DH.duration(seconds);
  }

  document.querySelectorAll("[data-ts]").forEach(function (node) {
    var value = Number(node.getAttribute("data-ts")) || 0;
    node.textContent = value ? new Date(value * 1000).toLocaleString() : "—";
  });

  if (root.getAttribute("data-welcome") === "1" && window.speechSynthesis) {
    var name = root.getAttribute("data-name") || "";
    var attempt = function () {
      try {
        window.speechSynthesis.cancel();
        var utterance = new SpeechSynthesisUtterance("Welcome, " + name);
        utterance.rate = 0.95;
        utterance.pitch = 1;
        window.speechSynthesis.speak(utterance);
      } catch (err) {
        /* speech is optional */
      }
    };
    attempt();
    document.addEventListener("click", function once() {
      document.removeEventListener("click", once);
      if (!window.speechSynthesis.speaking && !window.speechSynthesis.pending) attempt();
    });
  }

  function tick() {
    if (maintenance) return;
    document.querySelectorAll(".js-left").forEach(function (node) {
      if (node.getAttribute("data-state") !== "active") return;
      var expires = Number(node.getAttribute("data-expires")) || 0;
      var remaining = expires ? expires - Math.floor(Date.now() / 1000) : Number(node.getAttribute("data-remaining")) || 0;
      node.textContent = remaining > 0 ? formatTime(remaining) + " left" : "expired";
    });
  }

  tick();
  setInterval(tick, 1000);

  async function post(url, payload) {
    return DH.api(url, { json: payload });
  }

  document.getElementById("planGrid").addEventListener("click", async function (event) {
    var button = event.target.closest("button");
    if (!button || busy) return;

    if (button.hasAttribute("data-buy")) {
      var planId = button.getAttribute("data-buy");
      var plan = button.closest(".plan");
      var title = plan.querySelector("h4").textContent;
      var price = plan.querySelector(".price").textContent;
      if (!confirm("Buy " + title + " for " + price + "?")) return;
      busy = true;
      button.disabled = true;
      try {
        var data = await post("/reseller/buy", { plan_id: Number(planId) });
        toast("Bought. Key " + data.code);
        DH.copy(data.code);
        setTimeout(function () {
          location.reload();
        }, 1200);
      } catch (err) {
        toast((err.data && err.data.error) || "Could not buy this plan.", true);
        button.disabled = false;
        busy = false;
      }
      return;
    }

    if (button.hasAttribute("data-restock")) {
      var restockId = Number(button.getAttribute("data-restock"));
      if (!confirm("Send a restock request to the admin for this plan?")) return;
      busy = true;
      button.disabled = true;
      try {
        await post("/reseller/restock", { plan_id: restockId });
        toast("Restock request sent");
        setTimeout(function () {
          location.reload();
        }, 900);
      } catch (err) {
        toast((err.data && err.data.error) || "Could not send request.", true);
        button.disabled = false;
        busy = false;
      }
    }
  });

  setInterval(async function () {
    try {
      var state = await DH.api("/reseller/api/state");
      if ((state.maintenance === true) !== maintenance || !state.active) {
        location.reload();
        return;
      }
      document.getElementById("rsBalance").textContent = state.balance_label;
    } catch (err) {
      if (err.status === 401 || err.status === 403) location.replace("/reseller");
    }
  }, 30000);
})();
