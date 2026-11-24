(function () {
  "use strict";
  var plansCache = [];
  var geoLoaded = false;
  var configCache = null;
  var lastOverview = null;

  function el(id) {
    return document.getElementById(id);
  }

  function esc(value) {
    return DH.esc(value);
  }

  function toast(text, bad) {
    var box = el("toast");
    box.textContent = text;
    box.className = "toast show" + (bad ? " bad" : "");
    clearTimeout(box._timer);
    box._timer = setTimeout(function () {
      box.className = "toast";
    }, 2400);
  }

  function say(id, text, kind) {
    var node = el(id);
    if (!node) return;
    node.textContent = text || "";
    node.className = "msg-line" + (kind ? " " + kind : "");
  }

  function stamp(seconds) {
    var value = Number(seconds) || 0;
    if (!value) return "—";
    var date = new Date(value * 1000);
    return date.toLocaleString();
  }

  function tag(kind, text) {
    return '<span class="tag ' + kind + '">' + esc(text) + "</span>";
  }

  async function guard(task) {
    try {
      await task();
    } catch (err) {
      if (err.status === 401) {
        location.replace("/admin");
        return;
      }
      toast((err.data && (err.data.error || err.data.message)) || err.message || "Request failed", true);
    }
  }

  /* ---------------- tabs ---------------- */

  var loaders = {
    overview: loadOverview,
    keys: function () {
      loadPlanSelect();
      loadKeys();
    },
    plans: loadPlans,
    resellers: loadResellers,
    requests: loadRequests,
    bans: loadBans,
    geo: loadGeo,
    config: loadConfig,
    sessions: loadSessions,
    audit: loadAudit
  };

  function showTab(name) {
    var buttons = document.querySelectorAll("#admin-nav button");
    for (var i = 0; i < buttons.length; i += 1) {
      buttons[i].classList.toggle("active", buttons[i].getAttribute("data-tab") === name);
    }
    var sections = document.querySelectorAll(".section");
    for (var j = 0; j < sections.length; j += 1) {
      sections[j].classList.toggle("active", sections[j].id === "sec-" + name);
    }
    if (loaders[name]) guard(loaders[name]);
  }

  el("admin-nav").addEventListener("click", function (event) {
    var button = event.target.closest("button[data-tab]");
    if (button) showTab(button.getAttribute("data-tab"));
  });

  el("admin-logout").addEventListener("click", async function () {
    try {
      await fetch("/admin/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": DH.csrf() }
      });
    } catch (err) {
      /* ignore */
    }
    location.replace("/admin");
  });

  /* ---------------- overview ---------------- */

  async function loadOverview() {
    var data = await DH.api("/admin/api/overview");
    lastOverview = data;
    var stats = data.stats;
    el("st-keys-active").textContent = stats.keys_active;
    el("st-keys-unused").textContent = stats.keys_unused;
    el("st-keys-total").textContent = stats.keys_total;
    el("st-resellers").textContent = stats.resellers;
    el("st-requests").textContent = stats.requests;
    el("st-bans").textContent = (stats.bans || 0) + (stats.hwid_bans || 0);
    el("st-sessions").textContent = stats.sessions;
    el("st-revenue").textContent = data.revenue_label;
    el("who-admin").textContent = data.admin;
    el("who-ip").textContent = "IP " + data.ip;
    el("ov-base").textContent = data.base_url;
    el("maint-state").textContent = data.maintenance.on ? "ON" : "OFF";
    el("maint-state").className = "tag " + (data.maintenance.on ? "bad" : "ok");
    el("maint-toggle").textContent = data.maintenance.on ? "TURN OFF" : "TURN ON";
    el("maint-toggle").className = "btn " + (data.maintenance.on ? "ok" : "danger");
    el("maint-note").textContent = data.maintenance.on
      ? "Keys are paused since " + stamp(data.maintenance.started_at) + ". Paused time is added back when you turn it off."
      : "Timers are running normally.";

    var cfg = el("ov-config");
    if (data.config_errors.length) {
      cfg.innerHTML =
        '<div class="notice bad">Server config incomplete: ' +
        esc(data.config_errors.join(" ")) +
        "</div>";
    } else {
      cfg.innerHTML = '<div class="notice ok">Happ config is valid.</div>';
    }

    var rows = data.audit.map(function (item) {
      return (
        "<tr><td>" +
        esc(stamp(item.created_at)) +
        "</td><td>" +
        esc(item.actor) +
        "</td><td>" +
        esc(item.action) +
        "</td><td class=\"wrap\">" +
        esc(item.detail) +
        "</td><td>" +
        esc(item.ip) +
        "</td></tr>"
      );
    });
    el("ov-audit").innerHTML = rows.length ? rows.join("") : '<tr><td colspan="5" class="empty">No activity yet.</td></tr>';
  }

  el("maint-toggle").addEventListener("click", function () {
    guard(async function () {
      var on = !(lastOverview && lastOverview.maintenance.on);
      await DH.api("/admin/api/maintenance", { json: { on: on } });
      toast(on ? "Maintenance ON. Timers paused." : "Maintenance OFF. Timers resumed.");
      await loadOverview();
    });
  });

  /* ---------------- keys ---------------- */

  async function loadPlanSelect() {
    try {
      var data = await DH.api("/admin/api/plans");
      plansCache = data.plans;
      var select = el("key-plan");
      select.innerHTML = '<option value="">None</option>' + data.plans
        .map(function (plan) {
          return '<option value="' + plan.id + '">' + esc(plan.name) + "</option>";
        })
        .join("");
    } catch (err) {
      /* plan select is optional */
    }
  }

  function keyRow(key) {
    var stateClass = key.state === "active" ? "ok" : key.state === "revoked" ? "bad" : "dim";
    var actions =
      (key.state !== "revoked"
        ? '<button class="btn small ghost" data-act="revoke" data-id="' + key.id + '" type="button">Revoke</button> '
        : "") +
      '<button class="btn small danger" data-act="delete" data-id="' + key.id + '" type="button">Delete</button>';
    return (
      "<tr><td class=\"code\">" +
      esc(key.code) +
      "</td><td>" +
      esc(key.kind === "single" ? "Single" : "Unlimited") +
      "</td><td>" +
      tag(stateClass, key.state.toUpperCase()) +
      "</td><td>" +
      esc(key.remaining_label) +
      "</td><td>" +
      esc(key.plan || "—") +
      "</td><td>" +
      esc(key.reseller || "Admin") +
      "</td><td>" +
      key.device_count +
      "</td><td>" +
      actions +
      "</td></tr>"
    );
  }

  async function loadKeys() {
    var search = el("key-search").value.trim();
    var data = await DH.api("/admin/api/keys?q=" + encodeURIComponent(search));
    el("keys-body").innerHTML = data.keys.length
      ? data.keys.map(keyRow).join("")
      : '<tr><td colspan="8" class="empty">No keys.</td></tr>';
  }

  el("key-refresh").addEventListener("click", function () {
    guard(loadKeys);
  });

  el("key-search").addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
      event.preventDefault();
      guard(loadKeys);
    }
  });

  el("key-form").addEventListener("submit", function (event) {
    event.preventDefault();
    guard(async function () {
      var form = event.target;
      var payload = {
        value: Number(form.value.value),
        unit: form.unit.value,
        kind: form.kind.value,
        count: Number(form.count.value) || 1,
        plan_id: form.plan_id.value || null,
        note: form.note.value
      };
      say("key-msg", "Generating…");
      var data = await DH.api("/admin/api/keys", { json: payload });
      say("key-msg", data.count + " key(s) created.", "ok");
      el("key-out").value = data.codes.join("\n");
      el("key-out-wrap").classList.add("show");
      el("key-copy").textContent = "COPY";
      toast("Keys created");
      loadKeys();
    });
  });

  el("key-copy").addEventListener("click", function () {
    DH.copy(el("key-out").value, function (ok) {
      el("key-copy").textContent = ok ? "COPIED" : "SELECT ALL";
    });
  });

  el("test-key").addEventListener("click", function () {
    guard(async function () {
      var data = await DH.api("/admin/api/test-key", { json: {} });
      el("key-out").value =
        "TEST KEY (10 minutes, single device)\n\n" +
        data.code +
        "\n\nOpen the site on your phone, paste this key. It locks to that phone.";
      el("key-out-wrap").classList.add("show");
      say("key-msg", "Test key created.", "ok");
    });
  });

  el("test-config").addEventListener("click", function () {
    guard(async function () {
      var data = await DH.api("/admin/api/config/test", { json: {} });
      var test = data.test;
      el("key-out").value =
        (test.errors.length ? "ERRORS:\n- " + test.errors.join("\n- ") + "\n\n" : "CONFIG OK\n\n") +
        "URI:\n" +
        (test.uri || "(could not build)") +
        "\n\nTest target: " +
        test.target +
        "\nCrypto link: " +
        (test.crypto_enabled ? "on" : "off");
      el("key-out-wrap").classList.add("show");
      say("key-msg", test.ok ? "Config test passed." : "Config test found problems.", test.ok ? "ok" : "bad");
    });
  });

  el("keys-body").addEventListener("click", function (event) {
    var button = event.target.closest("button[data-act]");
    if (!button) return;
    var id = button.getAttribute("data-id");
    var act = button.getAttribute("data-act");
    if (act === "revoke" && !confirm("Revoke this key? Active users are disconnected.")) return;
    if (act === "delete" && !confirm("Delete this key permanently?")) return;
    guard(async function () {
      if (act === "revoke") {
        await DH.api("/admin/api/keys/" + id + "/revoke", { json: {} });
        toast("Key revoked");
      } else {
        await DH.api("/admin/api/keys/" + id, { method: "DELETE" });
        toast("Key deleted");
      }
      loadKeys();
    });
  });

  /* ---------------- plans ---------------- */

  function planRow(plan) {
    return (
      "<tr><td>" +
      esc(plan.name) +
      "</td><td>" +
      esc(plan.duration) +
      "</td><td>" +
      esc(plan.price_label) +
      "</td><td>" +
      plan.stock +
      "</td><td>" +
      plan.sold +
      "</td><td>" +
      tag(plan.active ? "ok" : "dim", plan.active ? "Active" : "Hidden") +
      "</td><td><div class=\"row-controls\">" +
      '<input class="mini" data-stock="' + plan.id + '" placeholder="+10">' +
      '<button class="btn small ghost" data-act="stock" data-id="' + plan.id + '" type="button">Add</button>' +
      "</div></td><td>" +
      '<button class="btn small ghost" data-act="edit" data-id="' + plan.id + '" type="button">Edit</button> ' +
      '<button class="btn small ghost" data-act="toggle" data-id="' + plan.id + '" type="button">' +
      (plan.active ? "Hide" : "Show") +
      '</button> <button class="btn small danger" data-act="delete" data-id="' + plan.id + '" type="button">Delete</button>' +
      "</td></tr>"
    );
  }

  async function loadPlans() {
    var data = await DH.api("/admin/api/plans");
    plansCache = data.plans;
    el("plans-body").innerHTML = data.plans.length
      ? data.plans.map(planRow).join("")
      : '<tr><td colspan="8" class="empty">No plans yet.</td></tr>';
  }

  el("plan-form").addEventListener("submit", function (event) {
    event.preventDefault();
    guard(async function () {
      var form = event.target;
      say("plan-msg", "Creating…");
      await DH.api("/admin/api/plans", {
        json: {
          name: form.name.value,
          value: Number(form.value.value),
          unit: form.unit.value,
          price: form.price.value,
          stock: Number(form.stock.value) || 0
        }
      });
      form.name.value = "";
      say("plan-msg", "Plan created.", "ok");
      toast("Plan created");
      loadPlans();
      loadPlanSelect();
    });
  });

  el("plans-body").addEventListener("click", function (event) {
    var button = event.target.closest("button[data-act]");
    if (!button) return;
    var id = Number(button.getAttribute("data-id"));
    var act = button.getAttribute("data-act");
    var plan = plansCache.filter(function (item) {
      return item.id === id;
    })[0];
    if (!plan) return;

    if (act === "delete") {
      if (!confirm("Delete plan " + plan.name + "? Its keys stay in the key list.")) return;
      guard(async function () {
        await DH.api("/admin/api/plans/" + id, { method: "DELETE" });
        toast("Plan deleted");
        loadPlans();
      });
      return;
    }

    if (act === "toggle") {
      guard(async function () {
        await DH.api("/admin/api/plans/" + id, { json: { active: !plan.active }, method: "PATCH" });
        toast(plan.active ? "Plan hidden" : "Plan visible");
        loadPlans();
      });
      return;
    }

    if (act === "stock") {
      var input = document.querySelector('input[data-stock="' + id + '"]');
      var amount = Number(input && input.value);
      if (!amount) {
        toast("Enter a stock amount", true);
        return;
      }
      guard(async function () {
        await DH.api("/admin/api/plans/" + id + "/stock", { json: { amount: amount } });
        toast("Stock updated");
        loadPlans();
      });
      return;
    }

    if (act === "edit") {
      var name = prompt("Plan name", plan.name);
      if (name === null) return;
      var price = prompt("Price (" + plan.price_label + ")", (plan.price_cents / 100).toFixed(2));
      if (price === null) return;
      guard(async function () {
        await DH.api("/admin/api/plans/" + id, { json: { name: name, price: price }, method: "PATCH" });
        toast("Plan updated");
        loadPlans();
      });
    }
  });

  /* ---------------- resellers ---------------- */

  function resellerRow(item) {
    var photo = item.photo
      ? '<img class="thumb" src="/reseller/photo/' + item.id + '" alt="">'
      : '<span class="tag dim">none</span>';
    return (
      "<tr><td>" +
      photo +
      '</td><td class="code">' +
      esc(item.username) +
      "</td><td>" +
      esc(item.first_name + " " + item.last_name) +
      "</td><td>" +
      (item.age || "—") +
      "</td><td>" +
      esc(item.balance_label) +
      "</td><td>" +
      item.key_count +
      "</td><td>" +
      tag(item.active ? "ok" : "bad", item.active ? "Active" : "Disabled") +
      "</td><td><div class=\"row-controls\">" +
      '<input class="mini" data-bal="' + item.id + '" placeholder="amount">' +
      '<button class="btn small ghost" data-act="add" data-id="' + item.id + '" type="button">Add</button>' +
      '<button class="btn small ghost" data-act="subtract" data-id="' + item.id + '" type="button">Sub</button>' +
      '<button class="btn small ghost" data-act="password" data-id="' + item.id + '" type="button">Pass</button>' +
      "</div></td><td>" +
      '<button class="btn small ghost" data-act="toggle" data-id="' + item.id + '" type="button">' +
      (item.active ? "Disable" : "Enable") +
      '</button> <button class="btn small danger" data-act="delete" data-id="' + item.id + '" type="button">Delete</button>' +
      "</td></tr>"
    );
  }

  async function loadResellers() {
    var data = await DH.api("/admin/api/resellers");
    el("resellers-body").innerHTML = data.resellers.length
      ? data.resellers.map(resellerRow).join("")
      : '<tr><td colspan="9" class="empty">No resellers yet.</td></tr>';
  }

  el("res-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var form = event.target;
    guard(async function () {
      say("res-msg", "Creating…");
      var body = new FormData();
      ["username", "password", "first_name", "last_name", "age", "balance"].forEach(function (name) {
        body.append(name, form[name].value);
      });
      if (form.photo.files[0]) body.append("photo", form.photo.files[0]);
      var res = await fetch("/admin/api/resellers", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": DH.csrf() },
        body: body
      });
      var data = await res.json().catch(function () {
        return {};
      });
      if (!res.ok) throw Object.assign(new Error(data.error || "Could not create reseller"), { status: res.status, data: data });
      say("res-msg", "Reseller created.", "ok");
      form.reset();
      toast("Reseller created");
      loadResellers();
    });
  });

  el("resellers-body").addEventListener("click", function (event) {
    var button = event.target.closest("button[data-act]");
    if (!button) return;
    var id = Number(button.getAttribute("data-id"));
    var act = button.getAttribute("data-act");

    if (act === "delete") {
      if (!confirm("Delete this reseller? Their keys remain but they lose access.")) return;
      guard(async function () {
        await DH.api("/admin/api/resellers/" + id, { method: "DELETE" });
        toast("Reseller deleted");
        loadResellers();
      });
      return;
    }

    if (act === "toggle") {
      guard(async function () {
        var data = await DH.api("/admin/api/resellers");
        var found = data.resellers.filter(function (item) {
          return item.id === id;
        })[0];
        await DH.api("/admin/api/resellers/" + id, { json: { active: !(found && found.active) }, method: "PATCH" });
        toast("Reseller updated");
        loadResellers();
      });
      return;
    }

    if (act === "password") {
      var password = prompt("New password (min 6 characters)");
      if (!password) return;
      guard(async function () {
        await DH.api("/admin/api/resellers/" + id, { json: { password: password }, method: "PATCH" });
        toast("Password changed");
      });
      return;
    }

    var input = document.querySelector('input[data-bal="' + id + '"]');
    var amount = input && input.value.trim();
    if (!amount) {
      toast("Enter an amount", true);
      return;
    }
    guard(async function () {
      await DH.api("/admin/api/resellers/" + id, {
        json: { balance_delta: amount, subtract: act === "subtract" },
        method: "PATCH"
      });
      toast(act === "subtract" ? "Balance reduced" : "Balance added");
      loadResellers();
    });
  });

  /* ---------------- requests ---------------- */

  async function loadRequests() {
    var data = await DH.api("/admin/api/requests");
    el("requests-body").innerHTML = data.requests.length
      ? data.requests
          .map(function (item) {
            var statusClass = item.status === "open" ? "warn" : item.status === "done" ? "ok" : "dim";
            var actions =
              item.status === "open"
                ? '<button class="btn small ok" data-act="done" data-id="' + item.id + '" type="button">Done</button> ' +
                  '<button class="btn small ghost" data-act="reject" data-id="' + item.id + '" type="button">Reject</button>'
                : '<button class="btn small danger" data-act="delete" data-id="' + item.id + '" type="button">Delete</button>';
            return (
              "<tr><td>" +
              esc(item.plan) +
              "</td><td>" +
              esc(item.username + " (" + item.name + ")") +
              '</td><td class="wrap">' +
              esc(item.note || "—") +
              "</td><td>" +
              tag(statusClass, item.status.toUpperCase()) +
              "</td><td>" +
              esc(stamp(item.created_at)) +
              "</td><td>" +
              actions +
              "</td></tr>"
            );
          })
          .join("")
      : '<tr><td colspan="6" class="empty">No requests.</td></tr>';
  }

  el("req-refresh").addEventListener("click", function () {
    guard(loadRequests);
  });

  el("requests-body").addEventListener("click", function (event) {
    var button = event.target.closest("button[data-act]");
    if (!button) return;
    var id = button.getAttribute("data-id");
    var act = button.getAttribute("data-act");
    guard(async function () {
      if (act === "delete") {
        await DH.api("/admin/api/requests/" + id, { method: "DELETE" });
      } else {
        await DH.api("/admin/api/requests/" + id + "/close", {
          json: { status: act === "done" ? "done" : "rejected" }
        });
      }
      toast("Request updated");
      loadRequests();
    });
  });

  /* ---------------- bans ---------------- */

  async function loadBans() {
    var data = await DH.api("/admin/api/bans");
    el("bans-body").innerHTML = data.bans.length
      ? data.bans
          .map(function (item) {
            return (
              '<tr><td class="code">' +
              esc(item.ip) +
              '</td><td class="wrap">' +
              esc(item.reason || "—") +
              "</td><td>" +
              esc(stamp(item.created_at)) +
              "</td><td>" +
              (item.expires_at ? esc(stamp(item.expires_at)) : "Permanent") +
              "</td><td>" +
              '<button class="btn small ghost" data-ip="' + esc(item.ip) + '" type="button">Unban</button>' +
              "</td></tr>"
            );
          })
          .join("")
      : '<tr><td colspan="5" class="empty">No banned IPs.</td></tr>';
    el("hwid-bans-body").innerHTML = data.hwid_bans && data.hwid_bans.length
      ? data.hwid_bans
          .map(function (item) {
            return (
              '<tr><td class="code">' +
              esc(item.hwid) +
              '</td><td class="wrap">' +
              esc(item.reason || "—") +
              "</td><td>" +
              esc(stamp(item.created_at)) +
              "</td><td>" +
              (item.expires_at ? esc(stamp(item.expires_at)) : "Permanent") +
              "</td><td>" +
              '<button class="btn small ghost" data-hwid="' + esc(item.hwid) + '" type="button">Unban</button>' +
              "</td></tr>"
            );
          })
          .join("")
      : '<tr><td colspan="5" class="empty">No banned devices.</td></tr>';
    try {
      var shield = await DH.api("/admin/api/sentinel");
      el("sentinel-form").enabled.checked = !!shield.enabled;
    } catch (err) {
      /* shield state is optional on this screen */
    }
  }

  el("sentinel-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var form = event.target;
    guard(async function () {
      say("sentinel-msg", "Saving…");
      await DH.api("/admin/api/sentinel", { json: { enabled: form.enabled.checked } });
      say("sentinel-msg", "Shield saved.", "ok");
      toast(form.enabled.checked ? "Shield on" : "Shield off");
    });
  });

  el("ban-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var form = event.target;
    guard(async function () {
      var payload = { ip: form.ip.value, hwid: form.hwid.value, reason: form.reason.value };
      if (form.amount.value) {
        payload.amount = Number(form.amount.value);
        payload.unit = form.unit.value;
      }
      say("ban-msg", "Banning…");
      await DH.api("/admin/api/bans", { json: payload });
      say("ban-msg", "Ban saved.", "ok");
      form.reset();
      toast("Ban saved");
      loadBans();
    });
  });

  el("bans-body").addEventListener("click", function (event) {
    var button = event.target.closest("button[data-ip]");
    if (!button) return;
    var ip = button.getAttribute("data-ip");
    guard(async function () {
      await DH.api("/admin/api/bans/" + encodeURIComponent(ip), { method: "DELETE" });
      toast("IP unbanned");
      loadBans();
    });
  });

  el("hwid-bans-body").addEventListener("click", function (event) {
    var button = event.target.closest("button[data-hwid]");
    if (!button) return;
    var hwid = button.getAttribute("data-hwid");
    guard(async function () {
      await DH.api("/admin/api/hwid-bans/" + encodeURIComponent(hwid), { method: "DELETE" });
      toast("Device unbanned");
      loadBans();
    });
  });

  /* ---------------- geo ---------------- */

  async function loadGeo() {
    var data = await DH.api("/admin/api/geo");
    var form = el("geo-mode-form");
    form.mode.value = data.mode;
    form.note.value = data.note;
    form.fail_open.value = data.fail_open ? "1" : "0";

    var country = el("geo-country");
    country.innerHTML =
      '<option value="">Choose country…</option>' +
      data.countries
        .map(function (item) {
          return '<option value="' + item.code + '">' + esc(item.name) + "</option>";
        })
        .join("");
    el("geo-state").innerHTML = '<option value="">Whole country</option>';
    el("geo-state").disabled = true;

    el("geo-rules").innerHTML = data.rules.length
      ? data.rules
          .map(function (rule) {
            return (
              "<tr><td>" +
              esc(rule.country_name || rule.country_code) +
              "</td><td>" +
              esc(rule.region_name || "Whole country") +
              "</td><td>" +
              tag(data.mode === "allow" ? "ok" : "bad", data.mode === "allow" ? "Allowed" : "Locked") +
              "</td><td>" +
              '<button class="btn small danger" data-rule="' + rule.id + '" type="button">Unlock</button>' +
              "</td></tr>"
            );
          })
          .join("")
      : '<tr><td colspan="4" class="empty">No places locked.</td></tr>';
    geoLoaded = true;
  }

  el("geo-country").addEventListener("change", function () {
    var code = el("geo-country").value;
    var state = el("geo-state");
    if (!code) {
      state.innerHTML = '<option value="">Whole country</option>';
      state.disabled = true;
      return;
    }
    state.disabled = true;
    state.innerHTML = '<option value="">Loading…</option>';
    guard(async function () {
      var data = await DH.api("/admin/api/geo?country=" + encodeURIComponent(code));
      state.innerHTML =
        '<option value="">Whole country</option>' +
        data.states
          .map(function (name) {
            return '<option value="' + esc(name) + '">' + esc(name) + "</option>";
          })
          .join("");
      state.disabled = false;
    });
  });

  el("geo-lock").addEventListener("click", function () {
    var code = el("geo-country").value;
    var region = el("geo-state").value;
    if (!code) {
      toast("Choose a country", true);
      return;
    }
    guard(async function () {
      await DH.api("/admin/api/geo/rules", { json: { country_code: code, region: region } });
      say("geo-msg", "Place saved.", "ok");
      toast("Place locked");
      await loadGeo();
    });
  });

  el("geo-mode-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var form = event.target;
    guard(async function () {
      await DH.api("/admin/api/geo/mode", {
        json: {
          mode: form.mode.value,
          fail_open: form.fail_open.value === "1",
          note: form.note.value
        }
      });
      say("geo-mode-msg", "Mode saved.", "ok");
      toast("Geo mode saved");
    });
  });

  el("geo-rules").addEventListener("click", function (event) {
    var button = event.target.closest("button[data-rule]");
    if (!button) return;
    var id = button.getAttribute("data-rule");
    guard(async function () {
      await DH.api("/admin/api/geo/rules/" + id, { method: "DELETE" });
      toast("Place unlocked");
      loadGeo();
    });
  });

  el("geo-lookup").addEventListener("click", function () {
    guard(async function () {
      var data = await DH.api("/admin/api/geo/lookup", { json: { ip: el("geo-ip").value } });
      var info = data.info || {};
      say(
        "geo-lookup-msg",
        (info.country_name || info.country_code || "Unknown") +
          " / " +
          (info.region || "—") +
          " / " +
          (info.city || "—") +
          " — " +
          (data.locked ? "LOCKED" : "allowed"),
        data.locked ? "bad" : "ok"
      );
    });
  });

  /* ---------------- config ---------------- */

  function applyConfig(conf) {
    configCache = conf;
    var form = el("config-form");
    var fields = [
      "protocol", "host", "port", "uuid", "password", "sni", "path", "network",
      "security", "flow", "fp", "alpn", "pbk", "sid", "ss_method", "remark"
    ];
    fields.forEach(function (name) {
      var input = form[name];
      if (!input) return;
      var locked = conf.locked && conf.locked[name];
      input.value = conf[name] == null ? "" : conf[name];
      input.disabled = !!locked;
    });
    form.crypto_link.checked = !!conf.crypto_link;
    form.crypto_link.disabled = !!(conf.locked && conf.locked.crypto_link);

    var site = conf.site || {};
    ["buy_url", "support_url", "currency", "public_base_url", "test_target"].forEach(function (name) {
      var input = form[name];
      if (!input) return;
      var locked = conf.site_locked && conf.site_locked[name];
      input.value = site[name] == null ? "" : site[name];
      input.disabled = !!locked;
    });

    el("config-base").textContent = conf.base_url || location.origin;

    var errors = (conf.test && conf.test.errors) || [];
    say("cfg-msg", errors.length ? errors.join(" ") : "Config looks valid.", errors.length ? "bad" : "ok");
  }

  async function loadConfig() {
    var data = await DH.api("/admin/api/config");
    applyConfig(data.config);
  }

  el("config-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var form = event.target;
    guard(async function () {
      say("cfg-msg", "Saving…");
      var payload = {};
      [
        "protocol", "host", "port", "uuid", "password", "sni", "path", "network",
        "security", "flow", "fp", "alpn", "pbk", "sid", "ss_method", "remark",
        "buy_url", "support_url", "currency", "public_base_url", "test_target"
      ].forEach(function (name) {
        var input = form[name];
        if (input && !input.disabled) payload[name] = input.value;
      });
      if (!form.crypto_link.disabled) payload.crypto_link = form.crypto_link.checked;
      var data = await DH.api("/admin/api/config", { json: payload });
      var errors = data.errors || [];
      say("cfg-msg", errors.length ? "Saved, but: " + errors.join(" ") : "Config saved.", errors.length ? "bad" : "ok");
      toast(errors.length ? "Saved with warnings" : "Config saved", errors.length > 0);
      await loadConfig();
      if (data.test && data.test.uri) {
        el("cfg-out").value = data.test.uri;
        el("cfg-out-wrap").classList.add("show");
      }
    });
  });

  el("cfg-test").addEventListener("click", function () {
    guard(async function () {
      var data = await DH.api("/admin/api/config/test", { json: {} });
      var test = data.test;
      el("cfg-out").value =
        (test.errors.length ? "ERRORS:\n- " + test.errors.join("\n- ") + "\n\n" : "OK\n\n") +
        "Sample URI:\n" +
        (test.uri || "(none)") +
        "\n\nTest target: " +
        test.target;
      el("cfg-out-wrap").classList.add("show");
      say("cfg-msg", test.ok ? "Test passed." : "Test found problems.", test.ok ? "ok" : "bad");
    });
  });

  /* ---------------- sessions / audit ---------------- */

  async function loadSessions() {
    var data = await DH.api("/admin/api/sessions");
    el("sessions-body").innerHTML = data.sessions.length
      ? data.sessions
          .map(function (item) {
            return (
              "<tr><td>" +
              esc(item.label) +
              "</td><td>" +
              tag("dim", item.role) +
              '</td><td class="code">' +
              esc(item.ip) +
              '</td><td class="wrap">' +
              esc(item.ua || "—") +
              "</td><td>" +
              esc(stamp(item.created_at)) +
              "</td><td>" +
              esc(stamp(item.expires_at)) +
              "</td><td>" +
              '<button class="btn small danger" data-session="' + item.id + '" type="button">Kill</button>' +
              "</td></tr>"
            );
          })
          .join("")
      : '<tr><td colspan="7" class="empty">No active sessions.</td></tr>';
  }

  el("sess-refresh").addEventListener("click", function () {
    guard(loadSessions);
  });

  el("sessions-body").addEventListener("click", function (event) {
    var button = event.target.closest("button[data-session]");
    if (!button) return;
    var id = button.getAttribute("data-session");
    guard(async function () {
      await DH.api("/admin/api/sessions/" + id, { method: "DELETE" });
      toast("Session killed");
      loadSessions();
    });
  });

  async function loadAudit() {
    var data = await DH.api("/admin/api/audit");
    el("audit-body").innerHTML = data.audit.length
      ? data.audit
          .map(function (item) {
            return (
              "<tr><td>" +
              esc(stamp(item.created_at)) +
              "</td><td>" +
              esc(item.actor) +
              "</td><td>" +
              esc(item.action) +
              '</td><td class="wrap">' +
              esc(item.detail) +
              '</td><td class="code">' +
              esc(item.ip) +
              "</td></tr>"
            );
          })
          .join("")
      : '<tr><td colspan="5" class="empty">No activity yet.</td></tr>';
  }

  el("audit-refresh").addEventListener("click", function () {
    guard(loadAudit);
  });

  /* ---------------- boot ---------------- */

  showTab("overview");
  loadPlanSelect();
  setInterval(function () {
    if (document.getElementById("sec-overview").classList.contains("active")) {
      guard(loadOverview);
    }
  }, 30000);
})();
