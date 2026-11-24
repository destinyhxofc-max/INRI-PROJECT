(function () {
  "use strict";
  var statusEl = document.getElementById("verifyStatus");
  var spinner = document.getElementById("verifySpinner");
  var lockBox = document.getElementById("lockBox");
  var lockTitle = document.getElementById("lockTitle");
  var lockMeta = document.getElementById("lockMeta");
  var retryWrap = document.getElementById("retryWrap");
  var retryBtn = document.getElementById("retryBtn");

  function fail(message) {
    statusEl.textContent = message;
    statusEl.classList.add("bad");
    spinner.classList.add("hidden");
    retryWrap.classList.remove("hidden");
  }

  function showLock(data) {
    statusEl.classList.add("hidden");
    spinner.classList.add("hidden");
    lockTitle.textContent = String(data.message || "State locked").toUpperCase();
    var place = [data.country, data.region].filter(function (part) {
      return part && String(part).trim();
    });
    lockMeta.textContent = place.join(" \u00b7 ");
    lockBox.classList.remove("hidden");
  }

  async function check() {
    statusEl.classList.remove("hidden", "bad");
    statusEl.textContent = "Verifying location";
    spinner.classList.remove("hidden");
    retryWrap.classList.add("hidden");
    lockBox.classList.add("hidden");
    try {
      var data = await DH.api("/api/geo/check", { json: {} });
      if (data.ok && data.redirect) {
        statusEl.textContent = "Verified";
        location.replace(data.redirect);
        return;
      }
      fail("Verification failed.");
    } catch (err) {
      if (err.status === 403 && err.data && err.data.locked) {
        showLock(err.data);
        return;
      }
      fail((err.data && err.data.message) || "Could not verify your location.");
    }
  }

  retryBtn.addEventListener("click", check);
  check();
})();
