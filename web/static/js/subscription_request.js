(() => {
  const $ = id => document.getElementById(id);
  const form = $("subscriptionRequestForm");
  let csrfToken = "";

  async function loadCsrf() {
    const response = await fetch("/api/auth/csrf", {credentials:"same-origin", cache:"no-store"});
    const data = await response.json();
    if (!response.ok || !data.csrf_token) {
      throw new Error("Secure session could not be verified. Please sign in again.");
    }
    csrfToken = data.csrf_token;
  }

  async function init() {
    const response = await fetch("/api/auth/me", {credentials:"same-origin", cache:"no-store"});
    const data = await response.json();
    if (!response.ok || !data.authenticated) {
      $("accountNotice").textContent = "Sign in to the PhishGuard account you want upgraded before submitting a request.";
      $("submitRequest").disabled = true;
      $("feedback").innerHTML = 'Please <a href="/">return to PhishGuard and sign in</a>, then choose your plan again.';
      return;
    }
    const user = data.user || data.account || {};
    $("accountNotice").textContent = "This request will be linked to your signed-in account: " + (user.email || "verified account") + ".";
    if (user.full_name) $("customerName").value = user.full_name;
    await loadCsrf();
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (!form.reportValidity()) return;

    const button = $("submitRequest");
    button.disabled = true;
    $("feedback").textContent = "Submitting your request to the PhishGuard admin…";
    try {
      if (!csrfToken) await loadCsrf();
      const response = await fetch("/api/billing/requests", {
        method:"POST",
        credentials:"same-origin",
        cache:"no-store",
        headers:{"Content-Type":"application/json", "X-CSRF-Token":csrfToken},
        body:JSON.stringify({
          plan_id:$("selectedPlan").value,
          customer_name:$("customerName").value.trim(),
          phone_number:$("phoneNumber").value.trim(),
          payment_method:$("paymentMethod").value,
          message:$("message").value.trim()
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not submit your request.");

      $("feedback").textContent = "Request #" + data.request_id + " has been submitted.";
      $("prepareEmailLink").href = "/subscription/request/" + encodeURIComponent(data.request_id) + "/email";
      $("requestSuccess").hidden = false;
      form.querySelectorAll("input,select,textarea,button").forEach(el => {
        if (el.type !== "hidden") el.disabled = true;
      });
      $("requestSuccess").scrollIntoView({behavior:"smooth", block:"center"});
    } catch (error) {
      $("feedback").textContent = error.message;
      button.disabled = false;
    }
  });

  init().catch(error => {
    $("accountNotice").textContent = error.message;
    $("submitRequest").disabled = true;
  });
})();