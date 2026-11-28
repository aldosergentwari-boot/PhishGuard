(() => {
  const $ = id => document.getElementById(id);
  const form = $("subscriptionRequestForm");
  const ownerEmail = document.querySelector(".request-shell")?.dataset.ownerEmail || "";
  let csrfToken = "";
  let emailApproved = false;

  async function csrf() {
    const response = await fetch("/api/auth/csrf", {credentials:"same-origin", cache:"no-store"});
    const data = await response.json();
    if (!response.ok || !data.csrf_token) throw new Error("Secure session could not be verified. Please sign in again.");
    csrfToken = data.csrf_token;
  }

  function buildEmail() {
    const plan = $("selectedPlan").value === "pro" ? "Pro" : "Business";
    const price = plan === "Pro" ? "$4.99 per month" : "$19.99 for 7 months";
    const name = $("customerName").value.trim();
    const phone = $("phoneNumber").value.trim();
    const method = $("paymentMethod").selectedOptions[0]?.textContent || "";
    const note = $("message").value.trim();
    return [
      "Dear PhishGuard Owner,",
      "",
      "I hope this message finds you well.",
      "",
      "I am writing to formally request a " + plan + " subscription for my PhishGuard account.",
      "",
      "My subscription details are:",
      "Full name: " + name,
      "Account email: " + (window.phishGuardAccountEmail || "My signed-in PhishGuard account"),
      "Requested plan: " + plan,
      "Plan price: " + price,
      "Contact phone: " + phone,
      "Preferred payment method: " + method,
      "Additional information: " + (note || "None"),
      "",
      "Kindly review my request and share the payment instructions and any further steps required to complete the subscription.",
      "",
      "I understand that my account will only be upgraded after the payment has been independently verified and approved.",
      "",
      "Thank you for your time and assistance.",
      "",
      "Yours faithfully,",
      name
    ].join("\\n");
  }

  function openPreview() {
    if (!form.reportValidity()) return;
    if (!ownerEmail) {
      $("feedback").textContent = "The PhishGuard owner email is not configured. Please contact support.";
      return;
    }
    $("requestEmailRecipient").textContent = "To: " + ownerEmail;
    $("requestEmailBody").textContent = buildEmail();
    $("requestEmailPreview").classList.add("is-open");
    $("confirmRequestEmail").focus();
  }

  function closePreview() {
    $("requestEmailPreview").classList.remove("is-open");
    $("submitRequest").focus();
  }

  $("submitRequest").addEventListener("click", openPreview);
  $("cancelRequestEmail").addEventListener("click", closePreview);
  $("requestEmailPreview").addEventListener("click", event => {
    if (event.target.id === "requestEmailPreview") closePreview();
  });
  $("confirmRequestEmail").addEventListener("click", () => {
    if (!window.confirm("Send this subscription request email to " + ownerEmail + "?")) return;
    emailApproved = true;
    $("requestEmailPreview").classList.remove("is-open");
    form.requestSubmit();
  });

  async function init() {
    const response = await fetch("/api/auth/me", {credentials:"same-origin", cache:"no-store"});
    const data = await response.json();
    if (!response.ok || !data.authenticated) {
      $("accountNotice").textContent = "You must sign in to the PhishGuard account you want upgraded before sending this request.";
      $("submitRequest").disabled = true;
      $("feedback").innerHTML = 'Please <a href="/">return to PhishGuard and sign in</a>, then choose your plan again.';
      return;
    }
    const user = data.user || data.account || {};
    window.phishGuardAccountEmail = user.email || "";
    $("accountNotice").textContent = "Request will be linked to your signed-in account: " + (user.email || "verified account") + ".";
    if (user.full_name) $("customerName").value = user.full_name;
    await csrf();
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (!emailApproved) {
      openPreview();
      return;
    }
    const button = $("submitRequest");
    const confirmButton = $("confirmRequestEmail");
    button.disabled = true;
    confirmButton.disabled = true;
    $("feedback").textContent = "Sending your approved request securely…";
    try {
      if (!csrfToken) await csrf();
      const response = await fetch("/api/billing/requests", {
        method:"POST", credentials:"same-origin", cache:"no-store",
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
      $("feedback").textContent = "Request #" + data.request_id + " submitted. " +
        (data.email_sent ? "The formal email has been sent to the PhishGuard owner." : data.message);
      if (data.mailto_url) {
        $("mailLink").href = data.mailto_url;
        $("mailFallback").hidden = Boolean(data.email_sent);
      }
      $("requestEmailPreview").classList.remove("is-open");
      $("submitRequest").textContent = "Request sent";
      $("subscriptionRequestForm").querySelectorAll("input,select,textarea,button").forEach(el => {
        if (el.type !== "hidden") el.disabled = true;
      });
    } catch (error) {
      $("feedback").textContent = error.message;
      emailApproved = false;
      button.disabled = false;
      confirmButton.disabled = false;
    }
  });

  init().catch(error => {
    $("accountNotice").textContent = error.message;
    $("submitRequest").disabled = true;
  });
})();