(() => {
  const $ = id => document.getElementById(id);
  let csrfToken = "";
  async function csrf() {
    const response = await fetch("/api/auth/csrf",{credentials:"same-origin",cache:"no-store"});
    const data = await response.json();
    if(!response.ok || !data.csrf_token) throw new Error("Secure session could not be verified. Please sign in again.");
    csrfToken = data.csrf_token;
  }
  async function init() {
    const response = await fetch("/api/auth/me",{credentials:"same-origin",cache:"no-store"});
    const data = await response.json();
    if(!response.ok || !data.authenticated) {
      $("accountNotice").textContent = "You must sign in to the PhishGuard account you want upgraded before sending this request.";
      $("submitRequest").disabled = true;
      $("feedback").innerHTML = 'Please <a href="/">return to PhishGuard and sign in</a>, then choose your plan again.';
      return;
    }
    const user = data.user || data.account || {};
    $("accountNotice").textContent = "Request will be linked to your signed-in account: " + (user.email || "verified account") + ".";
    if(user.full_name) $("customerName").value = user.full_name;
    await csrf();
  }
  $("subscriptionRequestForm").addEventListener("submit",async event=>{
    event.preventDefault();
    const button=$("submitRequest");
    button.disabled=true;
    $("feedback").textContent="Sending your request securely…";
    try {
      if(!csrfToken) await csrf();
      const response=await fetch("/api/billing/requests",{
        method:"POST",credentials:"same-origin",cache:"no-store",
        headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},
        body:JSON.stringify({
          plan_id:$("selectedPlan").value,
          customer_name:$("customerName").value.trim(),
          phone_number:$("phoneNumber").value.trim(),
          payment_method:$("paymentMethod").value,
          message:$("message").value.trim()
        })
      });
      const data=await response.json();
      if(!response.ok) throw new Error(data.error || "Could not submit your request.");
      $("feedback").textContent="Request #"+data.request_id+" received. "+data.message;
      if(data.mailto_url){
        $("mailLink").href=data.mailto_url;
        $("mailFallback").hidden=Boolean(data.email_sent);
      }
      $("submitRequest").textContent="Request sent";
      $("subscriptionRequestForm").querySelectorAll("input,select,textarea").forEach(el=>{if(el.type!=="hidden")el.disabled=true;});
    } catch(error) {
      $("feedback").textContent=error.message;
      button.disabled=false;
    }
  });
  init().catch(error=>{
    $("accountNotice").textContent=error.message;
    $("submitRequest").disabled=true;
  });
})();
