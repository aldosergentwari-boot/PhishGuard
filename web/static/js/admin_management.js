(() => {
  const $ = (id) => document.getElementById(id);
  let token = "";
  let userOffset = 0;
  const pageSize = 100;
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const dt = (v) => { if (!v) return "—"; const d = new Date(v); return Number.isNaN(d.getTime()) ? esc(v) : d.toLocaleString(); };
  async function csrf() {
    const r = await fetch("/api/auth/csrf", {credentials:"same-origin",cache:"no-store"});
    const d = await r.json(); if (!r.ok || !d.csrf_token) throw new Error("Secure owner session unavailable.");
    token = d.csrf_token;
  }
  async function api(url, options={}) {
    const headers = {...(options.headers || {})};
    if (options.method && options.method !== "GET") { if (!token) await csrf(); headers["X-CSRF-Token"] = token; }
    const r = await fetch(url,{...options,headers,credentials:"same-origin",cache:"no-store"});
    const d = await r.json();
    if (r.status === 401) { location.assign("/admin/login"); throw new Error("Owner session expired."); }
    if (!r.ok) throw new Error(d.error || "Request failed.");
    return d;
  }
  function feedback(id,msg){ const el=$(id); if(el)el.textContent=msg; }
  async function users() {
    const q = new URLSearchParams({limit:pageSize,offset:userOffset,q:$("advUserQ").value,status:$("advUserStatus").value,plan:$("advUserPlan").value});
    const d = await api("/api/admin/management/users?"+q);
    $("advUsers").innerHTML = d.users.length ? d.users.map(u => {
      const usage=u.scan_usage||{}, used=Number(usage.scans_used||0), total=Number(usage.scans_limit||0);
      const base=Number(usage.plan_scans_limit??usage.default_plan_limit??0);
      const owner=Boolean(u.is_owner);
      const scanCell='<strong>'+esc(used)+' / '+esc(total)+' scans</strong><small class="scan-usage-note">'+esc(Math.max(0,total-used))+' remaining this month</small><div class="scan-limit-controls"><input aria-label="Monthly scan limit for '+esc(u.email)+'" type="number" min="0" max="100000" step="1" value="'+esc(base)+'" data-scan-limit-input="'+esc(u.id)+'"><button class="btn" data-set-scan-limit="'+esc(u.id)+'">Save</button><button class="btn subtle" data-reset-scan-limit="'+esc(u.id)+'">Default</button></div>';
      const statusAction=owner?(u.is_active?'<strong>Owner protected</strong>':'<button class="btn" data-toggle-user="'+u.id+'" data-active="true">Reactivate owner</button>'):'<button class="btn" data-toggle-user="'+u.id+'" data-active="'+(!u.is_active)+'">'+(u.is_active?"Suspend":"Activate")+'</button>';
      const planControls=' <select data-plan-user="'+u.id+'" aria-label="Plan for '+esc(u.email)+'"><option value="free" '+(u.plan_id==="free"?'selected':'')+'>Free</option><option value="pro" '+(u.plan_id==="pro"?'selected':'')+'>Pro</option><option value="business" '+(u.plan_id==="business"?'selected':'')+'>Business</option></select><button class="btn" data-set-plan="'+u.id+'">Set plan</button>';
      const actions=statusAction+planControls;
      return '<tr data-user-row="'+esc(u.id)+'"><td>'+esc(u.id)+'</td><td>'+esc(u.email)+(owner?' <strong>(Owner)</strong>':'')+'</td><td>'+esc(u.plan_id)+'</td><td>'+esc(u.is_active?"Active":"Suspended")+'</td><td>'+esc(u.email_verified?"Verified":"Unverified")+'</td><td>'+scanCell+'</td><td><button class="btn subtle" data-view-scans="'+esc(u.id)+'">View scans</button></td><td>'+actions+'</td></tr>';
    }).join("") : '<tr><td colspan="8" class="empty">No matching accounts.</td></tr>';
    $("advUserPage").textContent = "Showing "+(d.total?userOffset+1:0)+"–"+Math.min(userOffset+d.users.length,d.total)+" of "+d.total;
    $("advUserPrev").disabled = userOffset === 0; $("advUserNext").disabled = userOffset+d.users.length >= d.total;
  }
  async function payments() {
    const q=new URLSearchParams({limit:100,q:$("advPaymentQ").value,status:$("advPaymentStatus").value});
    const d=await api("/api/admin/management/payments?"+q);
    $("advPayments").innerHTML=d.payments.length?d.payments.map(p=>'<tr><td>'+esc(p.id)+'</td><td>'+esc(p.email)+'</td><td>'+esc(p.plan_id)+'</td><td>'+esc(p.amount)+' '+esc(p.currency)+'</td><td>'+esc(p.payment_method)+' ('+esc(p.provider||'flutterwave')+')</td><td>'+esc(p.status)+'</td><td>'+dt(p.created_at)+'</td><td><button class="btn" data-payment="'+p.id+'">Details</button></td></tr>').join(""):'<tr><td colspan="8" class="empty">No payments.</td></tr>';
  }
  async function analytics(){
    const a=(await api("/api/admin/management/analytics")).analytics;
    $("advAnalytics").innerHTML=[["Total users",a.total_users],["Active users",a.active_users],["Paid subscribers",a.paid_subscribers],["Conversion",a.conversion_rate+"%"],["Lifetime revenue",a.lifetime_revenue],["Revenue this month",a.revenue_this_month],["Scans this month",a.scans_this_month]].map(x=>'<article class="metric"><span>'+esc(x[0].toUpperCase())+'</span><strong>'+esc(x[1])+'</strong></article>').join("");
    feedback("advAnalyticsNote",a.currency_note);
  }
  async function subscriptions(){
    const d=await api("/api/admin/management/subscriptions?limit=100");
    $("advSubscriptions").innerHTML=d.subscriptions.length?d.subscriptions.map(s=>'<tr><td>'+esc(s.id)+'</td><td>'+esc(s.email)+'</td><td>'+esc(s.plan_id)+'</td><td>'+esc(s.status)+'</td><td>'+dt(s.started_at)+'</td><td>'+dt(s.current_period_end)+'</td><td>'+(s.status==="active"&&s.plan_id!=="free"?'<button class="btn" data-cancel-sub="'+s.id+'">Cancel</button>':"—")+'</td></tr>').join(""):'<tr><td colspan="7" class="empty">No subscriptions.</td></tr>';
  }
  async function monetization(){
    const d=await api("/api/admin/management/monetization");
    const a=d.ads||{};
    const items=[
      ["AdSense publisher approval",a.approved],
      ["Certified CMP configured",a.consent_platform_configured],
      ["Ad display enabled",a.enabled_requested],
      ["Publisher ID valid",a.publisher_id_configured],
      ["Ad slot valid",a.slot_configured],
      ["Google AdSense ready",a.ready],
      ["Root ads.txt configured",a.ads_txt_endpoint_configured],
      ["Manual subscription requests",d.billing_model==="manual_owner_approval"],
      ["Automated online checkout disabled",d.automated_checkout_enabled===false]
    ];
    $("monetizationMetrics").innerHTML=items.map(([label,ready])=>
      '<article class="metric"><span>'+esc(label.toUpperCase())+'</span><strong class="'+(ready?'status-ready':'status-pending')+'">'+(ready?'Ready':'Not configured')+'</strong></article>'
    ).join("");
    feedback("monetizationNote",
      "Paid subscriptions are handled manually: customers submit requests, the owner verifies payment independently, and only the owner can activate Pro or Business. " +
      (a.ready ? "AdSense configuration and CMP gate are ready; each browser still needs valid TCF consent, and paid plans remain ad-free."
        : "Ads remain disabled until publisher approval, a certified TCF CMP, and every AdSense setting are complete.")
    );
  }
  async function audit(){
    const d=await api("/api/admin/management/audit?limit=100");
    $("advAudit").innerHTML=d.events.length?d.events.map(a=>'<tr><td>'+dt(a.created_at)+'</td><td>'+esc(a.actor_email)+'</td><td>'+esc(a.action)+'</td><td>'+esc(a.target_type)+' #'+esc(a.target_id)+'</td><td>'+esc(a.details)+'</td></tr>').join(""):'<tr><td colspan="5" class="empty">No administrative actions recorded yet.</td></tr>';
  }

  async function adminInbox(){
    const d=await api("/api/admin/management/inbox?limit=100");
    const badge=$("adminInboxBadge");
    if(badge){badge.textContent=String(d.unread_count||0);badge.hidden=!(d.unread_count>0);badge.classList.toggle("off",!(d.unread_count>0));}
    const target=$("adminInboxList");
    if(!target)return;
    target.innerHTML=d.notifications.length?d.notifications.map(n=>{
      const meta=n.metadata||{};
      const details=n.event_type==="subscription_request"
        ? '<div class="inbox-meta"><span>Request #'+esc(meta.request_id||"—")+'</span><span>Plan: '+esc(meta.plan_id||"—")+'</span><span>Phone: '+esc(meta.phone_number||"—")+'</span><span>Payment: '+esc(meta.payment_method||"—")+'</span></div>'+(meta.message?'<p>Customer message: '+esc(meta.message)+'</p>':'')+'<p><a href="#" data-open-subscription-requests>Open subscription requests</a></p>'
        : (n.event_type==="new_registration" ? '<div class="inbox-meta"><span>Account ID: '+esc(meta.user_id||n.user_id||"—")+'</span></div>' : '');
      return '<article class="panel inbox-item '+(n.read_at?'is-read':'is-unread')+'"><div class="inbox-heading"><div><strong>'+esc(n.title)+'</strong><small>'+esc(n.email||"Unknown user")+' · '+dt(n.created_at)+'</small></div><span>'+esc(n.event_type.replace(/_/g," "))+'</span></div><p>'+esc(n.message)+'</p>'+details+(n.read_at?'':'<button class="btn subtle" data-mark-inbox-read="'+esc(n.id)+'">Mark as read</button>')+'</article>';
    }).join(""):'<div class="panel empty">No incoming admin notifications yet.</div>';
  }
  async function show(name){
    const actions={ "advanced-users":users,"advanced-payments":payments,"analytics":analytics,"subscriptions":subscriptions,"monetization":monetization,"audit":audit,"notifications":adminInbox };
    if(actions[name])try{await actions[name]();}catch(e){alert(e.message);}
  }
  $("monetizationRefresh")?.addEventListener("click", () => show("monetization"));
  document.addEventListener("click", async e => {
    const t=e.target;
    if(t.matches(".nav[data-section]")) show(t.dataset.section);
    try {
      if(t.dataset.viewScans){
        const userId=t.dataset.viewScans;
        const row=document.querySelector('[data-user-row="'+userId+'"]');
        const existing=row && row.nextElementSibling;
        if(existing && existing.dataset.scanDetails==="true"){existing.remove();t.textContent="View scans";return;}
        if(existing && existing.dataset.scanDetails==="loading") existing.remove();
        const detail=document.createElement("tr");
        detail.dataset.scanDetails="loading";
        detail.innerHTML='<td colspan="8">Loading scan history…</td>';
        row.after(detail);
        t.textContent="Hide scans";
        try{
          const d=await api("/api/admin/management/users/"+userId+"/scans?limit=50");
          detail.dataset.scanDetails="true";
          const rows=d.scans.length?d.scans.map(s=>'<tr><td>'+esc(s.id)+'</td><td>'+esc(s.url)+'</td><td>'+esc(s.domain||"—")+'</td><td>'+esc(s.prediction)+'</td><td>'+esc((Number(s.risk_score||0)*100).toFixed(1))+'%</td><td>'+esc(s.detection_mode||"—")+'</td><td>'+dt(s.scanned_at)+'</td></tr>').join(""):'<tr><td colspan="7" class="empty">No URL scans recorded for this account.</td></tr>';
          detail.innerHTML='<td colspan="8"><div class="user-scan-history"><strong>Scan history · '+esc(d.user.email)+'</strong><small>'+esc(d.summary.total)+' total · '+esc(d.summary.phishing)+' phishing · '+esc(d.summary.suspicious)+' suspicious · '+esc(d.summary.legitimate)+' legitimate</small><div class="table-wrap"><table><thead><tr><th>ID</th><th>URL</th><th>DOMAIN</th><th>RESULT</th><th>RISK</th><th>MODE</th><th>SCANNED AT</th></tr></thead><tbody>'+rows+'</tbody></table></div><small>Showing '+esc(d.scans.length)+' most recent scans.</small></div></td>';
        }catch(err){detail.dataset.scanDetails="true";detail.innerHTML='<td colspan="8">'+esc(err.message)+'</td>';t.textContent="View scans";}
      }
      if(t.dataset.toggleUser){
        const reason=prompt("Reason for this account status change (required):"); if(!reason)return;
        await api("/api/admin/management/users/"+t.dataset.toggleUser+"/status",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({active:t.dataset.active==="true",reason})}); await users();
      }
      if(t.dataset.setScanLimit || t.dataset.resetScanLimit){
        const userId=t.dataset.setScanLimit || t.dataset.resetScanLimit;
        const input=document.querySelector('[data-scan-limit-input="'+userId+'"]');
        const monthlyLimit=t.dataset.resetScanLimit ? null : Number(input && input.value);
        if(monthlyLimit!==null && (!Number.isInteger(monthlyLimit)||monthlyLimit<0||monthlyLimit>100000)){
          alert("Enter a whole-number monthly limit from 0 to 100000."); return;
        }
        const reason=prompt(t.dataset.resetScanLimit
          ? "Reason for restoring this user's plan default scan limit:"
          : "Reason for changing this user's monthly scan limit:");
        if(!reason || reason.trim().length<3)return;
        await api("/api/admin/management/users/"+userId+"/scan-limit",{
          method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify({monthly_limit:monthlyLimit,reason:reason.trim()})
        });
        await users();
        alert(t.dataset.resetScanLimit ? "Plan default scan limit restored." : "Monthly scan limit updated.");
      }
      if(t.dataset.setPlan){
        const plan=document.querySelector('[data-plan-user="'+t.dataset.setPlan+'"]').value;
        const reason=prompt("Reason for this admin plan change (required):"); if(!reason)return;
        const payload={plan_id:plan,reason};
        if(plan==="pro"||plan==="business"){
          const reference=prompt("Enter the payment transaction reference. First verify that the money has arrived in your account."); if(!reference||reference.trim().length<3)return;
          if(!confirm("Have you independently verified that the full payment has arrived?"))return;
          payload.payment_confirmed=true;payload.payment_reference=reference.trim();
        }
        await api("/api/admin/management/users/"+t.dataset.setPlan+"/plan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); await users();
        alert("Plan change saved.");
      }
      if(t.dataset.markInboxRead){
        await api("/api/admin/management/inbox/"+t.dataset.markInboxRead+"/read",{method:"POST"});
        await adminInbox();
      }
      if(t.hasAttribute("data-open-subscription-requests")){
        e.preventDefault();
        const nav=document.querySelector('.nav[data-section="subscription-requests"]');
        if(nav)nav.click();
      }
      if(t.dataset.payment){
        const d=await api("/api/admin/management/payments/"+t.dataset.payment);
        alert(JSON.stringify(d.payment,null,2));
      }
      if(t.dataset.cancelSub){
        const reason=prompt("Reason for cancelling this subscription (required):"); if(!reason)return;
        await api("/api/admin/management/subscriptions/"+t.dataset.cancelSub+"/cancel",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({reason})}); await subscriptions();
      }
    } catch(err){alert(err.message);}
  });
  document.addEventListener("submit", async e => {
    if(e.target.id!=="advNotificationForm")return;
    e.preventDefault();
    try{
      await api("/api/admin/management/notifications",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({
        user_id:Number($("advNotifyUser").value),title:$("advNotifyTitle").value,message:$("advNotifyMessage").value,category:$("advNotifyCategory").value
      })});
      feedback("advNotifyFeedback","In-app notification saved. No email was sent.");e.target.reset();
    }catch(err){feedback("advNotifyFeedback",err.message);}
  });
  document.addEventListener("click",e=>{
    if(e.target.id==="advUserFilter"){userOffset=0;users().catch(x=>alert(x.message));}
    if(e.target.id==="advUserPrev"){userOffset=Math.max(0,userOffset-pageSize);users().catch(x=>alert(x.message));}
    if(e.target.id==="advUserNext"){userOffset+=pageSize;users().catch(x=>alert(x.message));}
    if(e.target.id==="advPaymentFilter")payments().catch(x=>alert(x.message));
    if(e.target.id==="advAnalyticsRefresh")analytics().catch(x=>alert(x.message));
    if(e.target.id==="advSubscriptionsRefresh")subscriptions().catch(x=>alert(x.message));
    if(e.target.id==="advAuditRefresh")audit().catch(x=>alert(x.message));
    if(e.target.id==="adminInboxRefresh")adminInbox().catch(x=>alert(x.message));
  });
  csrf().then(()=>Promise.allSettled([users(),payments(),analytics(),subscriptions(),audit(),adminInbox()])).catch(e=>console.warn(e.message));
})();