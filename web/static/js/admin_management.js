(() => {
  const $ = (id) => document.getElementById(id);
  let token = "";
  let userOffset = 0;
  const pageSize = 25;
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
    $("advUsers").innerHTML = d.users.length ? d.users.map(u => '<tr><td>'+esc(u.id)+'</td><td>'+esc(u.email)+'</td><td>'+esc(u.plan_id)+'</td><td>'+esc(u.is_active?"Active":"Suspended")+'</td><td>'+esc(u.email_verified?"Verified":"Unverified")+'</td><td><button class="btn" data-toggle-user="'+u.id+'" data-active="'+(!u.is_active)+'">'+(u.is_active?"Suspend":"Activate")+'</button> <select data-plan-user="'+u.id+'"><option value="free">Free</option><option value="pro">Pro</option><option value="business">Business</option></select><button class="btn" data-set-plan="'+u.id+'">Set</button></td></tr>').join("") : '<tr><td colspan="6" class="empty">No matching accounts.</td></tr>';
    $("advUserPage").textContent = "Showing "+(d.total?userOffset+1:0)+"–"+Math.min(userOffset+d.users.length,d.total)+" of "+d.total;
    $("advUserPrev").disabled = userOffset === 0; $("advUserNext").disabled = userOffset+d.users.length >= d.total;
  }
  async function payments() {
    const q=new URLSearchParams({limit:100,q:$("advPaymentQ").value,status:$("advPaymentStatus").value});
    const d=await api("/api/admin/management/payments?"+q);
    $("advPayments").innerHTML=d.payments.length?d.payments.map(p=>'<tr><td>'+esc(p.id)+'</td><td>'+esc(p.email)+'</td><td>'+esc(p.plan_id)+'</td><td>'+esc(p.amount)+' '+esc(p.currency)+'</td><td>'+esc(p.payment_method)+'</td><td>'+esc(p.status)+'</td><td>'+dt(p.created_at)+'</td><td><button class="btn" data-payment="'+p.id+'">Details</button></td></tr>').join(""):'<tr><td colspan="8" class="empty">No payments.</td></tr>';
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
  async function audit(){
    const d=await api("/api/admin/management/audit?limit=100");
    $("advAudit").innerHTML=d.events.length?d.events.map(a=>'<tr><td>'+dt(a.created_at)+'</td><td>'+esc(a.actor_email)+'</td><td>'+esc(a.action)+'</td><td>'+esc(a.target_type)+' #'+esc(a.target_id)+'</td><td>'+esc(a.details)+'</td></tr>').join(""):'<tr><td colspan="5" class="empty">No administrative actions recorded yet.</td></tr>';
  }
  async function show(name){
    const actions={ "advanced-users":users,"advanced-payments":payments,"analytics":analytics,"subscriptions":subscriptions,"audit":audit };
    if(actions[name])try{await actions[name]();}catch(e){alert(e.message);}
  }
  document.addEventListener("click", async e => {
    const t=e.target;
    if(t.matches(".nav[data-section]")) show(t.dataset.section);
    try {
      if(t.dataset.toggleUser){
        const reason=prompt("Reason for this account status change (required):"); if(!reason)return;
        await api("/api/admin/management/users/"+t.dataset.toggleUser+"/status",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({active:t.dataset.active==="true",reason})}); await users();
      }
      if(t.dataset.setPlan){
        const plan=document.querySelector('[data-plan-user="'+t.dataset.setPlan+'"]').value;
        const reason=prompt("Reason for this admin plan override (required):"); if(!reason)return;
        await api("/api/admin/management/users/"+t.dataset.setPlan+"/plan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({plan_id:plan,reason})}); await users();
        alert("Plan override saved. This action does not create or verify a payment.");
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
  });
  csrf().then(()=>Promise.allSettled([users(),payments(),analytics(),subscriptions(),audit()])).catch(e=>console.warn(e.message));
})();