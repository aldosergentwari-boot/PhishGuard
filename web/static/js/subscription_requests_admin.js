(() => {
  const $ = id => document.getElementById(id);
  let token = "";
  let activeRequest = null;
  let preparedMailto = "";
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
  const date = value => { if(!value)return "—"; const d=new Date(value); return Number.isNaN(d.getTime())?esc(value):d.toLocaleString(); };
  async function csrf(){
    const r=await fetch("/api/auth/csrf",{credentials:"same-origin",cache:"no-store"});
    const d=await r.json(); if(!r.ok||!d.csrf_token)throw new Error("Secure owner session unavailable.");
    token=d.csrf_token;
  }
  async function api(url,options={}){
    const headers={...(options.headers||{})};
    if(options.method&&options.method!=="GET"){if(!token)await csrf();headers["X-CSRF-Token"]=token;}
    const r=await fetch(url,{...options,headers,credentials:"same-origin",cache:"no-store"});
    const d=await r.json();
    if(r.status===401){location.assign("/admin/login");throw new Error("Owner session expired.");}
    if(!r.ok)throw new Error(d.error||"Request failed.");
    return d;
  }
  function draftFor(r){
    const title=r.plan_id==="pro"?"Pro":"Business";
    return {
      subject:"PhishGuard "+title+" subscription request #"+r.id+" — next steps",
      body:"Dear "+r.customer_name+",\n\nThank you for choosing PhishGuard and submitting your request for the "+title+" plan.\n\nWe have received your request and are reviewing the details. Your current plan will remain unchanged until payment has been independently verified and your subscription is approved.\n\nPreferred payment method on your request: "+String(r.payment_method||"").replaceAll("_"," ")+"\n\nPlease reply to this email if you need clarification or would like us to confirm the payment instructions before proceeding.\n\nKind regards,\nPhishGuard Customer Support"
    };
  }
  function openComposer(r){
    activeRequest=r;
    preparedMailto="";
    const draft=draftFor(r);
    $("customerEmailRecipient").textContent=r.customer_name+" · "+r.customer_email+" · Request #"+r.id;
    $("customerEmailSubject").value=draft.subject;
    $("customerEmailBody").value=draft.body;
    $("customerEmailFeedback").textContent="This message will be emailed to the customer and saved in their in-app notifications.";
    $("openPreparedCustomerEmail").hidden=true;
    $("customerEmailModal").hidden=false;
  }
  function closeComposer(){ $("customerEmailModal").hidden=true; activeRequest=null; }
  async function load(){
    const body=$("subscriptionRequestsTable");
    if(!body)return;
    body.innerHTML='<tr><td colspan="8" class="empty">Loading requests…</td></tr>';
    try{
      const status=$("subscriptionRequestStatus")?.value ?? "pending";
      const query=new URLSearchParams({limit:"100",status});
      const d=await api("/api/admin/management/subscription-requests?"+query);
      $("subscriptionPendingCount").textContent=Number(d.pending_count||0).toLocaleString();
      const badge=$("subscriptionRequestBadge");
      if(badge){badge.textContent=String(d.pending_count||0);badge.hidden=!d.pending_count;}
      body.innerHTML=d.requests.length?d.requests.map(r=>{
        const actions='<button class="btn" data-request-contact="'+r.id+'">Reply by email</button> '+
          (r.status==="pending"
            ? '<button class="btn primary" data-request-approve="'+r.id+'">Approve & activate</button> <button class="btn" data-request-reject="'+r.id+'">Reject</button>'
            : '<span class="muted">Reviewed '+date(r.reviewed_at)+'</span>');
        return '<tr><td>#'+esc(r.id)+'<small>'+date(r.created_at)+'</small></td>'+
          '<td><strong>'+esc(r.customer_name)+'</strong><small>'+esc(r.customer_email)+'</small><small>Account #'+esc(r.user_id)+' · Current: '+esc(r.current_plan)+'</small></td>'+
          '<td><strong>'+esc(r.plan_id.toUpperCase())+'</strong><small>'+(r.plan_id==="pro"?"$4.99 / month":"$19.99 / 7 months")+'</small></td>'+
          '<td>'+esc(r.phone_number)+'</td><td>'+esc(r.payment_method.replaceAll("_"," "))+'</td>'+
          '<td>'+esc(r.message||"—")+'</td><td>'+esc(r.status)+'</td><td>'+actions+'</td></tr>';
      }).join(""):'<tr><td colspan="8" class="empty">No subscription requests in this status.</td></tr>';
      $("subscriptionRequestsFeedback").textContent="Showing "+d.requests.length+" of "+d.total+" requests.";
    }catch(error){
      body.innerHTML='<tr><td colspan="8" class="empty">'+esc(error.message)+'</td></tr>';
    }
  }
  window.loadSubscriptionRequests=load;
  $("closeCustomerEmail")?.addEventListener("click",closeComposer);
  $("customerEmailModal")?.addEventListener("click",e=>{if(e.target.id==="customerEmailModal")closeComposer();});
  $("customerEmailForm")?.addEventListener("submit",async e=>{
    e.preventDefault();
    if(!activeRequest)return;
    const button=$("sendCustomerEmail");
    const feedback=$("customerEmailFeedback");
    button.disabled=true;
    $("openPreparedCustomerEmail").hidden=true;
    feedback.textContent="Sending and saving message…";
    try{
      const d=await api("/api/admin/management/subscription-requests/"+activeRequest.id+"/reply",{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({subject:$("customerEmailSubject").value.trim(),message:$("customerEmailBody").value.trim()})
      });
      preparedMailto=d.mailto_url||"";
      feedback.textContent=d.message;
      if(!d.email_sent&&preparedMailto){
        const link=$("openPreparedCustomerEmail");
        link.href=preparedMailto;
        link.hidden=false;
        link.textContent="Open prepared email to send manually";
      }
    }catch(error){feedback.textContent=error.message;}
    finally{button.disabled=false;}
  });
  document.addEventListener("click",async event=>{
    const target=event.target;
    if(target.id==="subscriptionRequestsRefresh"||target.id==="subscriptionRequestFilter"){await load();return;}
    const contact=target.closest("[data-request-contact]");
    const approve=target.closest("[data-request-approve]");
    const reject=target.closest("[data-request-reject]");
    try{
      if(contact){
        const id=Number(contact.dataset.requestContact);
        const row=await api("/api/admin/management/subscription-requests?status=");
        const request=row.requests.find(item=>Number(item.id)===id);
        if(request)openComposer(request);
      }else if(approve){
        const reference=prompt("Enter the payment transaction reference or a clear record of the manual payment. Verify the money has arrived in your account before continuing.");
        if(!reference||reference.trim().length<3)return;
        if(!confirm("Have you independently verified that the full payment has arrived? Only continue if the money is confirmed in your account."))return;
        await api("/api/admin/management/subscription-requests/"+approve.dataset.requestApprove+"/approve",{
          method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify({payment_confirmed:true,payment_reference:reference.trim(),admin_note:"Payment independently verified by owner."})
        });
        $("subscriptionRequestsFeedback").textContent="Payment confirmed, subscription activated and payment history updated.";
        await load();
      }else if(reject){
        const note=prompt("Reason for rejecting this subscription request (at least 3 characters):");
        if(!note||note.trim().length<3)return;
        await api("/api/admin/management/subscription-requests/"+reject.dataset.requestReject+"/reject",{
          method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({admin_note:note.trim()})
        });
        $("subscriptionRequestsFeedback").textContent="Request rejected and customer notified.";
        await load();
      }
    }catch(error){$("subscriptionRequestsFeedback").textContent=error.message;}
  });
  csrf().then(load).then(()=>window.setInterval(()=>{ if(document.visibilityState==="visible"&&!activeRequest) load(); },30000)).catch(error=>{if($("subscriptionRequestsFeedback"))$("subscriptionRequestsFeedback").textContent=error.message;});
})();