// Sign-in and identity: single sign-on, the multi-factor sign-in step,
// profile security (MFA enrolment) and the Sign-in & identity
// administration pane. Loaded after app.js and uses its helpers.
(()=>{
const ROLES=['Admin','Editor','Member','Stakeholder'];
const PROVIDERS={local:'Local',ldap:'Directory',oidc:'Single sign-on',serviceops:'ServiceOps'};
const identityStyles=`.mfa-step p{margin:0 0 12px;color:var(--muted)}.mfa-step input{letter-spacing:.2em;font-size:18px}.login-sso{display:block;text-align:center;margin-top:10px}.login-sso.secondary{width:100%}.secret-box{font-family:ui-monospace,monospace;font-size:15px;background:#f6f8fc;border:1px solid var(--line);border-radius:8px;padding:10px 12px;word-break:break-all;margin:6px 0}.backup-codes{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;font-family:ui-monospace,monospace;background:#f6f8fc;border-radius:8px;padding:12px;margin:10px 0}.security-status{display:flex;gap:10px;align-items:center;margin-bottom:12px}.identity-grid{display:grid;gap:16px}.identity-card .formgrid{grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}.mapping-rows{display:grid;gap:6px;margin:6px 0}.mapping-row{display:grid;grid-template-columns:1fr 1fr 32px;gap:6px}.mapping-row button{min-height:32px}.check-result{background:#f6f8fc;border-radius:8px;padding:12px;margin-top:8px;font-size:13px}.check-result ul{margin:6px 0 0 18px;padding:0}.id-badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;border-radius:999px;padding:1px 7px;margin-left:6px;background:#eef1f7;color:#41506b;vertical-align:1px}.id-badge.ok{background:#e4f5ed;color:#17855e}.id-badge.warn{background:#fdecee;color:#b43d4b}.test-line{font-size:13px;margin-top:6px}.preset-row{display:flex;gap:6px;flex-wrap:wrap;margin-top:4px}.preset-row button{font-size:12px;padding:4px 8px;min-height:28px}`;
document.head.append(Object.assign(document.createElement('style'),{textContent:identityStyles}));

// --- sign-in --------------------------------------------------------------
const loginForm=$('#enterpriseLoginForm');
const mfaForm=document.createElement('form');
mfaForm.id='mfaForm';mfaForm.className='enterprise-login mfa-step';mfaForm.hidden=true;
mfaForm.innerHTML=`<div class="enterprise-brand"><span class="enterprise-mark">F</span><strong>FlowOps</strong></div><h1>Verify it's you</h1><p>Enter the 6-digit code from your authenticator app, or one of your backup codes.</p><div class="auth-row"><label for="mfaCode">Verification code</label><input id="mfaCode" name="code" autocomplete="one-time-code" inputmode="numeric" required maxlength="20"></div><button class="primary login-button" type="submit">Verify</button><div class="enterprise-meta"><a href="#" id="mfaBack">Back to sign in</a></div>`;
if(loginForm)loginForm.after(mfaForm);
let mfaToken='';
async function finishSignIn(user){
  state.user=user;state.csrf=user.csrf_token;
  const session=await api('/api/auth/me');
  await enterWorkspace(session);
  if(user.notice)toast(user.notice);
}
window.startMfaStep=token=>{mfaToken=token;if(loginForm)loginForm.hidden=true;mfaForm.hidden=false;mfaForm.reset();$('#mfaCode').focus()};
function backToSignIn(){mfaToken='';mfaForm.hidden=true;if(loginForm){loginForm.hidden=false;$('#loginPassword').value='';$('#loginPassword').focus()}}
$('#mfaBack')?.addEventListener('click',e=>{e.preventDefault();backToSignIn()});
mfaForm.onsubmit=async e=>{e.preventDefault();const button=mfaForm.querySelector('button[type=submit]');button.disabled=true;
  try{await finishSignIn(await api('/api/auth/mfa',{method:'POST',body:JSON.stringify({mfa_token:mfaToken,code:$('#mfaCode').value})}));mfaForm.hidden=true;if(loginForm)loginForm.hidden=false}
  catch(err){toast(err.message,true);if(err.status===401&&/expired|Sign in again/.test(err.message))backToSignIn();else{$('#mfaCode').value='';$('#mfaCode').focus()}}
  finally{button.disabled=false}};
if(loginForm)loginForm.onsubmit=async e=>{e.preventDefault();const button=e.currentTarget.querySelector('button[type=submit]');button.disabled=true;button.textContent='Signing in…';const values=Object.fromEntries(new FormData(e.currentTarget));
  try{const result=await api('/api/auth/login',{method:'POST',body:JSON.stringify({username:values.username,password:values.password,source:values.source})});
    if(result.mfa_required)return window.startMfaStep(result.mfa_token);
    await finishSignIn(result)}
  catch(err){toast(err.message,true);$('#loginPassword').value='';$('#loginPassword').focus()}
  finally{button.disabled=false;button.textContent='Sign in'}};
api('/api/auth/sources').then(config=>{if(!config.sso||!loginForm||$('.login-sso'))return;const link=document.createElement('a');link.className='secondary login-sso';link.href=config.sso.url;link.textContent=config.sso.label;loginForm.querySelector('.login-button').after(link)}).catch(()=>{});

// --- profile security ------------------------------------------------------
const tabs=$('.profile-tabs');
if(tabs&&!$('[data-ptab="security"]')){
  const tab=document.createElement('button');tab.className='profile-tab';tab.dataset.ptab='security';tab.textContent='Security';tab.setAttribute('role','tab');tab.setAttribute('aria-controls','profileTabSecurity');tab.onclick=()=>{showProfileTab('security');renderSecurity()};
  $('[data-ptab="privacy"]').before(tab);
  const pane=document.createElement('div');pane.id='profileTabSecurity';pane.className='profile-pane';$('#profileTabPrivacy').before(pane);
}
async function refreshUser(){const session=await api('/api/auth/me');state.user=session.user}
function renderSecurity(view){
  const u=state.user,pane=$('#profileTabSecurity');if(!pane)return;
  if(u.auth_provider==='oidc'){pane.innerHTML='<p class="muted">You sign in with single sign-on. Multi-factor sign-in is managed by your identity provider.</p>';return}
  if(view)return void(pane.innerHTML=view);
  if(u.mfa_enabled){
    pane.innerHTML=`<div class="security-status"><span class="id-badge ok">On</span><b>Multi-factor sign-in</b></div><p class="muted">Each sign-in asks for a code from your authenticator app. ${u.mfa_backup_codes_remaining} backup code${u.mfa_backup_codes_remaining===1?'':'s'} left.</p><form id="mfaManageForm"><label>Current code or backup code<input name="code" autocomplete="one-time-code" required></label><div class="modalactions"><button type="button" class="secondary danger" data-mfa="disable">Turn off</button><button class="primary" data-mfa="backup-codes">Generate new backup codes</button></div></form>`;
    const form=$('#mfaManageForm');
    $$('[data-mfa]',form).forEach(b=>b.onclick=async e=>{e.preventDefault();if(!form.reportValidity())return;const action=b.dataset.mfa;
      if(action==='disable'&&!await confirmDialog({title:'Turn off multi-factor sign-in?',message:'Your account will be protected by your password alone.',confirmLabel:'Turn off',danger:true}))return;
      try{const result=await api(`/api/profile/mfa/${action}`,{method:'POST',body:JSON.stringify({code:form.code.value})});await refreshUser();
        if(result.backup_codes)return renderSecurity(backupCodesView(result.backup_codes));
        toast('Multi-factor sign-in turned off');renderSecurity()}catch(err){toast(err.message,true)}});
    return}
  const directory=u.auth_provider==='ldap';
  pane.innerHTML=`<div class="security-status"><span class="id-badge">Off</span><b>Multi-factor sign-in</b></div><p class="muted">Add a second step to sign-in using an authenticator app such as Microsoft Authenticator, Google Authenticator or 1Password.</p><form id="mfaSetupForm"><label>${directory?'Directory password':'Current password'}<input name="password" type="password" autocomplete="current-password" required></label><div class="modalactions"><span></span><button class="primary">Set up</button></div></form>`;
  $('#mfaSetupForm').onsubmit=async e=>{e.preventDefault();try{const setup=await api('/api/profile/mfa/setup',{method:'POST',body:JSON.stringify({password:e.currentTarget.password.value})});
    renderSecurity(`<p><b>1.</b> Add FlowOps to your authenticator app. On this device, <a href="${esc(setup.otpauth_uri)}">open it in your authenticator app</a>, or enter this key:</p><div class="secret-box">${esc(setup.secret.match(/.{1,4}/g).join(' '))}</div><form id="mfaEnableForm"><label><b>2.</b> Enter the 6-digit code it shows<input name="code" autocomplete="one-time-code" inputmode="numeric" required maxlength="8"></label><div class="modalactions"><button type="button" class="secondary" id="mfaCancel">Cancel</button><button class="primary">Turn on</button></div></form>`);
    $('#mfaCancel').onclick=()=>renderSecurity();
    $('#mfaEnableForm').onsubmit=async e2=>{e2.preventDefault();try{const result=await api('/api/profile/mfa/enable',{method:'POST',body:JSON.stringify({code:e2.currentTarget.code.value})});await refreshUser();toast('Multi-factor sign-in is on');renderSecurity(backupCodesView(result.backup_codes))}catch(err){toast(err.message,true)}}
  }catch(err){toast(err.message,true)}};
}
function backupCodesView(codes){
  setTimeout(()=>{$('#copyBackupCodes').onclick=()=>navigator.clipboard?.writeText(codes.join('\n')).then(()=>toast('Backup codes copied'));$('#backupCodesDone').onclick=()=>renderSecurity()});
  return `<div class="security-status"><span class="id-badge ok">On</span><b>Save your backup codes</b></div><p class="muted">Each code signs you in once if you lose your device. They are shown only now.</p><div class="backup-codes">${codes.map(c=>`<span>${esc(c)}</span>`).join('')}</div><div class="modalactions"><button type="button" class="secondary" id="copyBackupCodes">Copy codes</button><button type="button" class="primary" id="backupCodesDone">I've saved them</button></div>`;
}
const identityOpenProfile=openProfileModal;
openProfileModal=function(){identityOpenProfile();const local=state.user.auth_provider==='local'||!state.user.auth_provider;$('[data-ptab="password"]').hidden=!local;renderSecurity()};
$('#openProfile').onclick=openProfileModal;

// --- administration ----------------------------------------------------------
adminTools['platform-security'].unshift({key:'identity',title:'Sign-in & identity',desc:'Local sign-in policy, AD/LDAP directory, Keycloak/OIDC and multi-factor.',icon:'⚿'});
if(!$('#adminIdentity')){const pane=document.createElement('section');pane.id='adminIdentity';pane.className='admin-pane';$('#adminSessions').after(pane)}
const identityLoadAdminPanel=loadAdminPanel;
loadAdminPanel=async function(name){if(name==='identity')return renderIdentityAdmin();return identityLoadAdminPanel(name)};

function mappingEditor(name,json,values){
  let mapping={};try{mapping=JSON.parse(json||'{}')}catch(_){}
  const row=(group='',value='')=>`<div class="mapping-row"><input aria-label="Directory group" placeholder="Group name or DN" value="${esc(group)}">${values?`<select aria-label="FlowOps role">${values.map(r=>`<option ${r===value?'selected':''}>${r}</option>`).join('')}</select>`:`<input aria-label="FlowOps team" placeholder="Team" value="${esc(value)}">`}<button type="button" class="secondary" aria-label="Remove mapping">×</button></div>`;
  return `<div class="mapping-rows" data-mapping="${name}">${Object.entries(mapping).map(([g,v])=>row(g,v)).join('')}</div><button type="button" class="secondary" data-add-mapping="${name}" data-template="${esc(row())}">+ Add mapping</button>`;
}
function bindMappingEditors(root){
  $$('[data-add-mapping]',root).forEach(b=>b.onclick=()=>{$(`[data-mapping="${b.dataset.addMapping}"]`,root).insertAdjacentHTML('beforeend',b.dataset.template);bindMappingEditors(root)});
  $$('.mapping-row button',root).forEach(b=>b.onclick=()=>b.closest('.mapping-row').remove());
}
function readMapping(root,name){const out={};$$(`[data-mapping="${name}"] .mapping-row`,root).forEach(r=>{const [g,v]=[...r.querySelectorAll('input,select')].map(x=>x.value.trim());if(g&&v)out[g]=v});return JSON.stringify(out)}
const checked=v=>boolValue(v)?'checked':'';
function roleSelect(name,value){return `<select name="${name}">${ROLES.map(r=>`<option ${r===(value||'Member')?'selected':''}>${r}</option>`).join('')}</select>`}

async function renderIdentityAdmin(){
  const root=$('#adminIdentity');if(!root)return;
  let data,settings;try{[data,settings]=await Promise.all([api('/api/admin/integrations'),api('/api/admin/settings')])}catch(err){return toast(err.message,true)}
  const l=data.ldap,o=data.oidc,p=data.local,editable=l.credential_editable;
  root.innerHTML=`<div class="pagehead"><div><span class="eyebrow">PLATFORM & SECURITY</span><h2>Sign-in & identity</h2><p>Choose how people sign in. Directory and single sign-on accounts are created on first sign-in and take their role and team from group mappings.</p></div></div><div class="identity-grid">
  <article class="panel identity-card"><h2>Local sign-in</h2><form id="localPolicyForm"><label class="toggle"><input name="local_auth_enabled" type="checkbox" ${checked(p.local_auth_enabled)}> Allow local username and password sign-in</label><small class="muted">When off, only local administrators can use a local password (break-glass access).</small><div class="formgrid"><label>Failed attempts before lockout<input name="login_max_attempts" type="number" min="1" max="50" value="${esc(p.login_max_attempts)}"></label><label>Lockout duration (minutes)<input name="login_lockout_minutes" type="number" min="1" max="1440" value="${esc(p.login_lockout_minutes)}"></label></div><div class="form-actions"><button class="primary">Save sign-in policy</button></div></form></article>
  <article class="panel identity-card"><div class="connection-head"><span class="provider-icon">AD</span><div><h2>Active Directory / LDAP</h2><p>FlowOps binds to the directory directly.</p></div><span class="connection-state ${boolValue(l.enabled)&&l.credential_configured?'ready':''}"><i></i>${boolValue(l.enabled)?'Enabled':'Off'}</span></div>
   <form id="ldapForm" class="connection-form"><label class="toggle"><input name="enabled" type="checkbox" ${checked(l.enabled)}> Enable directory sign-in</label>
   <div class="formgrid"><label>Server URLs<input name="url" value="${esc(l.url)}" placeholder="ldaps://dc1.corp.example.com ldaps://dc2.corp.example.com"><small>Several servers are tried in order.</small></label><label>Domain shown at sign-in<input name="domain" value="${esc(l.domain)}" placeholder="corp.example.com"></label></div>
   <div class="formgrid"><label>Base DN<input name="base_dn" value="${esc(l.base_dn)}" placeholder="DC=corp,DC=example,DC=com"></label><label>Service account (bind DN)<input name="bind_dn" value="${esc(l.bind_dn)}" placeholder="CN=svc-flowops,OU=Service,DC=corp,DC=example,DC=com"></label></div>
   <label>Service account password<input name="credential" type="password" autocomplete="new-password" placeholder="${l.credential_configured?'Leave blank to keep the saved password':'Required'}" ${editable?'':'disabled'}><small>${editable?'Encrypted at rest and never returned to the browser.':'Credential encryption is not configured on this deployment.'}</small></label>
   <label>User search filter<input name="user_filter" value="${esc(l.user_filter)}"><div class="preset-row"><button type="button" class="secondary" data-preset="ad">Active Directory</button><button type="button" class="secondary" data-preset="openldap">OpenLDAP</button></div></label>
   <div class="formgrid"><label>Group search base (optional)<input name="group_base_dn" value="${esc(l.group_base_dn)}"></label><label>Group search filter (optional)<input name="group_search_filter" value="${esc(l.group_search_filter)}" placeholder="(&(objectClass=groupOfNames)(member={dn}))"><small>For directories without memberOf. Use {dn} or {username}.</small></label></div>
   <label class="toggle"><input name="nested_groups" type="checkbox" ${checked(l.nested_groups)}> Include nested groups (Active Directory)</label><label class="toggle"><input name="start_tls" type="checkbox" ${checked(l.start_tls||'true')}> Use StartTLS for ldap:// URLs</label><label class="toggle"><input name="validate_cert" type="checkbox" ${checked(l.validate_cert||'true')}> Verify the server certificate</label>
   <h3>Access and roles</h3><label class="toggle"><input name="require_access_group" type="checkbox" ${checked(l.require_access_group)}> Only members of a mapped group may sign in</label><label>Role when no group matches${roleSelect('default_role',l.default_role)}</label>
   <label>Group → role</label>${mappingEditor('role_mappings',l.role_mappings,ROLES)}<label>Group → team</label>${mappingEditor('team_mappings',l.team_mappings)}
   <div class="form-actions"><button class="primary">Save directory</button><button type="button" class="secondary" id="testLdap">Test connection</button></div><div class="test-line" id="ldapTest" role="status"></div></form>
   <form id="checkUserForm"><h3>Check a user</h3><p class="muted">See what a directory account would get, without signing in as them.</p><div class="formgrid"><label>Username<input name="username" placeholder="jsmith" required></label><span></span></div><div class="form-actions"><button class="secondary">Check user</button></div><div id="checkUserResult"></div></form></article>
  <article class="panel identity-card"><h2>ServiceOps directory pass-through</h2><form id="passThroughForm"><p class="muted">Used only when direct directory sign-in above is off: FlowOps asks ServiceOps to verify AD/LDAP passwords.</p><label class="toggle"><input name="directory_enabled" type="checkbox" ${checked(settings.directory_enabled)}> Verify directory passwords through ServiceOps</label><label>AD domain name<input name="directory_domain" value="${esc(settings.directory_domain||'')}" placeholder="corp.example.com"></label><div class="form-actions"><button class="primary">Save pass-through</button></div></form></article>
  <article class="panel identity-card"><div class="connection-head"><span class="provider-icon">ID</span><div><h2>Keycloak / OIDC single sign-on</h2><p>Authorization code flow with PKCE.</p></div><span class="connection-state ${boolValue(o.enabled)&&o.credential_configured?'ready':''}"><i></i>${boolValue(o.enabled)?'Enabled':'Off'}</span></div>
   <form id="oidcForm" class="connection-form"><label class="toggle"><input name="enabled" type="checkbox" ${checked(o.enabled)}> Show "Sign in with single sign-on"</label>
   <div class="formgrid"><label>Issuer URL<input name="url" value="${esc(o.url)}" placeholder="https://sso.example.com/realms/operations"></label><label>Client ID<input name="client_id" value="${esc(o.client_id)}" placeholder="flowops"></label></div>
   <label>Client secret<input name="credential" type="password" autocomplete="new-password" placeholder="${o.credential_configured?'Leave blank to keep the saved secret':'Required'}" ${o.credential_editable?'':'disabled'}></label>
   <label>Redirect URI to register in Keycloak<input value="${esc(o.redirect_uri)}" readonly></label>
   <label class="toggle"><input name="auto_provision" type="checkbox" ${checked(o.auto_provision)}> Create an account on first sign-in</label>
   <div class="formgrid"><label>Role claim<input name="role_claim" value="${esc(o.role_claim||'realm_access.roles')}"><small>Dot path to a list in the ID token, such as realm_access.roles or groups.</small></label><label>Required assurance level (acr)<input name="required_acr" value="${esc(o.required_acr)}" placeholder="Optional, e.g. 2 for MFA"></label></div>
   <label>Role when no claim matches${roleSelect('default_role',o.default_role)}</label><label>Claim value → role</label>${mappingEditor('oidc_role_mappings',o.role_mappings,ROLES)}<label>Claim value → team</label>${mappingEditor('oidc_team_mappings',o.team_mappings)}
   <div class="form-actions"><button class="primary">Save single sign-on</button><button type="button" class="secondary" id="testOidc">Test discovery</button></div><div class="test-line" id="oidcTest" role="status"></div></form></article></div>`;
  bindMappingEditors(root);
  const ldapForm=$('#ldapForm'),oidcForm=$('#oidcForm');
  $$('[data-preset]',ldapForm).forEach(b=>b.onclick=()=>{ldapForm.user_filter.value=b.dataset.preset==='ad'?'(&(objectClass=user)(sAMAccountName={username}))':'(&(objectClass=inetOrgPerson)(uid={username}))';if(b.dataset.preset==='openldap'&&!ldapForm.group_search_filter.value)ldapForm.group_search_filter.value='(&(objectClass=groupOfNames)(member={dn}))'});
  const formValues=(form,provider,mappings)=>{const data=Object.fromEntries(new FormData(form));data.provider=provider;$$('input[type=checkbox]',form).forEach(x=>data[x.name]=x.checked);if(!data.credential)delete data.credential;data.role_mappings=readMapping(form,mappings[0]);data.team_mappings=readMapping(form,mappings[1]);return data};
  const save=(form,provider,mappings,label)=>async e=>{e.preventDefault();try{await api('/api/admin/integrations',{method:'POST',body:JSON.stringify(formValues(form,provider,mappings))});toast(`${label} saved`);renderIdentityAdmin()}catch(err){toast(err.message,true)}};
  ldapForm.onsubmit=save(ldapForm,'ldap',['role_mappings','team_mappings'],'Directory settings');
  oidcForm.onsubmit=save(oidcForm,'oidc',['oidc_role_mappings','oidc_team_mappings'],'Single sign-on settings');
  const test=(form,provider,mappings,target)=>async()=>{const line=$(target);line.textContent='Testing the values in this form…';line.style.color='';try{const r=await api('/api/admin/integrations/test',{method:'POST',body:JSON.stringify(formValues(form,provider,mappings))});line.textContent=`✓ ${r.message}${r.latency_ms!==undefined?` · ${r.latency_ms} ms`:''}`;line.style.color='#17855e'}catch(err){line.textContent=err.message;line.style.color='#b43d4b'}};
  $('#testLdap').onclick=test(ldapForm,'ldap',['role_mappings','team_mappings'],'#ldapTest');
  $('#testOidc').onclick=test(oidcForm,'oidc',['oidc_role_mappings','oidc_team_mappings'],'#oidcTest');
  $('#localPolicyForm').onsubmit=async e=>{e.preventDefault();const f=e.currentTarget;try{await api('/api/admin/settings',{method:'POST',body:JSON.stringify({local_auth_enabled:f.local_auth_enabled.checked?'true':'false',login_max_attempts:f.login_max_attempts.value,login_lockout_minutes:f.login_lockout_minutes.value})});toast('Sign-in policy saved')}catch(err){toast(err.message,true)}};
  $('#passThroughForm').onsubmit=async e=>{e.preventDefault();const f=e.currentTarget;try{await api('/api/admin/settings',{method:'POST',body:JSON.stringify({directory_enabled:f.directory_enabled.checked?'true':'false',directory_domain:f.directory_domain.value})});state.settings={...state.settings,directory_enabled:f.directory_enabled.checked?'true':'false',directory_domain:f.directory_domain.value};toast('Pass-through saved')}catch(err){toast(err.message,true)}};
  $('#checkUserForm').onsubmit=async e=>{e.preventDefault();const out=$('#checkUserResult');out.innerHTML='';try{const r=await api('/api/admin/directory/check',{method:'POST',body:JSON.stringify({username:e.currentTarget.username.value})});
    out.innerHTML=r.found?`<div class="check-result"><b>${esc(r.name)}</b> · ${esc(r.email||'no email')}<br><small>${esc(r.dn)}</small><br>${r.allowed?`<span class="id-badge ok">Can sign in</span> as <b>${esc(r.role)}</b>${r.role_group?` via ${esc(r.role_group)}`:' (default role)'}${r.team?` · team <b>${esc(r.team)}</b>`:''}`:`<span class="id-badge warn">Cannot sign in</span> ${esc(r.reason)}`}<br>${r.group_count} group${r.group_count===1?'':'s'}:<ul>${r.groups.map(g=>`<li>${esc(g)}</li>`).join('')||'<li>none</li>'}</ul></div>`:`<div class="check-result">No unique directory account named <b>${esc(r.username)}</b>.</div>`}catch(err){out.innerHTML=`<div class="check-result">${esc(err.message)}</div>`}};
}

// Users list: provider, MFA and lock state, unlock and MFA reset.
const identityLoadAdmin=loadAdmin;
loadAdmin=async function(){await identityLoadAdmin();if(!can('admin:users'))return;let users;try{users=await api('/api/admin/users')}catch(_){return}
  users.forEach(u=>{const row=$(`#usersTable [data-user="${u.id}"]`);if(!row||row.dataset.identity)return;row.dataset.identity='1';
    const small=row.querySelector('div small');if(small)small.insertAdjacentHTML('beforeend',`<span class="id-badge">${esc(PROVIDERS[u.auth_provider]||u.auth_provider)}</span>${u.mfa_enabled?'<span class="id-badge ok">MFA</span>':''}${u.locked_until?'<span class="id-badge warn">Locked</span>':''}`);
    const actions=row.querySelector('.user-actions');if(!actions)return;
    if(u.auth_provider!=='local')actions.querySelector('[data-reset]')?.remove();
    if(u.locked_until)actions.insertAdjacentHTML('afterbegin',`<button data-unlock="${u.id}" title="Unlock account">🔓</button>`);
    if(u.mfa_enabled)actions.insertAdjacentHTML('afterbegin',`<button data-reset-mfa="${u.id}" title="Reset multi-factor sign-in">⚿</button>`);
    actions.querySelector('[data-unlock]')?.addEventListener('click',async()=>{try{await api(`/api/admin/users/${u.id}/unlock`,{method:'POST',body:'{}'});toast(`${u.display_name} unlocked`);loadAdmin()}catch(err){toast(err.message,true)}});
    actions.querySelector('[data-reset-mfa]')?.addEventListener('click',async()=>{if(!await confirmDialog({title:`Reset multi-factor sign-in for ${u.display_name}?`,message:'They are signed out everywhere and can sign in with their password alone until they enrol again.',confirmLabel:'Reset',danger:true}))return;try{await api(`/api/admin/users/${u.id}/reset-mfa`,{method:'POST',body:'{}'});toast('Multi-factor sign-in reset');loadAdmin()}catch(err){toast(err.message,true)}});
  })};
})();
