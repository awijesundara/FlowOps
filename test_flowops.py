import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import http.cookiejar
from unittest.mock import MagicMock, patch

tmp=tempfile.NamedTemporaryFile(suffix='.db',delete=False); tmp.close()
os.environ['FLOWOPS_DB']=tmp.name
os.environ['FLOWOPS_PREVIEW_TOKENS']='true'
os.environ['FLOWOPS_SETTINGS_ENCRYPTION_KEY']='a1J1M20wV3JlbklvNWt1a2NTYk9pQ3VHTW5PRzFjTFI='
import server

class FlowOpsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.init_db(); cls.http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        cls.base=f'http://127.0.0.1:{cls.http.server_port}'; threading.Thread(target=cls.http.serve_forever,daemon=True).start(); cls.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())); cls.csrf=''
        _,login=cls.req('/api/auth/login','POST',{'username':'admin','password':'FlowOps!Preview2026'}); cls.csrf=login['data']['csrf_token']
    @classmethod
    def tearDownClass(cls): cls.http.shutdown(); os.unlink(tmp.name)
    @classmethod
    def req(cls,path,method='GET',body=None):
        data=json.dumps(body).encode() if body is not None else None
        headers={'Content-Type':'application/json'}
        if cls.csrf: headers['X-CSRF-Token']=cls.csrf
        request=urllib.request.Request(cls.base+path,data=data,method=method,headers=headers)
        try:
            with cls.opener.open(request) as res:return res.status,json.load(res)
        except urllib.error.HTTPError as err:return err.code,json.load(err)
    def test_health_and_seed(self):
        self.assertEqual(self.req('/health')[0],200); code,body=self.req('/api/runbooks'); self.assertEqual(code,200); self.assertTrue(body['data'])
    def test_serviceops_sync_browser_action_uses_csrf_aware_api_helper(self):
        source=(server.STATIC/'app.js').read_text()
        function=source.split('async function syncServiceOps()',1)[1].split('function openModal',1)[0]
        self.assertIn("await api(`/api/runbooks/${state.current.id}/serviceops-sync`",function)
        self.assertNotIn('await fetch(',function)
    def test_customer_instance_registration_and_cross_tenant_isolation(self):
        _,original=self.req('/api/runbooks','POST',{'name':'Default tenant private runbook'});original_runbook=original['data']['id']
        _,original_doc=self.req(f'/api/runbooks/{original_runbook}/tasks','POST',{'title':'Private task'});original_task=original_doc['data']['tasks'][0]['id']
        _,original_users=self.req('/api/admin/users'); original_user=original_users['data'][0]['id']
        admin_opener,admin_csrf=self.opener,self.csrf
        self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
        try:
            code,created=self.req('/api/auth/register','POST',{'organization':'Acme Resilience','slug':'acme-resilience','username':'acme-admin','display_name':'Acme Admin','email':'admin@acme.example','password':'AcmeSecure!123'})
            self.assertEqual(code,201);self.assertEqual(created['data']['slug'],'acme-resilience')
            _,login=self.req('/api/auth/login','POST',{'username':'acme-admin','password':'AcmeSecure!123'});self.__class__.csrf=login['data']['csrf_token']
            code,runbooks=self.req('/api/runbooks');self.assertEqual(code,200);self.assertEqual(runbooks['data'],[])
            self.assertEqual(self.req(f'/api/runbooks/{original_runbook}')[0],404)
            self.assertEqual(self.req(f'/api/tasks/{original_task}','PATCH',{'status':'running'})[0],404)
            self.assertEqual(self.req(f'/api/admin/users/{original_user}','PATCH',{'role':'Member'})[0],404)
            _,workspaces=self.req('/api/workspaces');self.assertEqual([w['name'] for w in workspaces['data']],['Operations'])
            _,new=self.req('/api/runbooks','POST',{'name':'Acme-only recovery'});self.assertEqual(new['data']['name'],'Acme-only recovery')
        finally:
            self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
    def test_invitation_acceptance_and_password_reset_are_single_use(self):
        _,issued=self.req('/api/admin/invitations','POST',{'email':'invited@example.com','role':'Member'});token=issued['data']['invite_token']
        payload={'token':token,'username':'invited','display_name':'Invited User','password':'InitialSecure!123'}
        self.assertEqual(self.req('/api/auth/invitations/accept','POST',payload)[0],201);self.assertEqual(self.req('/api/auth/invitations/accept','POST',payload)[0],400)
        admin_opener,admin_csrf=self.opener,self.csrf;self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
        _,login=self.req('/api/auth/login','POST',{'username':'invited@example.com','password':'InitialSecure!123'});self.__class__.csrf=login['data']['csrf_token']
        old=os.environ.get('FLOWOPS_PREVIEW_TOKENS');os.environ['FLOWOPS_PREVIEW_TOKENS']='true'
        try:_,requested=self.req('/api/auth/password-reset/request','POST',{'identity':'invited'});reset_token=requested['data']['preview_token']
        finally:
            if old is None:os.environ.pop('FLOWOPS_PREVIEW_TOKENS',None)
            else:os.environ['FLOWOPS_PREVIEW_TOKENS']=old
        self.assertEqual(self.req('/api/auth/password-reset/complete','POST',{'token':reset_token,'password':'Replacement!456'})[0],200)
        self.assertEqual(self.req('/api/auth/me')[0],401);self.assertEqual(self.req('/api/auth/password-reset/complete','POST',{'token':reset_token,'password':'AnotherSecure!789'})[0],400)
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
    def test_admin_configuration_and_immediate_role_change(self):
        self.assertEqual(self.req('/api/admin/workspaces','POST',{'name':'Trading Infrastructure','description':'Regional execution'})[0],201)
        self.assertEqual(self.req('/api/admin/users','POST',{'username':'editor1','display_name':'Release Editor','email':'editor1@example.com','role':'Editor','password':'Temporary!123'})[0],201)
        admin_opener,admin_csrf=self.opener,self.csrf
        self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
        _,login=self.req('/api/auth/login','POST',{'username':'editor1@example.com','password':'Temporary!123'});self.__class__.csrf=login['data']['csrf_token'];editor_opener,editor_csrf=self.opener,self.csrf
        self.assertEqual(self.req('/api/runbooks','POST',{'name':'Editor can create'})[0],201)
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        _,users=self.req('/api/admin/users');uid=next(u['id'] for u in users['data'] if u['username']=='editor1')
        self.assertEqual(self.req(f'/api/admin/users/{uid}','PATCH',{'role':'Member'})[0],200)
        self.__class__.opener,self.__class__.csrf=editor_opener,editor_csrf
        self.assertEqual(self.req('/api/runbooks','POST',{'name':'Now forbidden'})[0],403)
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
    def test_admin_session_revocation_audit_and_health_are_tenant_scoped(self):
        self.req('/api/admin/users','POST',{'username':'session-user','display_name':'Session User','email':'session@example.com','role':'Member','password':'Temporary!123'})
        admin_opener,admin_csrf=self.opener,self.csrf
        self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
        _,login=self.req('/api/auth/login','POST',{'username':'session-user','password':'Temporary!123'});self.__class__.csrf=login['data']['csrf_token'];member_opener,member_csrf=self.opener,self.csrf
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        _,sessions=self.req('/api/admin/sessions');target=next(s for s in sessions['data'] if s['username']=='session-user')
        self.assertEqual(self.req(f"/api/admin/sessions/{target['id']}/revoke",'POST',{})[0],200)
        self.__class__.opener,self.__class__.csrf=member_opener,member_csrf;self.assertEqual(self.req('/api/auth/me')[0],401)
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        code,audit=self.req('/api/admin/audit');self.assertEqual(code,200);self.assertTrue(any(e['action']=='admin.session_revoked' for e in audit['data']))
        code,health=self.req('/api/admin/health');self.assertEqual(code,200);self.assertEqual(health['data']['database'],'ok');self.assertEqual(health['data']['realtime'],'SSE')
    def test_integration_admin_policy_secret_boundary_and_connection_test(self):
        code,saved=self.req('/api/admin/integrations','POST',{'provider':'serviceops','url':'mock://serviceops','credential':'sop_test_connection_key','enabled':True,'require_approved':True,'sync_on_live':True,'sync_on_complete':True});self.assertEqual(code,200);self.assertTrue(saved['data']['ok'])
        code,connections=self.req('/api/admin/integrations');self.assertEqual(code,200);self.assertEqual(connections['data']['serviceops']['url'],'mock://serviceops');self.assertNotIn('token',connections['data']['serviceops']);self.assertNotIn('jenkins',connections['data'])
        code,tested=self.req('/api/admin/integrations/test','POST',{'provider':'serviceops'});self.assertEqual(code,200);self.assertTrue(tested['data']['ok'])
        self.assertEqual(self.req('/api/admin/integrations','POST',{'provider':'unsupported','url':'mock://unsupported'})[0],400)
        self.assertEqual(self.req('/api/admin/integrations','POST',{'provider':'serviceops','revoke_credential':True})[0],200)
    def test_admin_can_rotate_and_revoke_encrypted_serviceops_credential_without_readback(self):
        secret='sop_ui_managed_secret_value'
        code,_=self.req('/api/admin/integrations','POST',{'provider':'serviceops','url':'https://serviceops.example','credential':secret});self.assertEqual(code,200)
        with server.connect() as db:
            stored=db.execute("SELECT secret_encrypted FROM integration_credentials WHERE provider='serviceops'").fetchone()[0]
        self.assertNotIn(secret,stored)
        _,connections=self.req('/api/admin/integrations');serviceops=connections['data']['serviceops']
        self.assertTrue(serviceops['credential_configured']);self.assertEqual(serviceops['credential_source'],'Encrypted FlowOps setting');self.assertNotIn('credential',serviceops)
        captured=[]
        class Response:
            status=200
            headers={'Content-Type':'application/json'}
            def read(self):return b'{"data":[]}'
            def __enter__(self):return self
            def __exit__(self,*_):return False
        def fake_open(request,timeout=0):captured.append(request);return Response()
        with patch('server.urllib.request.urlopen',fake_open):self.assertEqual(self.req('/api/admin/integrations/test','POST',{'provider':'serviceops'})[0],200)
        self.assertEqual(captured[0].get_header('Authorization'),f'Bearer {secret}')
        self.assertEqual(self.req('/api/admin/integrations','POST',{'provider':'serviceops','revoke_credential':True})[0],200)
        _,connections=self.req('/api/admin/integrations');self.assertFalse(connections['data']['serviceops']['credential_configured'])
    def test_connection_test_uses_current_unsaved_form_key_without_persisting_it(self):
        captured=[]
        class Response:
            status=200
            headers={'Content-Type':'application/json'}
            def read(self):return b'{"data":[]}'
            def __enter__(self):return self
            def __exit__(self,*_):return False
        def fake_open(request,timeout=0):captured.append(request);return Response()
        candidate='sop_newly_pasted_browser_key'
        with patch('server.urllib.request.urlopen',fake_open):
            code,result=self.req('/api/admin/integrations/test','POST',{'provider':'serviceops','url':'https://serviceops.example','credential':candidate})
        self.assertEqual(code,200);self.assertTrue(result['data']['tested_unsaved_credential'])
        self.assertEqual(captured[0].get_header('Authorization'),f'Bearer {candidate}')
        with server.connect() as db:self.assertFalse(db.execute("SELECT 1 FROM integration_credentials WHERE provider='serviceops'").fetchone())
    def test_login_sources_use_local_administrator_and_configured_directory_domain(self):
        _,sources=self.req('/api/auth/sources');self.assertEqual(sources['data']['sources'],[{'id':'local','label':'Local administrator','placeholder':'Username'}])
        self.req('/api/admin/settings','POST',{'directory_enabled':'true','directory_domain':'corp.example.com'})
        _,sources=self.req('/api/auth/sources');self.assertEqual(sources['data']['default'],'ldap');self.assertEqual(sources['data']['sources'][0]['label'],'corp.example.com');self.assertEqual(sources['data']['sources'][0]['placeholder'],'jsmith or jsmith@corp.example.com')
    def test_invitation_and_password_reset_use_smtp_without_returning_tokens(self):
        variables={'FLOWOPS_PREVIEW_TOKENS':'false','FLOWOPS_SMTP_HOST':'smtp.example','FLOWOPS_MAIL_FROM':'flowops@example.com','FLOWOPS_PUBLIC_URL':'https://flowops.example'}
        previous={key:os.environ.get(key) for key in variables};os.environ.update(variables)
        try:
            with patch('server.send_mail') as send:
                code,invite=self.req('/api/admin/invitations','POST',{'email':'smtp-invite@example.com','role':'Member'});self.assertEqual(code,201)
                self.assertEqual(invite['data']['delivery'],'email');self.assertNotIn('invite_token',invite['data']);self.assertIn('/?invite=',send.call_args.args[2])
                self.req('/api/admin/users','POST',{'username':'smtp-user','display_name':'SMTP User','email':'smtp-reset@example.com','role':'Member','password':'Temporary!123'})
                code,body=self.req('/api/auth/password-reset/request','POST',{'identity':'smtp-reset@example.com'});self.assertEqual(code,202);self.assertNotIn('preview_token',body['data']);self.assertIn('/?reset=',send.call_args.args[2])
        finally:
            for key,value in previous.items():
                if value is None:os.environ.pop(key,None)
                else:os.environ[key]=value
    def test_smtp_transport_uses_starttls_authentication_and_message_headers(self):
        variables={'FLOWOPS_SMTP_HOST':'smtp.example','FLOWOPS_SMTP_PORT':'587','FLOWOPS_SMTP_SECURITY':'starttls','FLOWOPS_SMTP_USERNAME':'flowops-sender','FLOWOPS_SMTP_PASSWORD':'smtp-secret','FLOWOPS_MAIL_FROM':'flowops@example.com','FLOWOPS_PUBLIC_URL':'https://flowops.example'}
        previous={key:os.environ.get(key) for key in variables};os.environ.update(variables);client=MagicMock();context=MagicMock();context.__enter__.return_value=client
        try:
            with patch('server.smtplib.SMTP',return_value=context) as smtp:server.send_mail('person@example.com','FlowOps test','Delivery body')
            smtp.assert_called_once_with('smtp.example',587,timeout=10);client.starttls.assert_called_once();client.login.assert_called_once_with('flowops-sender','smtp-secret');message=client.send_message.call_args.args[0];self.assertEqual(message['To'],'person@example.com');self.assertEqual(message['From'],'flowops@example.com')
        finally:
            for key,value in previous.items():
                if value is None:os.environ.pop(key,None)
                else:os.environ[key]=value
    def test_serviceops_v1_ticket_sync_uses_scoped_bearer_and_stores_projection(self):
        self.req('/api/admin/integrations','POST',{'provider':'serviceops','url':'https://serviceops.example','credential':'sop_test_only','enabled':True})
        _,created=self.req('/api/runbooks','POST',{'name':'Governed change','serviceops_ticket':'CHG0000042'});rid=created['data']['id']
        captured=[]
        class Response:
            status=200
            headers={'X-Request-ID':'serviceops-request-42'}
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def read(self,*_):return b'{"data":{"id":42,"number":"CHG0000042","type":"change","title":"Core release","state":"Approved","priority":"P2"}}'
        def fake_open(request,timeout=0):captured.append(request);return Response()
        with patch('server.urllib.request.urlopen',fake_open):code,body=self.req(f'/api/runbooks/{rid}/serviceops-sync','POST',{})
        self.assertEqual(code,200);doc=body['data'];self.assertEqual(doc['serviceops_state'],'Approved');self.assertEqual(doc['serviceops_title'],'Core release')
        self.assertEqual(captured[0].full_url,'https://serviceops.example/api/v1/tickets/CHG0000042');self.assertEqual(captured[0].get_header('Authorization'),'Bearer sop_test_only');self.assertTrue(captured[0].get_header('X-request-id'))
    def test_serviceops_change_approval_gate_and_idempotent_live_writeback(self):
        self.req('/api/admin/integrations','POST',{'provider':'serviceops','url':'https://serviceops.example','credential':'sop_lifecycle_test','enabled':True,'require_approved':True,'sync_on_live':True})
        _,created=self.req('/api/runbooks','POST',{'name':'API-governed run','serviceops_ticket':'CHG0000043'});rid=created['data']['id'];self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'})
        requests=[]
        class Response:
            status=200
            headers={'X-Request-ID':'request-live-43'}
            def __init__(self,state):self.state=state
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def read(self,*_):return json.dumps({'data':{'number':'CHG0000043','type':'change','title':'Payments release','state':self.state,'priority':'P1'}}).encode()
        def approved(request,timeout=0):requests.append(request);return Response('In Progress' if request.method=='PATCH' else 'Approved')
        with patch('server.urllib.request.urlopen',approved):code,body=self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        self.assertEqual(code,200);self.assertEqual(body['data']['serviceops_state'],'In Progress');self.assertEqual([r.method for r in requests],['GET','PATCH'])
        self.assertEqual(requests[1].get_header('Idempotency-key'),f'flowops-{rid}-live');self.assertEqual(json.loads(requests[1].data),{'state':'In Progress'})
    def test_webhook_delivers_signed_payload_to_a_real_receiver(self):
        import http.server as http_server_module
        received=[]
        class Receiver(http_server_module.BaseHTTPRequestHandler):
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'))
                received.append({'body':self.rfile.read(length),'signature':self.headers.get('X-FlowOps-Signature',''),'event':self.headers.get('X-FlowOps-Event','')})
                self.send_response(200); self.end_headers()
            def log_message(self,*a): pass
        receiver=http_server_module.HTTPServer(('127.0.0.1',0),Receiver)
        receiver_port=receiver.server_port
        threading.Thread(target=receiver.serve_forever,daemon=True).start()
        try:
            code,created=self.req('/api/admin/webhooks','POST',{'name':'Test receiver','url':f'http://127.0.0.1:{receiver_port}/hook','events':['*']})
            self.assertEqual(code,201)
            self.assertTrue(created['data']['secret'])
            webhook_id=created['data']['id']
            code,tested=self.req(f'/api/admin/webhooks/{webhook_id}/test','POST',{})
            self.assertEqual(code,200)
            self.assertEqual(len(received),1)
            payload=json.loads(received[0]['body'])
            self.assertEqual(payload['event'],'webhook.test')
            expected_signature='sha256='+__import__('hmac').new(created['data']['secret'].encode(),received[0]['body'],__import__('hashlib').sha256).hexdigest()
            self.assertEqual(received[0]['signature'],expected_signature)
            _,listed=self.req('/api/admin/webhooks')
            entry=next(w for w in listed['data'] if w['id']==webhook_id)
            self.assertEqual(entry['recent_deliveries'][0]['success'],1)
            self.assertEqual(self.req('/api/admin/webhooks','POST',{'name':'Bad url','url':'not-a-url'})[0],400)
            self.assertEqual(self.req(f'/api/admin/webhooks/{webhook_id}','DELETE')[0],200)
            _,listedAfter=self.req('/api/admin/webhooks')
            self.assertFalse(any(w['id']==webhook_id for w in listedAfter['data']))
        finally:
            receiver.shutdown()
    def test_api_token_scopes_grant_bearer_access_without_csrf(self):
        code,readToken=self.req('/api/admin/api-tokens','POST',{'name':'CI reader','scopes':['runbooks:read']})
        self.assertEqual(code,201)
        self.assertTrue(readToken['data']['token'].startswith('fo_'))
        code,writeToken=self.req('/api/admin/api-tokens','POST',{'name':'CI writer','scopes':['runbooks:write']})
        self.assertEqual(code,201)
        self.assertEqual(self.req('/api/admin/api-tokens','POST',{'name':'No scopes','scopes':[]})[0],400)
        def bearer_req(path,method,token,body=None):
            data=json.dumps(body).encode() if body is not None else None
            request=urllib.request.Request(self.base+path,data=data,method=method,headers={'Content-Type':'application/json','Authorization':f'Bearer {token}'})
            try:
                with urllib.request.urlopen(request) as res:return res.status,json.load(res)
            except urllib.error.HTTPError as err:return err.code,json.load(err)
        read_token=readToken['data']['token']; write_token=writeToken['data']['token']
        self.assertEqual(bearer_req('/api/runbooks','GET',read_token)[0],200)
        self.assertEqual(bearer_req('/api/runbooks','POST',read_token,{'name':'Blocked by scope'})[0],403)
        code,created=bearer_req('/api/runbooks','POST',write_token,{'name':'Created via API token'})
        self.assertEqual(code,201)
        rid=created['data']['id']
        code,transitioned=bearer_req(f'/api/runbooks/{rid}/transition','POST',write_token,{'status':'ready'})
        self.assertEqual(code,200)
        self.assertEqual(bearer_req('/api/runbooks','GET','fo_not-a-real-token')[0],401)
        _,listed=self.req('/api/admin/api-tokens')
        names={t['name']:t for t in listed['data']}
        self.assertEqual(sorted(names['CI reader']['scopes']),['runbooks:read'])
        token_id=names['CI reader']['id']
        self.assertEqual(self.req(f'/api/admin/api-tokens/{token_id}/revoke','POST',{})[0],200)
        self.assertEqual(bearer_req('/api/runbooks','GET',read_token)[0],401)
    def test_central_team_membership_propagates_live_to_linked_runbooks(self):
        _,users=self.req('/api/admin/users'); operator_id=next(u['id'] for u in users['data'] if u['username']=='operator')
        admin_id=next(u['id'] for u in users['data'] if u['username']=='admin')
        code,team=self.req('/api/central-teams','POST',{'name':'Platform SRE'})
        self.assertEqual(code,201); central_id=team['data']['id']
        self.assertEqual(self.req('/api/central-teams','POST',{'name':'Platform SRE'})[0],409)
        self.req(f'/api/central-teams/{central_id}/members','POST',{'user_id':operator_id})
        _,created=self.req('/api/runbooks','POST',{'name':'Central team run'}); rid=created['data']['id']
        code,linked=self.req(f'/api/runbooks/{rid}/teams','POST',{'central_team_id':central_id})
        self.assertEqual(code,201); runbook_team_id=linked['data']['id']
        self.assertEqual(linked['data']['name'],'Platform SRE')
        _,teamsView=self.req(f'/api/runbooks/{rid}/teams')
        self.assertEqual(teamsView['data'][0]['member_count'],1)
        self.assertEqual([m['id'] for m in teamsView['data'][0]['members']],[operator_id])
        self.req(f'/api/central-teams/{central_id}/members','POST',{'user_id':admin_id})
        _,teamsAfter=self.req(f'/api/runbooks/{rid}/teams')
        self.assertEqual(teamsAfter['data'][0]['member_count'],2)
        self.assertEqual(sorted(m['id'] for m in teamsAfter['data'][0]['members']),sorted([operator_id,admin_id]))
        self.assertEqual(self.req(f'/api/central-teams/{central_id}','DELETE')[0],409)
        _,assigned=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'SRE task','owner_team_id':runbook_team_id})
        assigned_id=assigned['data']['tasks'][0]['id']
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'});self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        admin_opener,admin_csrf=self.opener,self.csrf;self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
        _,login=self.req('/api/auth/login','POST',{'username':'operator','password':'Operator!Preview2026'});self.__class__.csrf=login['data']['csrf_token']
        self.assertEqual(self.req(f'/api/tasks/{assigned_id}','PATCH',{'status':'running'})[0],200)
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        self.req(f'/api/central-teams/{central_id}/members/{operator_id}','DELETE')
        _,teamsFinal=self.req(f'/api/runbooks/{rid}/teams')
        self.assertEqual(teamsFinal['data'][0]['member_count'],1)
    def test_folder_scopes_runbooks_and_blocks_deletion_while_in_use(self):
        code,folder=self.req('/api/folders','POST',{'name':'Q3 Releases'})
        self.assertEqual(code,201); folder_id=folder['data']['id']
        self.assertEqual(self.req('/api/folders','POST',{'name':'Q3 Releases'})[0],409)
        _,created=self.req('/api/runbooks','POST',{'name':'Foldered run','folder_id':folder_id})
        self.assertEqual(created['data']['folder_id'],folder_id)
        _,other=self.req('/api/runbooks','POST',{'name':'Unfoldered run'})
        scoped=self.req(f'/api/runbooks?folder_id={folder_id}')[1]['data']
        self.assertEqual([r['id'] for r in scoped],[created['data']['id']])
        _,folders=self.req('/api/folders')
        self.assertTrue(any(f['id']==folder_id and f['runbook_count']==1 for f in folders['data']))
        self.assertEqual(self.req(f'/api/folders/{folder_id}','DELETE')[0],409)
    def test_runbook_type_default_description_applies_when_creating_without_one(self):
        code,rtype=self.req('/api/runbook-types','POST',{'name':'Disaster Recovery','icon':'⌁','color':'#e5793a','default_description':'Declare, fail over, validate, and recover service.'})
        self.assertEqual(code,201); type_id=rtype['data']['id']
        self.assertEqual(self.req('/api/runbook-types','POST',{'name':'Disaster Recovery'})[0],409)
        _,created=self.req('/api/runbooks','POST',{'name':'DR drill','runbook_type_id':type_id})
        self.assertEqual(created['data']['description'],'Declare, fail over, validate, and recover service.')
        _,custom=self.req('/api/runbooks','POST',{'name':'DR drill 2','runbook_type_id':type_id,'description':'Custom description'})
        self.assertEqual(custom['data']['description'],'Custom description')
        _,types=self.req('/api/runbook-types')
        self.assertTrue(any(t['id']==type_id and t['runbook_count']==2 for t in types['data']))
        self.assertEqual(self.req(f'/api/runbook-types/{type_id}','DELETE')[0],409)
    def test_save_and_use_template_clones_streams_tasks_and_dependencies(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Template source'}); rid=created['data']['id']
        _,first=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Prep','stream':'Setup','duration':10}); first_id=first['data']['tasks'][0]['id']
        self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Deploy','stream':'Setup','duration':20,'depends_on':[first_id]})
        code,saved=self.req(f'/api/runbooks/{rid}/save-as-template','POST',{'name':'Release template','category':'Release'})
        self.assertEqual(code,201)
        template_id=saved['data']['id']
        _,listed=self.req('/api/templates')
        self.assertTrue(any(t['id']==template_id and t['task_count']==2 and t['category']=='Release' for t in listed['data']))
        code,used=self.req(f'/api/templates/{template_id}/use','POST',{'name':'From template run'})
        self.assertEqual(code,201)
        self.assertEqual(used['data']['name'],'From template run')
        self.assertEqual(len(used['data']['tasks']),2)
        self.assertEqual([s['name'] for s in used['data']['streams']],['Setup'])
        deploy=next(t for t in used['data']['tasks'] if t['title']=='Deploy')
        prep=next(t for t in used['data']['tasks'] if t['title']=='Prep')
        self.assertEqual(deploy['depends_on'],[prep['id']])
        self.assertEqual(self.req(f'/api/templates/{template_id}','DELETE')[0],200)
        _,listed_after=self.req('/api/templates')
        self.assertFalse(any(t['id']==template_id for t in listed_after['data']))
    def test_seed_runbook_has_backfilled_streams_on_fresh_install(self):
        _,doc=self.req('/api/runbooks/1')
        self.assertGreater(len(doc['data']['streams']),0)
        self.assertEqual({s['name'] for s in doc['data']['streams']}, {t['stream'] for t in doc['data']['tasks']})
    def test_duplicate_runbook_clones_streams_tasks_and_dependencies(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Original release'}); rid=created['data']['id']
        _,first=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Step one','stream':'Prep','duration':10}); first_id=first['data']['tasks'][0]['id']
        self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Step two','stream':'Prep','duration':10,'depends_on':[first_id]})
        code,dup=self.req(f'/api/runbooks/{rid}/duplicate','POST',{})
        self.assertEqual(code,201)
        self.assertEqual(dup['data']['name'],'Original release (copy)')
        self.assertNotEqual(dup['data']['id'],rid)
        self.assertEqual(len(dup['data']['tasks']),2)
        self.assertEqual([s['name'] for s in dup['data']['streams']],['Prep'])
        second_new=next(t for t in dup['data']['tasks'] if t['title']=='Step two')
        first_new=next(t for t in dup['data']['tasks'] if t['title']=='Step one')
        self.assertEqual(second_new['depends_on'],[first_new['id']])
        original_after=self.req(f'/api/runbooks/{rid}')[1]['data']
        self.assertEqual(len(original_after['tasks']),2)
    def test_archive_requires_complete_and_hides_from_default_listing(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Archivable'}); rid=created['data']['id']
        self.assertEqual(self.req(f'/api/runbooks/{rid}/archive','POST',{})[0],409)
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'})
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'complete'})
        code,archived=self.req(f'/api/runbooks/{rid}/archive','POST',{})
        self.assertEqual(code,200)
        self.assertTrue(any(a['action']=='runbook.archived' for a in archived['data']['audit']))
        listed=self.req('/api/runbooks')[1]['data']
        self.assertNotIn(rid,[r['id'] for r in listed])
        listed_all=self.req('/api/runbooks?include_archived=1')[1]['data']
        self.assertIn(rid,[r['id'] for r in listed_all])
    def test_task_field_edit_is_audited_without_requiring_live(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Edit audit'}); rid=created['data']['id']
        _,made=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Draft step','duration':10}); tid=made['data']['tasks'][0]['id']
        code,edited=self.req(f'/api/tasks/{tid}','PATCH',{'title':'Renamed step','duration':20})
        self.assertEqual(code,200)
        self.assertEqual(edited['data']['tasks'][0]['title'],'Renamed step')
        self.assertEqual(edited['data']['tasks'][0]['duration'],20)
        self.assertTrue(any(a['action']=='task.edited' for a in edited['data']['audit']))
        self.assertEqual(self.req(f'/api/tasks/{tid}','PATCH',{'title':''})[0],400)
    def test_runbook_field_edit_is_audited_and_blocked_when_terminal(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Edit runbook'}); rid=created['data']['id']
        code,edited=self.req(f'/api/runbooks/{rid}','PATCH',{'name':'Renamed runbook','owner':'New owner'})
        self.assertEqual(code,200)
        self.assertEqual(edited['data']['name'],'Renamed runbook')
        self.assertTrue(any(a['action']=='runbook.edited' for a in edited['data']['audit']))
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'})
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'complete'})
        self.assertEqual(self.req(f'/api/runbooks/{rid}','PATCH',{'name':'Too late'})[0],409)
    def test_stream_create_rename_delete_and_task_auto_creates_stream(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Stream mgmt'}); rid=created['data']['id']
        self.assertEqual(created['data']['streams'],[])
        code,made=self.req(f'/api/runbooks/{rid}/streams','POST',{'name':'Governance'})
        self.assertEqual(code,201)
        self.assertEqual([s['name'] for s in made['data']['streams']],['Governance'])
        self.assertEqual(self.req(f'/api/runbooks/{rid}/streams','POST',{'name':'Governance'})[0],409)
        self.assertEqual(self.req(f'/api/runbooks/{rid}/streams','POST',{'name':''})[0],400)
        _,task=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Ad hoc step','stream':'Deployment'})
        self.assertEqual(sorted(s['name'] for s in task['data']['streams']),['Deployment','Governance'])
        governance_id=next(s['id'] for s in task['data']['streams'] if s['name']=='Governance')
        code,renamed=self.req(f'/api/streams/{governance_id}','PATCH',{'name':'Approvals'})
        self.assertEqual(code,200)
        self.assertEqual(sorted(s['name'] for s in renamed['data']['streams']),['Approvals','Deployment'])
        deployment_id=next(s['id'] for s in renamed['data']['streams'] if s['name']=='Deployment')
        self.assertEqual(self.req(f'/api/streams/{deployment_id}','DELETE')[0],409)
        approvals_id=next(s['id'] for s in renamed['data']['streams'] if s['name']=='Approvals')
        code,after_delete=self.req(f'/api/streams/{approvals_id}','DELETE')
        self.assertEqual(code,200)
        self.assertEqual([s['name'] for s in after_delete['data']['streams']],['Deployment'])
    def test_full_execution_and_dependency_gate(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Test release'}); rid=created['data']['id']
        _,first=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'First','duration':5}); first_id=first['data']['tasks'][0]['id']
        _,second=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Second','depends_on':[first_id]}); second_id=second['data']['tasks'][1]['id']
        self.assertEqual(self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'})[0],200)
        self.assertEqual(self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})[0],200)
        self.assertEqual(self.req(f'/api/tasks/{second_id}','PATCH',{'status':'running'})[0],409)
        self.assertEqual(self.req(f'/api/tasks/{first_id}','PATCH',{'status':'running'})[0],200)
        self.assertEqual(self.req(f'/api/tasks/{first_id}','PATCH',{'status':'complete'})[0],200)
        self.assertEqual(self.req(f'/api/tasks/{second_id}','PATCH',{'status':'running'})[0],200)
    def test_task_can_depend_on_multiple_predecessors(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Fan-in release'}); rid=created['data']['id']
        _,a=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Migrate database','duration':5}); a_id=a['data']['tasks'][0]['id']
        _,b=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Sync configuration','duration':5}); b_id=b['data']['tasks'][1]['id']
        _,c=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Deploy release','depends_on':[a_id,b_id]}); c_id=c['data']['tasks'][2]['id']
        self.assertEqual(sorted(c['data']['tasks'][2]['depends_on']),sorted([a_id,b_id]))
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'});self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        self.req(f'/api/tasks/{a_id}','PATCH',{'status':'running'});self.req(f'/api/tasks/{a_id}','PATCH',{'status':'complete'})
        self.assertEqual(self.req(f'/api/tasks/{c_id}','PATCH',{'status':'running'})[0],409)
        self.req(f'/api/tasks/{b_id}','PATCH',{'status':'running'});self.req(f'/api/tasks/{b_id}','PATCH',{'status':'complete'})
        self.assertEqual(self.req(f'/api/tasks/{c_id}','PATCH',{'status':'running'})[0],200)
    def test_runbook_lifecycle_rejects_invalid_jump(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Lifecycle'}); rid=created['data']['id']
        self.assertEqual(self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})[0],409)
        self.assertEqual(self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'})[0],200)
        self.assertEqual(self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})[0],200)
    def test_runbook_countdown_elapsed_and_completion_timing(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Timed release','scheduled_at':'2099-09-06T18:30'});rid=created['data']['id']
        self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Release','duration':45})
        timing=self.req(f'/api/runbooks/{rid}')[1]['data']['timing']
        self.assertEqual(timing['phase'],'upcoming');self.assertGreater(timing['seconds_to_start'],0);self.assertEqual(timing['planned_seconds'],2700)
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'})
        live=self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})[1]['data']
        self.assertEqual(live['timing']['phase'],'live');self.assertIsNotNone(live['timing']['actual_started_at']);self.assertGreaterEqual(live['timing']['elapsed_seconds'],0)
        complete=self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'complete'})[1]['data']
        self.assertEqual(complete['timing']['phase'],'complete');self.assertIsNotNone(complete['timing']['actual_completed_at']);self.assertIsInstance(complete['timing']['variance_seconds'],int)
    def test_validation_result_and_automatic_lateness(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Validation run','scheduled_at':'2020-01-01T00:00'});rid=created['data']['id']
        _,made=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Validate recovery','task_type':'validation','duration':5});tid=made['data']['tasks'][0]['id']
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'});self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        self.assertTrue(self.req(f'/api/runbooks/{rid}')[1]['data']['tasks'][0]['late'])
        self.assertEqual(self.req(f'/api/tasks/{tid}','PATCH',{'status':'running'})[0],200)
        self.assertEqual(self.req(f'/api/tasks/{tid}','PATCH',{'status':'complete'})[0],400)
        code,done=self.req(f'/api/tasks/{tid}','PATCH',{'status':'complete','validation_result':'Pass','validation_comment':'Recovery checks passed'});self.assertEqual(code,200);self.assertEqual(done['data']['tasks'][0]['validation_result'],'Pass')
    def test_blocked_task_is_not_flagged_late_and_downstream_uses_chain_offset(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Chained lateness','scheduled_at':'2020-01-01T00:00'});rid=created['data']['id']
        _,first=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Step one','duration':30});first_id=first['data']['tasks'][0]['id']
        _,second=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Step two','duration':30,'depends_on':[first_id]});second_id=second['data']['tasks'][1]['id']
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'});self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        doc=self.req(f'/api/runbooks/{rid}')[1]['data']
        by_id={t['id']:t for t in doc['tasks']}
        self.assertTrue(by_id[first_id]['late'])
        self.assertTrue(by_id[second_id]['blocked'])
        self.assertFalse(by_id[second_id]['late'])
        self.req(f'/api/tasks/{first_id}','PATCH',{'status':'running'});self.req(f'/api/tasks/{first_id}','PATCH',{'status':'complete'})
        doc=self.req(f'/api/runbooks/{rid}')[1]['data']
        by_id={t['id']:t for t in doc['tasks']}
        self.assertFalse(by_id[second_id]['blocked'])
        self.assertTrue(by_id[second_id]['late'])
    def test_operator_privilege_boundaries(self):
        opener=self.opener; csrf=self.csrf
        self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())); self.__class__.csrf=''
        _,login=self.req('/api/auth/login','POST',{'username':'operator','password':'Operator!Preview2026'}); self.__class__.csrf=login['data']['csrf_token']
        self.assertEqual(self.req('/api/runbooks')[0],200)
        self.assertEqual(self.req('/api/runbooks','POST',{'name':'Forbidden'})[0],403)
        self.assertEqual(self.req('/api/admin/users')[0],403)
        self.__class__.opener=opener; self.__class__.csrf=csrf
    def test_member_sees_and_executes_only_assigned_team_tasks(self):
        _,users=self.req('/api/admin/users');operator_id=next(u['id'] for u in users['data'] if u['username']=='operator')
        _,created=self.req('/api/runbooks','POST',{'name':'Assigned execution'});rid=created['data']['id']
        _,team=self.req(f'/api/runbooks/{rid}/teams','POST',{'name':'Release Team','user_ids':[operator_id]});team_id=team['data']['id']
        _,assigned=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Assigned task','owner_team_id':team_id,'task_type':'milestone'});assigned_id=assigned['data']['tasks'][0]['id']
        _,unassigned=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Admin task'});unassigned_id=unassigned['data']['tasks'][1]['id']
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'});self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        admin_opener,admin_csrf=self.opener,self.csrf;self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
        _,login=self.req('/api/auth/login','POST',{'username':'operator','password':'Operator!Preview2026'});self.__class__.csrf=login['data']['csrf_token']
        _,doc=self.req(f'/api/runbooks/{rid}');self.assertEqual([t['title'] for t in doc['data']['tasks']],['Assigned task'])
        self.assertEqual(self.req(f'/api/tasks/{assigned_id}','PATCH',{'status':'complete'})[0],200)
        self.assertEqual(self.req(f'/api/tasks/{unassigned_id}','PATCH',{'status':'running'})[0],403)
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
    def test_realtime_feed_emits_after_change(self):
        stream=self.opener.open(self.base+'/api/events',timeout=4)
        self.assertEqual(stream.readline().decode().strip(),'event: connected')
        stream.readline(); stream.readline()
        self.assertEqual(self.req('/api/runbooks','POST',{'name':'Live update proof'})[0],201)
        lines=[]
        while len(lines)<5:
            line=stream.readline().decode().strip(); lines.append(line)
            if line=='event: workspace':
                payload=json.loads(stream.readline().decode().removeprefix('data: ').strip());break
        stream.close(); self.assertIn('event: workspace',lines);self.assertEqual(payload['action'],'runbook.created');self.assertEqual(payload['actor'],'Anushka')

if __name__=='__main__': unittest.main()
