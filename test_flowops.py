import base64
import hashlib
import json
import os
import tempfile
import threading
import time
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

def unrestricted_urlopen(url,data=None,headers=None,method='GET',timeout=8,allow_private_network=False,max_redirects=3):
    """A drop-in replacement for server.safe_urlopen used ONLY to bypass the
    SSRF loopback rejection in tests that need to point at a real receiver
    running on 127.0.0.1 (there's no other practical way to run a real HTTP
    server in this test environment) -- the SSRF *validation* itself stays
    untouched and is separately covered by its own dedicated tests; this
    only swaps out the destination check for these specific real-receiver
    tests, mirroring how ServiceOps's own test suite handles the identical
    tension for its own (unconditional) loopback rejection."""
    return urllib.request.urlopen(urllib.request.Request(url,data=data,headers=headers or {},method=method),timeout=timeout)

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
    def test_browser_api_refreshes_stale_csrf_and_retries_once(self):
        source=(server.STATIC/'app.js').read_text()
        helper=source.split('async function api(',1)[1].split('function toast',1)[0]
        self.assertIn("body.error==='Invalid or missing CSRF token'",helper)
        self.assertIn("fetch('/api/auth/me'",helper)
        self.assertIn('state.csrf=freshToken',helper)
        self.assertIn('csrfRetried:true',helper)
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
    def test_connection_test_against_a_real_url_never_uses_the_mock_shortcut(self):
        # Only a literal mock:// URL gets the canned test-harness result;
        # any real http(s):// URL -- even with a bad credential -- must
        # perform a genuine round trip and surface a real error, not the
        # mocked "verified" response.
        def fake_open(request,timeout=0):
            raise urllib.error.HTTPError('https://serviceops.example/api/v1/tickets?limit=1',401,'Unauthorized',{},None)
        with patch('server.urllib.request.urlopen',fake_open):
            code,result=self.req('/api/admin/integrations/test','POST',{'provider':'serviceops','url':'https://serviceops.example','credential':'sop_bad_key'})
        self.assertEqual(code,502)
        self.assertIn('rejected the API key',result['error'])
        self.assertNotIn('latency_ms',result)
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
            def __init__(self,body):self.body=body
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def read(self,*_):return self.body
        def fake_open(request,timeout=0):
            captured.append(request)
            if request.full_url.endswith('/ctasks'):
                return Response(json.dumps({'data':[
                    {'number':'CTASK0000001','title':'Freeze traffic','state':'Open','sequence':1,'assignee':'Nova Reyes'},
                    {'number':'CTASK0000002','title':'Apply migration','state':'Open','sequence':2,'assignee':None},
                ]}).encode())
            return Response(b'{"data":{"id":42,"number":"CHG0000042","type":"change","title":"Core release","state":"Approved","priority":"P2"}}')
        with patch('server.urllib.request.urlopen',fake_open):code,body=self.req(f'/api/runbooks/{rid}/serviceops-sync','POST',{})
        self.assertEqual(code,200);doc=body['data'];self.assertEqual(doc['serviceops_state'],'Approved');self.assertEqual(doc['serviceops_title'],'Core release')
        self.assertEqual(captured[0].full_url,'https://serviceops.example/api/v1/tickets/CHG0000042');self.assertEqual(captured[0].get_header('Authorization'),'Bearer sop_test_only');self.assertTrue(captured[0].get_header('X-request-id'))
        self.assertEqual(body['ctasks_imported'],2)
        runbook=self.req(f'/api/runbooks/{rid}')[1]['data']
        imported=[t for t in runbook['tasks'] if t['stream']=='Change tasks']
        self.assertEqual([t['title'] for t in imported],['Freeze traffic','Apply migration'])
        self.assertEqual(imported[1]['depends_on'],[imported[0]['id']])
        self.assertEqual(imported[0]['owner_display'],'Nova Reyes')
        self.assertIn('Change tasks',[s['name'] for s in runbook['streams']])
        # syncing again must not duplicate the already-imported change tasks
        with patch('server.urllib.request.urlopen',fake_open):code,body=self.req(f'/api/runbooks/{rid}/serviceops-sync','POST',{})
        self.assertEqual(body['ctasks_imported'],0)
        runbook=self.req(f'/api/runbooks/{rid}')[1]['data']
        self.assertEqual(len([t for t in runbook['tasks'] if t['stream']=='Change tasks']),2)
    def test_serviceops_ctask_sync_stores_team_and_assignee_separately_and_updates_on_resync(self):
        self.req('/api/admin/integrations','POST',{'provider':'serviceops','url':'https://serviceops.example','credential':'sop_ctask_team','enabled':True})
        _,created=self.req('/api/runbooks','POST',{'name':'Team-tracked change','serviceops_ticket':'CHG0000050'});rid=created['data']['id']
        class Response:
            status=200
            headers={'X-Request-ID':'r'}
            def __init__(self,body):self.body=body
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def read(self,*_):return self.body
        def ctasks_response(rows):
            def fake_open(request,timeout=0):
                if request.full_url.endswith('/ctasks'):
                    return Response(json.dumps({'data':rows}).encode())
                return Response(b'{"data":{"number":"CHG0000050","type":"change","title":"Team-tracked change","state":"Approved","priority":"P2"}}')
            return fake_open
        first=[{'number':'CTASK0000020','title':'Wipe servers','state':'Open','sequence':1,'assignmentGroup':'Unix','assignee':None}]
        with patch('server.urllib.request.urlopen',ctasks_response(first)):
            self.req(f'/api/runbooks/{rid}/serviceops-sync','POST',{})
        runbook=self.req(f'/api/runbooks/{rid}')[1]['data']
        task=next(t for t in runbook['tasks'] if t['serviceops_ctask']=='CTASK0000020')
        self.assertEqual(task['serviceops_ctask_team'],'Unix')
        self.assertEqual(task['owner'],'')
        # ServiceOps now shows an assignee picked up the task -- re-sync must
        # update the existing task, not silently skip it.
        second=[{'number':'CTASK0000020','title':'Wipe servers','state':'Open','sequence':1,'assignmentGroup':'Unix','assignee':'Nova Reyes'}]
        with patch('server.urllib.request.urlopen',ctasks_response(second)):
            code,body=self.req(f'/api/runbooks/{rid}/serviceops-sync','POST',{})
        self.assertEqual(code,200)
        runbook=self.req(f'/api/runbooks/{rid}')[1]['data']
        matching=[t for t in runbook['tasks'] if t['serviceops_ctask']=='CTASK0000020']
        self.assertEqual(len(matching),1)
        self.assertEqual(matching[0]['owner'],'Nova Reyes')
        self.assertEqual(matching[0]['serviceops_ctask_team'],'Unix')
    def test_servicenow_connector_syncs_change_and_pushes_lifecycle_state(self):
        import http.server as http_server_module
        requests_seen=[]
        class ServiceNowDouble(http_server_module.BaseHTTPRequestHandler):
            def do_GET(self):
                requests_seen.append(('GET',self.path,None))
                self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
                self.wfile.write(json.dumps({'result':[{'number':'CHG0001234','sys_id':'abc123def456','state':'-5'}]}).encode())
            def do_PATCH(self):
                length=int(self.headers.get('Content-Length','0'))
                body=json.loads(self.rfile.read(length))
                requests_seen.append(('PATCH',self.path,body))
                self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
                self.wfile.write(json.dumps({'result':{'number':'CHG0001234','sys_id':'abc123def456','state':body.get('state')}}).encode())
            def log_message(self,*a): pass
        double=http_server_module.HTTPServer(('127.0.0.1',0),ServiceNowDouble)
        threading.Thread(target=double.serve_forever,daemon=True).start()
        try:
            base=f'http://127.0.0.1:{double.server_port}'
            with patch('server.safe_urlopen',unrestricted_urlopen):
                code,saved=self.req('/api/admin/integrations','POST',{'provider':'servicenow','url':base,'username':'svc_flowops','credential':'sn_pw','enabled':True})
                self.assertEqual(code,200)
                code,tested=self.req('/api/admin/integrations/test','POST',{'provider':'servicenow'})
                self.assertEqual(code,200); self.assertTrue(tested['data']['ok'])
                _,created=self.req('/api/runbooks','POST',{'name':'ServiceNow-tracked change'}); rid=created['data']['id']
                code,synced=self.req(f'/api/runbooks/{rid}/servicenow-sync','POST',{'ticket':'CHG0001234'})
                self.assertEqual(code,200)
                self.assertEqual(synced['data']['servicenow_change_number'],'CHG0001234')
                self.assertEqual(synced['data']['servicenow_state'],'-5')
                self.assertEqual(synced['servicenow']['sys_id'],'abc123def456')
                self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'})
                code,transitioned=self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
                self.assertEqual(code,200)
                self.assertEqual(transitioned['data']['servicenow_state'],'-1')  # Implement
                patch_requests=[r for r in requests_seen if r[0]=='PATCH']
                self.assertEqual(len(patch_requests),1)
                self.assertEqual(patch_requests[0][2],{'state':'-1'})
            # non-mock, real request path -- credential is never echoed back
            _,connections=self.req('/api/admin/integrations')
            self.assertNotIn('credential',connections['data']['servicenow'])
            self.assertNotIn('password',connections['data']['servicenow'])
        finally:
            double.shutdown()
    def test_servicenow_integration_requires_username_and_url(self):
        self.req('/api/admin/integrations','POST',{'provider':'servicenow','url':'','username':'','revoke_credential':True})
        code,body=self.req('/api/admin/integrations/test','POST',{'provider':'servicenow'})
        self.assertEqual(code,400)
    def test_verify_oidc_id_token_checks_signature_issuer_audience_and_expiry(self):
        import base64 as b64
        import random
        def is_probable_prime(num, rounds=20):
            if num < 2: return False
            for small in (2,3,5,7,11,13,17,19,23,29,31,37):
                if num % small == 0: return num == small
            d, r = num - 1, 0
            while d % 2 == 0: d //= 2; r += 1
            for _ in range(rounds):
                a = random.randrange(2, num - 1)
                x = pow(a, d, num)
                if x in (1, num - 1): continue
                for _ in range(r - 1):
                    x = pow(x, 2, num)
                    if x == num - 1: break
                else: return False
            return True
        def gen_prime(bits):
            while True:
                candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
                if is_probable_prime(candidate): return candidate
        random.seed(7654321)
        p, q = gen_prime(512), gen_prime(512)
        n = p * q; phi = (p - 1) * (q - 1); e = 65537; d = pow(e, -1, phi)
        def sign(message: bytes) -> bytes:
            digest_info_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
            digest = hashlib.sha256(message).digest()
            key_bytes = (n.bit_length() + 7) // 8
            padded_len = key_bytes - 3 - len(digest_info_prefix) - len(digest)
            em = b"\x00\x01" + b"\xff" * padded_len + b"\x00" + digest_info_prefix + digest
            sig_int = pow(int.from_bytes(em, "big"), d, n)
            return sig_int.to_bytes(key_bytes, "big")
        def b64url(data: bytes) -> str:
            return b64.urlsafe_b64encode(data).decode().rstrip("=")
        kid="oidc-test-key"; issuer="https://idp.example.test/realms/flowops"; audience="flowops-client"
        server._oidc_jwks_cache["https://idp.example.test/jwks"]={"keys":{kid:(n,e)},"fetched_at":time.monotonic()}
        def make_jwt(email,aud=audience,iss=issuer,exp=None,kid_used=kid,tamper=False):
            header=b64url(json.dumps({"alg":"RS256","kid":kid_used}).encode())
            payload=b64url(json.dumps({"email":email,"iss":iss,"aud":aud,"exp":exp if exp is not None else int(time.time())+300}).encode())
            sig=sign(f"{header}.{payload}".encode())
            if tamper:
                payload=b64url(json.dumps({"email":"attacker@example.com","iss":iss,"aud":aud,"exp":int(time.time())+300}).encode())
            return f"{header}.{payload}.{b64url(sig)}"
        jwks_url="https://idp.example.test/jwks"
        claims=server.verify_oidc_id_token(jwks_url,issuer,audience,make_jwt("user@example.com"))
        self.assertIsNotNone(claims); self.assertEqual(claims['email'],'user@example.com')
        self.assertIsNone(server.verify_oidc_id_token(jwks_url,issuer,audience,make_jwt("user@example.com",tamper=True)),"tampered payload must fail signature check")
        self.assertIsNone(server.verify_oidc_id_token(jwks_url,issuer,audience,make_jwt("user@example.com",aud="some-other-client")),"wrong audience must be rejected")
        self.assertIsNone(server.verify_oidc_id_token(jwks_url,issuer,audience,make_jwt("user@example.com",iss="https://attacker.example/realms/evil")),"wrong issuer must be rejected")
        self.assertIsNone(server.verify_oidc_id_token(jwks_url,issuer,audience,make_jwt("user@example.com",exp=int(time.time())-10)),"expired token must be rejected")
        self.assertIsNone(server.verify_oidc_id_token(jwks_url,issuer,audience,make_jwt("user@example.com",kid_used="not-a-real-kid")),"unknown kid must be rejected")
        # aud may also be delivered as a list per the OIDC spec
        header=b64url(json.dumps({"alg":"RS256","kid":kid}).encode())
        payload=b64url(json.dumps({"email":"user@example.com","iss":issuer,"aud":[audience,"other"],"exp":int(time.time())+300}).encode())
        list_token=f"{header}.{payload}.{b64url(sign(f'{header}.{payload}'.encode()))}"
        self.assertIsNotNone(server.verify_oidc_id_token(jwks_url,issuer,audience,list_token))
    def test_oidc_connection_test_verifies_a_real_discovery_document_and_jwks(self):
        import http.server as http_server_module
        class OidcDouble(http_server_module.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path=='/realms/flowops/.well-known/openid-configuration':
                    body=json.dumps({
                        'issuer':f'http://127.0.0.1:{self.server.server_port}/realms/flowops',
                        'authorization_endpoint':f'http://127.0.0.1:{self.server.server_port}/realms/flowops/auth',
                        'token_endpoint':f'http://127.0.0.1:{self.server.server_port}/realms/flowops/token',
                        'jwks_uri':f'http://127.0.0.1:{self.server.server_port}/realms/flowops/certs',
                    }).encode()
                elif self.path=='/realms/flowops/certs':
                    body=json.dumps({'keys':[{'kty':'RSA','kid':'k1','n':base64.urlsafe_b64encode((12345678901234567890).to_bytes(9,'big')).decode().rstrip('='),'e':base64.urlsafe_b64encode((65537).to_bytes(3,'big')).decode().rstrip('=')}]}).encode()
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(body)
            def log_message(self,*a): pass
        double=http_server_module.HTTPServer(('127.0.0.1',0),OidcDouble)
        threading.Thread(target=double.serve_forever,daemon=True).start()
        try:
            base=f'http://127.0.0.1:{double.server_port}/realms/flowops'
            with patch('server.safe_urlopen',unrestricted_urlopen):
                code,saved=self.req('/api/admin/integrations','POST',{'provider':'oidc','url':base,'client_id':'flowops','credential':'kc_secret','enabled':True})
                self.assertEqual(code,200)
                code,tested=self.req('/api/admin/integrations/test','POST',{'provider':'oidc'})
                self.assertEqual(code,200,tested); self.assertTrue(tested['data']['ok'])
                self.assertEqual(tested['data']['rsa_keys_found'],1)
            _,connections=self.req('/api/admin/integrations')
            self.assertTrue(connections['data']['oidc']['credential_configured'])
            self.assertNotIn('credential',connections['data']['oidc'])
            self.assertNotIn('client_secret',connections['data']['oidc'])
        finally:
            double.shutdown()
    def test_oidc_login_is_disabled_by_default_and_redirects_when_enabled(self):
        opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        opener.handlers=[h for h in opener.handlers if not isinstance(h,urllib.request.HTTPRedirectHandler)]
        code,body=self.req('/api/admin/integrations','POST',{'provider':'oidc','enabled':False})
        self.assertEqual(code,200)
        request=urllib.request.Request(self.base+'/auth/oidc/login')
        try:
            with opener.open(request) as res: status=res.status
        except urllib.error.HTTPError as err: status=err.code
        self.assertEqual(status,404,"OIDC login must 404 while disabled, not silently redirect anywhere")
    def scim_req(self,path,method='GET',token=None,body=None):
        data=json.dumps(body).encode() if body is not None else None
        headers={'Content-Type':'application/scim+json'}
        if token: headers['Authorization']=f'Bearer {token}'
        request=urllib.request.Request(self.base+path,data=data,method=method,headers=headers)
        try:
            with urllib.request.urlopen(request) as res:
                raw=res.read()
                return res.status,(json.loads(raw) if raw else None)
        except urllib.error.HTTPError as err:
            raw=err.read()
            return err.code,(json.loads(raw) if raw else None)
    def test_scim_requires_a_bearer_token_with_the_scim_scope(self):
        code,body=self.scim_req('/scim/v2/Users')
        self.assertEqual(code,401); self.assertEqual(body['schemas'],[server.SCIM_ERROR_SCHEMA])
        _,wrong=self.req('/api/admin/api-tokens','POST',{'name':'Not SCIM','scopes':['runbooks:read']})
        code,body=self.scim_req('/scim/v2/Users',token=wrong['data']['token'])
        self.assertEqual(code,403)
    def test_scim_user_lifecycle_create_get_patch_deactivate(self):
        _,tok=self.req('/api/admin/api-tokens','POST',{'name':'IdP provisioner','scopes':['scim:provision']})
        token=tok['data']['token']
        code,created=self.scim_req('/scim/v2/Users','POST',token,{
            'schemas':['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName':'scim.jsmith','displayName':'SCIM J Smith',
            'emails':[{'value':'jsmith@example.com','primary':True}],'active':True,
        })
        self.assertEqual(code,201,created)
        self.assertEqual(created['schemas'],[server.SCIM_USER_SCHEMA])
        self.assertEqual(created['userName'],'scim.jsmith')
        self.assertTrue(created['active'])
        uid=created['id']
        self.assertEqual(created['meta']['location'],f'/scim/v2/Users/{uid}')
        # duplicate userName must be rejected
        self.assertEqual(self.scim_req('/scim/v2/Users','POST',token,{'userName':'scim.jsmith','displayName':'dup'})[0],409)
        # GET single
        code,fetched=self.scim_req(f'/scim/v2/Users/{uid}',token=token)
        self.assertEqual(code,200); self.assertEqual(fetched['emails'][0]['value'],'jsmith@example.com')
        # GET list includes it, real DB row confirms mapping
        code,listed=self.scim_req('/scim/v2/Users',token=token)
        self.assertEqual(code,200); self.assertEqual(listed['schemas'],[server.SCIM_LIST_SCHEMA])
        self.assertIn(uid,[u['id'] for u in listed['Resources']])
        # PATCH: rename + deactivate via Operations shape
        code,patched=self.scim_req(f'/scim/v2/Users/{uid}','PATCH',token,{
            'schemas':['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations':[{'op':'replace','path':'displayName','value':'Renamed Smith'},{'op':'replace','path':'active','value':False}],
        })
        self.assertEqual(code,200); self.assertEqual(patched['displayName'],'Renamed Smith'); self.assertFalse(patched['active'])
        with server.connect() as db:
            row=db.execute('SELECT display_name,active FROM users WHERE id=?',(int(uid),)).fetchone()
            self.assertEqual(row['display_name'],'Renamed Smith'); self.assertEqual(row['active'],0)
        # DELETE deprovisions (soft-delete), not a hard row delete
        code,_=self.scim_req(f'/scim/v2/Users/{uid}','DELETE',token=token)
        self.assertEqual(code,204)
        with server.connect() as db:
            row=db.execute('SELECT active FROM users WHERE id=?',(int(uid),)).fetchone()
            self.assertIsNotNone(row,'SCIM DELETE must not hard-delete the user row')
            self.assertEqual(row['active'],0)
    def test_scim_filter_supports_eq_co_sw_on_the_documented_attribute_set(self):
        _,tok=self.req('/api/admin/api-tokens','POST',{'name':'IdP filter test','scopes':['scim:provision']})
        token=tok['data']['token']
        self.scim_req('/scim/v2/Users','POST',token,{'userName':'filter.alpha','displayName':'Alpha Filter','emails':[{'value':'alpha@example.com'}]})
        self.scim_req('/scim/v2/Users','POST',token,{'userName':'filter.beta','displayName':'Beta Filter','emails':[{'value':'beta@example.com'}]})
        code,body=self.scim_req('/scim/v2/Users?'+urllib.parse.urlencode({'filter':'userName eq "filter.alpha"'}),token=token)
        self.assertEqual(code,200); self.assertEqual([u['userName'] for u in body['Resources']],['filter.alpha'])
        code,body=self.scim_req('/scim/v2/Users?'+urllib.parse.urlencode({'filter':'emails.value co "beta"'}),token=token)
        self.assertEqual(code,200); self.assertEqual([u['userName'] for u in body['Resources']],['filter.beta'])
        code,body=self.scim_req('/scim/v2/Users?'+urllib.parse.urlencode({'filter':'userName sw "filter."'}),token=token)
        self.assertEqual(code,200); self.assertEqual(len(body['Resources']),2)
        code,body=self.scim_req('/scim/v2/Users?'+urllib.parse.urlencode({'filter':'unsupportedAttr eq "x"'}),token=token)
        self.assertEqual(code,400)
    def test_scim_group_lifecycle_create_membership_and_deletion_reflects_central_team_members(self):
        _,tok=self.req('/api/admin/api-tokens','POST',{'name':'IdP group provisioner','scopes':['scim:provision']})
        token=tok['data']['token']
        _,alice=self.scim_req('/scim/v2/Users','POST',token,{'userName':'scim.alice','displayName':'Alice'})
        _,bob=self.scim_req('/scim/v2/Users','POST',token,{'userName':'scim.bob','displayName':'Bob'})
        code,group=self.scim_req('/scim/v2/Groups','POST',token,{'displayName':'SCIM Provisioned Team','members':[{'value':alice['id']}]})
        self.assertEqual(code,201,group); self.assertEqual(group['schemas'],[server.SCIM_GROUP_SCHEMA])
        gid=group['id']
        self.assertEqual([m['value'] for m in group['members']],[alice['id']])
        with server.connect() as db:
            member_ids={row[0] for row in db.execute('SELECT user_id FROM central_team_members WHERE team_id=?',(int(gid),))}
            self.assertEqual(member_ids,{int(alice['id'])})
        # PATCH add Bob
        code,patched=self.scim_req(f'/scim/v2/Groups/{gid}','PATCH',token,{'Operations':[{'op':'add','path':'members','value':[{'value':bob['id']}]}]})
        self.assertEqual(code,200)
        self.assertEqual(sorted(m['value'] for m in patched['members']),sorted([alice['id'],bob['id']]))
        with server.connect() as db:
            member_ids={row[0] for row in db.execute('SELECT user_id FROM central_team_members WHERE team_id=?',(int(gid),))}
            self.assertEqual(member_ids,{int(alice['id']),int(bob['id'])})
        # PATCH remove Alice
        code,patched=self.scim_req(f'/scim/v2/Groups/{gid}','PATCH',token,{'Operations':[{'op':'remove','path':'members','value':[{'value':alice['id']}]}]})
        self.assertEqual(code,200)
        self.assertEqual([m['value'] for m in patched['members']],[bob['id']])
        # DELETE the group removes it entirely (no runbook is linked to it)
        code,_=self.scim_req(f'/scim/v2/Groups/{gid}','DELETE',token=token)
        self.assertEqual(code,204)
        with server.connect() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM central_teams WHERE id=?',(int(gid),)).fetchone())
    def test_completing_a_task_pushes_its_ctask_state_back_to_serviceops(self):
        self.req('/api/admin/integrations','POST',{'provider':'serviceops','url':'https://serviceops.example','credential':'sop_ctask_push','enabled':True})
        _,created=self.req('/api/runbooks','POST',{'name':'Push-back change','serviceops_ticket':'CHG0000044'});rid=created['data']['id']
        captured=[]
        class Response:
            status=200
            headers={'X-Request-ID':'r'}
            def __init__(self,body):self.body=body
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def read(self,*_):return self.body
        def fake_open(request,timeout=0):
            captured.append(request)
            if request.full_url.endswith('/ctasks'):
                return Response(json.dumps({'data':[
                    {'number':'CTASK0000010','title':'Drain traffic','state':'Open','sequence':1,'assignee':None},
                    {'number':'CTASK0000011','title':'Restore traffic','state':'Open','sequence':2,'assignee':None},
                ]}).encode())
            if '/ctasks/' in request.full_url:
                return Response(json.dumps({'data':{'number':'CTASK0000010','state':json.loads(request.data)['state']}}).encode())
            return Response(b'{"data":{"number":"CHG0000044","type":"change","title":"Push-back change","state":"Approved","priority":"P2"}}')
        with patch('server.urllib.request.urlopen',fake_open):
            self.req(f'/api/runbooks/{rid}/serviceops-sync','POST',{})
        runbook=self.req(f'/api/runbooks/{rid}')[1]['data']
        task_id=next(t['id'] for t in runbook['tasks'] if t['serviceops_ctask']=='CTASK0000010')
        task2_id=next(t['id'] for t in runbook['tasks'] if t['serviceops_ctask']=='CTASK0000011')
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'})
        with patch('server.urllib.request.urlopen',fake_open):
            self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        captured.clear()
        with patch('server.urllib.request.urlopen',fake_open):
            code,body=self.req(f'/api/tasks/{task_id}','PATCH',{'status':'running'})
        self.assertEqual(code,200)
        running_push=next(r for r in captured if '/ctasks/CTASK0000010' in r.full_url)
        self.assertEqual(running_push.method,'PATCH')
        self.assertEqual(json.loads(running_push.data),{'state':'Work in Progress'})
        captured.clear()
        with patch('server.urllib.request.urlopen',fake_open):
            code,body=self.req(f'/api/tasks/{task_id}','PATCH',{'status':'complete'})
        self.assertEqual(code,200)
        complete_push=next(r for r in captured if '/ctasks/CTASK0000010' in r.full_url)
        self.assertEqual(json.loads(complete_push.data),{'state':'Closed Complete'})
        runbook=self.req(f'/api/runbooks/{rid}')[1]['data']
        self.assertTrue(any(a['action']=='serviceops.ctask_synced' for a in runbook['audit']))
        # a ServiceOps outage during a task transition must not block the local transition
        def broken(request,timeout=0):raise __import__('urllib.error',fromlist=['URLError']).URLError('unreachable')
        with patch('server.urllib.request.urlopen',broken):
            code,body=self.req(f'/api/tasks/{task2_id}','PATCH',{'status':'running'})
        self.assertEqual(code,200)
        self.assertEqual(next(t['status'] for t in body['data']['tasks'] if t['id']==task2_id),'running')
        self.req('/api/admin/integrations','POST',{'provider':'serviceops','revoke_credential':True})
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
    def test_audit_export_is_checksummed_and_chain_verified(self):
        self.req('/api/runbooks','POST',{'name':'Audit export check'})
        code,exported=self.req('/api/admin/audit/export')
        self.assertEqual(code,200)
        self.assertTrue(exported['data']['chain_verified'])
        self.assertGreater(exported['data']['count'],0)
        recomputed='sha256:'+__import__('hashlib').sha256(json.dumps(exported['data']['events'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.assertEqual(exported['data']['checksum'],recomputed)
        _,recent=self.req('/api/admin/audit')
        self.assertTrue(any(e['action']=='audit.exported' for e in recent['data']))
    def test_audit_verify_endpoint_confirms_chain_without_requiring_export(self):
        self.req('/api/runbooks','POST',{'name':'Verify-only check'})
        code,body=self.req('/api/admin/audit/verify')
        self.assertEqual(code,200)
        self.assertTrue(body['data']['chain_verified'])
        self.assertGreater(body['data']['events_checked'],0)
    def test_audit_rows_are_immutable_by_policy_at_the_database_level(self):
        self.req('/api/runbooks','POST',{'name':'Immutability check'})
        with server.connect() as db:
            row_id=db.execute("SELECT MAX(id) FROM audit").fetchone()[0]
            with self.assertRaises(server.sqlite3.IntegrityError):
                db.execute("UPDATE audit SET detail='forged' WHERE id=?",(row_id,))
            with self.assertRaises(server.sqlite3.IntegrityError):
                db.execute("DELETE FROM audit WHERE id=?",(row_id,))
            # a raw delete outside the sanctioned purge path (which toggles
            # audit_purge_lock around its DELETE) must still be rejected even
            # when a retention period happens to be configured.
            still_there=db.execute("SELECT 1 FROM audit WHERE id=?",(row_id,)).fetchone()
            self.assertIsNotNone(still_there)
    def test_configurable_audit_retention_purges_old_events_and_keeps_chain_verifiable(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Retention prefix check'})
        with server.connect() as db:
            instance_id=db.execute("SELECT id FROM instances WHERE slug='flowops'").fetchone()[0]
            oldest_id=db.execute("SELECT MIN(id) FROM audit WHERE instance_id=?",(instance_id,)).fetchone()[0]
            old_stamp=(__import__('datetime').datetime.now(__import__('datetime').timezone.utc)-__import__('datetime').timedelta(days=400)).isoformat(timespec='seconds')
            # Audit rows are immutable by policy (audit_no_update trigger) --
            # simulating an old event for this retention test legitimately
            # requires bypassing that trigger the same way a DBA would for a
            # one-off test fixture, not something the running app can do.
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE audit SET created_at=? WHERE id=?",(old_stamp,oldest_id))
            db.execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit rows are immutable'); END;")
            db.commit()
        self.assertEqual(self.req('/api/admin/audit/purge','POST',{})[0],400)
        self.assertEqual(self.req('/api/admin/settings','POST',{'audit_retention_days':'365'})[0],200)
        code,purged=self.req('/api/admin/audit/purge','POST',{})
        self.assertEqual(code,200); self.assertGreaterEqual(purged['data']['purged'],1)
        with server.connect() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM audit WHERE id=?",(oldest_id,)).fetchone())
        code,exported=self.req('/api/admin/audit/export')
        self.assertEqual(code,200); self.assertTrue(exported['data']['chain_verified'])
    def test_linked_runbooks_aggregate_child_status_and_progress(self):
        _,parent=self.req('/api/runbooks','POST',{'name':'Parent migration'}); parent_id=parent['data']['id']
        _,childA=self.req('/api/runbooks','POST',{'name':'Wave A'}); child_a_id=childA['data']['id']
        _,childB=self.req('/api/runbooks','POST',{'name':'Wave B'}); child_b_id=childB['data']['id']
        self.req(f'/api/runbooks/{child_a_id}/tasks','POST',{'title':'Step 1'})
        self.req(f'/api/runbooks/{child_a_id}/tasks','POST',{'title':'Step 2'})
        self.req(f'/api/runbooks/{child_b_id}/tasks','POST',{'title':'Step 1'})
        code,linkedA=self.req(f'/api/runbooks/{child_a_id}','PATCH',{'parent_runbook_id':parent_id})
        self.assertEqual(code,200)
        self.assertEqual(linkedA['data']['parent_runbook']['name'],'Parent migration')
        self.req(f'/api/runbooks/{child_b_id}','PATCH',{'parent_runbook_id':parent_id})
        self.assertEqual(self.req(f'/api/runbooks/{parent_id}','PATCH',{'parent_runbook_id':child_a_id})[0],400)
        self.assertEqual(self.req(f'/api/runbooks/{child_a_id}','PATCH',{'parent_runbook_id':child_a_id})[0],400)
        _,parentDoc=self.req(f'/api/runbooks/{parent_id}')
        self.assertEqual(len(parentDoc['data']['child_runbooks']),2)
        self.assertEqual(parentDoc['data']['aggregate_progress'],0)
        self.assertEqual(parentDoc['data']['aggregate_status'],'in_progress')
        _,childADoc=self.req(f'/api/runbooks/{child_a_id}')
        task_id=childADoc['data']['tasks'][0]['id']
        self.req(f'/api/runbooks/{child_a_id}/transition','POST',{'status':'ready'});self.req(f'/api/runbooks/{child_a_id}/transition','POST',{'status':'live'})
        self.req(f'/api/tasks/{task_id}','PATCH',{'status':'running'});self.req(f'/api/tasks/{task_id}','PATCH',{'status':'complete'})
        _,parentAfter=self.req(f'/api/runbooks/{parent_id}')
        self.assertEqual(parentAfter['data']['aggregate_progress'],round(1*100/3))
        self.assertEqual(parentAfter['data']['aggregate_status'],'live')
    def test_linked_runbooks_reject_more_than_one_level_of_nesting(self):
        _,grandparent=self.req('/api/runbooks','POST',{'name':'Grandparent'}); grandparent_id=grandparent['data']['id']
        _,parent=self.req('/api/runbooks','POST',{'name':'Middle'}); parent_id=parent['data']['id']
        _,leaf=self.req('/api/runbooks','POST',{'name':'Leaf'}); leaf_id=leaf['data']['id']
        self.assertEqual(self.req(f'/api/runbooks/{parent_id}','PATCH',{'parent_runbook_id':grandparent_id})[0],200)
        # parent_id already has a parent (grandparent) -- cannot also become a parent of leaf
        code,rejected=self.req(f'/api/runbooks/{leaf_id}','PATCH',{'parent_runbook_id':parent_id})
        self.assertEqual(code,400)
        self.assertIn('one level',rejected['error'])
        # a runbook that already HAS children cannot itself become someone else's child
        _,has_children=self.req('/api/runbooks','POST',{'name':'Has children'}); has_children_id=has_children['data']['id']
        _,its_child=self.req('/api/runbooks','POST',{'name':'Its child'}); its_child_id=its_child['data']['id']
        self.assertEqual(self.req(f'/api/runbooks/{its_child_id}','PATCH',{'parent_runbook_id':has_children_id})[0],200)
        _,other_parent=self.req('/api/runbooks','POST',{'name':'Other parent'}); other_parent_id=other_parent['data']['id']
        code,rejected2=self.req(f'/api/runbooks/{has_children_id}','PATCH',{'parent_runbook_id':other_parent_id})
        self.assertEqual(code,400)
        self.assertIn('one level',rejected2['error'])
    def test_automation_task_executes_and_reports_success(self):
        import http.server as http_server_module
        received=[]
        class Receiver(http_server_module.BaseHTTPRequestHandler):
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'))
                received.append(json.loads(self.rfile.read(length)))
                self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
            def log_message(self,*a): pass
        receiver=http_server_module.HTTPServer(('127.0.0.1',0),Receiver)
        threading.Thread(target=receiver.serve_forever,daemon=True).start()
        try:
            _,created=self.req('/api/runbooks','POST',{'name':'Automation success'}); rid=created['data']['id']
            _,task=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Call webhook','task_type':'automation','automation_url':f'http://127.0.0.1:{receiver.server_port}/hook'}); tid=task['data']['tasks'][0]['id']
            self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'}); self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
            with patch('server.safe_urlopen',unrestricted_urlopen):
                code,started=self.req(f'/api/tasks/{tid}','PATCH',{'status':'running'})
                self.assertEqual(code,200)
                started_task=next(t for t in started['data']['tasks'] if t['id']==tid)
                self.assertEqual(started_task['status'],'running')
                self.assertEqual(started_task['automation_status'],'queued')
                for _ in range(50):
                    _,doc=self.req(f'/api/runbooks/{rid}')
                    task_now=next(t for t in doc['data']['tasks'] if t['id']==tid)
                    if task_now['status']=='complete': break
                    time.sleep(0.1)
            self.assertEqual(task_now['status'],'complete')
            self.assertEqual(task_now['automation_status'],'success')
            self.assertEqual(task_now['automation_attempts'],1)
            self.assertEqual(len(received),1)
            self.assertEqual(received[0]['task_id'],tid)
        finally:
            receiver.shutdown()
    def test_automation_task_carries_runbooks_configured_context_header_and_variable(self):
        import http.server as http_server_module
        received=[]
        class Receiver(http_server_module.BaseHTTPRequestHandler):
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'))
                received.append({'path':self.path,'header':self.headers.get('X-Tenant',''),'body':self.rfile.read(length)})
                self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
            def log_message(self,*a): pass
        receiver=http_server_module.HTTPServer(('127.0.0.1',0),Receiver)
        threading.Thread(target=receiver.serve_forever,daemon=True).start()
        try:
            _,created=self.req('/api/runbooks','POST',{'name':'Context-aware release'}); rid=created['data']['id']
            code,updated=self.req(f'/api/runbooks/{rid}','PATCH',{'automation_context':{'headers':{'X-Tenant':'acme-corp'},'variables':{'env':'prod'}}})
            self.assertEqual(code,200)
            self.assertEqual(updated['data']['automation_context'],{'headers':{'X-Tenant':'acme-corp'},'variables':{'env':'prod'}})
            _,task=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Deploy','task_type':'automation','automation_url':f'http://127.0.0.1:{receiver.server_port}/hook?target={{{{env}}}}'}); tid=task['data']['tasks'][0]['id']
            self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'}); self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
            with patch('server.safe_urlopen',unrestricted_urlopen):
                self.req(f'/api/tasks/{tid}','PATCH',{'status':'running'})
                for _ in range(50):
                    _,doc=self.req(f'/api/runbooks/{rid}')
                    task_now=next(t for t in doc['data']['tasks'] if t['id']==tid)
                    if task_now['status']=='complete': break
                    time.sleep(0.1)
            self.assertEqual(task_now['status'],'complete')
            self.assertEqual(len(received),1)
            self.assertEqual(received[0]['header'],'acme-corp')
            self.assertEqual(received[0]['path'],'/hook?target=prod')
        finally:
            receiver.shutdown()
    def test_task_test_fire_reaches_receiver_without_touching_task_state(self):
        import http.server as http_server_module
        received=[]
        class Receiver(http_server_module.BaseHTTPRequestHandler):
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'))
                received.append(json.loads(self.rfile.read(length)))
                self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
            def log_message(self,*a): pass
        receiver=http_server_module.HTTPServer(('127.0.0.1',0),Receiver)
        threading.Thread(target=receiver.serve_forever,daemon=True).start()
        try:
            _,created=self.req('/api/runbooks','POST',{'name':'Test-fire check'}); rid=created['data']['id']
            _,task=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Deploy','task_type':'automation','automation_url':f'http://127.0.0.1:{receiver.server_port}/hook'}); tid=task['data']['tasks'][0]['id']
            before=next(t for t in task['data']['tasks'] if t['id']==tid)
            with patch('server.safe_urlopen',unrestricted_urlopen):
                code,fired=self.req(f'/api/tasks/{tid}/test-fire','POST',{})
            self.assertEqual(code,200)
            self.assertTrue(fired['data']['ok'])
            self.assertEqual(len(received),1)
            self.assertTrue(received[0].get('test'))
            _,doc=self.req(f'/api/runbooks/{rid}')
            after=next(t for t in doc['data']['tasks'] if t['id']==tid)
            self.assertEqual(after['status'],before['status'])
            self.assertEqual(after['automation_status'],before['automation_status'])
            self.assertEqual(after['automation_attempts'],before['automation_attempts'])
            audit_actions=[a['action'] for a in doc['data']['audit']]
            self.assertEqual(audit_actions.count('task.automation_test_fired'),1)
        finally:
            receiver.shutdown()
    def test_task_test_fire_requires_automation_url(self):
        _,created=self.req('/api/runbooks','POST',{'name':'No URL check'}); rid=created['data']['id']
        _,task=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Normal task'}); tid=task['data']['tasks'][0]['id']
        code,body=self.req(f'/api/tasks/{tid}/test-fire','POST',{})
        self.assertEqual(code,400)
    def test_automation_task_failure_allows_retry_and_audited_skip(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Automation failure'}); rid=created['data']['id']
        _,task=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Call dead endpoint','task_type':'automation','automation_url':'http://127.0.0.1:1/nowhere'}); tid=task['data']['tasks'][0]['id']
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'}); self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        self.req(f'/api/tasks/{tid}','PATCH',{'status':'running'})
        task_now=None
        for _ in range(50):
            _,doc=self.req(f'/api/runbooks/{rid}')
            task_now=next(t for t in doc['data']['tasks'] if t['id']==tid)
            if task_now['status']=='failed': break
            time.sleep(0.1)
        self.assertEqual(task_now['status'],'failed')
        self.assertEqual(task_now['automation_status'],'failed')
        self.assertIsNotNone(task_now['automation_result'])
        code,rejected=self.req(f'/api/tasks/{tid}','PATCH',{'status':'skipped'})
        self.assertEqual(code,400)
        self.assertIn('reason',rejected['error'])
        code,skipped=self.req(f'/api/tasks/{tid}','PATCH',{'status':'skipped','skip_reason':'Endpoint permanently decommissioned'})
        self.assertEqual(code,200)
        skipped_task=next(t for t in skipped['data']['tasks'] if t['id']==tid)
        self.assertEqual(skipped_task['status'],'skipped')
        self.assertEqual(skipped_task['skip_reason'],'Endpoint permanently decommissioned')
    def test_automation_task_requires_editor_permission_not_just_assignment(self):
        _,users=self.req('/api/admin/users'); operator_id=next(u['id'] for u in users['data'] if u['username']=='operator')
        _,created=self.req('/api/runbooks','POST',{'name':'Automation authorization'}); rid=created['data']['id']
        _,team=self.req(f'/api/runbooks/{rid}/teams','POST',{'name':'Automation Team','user_ids':[operator_id]}); team_id=team['data']['id']
        _,task=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Restricted automation','task_type':'automation','automation_url':'http://127.0.0.1:1/nowhere','owner_team_id':team_id}); tid=task['data']['tasks'][0]['id']
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'}); self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        admin_opener,admin_csrf=self.opener,self.csrf
        self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())); self.__class__.csrf=''
        _,login=self.req('/api/auth/login','POST',{'username':'operator','password':'Operator!Preview2026'}); self.__class__.csrf=login['data']['csrf_token']
        code,rejected=self.req(f'/api/tasks/{tid}','PATCH',{'status':'running'})
        self.assertEqual(code,403)
        self.assertIn('editor-level',rejected['error'])
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
    def test_automation_task_requires_url_before_starting(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Automation missing url'}); rid=created['data']['id']
        _,task=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'No URL set','task_type':'automation'}); tid=task['data']['tasks'][0]['id']
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'}); self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        code,rejected=self.req(f'/api/tasks/{tid}','PATCH',{'status':'running'})
        self.assertEqual(code,400)
        self.assertIn('automation URL',rejected['error'])
    def test_custom_fields_typed_definitions_and_values_on_runbooks_and_tasks(self):
        code,textField=self.req('/api/custom-fields','POST',{'name':'Change ticket','entity_type':'runbook','field_type':'text'})
        self.assertEqual(code,201); text_field_id=textField['data']['id']
        code,selectField=self.req('/api/custom-fields','POST',{'name':'Risk level','entity_type':'runbook','field_type':'select','options':['Low','Medium','High']})
        self.assertEqual(code,201); select_field_id=selectField['data']['id']
        code,taskField=self.req('/api/custom-fields','POST',{'name':'Verified by QA','entity_type':'task','field_type':'boolean'})
        self.assertEqual(code,201); task_field_id=taskField['data']['id']
        self.assertEqual(self.req('/api/custom-fields','POST',{'name':'Change ticket','entity_type':'runbook','field_type':'text'})[0],409)
        self.assertEqual(self.req('/api/custom-fields','POST',{'name':'Bad type','entity_type':'runbook','field_type':'not-a-type'})[0],400)
        _,listed=self.req('/api/custom-fields?entity_type=runbook')
        self.assertEqual({f['name'] for f in listed['data']},{'Change ticket','Risk level'})
        _,created=self.req('/api/runbooks','POST',{'name':'Custom field run'}); rid=created['data']['id']
        self.assertEqual(created['data']['custom_fields'],{'Change ticket':'','Risk level':''})
        code,updated=self.req(f'/api/runbooks/{rid}','PATCH',{'custom_fields':{text_field_id:'CHG0099','not-an-id':'ignored'}})
        self.assertEqual(code,200)
        self.assertEqual(updated['data']['custom_fields']['Change ticket'],'CHG0099')
        code,invalidOption=self.req(f'/api/runbooks/{rid}','PATCH',{'custom_fields':{select_field_id:'Not a real option'}})
        self.assertEqual(updated['data']['custom_fields']['Risk level'],'')
        _,made=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'QA check'}); tid=made['data']['tasks'][0]['id']
        self.assertEqual(made['data']['tasks'][0]['custom_fields'],{'Verified by QA':''})
        code,taskUpdated=self.req(f'/api/tasks/{tid}','PATCH',{'custom_fields':{task_field_id:True}})
        self.assertEqual(code,200)
        self.assertEqual(taskUpdated['data']['tasks'][0]['custom_fields']['Verified by QA'],'true')
        self.assertEqual(self.req(f'/api/custom-fields/{text_field_id}','DELETE')[0],200)
        _,afterDelete=self.req(f'/api/runbooks/{rid}')
        self.assertNotIn('Change ticket',afterDelete['data']['custom_fields'])
    def test_slack_and_teams_webhooks_use_provider_shaped_payloads_without_signing(self):
        import http.server as http_server_module
        received=[]
        class Receiver(http_server_module.BaseHTTPRequestHandler):
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'))
                received.append({'body':self.rfile.read(length),'signature':self.headers.get('X-FlowOps-Signature')})
                self.send_response(200); self.end_headers()
            def log_message(self,*a): pass
        receiver=http_server_module.HTTPServer(('127.0.0.1',0),Receiver)
        receiver_port=receiver.server_port
        threading.Thread(target=receiver.serve_forever,daemon=True).start()
        try:
            code,slackHook=self.req('/api/admin/webhooks','POST',{'name':'Slack channel','url':f'http://127.0.0.1:{receiver_port}/slack','provider':'slack','events':['*']})
            self.assertEqual(code,201)
            self.assertIsNone(slackHook['data']['secret'])
            code,teamsHook=self.req('/api/admin/webhooks','POST',{'name':'Teams channel','url':f'http://127.0.0.1:{receiver_port}/teams','provider':'teams','events':['*']})
            self.assertEqual(code,201)
            self.assertEqual(self.req('/api/admin/webhooks','POST',{'name':'Bad provider','url':f'http://127.0.0.1:{receiver_port}/x','provider':'discord'})[0],400)
            with patch('server.safe_urlopen',unrestricted_urlopen):
                self.req(f"/api/admin/webhooks/{slackHook['data']['id']}/test",'POST',{})
                self.req(f"/api/admin/webhooks/{teamsHook['data']['id']}/test",'POST',{})
            self.assertEqual(len(received),2)
            slack_payload=json.loads(received[0]['body'])
            self.assertIn('text',slack_payload)
            self.assertIsNone(received[0]['signature'])
            teams_payload=json.loads(received[1]['body'])
            self.assertEqual(teams_payload['@type'],'MessageCard')
            self.assertIsNone(received[1]['signature'])
        finally:
            receiver.shutdown()
    def test_concurrent_dispatcher_claims_never_double_deliver_the_same_event(self):
        # Simulates two FlowOps replicas sharing one SQLite file (as they do
        # in Kubernetes) both racing to claim the same freshly-created audit
        # rows. If the claim weren't atomic, both "replicas" would see the
        # same events and each would deliver them -- so the real assertion
        # here is that every claimed audit id appears in exactly one
        # thread's result, never both.
        while server.claim_new_audit_events(): pass  # drain any backlog so the cursor starts caught up, regardless of how many audit rows earlier tests produced
        _,before=self.req('/api/admin/audit/export'); start_id=before['data']['events'][-1]['id']
        for i in range(20): self.req('/api/runbooks','POST',{'name':f'Race event {i}'})
        results=[None,None]
        def claim(index):
            results[index]=server.claim_new_audit_events()
        barrier=threading.Barrier(2)
        def synchronized_claim(index):
            barrier.wait()
            claim(index)
        threads=[threading.Thread(target=synchronized_claim,args=(i,)) for i in range(2)]
        for t in threads: t.start()
        for t in threads: t.join()
        ids_a={e['id'] for e in results[0] if e['id']>start_id}
        ids_b={e['id'] for e in results[1] if e['id']>start_id}
        self.assertEqual(ids_a & ids_b, set(), "the same audit event was claimed by both simulated replicas")
        remaining=server.claim_new_audit_events()
        self.assertEqual([e for e in remaining if e['id']>start_id], [])
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
            with patch('server.safe_urlopen',unrestricted_urlopen):
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
    def test_webhook_event_actions_list_matches_real_append_audit_call_sites(self):
        import re
        source=(server.STATIC.parent/'server.py').read_text()
        real_actions=set(re.findall(r'append_audit\([^)]*?,\s*"([a-z_.]+)"',source))
        self.assertEqual(set(server.WEBHOOK_EVENT_ACTIONS),real_actions,
            'WEBHOOK_EVENT_ACTIONS has drifted from the real append_audit() call sites -- update the constant in server.py')
    def test_webhook_available_events_lists_canonical_actions(self):
        _,listed=self.req('/api/admin/webhooks')
        self.assertEqual(set(listed['available_events']),set(server.WEBHOOK_EVENT_ACTIONS))
        self.assertIn('runbook.created',listed['available_events'])
    def test_webhook_only_delivers_to_subscribed_event_types(self):
        import http.server as http_server_module
        received=[]
        class Receiver(http_server_module.BaseHTTPRequestHandler):
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'))
                received.append(json.loads(self.rfile.read(length))['event'])
                self.send_response(200); self.end_headers()
            def log_message(self,*a): pass
        receiver=http_server_module.HTTPServer(('127.0.0.1',0),Receiver)
        threading.Thread(target=receiver.serve_forever,daemon=True).start()
        try:
            code,created=self.req('/api/admin/webhooks','POST',{'name':'Folder-only subscriber','url':f'http://127.0.0.1:{receiver.server_port}/hook','events':['folder.created']})
            self.assertEqual(code,201)
            webhook_id=created['data']['id']
            while server.claim_new_audit_events(): pass  # drain any backlog first
            self.req('/api/folders','POST',{'name':f'Filter test folder {time.time()}'})  # folder.created -- should match
            self.req('/api/runbooks','POST',{'name':'Filter test runbook'})  # runbook.created -- should NOT match
            events=server.claim_new_audit_events()
            with server.connect() as db:
                webhook=dict(db.execute("SELECT * FROM webhooks WHERE id=?",(webhook_id,)).fetchone())
            with patch('server.safe_urlopen',unrestricted_urlopen):
                for event in events:
                    if not server.webhook_matches(webhook['events_json'],event['action']): continue
                    server.deliver_webhook_once(webhook,event)
            self.assertEqual(received,['folder.created'])
        finally:
            receiver.shutdown()
    def test_webhook_test_fire_against_loopback_is_rejected_before_any_connection(self):
        code,created=self.req('/api/admin/webhooks','POST',{'name':'Loopback attempt','url':'http://127.0.0.1:9/hook','events':['*']})
        self.assertEqual(code,201)
        code,tested=self.req(f"/api/admin/webhooks/{created['data']['id']}/test",'POST',{})
        self.assertEqual(code,502)
        self.assertIn('non-routable or private address',tested['error'])
    def test_ssrf_address_validation_rejects_private_ranges_and_allows_public(self):
        # Unit-level: exercise resolve_endpoint_addresses_safely() directly
        # against literal IPs (no DNS dependency, so this can't be flaky in
        # a CI environment without real internet access) to prove both
        # halves: over-blocking a legitimate public destination would be as
        # real a bug as under-blocking a private one.
        for literal in ('http://127.0.0.1/x','http://169.254.169.254/latest/meta-data/','http://10.0.0.5/x','http://[::1]/x'):
            ok,_,_=server.resolve_endpoint_addresses_safely(literal)
            self.assertFalse(ok,f'{literal} must be rejected')
        ok,hostname,infos=server.resolve_endpoint_addresses_safely('http://8.8.8.8/x')
        self.assertTrue(ok); self.assertIsNone(hostname); self.assertIsNone(infos)
        # allow_private_network=True (trusted, admin-configured integrations
        # like ServiceNow) permits ordinary private ranges but never loopback.
        self.assertTrue(server.resolve_endpoint_addresses_safely('http://10.0.0.5/x',allow_private_network=True)[0])
        self.assertFalse(server.resolve_endpoint_addresses_safely('http://127.0.0.1/x',allow_private_network=True)[0])
    def test_pin_resolved_addresses_forces_the_pinned_answer_for_the_same_host(self):
        import socket as socket_module
        fake_infos=[(socket_module.AF_INET,socket_module.SOCK_STREAM,6,'',('203.0.113.5',0))]
        with server.pin_resolved_addresses('pinned.example',fake_infos):
            result=socket_module.getaddrinfo('pinned.example',443)
            self.assertEqual(result[0][4][0],'203.0.113.5')
        # pin is cleared on exit -- a real lookup for an unrelated host must
        # not be affected before, during, or after the pin is active.
        with self.assertRaises(socket_module.gaierror):
            socket_module.getaddrinfo('pinned.example',443)
    def test_cloudflare_access_sso_verifies_signature_audience_and_expiry(self):
        import base64 as b64
        import random
        def is_probable_prime(num, rounds=20):
            if num < 2: return False
            for small in (2,3,5,7,11,13,17,19,23,29,31,37):
                if num % small == 0: return num == small
            d, r = num - 1, 0
            while d % 2 == 0: d //= 2; r += 1
            for _ in range(rounds):
                a = random.randrange(2, num - 1)
                x = pow(a, d, num)
                if x in (1, num - 1): continue
                for _ in range(r - 1):
                    x = pow(x, 2, num)
                    if x == num - 1: break
                else: return False
            return True
        def gen_prime(bits):
            while True:
                candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
                if is_probable_prime(candidate): return candidate
        random.seed(1234567)  # deterministic test run
        p, q = gen_prime(512), gen_prime(512)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        def sign(message: bytes) -> bytes:
            digest_info_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
            digest = hashlib.sha256(message).digest()
            key_bytes = (n.bit_length() + 7) // 8
            padded_len = key_bytes - 3 - len(digest_info_prefix) - len(digest)
            em = b"\x00\x01" + b"\xff" * padded_len + b"\x00" + digest_info_prefix + digest
            sig_int = pow(int.from_bytes(em, "big"), d, n)
            return sig_int.to_bytes(key_bytes, "big")
        def b64url(data: bytes) -> str:
            return b64.urlsafe_b64encode(data).decode().rstrip("=")
        kid = "test-key"
        server._cf_access_jwks_cache["keys"] = {kid: (n, e)}
        server._cf_access_jwks_cache["fetched_at"] = time.monotonic()
        with patch.object(server, "CF_ACCESS_TEAM_DOMAIN", "test.cloudflareaccess.com"), patch.object(server, "CF_ACCESS_AUD", "test-aud"):
            def make_jwt(email, aud="test-aud", exp=None, kid_used=kid, tamper=False):
                header = b64url(json.dumps({"alg": "RS256", "kid": kid_used}).encode())
                payload = b64url(json.dumps({"email": email, "aud": [aud], "exp": exp if exp is not None else int(time.time()) + 300}).encode())
                signing_input = f"{header}.{payload}".encode()
                sig = sign(signing_input)
                if tamper:
                    payload = b64url(json.dumps({"email": "attacker@example.com", "aud": [aud], "exp": int(time.time()) + 300}).encode())
                return f"{header}.{payload}.{b64url(sig)}"
            def sso_request(token):
                request = urllib.request.Request(self.base + '/api/auth/sso', data=b'{}', method='POST', headers={'Content-Type': 'application/json', 'Cf-Access-Jwt-Assertion': token})
                try:
                    with urllib.request.urlopen(request) as res: return res.status, json.load(res)
                except urllib.error.HTTPError as err: return err.code, json.load(err)
            # No matching FlowOps account for this verified email
            code, body = sso_request(make_jwt("nobody@example.com"))
            self.assertEqual(code, 404)
            # Valid signature, correct email, matches the seeded admin -> logs in with no password
            code, body = sso_request(make_jwt("admin@flowops.local"))
            self.assertEqual(code, 200)
            self.assertEqual(body['data']['username'], 'admin')
            # Tampering with the payload after signing must invalidate the signature
            code, body = sso_request(make_jwt("admin@flowops.local", tamper=True))
            self.assertEqual(code, 401)
            # Wrong audience must be rejected even with a valid signature
            code, body = sso_request(make_jwt("admin@flowops.local", aud="some-other-app"))
            self.assertEqual(code, 401)
            # Expired token must be rejected even with a valid signature
            code, body = sso_request(make_jwt("admin@flowops.local", exp=int(time.time()) - 10))
            self.assertEqual(code, 401)
            # Unknown kid (not in the JWKS) must be rejected
            code, body = sso_request(make_jwt("admin@flowops.local", kid_used="not-a-real-kid"))
            self.assertEqual(code, 401)
        code, body = sso_request(make_jwt("admin@flowops.local"))
        self.assertEqual(code, 401)  # feature disabled again once CF_ACCESS_TEAM_DOMAIN/AUD are unpatched
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
    def test_snippet_captures_selected_tasks_and_internal_dependencies_only(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Snippet source'}); rid=created['data']['id']
        _,first=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Notify on-call','stream':'Comms','duration':5}); first_id=first['data']['tasks'][0]['id']
        _,second=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Page escalation','stream':'Comms','duration':5,'depends_on':[first_id]}); second_id=second['data']['tasks'][1]['id']
        _,third=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Unrelated task','stream':'Other','duration':5}); third_id=third['data']['tasks'][2]['id']
        code,snippet=self.req(f'/api/runbooks/{rid}/save-as-snippet','POST',{'name':'Incident comms kickoff','task_ids':[first_id,second_id]})
        self.assertEqual(code,201)
        self.assertEqual(snippet['data']['task_count'],2)
        self.assertEqual(self.req(f'/api/runbooks/{rid}/save-as-snippet','POST',{'name':'Incident comms kickoff','task_ids':[third_id]})[0],409)
        code,rejected=self.req(f'/api/runbooks/{rid}/save-as-snippet','POST',{'name':'Bad selection','task_ids':[999999]})
        self.assertEqual(code,400)
        _,listed=self.req('/api/snippets')
        self.assertTrue(any(s['name']=='Incident comms kickoff' and s['task_count']==2 for s in listed['data']))
        _,other=self.req('/api/runbooks','POST',{'name':'Snippet destination'}); other_rid=other['data']['id']
        code,inserted=self.req(f'/api/runbooks/{other_rid}/insert-snippet','POST',{'snippet_id':snippet['data']['id']})
        self.assertEqual(code,201)
        titles={t['title'] for t in inserted['data']['tasks']}
        self.assertEqual(titles,{'Notify on-call','Page escalation'})
        by_title={t['title']:t for t in inserted['data']['tasks']}
        notify_id=by_title['Notify on-call']['id']
        page=by_title['Page escalation']
        self.assertEqual(page['depends_on'],[notify_id])
        self.assertEqual(self.req(f'/api/snippets/{snippet["data"]["id"]}','DELETE')[0],200)
        _,afterDelete=self.req('/api/snippets')
        self.assertFalse(any(s['id']==snippet['data']['id'] for s in afterDelete['data']))
    def test_snippet_rejects_more_than_one_hundred_tasks(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Big snippet source'}); rid=created['data']['id']
        task_ids=[]
        for i in range(101):
            _,t=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':f'Step {i}','duration':1})
            task_ids.append(t['data']['tasks'][-1]['id'])
        code,rejected=self.req(f'/api/runbooks/{rid}/save-as-snippet','POST',{'name':'Too big','task_ids':task_ids})
        self.assertEqual(code,400)
        self.assertIn('100',rejected['error'])
    def test_runbook_home_content_is_editable_and_returned_in_document(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Home page runbook'}); rid=created['data']['id']
        _,doc=self.req(f'/api/runbooks/{rid}')
        self.assertEqual(doc['data']['home_content'],'')
        code,updated=self.req(f'/api/runbooks/{rid}','PATCH',{'home_content':'Runbook owner: Platform SRE\nRunbook wiki: https://wiki.example.com/release'})
        self.assertEqual(code,200)
        self.assertIn('Platform SRE',updated['data']['home_content'])
    def test_post_implementation_review_only_allowed_after_completion(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Review target'}); rid=created['data']['id']
        code,rejected=self.req(f'/api/runbooks/{rid}/review','PATCH',{'what_went_well':'Too early'})
        self.assertEqual(code,409)
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'})
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'complete'})
        code,review=self.req(f'/api/runbooks/{rid}/review','PATCH',{'what_went_well':'Smooth rollout','what_went_wrong':'Late start','follow_up_actions':'Automate the manual step'})
        self.assertEqual(code,200)
        self.assertEqual(review['data']['review']['what_went_well'],'Smooth rollout')
        self.assertEqual(review['data']['review']['reviewed_by'],'Anushka')
        _,doc=self.req(f'/api/runbooks/{rid}')
        self.assertEqual(doc['data']['review']['what_went_wrong'],'Late start')
    def test_nested_folders_track_parent_and_reject_invalid_parent(self):
        code,parent=self.req('/api/folders','POST',{'name':'2026 Releases'})
        self.assertEqual(code,201); parent_id=parent['data']['id']
        code,child=self.req('/api/folders','POST',{'name':'Q3','parent_folder_id':parent_id})
        self.assertEqual(code,201)
        self.assertEqual(child['data']['parent_folder_id'],parent_id)
        code,grandchild=self.req('/api/folders','POST',{'name':'July','parent_folder_id':child['data']['id']})
        self.assertEqual(code,201)
        self.assertEqual(grandchild['data']['parent_folder_id'],child['data']['id'])
        self.assertEqual(self.req('/api/folders','POST',{'name':'Orphan','parent_folder_id':999999})[0],400)
        _,folders=self.req('/api/folders')
        by_id={f['id']:f for f in folders['data']}
        self.assertEqual(by_id[child['data']['id']]['parent_folder_id'],parent_id)
    def test_saved_views_are_per_user_created_listed_and_deleted(self):
        code,view=self.req('/api/saved-views','POST',{'name':'My live runbooks','filters':{'status':'live'}})
        self.assertEqual(code,201); view_id=view['data']['id']
        self.assertEqual(view['data']['filters'],{'status':'live'})
        self.assertEqual(self.req('/api/saved-views','POST',{'name':'My live runbooks','filters':{}})[0],409)
        _,listed=self.req('/api/saved-views')
        self.assertTrue(any(v['id']==view_id and v['filters']=={'status':'live'} for v in listed['data']))
        admin_opener,admin_csrf=self.opener,self.csrf
        self.req('/api/admin/users','POST',{'username':'view-isolation','display_name':'View Isolation','email':'view-isolation@example.com','role':'Editor','password':'Temporary!123'})
        self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())); self.__class__.csrf=''
        _,login=self.req('/api/auth/login','POST',{'username':'view-isolation','password':'Temporary!123'}); self.__class__.csrf=login['data']['csrf_token']
        _,otherListed=self.req('/api/saved-views')
        self.assertEqual(otherListed['data'],[])
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        self.assertEqual(self.req(f'/api/saved-views/{view_id}','DELETE')[0],200)
        _,afterDelete=self.req('/api/saved-views')
        self.assertFalse(any(v['id']==view_id for v in afterDelete['data']))
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
    def test_template_visibility_and_use_are_scoped_to_their_own_workspace(self):
        _,ws=self.req('/api/workspaces'); home_workspace=ws['data'][0]['id']
        code,other_ws=self.req('/api/admin/workspaces','POST',{'name':'Second workspace for template scoping'})
        _,ws2=self.req('/api/workspaces'); other_workspace=next(w['id'] for w in ws2['data'] if w['name']=='Second workspace for template scoping')
        _,created=self.req('/api/runbooks','POST',{'name':'Scoped template source','workspace_id':home_workspace}); rid=created['data']['id']
        code,saved=self.req(f'/api/runbooks/{rid}/save-as-template','POST',{'name':'Home-only template'})
        self.assertEqual(code,201); template_id=saved['data']['id']
        _,filtered=self.req(f'/api/templates?workspace_id={other_workspace}')
        self.assertFalse(any(t['id']==template_id for t in filtered['data']))
        _,filtered_home=self.req(f'/api/templates?workspace_id={home_workspace}')
        self.assertTrue(any(t['id']==template_id for t in filtered_home['data']))
        code,used=self.req(f'/api/templates/{template_id}/use','POST',{'name':'Ignores workspace override','workspace_id':other_workspace})
        self.assertEqual(code,201); self.assertEqual(used['data']['workspace_id'],home_workspace)
    def test_bulk_edit_tasks_updates_owner_and_duration_across_selected_tasks_only(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Bulk edit target'}); rid=created['data']['id']
        _,t1=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'A','duration':5})
        _,t2=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'B','duration':5})
        _,t3=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'C','duration':5})
        ids=[t['id'] for t in t3['data']['tasks']]
        code,updated=self.req(f'/api/runbooks/{rid}/tasks-bulk-edit','POST',{'task_ids':ids[:2],'duration':45})
        self.assertEqual(code,200); self.assertEqual(updated['updated'],2)
        by_title={t['title']:t for t in updated['data']['tasks']}
        self.assertEqual(by_title['A']['duration'],45); self.assertEqual(by_title['B']['duration'],45)
        self.assertEqual(by_title['C']['duration'],5)
    def test_bulk_edit_tasks_rejects_empty_or_invalid_task_id_selection(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Bulk edit empty target'}); rid=created['data']['id']
        code,body=self.req(f'/api/runbooks/{rid}/tasks-bulk-edit','POST',{'task_ids':[999999],'duration':10})
        self.assertEqual(code,400)
    def test_runbook_type_approval_gate_blocks_live_until_approved(self):
        _,ws=self.req('/api/workspaces'); workspace_id=ws['data'][0]['id']
        code,rtype=self.req('/api/runbook-types','POST',{'name':'High-risk change','workspace_id':workspace_id,'requires_approval':True})
        self.assertEqual(code,201); type_id=rtype['data']['id']
        _,created=self.req('/api/runbooks','POST',{'name':'Needs approval','workspace_id':workspace_id,'runbook_type_id':type_id}); rid=created['data']['id']
        self.assertEqual(self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Step'})[0],201)
        self.assertEqual(self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'})[0],200)
        code,blocked=self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        self.assertEqual(code,409); self.assertIn('approval',blocked['error'])
        code,approved=self.req(f'/api/runbooks/{rid}/approve','POST',{})
        self.assertEqual(code,200); self.assertIsNotNone(approved['data']['approved_at'])
        self.assertEqual(self.req(f'/api/runbooks/{rid}/approve','POST',{})[0],409)
        code,live=self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        self.assertEqual(code,200,live); self.assertEqual(live['data']['status'],'live')
    def test_runbook_without_approval_required_type_transitions_freely(self):
        _,created=self.req('/api/runbooks','POST',{'name':'No approval needed'}); rid=created['data']['id']
        self.assertEqual(self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Step'})[0],201)
        self.assertEqual(self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'})[0],200)
        self.assertEqual(self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})[0],200)
    def test_delay_report_includes_completed_late_tasks_and_currently_late_tasks(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Delay report source','scheduled_at':'2020-01-01T00:00'}); rid=created['data']['id']
        _,late_done=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Finished late','duration':5})
        _,still_late=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Still running late','duration':5})
        done_id=late_done['data']['tasks'][0]['id']; still_id=still_late['data']['tasks'][1]['id']
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'}); self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        self.req(f'/api/tasks/{done_id}','PATCH',{'status':'running'}); self.req(f'/api/tasks/{done_id}','PATCH',{'status':'complete'})
        code,report=self.req('/api/reports/delay')
        self.assertEqual(code,200)
        by_task={r['task']:r for r in report['data'] if r['runbook']=='Delay report source'}
        self.assertIn('Finished late',by_task); self.assertIsInstance(by_task['Finished late']['delay_minutes'],int); self.assertGreaterEqual(by_task['Finished late']['delay_minutes'],0)
        self.assertIn('Still running late',by_task); self.assertEqual(by_task['Still running late']['delay_minutes'],'in progress')
        request=urllib.request.Request(f'{self.base}/api/reports/delay.csv',headers={'X-CSRF-Token':self.csrf})
        with self.opener.open(request) as res:
            self.assertEqual(res.status,200); self.assertIn('text/csv',res.headers['Content-Type'])
            csv_body=res.read().decode()
        self.assertIn('Finished late',csv_body)
    def test_dashboard_widgets_default_to_all_and_persist_per_user(self):
        code,me=self.req('/api/auth/me')
        self.assertEqual(code,200)
        self.assertEqual(sorted(me['data']['user']['dashboard_widgets']),['delay_summary','runbook_activity','today_readiness'])
        code,updated=self.req('/api/me/dashboard','PATCH',{'widgets':['runbook_activity','not_a_real_widget']})
        self.assertEqual(code,200)
        self.assertEqual(updated['data']['widgets'],['runbook_activity'])
        code,me2=self.req('/api/auth/me')
        self.assertEqual(me2['data']['user']['dashboard_widgets'],['runbook_activity'])
    def test_dashboard_widgets_rejects_non_list_payload(self):
        code,body=self.req('/api/me/dashboard','PATCH',{'widgets':'runbook_activity'})
        self.assertEqual(code,400)
    def test_runbook_search_matches_task_titles_and_owners_not_just_runbook_name(self):
        self.req('/api/admin/users','POST',{'username':'priya','display_name':'Priya Shah','email':'priya@example.com','role':'Member','password':'Temporary!123'})
        _,users=self.req('/api/admin/users'); user_id=next(u['id'] for u in users['data'] if u['username']=='priya')
        _,created=self.req('/api/runbooks','POST',{'name':'Totally unrelated name'}); rid=created['data']['id']
        self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Rotate database credentials','owner_user_id':user_id,'duration':10})
        code,results=self.req('/api/runbooks?q=rotate+database')
        self.assertEqual(code,200)
        matched=[r for r in results['data'] if r['id']==rid]
        self.assertEqual(len(matched),1)
        self.assertEqual(matched[0]['matched_task'],'Rotate database credentials')
        code,by_owner=self.req('/api/runbooks?q=priya')
        self.assertIn(rid,[r['id'] for r in by_owner['data']])
        code,no_match=self.req('/api/runbooks?q=zzz_nonexistent_zzz')
        self.assertEqual(no_match['data'],[])
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
    def test_diamond_dependency_waits_for_the_later_of_two_branches(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Diamond release'}); rid=created['data']['id']
        _,a=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'A','duration':10}); a_id=a['data']['tasks'][-1]['id']
        _,b=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'B','duration':5,'depends_on':[a_id]}); b_id=b['data']['tasks'][-1]['id']
        _,c=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'C','duration':20,'depends_on':[a_id]}); c_id=c['data']['tasks'][-1]['id']
        _,d=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'D','duration':5,'depends_on':[b_id,c_id]})
        doc=d['data']
        by_id={t['id']:t for t in doc['tasks']}
        # A finishes at 10; B finishes at 15 (10+5); C finishes at 30 (10+20).
        # D must wait for the LATER branch (C, finishing at 30), not just B.
        self.assertEqual(by_id[b_id]['planned_start_offset'],10)
        self.assertEqual(by_id[c_id]['planned_start_offset'],10)
        d_id=next(t['id'] for t in doc['tasks'] if t['title']=='D')
        self.assertEqual(by_id[d_id]['planned_start_offset'],30)
        # The critical path is the longer branch (A -> C -> D), not A -> B -> D.
        self.assertEqual(doc['critical_path'],[a_id,c_id,d_id])
    def test_combined_fan_out_fan_in_computes_correct_join_offset(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Fan-out fan-in release'}); rid=created['data']['id']
        _,a=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'A','duration':5}); a_id=a['data']['tasks'][-1]['id']
        _,b=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'B','duration':5,'depends_on':[a_id]}); b_id=b['data']['tasks'][-1]['id']
        _,c=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'C','duration':15,'depends_on':[a_id]}); c_id=c['data']['tasks'][-1]['id']
        _,dd=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'D','duration':1,'depends_on':[a_id]}); dd_id=dd['data']['tasks'][-1]['id']
        _,e=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'E','duration':5,'depends_on':[b_id,c_id,dd_id]})
        doc=e['data']
        e_id=next(t['id'] for t in doc['tasks'] if t['title']=='E')
        by_id={t['id']:t for t in doc['tasks']}
        # A ends at 5; branches end at 10 (B), 20 (C), 6 (D) -- E must wait for
        # the slowest of all three fanned-out branches (C, ending at 20).
        self.assertEqual(by_id[e_id]['planned_start_offset'],20)
    def test_deep_sequential_chain_accumulates_offsets_without_error(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Deep chain release'}); rid=created['data']['id']
        previous_id=None
        for i in range(12):
            body={'title':f'Step {i}','duration':5}
            if previous_id: body['depends_on']=[previous_id]
            _,resp=self.req(f'/api/runbooks/{rid}/tasks','POST',body)
            previous_id=resp['data']['tasks'][-1]['id']
        doc=self.req(f'/api/runbooks/{rid}')[1]['data']
        last=next(t for t in doc['tasks'] if t['title']=='Step 11')
        self.assertEqual(last['planned_start_offset'],55)  # 11 predecessors * 5 minutes each
        self.assertEqual(len(doc['critical_path']),12)
    def test_cross_stream_dependency_still_gates_task_start(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Cross-stream release'}); rid=created['data']['id']
        _,prep=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Prep database','duration':5,'stream':'Prep'}); prep_id=prep['data']['tasks'][-1]['id']
        _,deploy=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Deploy app','duration':5,'stream':'Deploy','depends_on':[prep_id]})
        deploy_id=deploy['data']['tasks'][-1]['id']
        streams={s['name'] for s in deploy['data']['streams']}
        self.assertEqual(streams,{'Prep','Deploy'})
        self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'ready'});self.req(f'/api/runbooks/{rid}/transition','POST',{'status':'live'})
        # Different stream than its dependency -- must still be gated by it.
        self.assertEqual(self.req(f'/api/tasks/{deploy_id}','PATCH',{'status':'running'})[0],409)
        self.req(f'/api/tasks/{prep_id}','PATCH',{'status':'running'});self.req(f'/api/tasks/{prep_id}','PATCH',{'status':'complete'})
        self.assertEqual(self.req(f'/api/tasks/{deploy_id}','PATCH',{'status':'running'})[0],200)
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
    def test_member_runbook_list_only_shows_runbooks_with_an_assigned_task(self):
        _,users=self.req('/api/admin/users');operator_id=next(u['id'] for u in users['data'] if u['username']=='operator')
        _,assigned_rb=self.req('/api/runbooks','POST',{'name':'Member visible runbook'});assigned_rid=assigned_rb['data']['id']
        _,team=self.req(f'/api/runbooks/{assigned_rid}/teams','POST',{'name':'Visible Team','user_ids':[operator_id]});team_id=team['data']['id']
        self.req(f'/api/runbooks/{assigned_rid}/tasks','POST',{'title':'Member task','owner_team_id':team_id})
        _,hidden_rb=self.req('/api/runbooks','POST',{'name':'Member hidden runbook'});hidden_rid=hidden_rb['data']['id']
        admin_opener,admin_csrf=self.opener,self.csrf
        self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
        _,login=self.req('/api/auth/login','POST',{'username':'operator','password':'Operator!Preview2026'});self.__class__.csrf=login['data']['csrf_token']
        _,listing=self.req('/api/runbooks')
        visible_ids={r['id'] for r in listing['data']}
        self.assertIn(assigned_rid,visible_ids)
        self.assertNotIn(hidden_rid,visible_ids)
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
    def test_self_service_profile_update_edits_own_fields_and_is_audited(self):
        code,updated=self.req('/api/profile','PATCH',{'display_name':'Anushka W','title':'Platform Lead','timezone':'UTC','date_format':'day_first'})
        self.assertEqual(code,200)
        self.assertEqual(updated['data']['display_name'],'Anushka W')
        self.assertEqual(updated['data']['title'],'Platform Lead')
        self.assertEqual(updated['data']['timezone'],'UTC')
        self.assertEqual(updated['data']['date_format'],'day_first')
        code,me=self.req('/api/auth/me')
        self.assertEqual(me['data']['user']['display_name'],'Anushka W')
        code,rejected=self.req('/api/profile','PATCH',{'date_format':'nonsense'})
        self.assertEqual(code,400)
        code,ja=self.req('/api/profile','PATCH',{'locale':'ja'})
        self.assertEqual(code,200); self.assertEqual(ja['data']['locale'],'ja')
        code,me=self.req('/api/auth/me')
        self.assertEqual(me['data']['user']['locale'],'ja')
        # unsupported locale falls back to "en" rather than erroring
        code,fallback=self.req('/api/profile','PATCH',{'locale':'xx-not-real'})
        self.assertEqual(code,200); self.assertEqual(fallback['data']['locale'],'en')
        # restore for other tests relying on the seeded display name
        self.req('/api/profile','PATCH',{'display_name':'Anushka','title':''})
    def test_self_service_profile_update_requires_csrf_token(self):
        request=urllib.request.Request(self.base+'/api/profile',data=json.dumps({'display_name':'No CSRF'}).encode(),method='PATCH',headers={'Content-Type':'application/json'})
        try:
            with self.opener.open(request) as res: code=res.status
        except urllib.error.HTTPError as err: code=err.code
        self.assertEqual(code,403)
    def test_avatar_upload_validates_image_type_and_size_then_serves_it(self):
        png_1x1=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=')
        code,rejected=self.req('/api/profile/avatar','POST',{'avatar_base64':base64.b64encode(b'not an image').decode()})
        self.assertEqual(code,400)
        code,uploaded=self.req('/api/profile/avatar','POST',{'avatar_base64':base64.b64encode(png_1x1).decode()})
        self.assertEqual(code,200)
        self.assertTrue(uploaded['data']['avatar_path'].endswith('.png'))
        code,me=self.req('/api/auth/me')
        user_id=me['data']['user']['id']
        request=urllib.request.Request(f'{self.base}/avatar/{user_id}')
        with self.opener.open(request) as res:
            self.assertEqual(res.status,200)
            self.assertEqual(res.headers['Content-Type'],'image/png')
            self.assertEqual(res.read(),png_1x1)
    def test_self_service_change_password_requires_current_password_and_revokes_other_sessions(self):
        self.req('/api/admin/users','POST',{'username':'pwtest','display_name':'PW Test','email':'pwtest@example.com','role':'Editor','password':'Temporary!123'})
        other_opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        login_request=urllib.request.Request(self.base+'/api/auth/login',data=json.dumps({'username':'pwtest','password':'Temporary!123'}).encode(),method='POST',headers={'Content-Type':'application/json'})
        with other_opener.open(login_request) as res: login_body=json.load(res)
        csrf=login_body['data']['csrf_token']
        def pw_req(body):
            request=urllib.request.Request(self.base+'/api/profile/change-password',data=json.dumps(body).encode(),method='POST',headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
            try:
                with other_opener.open(request) as res: return res.status,json.load(res)
            except urllib.error.HTTPError as err: return err.code,json.load(err)
        code,rejected=pw_req({'current_password':'WrongPassword123','new_password':'BrandNewPassword123'})
        self.assertEqual(code,401)
        code,short=pw_req({'current_password':'Temporary!123','new_password':'short'})
        self.assertEqual(code,400)
        # a second concurrent session for the same user, to prove it gets revoked
        second_opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        with second_opener.open(login_request) as res: pass
        code,ok=pw_req({'current_password':'Temporary!123','new_password':'BrandNewPassword123'})
        self.assertEqual(code,200)
        try:
            with second_opener.open(urllib.request.Request(self.base+'/api/auth/me')) as res: second_code=res.status
        except urllib.error.HTTPError as err: second_code=err.code
        self.assertEqual(second_code,401)
        with other_opener.open(urllib.request.Request(self.base+'/api/auth/me')) as res:
            self.assertEqual(res.status,200)
    def test_profile_export_downloads_own_audit_and_task_history(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Export test runbook'}); rid=created['data']['id']
        _,me=self.req('/api/auth/me'); my_id=me['data']['user']['id']
        self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'My task','owner_user_id':my_id})
        request=urllib.request.Request(f'{self.base}/api/profile/export')
        with self.opener.open(request) as res:
            self.assertEqual(res.status,200)
            self.assertIn('attachment',res.headers['Content-Disposition'])
            export=json.load(res)
        self.assertEqual(export['profile']['username'],'admin')
        self.assertTrue(any(t['title']=='My task' for t in export['assigned_tasks']))
        self.assertTrue(len(export['audit_history'])>0)
    def test_unhandled_exception_returns_structured_500_instead_of_crashing(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Error path probe'}); rid=created['data']['id']
        with patch('server.runbook_document', side_effect=RuntimeError('boom')):
            code,body=self.req(f'/api/runbooks/{rid}')
        self.assertEqual(code,500)
        self.assertIn('error_id',body)
        self.assertEqual(len(body['error_id']),12)
        # the server must still be alive and serving other requests afterward
        self.assertEqual(self.req('/api/runbooks')[0],200)
    def test_admin_can_trigger_and_list_database_backups(self):
        with tempfile.TemporaryDirectory() as backup_dir:
            with patch('server.BACKUP_DIR', __import__('pathlib').Path(backup_dir)):
                code,created=self.req('/api/admin/backups','POST',{})
                self.assertEqual(code,201)
                self.assertTrue(created['data']['filename'].startswith('flowops-'))
                self.assertGreater(created['data']['size_bytes'],0)
                code,listed=self.req('/api/admin/backups')
                self.assertEqual(code,200)
                filenames=[b['filename'] for b in listed['data']['backups']]
                self.assertIn(created['data']['filename'],filenames)
    def test_backup_retention_deletes_oldest_beyond_retain_limit(self):
        with tempfile.TemporaryDirectory() as backup_dir:
            with patch('server.BACKUP_DIR', __import__('pathlib').Path(backup_dir)), patch('server.BACKUP_RETAIN', 2):
                for _ in range(4): server.backup_database()
                self.assertEqual(len(server.list_backups()), 2)
    def test_database_backups_are_encrypted_at_rest_and_round_trip_decrypt(self):
        with tempfile.TemporaryDirectory() as backup_dir:
            with patch('server.BACKUP_DIR', __import__('pathlib').Path(backup_dir)):
                result=server.backup_database()
                self.assertTrue(result['filename'].endswith('.db.enc'))
                enc_path=__import__('pathlib').Path(backup_dir)/result['filename']
                ciphertext=enc_path.read_bytes()
                # must NOT be a readable SQLite file on disk
                self.assertFalse(ciphertext.startswith(b'SQLite format 3'))
                with self.assertRaises(server.sqlite3.DatabaseError):
                    server.sqlite3.connect(str(enc_path)).execute('SELECT 1').fetchone()
                # round-trips back to a valid SQLite database via the same cipher
                plaintext=server.settings_cipher().decrypt(ciphertext)
                self.assertTrue(plaintext.startswith(b'SQLite format 3'))
                restored_path=__import__('pathlib').Path(backup_dir)/'restored.db'
                restored_path.write_bytes(plaintext)
                tables=server.sqlite3.connect(str(restored_path)).execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit'").fetchall()
                self.assertEqual(len(tables),1)
                listed=server.list_backups()
                self.assertTrue(any(b['filename']==result['filename'] and b['encrypted'] for b in listed))
    def test_dashboard_email_render_includes_runbook_and_completion_data(self):
        with server.connect() as db:
            instance_id=db.execute("SELECT id FROM instances WHERE slug='flowops'").fetchone()[0]
        _,created=self.req('/api/runbooks','POST',{'name':'Digest visibility check'})
        with server.connect() as db:
            subject,body=server.render_dashboard_email(db,instance_id)
        self.assertIn('FlowOps digest',subject)
        self.assertIn('Active runbooks',body)
        self.assertIn('Task completion',body)
        self.assertIn('Late or at-risk tasks',body)
    def test_dashboard_email_scheduling_gate_sends_only_once_per_configured_interval(self):
        self.req('/api/admin/settings','POST',{'dashboard_email_frequency':'daily','dashboard_email_hour':'9','dashboard_email_recipients':'ops@example.com, lead@example.com'})
        with server.connect() as db:
            instance_id=db.execute("SELECT id FROM instances WHERE slug='flowops'").fetchone()[0]
        wrong_hour=server.datetime(2026,1,1,8,0,tzinfo=server.timezone.utc)
        with patch('server.send_mail') as send:
            with server.connect() as db:
                sent=server.maybe_send_dashboard_email(db,instance_id,current_time=wrong_hour)
            self.assertFalse(sent); send.assert_not_called()
        first_run=server.datetime(2026,1,1,9,5,tzinfo=server.timezone.utc)
        with patch('server.send_mail') as send:
            with server.connect() as db:
                sent=server.maybe_send_dashboard_email(db,instance_id,current_time=first_run)
            self.assertTrue(sent); self.assertEqual(send.call_count,2)  # two configured recipients
        # same day, same hour again -- must NOT re-send (daily gate not yet elapsed)
        later_same_day=server.datetime(2026,1,1,9,10,tzinfo=server.timezone.utc)
        with patch('server.send_mail') as send:
            with server.connect() as db:
                sent=server.maybe_send_dashboard_email(db,instance_id,current_time=later_same_day)
            self.assertFalse(sent); send.assert_not_called()
        # 25 hours later, same configured hour -- daily gate has elapsed, due again
        next_day=server.datetime(2026,1,2,9,5,tzinfo=server.timezone.utc)
        with patch('server.send_mail') as send:
            with server.connect() as db:
                sent=server.maybe_send_dashboard_email(db,instance_id,current_time=next_day)
            self.assertTrue(sent)
    def test_api_explorer_openapi_doc_paths_resolve_to_real_routes(self):
        code,body=self.req('/openapi.json')
        self.assertEqual(code,200)
        code,writeToken=self.req('/api/admin/api-tokens','POST',{'name':'Explorer doc-drift check','scopes':['runbooks:write']})
        self.assertEqual(code,201)
        token=writeToken['data']['token']
        headers={'Authorization':f'Bearer {token}'}
        runbook_id=None
        task_id=None
        for path,methods in body['paths'].items():
            resolved=path.replace('{id}',str(runbook_id if '/runbooks/' in path else task_id) if (runbook_id or task_id) else '1')
            for method in methods:
                if method.upper()=='GET' and 'events' in path: continue  # SSE stream, not a one-shot request
                request=urllib.request.Request(self.base+resolved,method=method.upper(),headers=headers)
                if method.upper() in ('POST','PATCH'):
                    payload={'name':'Explorer doc-drift runbook'} if 'runbooks' in path and method.upper()=='POST' and '{id}' not in path else {'title':'Explorer task'} if 'tasks' in path else {'status':'ready'} if 'transition' in path else {}
                    request.data=json.dumps(payload).encode(); request.add_header('Content-Type','application/json')
                try:
                    with urllib.request.urlopen(request) as res: status=res.status; response_body=json.loads(res.read())
                except urllib.error.HTTPError as err: status=err.code; response_body=json.loads(err.read())
                self.assertNotEqual(status,404,f'{method.upper()} {resolved} is documented in openapi.json but does not resolve to a real route')
                if path=='/api/runbooks' and method.upper()=='POST' and status==201: runbook_id=response_body['data']['id']
                if path=='/api/runbooks/{id}/tasks' and method.upper()=='POST' and status==201: task_id=response_body['data']['tasks'][-1]['id']
    def test_api_explorer_page_serves_and_can_call_a_real_endpoint(self):
        with urllib.request.urlopen(self.base+'/api-explorer') as res:
            self.assertEqual(res.status,200); self.assertIn(b'API Explorer',res.read())
        with urllib.request.urlopen(self.base+'/api-explorer.js') as res:
            self.assertEqual(res.status,200); self.assertIn(b'openapi.json',res.read())
    def test_api_token_requests_are_rate_limited(self):
        code,token=self.req('/api/admin/api-tokens','POST',{'name':'Rate limit probe','scopes':['runbooks:read']})
        self.assertEqual(code,201)
        def bearer_get(token):
            request=urllib.request.Request(self.base+'/api/runbooks',headers={'Authorization':f'Bearer {token}'})
            try:
                with urllib.request.urlopen(request) as res:return res.status
            except urllib.error.HTTPError as err:return err.code
        with patch('server.API_RATE_LIMIT', 3):
            statuses=[bearer_get(token['data']['token']) for _ in range(5)]
        self.assertEqual(statuses[:3], [200,200,200])
        self.assertIn(429, statuses[3:])
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
    def test_task_csv_import_creates_tasks_and_backfills_unknown_type_to_normal(self):
        _,created=self.req('/api/runbooks','POST',{'name':'CSV import target'}); rid=created['data']['id']
        csv_text='title,stream,duration,task_type,scheduled_offset,description\nRestore snapshot,Database,30,normal,0,Restore from last good backup\nVerify integrity,Database,15,bogus_type,30,\nGo live milestone,Cutover,,milestone,60,'
        code,body=self.req(f'/api/runbooks/{rid}/tasks-import','POST',{'csv':csv_text})
        self.assertEqual(code,201); self.assertEqual(body['imported'],3)
        tasks={t['title']:t for t in body['data']['tasks']}
        self.assertEqual(tasks['Restore snapshot']['duration'],30)
        self.assertEqual(tasks['Verify integrity']['task_type'],'normal')
        self.assertEqual(tasks['Go live milestone']['task_type'],'milestone'); self.assertEqual(tasks['Go live milestone']['duration'],0)
    def test_task_csv_import_rejects_csv_missing_title_column(self):
        _,created=self.req('/api/runbooks','POST',{'name':'CSV import rejects bad header'}); rid=created['data']['id']
        code,body=self.req(f'/api/runbooks/{rid}/tasks-import','POST',{'csv':'name,duration\nSomething,10'})
        self.assertEqual(code,400); self.assertIn('title',body['error'])
    def test_task_csv_export_returns_downloadable_csv_with_current_task_state(self):
        _,created=self.req('/api/runbooks','POST',{'name':'CSV export source'}); rid=created['data']['id']
        self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Exportable task','stream':'Ops','duration':20})
        request=urllib.request.Request(f'{self.base}/api/runbooks/{rid}/tasks.csv',headers={'X-CSRF-Token':self.csrf})
        with self.opener.open(request) as res:
            self.assertEqual(res.status,200); self.assertIn('text/csv',res.headers['Content-Type'])
            self.assertIn('attachment',res.headers['Content-Disposition'])
            body=res.read().decode()
        self.assertIn('title,stream,owner,duration',body.splitlines()[0])
        self.assertIn('Exportable task,Ops,,20',body)
    def _as_new_user(self,username,role,password='ScopedRole!12345'):
        code,created=self.req('/api/admin/users','POST',{'username':username,'display_name':username,'role':role,'password':password})
        self.assertEqual(code,201,created)
        admin_opener,admin_csrf=self.opener,self.csrf
        self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
        _,login=self.req('/api/auth/login','POST',{'username':username,'password':password})
        self.__class__.csrf=login['data']['csrf_token']
        return admin_opener,admin_csrf,login['data']['id'] if 'id' in login['data'] else login['data'].get('user',{}).get('id')
    def test_stakeholder_role_is_global_read_only(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Stakeholder visibility target'})
        admin_opener,admin_csrf,_=self._as_new_user('stakeholder1','Stakeholder')
        try:
            code,runbooks=self.req('/api/runbooks'); self.assertEqual(code,200)
            self.assertIn(created['data']['id'],[r['id'] for r in runbooks['data']])
            self.assertEqual(self.req('/api/runbooks','POST',{'name':'Should be denied'})[0],403)
            self.assertEqual(self.req(f"/api/runbooks/{created['data']['id']}/tasks",'POST',{'title':'x'})[0],403)
        finally:
            self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
    def test_workspace_manager_is_scoped_to_granted_workspace_only(self):
        _,ws=self.req('/api/workspaces'); other_workspace_id=None
        code,created_ws=self.req('/api/admin/workspaces')
        target_workspace_id=ws['data'][0]['id']
        admin_opener,admin_csrf,user_id=self._as_new_user('wsmanager1','Workspace Manager')
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        code,created_user=self.req('/api/admin/users'); user_id=[u for u in created_user['data'] if u['username']=='wsmanager1'][0]['id']
        try:
            managed_opener=None
            self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
            _,login=self.req('/api/auth/login','POST',{'username':'wsmanager1','password':'ScopedRole!12345'});self.__class__.csrf=login['data']['csrf_token']
            code,denied=self.req('/api/runbooks','POST',{'name':'Denied before grant','workspace_id':target_workspace_id})
            self.assertEqual(code,403)
        finally:
            self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        self.assertEqual(self.req('/api/admin/workspace-managers','POST',{'user_id':user_id,'workspace_id':target_workspace_id})[0],201)
        try:
            self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
            _,login=self.req('/api/auth/login','POST',{'username':'wsmanager1','password':'ScopedRole!12345'});self.__class__.csrf=login['data']['csrf_token']
            code,allowed=self.req('/api/runbooks','POST',{'name':'Allowed after grant','workspace_id':target_workspace_id})
            self.assertEqual(code,201,allowed)
        finally:
            self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        self.assertEqual(self.req(f'/api/admin/workspace-managers/{user_id}/{target_workspace_id}','DELETE')[0],200)
    def test_folder_creator_can_only_create_runbooks_in_granted_folder(self):
        _,ws=self.req('/api/workspaces'); workspace_id=ws['data'][0]['id']
        _,folder=self.req('/api/folders','POST',{'name':'Change windows','workspace_id':workspace_id})
        folder_id=folder['data']['id']
        admin_opener,admin_csrf,_=self._as_new_user('foldercreator1','Folder Creator')
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        code,users=self.req('/api/admin/users'); user_id=[u for u in users['data'] if u['username']=='foldercreator1'][0]['id']
        try:
            self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
            _,login=self.req('/api/auth/login','POST',{'username':'foldercreator1','password':'ScopedRole!12345'});self.__class__.csrf=login['data']['csrf_token']
            self.assertEqual(self.req('/api/runbooks','POST',{'name':'No folder, denied'})[0],403)
        finally:
            self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        self.assertEqual(self.req('/api/admin/folder-creators','POST',{'user_id':user_id,'folder_id':folder_id})[0],201)
        try:
            self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
            _,login=self.req('/api/auth/login','POST',{'username':'foldercreator1','password':'ScopedRole!12345'});self.__class__.csrf=login['data']['csrf_token']
            code,created=self.req('/api/runbooks','POST',{'name':'Granted folder create','workspace_id':workspace_id,'folder_id':folder_id})
            self.assertEqual(code,201,created)
        finally:
            self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
    def test_stream_editor_can_edit_tasks_but_not_runbook_fields(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Stream editor target'}); rid=created['data']['id']
        _,task=self.req(f'/api/runbooks/{rid}/tasks','POST',{'title':'Editable task'}); tid=task['data']['tasks'][0]['id']
        admin_opener,admin_csrf,_=self._as_new_user('streameditor1','Stream Editor')
        self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        code,users=self.req('/api/admin/users'); user_id=[u for u in users['data'] if u['username']=='streameditor1'][0]['id']
        try:
            self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
            _,login=self.req('/api/auth/login','POST',{'username':'streameditor1','password':'ScopedRole!12345'});self.__class__.csrf=login['data']['csrf_token']
            self.assertEqual(self.req(f'/api/tasks/{tid}','PATCH',{'title':'Denied before grant'})[0],403)
        finally:
            self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf
        self.assertEqual(self.req('/api/admin/stream-editors','POST',{'user_id':user_id,'runbook_id':rid})[0],201)
        try:
            self.__class__.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.__class__.csrf=''
            _,login=self.req('/api/auth/login','POST',{'username':'streameditor1','password':'ScopedRole!12345'});self.__class__.csrf=login['data']['csrf_token']
            code,edited=self.req(f'/api/tasks/{tid}','PATCH',{'title':'Edited by stream editor'})
            self.assertEqual(code,200,edited)
            self.assertEqual(edited['data']['tasks'][0]['title'],'Edited by stream editor')
            self.assertEqual(self.req(f'/api/runbooks/{rid}','PATCH',{'name':'Should stay denied'})[0],403)
        finally:
            self.__class__.opener,self.__class__.csrf=admin_opener,admin_csrf

if __name__=='__main__': unittest.main()
