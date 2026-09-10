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
