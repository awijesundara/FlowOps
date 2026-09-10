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
    def test_configurable_audit_retention_purges_old_events_and_keeps_chain_verifiable(self):
        _,created=self.req('/api/runbooks','POST',{'name':'Retention prefix check'})
        with server.connect() as db:
            instance_id=db.execute("SELECT id FROM instances WHERE slug='flowops'").fetchone()[0]
            oldest_id=db.execute("SELECT MIN(id) FROM audit WHERE instance_id=?",(instance_id,)).fetchone()[0]
            old_stamp=(__import__('datetime').datetime.now(__import__('datetime').timezone.utc)-__import__('datetime').timedelta(days=400)).isoformat(timespec='seconds')
            db.execute("UPDATE audit SET created_at=? WHERE id=?",(old_stamp,oldest_id)); db.commit()
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
