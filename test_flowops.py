import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import http.cookiejar

tmp=tempfile.NamedTemporaryFile(suffix='.db',delete=False); tmp.close()
os.environ['FLOWOPS_DB']=tmp.name
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
    def test_integration_admin_policy_secret_boundary_and_connection_test(self):
        code,saved=self.req('/api/admin/integrations','POST',{'provider':'serviceops','url':'mock://serviceops','enabled':True,'require_approved':True,'sync_on_live':True,'sync_on_complete':True});self.assertEqual(code,200);self.assertTrue(saved['data']['ok'])
        code,connections=self.req('/api/admin/integrations');self.assertEqual(code,200);self.assertEqual(connections['data']['serviceops']['url'],'mock://serviceops');self.assertNotIn('token',connections['data']['serviceops'])
        code,tested=self.req('/api/admin/integrations/test','POST',{'provider':'serviceops'});self.assertEqual(code,200);self.assertTrue(tested['data']['ok'])
        self.assertEqual(self.req('/api/admin/integrations','POST',{'provider':'jenkins','url':'mock://jenkins','token':'must-not-enter-browser'})[0],400)
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
