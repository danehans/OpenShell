import json, os, tempfile, time, unittest
from pathlib import Path
from unittest.mock import patch
import codex_driver as c

RUN = '0123456789abcdef0123456789abcdef'
class FakeWire:
    def __init__(self): self.sent, self.events, self.turns, self.fail, self.bad, self.status = [], [], 0, False, False, 'completed'
    def send(self, v, deadline):
        self.sent.append(v)
        if self.fail: raise TimeoutError('unknown send')
        if 'id' not in v: return
        method=v['method']; result={}
        if method=='thread/start': result={'thread':{'id':'original-thread'}}
        if method=='turn/start':
            self.turns+=1; result={'turn':{'id':f'turn-{self.turns}'}}
        self.events.append({'id':v['id'],'result':result})
        if method=='turn/start': self.events.append({'method':'turn/completed','params':{'threadId':'different' if self.bad else 'original-thread','turn':{'id':f'turn-{self.turns}','status':self.status}}})
    def next(self, deadline):
        if not self.events: raise TimeoutError('no terminal')
        return self.events.pop(0)
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'journal';self.j=c.Journal(self.path,RUN,'A',create=True);self.addCleanup(self.j.close);self.addCleanup(self.tmp.cleanup)
    def driver(self):
        w=FakeWire();d=c.Driver(lambda:w,self.j,time.monotonic()+5);d.start();return d,w
    def test_same_process_thread_steps_and_separate_outcome(self):
        d,w=self.driver()
        for step in c.STEPS['A']:
            r=d.step(step);self.assertTrue(r['same_original_thread']);self.assertFalse(r['native_proof']);self.assertFalse(r['billed_usage_verified'])
        self.assertEqual(w.turns,4)
        self.assertTrue(all(v['params']['threadId']=='original-thread' for v in w.sent if v.get('method')=='turn/start'))
        self.assertRaises(c.Refused,d.step,'post-detach')
    def test_input_consumed_before_unknown_send_and_no_relaunch(self):
        d,w=self.driver();w.fail=True
        self.assertRaises(TimeoutError,d.step,'baseline');self.assertIn(b'baseline',self.path.read_bytes())
        self.assertRaises(c.Refused,d.step,'baseline');self.j.close()
        j=c.Journal(self.path,RUN,'A');self.addCleanup(j.close)
        with patch.object(c,'fixed_launch',side_effect=AssertionError('no launch')):
            self.assertRaises(c.Refused,c.Driver,lambda:c.fixed_launch(None,None,None),j,time.monotonic()+5)
    def test_correlation_substitution_refuses_no_retry(self):
        d,w=self.driver();w.bad=True;self.assertRaises(c.Refused,d.step,'baseline');self.assertEqual(w.turns,1);self.assertRaises(c.Refused,d.step,'audit-marker')
    def test_failed_client_outcome_not_native_refusal(self):
        d,w=self.driver();w.status='failed';r=d.step('baseline');self.assertEqual(r['status'],'failed');self.assertFalse(r['native_proof'])
    def test_deadline_prevents_input_effect(self):
        d,w=self.driver();d.deadline=time.monotonic()-1;self.assertRaises(c.Refused,d.step,'baseline');self.assertEqual(w.turns,0)
    def test_approval_requests_and_unrelated_terminal_refuse(self):
        d,w=self.driver();w.events.append({'id':99,'method':'item/tool/call','params':{}});self.assertRaises(c.Refused,d.next)
    def test_journal_original_binding_fifo_and_duplicate_fields(self):
        self.j.close();self.assertRaises(c.Refused,c.Journal,self.path,'f'*32,'A');fifo=Path(self.tmp.name)/'fifo';os.mkfifo(fifo,0o600);self.assertRaises(c.Refused,c.Journal,fifo,RUN,'A');self.assertRaises(c.Refused,c.unique,'{"id":1,"id":2}')
    def test_paid_ledger_initialization_exclusive_and_closed(self):
        p=Path(self.tmp.name)/'paid';c.initialize_paid_ledger(p,RUN,'boot',301000,1000)
        self.assertEqual(json.loads(p.read_text())['requests'],8)
        self.assertRaises(FileExistsError,c.initialize_paid_ledger,p,RUN,'boot',301000,1000)
        self.assertRaises(c.Refused,c.initialize_paid_ledger,p,RUN,'boot',301001,1000)
    def test_pinned_config_no_oauth_websockets_retries_or_host_secret(self):
        import tomllib
        v=tomllib.loads(c.CONFIG);p=v['model_providers']['m1_openai'];self.assertFalse(p['requires_openai_auth']);self.assertFalse(p['supports_websockets']);self.assertEqual(p['request_max_retries'],0);self.assertEqual(p['stream_max_retries'],0);self.assertEqual(v['model'],c.MODEL)
    def test_launch_mark_durable_before_factory(self):
        def fail():
            self.assertIn(b'"launch":true',self.path.read_bytes());raise RuntimeError('factory failed')
        self.assertRaises(RuntimeError,c.Driver,fail,self.j,time.monotonic()+5);self.assertTrue(self.j.started)
    def test_session_closes_original_on_startup_failure_and_after_success(self):
        for fail in (False,True):
            w=FakeWire();w.fail=fail;w.closed=False
            def close(): w.closed=True
            w.close=close
            root=Path(self.tmp.name)/('session-'+str(fail))
            with patch.object(c,'fixed_launch',return_value=w):
                if fail:
                    with self.assertRaises(TimeoutError):
                        with c.original_session(root,RUN,'B','openshell:resolve:public','/opt/m1/native-ca.pem'):pass
                else:
                    with c.original_session(root,RUN,'B','openshell:resolve:public','/opt/m1/native-ca.pem') as d:
                        self.assertEqual(d.step('baseline')['status'],'completed')
            self.assertTrue(w.closed)
            self.assertIn(b'"launch":true',(root/'original-inputs.jsonl').read_bytes())
    def test_real_key_is_refused_without_child_launch(self):
        with patch.object(c.subprocess,'Popen',side_effect=AssertionError('no child')):
            self.assertRaises(c.Refused,c.fixed_launch,Path(self.tmp.name)/'child','not-an-opaque-reference','/opt/m1/native-ca.pem')
if __name__=='__main__': unittest.main(verbosity=2)
