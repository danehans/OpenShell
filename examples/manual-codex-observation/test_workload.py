import json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import workload as w
from codex_driver import Refused
RUN='0123456789abcdef0123456789abcdef'
class Tests(unittest.TestCase):
    def test_original_gate_exact_closed_discrimination(self):
        good={'run':RUN,'actor':'A','ordinal':1,'step':'baseline'}
        self.assertEqual(w.gate_object(json.dumps(good),RUN,'A',1),'baseline')
        for k,v in [('run','f'*32),('actor','B'),('ordinal',2),('step','post-detach'),('extra',True)]:
            bad={**good,k:v};self.assertRaises(Refused,w.gate_object,json.dumps(bad),RUN,'A',1)
    def test_manual_sequence_has_no_automatic_input_and_keeps_original_alive(self):
        class D:
            def __init__(self):self.steps=[]
            def step(self,s):self.steps.append(s);return {'status':'completed','same_original_thread':True}
        d=D();t=[0.0];rows=[]
        def pause(n):t[0]+=n
        def read(path,run,actor,n):return 'baseline' if t[0]>=.1 and n==1 else None
        count=w.sequence(d,RUN,'B',.3,reader=read,clock=lambda:t[0],pause=pause,emit=rows.append)
        self.assertEqual(count,1);self.assertEqual(d.steps,['baseline']);self.assertGreaterEqual(t[0],.3)
        self.assertFalse(rows[0]['native_proof']);self.assertFalse(rows[0]['billed_usage_verified'])
    def test_same_original_driver_receives_all_ordered_steps_once(self):
        class D:
            def __init__(self):self.steps=[]
            def step(self,s):self.steps.append(s);return {'status':'failed','same_original_thread':True}
        d=D();t=[0.0]
        count=w.sequence(d,RUN,'A',.3,reader=lambda p,r,a,n:w.STEPS[a][n-1],clock=lambda:t[0],pause=lambda n:t.__setitem__(0,t[0]+n))
        self.assertEqual(count,4);self.assertEqual(d.steps,list(w.STEPS['A']))
    def test_missing_release_no_effect_and_real_key_no_child(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertIsNone(w.read_release(Path(t)/'missing',RUN,'A',1))
        with patch.object(w,'original_session',side_effect=AssertionError('no runtime')):
            # Malformed original window is rejected before any launch factory.
            with patch('sys.argv',['workload','--actor','A','--nonce',RUN,'--deadline-unix-ms','0']):
                self.assertRaises(Refused,w.main)
if __name__=='__main__':unittest.main(verbosity=2)
