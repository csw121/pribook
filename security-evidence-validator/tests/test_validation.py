import copy
import unittest
from sev.common import read_json,SevError
from sev.evidence_validator import classify
from sev.ai_result_validator import verify
from sev.report_gate import gate
from tests.support import fixture,ROOT

class Base(unittest.TestCase):
    def setUp(self):
        self.e,self.m,self.a=fixture();self.logs={l['id']:l for l in self.e['logs']}
    def decision(self):return classify(self.m['candidates'][0],self.logs,self.m['policy'])
    def codes(self):return {i['code'] for i in verify(self.e,self.m,self.a)['issues']}

class IDORTests(Base):
    def test_owner_only_confirmed(self):self.assertEqual(self.decision()['classification'],'confirmed')
    def test_missing_requester_none_not_different(self):
        self.logs['01']['body']={};self.assertEqual(self.decision()['classification'],'unknown')
    def test_missing_owner(self):
        del self.logs['04']['body']['owner_id'];self.assertEqual(self.decision()['classification'],'unknown')
    def test_wrong_identity_endpoint(self):
        self.logs['01']['path']='/api/other';self.assertEqual(self.decision()['classification'],'unknown')
    def test_session_mismatch(self):
        self.logs['04']['session']='different';self.assertEqual(self.decision()['classification'],'unknown')
    def test_different_resource(self):
        self.logs['04']['body']['id']=8;self.assertEqual(self.decision()['code'],'RESOURCE_MISMATCH')
    def test_policy_required(self):
        self.m['policy']['owner_only']=False;self.assertEqual(self.decision()['code'],'POLICY_REQUIRED')
    def test_http_200_without_protected_data(self):
        del self.logs['04']['body']['content'];self.assertEqual(self.decision()['classification'],'unknown')
    def test_different_target(self):
        self.logs['04']['target_id']='0'*64;self.assertEqual(self.decision()['classification'],'unknown')
    def test_redacted_protected_not_proof(self):
        self.logs['03']['body']['content']=self.logs['04']['body']['content']='[REDACTED]';self.assertEqual(self.decision()['classification'],'unknown')
    def test_identity_type_mismatch(self):
        self.logs['01']['body']['user_id']='1001';self.assertEqual(self.decision()['code'],'IDENTITY_TYPE_MISMATCH')
    def test_identity_query_untrusted(self):
        self.logs['01']['query']=[['user','1001']];self.assertEqual(self.decision()['classification'],'unknown')
    def test_resource_query_difference(self):
        self.logs['04']['query']=[['version','2']];self.assertEqual(self.decision()['classification'],'unknown')
    def test_identity_other_target(self):
        self.logs['01']['target_id']='0'*64;self.assertEqual(self.decision()['classification'],'unknown')

class SQLITests(Base):
    def setUp(self):
        super().setUp();self.m=read_json(ROOT/'examples/sqli_rules.json')
    def test_identical_baseline_error(self):self.assertEqual(self.decision()['code'],'ERROR_ALSO_IN_BASELINE')
    def test_differential_error_suspicious(self):
        self.logs['08']['status']=200;self.logs['08']['body']=[];self.assertEqual(self.decision()['classification'],'suspicious')
    def test_different_path(self):
        self.logs['08']['path']='/api/other';self.assertEqual(self.decision()['code'],'BASELINE_NOT_COMPARABLE')
    def test_different_session(self):
        self.logs['08']['session']='other';self.assertEqual(self.decision()['classification'],'unknown')
    def test_other_parameter_changed(self):
        self.logs['08']['query'].append(['page','2']);self.assertEqual(self.decision()['code'],'BASELINE_NOT_COMPARABLE')
    def test_no_quote(self):
        self.logs['05']['query']=[['search','banana']];self.assertEqual(self.decision()['code'],'INPUT_DIFFERENCE_NOT_ESTABLISHED')
    def test_no_baseline(self):
        del self.logs['08'];self.assertEqual(self.decision()['code'],'EVIDENCE_MISSING')
    def test_duplicate_search(self):
        self.logs['05']['query'].append(['search','extra']);self.assertEqual(self.decision()['classification'],'unknown')

class EvidenceCoverageTests(Base):
    def test_unexpected_log(self):
        self.a['findings'][0]['claims'][0]['log_id']='99';self.assertIn('UNEXPECTED_LOG',self.codes())
    def test_missing_reference(self):
        self.a['findings'][0]['evidence_ids'].pop();self.assertIn('EVIDENCE_COVERAGE',self.codes())
    def test_duplicate_candidate(self):
        self.a['findings'].append(copy.deepcopy(self.a['findings'][0]));self.assertIn('DUPLICATE_CANDIDATE',self.codes())
    def test_missing_candidate(self):
        self.m['candidates'].append(dict(self.m['candidates'][0],id='missing'));self.assertIn('MISSING_CANDIDATE',self.codes())
    def test_unknown_reference(self):
        self.m['candidates'][0]['access']='99';self.assertIn('UNKNOWN_LOG',self.codes())

class ClaimTests(Base):
    def test_changed_user(self):
        next(c for c in self.a['findings'][0]['claims'] if c['field']=='body/user_id')['value']=999;self.assertIn('CLAIM_VALUE_MISMATCH',self.codes())
    def test_nonexistent_field(self):
        self.a['findings'][0]['claims'].append({'log_id':'01','field':'body/id','value':1001});self.assertIn('UNSUPPORTED_OR_ABSENT_FIELD',self.codes())
    def test_string_number(self):
        next(c for c in self.a['findings'][0]['claims'] if c['field']=='body/user_id')['value']='1001';self.assertIn('CLAIM_TYPE_MISMATCH',self.codes())
    def test_string_path_changed(self):
        next(c for c in self.a['findings'][0]['claims'] if c['field']=='path')['value']='/invented';self.assertIn('CLAIM_VALUE_MISMATCH',self.codes())
    def test_bool_not_integer(self):
        next(c for c in self.a['findings'][0]['claims'] if c['field']=='body/user_id')['value']=True;self.assertIn('CLAIM_TYPE_MISMATCH',self.codes())
    def test_unsupported_narrative(self):
        self.a['findings'][0]['internals']='invented';self.assertRaises(SevError,verify,self.e,self.m,self.a)

class StatusCoverageTests(Base):
    def test_one_status_omitted(self):
        claims=self.a['findings'][0]['claims'];claims[:]=[c for c in claims if not(c['log_id']=='01' and c['field']=='status')];self.assertIn('CLAIM_COVERAGE',self.codes())
    def test_all_statuses_omitted(self):
        claims=self.a['findings'][0]['claims'];claims[:]=[c for c in claims if c['field']!='status'];self.assertIn('CLAIM_COVERAGE',self.codes())
    def test_status_mismatch(self):
        next(c for c in self.a['findings'][0]['claims'] if c['field']=='status')['value']=500;self.assertIn('CLAIM_VALUE_MISMATCH',self.codes())

class GateTests(Base):
    def test_matching_pass(self):
        self.assertEqual(gate(self.e,self.m,self.a,verify(self.e,self.m,self.a))['status'],'passed')
    def test_review_blocks(self):
        self.a['findings'][0]['classification']='unknown';self.assertRaises(SevError,gate,self.e,self.m,self.a,verify(self.e,self.m,self.a))
    def test_stale_input(self):
        r=verify(self.e,self.m,self.a);self.e['logs'][0]['status']=500;self.assertRaises(SevError,gate,self.e,self.m,self.a,r)
    def test_forged_result(self):
        r=verify(self.e,self.m,self.a);r['passed_checks']=999;self.assertRaises(SevError,gate,self.e,self.m,self.a,r)
    def test_policy_bound(self):
        r=verify(self.e,self.m,self.a);self.m['policy']['owner_only']=False;self.assertRaises(SevError,gate,self.e,self.m,self.a,r)
    def test_failure_artifact(self):self.assertRaises(SevError,gate,self.e,self.m,self.a,{'status':'blocked'})
