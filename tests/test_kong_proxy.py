import copy
from datetime import datetime,timedelta,timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch,Mock
import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import phase3_kong_proxy as policy
spec=importlib.util.spec_from_file_location('kong_gate_tests',ROOT/'tools/phase3-kong-proxy.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)


def service():
    ports=copy.deepcopy(policy.PORTS)
    for i,p in enumerate(ports):p['nodePort']=26000+i
    return {'apiVersion':'v1','kind':'Service','metadata':{'namespace':'nonrtric','name':policy.NAME,
        'uid':'synthetic-service','resourceVersion':'17','labels':{'app':'synthetic'},'annotations':{}},
        'spec':{'type':'LoadBalancer','clusterIP':'10.96.0.2','clusterIPs':['10.96.0.2'],
        'allocateLoadBalancerNodePorts':True,'externalTrafficPolicy':'Cluster','internalTrafficPolicy':'Cluster',
        'ipFamilies':['IPv4'],'ipFamilyPolicy':'SingleStack','ports':ports,
        'selector':copy.deepcopy(policy.SELECTOR),'sessionAffinity':'None'}}


def converted():
    s=service();s['spec']=policy.converted_spec(s);s['metadata']['resourceVersion']='18';return s


def pods():
    return [{'kind':'Pod','metadata':{'name':'synthetic-kong','uid':'synthetic-pod','labels':policy.SELECTOR},
        'spec':{'containers':[{'name':'proxy','image':'synthetic-image'}]},
        'status':{'phase':'Running','conditions':[{'type':'Ready','status':'True'}],
                  'containerStatuses':[{'name':'proxy','restartCount':0,'imageID':'synthetic-id'}]}}]


def slices():
    return [{'ports':[{'name':p['name'],'port':p['targetPort'],'protocol':'TCP'} for p in policy.PORTS],
        'endpoints':[{'addresses':['10.233.0.2'],'conditions':{'ready':True},
                      'targetRef':{'kind':'Pod','uid':'synthetic-pod'}}]}]


def manifest():
    svc=service();svc.pop('status',None)
    for key in ('uid','resourceVersion'):svc['metadata'].pop(key,None)
    svc['spec'].pop('clusterIP');svc['spec'].pop('clusterIPs')
    for key in policy.LB_FIELDS:svc['spec'].pop(key,None)
    for p in svc['spec']['ports']:p.pop('nodePort',None)
    return [svc,{'apiVersion':'apps/v1','kind':'Deployment','metadata':{'namespace':'nonrtric','name':'synthetic'},
                 'spec':{'template':{'spec':{'containers':[{'image':'synthetic'}]}}}}]


class PolicyTests(unittest.TestCase):
    def test_type_only_patch_has_uid_resource_version_and_old_type_preconditions(self):
        p=policy.patch(service())
        self.assertEqual(['test','test','test','replace'],[x['op'] for x in p])
        self.assertEqual(['/metadata/uid','/metadata/resourceVersion','/spec/type','/spec/type'],[x['path'] for x in p])
        self.assertEqual('17',p[1]['value']);self.assertEqual('ClusterIP',p[-1]['value'])

    def test_conversion_preserves_ip_uid_ports_and_selector(self):
        s=service();result=policy.check_conversion(s,converted())
        self.assertEqual('synthetic-service',result['uid']);self.assertEqual('10.96.0.2',result['cluster_ip'])
        for key in ('clusterIP','clusterIPs','selector','ipFamilies','ipFamilyPolicy'):
            self.assertEqual(s['spec'][key],converted()['spec'][key])
        self.assertEqual(policy.PORTS,converted()['spec']['ports'])

    def test_cleanup_does_not_mutate_original_and_json_roundtrip_is_stable(self):
        s=service();saved=copy.deepcopy(s);policy.converted_spec(s);self.assertEqual(saved,s)
        e=policy.endpoints_binding(slices(),pods());self.assertEqual(e,json.loads(json.dumps(e)))

    def test_unreviewed_lb_configuration_is_refused(self):
        for key,value in [('loadBalancerIP','192.0.2.1'),('loadBalancerClass','synthetic'),
                          ('loadBalancerSourceRanges',['192.0.2.0/24']),('externalIPs',['192.0.2.1'])]:
            s=service();s['spec'][key]=value
            with self.assertRaises(ValueError):policy.converted_spec(s)
        s=service();s['status']={'loadBalancer':{'ingress':[{'ip':'192.0.2.1'}]}}
        with self.assertRaises(ValueError):policy.patch(s)

    def test_clusterip_visibility_or_port_drift_refused(self):
        for key,value in [('externalIPs',['192.0.2.1']),('externalTrafficPolicy','Cluster'),
                          ('allocateLoadBalancerNodePorts',False),('selector',{}),('clusterIP','None')]:
            s=converted();s['spec'][key]=value
            with self.assertRaises(ValueError):policy.check_service(s)
        s=converted();s['spec']['ports'][0]['nodePort']=26000
        with self.assertRaises(ValueError):policy.check_service(s)

    def test_unrelated_field_uid_ip_and_metadata_conversion_drift_refused(self):
        for what in ('uid','clusterIP','port','labels','sessionAffinity'):
            s=converted()
            if what=='uid':s['metadata']['uid']='changed'
            elif what=='labels':s['metadata']['labels']={}
            elif what=='port':s['spec']['ports'][0]['targetPort']=9000
            elif what=='clusterIP':s['spec']['clusterIP']='10.96.0.3';s['spec']['clusterIPs']=['10.96.0.3']
            else:s['spec'][what]='ClientIP'
            with self.assertRaises(ValueError):policy.check_conversion(service(),s)

    def test_manifest_delta_is_one_field_only(self):
        old=manifest();new=copy.deepcopy(old);new[0]['spec']['type']='ClusterIP'
        self.assertEqual(2,policy.allowed_manifest_change(old,new))
        for change in ('pod','service','identity'):
            bad=copy.deepcopy(new)
            if change=='pod':bad[1]['spec']['template']['spec']['containers'][0]['image']='other'
            elif change=='service':bad[0]['spec']['ports'][0]['port']=81
            else:bad[1]['metadata']['name']='other'
            with self.assertRaises(ValueError):policy.allowed_manifest_change(old,bad)

    def test_missing_endpoint_unready_endpoint_and_pod_drift_refused(self):
        with self.assertRaises(ValueError):policy.endpoints_binding([],pods())
        for what in ('ready','target','ports'):
            e=slices()
            if what=='ready':e[0]['endpoints'][0]['conditions']['ready']=False
            elif what=='target':e[0]['endpoints'][0]['targetRef']['uid']='other'
            else:e[0]['ports'][0]['port']=9000
            with self.assertRaises(ValueError):policy.endpoints_binding(e,pods())
        p=pods();p[0]['status']['conditions'][0]['status']='False'
        with self.assertRaises(ValueError):policy.pods_binding(p)

    def test_pod_binding_detects_restarts_and_spec_or_uid_change(self):
        first=policy.pods_binding(pods())
        for what in ('uid','spec','restart'):
            p=pods()
            if what=='uid':p[0]['metadata']['uid']='other'
            elif what=='spec':p[0]['spec']['containers'][0]['image']='other'
            else:p[0]['status']['containerStatuses'][0]['restartCount']=1
            self.assertNotEqual(first,policy.pods_binding(p))

    def test_fresh_contract_never_adopts_retained_or_invalid_context(self):
        for value in (None,True,False,'1',1.0,0,2):
            with self.assertRaises(ValueError):policy.fresh_contract({'kong_proxy_contract':value})
        policy.fresh_contract({'kong_proxy_contract':1})


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'context.json';gate.write(self.path,{})
        self.review=Path(self.temp.name)/'review.json';self.override=Path(self.temp.name)/'override.json'
        gate.write(self.override,policy.OVERRIDE)
        self.binding={'service':service(),'historical':{'synthetic':True},'runtime':{'synthetic':True},
                      'release':{'revision':2,'status':'failed','manifest_sha256':'synthetic'},
                      'blocker_archive':{'directory':'/synthetic/archive','ledger_sha256':'0'*64},
                      'override':{'path':str(self.override),'sha256':gate.digest(self.override)}}

    def review_at(self,age=0):
        gate.write(self.review,{'schema':1,'created_utc':(datetime.now(timezone.utc)-timedelta(seconds=age)).isoformat(),
                                'binding':self.binding})

    def test_expired_review_or_prior_attempt_stops_before_cluster_reads(self):
        self.review_at(1801)
        with patch.object(gate,'audit_binding') as audit:
            with self.assertRaisesRegex(ValueError,'expired'):gate.apply(self.path,self.review,None,None,'slice')
            audit.assert_not_called()
        self.review.unlink();self.review_at();gate.write(self.path.parent/(gate.PREFIX+'attempt.json'),{})
        with patch.object(gate,'audit_binding') as audit:
            with self.assertRaisesRegex(ValueError,'no replay'):gate.apply(self.path,self.review,None,None,'slice')
            audit.assert_not_called()

    def test_binding_drift_never_patches_or_runs_helm(self):
        self.review_at()
        with patch.object(gate,'audit_binding',return_value={'drift':True}),patch.object(gate,'command') as call:
            with self.assertRaisesRegex(ValueError,'binding changed'):gate.apply(self.path,self.review,None,None,'slice')
            call.assert_not_called()

    def test_service_drift_immediately_before_transition_never_latches(self):
        self.review_at();changed=service();changed['metadata']['resourceVersion']='18'
        with patch.object(gate,'audit_binding',return_value=self.binding),patch.object(gate,'preserve',return_value={}), \
             patch.object(gate,'service',return_value=changed),patch.object(gate,'command') as call:
            with self.assertRaisesRegex(ValueError,'immediately before'):gate.apply(self.path,self.review,None,None,'slice')
            call.assert_not_called()
        self.assertFalse((self.path.parent/(gate.PREFIX+'attempt.json')).exists())

    def test_lost_patch_response_retains_latch_and_never_retries_or_runs_helm(self):
        self.review_at()
        with patch.object(gate,'audit_binding',return_value=self.binding),patch.object(gate,'preserve',return_value={}), \
             patch.object(gate,'service',return_value=service()),patch.object(gate,'command',side_effect=TimeoutError) as call, \
             patch.object(gate,'helm_logged') as helm:
            with self.assertRaises(TimeoutError):gate.apply(self.path,self.review,None,None,'slice')
            call.assert_called_once();helm.assert_not_called()
        self.assertTrue((self.path.parent/(gate.PREFIX+'attempt.json')).exists())
        self.assertFalse((self.path.parent/(gate.PREFIX+'acceptance.json')).exists())

    def test_unexpected_admission_cleanup_stops_before_helm(self):
        self.review_at();changed=converted();changed['spec']['sessionAffinity']='ClientIP'
        with patch.object(gate,'audit_binding',return_value=self.binding),patch.object(gate,'preserve',return_value={}), \
             patch.object(gate,'service',return_value=service()),patch.object(gate,'command',return_value=json.dumps(changed).encode()), \
             patch.object(gate,'helm_logged') as helm:
            with self.assertRaises(ValueError):gate.apply(self.path,self.review,None,None,'slice')
            helm.assert_not_called()

    def test_helm_failure_keeps_service_transition_and_no_acceptance(self):
        self.review_at()
        with patch.object(gate,'audit_binding',return_value=self.binding),patch.object(gate,'preserve',return_value={}), \
             patch.object(gate,'service',return_value=service()),patch.object(gate,'command',return_value=json.dumps(converted()).encode()), \
             patch.object(gate,'helm_logged',side_effect=policy.Blocked('bounded failure')) as helm:
            with self.assertRaisesRegex(ValueError,'bounded failure'):gate.apply(self.path,self.review,None,Mock(ROOT=ROOT),'slice')
            args=helm.call_args.args[2]
            self.assertIn('--no-hooks',args)
            for flag in ('--install','--force','--atomic'):self.assertNotIn(flag,args)
        self.assertTrue((self.path.parent/(gate.PREFIX+'service-transition.json')).exists())
        self.assertFalse((self.path.parent/(gate.PREFIX+'acceptance.json')).exists())

    def test_successful_apply_is_one_patch_one_reconciliation_then_separate_acceptance(self):
        self.review_at();old=manifest();new=copy.deepcopy(old);new[0]['spec']['type']='ClusterIP'
        def cmd(args,*a,**kw):
            if args[0]=='kubectl':return json.dumps(converted()).encode()
            self.assertEqual(['helm','get','manifest'],args[:3]);return yaml.safe_dump_all(old).encode()
        svc=[service(),converted(),converted()]
        with patch.object(gate,'audit_binding',return_value=self.binding) as audit,patch.object(gate,'preserve',return_value={}), \
             patch.object(gate,'service',side_effect=svc),patch.object(gate,'command',side_effect=cmd) as call, \
             patch.object(gate,'helm_logged') as helm,patch.object(gate,'historical',return_value=self.binding['historical']), \
             patch.object(gate.util,'release_binding',return_value=({'revision':3,'status':'deployed'},new)), \
             patch.object(gate,'render',return_value=new),patch.object(gate,'runtime',return_value=self.binding['runtime']), \
             patch.object(gate,'probe',return_value={'http_status':404}):
            gate.apply(self.path,self.review,None,Mock(ROOT=ROOT),'slice')
            helm.assert_called_once();self.assertEqual(2,call.call_count)
            self.assertEqual(self.binding['blocker_archive'],audit.call_args.args[-1])
        r=gate.read(self.path.parent/(gate.PREFIX+'acceptance.json'));self.assertTrue(r['passed'])
        self.assertEqual(3,r['release']['revision'])

    def test_review_paths_and_old_latches_are_not_overwritten(self):
        self.review_at()
        with patch.object(gate,'audit_binding') as audit:
            with self.assertRaisesRegex(ValueError,'no overwrite'):gate.review(self.path,self.review,None,None,'slice')
            audit.assert_not_called()
        for old in ('oru-readiness-continuation-attempt.json','dmaap-attempt.json'):
            gate.write(self.path.parent/old,{'historical':True})
        self.assertTrue(all(gate.read(self.path.parent/n)=={'historical':True}
                            for n in ('oru-readiness-continuation-attempt.json','dmaap-attempt.json')))

    def test_tampered_acceptance_stops_before_historical_verification(self):
        gate.write(self.path.parent/(gate.PREFIX+'acceptance.json'),{'review_file':str(self.review),'passed':False})
        self.review_at();gate.write(self.path.parent/(gate.PREFIX+'attempt.json'),{})
        with patch.object(gate,'historical') as check:
            with self.assertRaises(ValueError):gate.verify(self.path,None,None,'slice')
            check.assert_not_called()

    def test_continuation_latch_blocks_nts_and_no_nonrtric_reconciliation_is_repeated(self):
        gate.write(self.path.parent/(gate.PREFIX+'continuation-attempt.json'),{})
        with patch.object(gate,'verify',return_value={}),patch.object(gate,'empty_network'),patch.object(gate,'helm_logged') as helm:
            with self.assertRaisesRegex(ValueError,'no retry'):gate.continue_startup(self.path,None,None,'slice')
            helm.assert_not_called()
        import inspect
        source=inspect.getsource(gate.continue_startup)
        self.assertNotIn("'upgrade'",source);self.assertIn("'install','oran-simulator'",source)
        self.assertNotIn('setup-driver.sh',source);self.assertIn("'--require-ready'",source)

    def test_existing_nts_state_blocks_continuation(self):
        with patch.object(gate,'command',return_value=b'[{"name":"synthetic"}]'),patch.object(gate,'get') as get:
            with self.assertRaisesRegex(ValueError,'existing or attempted'):gate.empty_network()
            get.assert_not_called()

    def test_fresh_binding_is_explicit_readonly_afterward_and_json_stable(self):
        self.path.unlink();gate.write(self.path,{'kong_proxy_contract':1,'slice_urn':'slice'})
        with patch.object(gate,'command',return_value=b'slice'),patch.object(gate,'service',return_value=converted()), \
             patch.object(gate,'get',return_value={'items':pods()}),patch.object(gate,'endpoints',return_value=slices()), \
             patch.object(gate,'probe',return_value={'http_status':404}) as probe:
            with self.assertRaisesRegex(ValueError,'missing'):gate.verify_fresh(self.path,'slice')
            gate.verify_fresh(self.path,'slice',True);probe.assert_called_once()
            path=self.path.parent/(gate.PREFIX+'fresh-acceptance.json');before=path.read_bytes()
            gate.verify_fresh(self.path,'slice');self.assertEqual(before,path.read_bytes())
            svc=converted();svc['metadata']['uid']='changed'
            with patch.object(gate,'service',return_value=svc):
                with self.assertRaisesRegex(ValueError,'identity changed'):gate.verify_fresh(self.path,'slice')

    def test_server_dry_run_does_not_persist_a_patch_or_acceptance(self):
        with patch.object(gate,'command',return_value=json.dumps(converted()).encode()) as call, \
             patch.object(gate,'service',return_value=service()):
            self.assertEqual(policy.check_service(converted()),gate.server_dry_run(service()))
            self.assertIn('--dry-run=server',call.call_args.args[0])
        self.assertFalse((self.path.parent/(gate.PREFIX+'attempt.json')).exists())

    def test_server_dry_run_refuses_live_drift(self):
        changed=service();changed['metadata']['resourceVersion']='changed'
        with patch.object(gate,'command',return_value=json.dumps(converted()).encode()), \
             patch.object(gate,'service',return_value=changed):
            with self.assertRaisesRegex(ValueError,'during server dry-run'):gate.server_dry_run(service())

    def test_status_update_is_private_atomic_and_rejects_symlinks(self):
        target=self.path.parent/'status.json';gate.write_status(target,{'current':True})
        self.assertEqual({'current':True},gate.read(target));self.assertEqual(0o600,target.stat().st_mode&0o777)
        link=self.path.parent/'status-link.json';link.symlink_to(target)
        with self.assertRaisesRegex(ValueError,'not regular'):gate.write_status(link,{'current':False})
        self.assertEqual({'current':True},gate.read(target))


class ArchiveSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.work=Path(self.temp.name);self.path=self.work/'fresh-start/context.json'
        self.path.parent.mkdir();gate.write(self.path,{})
        self.log='oru-readiness-nonrtric-synthetic.log'
        (self.work/self.log).write_bytes(b'UPGRADE FAILED: context deadline exceeded\n')
        self.release={'revision':2,'status':'failed'}

    def archive(self,name,extra=False):
        directory=self.work/('nonrtric-kong-lb-blocker-'+name);directory.mkdir()
        gate.write(directory/'kong-service.json',service())
        gate.write(directory/'helm-status.json',{'version':2,'info':{'status':'failed'}})
        (directory/self.log).write_bytes((self.work/self.log).read_bytes())
        if extra:gate.write(directory/'extra-evidence.json',{'different':True})
        return gate.util.seal(directory)

    def select(self,record):return gate.blocker_archive(self.path,service(),self.release,record)

    def test_explicit_path_and_full_lowercase_hash_are_required(self):
        record=self.archive('a')
        for selected in (None,{},dict(record,ledger_sha256='bad'),dict(record,ledger_sha256='A'*64)):
            with self.assertRaisesRegex(ValueError,'Explicit'):self.select(selected)

    def test_single_selected_archive_preserves_original_ledger(self):
        record=self.archive('a');before=(Path(record['directory'])/'SHA256SUMS.json').read_bytes()
        result=self.select(record)
        self.assertEqual([record],result['equivalent_archives'])
        self.assertEqual(before,(Path(record['directory'])/'SHA256SUMS.json').read_bytes())

    def test_identical_copies_are_verified_and_bound_without_glob_first_selection(self):
        first=self.archive('a');selected=self.archive('z')
        self.assertEqual(first['ledger_sha256'],selected['ledger_sha256'])
        snapshots={str(p):p.read_bytes() for p in self.work.rglob('*') if p.is_file()}
        result=self.select(selected);gate.verify_blocker_archive(result)
        self.assertEqual(selected['directory'],result['directory'])
        self.assertEqual([first,selected],result['equivalent_archives'])
        self.assertEqual(snapshots,{str(p):p.read_bytes() for p in self.work.rglob('*') if p.is_file()})

    def test_wrong_hash_or_missing_selected_directory_never_adopts_another_copy(self):
        record=self.archive('a')
        for selected in (dict(record,ledger_sha256='0'*64),
                         dict(record,directory=str(self.work/'nonrtric-kong-lb-blocker-missing'))):
            with self.assertRaisesRegex(ValueError,'identity or hash'):self.select(selected)

    def test_outside_path_relative_path_wrong_prefix_and_symlink_are_refused(self):
        record=self.archive('a');link=self.work/'nonrtric-kong-lb-blocker-link'
        link.symlink_to(Path(record['directory']),target_is_directory=True)
        for directory in ('relative','/outside/nonrtric-kong-lb-blocker-a',str(self.work/'other'),str(link)):
            with self.assertRaisesRegex(ValueError,'outside'):self.select(dict(record,directory=directory))

    def test_matching_but_nonidentical_preserved_contents_are_refused(self):
        selected=self.archive('a');self.archive('z',extra=True)
        with self.assertRaisesRegex(ValueError,'conflicting contents'):self.select(selected)

    def test_tampered_equivalent_archive_is_not_ignored(self):
        selected=self.archive('a');other=self.archive('z')
        gate.write(Path(other['directory'])/'unrecorded.json',{})
        with self.assertRaisesRegex(ValueError,'archive changed'):self.select(selected)

    def test_selected_archive_must_match_retained_service_and_release(self):
        selected=self.archive('a')
        for svc,release in ((converted(),self.release),(service(),{'revision':3,'status':'failed'})):
            with self.assertRaisesRegex(ValueError,'identity or hash'):
                gate.blocker_archive(self.path,svc,release,selected)

    def test_verification_rechecks_all_bound_copies(self):
        selected=self.archive('a');other=self.archive('z');result=self.select(selected)
        gate.write(Path(other['directory'])/'unrecorded.json',{})
        with self.assertRaisesRegex(ValueError,'archive changed'):gate.verify_blocker_archive(result)

    def test_copy_binding_cannot_drop_selection_duplicate_paths_or_change_hash(self):
        selected=self.archive('a');self.archive('z');result=self.select(selected)
        for what in ('empty','selected','duplicate','hash'):
            bad=copy.deepcopy(result)
            if what=='empty':bad['equivalent_archives']=[]
            elif what=='selected':bad['directory']=str(self.work/'nonrtric-kong-lb-blocker-missing')
            elif what=='duplicate':bad['equivalent_archives'].append(bad['equivalent_archives'][0])
            else:bad['equivalent_archives'][1]['ledger_sha256']='0'*64
            with self.assertRaisesRegex(ValueError,'binding changed'):gate.verify_blocker_archive(bad)


if __name__=='__main__':unittest.main()
