"""Pure contracts for the pinned O-RU AAF readiness dependency; no cluster writes."""
import copy
import hashlib
import json

NAME='phase3-oru-aaf-readiness'
SA='oran-oru-app-read'
TARGETS=('aaf-locate','aaf-cm','aaf-service')
SOURCE_SHA256='19706add25101b88aa6171783ebe6db1cf1943c76225036badf2ad56f8377a5e'
IMAGE='nexus3.onap.org:10001/onap/oom/readiness@sha256:317c8a361ae73750f4d4a1b682c42b73de39083f73228dede31fd68b16c089db'
ARGS=[value for target in TARGETS for value in ('--container-name',target)]


class Blocked(ValueError):
    pass


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def sha(value):return hashlib.sha256(canonical(value)).hexdigest()


def owner(obj,kind):
    owners=obj['metadata'].get('ownerReferences',[])
    if len(owners)!=1 or owners[0].get('kind')!=kind or owners[0].get('controller') is not True:
        raise Blocked('Unexpected readiness dependency owner')
    return owners[0]


def dependencies(pods,replicasets,deployments):
    result=[]
    for target in TARGETS:
        found=[p for p in pods if any(c['name']==target for c in p['spec'].get('containers',[]))]
        if len(found)!=1:raise Blocked('AAF target Pod missing or ambiguous')
        pod=found[0]
        if (pod['metadata'].get('deletionTimestamp') or not any(c['type']=='Ready' and c['status']=='True'
                for c in pod.get('status',{}).get('conditions',[]))):raise Blocked('AAF target Pod is not Ready')
        ref=owner(pod,'ReplicaSet')
        sets=[r for r in replicasets if r['metadata']['name']==ref['name'] and r['metadata']['uid']==ref['uid']]
        if len(sets)!=1:raise Blocked('AAF ReplicaSet identity changed')
        rs=sets[0];ref=owner(rs,'Deployment')
        deps=[d for d in deployments if d['metadata']['name']=='onap-'+target
              and d['metadata']['name']==ref['name'] and d['metadata']['uid']==ref['uid']]
        if len(deps)!=1:raise Blocked('AAF Deployment identity changed')
        dep=deps[0];status=dep.get('status',{});desired=dep['spec'].get('replicas',1)
        if (status.get('observedGeneration')!=dep['metadata']['generation']
                or status.get('readyReplicas',0)!=desired or status.get('updatedReplicas',0)!=desired):
            raise Blocked('AAF Deployment is not reconciled and Ready')
        result.append({'container':target,'pod_uid':pod['metadata']['uid'],
            'replicaset':rs['metadata']['name'],'replicaset_uid':rs['metadata']['uid'],
            'deployment':dep['metadata']['name'],'deployment_uid':dep['metadata']['uid'],
            'deployment_spec_sha256':sha(dep['spec'])})
    return result


def resources(targets):
    if ([t['container'] for t in targets]!=list(TARGETS)
            or len({t['replicaset'] for t in targets})!=3
            or {t['deployment'] for t in targets}!={'onap-'+t for t in TARGETS}):
        raise Blocked('Unreviewed readiness targets')
    metadata={'name':NAME,'namespace':'onap','labels':{'phase3.onap.org/component':'oru-readiness'}}
    role={'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':metadata,
        'rules':[{'apiGroups':[''],'resources':['pods'],'verbs':['list']},
                 {'apiGroups':['apps'],'resources':['replicasets/status'],'verbs':['get'],
                  'resourceNames':sorted(t['replicaset'] for t in targets)},
                 {'apiGroups':['apps'],'resources':['deployments'],'verbs':['get'],
                  'resourceNames':sorted(t['deployment'] for t in targets)}]}
    binding={'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':copy.deepcopy(metadata),
        'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':NAME},
        'subjects':[{'kind':'ServiceAccount','name':SA,'namespace':'nonrtric'}]}
    return [role,binding]


def check_resource(actual,expected):
    if (actual['metadata'].get('deletionTimestamp') or any(actual.get(k)!=v for k,v in expected.items() if k!='metadata')
            or any(actual['metadata'].get(k)!=v for k,v in expected['metadata'].items())):
        raise Blocked('Scoped readiness RBAC changed')
    return {'uid':actual['metadata']['uid'],'spec_sha256':sha(expected)}


def check_pod(pod,expected_uid=None,unattempted=False,readiness_restarts=0):
    if (pod['metadata'].get('namespace')!='nonrtric' or pod['metadata'].get('deletionTimestamp')
            or expected_uid and pod['metadata']['uid']!=expected_uid
            or pod['spec'].get('serviceAccountName')!=SA):raise Blocked('O-RU Pod identity changed')
    init=pod['spec'].get('initContainers',[])
    if (len(init)!=2 or init[0]['name']!='oru-app-cert-initializer-readiness'
            or init[0]['image']!=IMAGE or init[0].get('command')!=['/phase3-helpers/phase3-readiness-wrapper.py']
            or init[0].get('args')!=ARGS
            or [x for x in init[0].get('env',[]) if x['name']=='NAMESPACE']!=[{'name':'NAMESPACE','value':'onap'}]
            or init[1]['name']!='oru-app-aaf-config'):
        raise Blocked('O-RU readiness contract changed')
    statuses=pod.get('status',{}).get('initContainerStatuses',[])
    if (len(statuses)!=2 or statuses[0].get('restartCount',0)!=readiness_restarts
            or statuses[1].get('restartCount') or statuses[1].get('lastState')
            or not readiness_restarts and statuses[0].get('lastState')):
        raise Blocked('O-RU initializer restart/history observed; no replay')
    states={s['name']:s.get('state',{}) for s in statuses}
    if any(s.get('terminated',{}).get('exitCode',0)!=0 for s in states.values()):
        raise Blocked('O-RU initializer failed; separate review required')
    if unattempted and (not states[init[0]['name']].get('running') or not states[init[1]['name']].get('waiting')
            or any(s.get('imageID') or s.get('restartCount') or s.get('lastState')
                   or s.get('state',{}).get('running') or s.get('state',{}).get('terminated')
                   for s in pod.get('status',{}).get('containerStatuses',[]))):
        raise Blocked('Certificate agent/main already executed; recovery audit refused')
    return states


def manifest_map(objects):
    result={}
    for obj in objects:
        if not obj:continue
        if (obj.get('metadata',{}).get('annotations') or {}).get('helm.sh/hook'):continue
        key=(obj['apiVersion'],obj['kind'],obj['metadata'].get('namespace') or 'nonrtric',obj['metadata']['name'])
        if key in result:raise Blocked('Duplicate retained manifest identity')
        if obj['kind'] in ('Job','CronJob'):raise Blocked('Retained initializer/hook replay refused')
        result[key]=obj
    return result


def identical_manifests(before,after):
    if not before or manifest_map(before)!=manifest_map(after):
        raise Blocked('Retained non-RT RIC render changed; no Helm retry')


def fresh_contract(context):
    if type(context.get('oru_readiness_contract')) is not int or context['oru_readiness_contract']!=1:
        raise Blocked('Retained context cannot enter automatic fresh RBAC')
