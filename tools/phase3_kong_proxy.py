"""Pure contracts for the Phase 3 internal-only Kong proxy Service."""
import copy
import hashlib
import ipaddress
import json
from phase3_oru_readiness import Blocked, canonical, manifest_map

NAME='oran-nonrtric-kong-proxy'
NAMESPACE='nonrtric'
OVERRIDE={'kong':{'proxy':{'type':'ClusterIP'}}}
PORTS=[{'name':'kong-proxy','port':80,'protocol':'TCP','targetPort':8000},
       {'name':'kong-proxy-tls','port':443,'protocol':'TCP','targetPort':8443}]
SELECTOR={'app.kubernetes.io/component':'app','app.kubernetes.io/instance':'oran-nonrtric',
          'app.kubernetes.io/name':'kong'}
LB_FIELDS=('allocateLoadBalancerNodePorts','externalTrafficPolicy','healthCheckNodePort',
           'loadBalancerClass','loadBalancerIP','loadBalancerSourceRanges')


def sha(value):return hashlib.sha256(canonical(value)).hexdigest()


def fresh_contract(context):
    if type(context.get('kong_proxy_contract')) is not int or context['kong_proxy_contract']!=1:
        raise Blocked('Fresh Kong policy requires its explicit context contract')


def check_service(service,kind='ClusterIP'):
    meta=service['metadata'];spec=service['spec']
    if (service.get('kind')!='Service' or meta.get('namespace')!=NAMESPACE or meta.get('name')!=NAME
            or meta.get('deletionTimestamp') or not meta.get('uid') or spec.get('type')!=kind
            or spec.get('selector')!=SELECTOR or spec.get('externalIPs')):
        raise Blocked('Unexpected Kong Service identity, exposure or selector')
    try:
        if ipaddress.ip_address(spec['clusterIP']).version!=4 or spec.get('clusterIPs')!=[spec['clusterIP']]:
            raise ValueError('address family')
    except (ValueError,KeyError):raise Blocked('Kong ClusterIP is not the reviewed allocated IPv4 address')
    ports=copy.deepcopy(spec.get('ports',[]))
    if kind=='LoadBalancer':
        if (spec.get('allocateLoadBalancerNodePorts') is not True or spec.get('externalTrafficPolicy')!='Cluster'
                or any(spec.get(k) for k in LB_FIELDS[2:]) or service.get('status',{}).get('loadBalancer',{}).get('ingress')):
            raise Blocked('Unreviewed LoadBalancer configuration or assigned ingress')
        for port in ports:
            if type(port.pop('nodePort',None)) is not int:raise Blocked('Expected allocated Kong NodePorts')
    elif any(k in spec for k in LB_FIELDS) or any('nodePort' in p for p in ports):
        raise Blocked('ClusterIP proxy retains LoadBalancer or NodePort settings')
    if ports!=PORTS:raise Blocked('Kong proxy port contract changed')
    return {'uid':meta['uid'],'cluster_ip':spec['clusterIP'],'spec_sha256':sha(spec)}


def converted_spec(before):
    check_service(before,'LoadBalancer');spec=copy.deepcopy(before['spec']);spec['type']='ClusterIP'
    for field in LB_FIELDS:spec.pop(field,None)
    for port in spec['ports']:port.pop('nodePort',None)
    return spec


def check_conversion(before,after):
    check_service(after)
    if (before['metadata']['uid']!=after['metadata']['uid'] or converted_spec(before)!=after['spec']
            or any(before['metadata'].get(k)!=after['metadata'].get(k) for k in ('name','namespace','labels','annotations'))):
        raise Blocked('Service conversion changed fields beyond reviewed API cleanup')
    return check_service(after)


def patch(before):
    check_service(before,'LoadBalancer')
    return [{'op':'test','path':'/metadata/uid','value':before['metadata']['uid']},
            {'op':'test','path':'/metadata/resourceVersion','value':before['metadata']['resourceVersion']},
            {'op':'test','path':'/spec/type','value':'LoadBalancer'},
            {'op':'replace','path':'/spec/type','value':'ClusterIP'}]


def allowed_manifest_change(before,after):
    left=manifest_map(before);right=manifest_map(after)
    key=('v1','Service',NAMESPACE,NAME)
    if key not in left or set(left)!=set(right) or left[key]['spec'].get('type')!='LoadBalancer':
        raise Blocked('Unexpected retained Kong manifest identities')
    expected=copy.deepcopy(left);expected[key]['spec']['type']='ClusterIP'
    if expected!=right:raise Blocked('Manifest changes exceed the single Kong Service type field')
    return len(left)


def pods_binding(pods):
    result={}
    if not pods:raise Blocked('Non-RT RIC Pods are missing')
    for p in pods:
        meta=p['metadata'];status=p.get('status',{})
        if (meta.get('deletionTimestamp') or status.get('phase')!='Running'
                or not any(c['type']=='Ready' and c['status']=='True' for c in status.get('conditions',[]))):
            raise Blocked('An existing non-RT RIC Pod is not Ready')
        states=status.get('initContainerStatuses',[])+status.get('containerStatuses',[])
        result[meta['name']]={'uid':meta['uid'],'spec_sha256':sha(p['spec']),
            'containers':[{k:s.get(k) for k in ('name','restartCount','imageID')} for s in states]}
    return result


def endpoints_binding(slices,pods):
    kong={p['metadata']['uid'] for p in pods if all(p['metadata'].get('labels',{}).get(k)==v for k,v in SELECTOR.items())}
    result=[]
    for item in slices:
        ports=sorted([p['name'],p['port'],p.get('protocol','TCP')] for p in item.get('ports',[]))
        if ports!=sorted([p['name'],p['targetPort'],'TCP'] for p in PORTS):
            raise Blocked('Kong EndpointSlice ports differ from the reviewed proxy')
        for endpoint in item.get('endpoints',[]):
            ref=endpoint.get('targetRef',{})
            if (endpoint.get('conditions',{}).get('ready') is not True
                    or endpoint.get('conditions',{}).get('terminating') or ref.get('kind')!='Pod' or ref.get('uid') not in kong):
                raise Blocked('Kong endpoint is not a Ready retained proxy Pod')
            result.append({'addresses':sorted(endpoint['addresses']),'pod_uid':ref['uid'],'ports':ports})
    if not result:raise Blocked('Kong has no Ready proxy endpoint')
    return sorted(result,key=lambda e:(e['pod_uid'],e['addresses']))
