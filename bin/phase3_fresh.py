"""Fresh-install-only chart overlay; existing recovery renderers do not use it."""
import copy
import hashlib
import json
from pathlib import Path
from phase3_lab_pki import CONFIG_IMAGE, AGENT_IMAGE, trust_config
import phase3_ves
import phase3_sms
import phase3_sms_backend

ROOT = Path(__file__).resolve().parents[1]
READINESS_IMAGE = 'nexus3.onap.org:10001/onap/oom/readiness@sha256:317c8a361ae73750f4d4a1b682c42b73de39083f73228dede31fd68b16c089db'
TARGETS = ('mariadb-galera','policy-mariadb','sdnrdb-master')


def helper_config(namespace):
    data = {n:(ROOT/'bin'/n).read_text() for n in ('phase3-readiness-wrapper.py','phase3-aaf-bootstrap.sh')}
    digest = hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
    return {'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'phase3-helpers-'+digest[:16],
            'namespace':namespace,'labels':{'phase3.onap.org/component':'fresh-compatibility'}},
            'immutable':True,'data':data}


def select_storage_node(nodes):
    # Logical profile role, resolved anew to the current Kubernetes Node UID.
    candidates = [n for n in nodes if n['metadata'].get('labels',{}).get('kubernetes.io/hostname') == 'node-2']
    if len(candidates) != 1:
        raise ValueError('Expected exactly one allocated node-2 worker')
    node = candidates[0]
    if (node['spec'].get('unschedulable') or
            any(t.get('effect') in ('NoSchedule','NoExecute') for t in node['spec'].get('taints',[])) or
            not any(c['type']=='Ready' and c['status']=='True' for c in node.get('status',{}).get('conditions',[]))):
        raise ValueError('Allocated storage worker is not Ready and schedulable')
    return {'name':node['metadata']['name'],'uid':node['metadata']['uid'],'hostname':'node-2'}


def pod_spec(resource):
    if resource.get('kind') == 'Pod':
        return resource.get('spec')
    spec = resource.get('spec',{})
    if resource.get('kind') == 'CronJob':
        spec = spec.get('jobTemplate',{}).get('spec',{})
    return spec.get('template',{}).get('spec')


def add_volume(spec, volume):
    volumes = spec.setdefault('volumes',[])
    same = [v for v in volumes if v['name']==volume['name']]
    if same and same != [volume]:
        raise ValueError('Unexpected compatibility volume collision')
    if not same:
        volumes.append(volume)


def overlay(resources, context):
    if context.get('schema') != 1 or context.get('baseline') != 'fresh-isolated-lab-pki':
        raise ValueError('Fresh install context is missing or unreviewed')
    resources = copy.deepcopy(resources)
    trust = trust_config(context['pki_directory'])
    for resource in resources:
        kind = resource.get('kind')
        meta = resource.get('metadata',{})
        name = meta.get('name','')
        if context.get('sms_backend_contract') == 1:
            phase3_sms_backend.check_stock_config(resource)
            resource.update(phase3_sms_backend.patch(resource, context))
        if kind == 'Deployment' and name == phase3_sms.NAME:
            resource.update(phase3_sms.patch_deployment(resource, context))
        elif kind == 'Service' and name == phase3_sms.SERVICE:
            resource.update(phase3_sms.patch_service(resource))
        elif kind == 'Job' and name == phase3_sms.JOB:
            resource.update(phase3_sms.hold_preload(resource))
        if kind == 'Deployment' and name == phase3_ves.NAME:
            patched = phase3_ves.patch_deployment(resource, context)
            resource.clear()
            resource.update(patched)
        if kind == 'ConfigMap' and 'truststoreONAPall.jks.b64' in resource.get('data',{}):
            if 'truststoreONAP.p12.b64' not in resource['data']:
                raise ValueError('Unreviewed partial AAF consumer trust ConfigMap')
            resource['data'].update(trust)
            meta.setdefault('annotations',{})['phase3.onap.org/trust-root-sha256'] = context['root_sha256']
        spec = pod_spec(resource)
        if spec is not None:
            helper_name = helper_config(meta.get('namespace','onap'))['metadata']['name']
            for container in spec.get('initContainers',[])+spec.get('containers',[]):
                image = container.get('image','')
                if image == READINESS_IMAGE:
                    command = container.get('command',[])
                    if not command or command[0] != '/app/ready.py':
                        raise ValueError('Unreviewed stock readiness entry point')
                    container['command'] = ['/phase3-helpers/phase3-readiness-wrapper.py']+command[1:]
                    container.setdefault('volumeMounts',[]).append({'name':'phase3-helpers','mountPath':'/phase3-helpers','readOnly':True})
                    add_volume(spec, {'name':'phase3-helpers','configMap':{'name':helper_name,'defaultMode':365}})
                    if kind == 'Job' and name == 'onap-dmaap-bc-dmaap-provisioning':
                        args = container.get('args', [])
                        if args != ['--container-name', 'dmaap-bc'] or command != ['/app/ready.py']:
                            raise ValueError('Unreviewed DMAAP provisioning readiness arguments')
                        container['args'] = args + ['--timeout', '30']
                elif image == CONFIG_IMAGE:
                    if kind == 'Deployment' and name == phase3_sms.NAME and phase3_sms.crypto_initializer(container):
                        continue  # Crypto-only SMS chain assembly, never the AAF server bootstrap.
                    if container not in spec.get('initContainers',[]) or container.get('command') != ['/bin/bash'] or container.get('args') != ['-c','cd /opt/app/aaf_config\nbin/agent.sh\n']:
                        raise ValueError('Unreviewed AAF server bootstrap contract')
                    container['command'] = ['/bin/bash','/phase3-helpers/phase3-aaf-bootstrap.sh']
                    container.pop('args',None)
                    container.setdefault('volumeMounts',[]).extend([
                        {'name':'phase3-helpers','mountPath':'/phase3-helpers','readOnly':True},
                        {'name':'phase3-pki','mountPath':'/phase3-pki','readOnly':True}])
                    add_volume(spec, {'name':'phase3-helpers','configMap':{'name':helper_name,'defaultMode':365}})
                    add_volume(spec, {'name':'phase3-pki','secret':{'secretName':context['secret_name'],'defaultMode':256}})
                elif 'onap/aaf/aaf_config' in image or 'onap/oom/readiness' in image:
                    raise ValueError('Unreviewed AAF/readiness image')
                elif image == AGENT_IMAGE:
                    mounts = container.get('volumeMounts',[])
                    for filename in ('truststoreONAPall.jks.b64','truststoreONAP.p12.b64'):
                        if not any(m.get('mountPath')=='/opt/app/aaf_config/cert/'+filename and m.get('subPath')==filename for m in mounts):
                            raise ValueError('AAF agent does not use reviewed chart-provided trust')
            if kind == 'StatefulSet' and any(name.endswith('-'+target) for target in TARGETS):
                if resource['spec'].get('replicas',1) != 1:
                    raise ValueError('Unreviewed persistent database replica count')
                selectors = spec.setdefault('nodeSelector',{})
                hostname = context['storage_node']['hostname']
                if selectors.get('kubernetes.io/hostname',hostname) != hostname:
                    raise ValueError('Conflicting fresh database placement')
                selectors['kubernetes.io/hostname'] = hostname
            if kind == 'Job':
                # First attempts only. A failure is an explicit review gate, not a retry loop.
                resource['spec']['backoffLimit'] = 0
                spec['restartPolicy'] = 'Never'
        if kind == 'PersistentVolume' and any('-'+target in name for target in TARGETS):
            pv = resource['spec']
            if not pv.get('hostPath',{}).get('path','').startswith('/storage/nfs/deployment-1/') or pv.get('nodeAffinity'):
                raise ValueError('Unreviewed backing-volume path or placement')
            pv['nodeAffinity'] = {'required':{'nodeSelectorTerms':[{'matchExpressions':[{
                'key':'kubernetes.io/hostname','operator':'In','values':[context['storage_node']['hostname']]}]}]}}
    return resources
