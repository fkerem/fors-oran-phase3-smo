"""Independent synthetic DMAAP wire model, never an exact-image substitute."""
import copy
import json


def plan():
    location = 'fixture-location'
    role = {'dcaeLocationName': location, 'clientRole': 'org.fixture.client', 'action': ['pub', 'sub']}
    identities = [{'dcaeLocationName': location, 'clientIdentity': n+'@fixture.invalid', 'action': ['pub', 'sub', 'view']}
                  for n in ('bridge','manager','demo')]
    bodies = [
        {'dmaapName': 'fixture', 'drProvUrl': 'https://localhost:18443', 'version': '1',
         'topicNsRoot': 'org.fixture', 'bridgeAdminTopic': 'mirrormakeragent'},
        {'dcaeLayer': 'central', 'dcaeLocationName': location},
        {'dcaeLocationName': location, 'fqdn': 'localhost', 'topicProtocol': 'http', 'topicPort': '18080'},
        *[{'clients': [copy.deepcopy(role)], 'owner': 'fixture', 'tnxEnabled': False,
           'topicDescription': 'synthetic '+n, 'topicName': n} for n in ('PNF_READY', 'PNF_REGISTRATION')],
        {'clients': identities, 'owner': 'fixture', 'tnxEnabled': False, 'topicDescription': 'synthetic bridge',
         'topicName': 'mirrormakeragent', 'partitionCount': '1', 'replicationCase': 'REPLICATION_NONE'}]
    names = [('dmaap','onap.json'), ('dcaeLocations','san-francisco.json'), ('mr_clusters','san-francisco.json'),
             ('topics','PNF_READY.json'), ('topics','PNF_REGISTRATION.json'), ('topics','mirrormakeragent.json')]
    return [dict(route=r, file=f, body=b) for (r,f),b in zip(names,bodies)]


class Journal:
    def __init__(self, binding):
        self.record = {'state': 'prepared', 'binding': copy.deepcopy(binding)}
        self.version = 1
        self.history = []

    def read(self):
        return dict(copy.deepcopy(self.record), _resourceVersion=str(self.version))

    def cas(self, old, new):
        if self.read() != old:
            raise ValueError('Fixture CAS conflict')
        self.record = {k:copy.deepcopy(v) for k,v in new.items() if not k.startswith('_')}
        self.history.append(copy.deepcopy(self.record))
        self.version += 1


class State:
    def __init__(self, fault=None):
        self.fault = fault
        self.data = {n: [] for n in ('dcaeLocations','mr_clusters','topics','mr_clients','dr_nodes','feeds','dr_pubs','dr_subs')}
        self.data['dmaap'] = dict.fromkeys(('dmaapName','topicNsRoot','drProvUrl','bridgeAdminTopic',
                                          'loggingUrl','nodeKey','accessKeyOwner'), '')
        self.data['dmaap'].update(version='0',status='NEW',statusValid=False,lastMod=0)
        self.requests = []

    def request(self, method, path, data=None):
        self.requests.append((method,path))
        route=path.rsplit('/',1)[-1]
        if route not in self.data: return 404,b'{}'
        if method=='GET':
            body=copy.deepcopy(self.data[route])
            if self.fault=='read-drift' and route=='dmaap' and body['version']!='0': body['dmaapName']='changed'
            return 200,json.dumps(body).encode()
        if method!='POST': return 405,b'{}'
        if self.fault in ('conflict','server-error','redirect','malformed'):
            code={'conflict':409,'server-error':500,'redirect':307,'malformed':200}[self.fault]
            return code,b'{' if self.fault=='malformed' else b'{}'
        value=copy.deepcopy(data)
        value.update(status='VALID',statusValid=True,lastMod=1)
        if route=='topics':
            value['tnxEnabled']='true' if value['tnxEnabled'] else 'false'
            value['fqtn']='org.fixture.'+value['topicName']
            for client in value['clients']:
                client.update(fqtn=value['fqtn'],mrClientId=str(len(self.data['mr_clients'])+1),
                              topicURL='http://localhost/topic',status='VALID',statusValid=True)
                self.data['mr_clients'].append(copy.deepcopy(client))
        if route=='dmaap': self.data[route]=copy.deepcopy(value)
        else: self.data[route].append(copy.deepcopy(value))
        if self.fault=='lost-response': raise ConnectionError('Fixture response lost after commit')
        return (200 if route=='dmaap' else 201),json.dumps(value).encode()


class KubeState:
    path='/api/v1/namespaces/onap/configmaps/phase3-dmaap-journal'

    def __init__(self,fault='success'):
        self.fault=fault;self.requests=[];self.version=1
        self.record={'state':'prepared','binding':{'fixture':'exact-images'}}

    def object(self):
        return {'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'phase3-dmaap-journal',
            'namespace':'onap','uid':'fixture-journal','resourceVersion':str(self.version)},
            'data':{'journal.json':json.dumps(self.record)}}

    def request_with_headers(self,method,path,data,headers):
        self.requests.append((method,path))
        if path!=self.path or headers.get('Authorization')!='Bearer synthetic-fixture-token':return 403,b'{}'
        if method=='GET':
            if self.fault=='read-403':return 403,b'{}'
            if self.fault=='read-redirect':return 307,b'{}'
            if self.fault=='malformed':return 200,b'{'
            if self.fault=='oversized':return 200,b' '*(1024*1024+1)
            obj=self.object()
            if self.fault=='read-uid':obj['metadata']['uid']='replaced'
        elif method=='PUT':
            if self.fault=='write-500':return 500,b'{}'
            if self.fault=='write-redirect':return 307,b'{}'
            m=data.get('metadata',{})
            if (m.get('name')!='phase3-dmaap-journal' or m.get('namespace')!='onap'
                    or m.get('uid')!='fixture-journal' or m.get('resourceVersion')!=str(self.version)):
                return 409,b'{}'
            self.record=json.loads(data['data']['journal.json']);self.version+=1
            if any(k.startswith('_') for k in self.record):return 400,b'{}'
            if self.fault=='lost-commit':raise ConnectionError('Synthetic acknowledgement loss')
            obj=self.object()
            if self.fault=='write-uid':obj['metadata']['uid']='replaced'
        else:return 405,b'{}'
        return 200,json.dumps(obj).encode()
