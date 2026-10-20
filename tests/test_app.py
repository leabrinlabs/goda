"""Host integration: actual C server/parser; no console or real game mutation."""
from pathlib import Path
import tempfile,subprocess,urllib.request,urllib.parse,json,re,sys,time,hashlib,struct,http.client
ROOT=Path(__file__).resolve().parents[1]
from sfo_fixture import make_sfo
with tempfile.TemporaryDirectory(prefix='ps4-loader-test-') as tmp:
 base=Path(tmp).resolve();outside=base.parent/'loader-outside-fixture'
 def game(name,title,category='gd'):
  p=base/name;(p/'sce_sys').mkdir(parents=True);(p/'sce_sys/param.sfo').write_bytes(make_sfo({'TITLE_ID':name,'TITLE':title,'APP_VER':'01.00','CATEGORY':category}));(p/'eboot.bin').write_bytes(b'\x7fELF'+bytes(124));return p
 a=game('CUSA12344','Sample Game');b=game('CUSA12345','Test <script> & "quote"');(base/'Genre').mkdir();b.rename(base/'Genre'/'Any Game Name');b=base/'Genre'/'Any Game Name';game('CUSA99999','Patch','gp');(base/'CUSA00001').symlink_to(a,target_is_directory=True)
 bad=game('CUSA00002','Malformed');sfo=bad/'sce_sys/param.sfo';data=bytearray(sfo.read_bytes());struct.pack_into('<I',data,12,0xffffffff);sfo.write_bytes(data)
 before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in base.rglob('*') if p.is_file()}
 proc=subprocess.Popen([str(ROOT/'dist/loader-host'),str(base)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 def req(op,auth=True,**kw):
  body=urllib.parse.urlencode({'op':op,**({'token':token} if auth else {}),**kw}).encode();r=urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:9134/api',data=body),timeout=5);return json.load(r)
 try:
  for i in range(40):
   try:html=urllib.request.urlopen('http://127.0.0.1:9134/',timeout=1).read().decode();break
   except OSError:time.sleep(.05)
  else:raise AssertionError('server did not start')
  token=re.search("const token='([0-9a-f]+)'",html)[1];assert len(token)==48
  for name in ['brand-compact','brand-face','selection','launch']:
   data=urllib.request.urlopen('http://127.0.0.1:9134/assets/'+name+'.png',timeout=3).read();assert data==(ROOT/'assets'/f'{name}.png').read_bytes()
  try:urllib.request.urlopen('http://127.0.0.1:9134/assets/../main.c',timeout=3);raise AssertionError('asset path traversal accepted')
  except urllib.error.HTTPError as e:assert e.code==404

  try:req('scan',auth=False,path=str(base));raise AssertionError('missing CSRF accepted')
  except urllib.error.HTTPError as e:assert e.code==403
  # Even a valid API token must not allow a browser from a foreign origin.
  def raw_request(method,headers,body=b''):
   c=http.client.HTTPConnection('127.0.0.1',9134,timeout=3);c.putrequest(method,'/api' if method=='POST' else '/',skip_host=True)
   for key,value in headers:c.putheader(key,value)
   if method=='POST':c.putheader('Content-Length',str(len(body)))
   c.endheaders(body);r=c.getresponse();code=r.status;data=r.read();c.close();return code,data
  attack_body=urllib.parse.urlencode({'op':'scan','token':token,'path':str(base)}).encode()
  for method,headers in [('GET',[('Host','example.invalid:9134')]),('GET',[]),('GET',[('Host','127.0.0.1:9134'),('Host','127.0.0.1:9134')]),('GET',[('Host','localhost:9134'),('Sec-Fetch-Site','cross-site')]),('POST',[('Host','127.0.0.1:9134'),('Origin','http://example.invalid')]),('POST',[('Host','127.0.0.1:9134'),('Origin','null')])]:
   code,data=raw_request(method,headers,attack_body if method=='POST' else b'');assert code==403 and token.encode() not in data,(code,data)
  code,data=raw_request('POST',[('Host','127.0.0.1:9134'),('Origin','http://127.0.0.1:9134')],urllib.parse.urlencode({'op':'state','token':token}).encode());assert code==200 and json.loads(data)['serial']==0
  got=req('scan',path=str(base));assert {g['id'] for g in got['games']}=={'CUSA12344','CUSA12345'},got
  # The resident process emits the same state without a control request.
  telemetry=base/'.loader-preview/runtime.log'
  for _ in range(80):
   if telemetry.exists():break
   time.sleep(.05)
  snapshot=json.loads(telemetry.read_text().splitlines()[-1])
  assert snapshot['v']==1 and snapshot['loader_pid']==proc.pid and snapshot['state']['serial']==0,snapshot
  assert not snapshot['state']['busy'] and not snapshot['state']['runtime_active']
  sys.path.insert(0,str(ROOT/'diagnostics'))
  from record_live_logs import Collector
  from runtime_state import read_runtime_state
  captured=base/'.loader-preview/capture-fixture'
  collector=Collector({'console_ip':'127.0.0.1','collector_ip':'127.0.0.1','token':'fixture'},captured)
  collector.runtime_data('host-fixture',(json.dumps(snapshot)+'\n').encode(),snapshot['mono_us']+100)
  session=base/'.loader-preview/session.json';session.write_text(json.dumps({'output':str(captured)}))
  assert read_runtime_state(session)['_telemetry']['loader_pid']==proc.pid
  collector.close()
  with telemetry.open('ab') as log:log.truncate(2*1024*1024)
  for _ in range(80):
   if telemetry.stat().st_size<1024*1024:break
   time.sleep(.05)
  assert telemetry.stat().st_size<1024*1024
  assert json.loads(telemetry.read_text().splitlines()[-1])['loader_pid']==proc.pid
  assert req('config')['root']==str(base)
  serial=req('state')['serial'];req('dismiss-ui')
  for _ in range(100):
   state=req('state')
   if not state['busy']:break
   time.sleep(.01)
  assert state['job']=='dismiss-ui' and state['serial']==serial+1 and not state['runtime_active'],state
  assert any(g['id']=='CUSA12345' and '/Genre/Any Game Name' in g['path'] for g in got['games'])
  assert all(g['release']=='' for g in got['games'])
  assert req('locations')['locations']==[{'name':'Önizleme diski','path':str(base)}]
  listing=req('browse',path=str(base));assert not listing['parent'];assert 'CUSA00001' not in {x['name'] for x in listing['directories']}
  try:req('browse',path='/');raise AssertionError('escape allowed')
  except urllib.error.HTTPError as e:assert e.code==400
  try:req('launch',id='CUSA77777');raise AssertionError('unlisted game accepted')
  except urllib.error.HTTPError as e:assert e.code==409
  req('launch',id='CUSA12344');time.sleep(.1);state=req('state');assert not state['busy'] and 'onizlemesi' in state['message'],state
  after={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in base.rglob('*') if p.is_file() and '.loader-preview' not in p.parts};assert before==after
  # All metadata fixtures are synthetic and self-contained.
  got=req('scan',path=str(base));assert any(g['id']=='CUSA12344' for g in got['games']),got
  # Duplicate title IDs must select by exact catalog path, never an arbitrary first match.
  import shutil
  shutil.copytree(a,base/'Sample Copy');got=req('scan',path=str(base));assert len([g for g in got['games'] if g['id']=='CUSA12344'])==2
  try:req('launch',id='CUSA12344');raise AssertionError('ambiguous title accepted')
  except urllib.error.HTTPError as e:assert e.code==409
  req('launch',id='CUSA12344',path=str(a));time.sleep(.1);assert not req('state')['busy']
  # Incomplete extraction must never become a launchable game.
  (a/'.ps4fl-incomplete').write_text('partial');got=req('scan',path=str(base));assert str(a) not in {g['path'] for g in got['games']};(a/'.ps4fl-incomplete').unlink()
  assert 'settingsPane' in html and 'pickPkg' in html and 'cancelExtract' in html
  pkg=base/'fixture.pkg';pkg.write_bytes(b'not a package')
  (base/'source-link.pkg').symlink_to(pkg)
  listed=req('files',path=str(base));assert {p['name'] for p in listed['packages']}=={'fixture.pkg'};assert listed['packages'][0]['size']==len(b'not a package')
  for source,target,code in [(str(base/'missing.pkg'),str(base),'GODA-PKG-SOURCE'),(str(pkg),'/','GODA-PKG-TARGET'),(str(base/'source-link.pkg'),str(base),'GODA-PKG-SOURCE'),('',str(base),'GODA-PKG-INPUT')]:
   try:req('extract',source=source,target=target);raise AssertionError('unsafe extraction accepted')
   except urllib.error.HTTPError as e:
    failure=json.load(e);assert e.code==400 and failure['code']==code and failure['detail'],failure
    assert req('state')['failure']==failure
  serial=req('state')['serial'];req('extract',source=str(pkg),target=str(base));
  for _ in range(100):
   state=req('state')
   if not state['busy']:break
   time.sleep(.01)
  assert state['job']=='extract' and state['result']!=0 and state['serial']==serial+1,state
  assert state['failure']['code']=='GODA-PKG-FORMAT' and state['failure']['detail']=='Invalid or unreadable package',state
  assert state['failure']['source']==str(pkg) and state['failure']['stage']=='Reading package inventory'
  failure=state['failure'];time.sleep(.1);assert req('state')['failure']==failure
  assert req('config')['extract_root']==str(base)
  assert pkg.read_bytes()==b'not a package'
  try:req('cancel');raise AssertionError('inactive cancel accepted')
  except urllib.error.HTTPError as e:assert e.code==409
  print('PASS: arbitrary names, nested discovery, duplicate-ID path selection, release display, discovery, synthetic SFO, patch/malformed/symlink rejection, path confinement, CSRF, selection, launch dispatch, source preservation.')
 finally:
  proc.terminate();proc.wait(timeout=5)
