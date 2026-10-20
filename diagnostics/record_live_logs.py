"""Authenticated, append-only log collector. Never controls the console."""
import argparse,base64,datetime,hashlib,hmac,json,os,re,socket,time
from pathlib import Path
from runtime_state import validate_snapshot
CHANNELS=frozenset(['klog','events','gate','lifecycle','modules','observation','browser','audit','status','runtime'])
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def validate_record(line):
 if len(line)>8192 or not line.endswith(b'\n'):raise ValueError('oversize or incomplete frame')
 d=json.loads(line)
 if not isinstance(d,dict) or set(d)!={'v','seq','mono_us','channel','offset','data_b64'} or type(d.get('v')) is not int or d['v']!=1:raise ValueError('invalid fields')
 for k in ['seq','mono_us']:
  if type(d[k]) is not int or not 0<d[k]<2**63:raise ValueError('invalid counter')
 if type(d['offset']) is not int or not -1<=d['offset']<2**63 or not isinstance(d['channel'],str) or d['channel'] not in CHANNELS:raise ValueError('invalid channel or offset')
 if not isinstance(d['data_b64'],str) or len(d['data_b64'])>5464:raise ValueError('invalid payload')
 data=base64.b64decode(d['data_b64'],validate=True)
 if len(data)>4096:raise ValueError('payload too large')
 return d,data
class Collector:
 def __init__(self,config,output):
  self.config=config;self.output=Path(output);self.output.mkdir(parents=True,exist_ok=False,mode=0o700)
  self.events=self.output.joinpath('records.jsonl').open('xb');os.chmod(self.events.name,0o600)
  self.files={};self.last={};self.digests={};self.record_count=0;self.gaps=0;self.duplicates=0
  self.runtime_buffers={};self.runtime_latest=None
  self.meta={'version':1,'started_utc':utc(),'reader_sha256':config.get('reader_sha256'),'console_ip':config['console_ip'],'collector_ip':config['collector_ip'],'limitations':['TCP and the kernel ring cannot guarantee delivery of every final byte during power loss.','Kernel log reads may consume the shared ring.','No console commands, launches or deployment are performed by the collector.']}
  self.output.joinpath('manifest.json').write_text(json.dumps(self.meta,indent=2)+'\n')
 def event(self,event):
  self.events.write((json.dumps({'received_utc':utc(),**event},ensure_ascii=False)+'\n').encode());self.events.flush();os.fsync(self.events.fileno())
 def save_runtime(self):
  path=self.output/'runtime-state.new'
  with path.open('w',encoding='utf-8') as f:
   os.chmod(path,0o600);json.dump(self.runtime_latest,f,ensure_ascii=False);f.write('\n');f.flush();os.fsync(f.fileno())
  path.replace(self.output/'runtime-state.json')
 def runtime_data(self,reader,data,frame_mono_us):
  buf=self.runtime_buffers.get(reader,b'')+data
  while b'\n' in buf:
   line,buf=buf.split(b'\n',1)
   try:
    if len(line)>8192:raise ValueError('oversized runtime line')
    snapshot=validate_snapshot(json.loads(line))
    if not 0<=frame_mono_us-snapshot['mono_us']<=10000000:raise ValueError('stale runtime source')
    old=self.runtime_latest
    if old and old['reader']==reader and old['snapshot']['loader_pid']==snapshot['loader_pid'] and old['snapshot']['started_us']==snapshot['started_us'] and snapshot['mono_us']<old['snapshot']['mono_us']:
     raise ValueError('runtime clock regressed')
    self.runtime_latest={'format':1,'reader':reader,'connected':True,'received_utc':utc(),'frame_mono_us':frame_mono_us,'snapshot':snapshot};self.save_runtime()
   except (ValueError,TypeError,KeyError,UnicodeError) as e:
    self.event({'event':'runtime_snapshot_rejected','reader':reader,'reason':str(e)[:120]})
  if len(buf)>8192:
   buf=b'';self.event({'event':'runtime_snapshot_rejected','reader':reader,'reason':'oversized incomplete runtime line'})
  self.runtime_buffers[reader]=buf
 def connection(self,conn,peer):
  if peer[0]!=self.config['console_ip']:raise ValueError('unexpected peer')
  conn.settimeout(5);stream=conn.makefile('rb');hello=stream.readline(256)
  try:fields=hello.decode('ascii').strip().split()
  except UnicodeError:raise ValueError('invalid handshake')
  if len(fields)!=3 or fields[0]!='PS4FL-LIVE/1' or not hmac.compare_digest(fields[1],self.config['token']) or not re.fullmatch(r'[0-9]+-[0-9]+',fields[2]):raise ValueError('authentication failed')
  reader=fields[2];self.runtime_buffers.pop(reader,None);self.event({'event':'connected','reader':reader})
  try:
   while True:
    try:line=stream.readline(8193)
    except (TimeoutError,OSError) as e:
     self.event({'event':'read_timeout_or_disconnect','reader':reader,'reason':type(e).__name__});break
    if not line:break
    d,data=validate_record(line);seq=d['seq'];key=(reader,seq);digest=hashlib.sha256(line).hexdigest();prev=self.last.get(reader,0)
    if seq<=prev:
     if self.digests.get(key)!=digest:raise ValueError('sequence reused with different data')
     self.duplicates+=1;continue
    if seq!=prev+1:self.gaps+=1;self.event({'event':'sequence_gap','reader':reader,'expected':prev+1,'actual':seq})
    filekey=(reader,d['channel'])
    if filekey not in self.files:
     path=self.output/(reader+'-'+d['channel']+'.log');self.files[filekey]=path.open('xb');os.chmod(path,0o600)
    f=self.files[filekey];f.write(data);f.flush();os.fsync(f.fileno())
    self.event({'event':'data','reader':reader,**d});self.record_count+=1;self.last[reader]=seq;self.digests[key]=digest
    if d['channel']=='runtime':self.runtime_data(reader,data,d['mono_us'])
    # Bounded replay window; old duplicates are rejected rather than appended.
    if len(self.digests)>4096:self.digests.pop(next(iter(self.digests)))
  finally:
   stream.close();self.event({'event':'disconnected','reader':reader,'last_seq':self.last.get(reader,0)})
   if self.runtime_latest and self.runtime_latest['reader']==reader:
    self.runtime_latest['connected']=False;self.save_runtime()
   self.runtime_buffers.pop(reader,None)
 def close(self):
  if self.runtime_latest:
   self.runtime_latest['connected']=False;self.save_runtime()
  for f in self.files.values():f.flush();os.fsync(f.fileno());f.close()
  self.meta.update(stopped_utc=utc(),records=self.record_count,gaps=self.gaps,duplicates=self.duplicates)
  self.output.joinpath('manifest.json').write_text(json.dumps(self.meta,indent=2)+'\n');self.events.flush();os.fsync(self.events.fileno());self.events.close()
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();config=json.loads(args.config.read_text())
 collector=Collector(config,args.output);server=socket.socket();server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind((config['collector_ip'],config['port']));server.listen(1);server.settimeout(1)
 print('Passive collector ready; no console payload is sent.',flush=True)
 try:
  while True:
   try:conn,peer=server.accept()
   except socket.timeout:continue
   with conn:
    try:collector.connection(conn,peer)
    except (ValueError,UnicodeError,json.JSONDecodeError,OSError) as e:collector.event({'event':'rejected_connection','reason':str(e)[:160]})
 except KeyboardInterrupt:pass
 finally:server.close();collector.close()
if __name__=='__main__':main()
