"""Exercise the real collector over local sockets, never the PS5."""
import sys,json,base64,socket,threading,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'diagnostics'))
from record_live_logs import Collector,validate_record

def frame(seq,data=b'test',channel='klog'):
 return (json.dumps(dict(v=1,seq=seq,mono_us=seq*100,channel=channel,offset=-1,data_b64=base64.b64encode(data).decode()))+'\n').encode()
with tempfile.TemporaryDirectory() as temp:
 output=Path(temp)/'capture';collector=Collector({'token':'a'*64,'console_ip':'127.0.0.1','collector_ip':'127.0.0.1','reader_sha256':'fixture'},output)
 def session(body,token='a'*64):
  server=socket.socket();server.bind(('127.0.0.1',0));server.listen(1);errors=[]
  def accept():
   conn,peer=server.accept()
   with conn:
    try:collector.connection(conn,peer)
    except ValueError as e:errors.append(str(e))
   server.close()
  thread=threading.Thread(target=accept);thread.start()
  with socket.create_connection(server.getsockname(),timeout=2) as client:
   client.sendall(('PS4FL-LIVE/1 '+token+' 123-456\n').encode()+body)
  thread.join(3);assert not thread.is_alive();return errors
 assert not session(frame(1,b'kernel\x00data\n')+frame(2,b'mount begin\n','audit'))
 assert not session(frame(2,b'mount begin\n','audit')+frame(3,b'mount end\n','audit')+frame(5,b'LOSS kernel_bytes=4096','status'))
 assert session(frame(6),token='b'*64)==['authentication failed']
 assert session(frame(6,channel='../save'))==['invalid channel or offset']
 for raw in [b'[]\n',b'null\n',b'{"v":1}\n',frame(0),frame(1,b'x'*4097),frame(1,channel='unlisted')]:
  try:validate_record(raw);raise AssertionError('malformed frame accepted')
  except ValueError:pass
 assert collector.duplicates==1 and collector.gaps==1 and collector.record_count==4
 state=dict(busy=False,runtime_active=False,runtime_phase=0,native_home_launch_supported=False,message='Closed',job='launch',serial=1,result=0,done=0,total=0)
 runtime=(json.dumps(dict(v=1,version='test',loader_pid=123,started_us=100,mono_us=200,state=state))+'\n').encode()
 assert not session(frame(6,runtime[:30],'runtime')+frame(7,runtime[30:],'runtime'))
 cached=json.loads((output/'runtime-state.json').read_text());assert cached['snapshot']['state']==state and cached['connected'] is False
 collector.close();assert (output/'123-456-klog.log').read_bytes()==b'kernel\x00data\n';assert (output/'123-456-audit.log').read_bytes()==b'mount begin\nmount end\n'
 manifest=json.loads((output/'manifest.json').read_text());assert manifest['records']==6 and manifest['gaps']==1
 assert (output/'records.jsonl').stat().st_mode&0o777==0o600
 print('PASS: local socket capture, reconnect, replay deduplication, gap records, binary data preservation, authentication and path rejection, durable files')
