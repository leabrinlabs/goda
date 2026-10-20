"""Build a passive reader and private collector config. Does not connect/deploy."""
import argparse,hashlib,ipaddress,json,os,secrets,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--collector-ip',required=True);p.add_argument('--console-ip',required=True);p.add_argument('--sdk',type=Path,default=Path(os.environ.get('PS5_PAYLOAD_SDK','/opt/ps5-payload-sdk')));p.add_argument('--port',type=int,default=19146);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 for value in [a.collector_ip,a.console_ip]:
  ip=ipaddress.IPv4Address(value)
  if not ip.is_private:raise SystemExit('Only private/local addresses are supported')
 if not 1024<=a.port<=65535:raise SystemExit('Invalid port')
 a.output.mkdir(parents=True,exist_ok=False,mode=0o700);token=secrets.token_hex(32);out=a.output/'ps4fl-live-reader.elf'
 env=dict(os.environ)
 cmd=[str(a.sdk/'bin/prospero-clang'),'-O2','-Wall','-Wextra','-Werror','-I'+str(ROOT/'vendor/shadowmount/include'),'-DFL_COLLECTOR_IP='+json.dumps(a.collector_ip),'-DFL_LIVE_TOKEN='+json.dumps(token),'-DFL_COLLECTOR_PORT='+str(a.port),str(ROOT/'diagnostics/live_log_reader.c'),'-o',str(out),'-lkernel_sys']
 subprocess.run(cmd,env=env,check=True);os.chmod(out,0o600)
 conf={'version':1,'collector_ip':a.collector_ip,'console_ip':a.console_ip,'port':a.port,'token':token,'reader_elf':str(out.resolve()),'reader_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'prepared_only':True,'deployed':False,'game_launch_capability':False}
 config=a.output/'config.json';config.write_text(json.dumps(conf,indent=2)+'\n');os.chmod(config,0o600)
 print('Prepared passive reader and private config; not deployed. '+str(a.output.resolve()))
if __name__=='__main__':main()
