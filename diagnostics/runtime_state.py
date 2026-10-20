"""Read resident-loader telemetry already captured on this PC. No network I/O."""
import argparse,datetime,json
from pathlib import Path

def validate_snapshot(value):
    if not isinstance(value,dict) or type(value.get('v')) is not int or value['v']!=1:
        raise ValueError('Invalid runtime snapshot')
    for key in ('loader_pid','started_us','mono_us'):
        if type(value.get(key)) is not int or not 0<value[key]<2**63:
            raise ValueError('Invalid runtime identity')
    if value['mono_us']<value['started_us'] or not isinstance(value.get('version'),str) or not 1<=len(value['version'])<=64:
        raise ValueError('Invalid runtime version or clock')
    state=value.get('state')
    if not isinstance(state,dict):raise ValueError('Missing runtime state')
    for key in ('busy','runtime_active','native_home_launch_supported'):
        if type(state.get(key)) is not bool:raise ValueError('Invalid runtime flag')
    phase=state.get('runtime_phase')
    if type(phase) is not int or not 0<=phase<=3 or bool(phase)!=state['runtime_active']:
        raise ValueError('Invalid runtime phase')
    for key in ('serial','done','total'):
        if type(state.get(key)) is not int or not 0<=state[key]<2**64:
            raise ValueError('Invalid runtime counter')
    if type(state.get('result')) is not int or not -2**31<=state['result']<2**31:
        raise ValueError('Invalid runtime result')
    if state.get('job') not in ('','launch','extract','permissions','dismiss-ui') or not isinstance(state.get('message'),str) or len(state['message'])>512:
        raise ValueError('Invalid runtime message or job')
    return value

def read_runtime_state(session_file=None,*,now=None,max_age=10):
    """Fail closed on missing/stale/disconnected capture; never deploy a helper."""
    if session_file is None:
        session_file=Path(__file__).resolve().parents[1]/'dist/live-captures/active_session.json'
    try:
        session=json.loads(Path(session_file).read_text())
        path=Path(session['output'])/'runtime-state.json'
        raw=path.read_bytes()
        if len(raw)>16384:raise ValueError('Oversized runtime snapshot')
        cached=json.loads(raw);snapshot=validate_snapshot(cached['snapshot'])
        if cached.get('connected') is not True:raise ValueError('Log stream is disconnected')
        received=datetime.datetime.fromisoformat(cached['received_utc'])
        if received.tzinfo is None:raise ValueError('Missing capture timezone')
        if now is None:now=datetime.datetime.now(datetime.timezone.utc)
        age=(now-received).total_seconds()
        if not 0<=age<=max_age:raise ValueError('Runtime snapshot is stale or future-dated')
        result=dict(snapshot['state'])
        result['_telemetry']={'source':str(path),'received_utc':cached['received_utc'],'age_seconds':age,'reader':cached['reader'],'loader_pid':snapshot['loader_pid'],'started_us':snapshot['started_us'],'version':snapshot['version']}
        return result
    except (OSError,ValueError,KeyError,TypeError) as error:
        raise RuntimeError('No verified live runtime state in local logs; no console request was sent: '+str(error)) from error

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session',type=Path)
    args=parser.parse_args()
    try:print(json.dumps(read_runtime_state(args.session),ensure_ascii=False,indent=2))
    except RuntimeError as error:parser.exit(1,str(error)+'\n')
