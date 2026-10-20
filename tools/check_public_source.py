#!/usr/bin/env python3
"""Read-only checks for accidental private material in the public source tree.
This is a publication guard, not a complete security/vulnerability audit.
Only paths/categories are reported; matched credential values are never printed.
"""
from pathlib import Path
import ipaddress,re,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
PATTERNS={
 'personal filesystem path':re.compile(r'(?:/'+'Users'+r'/[^/\s]+/|/'+'home'+r'/[^/\s]+/|[A-Za-z]:\\Users\\[^\\\s]+\\)'),
 'GitHub access token':re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b'),
 'cloud access key':re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
 'service credential':re.compile(r'\b(?:xox[baprs]-[A-Za-z0-9-]{20,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,})\b'),
 'private key PEM':re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'),
}
IP=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
BLOCKED={'.pkg','.elf','.bin','.cpk','.sprx','.prx','.self','.sfo','.db','.sqlite','.sqlite3','.jsonl','.log','.pyc','.pem','.key','.p12','.pfx'}
def main():
 raw=subprocess.check_output(['git','-C',str(ROOT),'ls-files','--cached','--others','--exclude-standard','-z'])
 paths=sorted(set(raw.decode().split('\0'))-{''});issues=[]
 for name in paths:
  p=ROOT/name
  if not p.exists():continue
  if p.is_symlink() or p.suffix.lower() in BLOCKED or any(x in p.parts for x in ('dist','__pycache__')):
   issues.append((name,'private/generated artifact'));continue
  if p.suffix.lower()=='.png':
   if name not in {'panel/icon0.png','assets/brand-compact.png','assets/brand-face.png','assets/selection.png','assets/launch.png'}:issues.append((name,'unapproved image asset'))
   continue
  try:text=p.read_text()
  except UnicodeError:issues.append((name,'unexpected binary'));continue
  for category,pattern in PATTERNS.items():
   if pattern.search(text):issues.append((name,category))
  for match in IP.finditer(text):
   try:address=ipaddress.ip_address(match.group())
   except ValueError:continue
   if address.is_private and not address.is_loopback and not address.is_unspecified:
    issues.append((name,'private device address'));break
 for name,category in issues:print(f'FAIL {name}: {category}')
 print(f'{"FAIL" if issues else "PASS"}: {len(paths)} public source paths checked; no secret values printed')
 return bool(issues)
if __name__=='__main__':sys.exit(main())
