#!/usr/bin/env python3
"""Run synthetic host tests only; never connects to or deploys on a console."""
import argparse,os,shlex,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--crypto',action='store_true',help='also run independent Python cryptography comparisons')
 args=parser.parse_args();out=ROOT/'build/tests';out.mkdir(parents=True,exist_ok=True)
 cc=shlex.split(os.environ.get('HOST_CC','cc'))
 flags=['-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-I.','-Isrc','-Ibuild/generated','-Ivendor/shadowmount/include','-ffunction-sections','-fdata-sections','-Wl,-dead_strip' if sys.platform=='darwin' else '-Wl,--gc-sections']
 def run(cmd):subprocess.run(cmd,cwd=ROOT,check=True)
 cases=[('http_policy',[],[]),('launch_policy',[],[]),('launch_observation',[],[]),('registration_policy',[],[]),('browser',[],[]),('lifecycle',[],[]),
        ('extractor',['src/extractor.c','src/catalog.c','vendor/crypto.c','vendor/pkg.c'],['-DFL_HOST']),
        ('extract_reader',['vendor/pkg.c','vendor/crypto.c'],['-DFL_HOST','-lz']),
        ('module_alias',['src/module_alias.c','src/catalog.c','vendor/crypto.c'],['-DFL_HOST']),
        ('module_links',['src/module_alias.c','src/catalog.c','vendor/crypto.c'],['-DFL_HOST','-DFL_LINK_VIEWS']),
        ('worker_reopen',[],['-ffunction-sections','-fdata-sections','-Wl,-dead_strip' if sys.platform=='darwin' else '-Wl,--gc-sections']),
        ('log_reader',[],['-lpthread'])]
 for name,sources,extra in cases:
  binary=out/name
  run(cc+flags+[f'tests/test_{name}.c']+sources+extra+['-o',str(binary)])
  run([str(binary)]+([str(out/'reader-frame.json')] if name=='log_reader' else []))
 run(['node','tests/test_ui_status.mjs'])
 run([sys.executable,'tests/test_live_logs.py'])
 run([sys.executable,'tests/test_app.py'])
 if args.crypto:run([sys.executable,'tests/test_crypto_pkg.py'])
 print('PASS: all host tests; no console operation performed')
if __name__=='__main__':main()
