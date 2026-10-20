from pathlib import Path
p=Path(__file__).resolve().parents[1]
b=(p/'web/ui.html').read_bytes()
(p/'build/generated').mkdir(parents=True,exist_ok=True)
(p/'build/generated/ui.h').write_text('/* Generated from web/ui.html */\nstatic const unsigned char fl_ui[]={'+','.join(map(str,b))+',0};\n')
