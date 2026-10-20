from pathlib import Path
p=Path(__file__).resolve().parent
b=(p/'ui.html').read_bytes()
(p/'ui.h').write_text('/* Generated from ui.html */\nstatic const unsigned char fl_ui[]={'+','.join(map(str,b))+',0};\n')
