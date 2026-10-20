from pathlib import Path
p=Path(__file__).resolve().parent
b=(p/'icon0.png').read_bytes()
(p/'icon.h').write_text('/* Generated Goda icon */\nstatic const unsigned char panel_icon[]={'+','.join(map(str,b))+'};\n')
