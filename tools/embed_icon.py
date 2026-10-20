from pathlib import Path
p=Path(__file__).resolve().parents[1]
b=(p/'assets/icon0.png').read_bytes()
(p/'build/generated').mkdir(parents=True,exist_ok=True)
(p/'build/generated/icon.h').write_text('/* Generated Goda icon */\nstatic const unsigned char panel_icon[]={'+','.join(map(str,b))+'};\n')
