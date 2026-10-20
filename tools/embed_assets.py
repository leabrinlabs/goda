from pathlib import Path
r=Path(__file__).resolve().parents[1]
names=['brand-compact','brand-face','selection','launch']
(r/'build/generated').mkdir(parents=True,exist_ok=True)
with (r/'build/generated/assets.h').open('w') as out:
 out.write('/* Generated from the selected Goda PNG assets. */\n#include <stddef.h>\n')
 for i,name in enumerate(names):
  b=(r/'assets'/f'{name}.png').read_bytes();assert b[:8]==b'\x89PNG\r\n\x1a\n' and len(b)<=2*1024*1024
  out.write(f'static const unsigned char fl_art_{i}[]={{'+','.join(map(str,b))+'};\n')
 out.write('static const struct {const char *route;const unsigned char *data;size_t size;} fl_assets[]={\n')
 for i,name in enumerate(names):out.write(f'{{"/assets/{name}.png",fl_art_{i},sizeof(fl_art_{i})}},\n')
 out.write('};\n')
