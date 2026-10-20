PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
CFLAGS := -O2 -std=gnu11 -Wall -Wextra -Werror -Ivendor/shadowmount/include
SOURCES := main.c catalog.c engine.c lifecycle.c browser.c audit.c module_alias.c extractor.c extract_reader.c vendor/pkg.c vendor/crypto.c vendor/zlib/zutil.c vendor/zlib/inflate.c vendor/zlib/inftrees.c vendor/zlib/inffast.c vendor/zlib/adler32.c vendor/zlib/crc32.c
CFLAGS += -DZ_SOLO -Ivendor/zlib
REG_SOURCES := registration.c registration_bridge.S launch_gate.c runtime_hooks.c runtime_bridge.S vendor/shadowmount/src/sm_shellcore_hooks.c vendor/shadowmount/src/sm_shellcore_remote.c vendor/shadowmount/src/sm_shellcore_offsets.c
all: candidate
candidate: dist/goda-v0.6.12.elf
assets.h: assets/brand-compact.png assets/brand-face.png assets/selection.png assets/launch.png embed_assets.py
	python3 embed_assets.py
ui.h: ui.html embed_ui.py
	python3 embed_ui.py
dist/goda-v0.6.12.elf: $(SOURCES) $(REG_SOURCES) http_policy.h registration_policy.h platform_at.h module_alias.h launch_gate.h launch_policy.h launch_observation.h lifecycle.h lifecycle_policy.h browser.h audit.h mount_snapshot.h runtime_symbols.h engine.h catalog.h extractor.h pkg_diagnostics.h extract_reader.h ui.h assets.h
	mkdir -p dist
	$(CC) $(CFLAGS) -DFL_LINK_VIEWS -DD3TR_REGISTRAR -ffunction-sections -fdata-sections -Wl,--gc-sections -o $@ $(SOURCES) $(REG_SOURCES) -lkernel_sys -lSceSystemService -lSceUserService -lpthread
host: $(SOURCES) ui.h assets.h
	mkdir -p dist
	/usr/bin/clang -DFL_HOST -DZ_SOLO -Ivendor/zlib -O1 -g -Wall -Wextra -Werror -o dist/loader-host $(SOURCES) -lpthread

# Current zero-copy lifecycle candidate; previous versioned binaries are preserved.
links: candidate

copy-fallback: dist/goda-v0.6.12-copy.elf
dist/goda-v0.6.12-copy.elf: $(SOURCES) $(REG_SOURCES) http_policy.h registration_policy.h platform_at.h module_alias.h launch_gate.h launch_policy.h launch_observation.h lifecycle.h lifecycle_policy.h browser.h audit.h mount_snapshot.h runtime_symbols.h engine.h catalog.h extractor.h pkg_diagnostics.h extract_reader.h ui.h assets.h
	mkdir -p dist
	$(CC) $(CFLAGS) -DD3TR_REGISTRAR -ffunction-sections -fdata-sections -Wl,--gc-sections -o $@ $(SOURCES) $(REG_SOURCES) -lkernel_sys -lSceSystemService -lSceUserService -lpthread

# Separate, explicit media-shortcut registration/update; never part of the UI build.
panel/icon.h: panel/icon0.png panel/embed_icon.py
	python3 panel/embed_icon.py
panel: dist/goda-shortcut.elf
dist/goda-shortcut.elf: panel/register.c panel/policy.h panel/panel_bridge.S panel/icon.h
	mkdir -p dist
	$(CC) $(CFLAGS) -DD3TR_REGISTRAR -ffunction-sections -fdata-sections -Wl,--gc-sections -o $@ panel/register.c panel/panel_bridge.S vendor/shadowmount/src/sm_shellcore_hooks.c vendor/shadowmount/src/sm_shellcore_remote.c vendor/shadowmount/src/sm_shellcore_offsets.c -lkernel_sys -lSceSystemService -lSceUserService -lpthread
