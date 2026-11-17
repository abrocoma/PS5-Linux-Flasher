SDK ?= /opt/ps5-payload-sdk
CC := $(SDK)/bin/prospero-clang
STRIP := $(SDK)/bin/prospero-strip
ELF := Linux_Flasher.elf

all: $(ELF)

# personal build: adds a Boot Linux button (downloads soniciso1's newest ps5-linux-loader)
personal: Linux_Flasher_personal.elf

# page.html -> C string literal
page.html.h: page.html
	sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/' -e 's/$$/\\n"/' $< > $@

$(ELF): main.c tile.c flash.c flash.h flash_api.inc download.c download.h net.c net.h drivename.c drivename.h sha256.c page.html.h assets/param.json assets/icon0.png
	$(CC) -Os -Wall -Wno-unused-parameter -I. -Ixz -o $@ main.c tile.c flash.c download.c net.c drivename.c sha256.c xz/xz_crc32.c xz/xz_crc64.c xz/xz_dec_lzma2.c xz/xz_dec_stream.c -lSceHttp -lSceSsl -lSceNet -lSceSystemService -lSceUserService -lSceAppInstUtil -lpthread
	$(STRIP) $@
	@sha256sum $@; ls -lh $@

Linux_Flasher_personal.elf: main.c tile.c boot.c flash.c flash.h flash_api.inc download.c download.h net.c net.h drivename.c drivename.h sha256.c page.html.h assets/param.json assets/icon0.png
	$(CC) -Os -Wall -Wno-unused-parameter -DWITH_LOADER -I. -Ixz -o $@ main.c tile.c boot.c flash.c download.c net.c drivename.c sha256.c xz/xz_crc32.c xz/xz_crc64.c xz/xz_dec_lzma2.c xz/xz_dec_stream.c -lSceHttp -lSceSsl -lSceNet -lSceSystemService -lSceUserService -lSceAppInstUtil -lpthread
	$(STRIP) $@
	@sha256sum $@; ls -lh $@

clean:
	rm -f $(ELF) Linux_Flasher_personal.elf page.html.h
.PHONY: all personal clean
