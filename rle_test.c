#include "rle.c"

int rletests(void);

static int
testunrle1(void)
{
	/* Bpix extended opcode (0xFE): sets the current pixel to zero */
	uchar src[] = {0xFE};
	uchar dst[1];
	uchar *end;

	end = unrle(dst, sizeof dst, src, sizeof src, 2, 1);
	if(end == nil)
		sysfatal("testunrle1: unexpected error: %r");
	if(end - dst != 1)
		sysfatal("testunrle1: length: want 1, got %d", (int)(end - dst));
	if(dst[0] != 0)
		sysfatal("testunrle1: pixel: want 0, got %d", dst[0]);
	return 0;
}

static int
testunrle2(void)
{
	/*
	 * Bg opcode on the first scan line (no previous line):
	 * memset(wp, 0, len) zero-fills the output.
	 * hdr=0x01: standard header, code=0 (Bg), raw_len=1 → len=1 pixel.
	 */
	uchar src[] = {0x01};
	uchar dst[1];
	uchar *end;

	end = unrle(dst, sizeof dst, src, sizeof src, 4, 1);
	if(end == nil)
		sysfatal("testunrle2: unexpected error: %r");
	if(end - dst != 1)
		sysfatal("testunrle2: length: want 1, got %d", (int)(end - dst));
	if(dst[0] != 0)
		sysfatal("testunrle2: pixel: want 0, got %d", dst[0]);
	return 0;
}

static int
testunrle3(void)
{
	/*
	 * Mix opcode on the first scan line with an all-zero mask byte:
	 * memset(wp, 0, pixelsize) zero-fills each pixel whose mask bit is 0.
	 * hdr=0x41: standard header, code=4 (Mix), raw_len=1 → len=8 pixels.
	 * mask=0x00: all bits 0, so all 8 pixels are zero-filled.
	 */
	uchar src[] = {0x41, 0x00};
	uchar dst[8];
	uchar *end;
	int i;

	memset(dst, 0xFF, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrle3: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrle3: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != 0)
			sysfatal("testunrle3: dst[%d]: want 0, got %d", i, dst[i]);
	return 0;
}

int
rletests(void)
{
	testunrle1();
	testunrle2();
	testunrle3();
	return 0;
}
