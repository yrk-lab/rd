#include "rle.c"

int rletests(void);

static int
testmemfill1(void)
{
	/* Fill with a pattern shorter than the destination (pattern repeats) */
	uchar dst[6];
	uchar pat[] = {0xAB, 0xCD};
	uchar want[] = {0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD};
	int i;

	memfill(dst, sizeof dst, pat, sizeof pat);
	for(i = 0; i < (int)sizeof dst; i++)
		if(dst[i] != want[i])
			sysfatal("testmemfill1: dst[%d]: want 0x%x, got 0x%x", i, want[i], dst[i]);
	return 0;
}

static int
testmemfill2(void)
{
	/* Fill with a pattern equal in length to the destination */
	uchar dst[4];
	uchar pat[] = {0x01, 0x02, 0x03, 0x04};
	int i;

	memfill(dst, sizeof dst, pat, sizeof pat);
	for(i = 0; i < (int)sizeof dst; i++)
		if(dst[i] != pat[i])
			sysfatal("testmemfill2: dst[%d]: want 0x%x, got 0x%x", i, pat[i], dst[i]);
	return 0;
}

static int
testmemfill3(void)
{
	/* Fill a single byte with a single-byte pattern */
	uchar dst[1] = {0x00};
	uchar pat[] = {0x42};

	memfill(dst, sizeof dst, pat, sizeof pat);
	if(dst[0] != 0x42)
		sysfatal("testmemfill3: dst[0]: want 0x42, got 0x%x", dst[0]);
	return 0;
}

static int
testmemfill4(void)
{
	/* Zero-length destination: no bytes written, returns a1 */
	uchar dst[1] = {0x99};
	uchar pat[] = {0x42};
	void *ret;

	ret = memfill(dst, 0, pat, sizeof pat);
	if(ret != dst)
		sysfatal("testmemfill4: return value: want dst, got something else");
	if(dst[0] != 0x99)
		sysfatal("testmemfill4: dst[0]: want 0x99, got 0x%x", dst[0]);
	return 0;
}

static int
testmemxor1(void)
{
	/* Basic XOR of two equal-length arrays */
	uchar a[] = {0xFF, 0x0F, 0xAA};
	uchar b[] = {0x0F, 0xFF, 0x55};
	uchar want[] = {0xF0, 0xF0, 0xFF};
	int i;

	memxor(a, b, sizeof a);
	for(i = 0; i < (int)sizeof a; i++)
		if((uchar)a[i] != want[i])
			sysfatal("testmemxor1: a[%d]: want 0x%x, got 0x%x", i, want[i], (uchar)a[i]);
	return 0;
}

static int
testmemxor2(void)
{
	/* XOR with zero-length: no bytes modified */
	uchar a[] = {0xAB, 0xCD};
	uchar b[] = {0xFF, 0xFF};

	memxor(a, b, 0);
	if(a[0] != 0xAB || a[1] != 0xCD)
		sysfatal("testmemxor2: unexpected modification: got 0x%x 0x%x", a[0], a[1]);
	return 0;
}

static int
testmemxor3(void)
{
	/* XOR with self yields all zeros */
	uchar a[] = {0x12, 0x34, 0x56};
	int i;

	memxor(a, a, sizeof a);
	for(i = 0; i < (int)sizeof a; i++)
		if(a[i] != 0)
			sysfatal("testmemxor3: a[%d]: want 0, got 0x%x", i, a[i]);
	return 0;
}

static int
testmemxor4(void)
{
	/* XOR with all-zero array leaves original unchanged */
	uchar a[] = {0xDE, 0xAD, 0xBE, 0xEF};
	uchar z[] = {0x00, 0x00, 0x00, 0x00};
	uchar orig[] = {0xDE, 0xAD, 0xBE, 0xEF};
	int i;

	memxor(a, z, sizeof a);
	for(i = 0; i < (int)sizeof a; i++)
		if(a[i] != orig[i])
			sysfatal("testmemxor4: a[%d]: want 0x%x, got 0x%x", i, orig[i], a[i]);
	return 0;
}

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
	testmemfill1();
	testmemfill2();
	testmemfill3();
	testmemfill4();
	testmemxor1();
	testmemxor2();
	testmemxor3();
	testmemxor4();
	testunrle1();
	testunrle2();
	testunrle3();
	return 0;
}
