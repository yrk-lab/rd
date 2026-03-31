#include "rle.c"

int rletests(void);

static int
testmemfillrepeat(void)
{
	/* Fill with a pattern shorter than the destination (pattern repeats) */
	uchar dst[6];
	uchar pat[] = {0xAB, 0xCD};
	uchar want[] = {0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD};
	int i;

	memfill(dst, sizeof dst, pat, sizeof pat);
	for(i = 0; i < (int)sizeof dst; i++)
		if(dst[i] != want[i])
			sysfatal("testmemfillrepeat: dst[%d]: want 0x%x, got 0x%x", i, want[i], dst[i]);
	return 0;
}

static int
testmemfillexact(void)
{
	/* Fill with a pattern equal in length to the destination */
	uchar dst[4];
	uchar pat[] = {0x01, 0x02, 0x03, 0x04};
	int i;

	memfill(dst, sizeof dst, pat, sizeof pat);
	for(i = 0; i < (int)sizeof dst; i++)
		if(dst[i] != pat[i])
			sysfatal("testmemfillexact: dst[%d]: want 0x%x, got 0x%x", i, pat[i], dst[i]);
	return 0;
}

static int
testmemfill1byte(void)
{
	/* Fill a single byte with a single-byte pattern */
	uchar dst[1] = {0x00};
	uchar pat[] = {0x42};

	memfill(dst, sizeof dst, pat, sizeof pat);
	if(dst[0] != 0x42)
		sysfatal("testmemfill1byte: dst[0]: want 0x42, got 0x%x", dst[0]);
	return 0;
}

static int
testmemfillempty(void)
{
	/* Zero-length destination: no bytes written, returns a1 */
	uchar dst[1] = {0x99};
	uchar pat[] = {0x42};
	void *ret;

	ret = memfill(dst, 0, pat, sizeof pat);
	if(ret != dst)
		sysfatal("testmemfillempty: return value: want dst, got something else");
	if(dst[0] != 0x99)
		sysfatal("testmemfillempty: dst[0]: want 0x99, got 0x%x", dst[0]);
	return 0;
}

static int
testmemxorbasic(void)
{
	/* Basic XOR of two equal-length arrays */
	uchar a[] = {0xFF, 0x0F, 0xAA};
	uchar b[] = {0x0F, 0xFF, 0x55};
	uchar want[] = {0xF0, 0xF0, 0xFF};
	int i;

	memxor(a, b, sizeof a);
	for(i = 0; i < (int)sizeof a; i++)
		if((uchar)a[i] != want[i])
			sysfatal("testmemxorbasic: a[%d]: want 0x%x, got 0x%x", i, want[i], (uchar)a[i]);
	return 0;
}

static int
testmemxorempty(void)
{
	/* XOR with zero-length: no bytes modified */
	uchar a[] = {0xAB, 0xCD};
	uchar b[] = {0xFF, 0xFF};

	memxor(a, b, 0);
	if(a[0] != 0xAB || a[1] != 0xCD)
		sysfatal("testmemxorempty: unexpected modification: got 0x%x 0x%x", a[0], a[1]);
	return 0;
}

static int
testmemxorself(void)
{
	/* XOR with self yields all zeros */
	uchar a[] = {0x12, 0x34, 0x56};
	int i;

	memxor(a, a, sizeof a);
	for(i = 0; i < (int)sizeof a; i++)
		if(a[i] != 0)
			sysfatal("testmemxorself: a[%d]: want 0, got 0x%x", i, a[i]);
	return 0;
}

static int
testmemxorzero(void)
{
	/* XOR with all-zero array leaves original unchanged */
	uchar a[] = {0xDE, 0xAD, 0xBE, 0xEF};
	uchar z[] = {0x00, 0x00, 0x00, 0x00};
	uchar orig[] = {0xDE, 0xAD, 0xBE, 0xEF};
	int i;

	memxor(a, z, sizeof a);
	for(i = 0; i < (int)sizeof a; i++)
		if(a[i] != orig[i])
			sysfatal("testmemxorzero: a[%d]: want 0x%x, got 0x%x", i, orig[i], a[i]);
	return 0;
}

static int
testunrlebpix(void)
{
	/* Bpix extended opcode (0xFE): sets the current pixel to zero */
	uchar src[] = {0xFE};
	uchar dst[1];
	uchar *end;

	end = unrle(dst, sizeof dst, src, sizeof src, 2, 1);
	if(end == nil)
		sysfatal("testunrlebpix: unexpected error: %r");
	if(end - dst != 1)
		sysfatal("testunrlebpix: length: want 1, got %d", (int)(end - dst));
	if(dst[0] != 0)
		sysfatal("testunrlebpix: pixel: want 0, got %d", dst[0]);
	return 0;
}

static int
testunrlebg1(void)
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
		sysfatal("testunrlebg1: unexpected error: %r");
	if(end - dst != 1)
		sysfatal("testunrlebg1: length: want 1, got %d", (int)(end - dst));
	if(dst[0] != 0)
		sysfatal("testunrlebg1: pixel: want 0, got %d", dst[0]);
	return 0;
}

static int
testunrlemixzero(void)
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
		sysfatal("testunrlemixzero: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrlemixzero: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != 0)
			sysfatal("testunrlemixzero: dst[%d]: want 0, got %d", i, dst[i]);
	return 0;
}

static int
testunrlelit(void)
{
	/*
	 * Lit opcode: code=8, bits=Bits5=31, raw_len=3 → len=3 pixels.
	 * hdr=0x83: copies 3 literal bytes verbatim into output.
	 */
	uchar src[] = {0x83, 0xAA, 0xBB, 0xCC};
	uchar dst[3];
	uchar *end;

	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrlelit: unexpected error: %r");
	if(end - dst != 3)
		sysfatal("testunrlelit: length: want 3, got %d", (int)(end - dst));
	if(dst[0] != 0xAA || dst[1] != 0xBB || dst[2] != 0xCC)
		sysfatal("testunrlelit: pixels: want AA BB CC, got %02x %02x %02x",
			dst[0], dst[1], dst[2]);
	return 0;
}

static int
testunrlefg1(void)
{
	/*
	 * Fg opcode on the first scan line (no previous line):
	 * fills with the initial pen (DWhite=0xFF for pixelsize=1), no XOR.
	 * hdr=0x24: code=2 (Fg), raw_len=4 → len=4 pixels.
	 */
	uchar src[] = {0x24};
	uchar dst[4];
	uchar *end;
	int i;

	memset(dst, 0, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrlefg1: unexpected error: %r");
	if(end - dst != 4)
		sysfatal("testunrlefg1: length: want 4, got %d", (int)(end - dst));
	for(i = 0; i < 4; i++)
		if(dst[i] != 0xFF)
			sysfatal("testunrlefg1: dst[%d]: want 0xFF, got 0x%02x", i, dst[i]);
	return 0;
}

static int
testunrlefgs(void)
{
	/*
	 * FgS opcode: code=12, bits=Bits4=15, raw_len=1 → len=1 pixel.
	 * hdr=0xC1: reads 1-byte pen (0x42), then fills 1 pixel with it.
	 * First scan line: no XOR with previous row.
	 */
	uchar src[] = {0xC1, 0x42};
	uchar dst[1];
	uchar *end;

	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrlefgs: unexpected error: %r");
	if(end - dst != 1)
		sysfatal("testunrlefgs: length: want 1, got %d", (int)(end - dst));
	if(dst[0] != 0x42)
		sysfatal("testunrlefgs: pixel: want 0x42, got 0x%02x", dst[0]);
	return 0;
}

static int
testunrlefill(void)
{
	/*
	 * Fill opcode: code=6, bits=Bits5=31, raw_len=3 → len=3 pixels.
	 * hdr=0x63: reads 1-byte fill colour (0x55), fills 3 pixels with it.
	 */
	uchar src[] = {0x63, 0x55};
	uchar dst[3];
	uchar *end;
	int i;

	memset(dst, 0, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrlefill: unexpected error: %r");
	if(end - dst != 3)
		sysfatal("testunrlefill: length: want 3, got %d", (int)(end - dst));
	for(i = 0; i < 3; i++)
		if(dst[i] != 0x55)
			sysfatal("testunrlefill: dst[%d]: want 0x55, got 0x%02x", i, dst[i]);
	return 0;
}

static int
testunrledith(void)
{
	/*
	 * Dith opcode: code=14, bits=Bits4=15, raw_len=1 → len=1 (×pixelsize).
	 * hdr=0xE1: inside Dith, len doubles to 2; reads two 1-byte colours
	 * {0xAA, 0xBB} and fills output with the alternating pattern.
	 */
	uchar src[] = {0xE1, 0xAA, 0xBB};
	uchar dst[2];
	uchar *end;

	memset(dst, 0, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrledith: unexpected error: %r");
	if(end - dst != 2)
		sysfatal("testunrledith: length: want 2, got %d", (int)(end - dst));
	if(dst[0] != 0xAA || dst[1] != 0xBB)
		sysfatal("testunrledith: pixels: want AA BB, got %02x %02x", dst[0], dst[1]);
	return 0;
}

static int
testunrlewpix(void)
{
	/*
	 * Wpix extended opcode (0xFD): sets the current pixel to DWhite (0xFF).
	 */
	uchar src[] = {0xFD};
	uchar dst[1];
	uchar *end;

	dst[0] = 0;
	end = unrle(dst, sizeof dst, src, sizeof src, 2, 1);
	if(end == nil)
		sysfatal("testunrlewpix: unexpected error: %r");
	if(end - dst != 1)
		sysfatal("testunrlewpix: length: want 1, got %d", (int)(end - dst));
	if(dst[0] != 0xFF)
		sysfatal("testunrlewpix: pixel: want 0xFF, got 0x%02x", dst[0]);
	return 0;
}

static int
testunrlemixmask(void)
{
	/*
	 * Mix opcode with non-trivial mask (0xAA = 10101010):
	 * hdr=0x41: code=4 (Mix), raw_len=1 → len=8 pixels.
	 * Even-indexed pixels (bit=0) are zero-filled; odd-indexed (bit=1)
	 * get the initial pen (DWhite=0xFF). No previous scan line, no XOR.
	 */
	uchar src[] = {0x41, 0xAA};
	uchar dst[8];
	uchar *end;
	uchar want[] = {0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF};
	int i;

	memset(dst, 0x55, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrlemixmask: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrlemixmask: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != want[i])
			sysfatal("testunrlemixmask: dst[%d]: want 0x%02x, got 0x%02x",
				i, want[i], dst[i]);
	return 0;
}

static int
testunrlemixs(void)
{
	/*
	 * MixS opcode: code=13, bits=Bits4=15, raw_len=1 → len=8 pixels.
	 * hdr=0xD1: reads 1-byte pen (0x42), mask=0xFF (all bits set).
	 * First scan line, all bits 1: every pixel written with new pen, no XOR.
	 */
	uchar src[] = {0xD1, 0x42, 0xFF};
	uchar dst[8];
	uchar *end;
	int i;

	memset(dst, 0, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrlemixs: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrlemixs: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != 0x42)
			sysfatal("testunrlemixs: dst[%d]: want 0x42, got 0x%02x", i, dst[i]);
	return 0;
}

static int
testunrlemix3(void)
{
	/*
	 * Mix3 extended opcode (0xF9): fixed bitmask sreg=3 (00000011).
	 * Produces 8 pixels: first two get pen (DWhite=0xFF), rest are zero.
	 * First scan line: no XOR with previous row.
	 */
	uchar src[] = {0xF9};
	uchar dst[8];
	uchar *end;
	uchar want[] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	int i;

	memset(dst, 0x55, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrlemix3: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrlemix3: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != want[i])
			sysfatal("testunrlemix3: dst[%d]: want 0x%02x, got 0x%02x",
				i, want[i], dst[i]);
	return 0;
}

static int
testunrlemix5(void)
{
	/*
	 * Mix5 extended opcode (0xFA): fixed bitmask sreg=5 (00000101).
	 * Produces 8 pixels: pixels 0 and 2 get pen (DWhite=0xFF), rest zero.
	 * First scan line: no XOR with previous row.
	 */
	uchar src[] = {0xFA};
	uchar dst[8];
	uchar *end;
	uchar want[] = {0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00};
	int i;

	memset(dst, 0x55, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrlemix5: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrlemix5: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != want[i])
			sysfatal("testunrlemix5: dst[%d]: want 0x%02x, got 0x%02x",
				i, want[i], dst[i]);
	return 0;
}

static int
testunrlebg2(void)
{
	/*
	 * Bg on second scan line: copies pixels from the previous scan line.
	 * First opcode: Lit 4 pixels {0x11,0x22,0x33,0x44}.
	 * Second opcode: hdr=0x04 (Bg, raw_len=4) — on second scan line
	 * wp-bpl points into the already-written first scan line, so
	 * memmove copies it verbatim (no XOR for Bg).
	 */
	uchar src[] = {0x84, 0x11, 0x22, 0x33, 0x44, 0x04};
	uchar dst[8];
	uchar *end;
	int i;

	memset(dst, 0, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 4, 1);
	if(end == nil)
		sysfatal("testunrlebg2: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrlebg2: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 4; i++)
		if(dst[4+i] != dst[i])
			sysfatal("testunrlebg2: dst[%d]: want 0x%02x, got 0x%02x",
				4+i, dst[i], dst[4+i]);
	return 0;
}

static int
testunrlefg2(void)
{
	/*
	 * Fg on second scan line: fills with pen (DWhite) then XORs with
	 * the previous scan line.
	 * First opcode: Lit 4 pixels {0x11,0x22,0x33,0x44}.
	 * Second opcode: hdr=0x24 (Fg, raw_len=4) — pen=0xFF XOR prev.
	 * Expected: {0xFF^0x11, 0xFF^0x22, 0xFF^0x33, 0xFF^0x44}
	 *         = {0xEE, 0xDD, 0xCC, 0xBB}.
	 */
	uchar src[] = {0x84, 0x11, 0x22, 0x33, 0x44, 0x24};
	uchar dst[8];
	uchar *end;
	uchar want[] = {0xEE, 0xDD, 0xCC, 0xBB};
	int i;

	memset(dst, 0, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 4, 1);
	if(end == nil)
		sysfatal("testunrlefg2: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrlefg2: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 4; i++)
		if(dst[4+i] != want[i])
			sysfatal("testunrlefg2: dst[%d]: want 0x%02x, got 0x%02x",
				4+i, want[i], dst[4+i]);
	return 0;
}

static int
testunrlefgs2(void)
{
	/*
	 * FgS on second scan line: sets a new pen (0xF0) then XORs with
	 * the previous scan line.
	 * First opcode: Lit 4 pixels {0x11,0x22,0x33,0x44}.
	 * Second opcode: hdr=0xC4 (FgS, raw_len=4), pen byte=0xF0.
	 * Expected: {0xF0^0x11, 0xF0^0x22, 0xF0^0x33, 0xF0^0x44}
	 *         = {0xE1, 0xD2, 0xC3, 0xB4}.
	 */
	uchar src[] = {0x84, 0x11, 0x22, 0x33, 0x44, 0xC4, 0xF0};
	uchar dst[8];
	uchar *end;
	uchar want[] = {0xE1, 0xD2, 0xC3, 0xB4};
	int i;

	memset(dst, 0, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 4, 1);
	if(end == nil)
		sysfatal("testunrlefgs2: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrlefgs2: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 4; i++)
		if(dst[4+i] != want[i])
			sysfatal("testunrlefgs2: dst[%d]: want 0x%02x, got 0x%02x",
				4+i, want[i], dst[4+i]);
	return 0;
}

static int
testunrlebgcons(void)
{
	/*
	 * Consecutive Bg runs (wasbg flag): after a Bg run sets wasbg=1, the
	 * next Bg run on the following scan line starts its first pixel using
	 * pen XOR previous-line-pixel, then copies the rest of the prev line.
	 * Lit 4: {0x11,0x22,0x33,0x44}; Bg 4 (copies prev → same); Bg 4.
	 * Third Bg (wasbg=1): pixel[8] = pen(0xFF) XOR dst[4](0x11) = 0xEE,
	 * pixels[9..11] copied from dst[5..7] = {0x22,0x33,0x44}.
	 */
	uchar src[] = {0x84, 0x11, 0x22, 0x33, 0x44, 0x04, 0x04};
	uchar dst[12];
	uchar *end;

	memset(dst, 0, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 4, 1);
	if(end == nil)
		sysfatal("testunrlebgcons: unexpected error: %r");
	if(end - dst != 12)
		sysfatal("testunrlebgcons: length: want 12, got %d", (int)(end - dst));
	if(dst[8] != 0xEE)
		sysfatal("testunrlebgcons: dst[8]: want 0xEE, got 0x%02x", dst[8]);
	if(dst[9] != 0x22 || dst[10] != 0x33 || dst[11] != 0x44)
		sysfatal("testunrlebgcons: dst[9..11]: want 22 33 44, got %02x %02x %02x",
			dst[9], dst[10], dst[11]);
	return 0;
}

static int
testunrleoverrun(void)
{
	/*
	 * Overrun detection: output buffer is smaller than the decoded data.
	 * Lit 4 bytes into a 3-byte buffer must return nil with an error.
	 */
	uchar src[] = {0x84, 0xAA, 0xBB, 0xCC, 0xDD};
	uchar dst[3];
	uchar *end;

	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end != nil)
		sysfatal("testunrleoverrun: expected nil return on overrun, got non-nil");
	return 0;
}

static int
testunrleextbg(void)
{
	/*
	 * Extended Bg opcode (0xF0): len taken from following 2-byte little-
	 * endian field. hdr=0xF0, len=4; first scan line → zero-fills 4 bytes.
	 */
	uchar src[] = {0xF0, 0x04, 0x00};
	uchar dst[4];
	uchar *end;
	int i;

	memset(dst, 0xFF, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrleextbg: unexpected error: %r");
	if(end - dst != 4)
		sysfatal("testunrleextbg: length: want 4, got %d", (int)(end - dst));
	for(i = 0; i < 4; i++)
		if(dst[i] != 0)
			sysfatal("testunrleextbg: dst[%d]: want 0, got 0x%02x", i, dst[i]);
	return 0;
}

static int
testunrleextfg(void)
{
	/*
	 * Extended Fg opcode (0xF1): len from 2-byte field.
	 * hdr=0xF1, len=3; pen=DWhite (0xFF), first scan line → no XOR.
	 * Output: 3 bytes of 0xFF.
	 */
	uchar src[] = {0xF1, 0x03, 0x00};
	uchar dst[3];
	uchar *end;
	int i;

	memset(dst, 0, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrleextfg: unexpected error: %r");
	if(end - dst != 3)
		sysfatal("testunrleextfg: length: want 3, got %d", (int)(end - dst));
	for(i = 0; i < 3; i++)
		if(dst[i] != 0xFF)
			sysfatal("testunrleextfg: dst[%d]: want 0xFF, got 0x%02x", i, dst[i]);
	return 0;
}

static int
testunrleextlit(void)
{
	/*
	 * Extended Lit opcode (0xF4): len from 2-byte field.
	 * hdr=0xF4, len=3; copies next 3 bytes verbatim.
	 */
	uchar src[] = {0xF4, 0x03, 0x00, 0xAA, 0xBB, 0xCC};
	uchar dst[3];
	uchar *end;

	memset(dst, 0, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 10, 1);
	if(end == nil)
		sysfatal("testunrleextlit: unexpected error: %r");
	if(end - dst != 3)
		sysfatal("testunrleextlit: length: want 3, got %d", (int)(end - dst));
	if(dst[0] != 0xAA || dst[1] != 0xBB || dst[2] != 0xCC)
		sysfatal("testunrleextlit: pixels: want AA BB CC, got %02x %02x %02x",
			dst[0], dst[1], dst[2]);
	return 0;
}

static int
testunrleextfill32(void)
{
	/*
	 * Extended Fill opcode (0xF3) with pixelsize=4 (32-bpp):
	 * hdr=0xF3, len=2 pixels → 8 bytes; fill colour = {0x12,0x34,0x56,0x78}.
	 * Output: two copies of the 4-byte pixel.
	 */
	uchar src[] = {0xF3, 0x02, 0x00, 0x12, 0x34, 0x56, 0x78};
	uchar dst[8];
	uchar *end;
	uchar want[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78};
	int i;

	memset(dst, 0, sizeof dst);
	end = unrle(dst, sizeof dst, src, sizeof src, 8, 4);
	if(end == nil)
		sysfatal("testunrleextfill32: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrleextfill32: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != want[i])
			sysfatal("testunrleextfill32: dst[%d]: want 0x%02x, got 0x%02x",
				i, want[i], dst[i]);
	return 0;
}

int
rletests(void)
{
	testmemfillrepeat();
	testmemfillexact();
	testmemfill1byte();
	testmemfillempty();
	testmemxorbasic();
	testmemxorempty();
	testmemxorself();
	testmemxorzero();
	testunrlebpix();
	testunrlebg1();
	testunrlemixzero();
	testunrlelit();
	testunrlefg1();
	testunrlefgs();
	testunrlefill();
	testunrledith();
	testunrlewpix();
	testunrlemixmask();
	testunrlemixs();
	testunrlemix3();
	testunrlemix5();
	testunrlebg2();
	testunrlefg2();
	testunrlefgs2();
	testunrlebgcons();
	testunrleoverrun();
	testunrleextbg();
	testunrleextfg();
	testunrleextlit();
	testunrleextfill32();
	return 0;
}
