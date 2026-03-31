#include "rle.c"

int rletests(void);

static int
testmemfill_repeat(void)
{
	/* Fill with a pattern shorter than the destination (pattern repeats) */
	uchar dst[6];
	uchar pat[] = {0xAB, 0xCD};
	uchar want[] = {0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD};
	int i;

	memfill(dst, sizeof dst, pat, sizeof pat);
	for(i = 0; i < (int)sizeof dst; i++)
		if(dst[i] != want[i])
			sysfatal("testmemfill_repeat: dst[%d]: want 0x%x, got 0x%x", i, want[i], dst[i]);
	return 0;
}

static int
testmemfill_exact(void)
{
	/* Fill with a pattern equal in length to the destination */
	uchar dst[4];
	uchar pat[] = {0x01, 0x02, 0x03, 0x04};
	int i;

	memfill(dst, sizeof dst, pat, sizeof pat);
	for(i = 0; i < (int)sizeof dst; i++)
		if(dst[i] != pat[i])
			sysfatal("testmemfill_exact: dst[%d]: want 0x%x, got 0x%x", i, pat[i], dst[i]);
	return 0;
}

static int
testmemfill_onebyte(void)
{
	/* Fill a single byte with a single-byte pattern */
	uchar dst[1] = {0x00};
	uchar pat[] = {0x42};

	memfill(dst, sizeof dst, pat, sizeof pat);
	if(dst[0] != 0x42)
		sysfatal("testmemfill_onebyte: dst[0]: want 0x42, got 0x%x", dst[0]);
	return 0;
}

static int
testmemfill_empty(void)
{
	/* Zero-length destination: no bytes written, returns a1 */
	uchar dst[1] = {0x99};
	uchar pat[] = {0x42};
	void *ret;

	ret = memfill(dst, 0, pat, sizeof pat);
	if(ret != dst)
		sysfatal("testmemfill_empty: return value: want dst, got something else");
	if(dst[0] != 0x99)
		sysfatal("testmemfill_empty: dst[0]: want 0x99, got 0x%x", dst[0]);
	return 0;
}

static int
testmemxor_basic(void)
{
	/* Basic XOR of two equal-length arrays */
	uchar a[] = {0xFF, 0x0F, 0xAA};
	uchar b[] = {0x0F, 0xFF, 0x55};
	uchar want[] = {0xF0, 0xF0, 0xFF};
	int i;

	memxor(a, b, sizeof a);
	for(i = 0; i < (int)sizeof a; i++)
		if((uchar)a[i] != want[i])
			sysfatal("testmemxor_basic: a[%d]: want 0x%x, got 0x%x", i, want[i], (uchar)a[i]);
	return 0;
}

static int
testmemxor_empty(void)
{
	/* XOR with zero-length: no bytes modified */
	uchar a[] = {0xAB, 0xCD};
	uchar b[] = {0xFF, 0xFF};

	memxor(a, b, 0);
	if(a[0] != 0xAB || a[1] != 0xCD)
		sysfatal("testmemxor_empty: unexpected modification: got 0x%x 0x%x", a[0], a[1]);
	return 0;
}

static int
testmemxor_self(void)
{
	/* XOR with self yields all zeros */
	uchar a[] = {0x12, 0x34, 0x56};
	int i;

	memxor(a, a, sizeof a);
	for(i = 0; i < (int)sizeof a; i++)
		if(a[i] != 0)
			sysfatal("testmemxor_self: a[%d]: want 0, got 0x%x", i, a[i]);
	return 0;
}

static int
testmemxor_zeros(void)
{
	/* XOR with all-zero array leaves original unchanged */
	uchar a[] = {0xDE, 0xAD, 0xBE, 0xEF};
	uchar z[] = {0x00, 0x00, 0x00, 0x00};
	uchar orig[] = {0xDE, 0xAD, 0xBE, 0xEF};
	int i;

	memxor(a, z, sizeof a);
	for(i = 0; i < (int)sizeof a; i++)
		if(a[i] != orig[i])
			sysfatal("testmemxor_zeros: a[%d]: want 0x%x, got 0x%x", i, orig[i], a[i]);
	return 0;
}

static int
testunrle_bpix(void)
{
	/* Bpix extended opcode (0xFE): sets the current pixel to zero */
	uchar src[] = {0xFE};
	uchar dst[1];
	uchar *end;

	end = unrle(dst, sizeof dst, src, sizeof src, 2, 1);
	if(end == nil)
		sysfatal("testunrle_bpix: unexpected error: %r");
	if(end - dst != 1)
		sysfatal("testunrle_bpix: length: want 1, got %d", (int)(end - dst));
	if(dst[0] != 0)
		sysfatal("testunrle_bpix: pixel: want 0, got %d", dst[0]);
	return 0;
}

static int
testunrle_bg_firstline(void)
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
		sysfatal("testunrle_bg_firstline: unexpected error: %r");
	if(end - dst != 1)
		sysfatal("testunrle_bg_firstline: length: want 1, got %d", (int)(end - dst));
	if(dst[0] != 0)
		sysfatal("testunrle_bg_firstline: pixel: want 0, got %d", dst[0]);
	return 0;
}

static int
testunrle_mix_zeromask(void)
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
		sysfatal("testunrle_mix_zeromask: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrle_mix_zeromask: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != 0)
			sysfatal("testunrle_mix_zeromask: dst[%d]: want 0, got %d", i, dst[i]);
	return 0;
}

static int
testunrle_lit(void)
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
		sysfatal("testunrle_lit: unexpected error: %r");
	if(end - dst != 3)
		sysfatal("testunrle_lit: length: want 3, got %d", (int)(end - dst));
	if(dst[0] != 0xAA || dst[1] != 0xBB || dst[2] != 0xCC)
		sysfatal("testunrle_lit: pixels: want AA BB CC, got %02x %02x %02x",
			dst[0], dst[1], dst[2]);
	return 0;
}

static int
testunrle_fg_firstline(void)
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
		sysfatal("testunrle_fg_firstline: unexpected error: %r");
	if(end - dst != 4)
		sysfatal("testunrle_fg_firstline: length: want 4, got %d", (int)(end - dst));
	for(i = 0; i < 4; i++)
		if(dst[i] != 0xFF)
			sysfatal("testunrle_fg_firstline: dst[%d]: want 0xFF, got 0x%02x", i, dst[i]);
	return 0;
}

static int
testunrle_fgs(void)
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
		sysfatal("testunrle_fgs: unexpected error: %r");
	if(end - dst != 1)
		sysfatal("testunrle_fgs: length: want 1, got %d", (int)(end - dst));
	if(dst[0] != 0x42)
		sysfatal("testunrle_fgs: pixel: want 0x42, got 0x%02x", dst[0]);
	return 0;
}

static int
testunrle_fill(void)
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
		sysfatal("testunrle_fill: unexpected error: %r");
	if(end - dst != 3)
		sysfatal("testunrle_fill: length: want 3, got %d", (int)(end - dst));
	for(i = 0; i < 3; i++)
		if(dst[i] != 0x55)
			sysfatal("testunrle_fill: dst[%d]: want 0x55, got 0x%02x", i, dst[i]);
	return 0;
}

static int
testunrle_dith(void)
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
		sysfatal("testunrle_dith: unexpected error: %r");
	if(end - dst != 2)
		sysfatal("testunrle_dith: length: want 2, got %d", (int)(end - dst));
	if(dst[0] != 0xAA || dst[1] != 0xBB)
		sysfatal("testunrle_dith: pixels: want AA BB, got %02x %02x", dst[0], dst[1]);
	return 0;
}

static int
testunrle_wpix(void)
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
		sysfatal("testunrle_wpix: unexpected error: %r");
	if(end - dst != 1)
		sysfatal("testunrle_wpix: length: want 1, got %d", (int)(end - dst));
	if(dst[0] != 0xFF)
		sysfatal("testunrle_wpix: pixel: want 0xFF, got 0x%02x", dst[0]);
	return 0;
}

static int
testunrle_mix_nontrivial(void)
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
		sysfatal("testunrle_mix_nontrivial: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrle_mix_nontrivial: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != want[i])
			sysfatal("testunrle_mix_nontrivial: dst[%d]: want 0x%02x, got 0x%02x",
				i, want[i], dst[i]);
	return 0;
}

static int
testunrle_mixs(void)
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
		sysfatal("testunrle_mixs: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrle_mixs: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != 0x42)
			sysfatal("testunrle_mixs: dst[%d]: want 0x42, got 0x%02x", i, dst[i]);
	return 0;
}

static int
testunrle_mix3(void)
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
		sysfatal("testunrle_mix3: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrle_mix3: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != want[i])
			sysfatal("testunrle_mix3: dst[%d]: want 0x%02x, got 0x%02x",
				i, want[i], dst[i]);
	return 0;
}

static int
testunrle_mix5(void)
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
		sysfatal("testunrle_mix5: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrle_mix5: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != want[i])
			sysfatal("testunrle_mix5: dst[%d]: want 0x%02x, got 0x%02x",
				i, want[i], dst[i]);
	return 0;
}

static int
testunrle_bg_secondline(void)
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
		sysfatal("testunrle_bg_secondline: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrle_bg_secondline: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 4; i++)
		if(dst[4+i] != dst[i])
			sysfatal("testunrle_bg_secondline: dst[%d]: want 0x%02x, got 0x%02x",
				4+i, dst[i], dst[4+i]);
	return 0;
}

static int
testunrle_fg_secondline(void)
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
		sysfatal("testunrle_fg_secondline: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrle_fg_secondline: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 4; i++)
		if(dst[4+i] != want[i])
			sysfatal("testunrle_fg_secondline: dst[%d]: want 0x%02x, got 0x%02x",
				4+i, want[i], dst[4+i]);
	return 0;
}

static int
testunrle_fgs_secondline(void)
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
		sysfatal("testunrle_fgs_secondline: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrle_fgs_secondline: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 4; i++)
		if(dst[4+i] != want[i])
			sysfatal("testunrle_fgs_secondline: dst[%d]: want 0x%02x, got 0x%02x",
				4+i, want[i], dst[4+i]);
	return 0;
}

static int
testunrle_bg_consecutive(void)
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
		sysfatal("testunrle_bg_consecutive: unexpected error: %r");
	if(end - dst != 12)
		sysfatal("testunrle_bg_consecutive: length: want 12, got %d", (int)(end - dst));
	if(dst[8] != 0xEE)
		sysfatal("testunrle_bg_consecutive: dst[8]: want 0xEE, got 0x%02x", dst[8]);
	if(dst[9] != 0x22 || dst[10] != 0x33 || dst[11] != 0x44)
		sysfatal("testunrle_bg_consecutive: dst[9..11]: want 22 33 44, got %02x %02x %02x",
			dst[9], dst[10], dst[11]);
	return 0;
}

static int
testunrle_overrun(void)
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
		sysfatal("testunrle_overrun: expected nil return on overrun, got non-nil");
	return 0;
}

static int
testunrle_extbg(void)
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
		sysfatal("testunrle_extbg: unexpected error: %r");
	if(end - dst != 4)
		sysfatal("testunrle_extbg: length: want 4, got %d", (int)(end - dst));
	for(i = 0; i < 4; i++)
		if(dst[i] != 0)
			sysfatal("testunrle_extbg: dst[%d]: want 0, got 0x%02x", i, dst[i]);
	return 0;
}

static int
testunrle_extfg(void)
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
		sysfatal("testunrle_extfg: unexpected error: %r");
	if(end - dst != 3)
		sysfatal("testunrle_extfg: length: want 3, got %d", (int)(end - dst));
	for(i = 0; i < 3; i++)
		if(dst[i] != 0xFF)
			sysfatal("testunrle_extfg: dst[%d]: want 0xFF, got 0x%02x", i, dst[i]);
	return 0;
}

static int
testunrle_extlit(void)
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
		sysfatal("testunrle_extlit: unexpected error: %r");
	if(end - dst != 3)
		sysfatal("testunrle_extlit: length: want 3, got %d", (int)(end - dst));
	if(dst[0] != 0xAA || dst[1] != 0xBB || dst[2] != 0xCC)
		sysfatal("testunrle_extlit: pixels: want AA BB CC, got %02x %02x %02x",
			dst[0], dst[1], dst[2]);
	return 0;
}

static int
testunrle_extfill_32bpp(void)
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
		sysfatal("testunrle_extfill_32bpp: unexpected error: %r");
	if(end - dst != 8)
		sysfatal("testunrle_extfill_32bpp: length: want 8, got %d", (int)(end - dst));
	for(i = 0; i < 8; i++)
		if(dst[i] != want[i])
			sysfatal("testunrle_extfill_32bpp: dst[%d]: want 0x%02x, got 0x%02x",
				i, want[i], dst[i]);
	return 0;
}

int
rletests(void)
{
	testmemfill_repeat();
	testmemfill_exact();
	testmemfill_onebyte();
	testmemfill_empty();
	testmemxor_basic();
	testmemxor_empty();
	testmemxor_self();
	testmemxor_zeros();
	testunrle_bpix();
	testunrle_bg_firstline();
	testunrle_mix_zeromask();
	testunrle_lit();
	testunrle_fg_firstline();
	testunrle_fgs();
	testunrle_fill();
	testunrle_dith();
	testunrle_wpix();
	testunrle_mix_nontrivial();
	testunrle_mixs();
	testunrle_mix3();
	testunrle_mix5();
	testunrle_bg_secondline();
	testunrle_fg_secondline();
	testunrle_fgs_secondline();
	testunrle_bg_consecutive();
	testunrle_overrun();
	testunrle_extbg();
	testunrle_extfg();
	testunrle_extlit();
	testunrle_extfill_32bpp();
	return 0;
}
