#include "mppc.c"

int mppctests(void);

static int
testuncomp1(void)
{
	/* Preset with no Pcompress: history is reset and input returned unchanged */
	uchar input[] = {0x12, 0x34};
	int psize = -1;
	uchar *out;

	out = uncomp(input, 2, 0x80, &psize);	/* flags=Preset */
	if(out == nil)
		sysfatal("testuncomp1: unexpected error: %r");
	if(out != input)
		sysfatal("testuncomp1: expected input buffer returned unchanged");
	if(psize != 2)
		sysfatal("testuncomp1: psize: want 2, got %d", psize);
	return 0;
}

static int
testuncomp2(void)
{
	/*
	 * Preset + Pcompress: decompress two 7-bit literals.
	 * In 8K mode, bytes with high bit 0 encode as Lit7 and decode to themselves.
	 */
	uchar input[] = {0x41, 0x42};	/* 'A', 'B' as 7-bit literals */
	int psize = -1;
	uchar *out;

	out = uncomp(input, 2, 0x80|0x20, &psize);	/* flags=Preset|Pcompress */
	if(out == nil)
		sysfatal("testuncomp2: unexpected error: %r");
	if(psize != 2)
		sysfatal("testuncomp2: psize: want 2, got %d", psize);
	if(out[0] != 'A' || out[1] != 'B')
		sysfatal("testuncomp2: data: want AB, got %c%c", out[0], out[1]);
	return 0;
}

static int
testuncomp_lit8(void)
{
	/*
	 * Lit8 opcode (8K mode): value 0x80 encodes as the 9-bit sequence
	 * "10 0000000" (2-bit prefix + 7 data bits), packed into {0x80, 0x00}.
	 */
	uchar input[] = {0x80, 0x00};
	int psize = -1;
	uchar *out;

	out = uncomp(input, 2, 0x80|0x20, &psize);	/* Preset|Pcompress */
	if(out == nil)
		sysfatal("testuncomp_lit8: unexpected error: %r");
	if(psize != 1)
		sysfatal("testuncomp_lit8: psize: want 1, got %d", psize);
	if(out[0] != 0x80)
		sysfatal("testuncomp_lit8: out[0]: want 0x80, got 0x%02x", out[0]);
	return 0;
}

static int
testuncomp_off6(void)
{
	/*
	 * Off6 opcode (8K mode): 4 Lit7 'A' literals set up 4 bytes of history,
	 * then a back-reference with 6-bit offset=4 and length=3 copies them.
	 * Bit layout: "1111"(Off6) "000100"(off=4) "0"(len=3) → {0xF1, 0x00}.
	 */
	uchar input[] = {0x41, 0x41, 0x41, 0x41, 0xF1, 0x00};
	int psize = -1;
	uchar *out;
	int i;

	out = uncomp(input, 6, 0x80|0x20, &psize);	/* Preset|Pcompress */
	if(out == nil)
		sysfatal("testuncomp_off6: unexpected error: %r");
	if(psize != 7)
		sysfatal("testuncomp_off6: psize: want 7, got %d", psize);
	for(i = 0; i < psize; i++)
		if(out[i] != 'A')
			sysfatal("testuncomp_off6: out[%d]: want 'A', got 0x%02x", i, out[i]);
	return 0;
}

static int
testuncomp_off8(void)
{
	/*
	 * Off8 opcode (8K mode): 64 Lit7 'A' literals fill 64 bytes of history,
	 * then a back-reference with 8-bit raw offset=0 (off=64) and length=3.
	 * Bit layout: "1110"(Off8) "00000000"(raw=0) "0"(len=3) → {0xE0, 0x00}.
	 */
	uchar input[66];
	int psize = -1;
	uchar *out;
	int i;

	memset(input, 0x41, 64);
	input[64] = 0xE0;
	input[65] = 0x00;
	out = uncomp(input, 66, 0x80|0x20, &psize);	/* Preset|Pcompress */
	if(out == nil)
		sysfatal("testuncomp_off8: unexpected error: %r");
	if(psize != 67)
		sysfatal("testuncomp_off8: psize: want 67, got %d", psize);
	for(i = 0; i < psize; i++)
		if(out[i] != 'A')
			sysfatal("testuncomp_off8: out[%d]: want 'A', got 0x%02x", i, out[i]);
	return 0;
}

static int
testuncomp_off13(void)
{
	/*
	 * Off13 opcode (8K mode): 320 Lit7 'A' literals fill 320 bytes of history,
	 * then a back-reference with 13-bit raw offset=0 (off=320) and length=3.
	 * The 4-bit lookup prefix "1100" triggers Off13; bits-=3 consumes "110"
	 * and the remaining "0" becomes the MSB of the 13-bit offset field.
	 * Bit layout: "1100"(4-bit prefix) + "000000000000"(12 more offset bits)
	 * + "0"(len=3) → {0xC0, 0x00, 0x00} (17 bits, 7 padding).
	 */
	uchar input[323];
	int psize = -1;
	uchar *out;
	int i;

	memset(input, 0x41, 320);
	input[320] = 0xC0;
	input[321] = 0x00;
	input[322] = 0x00;
	out = uncomp(input, 323, 0x80|0x20, &psize);	/* Preset|Pcompress */
	if(out == nil)
		sysfatal("testuncomp_off13: unexpected error: %r");
	if(psize != 323)
		sysfatal("testuncomp_off13: psize: want 323, got %d", psize);
	for(i = 0; i < psize; i++)
		if(out[i] != 'A')
			sysfatal("testuncomp_off13: out[%d]: want 'A', got 0x%02x", i, out[i]);
	return 0;
}

static int
testuncomp_off11(void)
{
	/*
	 * Off11 opcode (64K mode): 320 Lit7 'A' literals fill 320 bytes of history,
	 * then a back-reference with 11-bit raw offset=0 (off=320) and length=3.
	 * The 5-bit lookup prefix "11100" triggers Off11; bits-=4 consumes "1110"
	 * and the remaining "0" becomes the MSB of the 11-bit offset field.
	 * Bit layout: "11100"(5-bit prefix) + "0000000000"(10 more offset bits)
	 * + "0"(len=3) → {0xE0, 0x00} (16 bits, no padding).
	 */
	uchar input[322];
	int psize = -1;
	uchar *out;
	int i;

	memset(input, 0x41, 320);
	input[320] = 0xE0;
	input[321] = 0x00;
	out = uncomp(input, 322, 0x80|0x20|0x01, &psize);	/* Preset|Pcompress|Pbulk64 */
	if(out == nil)
		sysfatal("testuncomp_off11: unexpected error: %r");
	if(psize != 323)
		sysfatal("testuncomp_off11: psize: want 323, got %d", psize);
	for(i = 0; i < psize; i++)
		if(out[i] != 'A')
			sysfatal("testuncomp_off11: out[%d]: want 'A', got 0x%02x", i, out[i]);
	return 0;
}

static int
testuncomp_off16(void)
{
	/*
	 * Off16 opcode (64K mode): 2368 Lit7 'A' literals fill 2368 bytes of history,
	 * then a back-reference with 16-bit raw offset=0 (off=2368) and length=3.
	 * The 5-bit lookup prefix "11000" triggers Off16; bits-=3 consumes "110"
	 * and the remaining "00" become the high 2 bits of the 16-bit offset field.
	 * Bit layout: "11000"(5-bit prefix) + "00000000000000"(14 more offset bits)
	 * + "0"(len=3) → {0xC0, 0x00, 0x00} (20 bits, 4 padding).
	 */
	uchar *input;
	int psize = -1;
	uchar *out;
	int i;

	input = malloc(2371);
	if(input == nil)
		sysfatal("testuncomp_off16: malloc: %r");
	memset(input, 0x41, 2368);
	input[2368] = 0xC0;
	input[2369] = 0x00;
	input[2370] = 0x00;
	out = uncomp(input, 2371, 0x80|0x20|0x01, &psize);	/* Preset|Pcompress|Pbulk64 */
	free(input);
	if(out == nil)
		sysfatal("testuncomp_off16: unexpected error: %r");
	if(psize != 2371)
		sysfatal("testuncomp_off16: psize: want 2371, got %d", psize);
	for(i = 0; i < psize; i++)
		if(out[i] != 'A')
			sysfatal("testuncomp_off16: out[%d]: want 'A', got 0x%02x", i, out[i]);
	return 0;
}

static int
testuncomp_pfront(void)
{
	/*
	 * Pfront flag: resets the history write index to zero without clearing
	 * history. After a Preset|Pcompress call writing "AA", a subsequent
	 * Pfront|Pcompress call restarts writing from the beginning of history.
	 */
	uchar input1[] = {0x41, 0x41};
	uchar input2[] = {0x42, 0x42};
	int psize = -1;
	uchar *out;

	out = uncomp(input1, 2, 0x80|0x20, &psize);	/* Preset|Pcompress */
	if(out == nil)
		sysfatal("testuncomp_pfront: call1: unexpected error: %r");
	if(psize != 2)
		sysfatal("testuncomp_pfront: call1: psize: want 2, got %d", psize);
	psize = -1;
	out = uncomp(input2, 2, 0x40|0x20, &psize);	/* Pfront|Pcompress */
	if(out == nil)
		sysfatal("testuncomp_pfront: call2: unexpected error: %r");
	if(psize != 2)
		sysfatal("testuncomp_pfront: call2: psize: want 2, got %d", psize);
	if(out[0] != 'B' || out[1] != 'B')
		sysfatal("testuncomp_pfront: call2: data: want BB, got %c%c", out[0], out[1]);
	return 0;
}

static int
testuncomp_eof_err(void)
{
	/*
	 * Eof error: the compressed stream ends while decoding a Lit8 opcode.
	 * 0x80 triggers Lit8 (prefix "10"), which needs 9 bits but only 8
	 * are available, so uncomp returns nil.
	 */
	uchar input[] = {0x80};
	int psize = -1;
	uchar *out;

	out = uncomp(input, 1, 0x80|0x20, &psize);	/* Preset|Pcompress */
	if(out != nil)
		sysfatal("testuncomp_eof_err: expected nil on truncated input, got non-nil");
	return 0;
}

static int
testuncomp_bad_length(void)
{
	/*
	 * Bad length: Off6 with offset=0 followed by 12 consecutive 1-bits
	 * in the length field exceeds maxones=11 (8K mode), so uncomp returns nil.
	 * Bit stream: "1111"(Off6) "000000"(off=0) "111111111111"(12 ones) "0"
	 *   B1=11110000=0xF0  B2=00111111=0x3F  B3=11111100=0xFC
	 */
	uchar input[] = {0xF0, 0x3F, 0xFC};
	int psize = -1;
	uchar *out;

	out = uncomp(input, 3, 0x80|0x20, &psize);	/* Preset|Pcompress */
	if(out != nil)
		sysfatal("testuncomp_bad_length: expected nil on bad length, got non-nil");
	return 0;
}

int
mppctests(void)
{
	testuncomp1();
	testuncomp2();
	testuncomp_lit8();
	testuncomp_off6();
	testuncomp_off8();
	testuncomp_off13();
	testuncomp_off11();
	testuncomp_off16();
	testuncomp_pfront();
	testuncomp_eof_err();
	testuncomp_bad_length();
	return 0;
}
