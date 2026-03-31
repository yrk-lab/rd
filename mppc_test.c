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

int
mppctests(void)
{
	testuncomp1();
	testuncomp2();
	return 0;
}
