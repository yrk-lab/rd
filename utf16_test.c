#include <u.h>
#include <libc.h>
#include "dat.h"
#include "fns.h"

int utf16tests(void);

static int
testtoutf16_ascii(void)
{
	/* Single ASCII character 'A' → UTF-16LE: 41 00 */
	char s[] = "A";
	uchar buf[2];
	int n;

	n = toutf16(buf, sizeof buf, s, 1);
	if(n != 2)
		sysfatal("testtoutf16_ascii: len: want 2, got %d", n);
	if(buf[0] != 0x41 || buf[1] != 0x00)
		sysfatal("testtoutf16_ascii: bytes: want 41 00, got %02x %02x",
			buf[0], buf[1]);
	return 0;
}

static int
testtoutf16_crlf(void)
{
	/*
	 * Newline '\n' → CR LF pair in UTF-16LE: 0D 00 0A 00.
	 * toutf16 inserts a 0D 00 word before each 0A 00 word.
	 */
	char s[] = "\n";
	uchar buf[4];
	int n;

	n = toutf16(buf, sizeof buf, s, 1);
	if(n != 4)
		sysfatal("testtoutf16_crlf: len: want 4, got %d", n);
	if(buf[0]!=0x0D || buf[1]!=0x00 || buf[2]!=0x0A || buf[3]!=0x00)
		sysfatal("testtoutf16_crlf: bytes: want 0D 00 0A 00, got %02x %02x %02x %02x",
			buf[0], buf[1], buf[2], buf[3]);
	return 0;
}

static int
testtoutf16_empty(void)
{
	/* Empty string (ns=0) → 0 bytes written */
	uchar buf[2];
	int n;

	n = toutf16(buf, sizeof buf, "", 0);
	if(n != 0)
		sysfatal("testtoutf16_empty: len: want 0, got %d", n);
	return 0;
}

static int
testtoutf16_buftoosmall(void)
{
	/* Buffer too small (1 byte) to hold a UTF-16 unit → 0 bytes written */
	char s[] = "A";
	uchar buf[1];
	int n;

	n = toutf16(buf, sizeof buf, s, 1);
	if(n != 0)
		sysfatal("testtoutf16_buftoosmall: len: want 0, got %d", n);
	return 0;
}

static int
testtoutf16_bmp(void)
{
	/*
	 * Non-ASCII BMP character U+00E9 'é' (UTF-8: C3 A9)
	 * → UTF-16LE: E9 00
	 */
	uchar s[] = {0xC3, 0xA9};
	uchar buf[2];
	int n;

	n = toutf16(buf, sizeof buf, (char*)s, 2);
	if(n != 2)
		sysfatal("testtoutf16_bmp: len: want 2, got %d", n);
	if(buf[0] != 0xE9 || buf[1] != 0x00)
		sysfatal("testtoutf16_bmp: bytes: want E9 00, got %02x %02x",
			buf[0], buf[1]);
	return 0;
}

static int
testtoutf16_surrogate(void)
{
	/*
	 * U+1F600 😀 (UTF-8: F0 9F 98 80) is outside the BMP and encodes
	 * as a surrogate pair in UTF-16LE: 3D D8 00 DE.
	 */
	uchar s[] = {0xF0, 0x9F, 0x98, 0x80};
	uchar buf[4];
	int n;

	n = toutf16(buf, sizeof buf, (char*)s, 4);
	if(n != 4)
		sysfatal("testtoutf16_surrogate: len: want 4, got %d", n);
	if(buf[0]!=0x3D || buf[1]!=0xD8 || buf[2]!=0x00 || buf[3]!=0xDE)
		sysfatal("testtoutf16_surrogate: bytes: want 3D D8 00 DE, got %02x %02x %02x %02x",
			buf[0], buf[1], buf[2], buf[3]);
	return 0;
}

static int
testfromutf16_ascii(void)
{
	/* UTF-16LE 41 00 → ASCII 'A' */
	uchar ws[] = {0x41, 0x00};
	char buf[1];
	int n;

	n = fromutf16(buf, sizeof buf, ws, 2);
	if(n != 1)
		sysfatal("testfromutf16_ascii: len: want 1, got %d", n);
	if(buf[0] != 'A')
		sysfatal("testfromutf16_ascii: byte: want 'A', got %02x", (uchar)buf[0]);
	return 0;
}

static int
testfromutf16_crlf(void)
{
	/*
	 * CR LF in UTF-16LE (0D 00 0A 00): fromutf16 discards CR,
	 * so only '\n' appears in the output.
	 */
	uchar ws[] = {0x0D, 0x00, 0x0A, 0x00};
	char buf[1];
	int n;

	n = fromutf16(buf, sizeof buf, ws, 4);
	if(n != 1)
		sysfatal("testfromutf16_crlf: len: want 1, got %d", n);
	if(buf[0] != '\n')
		sysfatal("testfromutf16_crlf: byte: want '\\n', got %02x", (uchar)buf[0]);
	return 0;
}

static int
testfromutf16_empty(void)
{
	/* Empty input (nw=0) → 0 bytes written */
	uchar ws[1];
	char buf[4];
	int n;

	n = fromutf16(buf, sizeof buf, ws, 0);
	if(n != 0)
		sysfatal("testfromutf16_empty: len: want 0, got %d", n);
	return 0;
}

static int
testfromutf16_buftoosmall(void)
{
	/*
	 * Output buffer too small for all input: 'A' 'B' in UTF-16LE
	 * (41 00 42 00) with a 1-byte output buffer → only 'A' is written.
	 */
	uchar ws[] = {0x41, 0x00, 0x42, 0x00};
	char buf[1];
	int n;

	n = fromutf16(buf, sizeof buf, ws, 4);
	if(n != 1)
		sysfatal("testfromutf16_buftoosmall: len: want 1, got %d", n);
	if(buf[0] != 'A')
		sysfatal("testfromutf16_buftoosmall: byte: want 'A', got %02x", (uchar)buf[0]);
	return 0;
}

static int
testfromutf16_bmp(void)
{
	/*
	 * Non-ASCII BMP character: UTF-16LE E9 00 → U+00E9 'é' (UTF-8: C3 A9)
	 */
	uchar ws[] = {0xE9, 0x00};
	uchar buf[2];
	int n;

	n = fromutf16((char*)buf, sizeof buf, ws, 2);
	if(n != 2)
		sysfatal("testfromutf16_bmp: len: want 2, got %d", n);
	if(buf[0] != 0xC3 || buf[1] != 0xA9)
		sysfatal("testfromutf16_bmp: bytes: want C3 A9, got %02x %02x",
			buf[0], buf[1]);
	return 0;
}

static int
testfromutf16_surrogate(void)
{
	/*
	 * Surrogate pair 3D D8 00 DE → U+1F600 😀 (UTF-8: F0 9F 98 80)
	 */
	uchar ws[] = {0x3D, 0xD8, 0x00, 0xDE};
	uchar buf[4];
	int n;

	n = fromutf16((char*)buf, sizeof buf, ws, 4);
	if(n != 4)
		sysfatal("testfromutf16_surrogate: len: want 4, got %d", n);
	if(buf[0]!=0xF0 || buf[1]!=0x9F || buf[2]!=0x98 || buf[3]!=0x80)
		sysfatal("testfromutf16_surrogate: bytes: want F0 9F 98 80, got %02x %02x %02x %02x",
			buf[0], buf[1], buf[2], buf[3]);
	return 0;
}

int
utf16tests(void)
{
	testtoutf16_ascii();
	testtoutf16_crlf();
	testtoutf16_empty();
	testtoutf16_buftoosmall();
	testtoutf16_bmp();
	testtoutf16_surrogate();
	testfromutf16_ascii();
	testfromutf16_crlf();
	testfromutf16_empty();
	testfromutf16_buftoosmall();
	testfromutf16_bmp();
	testfromutf16_surrogate();
	return 0;
}
