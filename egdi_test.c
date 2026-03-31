#include "egdi.c"

int egditests(void);

static int
testegdinonstd(void)
{
	/*
	 * Non-standard order: Standard bit (bit 0) is not set.
	 * getfupd should print a warning and return 0 bytes consumed.
	 */
	uchar pkt[] = {0x00};
	Imgupd up;
	int n;

	memset(&up, 0, sizeof up);
	n = getfupd(&up, pkt, sizeof pkt);
	if(n != 0)
		sysfatal("testegdinonstd: consumed: want 0, got %d", n);
	return 0;
}

static int
testegdiscrblt(void)
{
	/*
	 * ScrBlt primary order, NewOrder, SameClipping, all fields set.
	 *   ctl = Standard|NewOrder|SameClipping (0x29)
	 *   order = ScrBlt (2)
	 *   fset = 0x7F: bits 0-6 (left, top, width, height, rop3, src.x, src.y)
	 *   rect:  left=10, top=20, width=100, height=100 → r={(10,20),(110,120)}
	 *   rop3 = 0xCC (Scopy, no warning)
	 *   src:   (5, 15)
	 * No Clipped bit set so rectclip is not called.
	 */
	uchar pkt[] = {
		0x29,		/* ctl: Standard|NewOrder|SameClipping */
		0x02,		/* order: ScrBlt */
		0x7F,		/* fset: bits 0-6 */
		0x0A, 0x00,	/* left  = 10 */
		0x14, 0x00,	/* top   = 20 */
		0x64, 0x00,	/* width = 100 */
		0x64, 0x00,	/* height= 100 */
		0xCC,		/* rop3 = Scopy */
		0x05, 0x00,	/* src.x = 5 */
		0x0F, 0x00,	/* src.y = 15 */
	};
	Imgupd up;
	int n;

	memset(&up, 0, sizeof up);
	n = getfupd(&up, pkt, sizeof pkt);
	if(n != (int)sizeof pkt)
		sysfatal("testegdiscrblt: consumed: want %d, got %d", (int)sizeof pkt, n);
	if(up.type != Uscrblt)
		sysfatal("testegdiscrblt: type: want %d, got %d", Uscrblt, up.type);
	if(up.x != 10 || up.y != 20)
		sysfatal("testegdiscrblt: pos: want (10,20), got (%d,%d)", up.x, up.y);
	if(up.xsz != 100 || up.ysz != 100)
		sysfatal("testegdiscrblt: size: want (100,100), got (%d,%d)", up.xsz, up.ysz);
	if(up.sx != 5 || up.sy != 15)
		sysfatal("testegdiscrblt: src: want (5,15), got (%d,%d)", up.sx, up.sy);
	return 0;
}

static int
testegdiscrblclip(void)
{
	/*
	 * ScrBlt with Clipped flag set.
	 *   ctl = Standard|NewOrder|Clipped (0x0D)
	 *   cfclipr encodes clip rect (0,0)-(200,100) using bctl=0x0F (all absolute).
	 *   rect: left=10, top=20, width=100, height=100 → wr={(10,20),(110,120)}.
	 *   After rectclip(wr, clip): r={(10,20),(110,100)} → xsz=100, ysz=80.
	 */
	uchar pkt[] = {
		0x0D,		/* ctl: Standard|NewOrder|Clipped */
		0x02,		/* order: ScrBlt */
		0x7F,		/* fset: bits 0-6 */
		/* cfclipr: bctl=0x0F (bits 0-3 = all absolute coords) */
		0x0F,
		0x00, 0x00,	/* min.x = 0 */
		0x00, 0x00,	/* min.y = 0 */
		0xC7, 0x00,	/* max.x: stored 199, +1 → 200 */
		0x63, 0x00,	/* max.y: stored 99,  +1 → 100 */
		/* getscrblt data */
		0x0A, 0x00,	/* left  = 10 */
		0x14, 0x00,	/* top   = 20 */
		0x64, 0x00,	/* width = 100 */
		0x64, 0x00,	/* height= 100 */
		0xCC,		/* rop3 = Scopy */
		0x05, 0x00,	/* src.x = 5 */
		0x0F, 0x00,	/* src.y = 15 */
	};
	Imgupd up;
	int n;

	memset(&up, 0, sizeof up);
	n = getfupd(&up, pkt, sizeof pkt);
	if(n != (int)sizeof pkt)
		sysfatal("testegdiscrblclip: consumed: want %d, got %d", (int)sizeof pkt, n);
	if(up.type != Uscrblt)
		sysfatal("testegdiscrblclip: type: want %d, got %d", Uscrblt, up.type);
	if(up.x != 10 || up.y != 20)
		sysfatal("testegdiscrblclip: pos: want (10,20), got (%d,%d)", up.x, up.y);
	if(up.xsz != 100 || up.ysz != 80)
		sysfatal("testegdiscrblclip: size: want (100,80), got (%d,%d)", up.xsz, up.ysz);
	if(up.sx != 5 || up.sy != 15)
		sysfatal("testegdiscrblclip: src: want (5,15), got (%d,%d)", up.sx, up.sy);
	return 0;
}

static int
testegdimemblt(void)
{
	/*
	 * MemBlt primary order, NewOrder, SameClipping, all fields set.
	 *   ctl = Standard|NewOrder|SameClipping (0x29)
	 *   order = MemBlt (13)
	 *   fset = 0x01FF (bits 0-8): cid, rect, rop3, src, coff
	 *   cid=1, rect: left=50,top=60,width=100,height=100 → r={(50,60),(150,160)}
	 *   rop3=0xCC, src=(10,20), coff=5
	 */
	uchar pkt[] = {
		0x29,		/* ctl: Standard|NewOrder|SameClipping */
		0x0D,		/* order: MemBlt (13) */
		0xFF, 0x01,	/* fset = 0x01FF (little-endian) */
		0x01, 0x00,	/* cid = 1 */
		0x32, 0x00,	/* left  = 50 */
		0x3C, 0x00,	/* top   = 60 */
		0x64, 0x00,	/* width = 100 */
		0x64, 0x00,	/* height= 100 */
		0xCC,		/* rop3 = Scopy */
		0x0A, 0x00,	/* src.x = 10 */
		0x14, 0x00,	/* src.y = 20 */
		0x05, 0x00,	/* coff = 5 */
	};
	Imgupd up;
	int n;

	memset(&up, 0, sizeof up);
	n = getfupd(&up, pkt, sizeof pkt);
	if(n != (int)sizeof pkt)
		sysfatal("testegdimemblt: consumed: want %d, got %d", (int)sizeof pkt, n);
	if(up.type != Umemblt)
		sysfatal("testegdimemblt: type: want %d, got %d", Umemblt, up.type);
	if(up.cid != 1)
		sysfatal("testegdimemblt: cid: want 1, got %d", up.cid);
	if(up.coff != 5)
		sysfatal("testegdimemblt: coff: want 5, got %d", up.coff);
	if(up.x != 50 || up.y != 60)
		sysfatal("testegdimemblt: pos: want (50,60), got (%d,%d)", up.x, up.y);
	if(up.xm != 149 || up.ym != 159)
		sysfatal("testegdimemblt: max: want (149,159), got (%d,%d)", up.xm, up.ym);
	if(up.xsz != 100 || up.ysz != 100)
		sysfatal("testegdimemblt: size: want (100,100), got (%d,%d)", up.xsz, up.ysz);
	if(up.sx != 10 || up.sy != 20)
		sysfatal("testegdimemblt: src: want (10,20), got (%d,%d)", up.sx, up.sy);
	if(up.clipped != 0)
		sysfatal("testegdimemblt: clipped: want 0, got %d", up.clipped);
	return 0;
}

static int
testegdimembltclip(void)
{
	/*
	 * MemBlt with Clipped flag set.
	 * Unlike ScrBlt, MemBlt does not call rectclip(); it stores the clip-rect
	 * coordinates directly in Imgupd.{cx,cy,cxsz,cysz}.
	 *   ctl = Standard|NewOrder|Clipped (0x0D)
	 *   clip rect: (0,0)-(200,100) via cfclipr with bctl=0x0F
	 *   rect: left=50,top=60,width=100,height=100 → r={(50,60),(150,160)}
	 */
	uchar pkt[] = {
		0x0D,		/* ctl: Standard|NewOrder|Clipped */
		0x0D,		/* order: MemBlt (13) */
		0xFF, 0x01,	/* fset = 0x01FF (little-endian) */
		/* cfclipr: bctl=0x0F (bits 0-3 = all absolute coords) */
		0x0F,
		0x00, 0x00,	/* min.x = 0 */
		0x00, 0x00,	/* min.y = 0 */
		0xC7, 0x00,	/* max.x: stored 199, +1 → 200 */
		0x63, 0x00,	/* max.y: stored 99,  +1 → 100 */
		/* getmemblt data */
		0x01, 0x00,	/* cid = 1 */
		0x32, 0x00,	/* left  = 50 */
		0x3C, 0x00,	/* top   = 60 */
		0x64, 0x00,	/* width = 100 */
		0x64, 0x00,	/* height= 100 */
		0xCC,		/* rop3 = Scopy */
		0x0A, 0x00,	/* src.x = 10 */
		0x14, 0x00,	/* src.y = 20 */
		0x05, 0x00,	/* coff = 5 */
	};
	Imgupd up;
	int n;

	memset(&up, 0, sizeof up);
	n = getfupd(&up, pkt, sizeof pkt);
	if(n != (int)sizeof pkt)
		sysfatal("testegdimembltclip: consumed: want %d, got %d", (int)sizeof pkt, n);
	if(up.type != Umemblt)
		sysfatal("testegdimembltclip: type: want %d, got %d", Umemblt, up.type);
	if(up.clipped != 1)
		sysfatal("testegdimembltclip: clipped: want 1, got %d", up.clipped);
	if(up.cx != 0 || up.cy != 0)
		sysfatal("testegdimembltclip: clip pos: want (0,0), got (%d,%d)", up.cx, up.cy);
	if(up.cxsz != 200 || up.cysz != 100)
		sysfatal("testegdimembltclip: clip size: want (200,100), got (%d,%d)", up.cxsz, up.cysz);
	return 0;
}

static int
testegdicmapcache(void)
{
	/*
	 * CacheCmap secondary order: cache a 256-entry colour map.
	 * Packet layout: 6-byte secondary header + 1-byte cid + 2-byte count + 1024-byte table.
	 * Total size = 1033.  GSHORT(p+1) = 1033 - 13 = 1020 = 0x03FC.
	 */
	static uchar pkt[1033];
	Imgupd up;
	int n, i;

	memset(pkt, 0, sizeof pkt);
	pkt[0] = 0x03;		/* ctl: Standard|Secondary */
	pkt[1] = 0xFC;		/* GSHORT(p+1) low  = 0xFC (1020 & 0xFF) */
	pkt[2] = 0x03;		/* GSHORT(p+1) high = 0x03 → size-13=1020 → size=1033 */
	pkt[3] = 0x00;		/* opt low */
	pkt[4] = 0x00;		/* opt high */
	pkt[5] = 0x01;		/* xorder: CacheCmap */
	pkt[6] = 0x03;		/* cid = 3 */
	pkt[7] = 0x00;		/* n = 256, low byte */
	pkt[8] = 0x01;		/* n = 256, high byte (GSHORT = 0x0100 = 256) */
	/* colour table at pkt[9..1032] */
	for(i = 0; i < 1024; i++)
		pkt[9+i] = (uchar)(i & 0xFF);

	memset(&up, 0, sizeof up);
	n = getfupd(&up, pkt, sizeof pkt);
	if(n != 1033)
		sysfatal("testegdicmapcache: consumed: want 1033, got %d", n);
	if(up.type != Umcache)
		sysfatal("testegdicmapcache: type: want %d, got %d", Umcache, up.type);
	if(up.cid != 3)
		sysfatal("testegdicmapcache: cid: want 3, got %d", up.cid);
	if(up.nbytes != 1024)
		sysfatal("testegdicmapcache: nbytes: want 1024, got %d", up.nbytes);
	if(up.bytes != pkt+9)
		sysfatal("testegdicmapcache: bytes ptr: want pkt+9, got something else");
	return 0;
}

static int
testegdiimgcache2(void)
{
	/*
	 * CacheImage2 secondary order (uncompressed, no persistent key).
	 *   opt = 0 → cid=0, no persistent key, read ysz separately, no compr hdr skip.
	 *   xsz = 8 (single byte, high bit clear).
	 *   ysz = 8 (single byte, high bit clear).
	 *   pixel-data size = 32 (encoded as single byte 0x20: n=bits[7:6]=0, g=bits[5:0]=32).
	 *   coff = 2 (single byte, high bit clear).
	 * Packet: 6-byte secondary header + 4-byte data header + 32-byte pixel data = 42 bytes.
	 * GSHORT(p+1) = 42 - 13 = 29 = 0x1D.
	 */
	uchar pkt[42];
	Imgupd up;
	int n;

	memset(pkt, 0xAA, sizeof pkt);	/* fill pixel region with known pattern */
	pkt[0] = 0x03;		/* ctl: Standard|Secondary */
	pkt[1] = 0x1D;		/* GSHORT(p+1) low  = 29 → size = 42 */
	pkt[2] = 0x00;		/* GSHORT(p+1) high */
	pkt[3] = 0x00;		/* opt low */
	pkt[4] = 0x00;		/* opt high */
	pkt[5] = 0x04;		/* xorder: CacheImage2 */
	pkt[6] = 0x08;		/* xsz = 8 */
	pkt[7] = 0x08;		/* ysz = 8 */
	pkt[8] = 0x20;		/* size: n=0 (bits 7-6=00), g=32 (bits 5-0) */
	pkt[9] = 0x02;		/* coff = 2 */
	/* pkt[10..41]: pixel data (already 0xAA from memset) */

	memset(&up, 0, sizeof up);
	n = getfupd(&up, pkt, sizeof pkt);
	if(n != (int)sizeof pkt)
		sysfatal("testegdiimgcache2: consumed: want %d, got %d", (int)sizeof pkt, n);
	if(up.type != Uicache)
		sysfatal("testegdiimgcache2: type: want %d, got %d", Uicache, up.type);
	if(up.cid != 0)
		sysfatal("testegdiimgcache2: cid: want 0, got %d", up.cid);
	if(up.coff != 2)
		sysfatal("testegdiimgcache2: coff: want 2, got %d", up.coff);
	if(up.xsz != 8 || up.ysz != 8)
		sysfatal("testegdiimgcache2: dim: want (8,8), got (%d,%d)", up.xsz, up.ysz);
	if(up.nbytes != 32)
		sysfatal("testegdiimgcache2: nbytes: want 32, got %d", up.nbytes);
	if(up.bytes != pkt+10)
		sysfatal("testegdiimgcache2: bytes ptr: want pkt+10, got something else");
	if(up.iscompr != 0)
		sysfatal("testegdiimgcache2: iscompr: want 0, got %d", up.iscompr);
	return 0;
}

static int
testegdisecunsup(void)
{
	/*
	 * Secondary order with an xorder value not present in auxtab
	 * (CacheImage=0, auxtab[0].get==nil).
	 * getfupd should print a warning, skip the entire order, and return size.
	 * size = 20, GSHORT(p+1) = 20 - 13 = 7.
	 */
	uchar pkt[20];
	Imgupd up;
	int n;

	memset(pkt, 0, sizeof pkt);
	pkt[0] = 0x03;		/* ctl: Standard|Secondary */
	pkt[1] = 0x07;		/* GSHORT(p+1) = 7 → size = 20 */
	pkt[2] = 0x00;
	pkt[3] = 0x00;		/* opt */
	pkt[4] = 0x00;
	pkt[5] = 0x00;		/* xorder: CacheImage (0), not handled in auxtab */

	memset(&up, 0, sizeof up);
	n = getfupd(&up, pkt, sizeof pkt);
	if(n != 20)
		sysfatal("testegdisecunsup: consumed: want 20, got %d", n);
	return 0;
}

int
egditests(void)
{
	testegdinonstd();
	testegdiscrblt();
	testegdiscrblclip();
	testegdimemblt();
	testegdimembltclip();
	testegdicmapcache();
	testegdiimgcache2();
	testegdisecunsup();
	return 0;
}
