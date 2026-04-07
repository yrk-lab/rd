#include "msg.c"

static int
testputmsgxconnect(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Xconnect;
	m.negproto = ProtoTLS;
	n = putmsg(buf, sizeof buf, &m);

	if(n < 0)
		sysfatal("testputmsgxconnect: unexpected error: %r\n");
	s = smprint("%.*H", n, buf);
	want = "0300002722E00000000000436F6F6B69653A206D737473686173683D780D0A0100080001000000";
	if(strcmp(s, want) != 0)
		sysfatal("testputmsgxconnect: want %s, got %s", want, s);
	free(s);
	return 0;

}

static int
testputmsgxconnectnla(void)
{
	/* Xconnect advertising HYBRID+HYBRID_EX (ProtoCSSP|ProtoUAUTH) for NLA */
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Xconnect;
	m.negproto = ProtoCSSP | ProtoUAUTH;
	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgxconnectnla: unexpected error: %r\n");
	s = smprint("%.*H", n, buf);
	want = "0300002722E00000000000436F6F6B69653A206D737473686173683D780D0A010008000A000000";
	if(strcmp(s, want) != 0)
		sysfatal("testputmsgxconnectnla: want %s, got %s", want, s);
	free(s);
	return 0;
}

static int
testputmsgxhangup(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Xhangup;
	n = putmsg(buf, sizeof buf, &m);

	if(n < 0)
		sysfatal("testputmsgxhangup: unexpected error: %r\n");
	s = smprint("%.*H", n, buf);
	if(strcmp(s, want = "03000007028080") != 0)
		sysfatal("testputmsgxhangup: want %s, got %s", want, s);
	free(s);
	return 0;

}

static int
testputmsgmattach(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Mattach;
	n = putmsg(buf, sizeof buf, &m);

	if(n < 0)
		sysfatal("testputmsgmattach: unexpected error: %r\n");
	s = smprint("%.*H", n, buf);
	if(strcmp(s, want = "0300000802F08028") != 0)
		sysfatal("testputmsgmattach: want %s, got %s", want, s);
	free(s);
	return 0;

}

static int
testputmsgmjoin(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Mjoin;
	m.mcsuid = 0xdead;
	m.chanid = 0xbeef;
	n = putmsg(buf, sizeof buf, &m);

	if(n < 0)
		sysfatal("testputmsgmjoin: unexpected error: %r\n");
	s = smprint("%.*H", n, buf);
	if(strcmp(s, want = "0300000C02F08038DEADBEEF") != 0)
		sysfatal("testputmsgmjoin: want %s, got %s", want, s);
	free(s);
	return 0;

}

static int
testputmsgmerectdom(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Merectdom;
	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgmerectdom: unexpected error: %r\n");

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want = "0300000C02F0800400010001") != 0)
		sysfatal("testputmsgmerectdom: want %s, got %s", want, s);
	free(s);
	return 0;

}


static int
testputmsgmconnect(void){
	int n;
	char *s, *want;
	uchar buf[1024];
	Msg m;
	Vchan vctab[] = {
		{ .mcsid = GLOBALCHAN+1, .name = "CLIPRDR", .flags = 1<<31 },
		{ .mcsid = GLOBALCHAN+2, .name = "RDPDR", .flags = 1<<31 },
	};

	m.type = Mconnect;
	m.ver = 0x80004;	/* RDP5 */
	m.depth = 32;
	m.xsz = 1024;
	m.ysz = 768;
	m.sysname = "TSCLIENT-TEST";
	m.sproto = ProtoTLS;
	m.wantconsole = 0;
	m.nvc = 2;
	m.vctab = vctab;

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgmconnect: unexpected error: %r\n");

	want = "030001A602F0807F6582019A0401010401010101FF30200202002202020002020200000202000102020000020200010202FFFF020200023020020200010202000102020001020200010202000002020001020204200202000230200202FFFF0202FFFF0202FFFF0202000102020000020200010202FFFF0202000204820127000500147C0001811E000800100001C00044756361811001C0D800040008000004000301CA03AA09040000280A00005400530043004C00490045004E0054002D00540045005300540000000000000004000000000000000C0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001CA01000000000018000F0003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007000100000002C00C00000000000000000004C00C00090000000000000003C0200002000000434C49505244520080000000524450445200000080000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0){
		fprint(2, "testputmsgmconnect: want '%s', got '%s'\n", want, s);
		sysfatal("testputmsgmconnect");
	}
	free(s);
	return 0;

}

static int
testputmsgdclientinfo(void){
	int n;
	char *s, *want;
	uchar buf[4*1024];
	Msg m;

	m.type = Dclientinfo;
	m.mcsuid = 0xBEEF;
	m.dom = "TESTDOM";
	m.user = "testuser";
	m.pass = "secret";
	m.rshell = "explorer.exe";
	m.rwd = "C:\\";
	m.dologin = 1;

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgdclientinfo: unexpected error: %r\n");

	want = "0300013302F08064BEEF03EB7081244000000000000000BB0300000E0010000C0018000600540045005300540044004F004D00000074006500730074007500730065007200000073006500630072006500740000006500780070006C006F007200650072002E00650078006500000043003A005C00000002000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000CE000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0){
		fprint(2, "testputmsgdclientinfo: want '%s', got '%s'\n", want, s);
		sysfatal("testputmsgdclientinfo");
	}
	free(s);
	return 0;

}

static int
testputmsgmactivated(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Mactivated;
	m.originid = 0xAAAA;
	m.mcsuid = 0xBBBB;
	m.shareid = 0xCCCC;
	m.xsz = 1024;
	m.ysz = 600;
	m.depth = 32;

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgmactivated: unexpected error: %r\n");

	want = "0300018402F08064BBBB03EB70817575011300BBBBCCCC0000AAAA07005E01506C616E2039000800000001001800000000000002000000000504000000000000000002001E002000010001000100000458020000010001000000010001000000030058000000000000000000000000000000000000000000010014000000010000006A000000010100000000000000000000000000000000000000000000000000000000A1060000000000000084030000000000E40004001300280000000003780000007800000050010000000000000000000000000000000000000000000008000800000014000D005800110000000904000004000000000000000C000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000C00080000000000140008000000000010003400FE000400FE000400FE000800FE000800FE001000FE002000FE004000FE008000FE000001400000080001000100000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0){
		fprint(2, "testputmsgmactivated: want '%s', got '%s'\n", want, s);
		sysfatal("testputmsgmactivated");
	}
	free(s);
	return 0;

}

static int
testputmsgmvchan(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	enum {
		First=	1<<0,
		Last=	1<<1,
		Vis=  	1<<4,
	};
	Msg m = {
		.type = Mvchan,
		.originid = 0x1111,
		.chanid = 0x2222,
		.flags = First | Vis | Last,
		.len = 7,
		.ndata = 7,
		.data = (uchar*)"abcdefg",
	};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgmvchan: unexpected error: %r\n");

	want = "0300001E02F080641111222270800F070000001300000061626364656667";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsgmvchan: want '%s', got '%s'", want, s);
	free(s);
	return 0;
}

static int
testputmsgasync(void){
	int n;
	char *s, *want;
	uchar buf[512];
	Msg m = {
		.type = Async,
		.mcsuid = 0x1111,
		.originid = 0x2222,
		.shareid = 0x3333,
	};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgasync: unexpected error: %r\n");

	want = "0300002502F08064222203EB70801616001700222233330000000116001F00000001001111";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsgasync: want '%s', got '%s'", want, s);
	free(s);
	return 0;
}

static int
testputmsgactlcoop(void){
	int n;
	char *s, *want;
	uchar buf[1024];
	Msg m = {.type = Actl, .action = CAcooperate, .originid = 0x1111, .shareid = 0x2222};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgactlcoop: unexpected error: %r\n");

	want = "0300002902F08064111103EB70801A1A00170011112222000000011A00140000000400000000000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsgactlcoop: want '%s', got '%s'", want, s);
	free(s);
	return 0;
}

static int
testputmsgactlreqctl(void){
	int n;
	char *s, *want;
	uchar buf[1024];
	Msg m = {.type = Actl, .action = CAreqctl, .originid = 0x3333, .shareid = 0x4444};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgactlreqctl: unexpected error: %r\n");

	want = "0300002902F08064333303EB70801A1A00170033334444000000011A00140000000100000000000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsgactlreqctl: want '%s', got '%s'", want, s);
	free(s);
	return 0;
}

static int
testputmsgafontls(void){
	int n;
	char *s, *want;
	uchar buf[1024];
	Msg m = {.type = Afontls, .originid = 0x4444, .shareid = 0x5555};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgafontls: unexpected error: %r\n");

	want = "0300002902F08064444403EB70801A1A00170044445555000000011A00270000000000000003003200";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsgafontls: want '%s', got '%s'", want, s);
	free(s);
	return 0;
}

static int
testputmsgainputsync(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Ainput;
	m.originid = 0x1111;
	m.shareid = 0x2222;
	m.msec = 0;
	m.mtype = InputSync;
	m.flags = 0;
	m.iarg[0] = 0;
	m.iarg[1] = 0;

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgainputsync: unexpected error: %r\n");

	want = "0300003102F08064111103EB70802222001700111122220000000122001C00000001000000000000000000000000000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsgainputsync: want '%s', got '%s'", want, s);
	free(s);
	return 0;

}

static int
testputmsgainputkey(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;
	enum {
		Slshift=	42,
	};

	m.type = Ainput;
	m.originid = 0x1111;
	m.shareid = 0x2222;
	m.msec = 0x3333;
	m.mtype = InputKeycode;
	m.flags = 0x44;
	m.iarg[0] = Slshift;
	m.iarg[1] = 0;

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgainputkey: unexpected error: %r\n");

	want = "0300003102F08064111103EB70802222001700111122220000000122001C0000000100000033330000040044002A000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsgainputkey: want '%s', got '%s'", want, s);
	free(s);
	return 0;

}

static int
testputmsglreq(void){
	int n;
	char *s, *want;
	uchar buf[2*1024];

	Msg m = {.type = Lreq, .sysname = "TESTSYS", .user = "testuser", .originid=0x1111};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsglreq: unexpected error: %r\n");

	want = 
		// TPKT header
		"03"			// version[1] = 3
		"00"			// unused[1] = 0
		"008C"		// len[2]

		// TPDU header
		"02"			// hdlen[1] = 2
		"F0"			// type[1] = Data
		"80"			// seqno[1] = (0 in Class 0) + EOT mark (1<<7)

		// MCS Send Data Request: header
		"64"			// type = Msdr(25) <<2
		"1111"		// mcsuid = m.originid (0x1111)
		"03EB"		// chanid = GLOBALCHAN(1003)
		"70"			// always 0x70
		"807D"		// 0x8000 | ndata(125)

		// MCS Send Data Request: data
		"80000000"	// sechdr[4]: secflags[4] = Slicensepk(0x80)
		"13"			// type[1] = CNeedLicense
		"03"			// flags[1] = PreambleV3
		"7900"		// size[2]
		"01000000"	// kexalg[4] = KeyExRSA
		"00000000"	// platfid[4] = 0
		"0000000000000000" "0000000000000000"
		"0000000000000000" "0000000000000000"
					// crandom[32] = 32 {0}

		// premaster[blob]
		"0200"		// type[2] = Brandom(2)
		"3000"		// len[2] = 48
		"0000000000000000" "0000000000000000"
		"0000000000000000" "0000000000000000"
		"0000000000000000" "0000000000000000"
					// data[len] = 48 {0}

		// cuser[blob]
		"0F00"		// type[2] = Bcuser(15)
		"0900"		// len[2] = 9
		"746573747573657200"
					// data[len] = "testuser\0"

		// chost[blob]
		"1000"		// type[2] = Bchost(16)
		"0800"		// len[2] = 8
		"5445535453595300"
					// data[len] = "TESTSYS\0"
		;

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0){
		fprint(2, "testputmsglreq: want '%s', got '%s'\n", want, s);
		sysfatal("testputmsglreq");
	}
	free(s);
	return 0;
}

static int
testputmsglnolicense(void){
	int n;
	char *s, *want;
	uchar buf[1024];
	Msg m = {.type = Lnolicense, .originid=0x1111};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsglnolicense: unexpected error: %r\n");

	want =
		"0300002302F08064111103EB70801480000000FF031000020000000100000004000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsglnolicense: want '%s', got '%s'", want, s);
	free(s);
	return 0;
}

static int
testputmsgdsupress(void){
	int n;
	char *s, *want;
	uchar buf[512];
	Msg m = {
		.type = Dsupress,
		.originid = 0x2222,
		.shareid = 0x3333,
		.xsz = 1280,
		.ysz = 800,
		.allow = 1,
	};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsgdsupress: unexpected error: %r\n");

	want =
		"0300002D02F08064222203EB70801E1E00170022223333000000011E00230000000100000000000000FF041F03";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsgdsupress: want '%s', got '%s'", want, s);
	free(s);
	return 0;
}


static int
testgetmsgfp2(void)
{
	/* Fast-path update: 2-byte length header */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	char *hex = "0006DEADBEEF";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgfp2: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgfp2: type: want %d, got %d", Aupdate, m.type);
	if(m.ndata != 4)
		sysfatal("testgetmsgfp2: ndata: want 4, got %d", m.ndata);
	if(m.getshare != getshareF)
		sysfatal("testgetmsgfp2: getshare: expected getshareF");
	return 0;
}

static int
testgetmsgfp3(void)
{
	/* Fast-path update: 3-byte length header */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	char *hex = "008006AABBCC";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgfp3: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgfp3: type: want %d, got %d", Aupdate, m.type);
	if(m.ndata != 3)
		sysfatal("testgetmsgfp3: ndata: want 3, got %d", m.ndata);
	if(m.getshare != getshareF)
		sysfatal("testgetmsgfp3: getshare: expected getshareF");
	return 0;
}

static int
testgetmsgxconntls(void)
{
	/* X.224 connection confirm with TLS negotiation response */
	int n, nb;
	uchar buf[32];
	Msg m = {0};
	char *hex = "0300001306D000000000000200080001000000";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgxconntls: unexpected error: %r");
	if(m.type != Xconnected)
		sysfatal("testgetmsgxconntls: type: want %d, got %d", Xconnected, m.type);
	if(m.negproto != ProtoTLS)
		sysfatal("testgetmsgxconntls: negproto: want %d (ProtoTLS), got %d", ProtoTLS, m.negproto);
	return 0;
}

static int
testgetmsgxconnhybridex(void)
{
	/* X.224 connection confirm with HYBRID_EX (ProtoUAUTH) selected by server */
	int n, nb;
	uchar buf[32];
	Msg m = {0};
	char *hex = "0300001306D000000000000200080008000000";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgxconnhybridex: unexpected error: %r");
	if(m.type != Xconnected)
		sysfatal("testgetmsgxconnhybridex: type: want %d, got %d", Xconnected, m.type);
	if(m.negproto != ProtoUAUTH)
		sysfatal("testgetmsgxconnhybridex: negproto: want %d (ProtoUAUTH), got %d", ProtoUAUTH, m.negproto);
	return 0;
}

static int
testgetmsgxconnnonego(void)
{
	/* X.224 connection confirm with non-matching nego type: negproto stays 0 */
	int n, nb;
	uchar buf[32];
	Msg m = {0};
	char *hex = "0300001306D000000000000100080000000000";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgxconnnonego: unexpected error: %r");
	if(m.type != Xconnected)
		sysfatal("testgetmsgxconnnonego: type: want %d, got %d", Xconnected, m.type);
	if(m.negproto != 0)
		sysfatal("testgetmsgxconnnonego: negproto: want 0, got %d", m.negproto);
	return 0;
}

static int
testgetmsgmattacheduid(void)
{
	/* MCS Attach User Confirm with userId present */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	char *hex = "0300000B02F0802E00BEEF";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgmattacheduid: unexpected error: %r");
	if(m.type != Mattached)
		sysfatal("testgetmsgmattacheduid: type: want %d, got %d", Mattached, m.type);
	if(m.mcsuid != 0xBEEF)
		sysfatal("testgetmsgmattacheduid: mcsuid: want 0xBEEF, got 0x%X", m.mcsuid);
	return 0;
}

static int
testgetmsgmattachednouid(void)
{
	/* MCS Attach User Confirm without userId */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	char *hex = "0300000902F0802C00";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgmattachednouid: unexpected error: %r");
	if(m.type != Mattached)
		sysfatal("testgetmsgmattachednouid: type: want %d, got %d", Mattached, m.type);
	if(m.mcsuid != 0)
		sysfatal("testgetmsgmattachednouid: mcsuid: want 0, got 0x%X", m.mcsuid);
	return 0;
}

static int
testgetmsgmjoined(void)
{
	/* MCS Channel Join Confirm */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	char *hex = "0300000902F0803C00";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgmjoined: unexpected error: %r");
	if(m.type != Mjoined)
		sysfatal("testgetmsgmjoined: type: want %d, got %d", Mjoined, m.type);
	return 0;
}

static int
testgetmsgmclosing(void)
{
	/* Disconnect Provider Ultimatum */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	char *hex = "0300000902F0802180";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgmclosing: unexpected error: %r");
	if(m.type != Mclosing)
		sysfatal("testgetmsgmclosing: type: want %d, got %d", Mclosing, m.type);
	return 0;
}

static int
testgetmsgmvchan(void)
{
	/* MCS virtual channel data (non-global channel) */
	int n, nb;
	uchar buf[64];
	Msg m = {0};
	char *hex = "0300001E02F080681111222270800F070000001300000061626364656667";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgmvchan: unexpected error: %r");
	if(m.type != Mvchan)
		sysfatal("testgetmsgmvchan: type: want %d, got %d", Mvchan, m.type);
	if(m.chanid != 0x2222)
		sysfatal("testgetmsgmvchan: chanid: want 0x2222, got 0x%X", m.chanid);
	if(m.len != 7)
		sysfatal("testgetmsgmvchan: len: want 7, got %d", m.len);
	if(m.flags != 0x13)
		sysfatal("testgetmsgmvchan: flags: want 0x13, got 0x%lX", m.flags);
	if(m.ndata != 7)
		sysfatal("testgetmsgmvchan: ndata: want 7, got %d", m.ndata);
	if(memcmp(m.data, "abcdefg", 7) != 0)
		sysfatal("testgetmsgmvchan: data mismatch");
	return 0;
}

static int
testgetmsgspupdate(void)
{
	/* Slow-path update on global channel */
	int n, nb;
	uchar buf[32];
	Msg m = {0};
	char *hex = "0300001302F08068111103EB70800400000000";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgspupdate: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgspupdate: type: want %d, got %d", Aupdate, m.type);
	if(m.ndata != 4)
		sysfatal("testgetmsgspupdate: ndata: want 4, got %d", m.ndata);
	if(m.getshare != getshareT)
		sysfatal("testgetmsgspupdate: getshare: expected getshareT");
	return 0;
}

static int
testgetmsgmattacherr(void)
{
	/* Error: MCS Attach User Confirm with non-zero error result */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	char *hex = "0300000902F0802C01";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n >= 0)
		sysfatal("testgetmsgmattacherr: expected error, got %d", n);
	return 0;
}

static int
testgetmsgmjoinerr(void)
{
	/* Error: MCS Channel Join Confirm with non-zero error result */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	char *hex = "0300000902F0803C01";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n >= 0)
		sysfatal("testgetmsgmjoinerr: expected error, got %d", n);
	return 0;
}

static int
testgetmsgfpencr(void)
{
	/* Error: legacy encryption in fast-path PDU */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	char *hex = "8006DEADBEEF";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n >= 0)
		sysfatal("testgetmsgfpencr: expected error, got %d", n);
	return 0;
}

static int
testgetmsgaflow(void)
{
	/* Flow PDU on global channel (isflowpdu): GSHORT = 0x8000 → Aflow */
	int n, nb;
	uchar buf[32];
	Msg m = {0};
	char *hex = "0300001302F08068111103EB70800400800000";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgaflow: unexpected error: %r");
	if(m.type != Aflow)
		sysfatal("testgetmsgaflow: type: want %d (Aflow), got %d", Aflow, m.type);
	return 0;
}

static int
testgetmsglicpksctlv1(void)
{
	/*
	 * Slow-path on global channel with Slicensepk flag but sctlver==1.
	 * The condition "secflg&Slicensepk && sctlver != 1" is false, so
	 * getlicensemsg is NOT called and the PDU falls through to Aupdate.
	 */
	int n, nb;
	uchar buf[32];
	Msg m = {0};
	char *hex = "0300001302F08068111103EB70800480001000";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsglicpksctlv1: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsglicpksctlv1: type: want %d (Aupdate), got %d", Aupdate, m.type);
	if(m.ndata != 4)
		sysfatal("testgetmsglicpksctlv1: ndata: want 4, got %d", m.ndata);
	if(m.getshare != getshareT)
		sysfatal("testgetmsglicpksctlv1: getshare: expected getshareT");
	return 0;
}

static int
testgetmsgldone(void)
{
	/* License PDU with Notify (0xFF) type → Ldone */
	int n, nb;
	uchar buf[32];
	Msg m = {0};
	char *hex = "0300001402F08068111103EB70800580000000FF";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgldone: unexpected error: %r");
	if(m.type != Ldone)
		sysfatal("testgetmsgldone: type: want %d (Ldone), got %d", Ldone, m.type);
	return 0;
}

static int
testgetmsglneedlicense(void)
{
	/* License PDU with SNeedLicense (0x01) type → Lneedlicense */
	int n, nb;
	uchar buf[32];
	Msg m = {0};
	char *hex = "0300001402F08068111103EB7080058000000001";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsglneedlicense: unexpected error: %r");
	if(m.type != Lneedlicense)
		sysfatal("testgetmsglneedlicense: type: want %d (Lneedlicense), got %d", Lneedlicense, m.type);
	return 0;
}

static int
testgetmsglhavechal(void)
{
	/* License PDU with SHaveChal (0x02) type → Lhavechal */
	int n, nb;
	uchar buf[32];
	Msg m = {0};
	char *hex = "0300001402F08068111103EB7080058000000002";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsglhavechal: unexpected error: %r");
	if(m.type != Lhavechal)
		sysfatal("testgetmsglhavechal: type: want %d (Lhavechal), got %d", Lhavechal, m.type);
	return 0;
}

static int
testgetmsgspdeactivate(void)
{
	/*
	 * Slow-path Deactivate All PDU (PDUdeactivate=6) on global channel:
	 * getmsg → Aupdate / getshareT → ShDeactivate
	 */
	int n, nb;
	uchar buf[32];
	Msg m = {0};
	Share u = {0};
	char *hex =
		/* TPKT + X.224 Data */
		"0300001502F080"
		/* MCS SDI on GLOBALCHAN, data length=6 */
		"68" "1111" "03EB" "70" "8006"
		/* Share Control Header: totalLength=6, pduType=6 (PDUdeactivate), source */
		"0600" "0600" "1111";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgspdeactivate: getmsg: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgspdeactivate: type: want Aupdate, got %d", m.type);
	if(m.getshare != getshareT)
		sysfatal("testgetmsgspdeactivate: getshare: expected getshareT");
	n = m.getshare(&u, m.data, m.ndata);
	if(n <= 0)
		sysfatal("testgetmsgspdeactivate: getshare: unexpected error: %r");
	if(u.type != ShDeactivate)
		sysfatal("testgetmsgspdeactivate: share type: want ShDeactivate (%d), got %d", ShDeactivate, u.type);
	return 0;
}

static int
testgetmsgspeinfo(void)
{
	/*
	 * Slow-path Set Error Info PDU (ADerrx=47) on global channel:
	 * getmsg → Aupdate / getshareT → ShEinfo, err=0x1234
	 */
	int n, nb;
	uchar buf[64];
	Msg m = {0};
	Share u = {0};
	char *hex =
		/* TPKT + X.224 Data */
		"0300002502F080"
		/* MCS SDI on GLOBALCHAN, data length=22 */
		"68" "1111" "03EB" "70" "8016"
		/* Share Control Header: totalLength=22, pduType=7 (PDUdata), source */
		"1600" "0700" "1111"
		/* Share Data Header: shareId, pad, streamId, uncomprLen=22, pduType2=47 (ADerrx), comprType, comprLen */
		"EFBEADDE" "00" "01" "1600" "2F" "00" "0000"
		/* Error code: 0x1234 (LE) */
		"34120000";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgspeinfo: getmsg: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgspeinfo: type: want Aupdate, got %d", m.type);
	if(m.getshare != getshareT)
		sysfatal("testgetmsgspeinfo: getshare: expected getshareT");
	n = m.getshare(&u, m.data, m.ndata);
	if(n <= 0)
		sysfatal("testgetmsgspeinfo: getshare: unexpected error: %r");
	if(u.type != ShEinfo)
		sysfatal("testgetmsgspeinfo: share type: want ShEinfo (%d), got %d", ShEinfo, u.type);
	if(u.err != 0x1234)
		sysfatal("testgetmsgspeinfo: err: want 0x1234, got 0x%X", u.err);
	return 0;
}

static int
testgetmsgsporders(void)
{
	/*
	 * Slow-path Drawing Orders update (ADdraw/UpdOrders=0) on global channel:
	 * getmsg → Aupdate / getshareT → ShUorders, nr=3
	 */
	int n, nb;
	uchar buf[64];
	Msg m = {0};
	Share u = {0};
	char *hex =
		/* TPKT + X.224 Data */
		"0300002902F080"
		/* MCS SDI on GLOBALCHAN, data length=26 */
		"68" "1111" "03EB" "70" "801A"
		/* Share Control Header: totalLength=26, pduType=7 (PDUdata), source */
		"1A00" "0700" "1111"
		/* Share Data Header: shareId, pad, streamId, uncomprLen=26, pduType2=2 (ADdraw), comprType, comprLen */
		"EFBEADDE" "00" "01" "1A00" "02" "00" "0000"
		/* TS_GRAPHICS_UPDATE: updateType=0 (UpdOrders), pad, pad, numberOrders=3, pad */
		"0000" "0000" "0300" "0000";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgsporders: getmsg: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgsporders: type: want Aupdate, got %d", m.type);
	if(m.getshare != getshareT)
		sysfatal("testgetmsgsporders: getshare: expected getshareT");
	n = m.getshare(&u, m.data, m.ndata);
	if(n <= 0)
		sysfatal("testgetmsgsporders: getshare: unexpected error: %r");
	if(u.type != ShUorders)
		sysfatal("testgetmsgsporders: share type: want ShUorders (%d), got %d", ShUorders, u.type);
	if(u.nr != 3)
		sysfatal("testgetmsgsporders: nr: want 3, got %d", u.nr);
	return 0;
}

static int
testgetmsgspbitmap(void)
{
	/*
	 * Slow-path Bitmap Update (ADdraw/UpdBitmap=1) on global channel:
	 * getmsg → Aupdate / getshareT → ShUimg, nr=2
	 */
	int n, nb;
	uchar buf[64];
	Msg m = {0};
	Share u = {0};
	char *hex =
		/* TPKT + X.224 Data */
		"0300002502F080"
		/* MCS SDI on GLOBALCHAN, data length=22 */
		"68" "1111" "03EB" "70" "8016"
		/* Share Control Header: totalLength=22, pduType=7 (PDUdata), source */
		"1600" "0700" "1111"
		/* Share Data Header: shareId, pad, streamId, uncomprLen=22, pduType2=2 (ADdraw), comprType, comprLen */
		"EFBEADDE" "00" "01" "1600" "02" "00" "0000"
		/* TS_GRAPHICS_UPDATE: updateType=1 (UpdBitmap), numberRectangles=2 */
		"0100" "0200";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgspbitmap: getmsg: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgspbitmap: type: want Aupdate, got %d", m.type);
	if(m.getshare != getshareT)
		sysfatal("testgetmsgspbitmap: getshare: expected getshareT");
	n = m.getshare(&u, m.data, m.ndata);
	if(n <= 0)
		sysfatal("testgetmsgspbitmap: getshare: unexpected error: %r");
	if(u.type != ShUimg)
		sysfatal("testgetmsgspbitmap: share type: want ShUimg (%d), got %d", ShUimg, u.type);
	if(u.nr != 2)
		sysfatal("testgetmsgspbitmap: nr: want 2, got %d", u.nr);
	return 0;
}

static int
testgetmsgspcmap(void)
{
	/*
	 * Slow-path Color Table Cache Update (ADdraw/UpdCmap=2) on global channel:
	 * getmsg → Aupdate / getshareT → ShUcmap
	 */
	int n, nb;
	uchar buf[64];
	Msg m = {0};
	Share u = {0};
	char *hex =
		/* TPKT + X.224 Data */
		"0300002302F080"
		/* MCS SDI on GLOBALCHAN, data length=20 */
		"68" "1111" "03EB" "70" "8014"
		/* Share Control Header: totalLength=20, pduType=7 (PDUdata), source */
		"1400" "0700" "1111"
		/* Share Data Header: shareId, pad, streamId, uncomprLen=20, pduType2=2 (ADdraw), comprType, comprLen */
		"EFBEADDE" "00" "01" "1400" "02" "00" "0000"
		/* TS_GRAPHICS_UPDATE: updateType=2 (UpdCmap) */
		"0200";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgspcmap: getmsg: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgspcmap: type: want Aupdate, got %d", m.type);
	if(m.getshare != getshareT)
		sysfatal("testgetmsgspcmap: getshare: expected getshareT");
	n = m.getshare(&u, m.data, m.ndata);
	if(n <= 0)
		sysfatal("testgetmsgspcmap: getshare: unexpected error: %r");
	if(u.type != ShUcmap)
		sysfatal("testgetmsgspcmap: share type: want ShUcmap (%d), got %d", ShUcmap, u.type);
	return 0;
}

static int
testgetmsgspwarp(void)
{
	/*
	 * Slow-path Pointer Position Update (ADcursor/PDUcursorwarp=3) on global channel:
	 * getmsg → Aupdate / getshareT → ShUwarp, x=100, y=200
	 */
	int n, nb;
	uchar buf[64];
	Msg m = {0};
	Share u = {0};
	char *hex =
		/* TPKT + X.224 Data */
		"0300002902F080"
		/* MCS SDI on GLOBALCHAN, data length=26 */
		"68" "1111" "03EB" "70" "801A"
		/* Share Control Header: totalLength=26, pduType=7 (PDUdata), source */
		"1A00" "0700" "1111"
		/* Share Data Header: shareId, pad, streamId, uncomprLen=26, pduType2=27 (ADcursor), comprType, comprLen */
		"EFBEADDE" "00" "01" "1A00" "1B" "00" "0000"
		/* TS_POINTER_PDU: messageType=3 (PDUcursorwarp), pad, pad, x=100, y=200 */
		"0300" "0000" "6400" "C800";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgspwarp: getmsg: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgspwarp: type: want Aupdate, got %d", m.type);
	if(m.getshare != getshareT)
		sysfatal("testgetmsgspwarp: getshare: expected getshareT");
	n = m.getshare(&u, m.data, m.ndata);
	if(n <= 0)
		sysfatal("testgetmsgspwarp: getshare: unexpected error: %r");
	if(u.type != ShUwarp)
		sysfatal("testgetmsgspwarp: share type: want ShUwarp (%d), got %d", ShUwarp, u.type);
	if(u.x != 100)
		sysfatal("testgetmsgspwarp: x: want 100, got %d", u.x);
	if(u.y != 200)
		sysfatal("testgetmsgspwarp: y: want 200, got %d", u.y);
	return 0;
}

static int
testgetmsgfporders(void)
{
	/*
	 * Fast-path Drawing Orders update (FUpdOrders=0):
	 * getmsg → Aupdate / getshareF → ShUorders, nr=5
	 */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	Share u = {0};
	/* action=0, total=7; updateHeader=0 (FUpdOrders), size=2, numberOrders=5 */
	char *hex = "0007" "00" "0200" "0500";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgfporders: getmsg: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgfporders: type: want Aupdate, got %d", m.type);
	if(m.getshare != getshareF)
		sysfatal("testgetmsgfporders: getshare: expected getshareF");
	n = m.getshare(&u, m.data, m.ndata);
	if(n <= 0)
		sysfatal("testgetmsgfporders: getshare: unexpected error: %r");
	if(u.type != ShUorders)
		sysfatal("testgetmsgfporders: share type: want ShUorders (%d), got %d", ShUorders, u.type);
	if(u.nr != 5)
		sysfatal("testgetmsgfporders: nr: want 5, got %d", u.nr);
	return 0;
}

static int
testgetmsgfpbitmap(void)
{
	/*
	 * Fast-path Bitmap Update (FUpdBitmap=1):
	 * getmsg → Aupdate / getshareF → ShUimg, nr=3
	 */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	Share u = {0};
	/* action=0, total=9; updateHeader=1 (FUpdBitmap), size=4, pad, numberRectangles=3 */
	char *hex = "0009" "01" "0400" "0000" "0300";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgfpbitmap: getmsg: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgfpbitmap: type: want Aupdate, got %d", m.type);
	if(m.getshare != getshareF)
		sysfatal("testgetmsgfpbitmap: getshare: expected getshareF");
	n = m.getshare(&u, m.data, m.ndata);
	if(n <= 0)
		sysfatal("testgetmsgfpbitmap: getshare: unexpected error: %r");
	if(u.type != ShUimg)
		sysfatal("testgetmsgfpbitmap: share type: want ShUimg (%d), got %d", ShUimg, u.type);
	if(u.nr != 3)
		sysfatal("testgetmsgfpbitmap: nr: want 3, got %d", u.nr);
	return 0;
}

static int
testgetmsgfpcmap(void)
{
	/*
	 * Fast-path Color Table Cache Update (FUpdCmap=2):
	 * getmsg → Aupdate / getshareF → ShUcmap
	 */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	Share u = {0};
	/* action=0, total=5; updateHeader=2 (FUpdCmap), size=0 */
	char *hex = "0005" "02" "0000";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgfpcmap: getmsg: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgfpcmap: type: want Aupdate, got %d", m.type);
	if(m.getshare != getshareF)
		sysfatal("testgetmsgfpcmap: getshare: expected getshareF");
	n = m.getshare(&u, m.data, m.ndata);
	if(n <= 0)
		sysfatal("testgetmsgfpcmap: getshare: unexpected error: %r");
	if(u.type != ShUcmap)
		sysfatal("testgetmsgfpcmap: share type: want ShUcmap (%d), got %d", ShUcmap, u.type);
	return 0;
}

static int
testgetmsgfpwarp(void)
{
	/*
	 * Fast-path Pointer Position Update (FUpdWarp=8):
	 * getmsg → Aupdate / getshareF → ShUwarp, x=100, y=200
	 */
	int n, nb;
	uchar buf[16];
	Msg m = {0};
	Share u = {0};
	/* action=0, total=9; updateHeader=8 (FUpdWarp), size=4, x=100, y=200 */
	char *hex = "0009" "08" "0400" "6400" "C800";

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetmsgfpwarp: getmsg: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetmsgfpwarp: type: want Aupdate, got %d", m.type);
	if(m.getshare != getshareF)
		sysfatal("testgetmsgfpwarp: getshare: expected getshareF");
	n = m.getshare(&u, m.data, m.ndata);
	if(n <= 0)
		sysfatal("testgetmsgfpwarp: getshare: unexpected error: %r");
	if(u.type != ShUwarp)
		sysfatal("testgetmsgfpwarp: share type: want ShUwarp (%d), got %d", ShUwarp, u.type);
	if(u.x != 100)
		sysfatal("testgetmsgfpwarp: x: want 100, got %d", u.x);
	if(u.y != 200)
		sysfatal("testgetmsgfpwarp: y: want 200, got %d", u.y);
	return 0;
}

static int
testgetcapsgenbmp(void)
{
	/*
	 * Server Demand Active PDU containing two capability sets:
	 *   CapGeneral (type=1, len=24): canrefresh=1, cansupress=1
	 *   CapBitmap  (type=2, len=16): depth=32, xsz=1024, ysz=768
	 * getcaps is exercised via getmsg → getshareT → getcaps.
	 */
	int n, nb;
	uchar buf[128];
	Msg m = {0};
	Share as = {0};
	Caps caps;
	char *hex =
		/* TPKT + X.224 Data */
		"0300004902F080"
		/* MCS Send Data Indication on GLOBALCHAN */
		"68" "1111" "03EB" "70" "803A"
		/* Share Control Header: totalLength=58, PDUactivate, source */
		"3A00" "0100" "1111"
		/* shareid(LE), nsrc=0, capsLen=44 */
		"EFBEADDE" "0000" "2C00"
		/* ncap=2, pad */
		"02000000"
		/* CapGeneral: type=1, len=24; canrefresh=p[22]=1, cansupress=p[23]=1 */
		"01001800"
		"00000000000000000000"	// data[4..13]
		"0000000000000000"	// data[14..21]
		"0101"			// canrefresh, cansupress
		/* CapBitmap: type=2, len=16; depth=32, xsz=1024, ysz=768 */
		"02001000"
		"2000"			// depth=32
		"000000000000"		// receive* fields
		"00040003";		// xsz=1024 (LE), ysz=768 (LE)

	nb = dec16(buf, sizeof buf, hex, strlen(hex));
	n = getmsg(&m, buf, nb);
	if(n <= 0)
		sysfatal("testgetcapsgenbmp: getmsg: unexpected error: %r");
	if(m.type != Aupdate)
		sysfatal("testgetcapsgenbmp: type: want Aupdate, got %d", m.type);
	if(m.getshare != getshareT)
		sysfatal("testgetcapsgenbmp: getshare: expected getshareT");
	n = m.getshare(&as, m.data, m.ndata);
	if(n <= 0)
		sysfatal("testgetcapsgenbmp: getshare: unexpected error: %r");
	if(as.type != ShActivate)
		sysfatal("testgetcapsgenbmp: share type: want ShActivate, got %d", as.type);
	n = getcaps(&caps, as.data, as.ndata);
	if(n < 0)
		sysfatal("testgetcapsgenbmp: getcaps: unexpected error: %r");
	if(!caps.general)
		sysfatal("testgetcapsgenbmp: caps.general: want 1, got 0");
	if(caps.canrefresh != 1)
		sysfatal("testgetcapsgenbmp: canrefresh: want 1, got %d", caps.canrefresh);
	if(caps.cansupress != 1)
		sysfatal("testgetcapsgenbmp: cansupress: want 1, got %d", caps.cansupress);
	if(!caps.bitmap)
		sysfatal("testgetcapsgenbmp: caps.bitmap: want 1, got 0");
	if(caps.depth != 32)
		sysfatal("testgetcapsgenbmp: depth: want 32, got %d", caps.depth);
	if(caps.xsz != 1024)
		sysfatal("testgetcapsgenbmp: xsz: want 1024, got %d", caps.xsz);
	if(caps.ysz != 768)
		sysfatal("testgetcapsgenbmp: ysz: want 768, got %d", caps.ysz);
	return 0;
}

int
msgtests(void)
{
	fmtinstall('H', encodefmt);
	testputmsgxconnect();
	testputmsgxconnectnla();
	testputmsgxhangup();
	testputmsgmattach();
	testputmsgmjoin();
	testputmsgmerectdom();
	testputmsgmconnect();
	testputmsgdclientinfo();
	testputmsgmactivated();
	testputmsgmvchan();
	testputmsgasync();
	testputmsgactlcoop();
	testputmsgactlreqctl();
	testputmsgafontls();
	testputmsgainputsync();
	testputmsgainputkey();
	testputmsglreq();
	testputmsglnolicense();
	testputmsgdsupress();
	testgetmsgfp2();
	testgetmsgfp3();
	testgetmsgxconntls();
	testgetmsgxconnhybridex();
	testgetmsgxconnnonego();
	testgetmsgmattacheduid();
	testgetmsgmattachednouid();
	testgetmsgmjoined();
	testgetmsgmclosing();
	testgetmsgmvchan();
	testgetmsgspupdate();
	testgetmsgmattacherr();
	testgetmsgmjoinerr();
	testgetmsgfpencr();
	testgetmsgaflow();
	testgetmsglicpksctlv1();
	testgetmsgldone();
	testgetmsglneedlicense();
	testgetmsglhavechal();
	testgetmsgspdeactivate();
	testgetmsgspeinfo();
	testgetmsgsporders();
	testgetmsgspbitmap();
	testgetmsgspcmap();
	testgetmsgspwarp();
	testgetmsgfporders();
	testgetmsgfpbitmap();
	testgetmsgfpcmap();
	testgetmsgfpwarp();
	testgetcapsgenbmp();
	return 0;
}
