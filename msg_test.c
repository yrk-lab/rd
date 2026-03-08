#include "msg.c"

char Ebignum[]=	"number too big";

static int
testputmsg1(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Xconnect;
	m.negproto = ProtoTLS;
	n = putmsg(buf, sizeof buf, &m);

	if(n < 0)
		sysfatal("testputmsg1: unexpected error: %r\n");
	s = smprint("%.*H", n, buf);
	want = "0300002722E00000000000436F6F6B69653A206D737473686173683D780D0A0100080001000000";
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg1: want %s, got %s", want, s);
	return 0;

}

static int
testputmsg2(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Xhangup;
	n = putmsg(buf, sizeof buf, &m);

	if(n < 0)
		sysfatal("testputmsg2: unexpected error: %r\n");
	s = smprint("%.*H", n, buf);
	if(strcmp(s, want = "03000007028080") != 0)
		sysfatal("testputmsg2: want %s, got %s", want, s);
	return 0;

}

static int
testputmsg3(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Mattach;
	n = putmsg(buf, sizeof buf, &m);

	if(n < 0)
		sysfatal("testputmsg3: unexpected error: %r\n");
	s = smprint("%.*H", n, buf);
	if(strcmp(s, want = "0300000802F08028") != 0)
		sysfatal("testputmsg3: want %s, got %s", want, s);
	return 0;

}

static int
testputmsg4(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Mjoin;
	m.mcsuid = 0xdead;
	m.chanid = 0xbeef;
	n = putmsg(buf, sizeof buf, &m);

	if(n < 0)
		sysfatal("testputmsg4: unexpected error: %r\n");
	s = smprint("%.*H", n, buf);
	if(strcmp(s, want = "0300000C02F08038DEADBEEF") != 0)
		sysfatal("testputmsg4: want %s, got %s", want, s);
	return 0;

}

static int
testputmsg5(void){
	int n;
	char *s, *want;
	uchar buf[1042];
	Msg m;

	m.type = Merectdom;
	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsg5: unexpected error: %r\n");

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want = "0300000C02F0800400010001") != 0)
		sysfatal("testputmsg5: want %s, got %s", want, s);
	return 0;

}


static int
testputmsg6(void){
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
		sysfatal("testputmsg6: unexpected error: %r\n");

	// Edit s/................/&" "/g
	want =
		"030001A602F0807F6582019A04010104" "01010101FF3020020200220202000202"
		"02000002020001020200000202000102" "02FFFF02020002302002020001020200"
		"01020200010202000102020000020200" "01020204200202000230200202FFFF02"
		"02FFFF0202FFFF020200010202000002" "0200010202FFFF020200020482012700"
		"0500147C0001811E000800100001C000" "44756361811001C0D800040008000004"
		"000301CA03AA09040000280A00005400" "530043004C00490045004E0054002D00"
		"54004500530054000000F90700000400" "0000000000000C000000080000000600"
		"010044AC000044AC0000010008000000" "070002002256000044AC000002000800"
		"00000700010044AC000044AC00000100" "0800000002000200225601CA01000000"
		"000018000F0003000700000100000002" "00FF00000000C0004000F0000000CC01"
		"30FF880118FF1100020022560000B956" "0000000404000200F9030200010044AC"
		"0000A3560000000407000100000002C0" "0C00000000000000000004C00C000900"
		"00000000000003C0200002000000434C" "49505244520080000000524450445200"
		"000080000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg6: want '%s', got '%s'", want, s);
	return 0;

}

static int
testputmsg7(void){
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
		sysfatal("testputmsg7: unexpected error: %r\n");

	// Edit s/................................................................/&"\n		"/g
	want = 
		"AwABMwLwgGS+7wPrcIEkQAAAAAAAAAC7AwAADgAQAAwAGAAGAFQARQBTAFQARABP"
		"AE0AAAB0AGUAcwB0AHUAcwBlAHIAAABzAGUAYwByAGUAdAAAAGUAeABwAGwAbwBy"
		"AGUAcgAuAGUAeABlAAAAQwA6AFwAAAACAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAzgAAAA==";

	s = smprint("%.*[", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg7: want '%s', got '%s'", want, s);
	return 0;

}

static int
testputmsg8(void){
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

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsg8: unexpected error: %r\n");

	// Edit s/................................................................/&"\n		"/g
	want =
		"AwABhALwgGS7uwPrcIF1dQETALu7zMwAAKqqBwBeAVBsYW4gOQAIAAAAAQAYAAAA"
		"AAAAAgIAAAAFBAAAAAAAAAAAAgAeAAAAAQABAAEAAARYAgAAAQABAAAAAQAAAAIA"
		"AwBYAAECAgQgAgIAAjAgAgL//wIAAAAAAQAUAAAAAQAAAGoAAAABAQAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAChBgAAAAAAAACEAwAAAAAA5AAEABMAKAAAAAAD"
		"eAAAAHgAAABQAQAAAAAAAAAAAABUAEUAUwBUAAAA+QcIAAgAAAAUAA0AWAARAAAA"
		"CQQAAAQAAAAAAAAADAAAAAgAAAAHAAIAIlYAAESsAAACAAgAAAAHAAEARKwAAESs"
		"AAABAAgAAAACAAIAIlYBygEAAAAAABgADwADAAcAAAEMAAgAAAAAABQACAAAAAAA"
		"EAA0AP4ABAD+AAQA/gAIAP4ACAD+ABAA/gAgAP4AQAD+AIAA/gAAAUAAAAgAAQAB"
		"AAAAAA==";

	s = smprint("%.*[", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg8: want '%s', got '%s'", want, s);
	return 0;

}

static int
testputmsg9(void){
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
		sysfatal("testputmsg9: unexpected error: %r\n");

	want = "0300001E02F080641111222270800F070000001300000061626364656667";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg9: want '%s', got '%s'", want, s);
	return 0;
}

static int
testputmsg10(void){
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
		sysfatal("testputmsg10: unexpected error: %r\n");

	want = "0300002502F08064222203EB70801616001700222233330000000116001F00000001001111";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg10: want '%s', got '%s'", want, s);
	return 0;
}

static int
testputmsg11(void){
	int n;
	char *s, *want;
	uchar buf[1024];
	Msg m = {.type = Actl, .action = CAcooperate, .originid = 0x1111, .shareid = 0x2222};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsg11: unexpected error: %r\n");

	want = "0300002902F08064111103EB70801A1A00170011112222000000011A00140000000400000000000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg11: want '%s', got '%s'", want, s);
	return 0;
}

static int
testputmsg12(void){
	int n;
	char *s, *want;
	uchar buf[1024];
	Msg m = {.type = Actl, .action = CAreqctl, .originid = 0x3333, .shareid = 0x4444};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsg12: unexpected error: %r\n");

	want = "0300002902F08064333303EB70801A1A00170033334444000000011A00140000000100000000000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg12: want '%s', got '%s'", want, s);
	return 0;
}

static int
testputmsg13(void){
	int n;
	char *s, *want;
	uchar buf[1024];
	Msg m = {.type = Afontls, .originid = 0x4444, .shareid = 0x5555};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsg13: unexpected error: %r\n");

	want = "0300002902F08064444403EB70801A1A00170044445555000000011A00270000000000000003003200";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg13: want '%s', got '%s'", want, s);
	return 0;
}

static int
testputmsg14(void){
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
		sysfatal("testputmsg14: unexpected error: %r\n");

	// Edit s/................/&" "/g
	want =
		"0300003102F08064" "111103EB70802222" "0017001111222200" "00000122001C0000"
		"0001000000000000" "0000000000000000" "00";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg14: want '%s', got '%s'", want, s);
	return 0;

}

static int
testputmsg15(void){
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
		sysfatal("testputmsg15: unexpected error: %r\n");

	// Edit s/................/&" "/g
	want =
		"0300003102F08064" "111103EB70802222" "0017001111222200" "00000122001C0000"
		"0001000000333300" "00040044002A0000" "00";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg15: want '%s', got '%s'", want, s);
	return 0;

}

static int
testputmsg16(void){
	int n;
	char *s, *want;
	uchar buf[2*1024];
	Msg m = {.type = Lreq, .sysname = "TESTSYS", .user = "testuser", .originid=0x1111};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsg16: unexpected error: %r\n");

	// Edit s/................/&" "/g
	want = 
		"0300008C02F08064" "111103EB70807D80" "0000001303790001" "0000000000000000"
		"0000000000000000" "0000000000000000" "0000000000000000" "0000000000000002"
		"0030000000000000" "0000000000000000" "0000000000000000" "0000000000000000"
		"0000000000000000" "0000000000000000" "0000000F00090074" "6573747573657200"
		"1000080054455354" "53595300";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg16: want '%s', got '%s'", want, s);
	return 0;
}

static int
testputmsg17(void){
	int n;
	char *s, *want;
	uchar buf[1024];
	Msg m = {.type = Lnolicense, .originid=0x1111};

	n = putmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testputmsg17: unexpected error: %r\n");

	// Edit s/................/&" "/g
	want =
		"0300002302F08064" "111103EB70801480"
		"000000FF03100002" "0000000100000004"
		"000000";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg17: want '%s', got '%s'", want, s);
	return 0;
}

static int
testputmsg18(void){
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
		sysfatal("testputmsg18: unexpected error: %r\n");

	// Edit s/................/&" "/g
	want =
		"0300002D02F08064" "222203EB70801E1E"
		"0017002222333300" "0000011E00230000"
		"0001001111000000" "00FF041F03";

	s = smprint("%.*H", n, buf);
	if(strcmp(s, want) != 0)
		sysfatal("testputmsg18: want '%s', got '%s'", want, s);
	return 0;
}


int
msgtests()
{
	fmtinstall('H', encodefmt);
	fmtinstall('[', encodefmt);
	testputmsg1();
	testputmsg2();
	testputmsg3();
	testputmsg4();
	testputmsg5();
	testputmsg6();
	testputmsg7();
	testputmsg8();
	testputmsg9();
	testputmsg10();
	testputmsg11();
	testputmsg12();
	testputmsg13();
	testputmsg14();
	testputmsg15();
	testputmsg16();
	testputmsg17();
	testputmsg18();
	return 0;
}
