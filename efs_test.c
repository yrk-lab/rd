#include <u.h>
#include <libc.h>
#include "dat.h"
#include "fns.h"

char Eshort[]=	"short data";
char Esmall[]=	"buffer too small";
int sendvc(Rdp*, char*, uchar*, int) { return -1; }

void testcann(void);
void testcnrq(void);
void testsannrq(void);

int audiotests(void);
int msgtests(void);

void
testsannrq()
{
	int n, nb;
	uchar buf[32];
	Efsmsg m;
	char *sannrq;


	n = getefsmsg(&m, nil, 0);
	if(n >= 0)
		sysfatal("testsannrq: expected error");	

	memset(buf, 8, 0);
	n = getefsmsg(&m, buf, 8);
	if(n >= 0)
		sysfatal("testsannrq: expected error");	

	sannrq = "72446E4901000D0005000000";
	nb = dec16(buf, sizeof buf, sannrq, strlen(sannrq));
	//fmtinstall('H', encodefmt);
	//fprint(2, "testsannrq %.*H\n", nb, buf);
	n = getefsmsg(&m, buf, nb);
	if(n < 0)
		sysfatal("testsannrq: unexpected error: %r\n");
	if(m.ctype != CTcore)
		sysfatal("testsannrq: m.ctype: expected 0x%x, got 0x%x\n", CTcore, m.ctype);
	if(m.pakid != CSann)
		sysfatal("testsannrq: m.pakid: expected 0x%x, got 0x%x\n", CSann, m.pakid);
	if(m.vermaj != 1)
		sysfatal("testsannrq: m.vermaj: expected %d, got %d\n", 1, m.vermaj);
	if(m.vermin != 13)
		sysfatal("testsannrq: m.vermin: expected %d, got %d\n", 13, m.vermin);
	if(m.cid != 5)
		sysfatal("testsannrq: m.cid: expected %d, got %d\n", 5, m.cid);
}

void
testcann()
{
	int n;
	uchar buf[32];
	Efsmsg m;
	char *targ,*s;

	m.ctype = CTcore;
	m.pakid = CCann;
	m.vermaj = 1;
	m.vermin = 13;
	m.cid = 5;
	n = putefsmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testcann: unexpected errror: %r");
	fmtinstall('H', encodefmt);
	s = smprint("%.*H", n, buf);
	targ = 
		"7244"	// Header->RDPDR_CTYP_CORE = 0x4472
		"4343"	// Header->PAKID_CORE_CLIENTID_CONFIRM = 0x4343
		"0100"	// VersionMajor = 0x0001
		"0D00"	// VersionMinor = 0x000d
		"05000000";	// ClientId = 0x00000005
	if(strcmp(s, targ) != 0)
		sysfatal("testcann: expected %s, got %s", targ, s);
	if(n != strlen(targ)/2)
		sysfatal("testcann: ret: expected %ld, got %d",
			strlen(targ)/2, n);
}

void
testcnrq()
{
	int n;
	uchar buf[64];
	Efsmsg t;
	char *targ,*s;

	t.ctype = CTcore;
	t.pakid= CCnrq;
	t.cname = "TSDEV-SELFHOST";
	n = putefsmsg(buf, sizeof buf, &t);
	if(n < 0)
		sysfatal("testcann: unexpected errror: %r");
	fmtinstall('H', encodefmt);
	s = smprint("%.*H", n, buf);
	/* [MS-RDPEFS] 4.5 Client Name Request */
	targ =
		"7244"	// Header->RDPDR_CTYP_CORE = 0x4472
		"4E43"	// Header->PAKID_CORE_CLIENT_NAME = 0x434e
		"01000000"	// UnicodeFlag = 0x00000001
		"00000000"	// CodePage = 0x00000000
		"1E000000"	// ComputerNameLen = 0x0000001e (30)
		"54005300"	// ComputerName
		"44004500"	// ComputerName (continued)
		"56002D00"	// ComputerName (continued)
		"53004500"	// ComputerName (continued)
		"4C004600"	// ComputerName (continued)
		"48004F00"	// ComputerName (continued)
		"53005400"	// ComputerName (continued)
		"0000";	// ComputerName (continued)
	if(strcmp(s, targ) != 0)
		sysfatal("testcann: expected %s, got %s", targ, s);
	if(n != strlen(targ)/2)
		sysfatal("testcann: ret: expected %ld, got %d",
			strlen(targ)/2, n);
}

void
main(int, char**)
{
	testsannrq();
	testcann();
	testcnrq();
	audiotests();
	msgtests();
	print("ok\n");
	exits(nil);
}
