/* [MS-RDPEFS]: Remote Desktop Protocol: File System Virtual Channel Extension */
#include <u.h>
#include <libc.h>
#include "dat.h"
#include "fns.h"

int
sendefsmsg(Rdp* c, Efsmsg* m)
{
	int n;
	uchar buf[64];

	n = putefsmsg(buf, sizeof buf, m);
	if(n < 0)
		return n;
	return sendvc(c, "RDPDR", buf, n);
}

/* 3.2.5.1.3 Sending a Client Announce Reply Message */
static void
clientidconfirm(Rdp* c)
{
	Efsmsg t;

	t.ctype = CTcore;
	t.pakid = CCann; /* 2.2.2.3 Client Announce Reply */
	t.vermaj = 1;
	t.vermin = 13;
	t.cid = c->efs.cid;

	if(sendefsmsg(c, &t) < 0)
		fprint(2, "clientidconfirm: %r\n");
}

static void
clientnamereq(Rdp* c)
{
	Efsmsg t;

	t.ctype = CTcore;
	t.pakid = CCnrq;	/* 2.2.2.4 Client Name Request */
	t.cname = c->local;

// fprint(2, "DBG clientnamereq: %s\n", c->local);
	if(sendefsmsg(c, &t) < 0)
		fprint(2, "clientnamereq: %r\n");
}


/* 3.1.3 Initialization */
static void
serverannounced(Rdp* c, Efsmsg* r)
{
	/* r is 2.2.2.2 Server Announce Request */
	if(r->vermin >= 12){
		c->efs.cid = r->cid;
//fprint(2, "DBG c->efs.cid = %lud\n", (ulong)c->efs.cid);
	}else{
		c->efs.cid = lrand();
	}
	clientidconfirm(c);
	clientnamereq(c);
	/* BUG we'd expect receiving Server Core Capability Request (section 2.2.2.7)
	followed by Server Client ID Confirm (2.2.2.6) - but never get them */
}

void
efsvcfn(Rdp* c, uchar* a, uint nb)
{
	Efsmsg r;

	if(getefsmsg(&r, a, nb) < 0){
		fprint(2, "EFS: %r");
		return;
	}
	if(r.ctype != CTcore)
		return; // no printing
	switch(r.pakid){
	case CSann:
		serverannounced(c, &r);
		break;
	default:
		fprint(2, "EFS: new msg: %.*H\n", nb, a);
		return;
	}
}

int
getefsmsg(Efsmsg* m, uchar* a, int nb)
{
	if(nb < 4){
		werrstr(Eshort);
		return -1;
	}
	/* 2.2.1.1 Shared Header (RDPDR_HEADER)
	 * ctype[2] pakid[2]
	 */
	m->ctype = GSHORT(a);
	m->pakid = GSHORT(a+2);
	switch(m->ctype+m->pakid<<16){
	case CTcore+CSann<<16:
		/* 2.2.2.2 Server Announce Request */
		if(nb < 12){
			werrstr(Eshort);
			return -1;
		}
		m->vermaj = GSHORT(a+4);
		m->vermin = GSHORT(a+6);
		m->cid = GLONG(a+8);
		break;
	default:
		werrstr("unrecognised packet type (%x:%x)",
			m->ctype, m->pakid);
		return -1;
	}
	return 0;
}

int
putefsmsg(uchar* a, int nb, Efsmsg* m)
{
	int n, len;

	n = (2+2);
	if(nb < n){
		werrstr(Esmall);
		return -1;
	}
	PSHORT(a, m->ctype);
	PSHORT(a+2, m->pakid);
	switch(m->ctype+m->pakid<<16){
	case CTcore+CCann<<16:
		/* 2.2.2.3 Client Announce Reply */
		n = (2+2)+(2+2+4);
		if(nb < n){
			werrstr(Esmall);
			return -1;
		}
		PSHORT(a+4, m->vermaj);
		PSHORT(a+6, m->vermin);
		PLONG(a+8, m->cid);
		break;
	case CTcore+CCnrq<<16:
		/* 2.2.2.4 Client Name Request */
		len = strlen(m->cname)+1;
		if(nb < 16){
			werrstr(Esmall);
			return -1;
		}
		PLONG(a+4, 1);	// UnicodeFlag
		PLONG(a+8, 0); // CodePage
		n = toutf16(a+16, nb-16, m->cname, len);
		PLONG(a+12, n);
		return 16+n;
	default:
		werrstr("unrecognised packet type (%x:%x)",
			m->ctype, m->pakid);
		return -1;
	}	return n;
}
