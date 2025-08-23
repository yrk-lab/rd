/* [MS-RDPEA]: Remote Desktop Protocol: Audio Output Virtual Channel Extension */
#include <u.h>
#include <libc.h>
#include "dat.h"
#include "fns.h"

/*
[MS-RDPEA] "6 Appendix A: Product Behavior":
<1> Section 2.1: In Windows, the client advertises the static virtual
channel named "RDPDR", as defined in [MS-RDPEFS].  If that channel is
not advertised, the server will not issue any communication on the
"RDPSND" channel.  Not supported on Windows XP and Windows Server
2003.
*/

static char	rdpsnd[]				= "RDPSND";

enum	/* Audiomsg.type */
{
	Awinf=	2,	/* WaveInfo PDU */
	Awav=	0,	/* Wave PDU - always follows Awinf */
	Awack=	5,	/* Wave Confirm PDU */
	Aping=	6,	/* Training PDU or Training Confirm PDU */
	Afmt=	7,	/* Client/Server Audio Formats and Version PDU */
	Afin=	1,	/* 2.2.3.9 Close PDU */
};

enum /* RFC2361 Appendix A */
{
	FmtPCM=	0x01,	/* WAVE_FORMAT_PCM */		
};

typedef	struct	Audiomsg Audiomsg;
struct Audiomsg
{
	uint	type;
	uint	nfmt;	/* Afmt */
	uint	seq;	/* Afmt, Awinf, Awack */
	uint	time;	/* Awinf, Awack, Aping */
	uint	ping;	/* Aping */
	uint	ver;	/* Afmt */
	uint	ndata;	/* Afmt, Awinf */
	uint	nxdata;	/* Awinf */
	uchar	*data;	/* Afmt, Awinf, Awav */
};
static	int	audiogetmsg(Audiomsg*,uchar*,int);
static	int	audioputmsg(uchar*,int, Audiomsg*);
static	int	audiosendmsg(Rdp*, Audiomsg*);
static	void	sfmtrcvd(Rdp*,Audiomsg*);
static	void	winfrcvd(Rdp*,Audiomsg*);
static	void	wavrcvd(Rdp*,Audiomsg*);
static	void	pingrcvd(Rdp*,Audiomsg*);
static	void	finrcvd(Rdp*,Audiomsg*);
static	void	sendcfmt(Rdp*);
static	void	sendwack(Rdp*);
static	void	sendping(Rdp*, uint, uint);

void
audiovcfn(Rdp* c, uchar* a, uint nb)
{
	Audiomsg r;

	if(audiogetmsg(&r, a, nb) < 0){
		fprint(2, "audio: %r\n");
		return;
	}
	switch(r.type){
	case Afmt:	sfmtrcvd(c, &r); break;
	case Awinf:	winfrcvd(c, &r); break;
	case Awav:	wavrcvd(c, &r); break;
	case Aping:	pingrcvd(c, &r); break;
	case Afin:	finrcvd(c, &r); break;
	}
}

static void
sfmtrcvd(Rdp* c, Audiomsg* r)
{
	c->audio.seq = r->seq;
	sendcfmt(c);
}

static void
winfrcvd(Rdp* c, Audiomsg* r)
{
	c->audio.seq = r->seq;
	c->audio.time = r->time;
	playsound(c, r->data, r->ndata);
}

static void
wavrcvd(Rdp* c, Audiomsg* r)
{
	playsound(c, r->data, r->ndata);
	sendwack(c);
}

static void
pingrcvd(Rdp* c, Audiomsg* r)
{
	sendping(c, r->time, r->ping);
}

static void
finrcvd(Rdp* c, Audiomsg* r)
{
	USED(c);
	USED(r);
}

static void
sendcfmt(Rdp* c)
{
	Audiomsg t;

	t.type = Afmt;
	if(audiosendmsg(c, &t) < 0)
		fprint(2, "audio: sendcfmt: %r\n");
}

static void
sendwack(Rdp* c)
{
	Audiomsg t;

	t.type = Awack;
	t.seq = c->audio.seq;
	t.time = c->audio.time;
	if(audiosendmsg(c, &t) < 0)
		fprint(2, "audio: sendwack: %r\n");
}

static void
sendping(Rdp* c, uint time, uint v)
{
	Audiomsg t;

	t.type = Aping;
	t.time = time;
	t.ping = v;
	if(audiosendmsg(c, &t) < 0)
		fprint(2, "audio: sendping: %r\n");
}

/*
 * 2.2.1 RDPSND PDU Header (SNDPROLOG)
 *	msgtype[1] pad[1] bodysize[2]
 *
 * 2.2.2.1 Server Audio Formats and Version PDU
 *	hdr[4] flags[4] vol[4] pitch[4] dgport[2] nfmt[2] ack[1] ver[2] pad[1] nfmt*(afmt[*])
 *
 * 2.2.2.1.1 Audio Format (AUDIO_FORMAT)
 *	ftag[2] nchan[2] samphz[4] avgbytehz[4] blocksz[2] sampbitsz[2] ndata[2] data[ndata]
 */

static int
audiogetmsg(Audiomsg* m, uchar* a, int nb)
{
	ulong len;

	if(nb < 4){
		werrstr(Eshort);
		return -1;
	}
	
	m->type = *a;
	len = GSHORT(a+2);
	switch(m->type){
	case Afmt:
		if(len < 20 || nb < len+4){
			werrstr(Eshort);
			return -1;
		}
		m->nfmt = GSHORT(a+18);
		m->seq = a[20];
		m->ver = GSHORT(a+21);
		m->data = a+24;
		m->ndata = len-20;
		return len+4;
	case Awinf:
		if(len < 16 || nb < 16){
			werrstr(Eshort);
			return -1;
		}
		m->time = GSHORT(a+4);
		m->seq = a[8];
		m->data = a+12;
		m->ndata = 4;
		m->nxdata = len-16;
		return 16;
	case Awav:
		m->data = a+4;
		m->ndata = nb-4;
		return nb;
	case Aping:
		if(nb < 8){
			werrstr(Eshort);
			return -1;
		}
		m->time = GSHORT(a+4);
		m->ping = GSHORT(a+6);
		return 8;	
	case Afin:
		return 4;
	}
	werrstr("unrecognized audio msg type(%ud)", m->type);
	return -1;
}

static int
audioputmsg(uchar* a, int n, Audiomsg* m)
{
	int len;

	switch(m->type){
	case Afmt:
		len = 42-4;
		if(n < 42){
			werrstr(Esmall);
			return -1;
		}
		a[0] = m->type;
		a[1] = 0; // pad
		PSHORT(a+2, len);
		PLONG(a+4, 1);	// flags: 1=alive
		PLONG(a+8, 0xffffffff);	// volume: l=100, r=100
		PLONG(a+12, 1<<16);	// pitch
		PSHORT(a+16, 0);	// dgport
		PSHORT(a+18, 1);	// nfmt
		a[20] = 0;	// seq
		PSHORT(a+21, 5);	// ver
		a[23] = 0;	// pad
		// afmt[0]
		PSHORT(a+24, FmtPCM);	// ftag
		PSHORT(a+26, 2);	// nchan
		PLONG(a+28, 44100);	// samphz
		PLONG(a+32, 44100*2*2);	// avgbytehz
		PSHORT(a+36, 4);	// blocksz (nchan*sampbitsz/8)
		PSHORT(a+38, 16);	// sampbitsz
		PSHORT(a+40, 0);	// ndata
		/* NOTE: we shouldn't send this unless the server
		 * also declared support for the exact same format */
		return 42;
	case Awack:
		len = 8-4;
		if(n < 8){
			werrstr(Esmall);
			return -1;
		}
		a[0] = m->type;
		a[1] = 0; // pad
		PSHORT(a+2, len);
		PSHORT(a+4, m->time);
		a[6] = m->seq;
		a[7] = 0;	// pad
		return 8;
	case Aping:
		len = 8-4;
		if(n < 8){
			werrstr(Esmall);
			return -1;
		}
		a[0] = m->type;
		a[1] = 0; // pad
		PSHORT(a+2, len);
		PSHORT(a+4, m->time);
		PSHORT(a+6, m->ping);
		return 8;
	}
	werrstr("unrecognized audio msg type(%ud)", m->type);
	return -1;
}


static int
audiosendmsg(Rdp* c, Audiomsg* m)
{
	int n;
	uchar buf[64];

	n = audioputmsg(buf, sizeof buf, m);
	if(n < 0)
		return n;
	return sendvc(c, rdpsnd, buf, n);
}
