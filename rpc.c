#include <u.h>
#include <libc.h>
#include <auth.h>
#include <libsec.h>
#include "dat.h"
#include "fns.h"

static void	applyvc(Rdp*, Msg*);
static void	applyupdates(Rdp*, Msg*);

extern
	int	mcsconnect(Rdp*);
	int	attachuser(Rdp*);
	int	joinchannel(Rdp*,int,int);

	int	defragvc(Rdp*,Msg*);
	void	callvcfunc(Rdp*,Msg*);


int
x224handshake(Rdp* c)
{
	Msg t, r;

	t.type = Xconnect;
	/* advertise HYBRID_EX (ProtoUAUTH) alongside HYBRID so the server
	 * may send the Early User Authorization Result PDU ([MS-RDPBCGR] 2.2.1.14) */
	t.negproto = c->nla ? (ProtoCSSP | ProtoUAUTH) : ProtoTLS;
	if(writemsg(c, &t) <= 0)
		return -1;
	if(readmsg(c, &r) <= 0)
		return -1;
	if(r.type != Xconnected){
		werrstr("X.224: protocol botch");
		return -1;
	}
	if(c->nla){
		/* server may select HYBRID (ProtoCSSP) or HYBRID_EX (ProtoUAUTH) */
		if((r.negproto & (ProtoCSSP | ProtoUAUTH)) == 0){
			werrstr("server refused CredSSP");
			return -1;
		}
	}else{
		if((r.negproto&ProtoTLS) == 0){
			werrstr("server refused STARTTLS");
			return -1;
		}
	}
	c->sproto = r.negproto;

	if(starttls(c) < 0)
		return -1;
	if(c->nla && nlahandshake(c) < 0)
		return -1;

	/* [MS-RDPBCGR] 2.2.1.14: Early User Authorization Result PDU —
	 * server sends a 4-byte authorizationResult immediately after the
	 * CredSSP handshake if (and only if) client advertised HYBRID_EX */
	if(c->nla && (c->sproto & ProtoUAUTH)){
		uchar authbuf[4];
		ulong authresult;
		if(readn(c->fd, authbuf, 4) != 4){
			werrstr("NLA: read Early User Authorization Result: %r");
			return -1;
		}
		authresult = GLONG(authbuf);
		fprint(2, "nla: Early User Authorization Result: %08lux\n", authresult);
		if(authresult != 0){
			werrstr("NLA: server denied access (authorizationResult=%08lux)", authresult);
			return -1;
		}
	}

	return 0;
}

int
nlahandshake(Rdp *c)
{
	uchar ntnego[64], ntauth[640];
	uchar challenge[8], chal[8], ntresp[64], tsreqbuf[4096];
	uchar esscnonce[8], tmp[16], md5out[MD5dlen];
	uchar lmresp[24], *lmrespptr;	/* LmChallengeResponse is 24 bytes */
	uchar ntresp_direct[24], *nt_for_auth, *lm_for_auth;
	char user[256], domfromchal[256], pass[256], *dom;
	uchar *ntp;
	int n, ntlen, nresp, i, tlen, toff;
	long srvflags;
	UserPasswd *up;

	/* Phase A: NTLM Negotiate (CredSSP v2, no clientNonce) */
	fprint(2, "nla: sending Phase A (NTLM Negotiate)\n");
	n = mkntnego(ntnego, sizeof ntnego);
	if(n < 0)
		return -1;
	if(writetsreq(c->fd, ntnego, n) < 0)
		return -1;
	fprint(2, "nla: Phase A sent (%d byte token)\n", n);

	/* Phase B: NTLM Challenge.
	 * In PROTOCOL_HYBRID_EX mode the server may send a 4-byte Early User
	 * Authorization Result PDU here instead of a TSRequest, e.g. to deny
	 * access before the full CredSSP exchange completes. */
	fprint(2, "nla: reading Phase B (NTLM Challenge)\n");
	if(c->sproto & ProtoUAUTH){
		ulong euarp;
		n = readtsreq_oreuarp(c->fd, tsreqbuf, sizeof tsreqbuf, &euarp);
		if(n == 0){
			fprint(2, "nla: Early User Authorization Result at Phase B: %08lux\n", euarp);
			werrstr("NLA: server denied access (EUARP authorizationResult=%08lux)", euarp);
			return -1;
		}
	} else {
		n = readtsreq(c->fd, tsreqbuf, sizeof tsreqbuf);
	}
	if(n < 0)
		return -1;
	ntp = gettsreq(tsreqbuf, n, &ntlen);
	if(ntp == nil)
		return -1;
	if(getntchal(challenge, ntp, ntlen) < 0)
		return -1;

	fprint(2, "nla: Phase B received (%d byte TSRequest, %d byte token)\n", n, ntlen);
	/* Debug: dump the raw NTLM Challenge packet */
	fprint(2, "ntlm challenge (%d bytes):", ntlen);
	for(i = 0; i < ntlen; i++)
		fprint(2, " %02ux", ntp[i]);
	fprint(2, "\n");

	/* Check if server requested Extended Session Security (ESS/NTLMv1-ESS) */
	srvflags = (ntlen >= 24) ? (long)GLONG(ntp+20) : 0;
	lmrespptr = nil;
	memmove(chal, challenge, 8);
	if(srvflags & 0x00080000){	/* NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY */
		/* generate random 8-byte client nonce */
		genrandom(esscnonce, sizeof esscnonce);
		/* ESS challenge = MD5(server_challenge || client_nonce)[0..7] */
		memmove(tmp, challenge, 8);
		memmove(tmp+8, esscnonce, 8);
		md5(tmp, 16, md5out, nil);
		memmove(chal, md5out, 8);
		/* LM response = client_nonce (8 bytes) + zeros (16 bytes) */
		memmove(lmresp, esscnonce, 8);
		memset(lmresp+8, 0, 16);
		lmrespptr = lmresp;
	}

	/* Use TargetName from Challenge as domain if none was specified */
	dom = c->windom;
	if(*dom == '\0' && ntlen >= 20){
		tlen = GSHORT(ntp+12);
		toff = GLONG(ntp+16);
		if(tlen > 0 && toff >= 0 && tlen <= ntlen - toff){
			n = fromutf16(domfromchal, sizeof(domfromchal)-1, ntp+toff, tlen);
			domfromchal[n] = '\0';
			dom = domfromchal;
		}
	}

	/*
	 * Get password for NT response and credential delegation.
	 * Try proto=pass first, then the -p flag.
	 * If a password is available we compute the NT response directly
	 * (DESL(MD4(UNICODE(pass)), chal)) which avoids needing a separate
	 * proto=mschap key in factotum.  If no password, fall back to
	 * auth_respond with proto=mschap.
	 */
	fprint(2, "nla: retrieving password (keyspec=%s)\n", c->keyspec);
	user[0] = '\0';
	pass[0] = '\0';
	up = auth_getuserpasswd(auth_getkey, "proto=pass service=rdp %s", c->keyspec);
	if(up != nil){
		if(up->user != nil)
			snprint(user, sizeof user, "%s", up->user);
		if(up->passwd != nil)
			snprint(pass, sizeof pass, "%s", up->passwd);
		free(up);
	}
	if(pass[0] == '\0' && c->passwd != nil && c->passwd[0] != '\0'){
		snprint(pass, sizeof pass, "%s", c->passwd);
		if(user[0] == '\0' && c->user != nil && c->user[0] != '\0')
			snprint(user, sizeof user, "%s", c->user);
	}

	if(pass[0] != '\0'){
		/* Compute NT response directly from password */
		fprint(2, "nla: computing NT response from password (user=%s, dom=%s)\n", user, dom);
		ntrespfrompasswd(pass, chal, ntresp_direct);
		nt_for_auth = ntresp_direct;
		/* LM response: nil for non-ESS (no NfESS); ESS cnonce+zeros otherwise */
		lm_for_auth = lmrespptr;
	}else{
		/* Fall back to factotum mschap */
		fprint(2, "nla: calling factotum mschap (keyspec=%s, dom=%s)\n", c->keyspec, dom);
		nresp = auth_respond(chal, 8,
			user, sizeof(user)-1,
			ntresp, sizeof(ntresp),
			auth_getkey,
			"proto=mschap role=client service=rdp %s", c->keyspec);
		if(nresp < 0){
			werrstr("factotum mschap: %r");
			return -1;
		}
		if(nresp < 2*24){ /* sizeof(MSchapreply) = LMresp[24] + NTresp[24] */
			werrstr("factotum mschap: response too short (%d)", nresp);
			return -1;
		}
		fprint(2, "nla: factotum returned user=%s nresp=%d\n", user, nresp);
		/* factotum mschap returns MSchapreply: LMresp[24] at [0], NTresp[24] at [24] */
		nt_for_auth = ntresp + 24;
		/* nil for non-ESS so NfESS is not set; ESS cnonce+zeros otherwise */
		lm_for_auth = lmrespptr;
	}

	/* Propagate user name if not yet set on the connection */
	if(user[0] != '\0' && c->user[0] == '\0'){
		c->user = strdup(user);
		if(c->user == nil)
			sysfatal("strdup: %r");
	}

	/* Phase C: NTLM Authenticate */
	fprint(2, "nla: sending Phase C (NTLM Authenticate, user=%s, dom=%s)\n", c->user, dom);
	n = mkntauth(ntauth, sizeof ntauth, c->user, dom, nt_for_auth, lm_for_auth);
	if(n < 0)
		return -1;
	if(writetsreq(c->fd, ntauth, n) < 0)
		return -1;
	fprint(2, "nla: Phase C sent (%d byte token)\n", n);

	if(pass[0] == '\0'){
		werrstr("NLA: no password for credential delegation; "
			"add 'proto=pass service=rdp' key to factotum or use -p");
		return -1;
	}
	fprint(2, "nla: password obtained (%d chars), calling nlafinish\n", (int)strlen(pass));

	/* Phases D and E: read server pubKeyAuth, send TSCredentials */
	n = nlafinish(c->fd, c->tlscert, c->tlscertlen, dom, c->user, pass);
	memset(pass, 0, sizeof pass);
	return n;
}

int
x224hangup(Rdp* c)
{
	Msg t;

	t.type = Xhangup;
	return writemsg(c, &t);
}

int
mcsconnect(Rdp* c)
{
	Msg t, r;
		
	t.type = Mconnect;
	t.ver = 0x80004;	/* RDP5 */
	t.depth = c->depth;
	t.xsz = c->xsz;
	t.ysz = c->ysz;
	t.sysname = c->local;
	t.sproto = c->sproto;
	t.wantconsole = c->wantconsole;
	t.vctab = c->vc;
	t.nvc = c->nvc;
	if(writemsg(c, &t) <= 0)
		sysfatal("Connect Initial: writemsg: %r");
	if(readmsg(c, &r) <= 0)
		sysfatal("Connect Response: readmsg: %r");
	if(r.type != Mconnected)
		sysfatal("Connect Response: protocol botch");
	if(r.ver < t.ver)
		sysfatal("Connect Response: unsupported RDP protocol version %x", r.ver);

	return 0;
}

void
erectdom(Rdp* c)
{
	Msg t;
	
	t.type = Merectdom;
	if(writemsg(c, &t) <= 0)
		sysfatal("Erect Domain: writemsg: %r");
}

int
attachuser(Rdp* c)
{
	Msg t, r;

	t.type = Mattach;
	if(writemsg(c, &t) <= 0)
		sysfatal("attachuser: writemsg: %r");
	if(readmsg(c, &r) <= 0)
		sysfatal("attachuser: readmsg: %r");
	if(r.type != Mattached)
		sysfatal("attachuser: protocol botch");

	c->mcsuid = r.mcsuid;
	c->userchan = r.mcsuid;
	return 0;
}

int
joinchannel(Rdp* c, int mcsuid, int chanid)
{
	Msg t, r;

	t.type = Mjoin;
	t.mcsuid = mcsuid;
	t.chanid = chanid;
	if(writemsg(c, &t) <= 0)
		sysfatal("Channel Join: writemsg: %r");
	if(readmsg(c, &r) <= 0)
		sysfatal("Channel Join: readmsg: %r");
	if(r.type != Mjoined)
		sysfatal("Channel Join: protocol botch");

	/* BUG: ensure the returned and requested chanids match */

	return 0;
}

int
rdphandshake(Rdp* c)
{
	int i, nv;
	Vchan* v;
	Msg r;
	Share u;

	v = c->vc;
	nv = c->nvc;

	if(mcsconnect(c) < 0)
		return -1;
	erectdom(c);
	if(attachuser(c) < 0)
		return -1;

	if(joinchannel(c, c->mcsuid, c->userchan) < 0)
		return -1;
	if(joinchannel(c, c->mcsuid, GLOBALCHAN) < 0)
		return -1;
	for(i = 0; i < nv; i++)
		if(joinchannel(c, c->mcsuid, v[i].mcsid) < 0)
			return -1;

	sendclientinfo(c);
	for(;;){
		if(readmsg(c, &r) <= 0)
			return -1;
		switch(r.type){
		case Mclosing:
			werrstr("Disconnect Provider Ultimatum");
			return -1;
		case Ldone:
			break;
		case Lneedlicense:
		case Lhavechal:
			respondlicense(c, &r);
			break;
		case Aupdate:
			if(r.getshare(&u, r.data, r.ndata) < 0)
				return -1;
			switch(u.type){
			default:
				fprint(2, "handshake: unhandled %d\n", u.type);
				break;
			case ShEinfo:	/* do we really expect this here? */
				c->hupreason = u.err;
				break;
			case ShActivate:
				activate(c, &u);
				return 0;
			}
		}
	}
}

/* 2.2.1.13.1 Server Demand Active PDU */
void
activate(Rdp* c, Share* as)
{
	Caps rcaps;

	if(getcaps(&rcaps, as->data, as->ndata) < 0)
		sysfatal("getcaps: %r");
	if(!rcaps.canrefresh)
		sysfatal("server can not Refresh Rect PDU");
	if(!rcaps.cansupress)
		sysfatal("server can not Suppress Output PDU");
	if(!rcaps.bitmap)
		sysfatal("server concealed their Bitmap Capabilities");
	c->depth = rcaps.depth;
	c->xsz = rcaps.xsz;
	c->ysz = rcaps.ysz;
	c->srvchan = as->source;
	c->shareid = as->shareid;
	c->active = 1;

	confirmactive(c);
	finalhandshake(c);

	act(c, 0, InputSync, 0, 0, 0);
}

void
deactivate(Rdp* c, Share* as)
{
	USED(as);
	c->active = 0;
}

void
finalhandshake(Rdp* c)
{
	Msg r;
	Share u;

	assync(c);
	asctl(c, CAcooperate);
	asctl(c, CAreqctl);
	asfontls(c);

	for(;;){
		if(readmsg(c, &r) <= 0)
			sysfatal("activate: readmsg: %r");
		switch(r.type){
		default:
			fprint(2, "activate: unhandled PDU type %d\n", u.type);
			break;
		case Mclosing:
			fprint(2, "disconnecting early");
			return;
		case Aupdate:
			if(r.getshare(&u, r.data, r.ndata) < 0)
				sysfatal("activate: r.getshare: %r");
			switch(u.type){
			default:
				fprint(2, "activate: unhandled ASPDU type %d\n", u.type);
				break;
			case ShSync:
			case ShCtl:
				/* responses to the assync(). asctl() calls above */
				break;
			case ShFmap:
				/* finalized - we're good */
				return;
			}
		}
	}
}

void
sendclientinfo(Rdp* c)
{
	Msg t;

	t.type = Dclientinfo;
	t.mcsuid = c->mcsuid;
	if(c->nla){
		/* server already knows credentials from CredSSP exchange */
		t.dom = "";
		t.user = "";
		t.pass = "";
		t.dologin = 0;
	}else{
		t.dom = c->windom;
		t.user = c->user;
		t.pass = c->passwd;
		t.dologin = (strlen(c->user) > 0);
	}
	t.rshell = c->shell;
	t.rwd = c->rwd;

	if(writemsg(c, &t) <= 0)
		sysfatal("sendclientinfo: %r");
}

void
confirmactive(Rdp* c)
{
	Msg	t;

	t.type = Mactivated;
	t.originid = c->srvchan;
	t.mcsuid = c->userchan;
	t.shareid = c->shareid;
	t.xsz = c->xsz;
	t.ysz = c->ysz;
	t.depth = c->depth;
	if(writemsg(c, &t) <= 0)
		sysfatal("confirmactive: %r");
}

void
respondlicense(Rdp *c, Msg *r)
{
	Msg t;

	switch(r->type){
	default:
		return;
	case Lneedlicense:
		t.type = Lreq;
		t.sysname = c->local;
		t.user = c->user;
		t.originid = c->userchan;
		break;
	case Lhavechal:
			fprint(2, "unhandled Lhavechal\n");
		t.type = Lnolicense;
		t.originid = c->userchan;
		break;
	}

	if(writemsg(c, &t) < 0)
		sysfatal("respondlicense: writemsg failed: %r");
}


void
assync(Rdp *c)
{
	Msg t;

	t.type = Async;
	t.mcsuid = c->srvchan;
	t.originid = c->userchan;
	t.shareid = c->shareid;
	if(writemsg(c, &t) <= 0)
		sysfatal("assync: %r");
}

void
asctl(Rdp* c, int action)
{
	Msg t;

	t.type = Actl;
	t.originid = c->userchan;
	t.shareid = c->shareid;
	t.action = action;
	if(writemsg(c, &t) <= 0)
		sysfatal("asctl: %r");
}

void
asfontls(Rdp* c)
{
	Msg t;

	t.type = Afontls;
	t.originid = c->userchan;
	t.shareid = c->shareid;
	if(writemsg(c, &t) <= 0)
		sysfatal("asfontls: %r");
}

void
act(Rdp* c, ulong msec, int typ, int f, int a, int b)
{
	Msg t;

	t.type = Ainput;
	t.originid = c->userchan;
	t.shareid = c->shareid;
	t.msec = msec;
	t.mtype = typ;
	t.flags = f;
	t.iarg[0] = a;
	t.iarg[1] = b;
	if(writemsg(c, &t) <= 0)
		sysfatal("act: %r");
}

void
turnupdates(Rdp* c, int allow)
{
	Msg t;

	t.type = Dsupress;
	t.originid = c->userchan;
	t.shareid = c->shareid;
	t.xsz = c->xsz;
	t.ysz = c->ysz;
	t.allow = allow;
	writemsg(c, &t);
}

void
apply(Rdp* c, Msg* m)
{
	switch(m->type){
	default:	fprint(2, "type %d is not expected\n", m->type); break;
	case 0:	fprint(2, "unsupported PDU\n"); break;
	case Mvchan:	applyvc(c, m); break;
	case Aupdate:	applyupdates(c, m); break;
	}
}

static void
applyvc(Rdp* c, Msg* m)
{
	if(defragvc(c, m) > 0)
		callvcfunc(c, m);
}

static void
applyupdates(Rdp* c, Msg* m)
{
	int n;
	uchar *p, *ep;
	Share u;

	p = m->data;
	ep = m->data + m->ndata;

	for(; p < ep; p += n){
		n = m->getshare(&u, p, ep-p);
		if(n < 0)
			sysfatal("applyupdates: %r");

		switch(u.type){
		default:
			if(u.type != 0)
				fprint(2, "applyupdates: unhandled %d\n", u.type);
			break;
		case ShDeactivate:
			deactivate(c, &u);
			break;
		case ShActivate:	// server may initiate capability re-exchange
			activate(c, &u);
			break;
		case ShEinfo:
			c->hupreason = u.err;
			break;
		case ShUorders:
		case ShUimg:
			drawimgupdate(c, &u);
			break;
		case ShUcmap:
			loadcmap(c, &u);
			break;
		case ShUwarp:
			warpmouse(u.x, u.y);
			break;
		case Aflow:
			break;
		}
	}
}
