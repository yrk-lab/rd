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
	uchar ntnego[64], ntauth[2048];
	uchar challenge[8], tsreqbuf[4096];
	uchar cchal[8];				/* NTLMv2 client challenge */
	uchar lmv2resp[24];			/* NTLMv2 LmChallengeResponse */
	uchar ntv2resp[16 + 32 + 1024 + 600];		/* NTLMv2 NtChallengeResponse (extra for EPA AvPairs) */
	uchar ntresp[64];			/* factotum mschap NTLMv1 fallback */
	uchar sesskey[MD5dlen];			/* NTLMv2 SessionBaseKey (= KeyExchangeKey) */
	uchar exportedsk[MD5dlen];		/* random ExportedSessionKey (used for sign/seal) */
	uchar eskresp[MD5dlen];			/* EncryptedRandomSessionKey = RC4K(sesskey, exportedsk) */
	RC4state rc4st;
	uchar cnonce[32];			/* CredSSP v5 client nonce */
	char user[256], domfromchal[256], pass[256], *dom;
	uchar *ntp, *ti;
	int n, ntlen, ntv2len, nresp, tilen, i, tlen, toff, nnego;
	UserPasswd *up;

	ntv2len = 0;
	memset(sesskey, 0, sizeof sesskey);
	memset(exportedsk, 0, sizeof exportedsk);

	/* Phase A: NTLM Negotiate (CredSSP v5, with clientNonce) */
	fprint(2, "nla: sending Phase A (NTLM Negotiate)\n");
	n = mkntnego(ntnego, sizeof ntnego);
	if(n < 0)
		return -1;
	nnego = n;			/* save for MIC computation */
	genrandom(cnonce, sizeof cnonce);
	if(writetsreqnonce(c->fd, ntnego, n, cnonce, sizeof cnonce) < 0)
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

	/* Extract TargetInfo (needed for NTLMv2 blob and timestamp) */
	ti = getntargetinfo(ntp, ntlen, &tilen);
	if(ti == nil)
		tilen = 0;

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
		/* Compute NTLMv2 NT and LM responses from password (MS-NLMP §3.3.2) */
		fprint(2, "nla: computing NTLMv2 response from password (user=%s, dom=%s)\n", user, dom);
		genrandom(cchal, sizeof cchal);
		{
			/*
			 * Build SPN "TERMSRV/<hostname>" for MsvAvTargetName.
			 * Strip any "net!" prefix and "!port" suffix from c->server
			 * (Plan 9 dial address format is "net!host!port").
			 */
			char spnbuf[280];
			char *h, *bang;
			h = (c->server != nil) ? c->server : "";
			if((bang = strchr(h, '!')) != nil)
				h = bang + 1;	/* skip "tcp!" or other network prefix */
			if((bang = strchr(h, '!')) != nil)
				snprint(spnbuf, sizeof spnbuf, "TERMSRV/%.*s", (int)(bang - h), h);
			else
				snprint(spnbuf, sizeof spnbuf, "TERMSRV/%s", h);
			fprint(2, "nla: SPN for MsvAvTargetName: %s\n", spnbuf);
			ntv2len = ntv2frompasswd(pass, user, dom,
				challenge, cchal, ti, tilen,
				ntv2resp, sizeof ntv2resp, lmv2resp, sesskey,
				c->tlscert, c->tlscertlen, spnbuf);
		}
		if(ntv2len < 0)
			return -1;
		fprint(2, "nla: SessionBaseKey (KeyExchangeKey):");
		for(i = 0; i < MD5dlen; i++) fprint(2, " %02ux", sesskey[i]);
		fprint(2, "\n");
		/*
		 * Generate a random ExportedSessionKey and compute EncryptedRandomSessionKey
		 * = RC4K(SessionBaseKey, ExportedSessionKey) per MS-NLMP §3.1.5.1.2.3.
		 * The ExportedSessionKey is used for sign/seal key derivation and CredSSP hashes.
		 */
		genrandom(exportedsk, MD5dlen);
		memmove(eskresp, exportedsk, MD5dlen);
		setupRC4state(&rc4st, sesskey, MD5dlen);
		rc4(&rc4st, eskresp, MD5dlen);
		fprint(2, "nla: ExportedSessionKey (random):");
		for(i = 0; i < MD5dlen; i++) fprint(2, " %02ux", exportedsk[i]);
		fprint(2, "\n");
		fprint(2, "nla: EncryptedRandomSessionKey:");
		for(i = 0; i < MD5dlen; i++) fprint(2, " %02ux", eskresp[i]);
		fprint(2, "\n");
		fprint(2, "nla: ntnego (%d bytes):", nnego);
		for(i = 0; i < nnego; i++) fprint(2, " %02ux", ntnego[i]);
		fprint(2, "\n");
	}else{
		/* Fall back to factotum mschap (NTLMv1; credential delegation will fail) */
		fprint(2, "nla: calling factotum mschap (keyspec=%s, dom=%s)\n", c->keyspec, dom);
		nresp = auth_respond(challenge, 8,
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
	}

	/* Propagate user name if not yet set on the connection */
	if(user[0] != '\0' && c->user[0] == '\0'){
		c->user = strdup(user);
		if(c->user == nil)
			sysfatal("strdup: %r");
	}

	/* Phase C: NTLM Authenticate */
	fprint(2, "nla: sending Phase C (NTLM Authenticate, user=%s, dom=%s)\n", c->user, dom);
	if(pass[0] != '\0'){
		n = mkntauth(ntauth, sizeof ntauth, c->user, dom, ntv2resp, ntv2len, lmv2resp, eskresp);
		if(n < 0)
			return -1;
		/*
		 * Compute and fill the MIC field at bytes 72–87 of AUTHENTICATE_MESSAGE.
		 * Required by MS-NLMP §3.1.5.1.2.3 when the Challenge TargetInfo contains
		 * MsvAvTimestamp (AvId=7), which Windows servers always include.
		 * MIC = HMAC_MD5(ExportedSessionKey,
		 *                 NTLM_Negotiate || NTLM_Challenge || NTLM_Authenticate)
		 * ntauth[72..87] was zeroed by mkntauth, so HMAC is computed over the
		 * message as it will appear on the wire (MIC field = 0 during computation).
		 * ExportedSessionKey is the random key (not the SessionBaseKey).
		 */
		{
			DigestState *mds;
			mds = hmac_md5(ntnego, nnego, exportedsk, MD5dlen, nil, nil);
			mds = hmac_md5(ntp, ntlen, exportedsk, MD5dlen, nil, mds);
			hmac_md5(ntauth, n, exportedsk, MD5dlen, ntauth+72, mds);
		}
		fprint(2, "nla: MIC:");
		for(i = 0; i < 16; i++) fprint(2, " %02ux", ntauth[72+i]);
		fprint(2, "\n");
		fprint(2, "nla: ntauth (%d bytes):", n);
		for(i = 0; i < n; i++) fprint(2, " %02ux", ntauth[i]);
		fprint(2, "\n");
	} else {
		n = mkntauth(ntauth, sizeof ntauth, c->user, dom, ntresp+24, 24, nil, nil);
		if(n < 0)
			return -1;
	}
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
	n = nlafinish(c->fd, c->tlscert, c->tlscertlen, cnonce, dom, c->user, pass, exportedsk);
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
