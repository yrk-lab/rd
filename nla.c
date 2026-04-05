/*
 * Network Level Authentication (NLA) via CredSSP [MS-CSSP].
 *
 * After TLS is established, the client authenticates using NTLM
 * (MS-NLMP) encapsulated in TSRequest ASN.1 DER messages.
 * The NT response is computed by factotum via auth_respond(2)
 * with proto=mschap, so the plaintext password never leaves factotum.
 *
 * Exchange:
 *   Client → Server: TSRequest { negoTokens = [NTLM Negotiate] }
 *   Server → Client: TSRequest { negoTokens = [NTLM Challenge] }
 *   Client → Server: TSRequest { negoTokens = [NTLM Authenticate] }
 */
#include <u.h>
#include <libc.h>
#include "dat.h"
#include "fns.h"

enum
{
	/* NTLM NegotiateFlags (subset used here) */
	NfUnicode	= 0x00000001,	/* NTLMSSP_NEGOTIATE_UNICODE */
	NfReqTarget	= 0x00000004,	/* NTLMSSP_REQUEST_TARGET */
	NfNTLM		= 0x00000200,	/* NTLMSSP_NEGOTIATE_NTLM */
	NfAlwaysSign	= 0x00008000,	/* NTLMSSP_NEGOTIATE_ALWAYS_SIGN */

	NTLMFlags	= NfUnicode | NfReqTarget | NfNTLM | NfAlwaysSign,

	/* NTLM response size (NTLMv1) */
	NTRespLen	= 24,

	/* ASN.1 Universal tags (BER/DER) */
	TagInt		= 2,	/* INTEGER */
	TagOctetString	= 4,	/* OCTET STRING */
	TagSeq		= 16,	/* SEQUENCE / SEQUENCE OF */

	/* BER class/construction bits */
	BerConstructed	= 0x20,	/* constructed encoding bit */
	BerContext	= 0xa0,	/* context-specific + constructed base */

	/* BER long-form length octets */
	BerShortMax	= 0x80,	/* values below this fit in one byte */
	BerLen1		= 0x81,	/* long form: length in next 1 byte */
	BerLen2		= 0x82,	/* long form: length in next 2 bytes */

	/* CredSSP TSRequest context-specific field tags (gbtag returns 5-bit tag number) */
	TSSnegoTokens	= 1,	/* TSRequest [1] negoTokens field */
	TSSnegoToken	= 0,	/* NegoDataItem [0] negoToken field */

	/* CredSSP version advertised in TSRequest */
	CredSSPVer	= 5,
};

static int
sizeder(int n)
{
	if(n < BerShortMax)
		return 1;
	if(n < 0x100)
		return 2;
	return 3;
}

static uchar*
putder(uchar *p, int n)
{
	if(n < BerShortMax){
		*p++ = n;
	}else if(n < 0x100){
		*p++ = BerLen1;
		*p++ = n;
	}else{
		*p++ = BerLen2;
		*p++ = n >> 8;
		*p++ = n;
	}
	return p;
}

/*
 * Encode TSRequest { version=CredSSPVer, negoTokens=[{negoToken=ntlm}] }
 *
 * ASN.1:
 *   TSRequest ::= SEQUENCE {
 *     version    [0] INTEGER,
 *     negoTokens [1] SEQUENCE OF SEQUENCE { [0] OCTET STRING } OPTIONAL,
 *     ...
 *   }
 */
static int
mktsreq(uchar *buf, int nbuf, uchar *tok, int toklen)
{
	int octetsz, a0toksz, itemsz, datasz, a1sz, bodysz, total;
	uchar *p;

	/* OCTET STRING wrapping the NTLM token */
	octetsz  = 1 + sizeder(toklen) + toklen;
	/* [0] { octet } = negoToken field inside NegoDataItem */
	a0toksz  = 1 + sizeder(octetsz) + octetsz;
	/* SEQUENCE { a0tok } = NegoDataItem */
	itemsz   = 1 + sizeder(a0toksz) + a0toksz;
	/* SEQUENCE OF { item } = NegoData */
	datasz   = 1 + sizeder(itemsz) + itemsz;
	/* [1] { seqdata } = negoTokens field */
	a1sz     = 1 + sizeder(datasz) + datasz;
	/* [0] { INTEGER CredSSPVer } = version field; always 5 bytes: a0 03 02 01 vv */
	bodysz   = 5 + a1sz;
	total    = 1 + sizeder(bodysz) + bodysz;

	if(total > nbuf){
		werrstr("mktsreq: buffer too small (%d < %d)", nbuf, total);
		return -1;
	}

	p = buf;
	/* TSRequest SEQUENCE */
	*p++ = BerConstructed|TagSeq; p = putder(p, bodysz);
	/* version [0] EXPLICIT INTEGER CredSSPVer */
	*p++ = BerContext|TSSnegoToken; *p++ = 0x03; /* len */
	*p++ = TagInt; p = putder(p, 1); *p++ = CredSSPVer;
	/* negoTokens [1] EXPLICIT NegoData */
	*p++ = BerContext|TSSnegoTokens; p = putder(p, datasz);
	/* NegoData SEQUENCE OF */
	*p++ = BerConstructed|TagSeq; p = putder(p, itemsz);
	/* NegoDataItem SEQUENCE */
	*p++ = BerConstructed|TagSeq; p = putder(p, a0toksz);
	/* negoToken [0] EXPLICIT OCTET STRING */
	*p++ = BerContext|TSSnegoToken; p = putder(p, octetsz);
	*p++ = TagOctetString; p = putder(p, toklen);
	memmove(p, tok, toklen);
	p += toklen;

	return p - buf;
}

/*
 * Parse TSRequest and return a pointer to the NTLM token in negoTokens[0].
 * Writes the token length to *ntlenp. Returns nil on error.
 */
uchar*
gettsreq(uchar *buf, int n, int *ntlenp)
{
	uchar *p, *ep, *q;
	int tag, len;

	p = buf;
	ep = buf + n;

	/* TSRequest SEQUENCE */
	if((p = gbtag(p, ep, &tag)) == nil || tag != TagSeq
		|| (p = gblen(p, ep, &len)) == nil)
		goto bad;
	ep = p + len;

	/* walk SEQUENCE body looking for [1] negoTokens */
	while(p < ep){
		if((q = gbtag(p, ep, &tag)) == nil
			|| (q = gblen(q, ep, &len)) == nil)
			goto bad;
		if(tag == TSSnegoTokens){
			/* NegoData SEQUENCE OF */
			if((p = gbtag(q, ep, &tag)) == nil || tag != TagSeq
				|| (p = gblen(p, ep, &len)) == nil)
				goto bad;
			/* NegoDataItem SEQUENCE */
			if((p = gbtag(p, ep, &tag)) == nil || tag != TagSeq
				|| (p = gblen(p, ep, &len)) == nil)
				goto bad;
			/* negoToken [0] */
			if((p = gbtag(p, ep, &tag)) == nil || tag != TSSnegoToken
				|| (p = gblen(p, ep, &len)) == nil)
				goto bad;
			/* OCTET STRING */
			if((p = gbtag(p, ep, &tag)) == nil || tag != TagOctetString
				|| (p = gblen(p, ep, &len)) == nil)
				goto bad;
			*ntlenp = len;
			return p;
		}
		p = q + len;
	}
bad:
	werrstr("NLA: TSRequest parse error");
	return nil;
}

/*
 * Send a TSRequest wrapping the given NTLM token over the TLS fd.
 */
int
writetsreq(int fd, uchar *tok, int toklen)
{
	uchar buf[4096];
	int n;

	n = mktsreq(buf, sizeof buf, tok, toklen);
	if(n < 0)
		return -1;
	if(write(fd, buf, n) != n){
		werrstr("NLA: write TSRequest: %r");
		return -1;
	}
	return 0;
}

/*
 * Read one raw TSRequest DER blob from fd.
 * Returns the total number of bytes read, or -1 on error.
 */
int
readtsreq(int fd, uchar *buf, int nbuf)
{
	uchar hdr[4];
	int hlen, bodylen, total, n;

	/* Read tag + first length byte */
	n = readn(fd, hdr, 2);
	if(n != 2){
		werrstr("NLA: read TSRequest header: %r");
		return -1;
	}
	if(hdr[0] != (BerConstructed|TagSeq)){
		werrstr("NLA: TSRequest not a SEQUENCE (got 0x%02x)", hdr[0]);
		return -1;
	}
	if(hdr[1] < BerShortMax){
		bodylen = hdr[1];
		hlen = 2;
	}else if(hdr[1] == BerLen1){
		if(readn(fd, hdr+2, 1) != 1){
			werrstr("NLA: read TSRequest length: %r");
			return -1;
		}
		bodylen = hdr[2];
		hlen = 3;
	}else if(hdr[1] == BerLen2){
		if(readn(fd, hdr+2, 2) != 2){
			werrstr("NLA: read TSRequest length: %r");
			return -1;
		}
		bodylen = (hdr[2]<<8)|hdr[3];
		hlen = 4;
	}else{
		werrstr("NLA: bad TSRequest length form 0x%02x", hdr[1]);
		return -1;
	}
	total = hlen + bodylen;
	if(total > nbuf){
		werrstr("NLA: TSRequest too large (%d)", total);
		return -1;
	}
	memmove(buf, hdr, hlen);
	n = readn(fd, buf+hlen, bodylen);
	if(n != bodylen){
		werrstr("NLA: read TSRequest body: %r");
		return -1;
	}
	return total;
}

/*
 * Build NTLM Negotiate message (Type 1).
 * This is a minimal negotiate with no domain or workstation names.
 */
int
mkntnego(uchar *buf, int nbuf)
{
	uchar *p;

	if(nbuf < 32){
		werrstr("mkntnego: buffer too small");
		return -1;
	}
	p = buf;
	memmove(p, "NTLMSSP\0", 8);	p += 8;
	PLONG(p, 1);			p += 4;		/* MessageType */
	PLONG(p, NTLMFlags);		p += 4;		/* NegotiateFlags */
	memset(p, 0, 8);		p += 8;		/* DomainNameFields (empty) */
	memset(p, 0, 8);		p += 8;		/* WorkstationFields (empty) */
	return p - buf;
}

/*
 * Extract the 8-byte server challenge from an NTLM Challenge (Type 2) message.
 */
int
getntchal(uchar challenge[8], uchar *buf, int n)
{
	if(n < 32){
		werrstr("NTLM Challenge: too short (%d)", n);
		return -1;
	}
	if(memcmp(buf, "NTLMSSP\0", 8) != 0){
		werrstr("NTLM Challenge: bad signature");
		return -1;
	}
	if(GLONG(buf+8) != 2){
		werrstr("NTLM Challenge: bad MessageType (%ld)", (long)GLONG(buf+8));
		return -1;
	}
	memmove(challenge, buf+24, 8);
	return 0;
}

int
mkntauth(uchar *buf, int nbuf, char *user, char *domain, uchar ntresp[NTRespLen])
{
	uchar dom16[512], usr16[512];
	int domlen, usrlen;
	int domoff, usroff, lmoff, ntoff;
	int lmlen, total;
	uchar *p;

	domlen = toutf16(dom16, sizeof dom16, domain, strlen(domain));
	usrlen = toutf16(usr16, sizeof usr16, user, strlen(user));

	lmlen     = NTRespLen;		/* zeros for LM response */
	domoff    = 64;
	usroff    = domoff + domlen;
	lmoff     = usroff + usrlen;
	ntoff     = lmoff  + lmlen;
	total     = ntoff  + NTRespLen;

	if(total > nbuf){
		werrstr("mkntauth: buffer too small (%d < %d)", nbuf, total);
		return -1;
	}

	p = buf;
	memmove(p, "NTLMSSP\0", 8);	p += 8;
	PLONG(p, 3);			p += 4;		/* MessageType */

	/* LmChallengeResponseFields */
	PSHORT(p, lmlen);
	PSHORT(p+2, lmlen);
	PLONG(p+4, lmoff);
	p += 8;

	/* NtChallengeResponseFields */
	PSHORT(p, NTRespLen);
	PSHORT(p+2, NTRespLen);
	PLONG(p+4, ntoff);
	p += 8;

	/* DomainNameFields */
	PSHORT(p, domlen);
	PSHORT(p+2, domlen);
	PLONG(p+4, domoff);
	p += 8;

	/* UserNameFields */
	PSHORT(p, usrlen);
	PSHORT(p+2, usrlen);
	PLONG(p+4, usroff);
	p += 8;

	/* WorkstationFields (empty) */
	PSHORT(p, 0);
	PSHORT(p+2, 0);
	PLONG(p+4, lmoff);	/* offset points to lm area; length is 0 */
	p += 8;

	/* EncryptedRandomSessionKeyFields (empty) */
	PSHORT(p, 0);
	PSHORT(p+2, 0);
	PLONG(p+4, ntoff+NTRespLen);
	p += 8;

	/* NegotiateFlags */
	PLONG(p, NTLMFlags);  p += 4;

	/* payload */
	memmove(p, dom16, domlen);  p += domlen;		/* DomainName */
	memmove(p, usr16, usrlen);  p += usrlen;		/* UserName */
	memset(p, 0, lmlen);        p += lmlen;			/* LmChallengeResponse */
	memmove(p, ntresp, NTRespLen);  p += NTRespLen;		/* NtChallengeResponse */

	return p - buf;
}
