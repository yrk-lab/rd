/*
 * Network Level Authentication (NLA) via CredSSP [MS-CSSP].
 *
 * After TLS is established, the client authenticates using NTLM
 * (MS-NLMP) encapsulated in TSRequest ASN.1 DER messages, then
 * delegates credentials via TSCredentials encrypted with the NTLM
 * session key.  The NT response is computed by factotum via
 * auth_respond(2) with proto=mschap.  The session key and TSCredentials
 * password require a separate proto=pass factotum key (or -p flag).
 *
 * Exchange:
 *   Client → Server: TSRequest { version, negoTokens=[NTLM Negotiate], clientNonce }
 *   Server → Client: TSRequest { negoTokens=[NTLM Challenge] }
 *   Client → Server: TSRequest { negoTokens=[NTLM Authenticate] }
 *   Server → Client: TSRequest { pubKeyAuth }
 *   Client → Server: TSRequest { pubKeyAuth, authInfo=TSCredentials }
 */
#include <u.h>
#include <libc.h>
#include <libsec.h>
#include "dat.h"
#include "fns.h"

enum
{
	/* NTLM NegotiateFlags (subset used here) */
	NfUnicode	= 0x00000001,	/* NTLMSSP_NEGOTIATE_UNICODE */
	NfReqTarget	= 0x00000004,	/* NTLMSSP_REQUEST_TARGET */
	NfNTLM		= 0x00000200,	/* NTLMSSP_NEGOTIATE_NTLM */
	NfAlwaysSign	= 0x00008000,	/* NTLMSSP_NEGOTIATE_ALWAYS_SIGN */
	NfESS		= 0x00080000,	/* NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY */

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
	TSSauthInfo	= 2,	/* TSRequest [2] authInfo field */
	TSSpubKeyAuth	= 3,	/* TSRequest [3] pubKeyAuth field */
	TSSclientNonce	= 5,	/* TSRequest [5] clientNonce field (version 5+) */

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
 * Extract SubjectPublicKeyInfo (SPKI) from a DER-encoded X.509 certificate.
 * Returns a pointer to the SPKI TLV within cert and sets *spkilen.
 * Returns nil on error (cert malformed or SPKI not found).
 */
static uchar*
certspki(uchar *cert, int certlen, int *spkilen)
{
	uchar *p, *ep, *tbsep, *start;
	int tag, len, i;

	p = cert;
	ep = cert + certlen;

	/* Certificate SEQUENCE */
	if((p = gbtag(p, ep, &tag)) == nil || tag != TagSeq
	|| (p = gblen(p, ep, &len)) == nil)
		return nil;
	ep = p + len;

	/* tbsCertificate SEQUENCE */
	if((p = gbtag(p, ep, &tag)) == nil || tag != TagSeq
	|| (p = gblen(p, ep, &len)) == nil)
		return nil;
	tbsep = p + len;

	/* optional [0] version (context tag 0) */
	{
		uchar *q;
		int t, l;
		q = gbtag(p, tbsep, &t);
		if(q != nil && t == 0){
			if((q = gblen(q, tbsep, &l)) == nil)
				return nil;
			p = q + l;
		}
	}

	/* serialNumber INTEGER, signature SEQUENCE, issuer SEQUENCE,
	 * validity SEQUENCE, subject SEQUENCE: skip 5 fields */
	for(i = 0; i < 5; i++){
		uchar *q;
		int t, l;
		if((q = gbtag(p, tbsep, &t)) == nil
		|| (q = gblen(q, tbsep, &l)) == nil)
			return nil;
		p = q + l;
	}

	/* subjectPublicKeyInfo SEQUENCE is next */
	start = p;
	if((p = gbtag(p, tbsep, &tag)) == nil || tag != TagSeq
	|| (p = gblen(p, tbsep, &len)) == nil)
		return nil;
	*spkilen = (p + len) - start;
	return start;
}

/*
 * Derive the NTLMv1 ExportedSessionKey from a plaintext password.
 * sesskey = MD4(MD4(unicode(password)))
 * The inner MD4 is the NT hash; the outer MD4 is the SessionBaseKey.
 */
static void
ntsesskey(char *pass, uchar sesskey[MD5dlen])
{
	Rune r;
	int i, n;
	uchar *w, unipass[256], nthash[MD5dlen];

	n = strlen(pass);
	if(n > 128)
		n = 128;
	for(i = 0, w = unipass; i < n; i++){
		pass += chartorune(&r, pass);
		*w++ = r & 0xff;
		*w++ = r >> 8;
	}
	md4(unipass, w - unipass, nthash, nil);
	md4(nthash, MD5dlen, sesskey, nil);
}

/*
 * Expand a 7-byte NTLM DES key to 8 bytes by inserting parity bits.
 */
static void
des7to8(uchar key7[7], uchar key8[8])
{
	key8[0] =  key7[0]                    & 0xfe;
	key8[1] = ((key7[0]<<7)|(key7[1]>>1)) & 0xfe;
	key8[2] = ((key7[1]<<6)|(key7[2]>>2)) & 0xfe;
	key8[3] = ((key7[2]<<5)|(key7[3]>>3)) & 0xfe;
	key8[4] = ((key7[3]<<4)|(key7[4]>>4)) & 0xfe;
	key8[5] = ((key7[4]<<3)|(key7[5]>>5)) & 0xfe;
	key8[6] = ((key7[5]<<2)|(key7[6]>>6)) & 0xfe;
	key8[7] = (key7[6]<<1)                & 0xfe;
}

/*
 * Apply DES-ECB to an 8-byte block using a 7-byte (56-bit) NTLM DES key.
 * DES is mandated by MS-NLMP §3.3.1 (DESL function) and cannot be avoided
 * in NTLMv1; this is a known protocol weakness.
 */
static void
ntlmdes(uchar *key7, uchar chal[8], uchar out[8])
{
	DESstate ds;
	uchar key8[8];

	des7to8(key7, key8);
	setupDESstate(&ds, key8, nil);
	memmove(out, chal, 8);
	des_ecb_encrypt(out, 8, &ds);
}

/*
 * Compute the 24-byte NTLMv1 NT response from a plaintext password and
 * challenge.  Implements DESL(MD4(UNICODE(pass)), chal) per MS-NLMP §3.3.1.
 * ntresp must be at least 24 bytes.
 */
void
ntrespfrompasswd(char *pass, uchar chal[8], uchar ntresp[24])
{
	Rune r;
	int i, n;
	uchar *w, unipass[256], nthash[MD4dlen], padded[21];

	n = strlen(pass);
	if(n > 128)	/* 128 chars × 2 bytes UTF-16 = 256 byte unipass[] */
		n = 128;
	for(i = 0, w = unipass; i < n; i++){
		pass += chartorune(&r, pass);
		*w++ = r & 0xff;
		*w++ = r >> 8;
	}
	md4(unipass, w - unipass, nthash, nil);
	memset(padded, 0, sizeof padded);
	memmove(padded, nthash, MD4dlen);
	ntlmdes(padded+0,  chal, ntresp+0);
	ntlmdes(padded+7,  chal, ntresp+8);
	ntlmdes(padded+14, chal, ntresp+16);
}

/*
 * Derive NTLM SignKey and SealKey from the ExportedSessionKey (MS-NLMP).
 * Magic strings include the explicit NUL terminator per spec.
 */
static void
ntlmkeys(uchar *sesskey, uchar signkey[MD5dlen], uchar sealkey[MD5dlen])
{
	DigestState *ds;
	static char signmagic[] = "session key to client-to-server signing key magic constant";
	static char sealmagic[] = "session key to client-to-server sealing key magic constant";

	ds = md5((uchar*)sesskey, MD5dlen, nil, nil);
	md5((uchar*)signmagic, sizeof signmagic, signkey, ds);	/* sizeof includes '\0' */
	ds = md5((uchar*)sesskey, MD5dlen, nil, nil);
	md5((uchar*)sealmagic, sizeof sealmagic, sealkey, ds);
}

/*
 * NTLM EncryptMessage (NTLMv1 without ESS) per MS-NLMP Table 3.
 * Output: NTLMSSP_MESSAGE_SIGNATURE (16 bytes) || encrypted message.
 * RC4 state is shared: message is encrypted first, checksum second.
 */
static int
ntlmseal(uchar *out, int nout, uchar *signkey, uchar *sealkey,
         ulong seqno, uchar *msg, int nmsg)
{
	RC4state h;
	uchar hmac[MD5dlen], seqbuf[4];
	DigestState *ds;

	if(nout < 16 + nmsg){
		werrstr("ntlmseal: buffer too small");
		return -1;
	}
	/* Encrypt message using SealKey; RC4 state advances */
	setupRC4state(&h, sealkey, MD5dlen);
	memmove(out+16, msg, nmsg);
	rc4(&h, out+16, nmsg);

	/* HMAC_MD5(SignKey, seqno_le || plaintext) – first 4 bytes used */
	seqbuf[0] = seqno; seqbuf[1] = seqno>>8;
	seqbuf[2] = seqno>>16; seqbuf[3] = seqno>>24;
	ds = hmac_md5(seqbuf, 4, signkey, MD5dlen, nil, nil);
	hmac_md5(msg, nmsg, signkey, MD5dlen, hmac, ds);

	/* Encrypt 4-byte checksum using the continued RC4 state */
	rc4(&h, hmac, 4);

	/* NTLMSSP_MESSAGE_SIGNATURE: Version | RandomPad=0 | Checksum | SeqNum */
	PLONG(out, 0x00000001);
	PLONG(out+4, 0);
	memmove(out+8, hmac, 4);
	PLONG(out+12, seqno);

	return 16 + nmsg;
}

/*
 * Encode TSPasswordCreds { domainName [0], userName [1], password [2] }
 * All string fields are UTF-16LE OCTET STRINGs wrapped in EXPLICIT context tags.
 */
static int
mktspasswdcreds(uchar *buf, int nbuf, char *dom, char *user, char *pass)
{
	uchar d16[512], u16[512], p16[512];
	int dlen, ulen, plen;
	int f0sz, f1sz, f2sz, seqbody, total;
	uchar *p;

	dlen = toutf16(d16, sizeof d16, dom, strlen(dom));
	ulen = toutf16(u16, sizeof u16, user, strlen(user));
	plen = toutf16(p16, sizeof p16, pass, strlen(pass));

	/* Each field: [n] EXPLICIT OCTET STRING  = context_tag + len(inner) + 0x04 + len(val) + val */
#define FIELDSZ(vlen)	(1 + sizeder(1 + sizeder(vlen) + (vlen)) + 1 + sizeder(vlen) + (vlen))
	f0sz = FIELDSZ(dlen);
	f1sz = FIELDSZ(ulen);
	f2sz = FIELDSZ(plen);
#undef FIELDSZ

	seqbody = f0sz + f1sz + f2sz;
	total = 1 + sizeder(seqbody) + seqbody;
	if(total > nbuf){
		werrstr("mktspasswdcreds: buffer too small");
		return -1;
	}

	p = buf;
	*p++ = BerConstructed|TagSeq; p = putder(p, seqbody);

#define PUTFIELD(tag, v16, vlen) \
	do { \
		*p++ = BerContext|(tag); p = putder(p, 1 + sizeder(vlen) + (vlen)); \
		*p++ = TagOctetString; p = putder(p, vlen); \
		memmove(p, v16, vlen); p += vlen; \
	} while(0)

	PUTFIELD(0, d16, dlen);
	PUTFIELD(1, u16, ulen);
	PUTFIELD(2, p16, plen);
#undef PUTFIELD

	return p - buf;
}

/*
 * Encode TSCredentials { credType [0] INTEGER 1, credentials [1] OCTET STRING }.
 * The credentials field contains the DER encoding of TSPasswordCreds.
 */
static int
mktscreds(uchar *buf, int nbuf, char *dom, char *user, char *pass)
{
	uchar pwdbuf[2048];
	int pwdlen;
	int a0body, a0sz, a1octsz, a1sz, seqbody, total;
	uchar *p;

	pwdlen = mktspasswdcreds(pwdbuf, sizeof pwdbuf, dom, user, pass);
	if(pwdlen < 0)
		return -1;

	/* [0] EXPLICIT INTEGER 1 – always 5 bytes: a0 03 02 01 01 */
	a0body = 3;	/* TagInt(1) + len(1) + value(1) */
	a0sz = 1 + sizeder(a0body) + a0body;

	/* [1] EXPLICIT OCTET STRING (DER of TSPasswordCreds) */
	a1octsz = 1 + sizeder(pwdlen) + pwdlen;
	a1sz = 1 + sizeder(a1octsz) + a1octsz;

	seqbody = a0sz + a1sz;
	total = 1 + sizeder(seqbody) + seqbody;
	if(total > nbuf){
		werrstr("mktscreds: buffer too small");
		return -1;
	}

	p = buf;
	*p++ = BerConstructed|TagSeq; p = putder(p, seqbody);
	/* [0] credType = 1 (password) */
	*p++ = BerContext|0; p = putder(p, a0body);
	*p++ = TagInt; *p++ = 1; *p++ = 1;
	/* [1] credentials = DER(TSPasswordCreds) */
	*p++ = BerContext|1; p = putder(p, a1octsz);
	*p++ = TagOctetString; p = putder(p, pwdlen);
	memmove(p, pwdbuf, pwdlen); p += pwdlen;

	return p - buf;
}

/*
 * Compute the CredSSP v5 client-to-server pubKeyAuth:
 *   ClientServerHashKey = HMAC_SHA256(sesskey, "CredSSP Client-To-Server Binding Hash\0")
 *   pubKeyAuth          = HMAC_SHA256(ClientServerHashKey, cnonce || spki)
 * cnonce is the 32-byte client nonce sent in Phase A.
 * spki is the SubjectPublicKeyInfo DER from the server's TLS certificate.
 */
static int
mkpubkeyauth(uchar *out, int nout, uchar *sesskey, uchar *cnonce,
             uchar *spki, int spkilen)
{
	uchar hashkey[SHA2_256dlen];
	DigestState *ds;
	/* sizeof includes the terminating NUL, which is the explicit \0 in the spec */
	static char csmagic[] = "CredSSP Client-To-Server Binding Hash";

	if(nout < SHA2_256dlen){
		werrstr("mkpubkeyauth: buffer too small");
		return -1;
	}
	hmac_sha2_256((uchar*)csmagic, sizeof csmagic, sesskey, MD5dlen, hashkey, nil);
	ds = hmac_sha2_256(cnonce, 32, hashkey, SHA2_256dlen, nil, nil);
	hmac_sha2_256(spki, spkilen, hashkey, SHA2_256dlen, out, ds);
	return SHA2_256dlen;
}

/*
 * Build Phase A TSRequest: version + negoTokens + clientNonce [5].
 * (Same as mktsreq but also includes [5] OCTET STRING clientNonce for CredSSP v5.)
 */
static int
mktsreqA(uchar *buf, int nbuf, uchar *tok, int toklen, uchar *nonce, int noncelen)
{
	int octetsz, a0toksz, itemsz, datasz, a1sz, nonceoct, a5sz, bodysz, total;
	uchar *p;

	octetsz  = 1 + sizeder(toklen) + toklen;
	a0toksz  = 1 + sizeder(octetsz) + octetsz;
	itemsz   = 1 + sizeder(a0toksz) + a0toksz;
	datasz   = 1 + sizeder(itemsz) + itemsz;
	a1sz     = 1 + sizeder(datasz) + datasz;
	/* [5] clientNonce OCTET STRING */
	nonceoct = 1 + sizeder(noncelen) + noncelen;
	a5sz     = 1 + sizeder(nonceoct) + nonceoct;
	/* [0] INTEGER CredSSPVer: 5 bytes */
	bodysz   = 5 + a1sz + a5sz;
	total    = 1 + sizeder(bodysz) + bodysz;

	if(total > nbuf){
		werrstr("mktsreqA: buffer too small (%d < %d)", nbuf, total);
		return -1;
	}

	p = buf;
	*p++ = BerConstructed|TagSeq; p = putder(p, bodysz);
	/* version [0] */
	*p++ = BerContext|TSSnegoToken; *p++ = 0x03; /* len */
	*p++ = TagInt; p = putder(p, 1); *p++ = CredSSPVer;
	/* negoTokens [1] */
	*p++ = BerContext|TSSnegoTokens; p = putder(p, datasz);
	*p++ = BerConstructed|TagSeq; p = putder(p, itemsz);
	*p++ = BerConstructed|TagSeq; p = putder(p, a0toksz);
	*p++ = BerContext|TSSnegoToken; p = putder(p, octetsz);
	*p++ = TagOctetString; p = putder(p, toklen);
	memmove(p, tok, toklen); p += toklen;
	/* clientNonce [5] */
	*p++ = BerContext|TSSclientNonce; p = putder(p, nonceoct);
	*p++ = TagOctetString; p = putder(p, noncelen);
	memmove(p, nonce, noncelen); p += noncelen;

	return p - buf;
}

/*
 * Build Phase E TSRequest: version + authInfo [2] + pubKeyAuth [3].
 */
static int
mktsreqE(uchar *buf, int nbuf, uchar *pubkey, int pubkeylen, uchar *auth, int authlen)
{
	int aucoctsz, a2sz, puoctsz, a3sz, bodysz, total;
	uchar *p;

	/* [2] authInfo OCTET STRING */
	aucoctsz = 1 + sizeder(authlen) + authlen;
	a2sz     = 1 + sizeder(aucoctsz) + aucoctsz;
	/* [3] pubKeyAuth OCTET STRING */
	puoctsz  = 1 + sizeder(pubkeylen) + pubkeylen;
	a3sz     = 1 + sizeder(puoctsz) + puoctsz;
	/* [0] version: 5 bytes */
	bodysz   = 5 + a2sz + a3sz;
	total    = 1 + sizeder(bodysz) + bodysz;

	if(total > nbuf){
		werrstr("mktsreqE: buffer too small (%d < %d)", nbuf, total);
		return -1;
	}

	p = buf;
	*p++ = BerConstructed|TagSeq; p = putder(p, bodysz);
	/* version [0] */
	*p++ = BerContext|TSSnegoToken; *p++ = 0x03; /* len */
	*p++ = TagInt; p = putder(p, 1); *p++ = CredSSPVer;
	/* authInfo [2] */
	*p++ = BerContext|TSSauthInfo; p = putder(p, aucoctsz);
	*p++ = TagOctetString; p = putder(p, authlen);
	memmove(p, auth, authlen); p += authlen;
	/* pubKeyAuth [3] */
	*p++ = BerContext|TSSpubKeyAuth; p = putder(p, puoctsz);
	*p++ = TagOctetString; p = putder(p, pubkeylen);
	memmove(p, pubkey, pubkeylen); p += pubkeylen;

	return p - buf;
}

/*
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
	PLONG(p, NfUnicode|NfReqTarget|NfNTLM|NfAlwaysSign);	p += 4;		/* NegotiateFlags */
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
mkntauth(uchar *buf, int nbuf, char *user, char *domain, uchar ntresp[NTRespLen], uchar *lmresp)
{
	uchar dom16[512], usr16[512];
	int domlen, usrlen;
	int domoff, usroff, lmoff, ntoff;
	int lmlen, total;
	uchar *p;

	domlen = toutf16(dom16, sizeof dom16, domain, strlen(domain));
	usrlen = toutf16(usr16, sizeof usr16, user, strlen(user));

	lmlen     = NTRespLen;		/* LmChallengeResponse length (24 bytes) */
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
	PLONG(p, NfUnicode|NfReqTarget|NfNTLM|NfAlwaysSign | (lmresp != nil ? NfESS : 0));  p += 4;

	/* payload */
	memmove(p, dom16, domlen);  p += domlen;		/* DomainName */
	memmove(p, usr16, usrlen);  p += usrlen;		/* UserName */
	if(lmresp != nil)
		memmove(p, lmresp, lmlen);			/* ESS: cnonce||zeros; NTLMv1: factotum LMresp */
	else
		memset(p, 0, lmlen);				/* fallback: all zeros */
	p += lmlen;
	memmove(p, ntresp, NTRespLen);  p += NTRespLen;		/* NtChallengeResponse */

	return p - buf;
}

/*
 * Write Phase A TSRequest (NTLM Negotiate + CredSSP v5 clientNonce) to fd.
 */
int
writetsreqnonce(int fd, uchar *tok, int toklen, uchar *nonce, int noncelen)
{
uchar buf[4096];
int n;

n = mktsreqA(buf, sizeof buf, tok, toklen, nonce, noncelen);
if(n < 0)
return -1;
if(write(fd, buf, n) != n){
werrstr("NLA: write TSRequest (phase A): %r");
return -1;
}
return 0;
}

/*
 * Write Phase E TSRequest (pubKeyAuth + authInfo) to fd.
 */
int
writetsreqdone(int fd, uchar *pubkey, int pubkeylen, uchar *auth, int authlen)
{
uchar buf[8192];
int n;

n = mktsreqE(buf, sizeof buf, pubkey, pubkeylen, auth, authlen);
if(n < 0)
return -1;
if(write(fd, buf, n) != n){
werrstr("NLA: write TSRequest (phase E): %r");
return -1;
}
return 0;
}

/*
 * Complete the CredSSP handshake (Phases D and E).
 * Phase D: read the server's TSRequest containing pubKeyAuth.
 * Phase E: send TSRequest with client pubKeyAuth + encrypted TSCredentials.
 *
 *   fd      - TLS file descriptor
 *   cert    - server's TLS certificate DER (for pubKeyAuth channel binding)
 *   certlen - length of cert
 *   clnonce - 32-byte client nonce (sent in Phase A, per CredSSP v5)
 *   dom     - Windows domain (for TSCredentials)
 *   user    - username (for TSCredentials)
 *   pass    - plaintext password (session key derivation + TSCredentials)
 */
int
nlafinish(int fd, uchar *cert, int certlen, uchar *clnonce,
          char *dom, char *user, char *pass)
{
uchar tsreqbuf[4096];
uchar sesskey[MD5dlen], signkey[MD5dlen], sealkey[MD5dlen];
uchar creds[2048], sealcreds[2048+16];
uchar pubkeyauth[SHA2_256dlen];
uchar *spki;
int n, spkilen;

/* Phase D: read server's pubKeyAuth TSRequest */
fprint(2, "nla: reading Phase D (server pubKeyAuth)\n");
n = readtsreq(fd, tsreqbuf, sizeof tsreqbuf);
if(n < 0)
return -1;
fprint(2, "nla: Phase D received (%d bytes)\n", n);

/* Derive NTLMv1 ExportedSessionKey, SignKey, SealKey */
fprint(2, "nla: deriving session/sign/seal keys\n");
ntsesskey(pass, sesskey);
ntlmkeys(sesskey, signkey, sealkey);

/* Extract SubjectPublicKeyInfo from server's TLS certificate */
fprint(2, "nla: extracting server SubjectPublicKeyInfo (certlen=%d)\n", certlen);
spki = nil; spkilen = 0;
if(cert != nil && certlen > 0)
spki = certspki(cert, certlen, &spkilen);
if(spki == nil || spkilen <= 0){
werrstr("NLA: cannot extract server public key from TLS certificate");
return -1;
}
fprint(2, "nla: SPKI extracted (%d bytes)\n", spkilen);

n = mkpubkeyauth(pubkeyauth, sizeof pubkeyauth,
sesskey, clnonce, spki, spkilen);
if(n < 0)
return -1;
fprint(2, "nla: pubKeyAuth computed (%d bytes)\n", n);

n = mktscreds(creds, sizeof creds, dom, user, pass);
if(n < 0)
return -1;
fprint(2, "nla: TSCredentials encoded (%d bytes)\n", n);

n = ntlmseal(sealcreds, sizeof sealcreds, signkey, sealkey, 0, creds, n);
if(n < 0)
return -1;
fprint(2, "nla: authInfo sealed (%d bytes)\n", n);

/* Phase E: send pubKeyAuth + authInfo (encrypted TSCredentials) */
fprint(2, "nla: sending Phase E (pubKeyAuth + authInfo)\n");
n = writetsreqdone(fd, pubkeyauth, sizeof pubkeyauth, sealcreds, n);
fprint(2, "nla: Phase E sent (result=%d)\n", n);
return n;
}
