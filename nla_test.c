#include "nla.c"

int nlatests(void);

/*
 * testmkntnego: NTLM Negotiate (Type 1) message must be 32 bytes with
 * correct signature, message type, and negotiate flags.
 */
static int
testmkntnego(void)
{
	uchar buf[64];
	int n;

	n = mkntnego(buf, sizeof buf);
	if(n != 32)
		sysfatal("testmkntnego: want 32 bytes, got %d", n);
	if(memcmp(buf, "NTLMSSP\0", 8) != 0)
		sysfatal("testmkntnego: bad signature");
	if(GLONG(buf+8) != 1)
		sysfatal("testmkntnego: want MessageType=1, got %ld", (long)GLONG(buf+8));
	if(GLONG(buf+12) != (NfUnicode|NfReqTarget|NfNTLM|NfSign|NfSeal|NfAlwaysSign))
		sysfatal("testmkntnego: want NTLMFlags=%ux, got %lux",
			NfUnicode|NfReqTarget|NfNTLM|NfSign|NfSeal|NfAlwaysSign, (ulong)GLONG(buf+12));
	return 0;
}

/*
 * testmkntnegosmall: buffer too small must return an error.
 */
static int
testmkntnegosmall(void)
{
	uchar buf[16];
	int n;

	n = mkntnego(buf, sizeof buf);
	if(n >= 0)
		sysfatal("testmkntnegosmall: expected error, got %d", n);
	return 0;
}

/*
 * testgetntchal: extract the 8-byte challenge from a minimal but valid
 * NTLM Challenge (Type 2) message.
 */
static int
testgetntchal(void)
{
	uchar msg[48];
	uchar challenge[8];
	uchar wantchal[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	int n;

	memset(msg, 0, sizeof msg);
	memmove(msg, "NTLMSSP\0", 8);
	PLONG(msg+8, 2);			/* MessageType = 2 */
	memmove(msg+24, wantchal, 8);		/* ServerChallenge */

	n = getntchal(challenge, msg, sizeof msg);
	if(n < 0)
		sysfatal("testgetntchal: unexpected error");
	if(memcmp(challenge, wantchal, 8) != 0)
		sysfatal("testgetntchal: challenge mismatch");
	return 0;
}

/*
 * testgetntchalshort: message shorter than 32 bytes must return an error.
 */
static int
testgetntchalshort(void)
{
	uchar msg[10];
	uchar challenge[8];
	int n;

	memset(msg, 0, sizeof msg);
	n = getntchal(challenge, msg, sizeof msg);
	if(n >= 0)
		sysfatal("testgetntchalshort: expected error, got %d", n);
	return 0;
}

/*
 * testgetntchalbadsig: wrong signature must return an error.
 */
static int
testgetntchalbadsig(void)
{
	uchar msg[48];
	uchar challenge[8];
	int n;

	memset(msg, 0, sizeof msg);
	memmove(msg, "BADMSSSP", 8);
	PLONG(msg+8, 2);

	n = getntchal(challenge, msg, sizeof msg);
	if(n >= 0)
		sysfatal("testgetntchalbadsig: expected error, got %d", n);
	return 0;
}

/*
 * testgetntchalbadtype: MessageType != 2 must return an error.
 */
static int
testgetntchalbadtype(void)
{
	uchar msg[48];
	uchar challenge[8];
	int n;

	memset(msg, 0, sizeof msg);
	memmove(msg, "NTLMSSP\0", 8);
	PLONG(msg+8, 1);			/* Type 1, not 2 */

	n = getntchal(challenge, msg, sizeof msg);
	if(n >= 0)
		sysfatal("testgetntchalbadtype: expected error, got %d", n);
	return 0;
}

/*
 * testmktsreqhdr: verify the exact DER encoding of a TSRequest wrapping a
 * single-byte NTLM token (0xAA).
 *
 *   30 10  SEQUENCE(16)
 *     a0 03 02 01 05  [0] version=5
 *     a1 09  [1] negoTokens(9)
 *       30 07  SEQUENCE OF(7)
 *         30 05  SEQUENCE(5)
 *           a0 03  [0](3)
 *             04 01 AA  OCTET STRING{AA}
 */
static int
testmktsreqhdr(void)
{
	uchar token[] = {0xAA};
	uchar want[] = {
		0x30, 0x10,
		0xa0, 0x03, 0x02, 0x01, 0x05,
		0xa1, 0x09,
		0x30, 0x07,
		0x30, 0x05,
		0xa0, 0x03,
		0x04, 0x01, 0xAA,
	};
	uchar buf[64];
	int n;

	n = mktsreq(buf, sizeof buf, token, sizeof token);
	if(n != (int)sizeof want)
		sysfatal("testmktsreqhdr: len: want %d, got %d", (int)sizeof want, n);
	if(memcmp(buf, want, sizeof want) != 0)
		sysfatal("testmktsreqhdr: bytes mismatch");
	return 0;
}

/*
 * testmktsreqround: round-trip encode/decode must recover the original token.
 */
static int
testmktsreqround(void)
{
	uchar token[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
	uchar buf[256];
	uchar *outp;
	int n, outlen;

	n = mktsreq(buf, sizeof buf, token, sizeof token);
	if(n < 0)
		sysfatal("testmktsreqround: mktsreq failed");
	outp = gettsreq(buf, n, &outlen);
	if(outp == nil)
		sysfatal("testmktsreqround: gettsreq failed");
	if(outlen != (int)sizeof token)
		sysfatal("testmktsreqround: outlen: want %d, got %d",
			(int)sizeof token, outlen);
	if(memcmp(outp, token, sizeof token) != 0)
		sysfatal("testmktsreqround: token mismatch");
	return 0;
}

/*
 * testmktsreqsmallbuf: buffer too small must return an error.
 */
static int
testmktsreqsmallbuf(void)
{
	uchar token[8] = {0};
	uchar buf[4];
	int n;

	n = mktsreq(buf, sizeof buf, token, sizeof token);
	if(n >= 0)
		sysfatal("testmktsreqsmallbuf: expected error, got %d", n);
	return 0;
}

/*
 * testmkntauth: NTLM Authenticate (Type 3) message must have correct
 * signature, message type, and negotiate flags at the expected offsets.
 */
static int
testmkntauth(void)
{
	uchar ntresp[NTRespLen];
	uchar buf[640];
	int n;

	memset(ntresp, 0x55, NTRespLen);
	n = mkntauth(buf, sizeof buf, "joe", "CORP", ntresp, nil);
	if(n < 0)
		sysfatal("testmkntauth: unexpected error");
	if(n < 64)
		sysfatal("testmkntauth: message too short (%d)", n);
	if(memcmp(buf, "NTLMSSP\0", 8) != 0)
		sysfatal("testmkntauth: bad signature");
	if(GLONG(buf+8) != 3)
		sysfatal("testmkntauth: want MessageType=3, got %ld", (long)GLONG(buf+8));
	if(GLONG(buf+60) != (NfUnicode|NfReqTarget|NfNTLM|NfSign|NfSeal|NfAlwaysSign))
		sysfatal("testmkntauth: bad NegotiateFlags");
	return 0;
}

int
nlatests(void)
{
	testmkntnego();
	testmkntnegosmall();
	testgetntchal();
	testgetntchalshort();
	testgetntchalbadsig();
	testgetntchalbadtype();
	testmktsreqhdr();
	testmktsreqround();
	testmktsreqsmallbuf();
	testmkntauth();
	return 0;
}
