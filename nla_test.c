#define NLATESTONLY
#include "nla.c"

int nlatests(void);

/*
 * testmkntlmnego: NTLM Negotiate (Type 1) message must be 32 bytes with
 * correct signature, message type, and negotiate flags.
 */
static int
testmkntlmnego(void)
{
	uchar buf[64];
	int n;

	n = mkntlmnego(buf, sizeof buf);
	if(n != 32)
		sysfatal("testmkntlmnego: want 32 bytes, got %d", n);
	if(memcmp(buf, "NTLMSSP\0", 8) != 0)
		sysfatal("testmkntlmnego: bad signature");
	if(GLONG(buf+8) != 1)
		sysfatal("testmkntlmnego: want MessageType=1, got %ld", (long)GLONG(buf+8));
	if(GLONG(buf+12) != NTLMFlags)
		sysfatal("testmkntlmnego: want NTLMFlags=%ux, got %lux",
			NTLMFlags, (ulong)GLONG(buf+12));
	return 0;
}

/*
 * testmkntlmnegosmall: buffer too small must return an error.
 */
static int
testmkntlmnegosmall(void)
{
	uchar buf[16];
	int n;

	n = mkntlmnego(buf, sizeof buf);
	if(n >= 0)
		sysfatal("testmkntlmnegosmall: expected error, got %d", n);
	return 0;
}

/*
 * testgetntlmchal: extract the 8-byte challenge from a minimal but valid
 * NTLM Challenge (Type 2) message.
 */
static int
testgetntlmchal(void)
{
	uchar msg[48];
	uchar challenge[8];
	uchar wantchal[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	int n;

	memset(msg, 0, sizeof msg);
	memmove(msg, "NTLMSSP\0", 8);
	PLONG(msg+8, 2);			/* MessageType = 2 */
	memmove(msg+24, wantchal, 8);		/* ServerChallenge */

	n = getntlmchal(msg, sizeof msg, challenge);
	if(n < 0)
		sysfatal("testgetntlmchal: unexpected error");
	if(memcmp(challenge, wantchal, 8) != 0)
		sysfatal("testgetntlmchal: challenge mismatch");
	return 0;
}

/*
 * testgetntlmchalshort: message shorter than 32 bytes must return an error.
 */
static int
testgetntlmchalshort(void)
{
	uchar msg[10];
	uchar challenge[8];
	int n;

	memset(msg, 0, sizeof msg);
	n = getntlmchal(msg, sizeof msg, challenge);
	if(n >= 0)
		sysfatal("testgetntlmchalshort: expected error, got %d", n);
	return 0;
}

/*
 * testgetntlmchalbadsig: wrong signature must return an error.
 */
static int
testgetntlmchalbadsig(void)
{
	uchar msg[48];
	uchar challenge[8];
	int n;

	memset(msg, 0, sizeof msg);
	memmove(msg, "BADMSSSP", 8);
	PLONG(msg+8, 2);

	n = getntlmchal(msg, sizeof msg, challenge);
	if(n >= 0)
		sysfatal("testgetntlmchalbadsig: expected error, got %d", n);
	return 0;
}

/*
 * testgetntlmchalbadtype: MessageType != 2 must return an error.
 */
static int
testgetntlmchalbadtype(void)
{
	uchar msg[48];
	uchar challenge[8];
	int n;

	memset(msg, 0, sizeof msg);
	memmove(msg, "NTLMSSP\0", 8);
	PLONG(msg+8, 1);			/* Type 1, not 2 */

	n = getntlmchal(msg, sizeof msg, challenge);
	if(n >= 0)
		sysfatal("testgetntlmchalbadtype: expected error, got %d", n);
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
	if(gettsreq(buf, n, &outp, &outlen) < 0)
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
 * testmkntlmauth: NTLM Authenticate (Type 3) message must have correct
 * signature, message type, and negotiate flags at the expected offsets.
 */
static int
testmkntlmauth(void)
{
	uchar ntresp[NTRespLen];
	uchar buf[640];
	int n;

	memset(ntresp, 0x55, NTRespLen);
	n = mkntlmauth(buf, sizeof buf, "joe", "CORP", ntresp);
	if(n < 0)
		sysfatal("testmkntlmauth: unexpected error");
	if(n < 64)
		sysfatal("testmkntlmauth: message too short (%d)", n);
	if(memcmp(buf, "NTLMSSP\0", 8) != 0)
		sysfatal("testmkntlmauth: bad signature");
	if(GLONG(buf+8) != 3)
		sysfatal("testmkntlmauth: want MessageType=3, got %ld", (long)GLONG(buf+8));
	if(GLONG(buf+60) != NTLMFlags)
		sysfatal("testmkntlmauth: bad NegotiateFlags");
	return 0;
}

int
nlatests(void)
{
	testmkntlmnego();
	testmkntlmnegosmall();
	testgetntlmchal();
	testgetntlmchalshort();
	testgetntlmchalbadsig();
	testgetntlmchalbadtype();
	testmktsreqhdr();
	testmktsreqround();
	testmktsreqsmallbuf();
	testmkntlmauth();
	return 0;
}
