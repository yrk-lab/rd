
/* mcs.c */
int		mcschan(uchar*,uchar*);
int		mcstype(uchar*,uchar*);
int		ismcshangup(uchar*,uchar*);
uchar*	mcsdat(uchar*,uchar*);
int		mkmcsci(uchar*, int, int);
int		putmsdr(uchar*,int,int,int,int);

/* mpas.c */
int		isflowpdu(uchar*,uchar*);
int		sizesechdr(int);
uchar*	txprep(uchar*,int,int,int,int,int);

/* snarf.c */
void		initsnarf(void);
char*	getsnarfn(int*);
void		putsnarfn(char*,int);

/* mouse.c */
void		warpmouse(int,int);

/* mppc.c */
uchar*	uncomp(uchar*,int,int,int*);

/* rle.c */
uchar*	unrle(uchar*,int, uchar*,int,int,int);

/* utf16.c */
int		fromutf16(char*,int,uchar*,int);
int		toutf16(uchar*,int,char*,int);

/* x224.c */
int		mktpdat(uchar*,int,int);
int		readpdu(int,uchar*,uint);
int		mktpcr(uchar*,int,int);
int		mktpdr(uchar*,int,int);
int		istpkt(uchar*,uchar*);
int		tptype(uchar*,uchar*);
uchar*	tpdat(uchar*,uchar*);

/* nla.c buffer sizes (also used by rpc.c) */
enum
{
	MaxNTLMTargetInfo	= 1024,	/* maximum TargetInfo AvPairs length from challenge */
	MaxNTLMClientAvExtra	= 8 + (4+16) + (4+512) + 4,	/* MsvAvFlags+MsvAvChannelBindings+MsvAvTargetName+EOL */
	NTv2RespMax		= 16 + 28 + MaxNTLMTargetInfo + MaxNTLMClientAvExtra,	/* max NTLMv2 NtChallengeResponse */
};

/* nla.c */
int		mkntnego(uchar*, int);
int		getntchal(uchar[8], uchar*, int);
uchar*		getntargetinfo(uchar*, int, int*);
int		ntv2frompasswd(char*, char*, char*, uchar*, uchar*, uchar*, int, uchar*, int, uchar*, uchar*, uchar*, int, char*);
int		mkntauth(uchar*, int, char*, char*, uchar*, int, uchar*, uchar*);
void		ntrespfrompasswd(char*, uchar[8], uchar[24]);
int		writetsreq(int, uchar*, int);
int		writetsreqnonce(int, uchar*, int, uchar*, int);
int		writetsreqdone(int, uchar*, int, uchar*, int);
int		nlafinish(int, uchar*, int, uchar*, char*, char*, char*, uchar*);
int		readtsreq(int, uchar*, int);
int		readtsreq_oreuarp(int, uchar*, int, ulong*);
uchar*	gettsreq(uchar*, int, int*);

/* rpc.c */
int		nlahandshake(Rdp*);

/* rd.c */
void		atexitkiller(void);
void		atexitkill(int pid);
void*	emalloc(ulong);
void*	erealloc(void*,ulong);

uchar*	gblen(uchar*,uchar*,int*);
uchar*	gbtag(uchar*,uchar*,int*);
void		pbshort(uchar*,int);

uchar*	putsdh(uchar*,uchar*,int,int,int,int);
