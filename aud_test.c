#include "audio.c"

void playsound(Rdp*, uchar*, uint) {};

int audiotests(void);

static int testaudio1(void);
static int testaudio2(void);


static char* pkt1 = 
"07000E04"	// Header
"F0EEC802"	// dwFlags
"AB95AC03"	// dwVolume
"4B8E1731"	// dwPitch
"0000"	// wDGramPort 
"2900"	// wNumberOfFormats=41
"FF"	// cLastBlockConfirmed=255
"0800"	// wVersion=8
"00"	// bPad
// AUDIO_FORMAT[0]
"06A1"	// wFormatTag=0xA106 (AAC)
"0200"	// nChannels=2
"44AC0000"	// nSamplesPerSec=44,100
"C05D0000"	// nAvgBytesPerSec=0x5DC0
"0400"	// nBlockAlign=4 
"1000"	// wBitsPerSample=16
"0000"	// cbSize=0
// AUDIO_FORMAT[1]
"06A1"	// wFormatTag=0xA106 (AAC)
"0200"	// nChannels=2
"44AC0000"	// nSamplesPerSec=0xAC44
"204E0000"	// nAvgBytesPerSec=0x4E20
"0400"	// nBlockAlign=4
"1000"	// wBitsPerSample=16
"0000"	// cbSize=0
// AUDIO_FORMAT[2]
"06A1"	// wFormatTag=0xA106 (AAC)
"0200"	// nChannels=2
"44AC0000"	// nSamplesPerSec=44,100
"803E0000"	// nAvgBytesPerSec=0x3E80
"0400"	// nBlockAlign=4
"1000"	// wBitsPerSample=16
"0000"	// cbSize=0
// AUDIO_FORMAT[3]
"06A1"	// wFormatTag=0xA106 (AAC)
"0200"	// nChannels=2
"44AC0000"	// nSamplesPerSec=44,100
"E02E0000"	// nAvgBytesPerSec=0x2EE0
"0400"	// nBlockAlign=4
"1000"	// wBitsPerSample=16
"0000"	// cbSize=0
// AUDIO_FORMAT[4]
"0100"	// wFormatTag=0x0001 (PCM)
"0200"	// nChannels=2
"44AC0000"	// nSamplesPerSec=44,100
"10B10200"	// nAvgBytesPerSec=176,400
"0400"	// nBlockAlign=4
"1000"	// wBitsPerSample=16
"0000"	// cbSize=0
// AUDIO_FORMAT[5]
"0600"	// wFormatTag=0x0006 (ALAW)
"0200"
"44AC0000"
"88580100"
"0200"
"0800"
"0000"
// AUDIO_FORMAT[6]
"0700"	// wFormatTag=0x0007 (MULAW)
"0200"
"44AC0000"
"88580100"
"0200"
"0800"
"0000"
// AUDIO_FORMAT[7]
"0200"	// wFormatTag=0x0002 (ADPCM)
"0200"	// nChannels=2
"44AC0000"	// nSamplesPerSec=44,100
"47AD0000"	// nAvgBytesPerSec=0xAD47
"0008"	// nBlockAlign=2048
"0400"	// wBitsPerSample=4
"2000"	// cbSize=32
"F4070700"	"00010000"
"000200FF"	"00000000"
"C0004000"	"F0000000"
"CC0130FF"	"880118FF"
// AUDIO_FORMAT[8]
"1100"	// wFormatTag=0x11(DVI_ADPCM)
"0200"
"44AC0000"
"DBAC0000"
"0008"
"0400"
"0200"	// cbSize=2
"F907"
// AUDIO_FORMAT[9]
"0600"	// wFormatTag=0x0006 (ALAW)
"0200"
"22560000"
"44AC0000"
"0200"
"0800"
"0000"
// AUDIO_FORMAT[10]
"0600"
"0100"
"44AC0000"
"44AC0000"
"0100"
"0800"
"0000"
// AUDIO_FORMAT[11]
"0700"
"0200"
"22560000"
"44AC0000"
"0200"
"0800"
"0000"
// AUDIO_FORMAT[11]
"0700"
"0100"
"44AC0000"
"44AC0000"
"0100"
"0800"
"0000"
// AUDIO_FORMAT[12]
"0200"
"0200"
"22560000"
"27570000"
"0004"
"0400"
"2000"	// cbSize=32
"F4030700"	"00010000"
"000200FF"	"00000000"
"C0004000"	"F0000000"
"CC0130FF"	"880118FF"
// AUDIO_FORMAT[13]
"1100"
"0200"
"22560000"
"B9560000"
"0004"
"0400"
"0200"	// cbSize=2
"F903"
// AUDIO_FORMAT[14]
"0200"
"0100"
"44AC0000"
"A3560000"
"0004"
"0400"
"2000"	// cbSize=32
"F4070700"	"00010000"
"000200FF"	"00000000"
"C0004000"	"F0000000"
"CC0130FF"	"880118FF"
// AUDIO_FORMAT[14]
"1100"
"0100"
"44AC0000"
"6D560000"
"0004"
"0400"
"0200"
"F907"
// [15]
"0600"
"0200"
"112B0000"
"22560000"
"0200"
"0800"
"0000"
// [16]
"0600"
"0100"
"22560000"
"22560000"
"0100"
"0800"
"0000"
// [17]
"0700"
"0200"
"112B0000"
"22560000"
"0200"
"0800"
"0000"
// [18]
"0700"
"0100"
"22560000"
"22560000"
"0100"
"0800"
"0000"
// [19]
"0600"
"0200"
"401F0000"
"803E0000"
"0200"
"0800"
"0000"
// [20]
"0700"
"0200"
"401F0000"
"803E0000"
"0200"
"0800"
"0000"
// [21]
"0200"
"0200"
"112B0000"
"192C0000"
"0002"
"0400"
"2000"
"F4010700"	"00010000"
"000200FF"	"00000000"
"C0004000"	"F0000000"
"CC0130FF"	"880118FF"
// [22]
"1100"
"0200"
"112B0000"
"A92B0000"
"0002"
"0400"
"0200"
"F901"
// [23]
"0200"
"0100"
"22560000"
"932B0000"
"0002"
"0400"
"2000"
"F4030700"	"00010000"
"000200FF"	"00000000"
"C0004000"	"F0000000"
"CC0130FF"	"880118FF"
// [24]
"1100"
"0100"
"22560000"
"5C2B0000"
"0002"
"0400"
"0200"
"F903"
// [25]
"0600"
"0100"
"112B0000"
"112B0000"
"0100"
"0800"
"0000"
// [26]
"0700"
"0100"
"112B0000"
"112B0000"
"0100"
"0800"
"0000"
// [27]
"3100"	// wFormatTag=0x31 (GSM610)
"0100"
"44AC0000"
"FD220000"
"4100"
"0000"
"0200"
"4001"	// cbSize=320
// [28]
"02000200" "401F0000" "00200000" "00020400"
"2000F401" "07000001" "00000002" "00FF0000"
"0000C000" "4000F000" "0000CC01" "30FF8801"
"18FF1100" "0200401F" "0000AE1F" "00000002"
"04000200" "F9010600" "0100401F" "0000401F"
"00000100" "08000000" "07000100" "401F0000"
"401F0000" "01000800" "00000200" "0100112B"
"00000C16" "00000001" "04002000" "F4010700"
"00010000" "000200FF" "00000000" "C0004000"
"F0000000" "CC0130FF" "880118FF" "11000100"
"112B0000" "D4150000" "00010400" "0200F901"
"31000100" "22560000" "7E110000" "41000000"
"02004001" "02000100" "401F0000" "00100000"
"00010400" "2000F401" "07000001" "00000002"
"00FF0000" "0000C000" "4000F000" "0000CC01"
"30FF8801" "18FF1100" "0100401F" "0000D70F"
"00000001" "04000200" "F9013100" "0100112B"
"0000BF08" "00004100" "00000200" "40013100"
"0100401F" "00005906" "00004100" "00000200"
"4001";

static int
testaudio1(){
	int n, nb;
	uchar buf[1042];
	Audiomsg r;

	nb = dec16(buf, sizeof buf, pkt1, strlen(pkt1));
	n = audiogetmsg(&r, buf, nb);
	if(n < 0)
		sysfatal("testaudio1: unexpected error: %r\n");
	if(n != 1042)
		sysfatal("testaudio1: len: want %d, got %d\n", 1042, n);
	if(r.type != Afmt)
		sysfatal("testaudio1: r.type: want 0x%x, got 0x%x\n",
			Afmt, r.type);
	if(r.seq != 255)
		sysfatal("testaudio1: r.seq: want %ud, got %ud\n",
			255, r.seq);
	if(r.ver != 8)
		sysfatal("testaudio1: r.ver: want %ud, got %ud\n",
			8, r.ver);
	if(r.nfmt != 41)
		sysfatal("testaudio1: r.nfmt: want %ud, got %ud\n",
			41, r.nfmt);
	if(r.ndata != 1018)
		sysfatal("testaudio1: r.bdata: want %ud, got %ud\n",
			1018, r.ndata);
	return 0;
}

static int
testaudio2()
{
	int n;
	char *s, *want;
	uchar buf[1042];
	Audiomsg m;

	m.type = Afmt;
	n = audioputmsg(buf, sizeof buf, &m);
	if(n < 0)
		sysfatal("testaudio2: unexpected error: %r\n");
	s = smprint("%.*H", n, buf);
	want = "07002600" "01000000" "FFFFFFFF" "00000100"
		"00000100" "00050000" "01000200" "44AC0000"
		"10B10200" "04001000" "0000";
	if(strcmp(s, want) != 0)
		sysfatal("testaudio2: want %s, got %s", want, s);
	if(n != strlen(want)/2)
		sysfatal("testaudio2: want %ld, got %d", strlen(want)/2, n);
	return 0;
}

int
audiotests()
{
	fmtinstall('H', encodefmt);

	testaudio1();
	testaudio2();
	return 0;
}
