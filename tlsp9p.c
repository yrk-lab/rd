#include <u.h>
#include <sys/socket.h>	/* before libc.h to avoid accept/listen macro conflicts */
#include <libc.h>
#include <mp.h>
#include <libsec.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "dat.h"
#include "fns.h"

static int
istrusted(uchar* cert, int certlen)
{
	uchar digest[SHA1dlen];
	Thumbprint* table;

	fmtinstall('H', encodefmt);
	if(cert == nil || certlen <= 0){
		werrstr("server did not provide TLS certificate");
		return 0;
	}
	sha1(cert, certlen, digest, nil);
	table = initThumbprints(unsharp("#9/lib/tls/rdp"), unsharp("#9/lib/tls/rdp.exclude"));
	if(!table || !okThumbprint(digest, table)){
		werrstr("server certificate not recognized");
		fprint(2, "verify server certificate %.*H\n", SHA1dlen, digest);
		fprint(2, "add thumbprint after verification:\n");
		fprint(2, "\techo 'x509 sha1=%.*H' >> $PLAN9/lib/tls/rdp\n", SHA1dlen, digest);
		return 0;
	}
	freeThumbprints(table);
	return 1;
}

static int
checkpeer(SSL* s)
{
	X509* peercrt;
	uchar* cert;
	int certlen, ok;

	peercrt = SSL_get_peer_certificate(s);
	cert = nil;
	certlen = 0;
	if(peercrt != nil)
		certlen = i2d_X509(peercrt, &cert);
	X509_free(peercrt);
	ok = istrusted(cert, certlen);
	OPENSSL_free(cert);
	return ok;
}

static void
readtls(int pipefd, SSL* s)
{
	char buf[16384];
	int n;

	for(;;){
		n = SSL_read(s, buf, sizeof buf);
		if(n <= 0)
			break;
		if(write(pipefd, buf, n) != n)
			break;
	}
	SSL_shutdown(s);
	SSL_free(s);
	close(pipefd);
	_exits(nil);
}

static void
readlocal(int pipefd, SSL* s)
{
	char buf[16384];
	int n;

	for(;;){
		n = read(pipefd, buf, sizeof buf);
		if(n <= 0)
			break;
		if(SSL_write(s, buf, n) <= 0)
			break;
	}
	SSL_free(s);
	close(pipefd);
	_exits(nil);
}

int
starttls(Rdp* r)
{
	SSL_CTX* ctx;
	SSL* s;
	int p[2];
	static int inited;

	if(!inited){
		SSL_library_init();
		SSL_load_error_strings();
		inited = 1;
	}

	ctx = SSL_CTX_new(TLS_client_method());
	if(ctx == nil)
		goto ErrCtx;
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil);
	s = SSL_new(ctx);
	SSL_CTX_free(ctx);
	if(s == nil)
		goto ErrNew;
	if(SSL_set_fd(s, r->fd) != 1 || SSL_connect(s) != 1)
		goto ErrConnect;
	fprint(2, "tls: %s %s\n", SSL_get_version(s), SSL_get_cipher(s));

	if(!checkpeer(s))
		goto ErrCert;

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, p) < 0)
		goto ErrSocket;
	switch(fork()){
	case -1:
		goto ErrFork;
	case 0:
		close(p[1]);
		readtls(p[0], s);
	}
	switch(fork()){
	case -1:
		goto ErrFork;
	case 0:
		close(p[1]);
		readlocal(p[0], s);
	}

	close(r->fd);
	close(p[0]);
	r->fd = p[1];
	return p[1];

ErrFork:
	werrstr("fork: %r");
	close(p[0]);
	close(p[1]);
	SSL_free(s);
	return -1;
ErrSocket:
	werrstr("socketpair: %r");
	SSL_free(s);
	return -1;
ErrCert:
	SSL_free(s);
	return -1;
ErrConnect:
	werrstr("SSL: %s", ERR_reason_error_string(ERR_get_error()));
	SSL_free(s);
	return -1;
ErrNew:
	werrstr("SSL_new failed");
	return -1;
ErrCtx:
	werrstr("SSL_CTX_new: %s", ERR_reason_error_string(ERR_get_error()));
	return -1;
}
