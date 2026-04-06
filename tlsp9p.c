#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>
#include "dat.h"
#include "fns.h"

int
istrusted(uchar* cert, int certlen)
{
	return 1;
}

/* lifted from /sys/src/cmd/upas/fs/imap4.c:/^starttls */
int
starttls(Rdp* r)
{
	TLSconn c;
	int fd, sfd;

	fd = r->fd;

	memset(&c, 0, sizeof c);
	sfd = tlsClient(fd, &c);
	if(sfd < 0){
		werrstr("tlsClient: %r");
		return -1;
	}
	if(!istrusted(c.cert, c.certlen)){
		close(sfd);
		return -1;
	}
	if(c.cert != nil && c.certlen > 0){
		r->tlscert = malloc(c.certlen);
		if(r->tlscert != nil){
			memmove(r->tlscert, c.cert, c.certlen);
			r->tlscertlen = c.certlen;
		}
	}
	/* BUG: free c.cert? */

	close(r->fd);
	r->fd = sfd;
	return sfd;
}
