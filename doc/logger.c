#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define AUTHLOG_PATH "/var/run/authlog"

int
main(int argc, char *argv[])
{
	int s;
	struct sockaddr_un sa;
	
	/*
	 * Set up socket variables (address family; name of server socket)
	 * (they'll be used later for the connect() call)
	 */
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, AUTHLOG_PATH,
	    (sizeof(struct sockaddr_un) - sizeof(short)));
	
	/*
	 * Create the client socket
	 */
	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("pitch - socket failed");
		exit(0);
	}

	/*
	 * Connect to the server
	 */
	if ((connect(s, (const struct sockaddr *)&sa, sizeof(struct sockaddr_un))) == - 1) {
		perror("pitch - connect failed");
		exit(0);
	}

	printf("My creds are gid: %d, uid: %d, pid: %d\n", getegid(), geteuid(), getpid());

	close(s);
	
	return 0;
}
