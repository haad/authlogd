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

char buf1[] = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";
char buf2[] = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@0 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] BOMAn application event log entry";
char buf3[] = "<35>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";
char buf4[] = "<166>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@0 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] BOMAn application event log entry";

int
main(int argc, char *argv[])
{
	int s;
	ssize_t size;
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

	if ((size = send(s, buf1, sizeof(buf1), 0)) == -1)
		perror("send failed\n");
	
	printf("size = %d\n", size);
	
	if ((size = send(s, buf4, sizeof(buf4), 0)) == -1)
		perror("send failed\n");
	
	printf("size = %d\n", size);

	if ((size = send(s, buf3, sizeof(buf3), 0)) == -1)
		perror("send failed\n");

	printf("size = %d\n", size);
	
	if ((size = send(s, buf2, sizeof(buf2), 0)) == -1)
		perror("send failed\n");
	
	printf("size = %d\n", size);

	if ((size = send(s, buf1, sizeof(buf1), 0)) == -1)
		perror("send failed\n");

	printf("size = %d\n", size);

	if ((size = send(s, buf4, sizeof(buf4), 0)) == -1)
		perror("send failed\n");

	printf("size = %d\n", size);
	
	close(s);
	
	return 0;
}
