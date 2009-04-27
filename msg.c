#include <sys/param.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "authlogd.h"


static void find_sd(msg_t *);
static void get_auth_sd(msg_t *);

/*!
 * Parse syslog message and fills msg_t structure.
 * @bug I need to validate syslog message, we can use only syslog
 *      protocol messages with valid syntax.
 * @param msg General syslog message description structure.
 */
void
parse_msg(msg_t *msg)
{
	find_sd(msg);
	get_auth_sd(msg);

	/** There is 6 space chars from message start to start of SD element part. */
	snprintf(msg->msg_new, sizeof(msg->msg_new), "%s%s%s\n",
	    msg->msg_header, msg->msg_auth_sd, msg->msg_body);
}


/*!
 * Create and sign Authlog message SD element. This element will be later
 * appended to original syslog message.
 * @param msg General syslog message description structure.
 */
static void
get_auth_sd(msg_t *msg)
{
	char *sign = '\0';
	const char *status;
	
	status = NULL;
	
#define AUTHORIZE   "Authorized"
#define DENY        "Denied"
#define UNKNOWN     "Unknown"	
	switch (msg->msg_auth_status) {
	case 0:
		status = DENY;
		break;
	case 1:
		status = AUTHORIZE;
		break;
	case 2:
		status = UNKNOWN;
		break;
	}
	
	sign = authlogd_sign_buf(status, strlen(status));
		
	snprintf(msg->msg_auth_sd, AUTHLOG_AUTH_SD, " [@authlogd msg=\"%s\" sign=\"%s\"]", status, sign);
		
	return;
}

/*!
 * Parse syslog message and find place where we can place Authlogd SD element.
 * There are 2 possible cases:
 * 1) There is no SD element in present message then we are looking for '-'
 *    after 6th ' ' char.
 * 2) There is already SD element present in message we will add auth sd element
 *    before it.
 * In both cases I set msg::msg_header to string which ends in place of 6th space
 * with '\0'. msg::msg_body is set to other part of message wich starts with
 * '[' in case the second or with ' ' in the first case.
 * @param msg General message structure.
 */
static void
find_sd(msg_t *msg)
{
	int space;
	char *str;

	str = msg->msg_buf;
	space = 0;
	
	for (str = msg->msg_buf; str != '\0'; str++) {
		
		if (*str == ' ') {
			space++;
		} else
			continue;

		if (space == 6) {
			str++;

			/** There are no SD elements in message */
			if (*str == '-') {
				msg->msg_header = msg->msg_buf;
				msg->msg_body = ++str;

				str -= 2;
				*str = '\0';
			}

			if (*str == '[') {
				msg->msg_body = str;
				msg->msg_header = msg->msg_buf;
								
				str--;
				*str = '\0';
			}
			break;
		}
	}
	return;
}
