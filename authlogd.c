
#include <sys/param.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void usage(void);

int
main(int argc, char **argv)
{

  usage();

  return EXIT_SUCCESS;
}

static void 
usage(void)
{

  printf("Authlogd daemon accept these switches\n");

  exit(EXIT_FAILURE);
}
