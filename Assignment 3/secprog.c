/* secprog.c: Valid users can log in and run a command, writing the output to a logfile */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

char *users[] = { "foo"   , "bar"   , "baz" };
char *pass[]  = { "secret", "mypass", "letmein" };
size_t nusers = sizeof(users)/sizeof(*users);

struct {
  char current_user[32];
  int logged_in;
} userdata;

int
main(int argc, char *argv[])
{
  int fd;
  size_t i;
  char logfile[64], cmd[64];

  if(argc < 3) {
    printf("Usage: %s <username> <password>\n", argv[0]);
    return 1;
  }

  userdata.logged_in = 0;
  strcpy(userdata.current_user, argv[1]);//vulnerable, can overflow, should use strncpy
  for(i = 0; i < nusers; i++) {
    if(!strcmp(users[i], argv[1]) && !strcmp(pass[i], argv[2])) { //vulnerable should use strncmp
      userdata.logged_in = 1;
      break;
    }
  }
  if(!userdata.logged_in) {
    printf("User not found\n");
    return 1;
  }

  printf("Welcome %s\n", userdata.current_user);

  printf("Specify logfile name: ");
  gets(logfile);//overflow + format

  printf("Using the following logfile: ");
  printf(logfile);

  if(access(logfile, W_OK) < 0) {//setuid attack
    printf("\nForbidden\n");
    return 1;
  }

  printf("\nEnter command to run: ");
  gets(cmd);//overflow

  fd = open(logfile, O_RDWR);//no i-node check
  if(fd < 0) {
    printf("Failed to open logfile\n");
    return 1;
  }

  dup2(fd, STDOUT_FILENO);
  system(cmd);

  return 0;
}

