#define _DEFAULT_SOURCE
#include <syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h> 
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

#define printable(ch) (isprint((unsigned char) ch) ? ch : '#')

#define ADDRSTRLEN (NI_MAXHOST + NI_MAXSERV + 10)
#define MAX_EVENTS 10
#define MAX_LINE 1024
#define MAX_SERVICES 128

fd_set readfds;
char buf[MAX_LINE];

struct service {
  int fd;
  int wait;
  int type;
  uid_t uid;
  uid_t gid;
  pid_t pid;
  char **line;
};

struct service *services[MAX_SERVICES];
int cur_ind = 0;

struct service* findServiceFromFd(int fd) {
  for (int i = 0; i < cur_ind; i++) {
    if (services[i] -> fd == fd) {
      return services[i];
    }
  }
  return NULL;
}

struct service* findServiceFromPid(pid_t pid) {
  for (int i = 0; i < cur_ind; i++) {
    if (services[i] -> pid == pid) {
      return services[i];
    }
  }
  return NULL;
}

struct service* getService(char **line) {
  struct service *service = malloc(sizeof(struct service));
  if (strcmp(line[3], "nowait") == 0) {
    service -> wait = 0;
  } else {
    service -> wait = 1;
  }
  service -> line = line;

  service -> uid = -1;
  service -> gid = -1;

  int name_len = strlen(line[4]);
  char name[name_len + 1];
  strcpy(name, line[4]);

  char *token = strtok(name, ".:"); 
  if (token != NULL) {
    struct passwd *passwd = getpwnam(token);
    if (passwd != NULL) {
      service -> uid = passwd -> pw_uid;
    }
  }
  token = strtok(NULL, ".:"); 
  if (token != NULL) {
    struct group *group = getgrnam(token);
    if (group != NULL) {
      service -> gid = group -> gr_gid;
    }
  }
  services[cur_ind++] = service;
  return service;
}

void openSocket(struct service *service) {
  int sfd, optval;
  struct addrinfo hints;
  struct addrinfo *result, *rp;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;
  if (strcmp(service -> line[1], "stream") == 0) {
    hints.ai_socktype = SOCK_STREAM;
  } else if (strcmp(service -> line[1], "dgram") == 0) {
    hints.ai_socktype = SOCK_DGRAM;
  }
  if (strcmp(service -> line[2], "tcp") == 0) {
    hints.ai_protocol = IPPROTO_TCP;
  } else if (strcmp(service -> line[2], "udp") == 0) {
    hints.ai_protocol = IPPROTO_UDP;
  } else if (strcmp(service -> line[2], "sctp") == 0) {
    hints.ai_protocol = IPPROTO_SCTP;
  }
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(NULL, service -> line[0], &hints, &result) != 0) {
    perror("getaddrinfo");
    exit(EXIT_FAILURE);
  }

  optval = 1;
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp -> ai_family, rp -> ai_socktype | SOCK_NONBLOCK, rp -> ai_protocol);
    if (sfd == -1)
      continue;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
      perror("setsockopt");
      exit(EXIT_FAILURE);
    }
    if (bind(sfd, rp -> ai_addr, rp -> ai_addrlen) == 0)
      break;
    close(sfd);
  }
  if (rp == NULL) {
    printf("Could not bind socket to any address\n");
    exit(EXIT_FAILURE);
  }
  if (rp -> ai_socktype == SOCK_STREAM && listen(sfd, SOMAXCONN) == -1) {
    perror("listen");
    exit(EXIT_FAILURE);
  }
  freeaddrinfo(result);

  service -> type = rp -> ai_socktype;
  service -> fd = sfd;
}

char** parseLine(char *buf) {
  int line_len = strlen(buf);
  char *lineStr = malloc(sizeof(char) * (line_len + 1));
  strcpy(lineStr, buf);

  int num_tok = 1;
  for (int i = 0; i < line_len; i++) {
    if (lineStr[i] == ' ' || lineStr[i] == '\t') num_tok++;
  }

  char **line = malloc(sizeof(char*) * (num_tok + 1));
  char **lp = line;
  *lp = strtok(lineStr, " \t"); 
  while (*lp != NULL) { 
    printf("%s\n", *lp); 
    lp++;
    *lp = strtok(NULL, " \t"); 
  }
  lp = NULL;
  return line;
}

void setupFd(int nfds, int fd) {
  for (int fdi = 0; fdi < nfds; fdi++) {
    if (fdi == fd) continue;
    close(fdi);
  }
  if (dup2(fd, STDIN_FILENO) != STDIN_FILENO) {
    perror("dup2");
    exit(EXIT_FAILURE);
  }
  if (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO) {
    perror("dup2");
    exit(EXIT_FAILURE);
  }
  if (dup2(fd, STDERR_FILENO) != STDERR_FILENO) {
    perror("dup2");
    exit(EXIT_FAILURE);
  }
  if (fd > 2) {
    close(fd);
  }
}

void setUGId(struct service *service) {
  if (service -> uid != -1) {
    setuid(service -> uid);
  }
  if (service -> gid != -1) {
    setgid(service -> gid);
  }
}

void sigChldHandler(int sig) {
  int status = 0;
  pid_t childPid;
  while ((childPid = waitpid(-1, &status, WNOHANG)) > 0) {
    struct service *service = findServiceFromPid(childPid);
    if (service != NULL && service -> wait) {
      service -> pid = -1;
      FD_SET(service -> fd, &readfds);
    }
  }
  if (childPid == -1 && errno != ECHILD) {
    perror("waitpid");
  }
}

static void usageError(char *progName, char *msg, int opt) {
  if (msg != NULL && opt != 0)
  fprintf(stderr, "%s (-%c)\n", msg, printable(opt));
  fprintf(stderr, "Usage: %s [-c config_path]\n", progName);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  int opt;
  char *confStr = "/etc/inted.conf";
  while ((opt = getopt(argc, argv, ":c:")) != -1) {
    switch (opt) {
    case 'c':
      confStr = optarg;
      break;
    case ':':
      usageError(argv[0], "Missing argument", optopt);
    case '?':
      usageError(argv[0], "Unrecognized option", optopt);
    default:
      printf("Unexpected case in switch()\n");
      exit(EXIT_FAILURE);
    }
  }

  signal(SIGCHLD, sigChldHandler);

  int nfds = 0;
  FD_ZERO(&readfds);

  /* daemon(0, 0); */

  FILE *cf = fopen(confStr, "r");
  if (cf == NULL) {
    /* syslog(LOG_PERROR, "Cannot open configuration file"); */
    printf("Cannot open configuration file\n");
    exit(EXIT_FAILURE);
  }

  while (fgets(buf, MAX_LINE, cf) != NULL) {
    if (buf[0] == '#') continue;

    char **line = parseLine(buf);
    struct service *service = getService(line);
    openSocket(service);

    nfds = service -> fd + 1;
    FD_SET(service -> fd, &readfds);
  }

  for (;;) {
    select(nfds, &readfds, NULL, NULL, 0);
    for (int fd = 0; fd < nfds; fd++) {
      if (FD_ISSET(fd, &readfds)) {
        struct service *service = findServiceFromFd(fd);

        if (service -> type == SOCK_STREAM) {
          int cfd;
          if (service -> wait) {
            FD_CLR(fd, &readfds);
          } else {
            cfd = accept(fd, NULL, NULL);
            if (cfd == -1) {
              perror("accept");
              exit(EXIT_FAILURE);
            }
          }
          pid_t pid = fork();
          if (pid < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
          } else if (pid == 0) {
            setUGId(service);
            if (service -> wait) {
              setupFd(nfds, fd);
              service -> pid = getpid();
            } else {
              setupFd(nfds, cfd);
            }
            execv(service -> line[5], service -> line + 5);
          }
          if (!service -> wait) {
            close(cfd);
          }

        } else {
          if (service -> wait) {
            FD_CLR(fd, &readfds);
          }
          int pid = fork();
          if (pid < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
          } else if (pid == 0) {
            setUGId(service);
            if (service -> wait) {
              setupFd(nfds, fd);
              service -> pid = getpid();
            }
            execv(service -> line[5], service -> line + 5);
          }
        }
      }
    }
  }

  return 0;
}
