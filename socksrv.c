/* Copyright (C) 2024 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>

#include <ps5/kernel.h>

#include "elfldr.h"
#include "log.h"
#include "notify.h"
#include "selfldr.h"
#include "uri.h"


/**
 * Magic number that socket input starts with (little endian).
 **/
#define PAYLOAD_MAGIC_ELF      0x464C457F // ELF payload
#define PAYLOAD_MAGIC_URI_FILE 0x656C6966 // file:// URI
#define PAYLOAD_MAGIC_URI_HTTP 0x70747468 // http:// or https:// URI
#define PAYLOAD_MAGIC_PS4_SELF 0x1D3D154F // PS4 SELF payload
#define PAYLOAD_MAGIC_PS5_SELF 0xEEF51454 // PS5 SELF payload
#define PAYLOAD_MAGIC_HTTP_GET 0x20544547 // HTTP GET request
#define PAYLOAD_MAGIC_TRACK    0x43415254 // tracked launch request


/**
 * A tracked launch request starts with TRACK_MAGIC, followed by the length of
 * the payload input (32 bits, big endian), the input itself, and the payload.
 * The payload gets the input on stdin instead of the client socket, and the
 * client gets TRACK_REPLY ("TPID") followed by the pid (both 32 bits, big
 * endian). A payload that is given input confirms that it has consumed it by
 * writing TRACK_READY to stdout within TRACK_TIMEOUT seconds.
 **/
#define TRACK_MAGIC   "TRACKED"
#define TRACK_REPLY   0x54504944
#define TRACK_READY   "PAYLOAD_READY\n"
#define TRACK_TIMEOUT 15


/**
 * Decode an escaped argument.
 **/
static char*
args_decode(const char* s) {
  size_t length = strlen(s);
  char *arg = malloc(length+1);
  size_t off = 0;
  int escape = 0;

  for(size_t i=0; i<length; i++) {
    if(s[i] == '\\' && !escape) {
      escape = 1;
    } else {
      arg[off++] = s[i];
      escape = 0;
    }
  }

  arg[off] = 0;
  return arg;
}


/**
 *
 **/
static int
args_split(const char* args, char** argv, size_t size) {
  char* buf = strdup(args);
  size_t len = strlen(buf);
  int escape = 0;
  int argc = 0;

  memset(argv, 0, size*sizeof(char*));
  for(int i=0; i<len && argc<size; i++) {
    if(escape) {
      escape = 0;
      continue;
    }

    if(buf[i] == '\\') {
      escape = 1;
      continue;
    }

    if(buf[i] == ' ') {
      buf[i] = 0;
      continue;
    }

    if(buf[i] && !i) {
      argv[argc++] = buf+i;
      continue;
    }

    if(buf[i] && !buf[i-1]) {
      argv[argc++] = buf+i;
    }
  }

  for(int i=0; i<argc; i++) {
    argv[i] = args_decode(argv[i]);
  }

  free(buf);

  return argc;
}


/**
 * Spawn an ELF or a SELF payload.
 **/
static pid_t
payload_spawn(char* filename, char* args, int fd,
	      uint8_t* payload, size_t payload_size) {
  int magic = *((int*)payload);
  char* argv[255+2] = {0};
  pid_t pid = -1;

  argv[0] = filename;
  args_split(args, argv+1, 255);

  if(magic == PAYLOAD_MAGIC_ELF) {
    pid = elfldr_spawn(fd, argv, payload, payload_size);

  } else if(magic == PAYLOAD_MAGIC_PS4_SELF || magic == PAYLOAD_MAGIC_PS5_SELF) {
    pid = selfldr_spawn(fd, argv, payload, payload_size);
  }

  for(int i=1; argv[i]; i++) {
    free(argv[i]);
  }

  return pid;
}


/**
 * Read the header of a tracked launch request.
 **/
static int
track_read(int fd, char* input, size_t size, uint32_t* input_len) {
  char magic[sizeof(TRACK_MAGIC)-1];
  uint32_t len;

  if(recv(fd, magic, sizeof(magic), MSG_WAITALL) != sizeof(magic) ||
     memcmp(magic, TRACK_MAGIC, sizeof(magic))) {
    return -1;
  }

  if(recv(fd, &len, sizeof(len), MSG_WAITALL) != sizeof(len)) {
    return -1;
  }

  len = ntohl(len);
  if(len >= size) {
    return -1;
  }

  if(len && recv(fd, input, len, MSG_WAITALL) != len) {
    return -1;
  }

  *input_len = len;

  return 0;
}


/**
 * Spawn a payload that is detached from the client socket, and tell the
 * client which pid it got.
 **/
static void
track_spawn(char* filename, char* args, int fd, uint8_t* payload,
	    size_t payload_size, const char* input, uint32_t input_len) {
  struct timeval timeout = {TRACK_TIMEOUT, 0};
  char ready[sizeof(TRACK_READY)-1];
  int pair[2] = {-1, -1};
  uint32_t reply[2];
  pid_t pid = -1;
  size_t off = 0;
  int io = -1;
  ssize_t n;

  // Keep payload stdout separate from the launch acknowledgement.
  if(!input_len) {
    io = open("/dev/null", O_RDWR);
  } else if(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) {
    setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if(write(pair[0], input, input_len) == input_len) {
      io = pair[1];
    }
    shutdown(pair[0], SHUT_WR);
  }

  if(io >= 0) {
    pid = payload_spawn(filename, args, io, payload, payload_size);
  }

  // Payloads that are given input confirm that they consumed it.
  if(pid > 0 && input_len) {
    if(recv(pair[0], ready, sizeof(ready), MSG_WAITALL) != sizeof(ready) ||
       memcmp(ready, TRACK_READY, sizeof(ready))) {
      kill(pid, SIGKILL);
      pid = -1;
    }
  }

  if(pair[0] >= 0) {
    close(pair[0]);
  }
  if(pair[1] >= 0) {
    close(pair[1]);
  }
  if(!input_len && io >= 0) {
    close(io);
  }

  reply[0] = htonl(TRACK_REPLY);
  reply[1] = htonl(pid);
  while(off < sizeof(reply)) {
    if((n=send(fd, (char*)reply + off, sizeof(reply) - off, 0)) <= 0) {
      break;
    }
    off += n;
  }
}


/**
 *
 **/
static int
payload_readuri(int fd, char* uri, size_t size) {
  char c;
  int n;

  for(int i=0; i<size; i++) {
    if((n=read(fd, &c, 1)) < 0) {
      return -1;
    }
    if(n == 0) {
      uri[i] = 0;
      return 0;
    }
    if(c == '\r') {
      continue;
    }
    if(c == '\n') {
      uri[i] = 0;
      return 0;
    }

    uri[i] = c;
  }

  return -1;
}



/**
 * Read a HTTP (GET) request.
 **/
static int
payload_readhttp(int fd, char* uri, size_t size) {
  const char *headers = ("HTTP/1.1 200 OK\r\n"
			 "Content-Type: text/plain; charset=utf-8\r\n"
			 "Access-Control-Allow-Origin: *\r\n"
			 "Connection: close\r\n"
			 "\r\n");
  char buf[PATH_MAX+255] = {0};
  char* param_uri;
  ssize_t n;
  char* p;

  if((n=read(fd, buf, sizeof(buf)-1)) < 0) {
    return -1;
  }

  if(memcmp(buf, "GET ", 4)) {
    return -1;
  }

  if(!(p=strchr(buf+4, ' '))) {
    return -1;
  }

  if(strstr(buf, "user-agent: rnps-action-cards")) {
    return -1;
  }

  *p = 0;

  if((param_uri=uri_get_param(buf+4, "uri"))) {
    strncpy(uri, param_uri, size);
    free(param_uri);
  } else {
    snprintf(uri, size, "file:/%s", buf+4);
  }

  write(fd, headers, strlen(headers));

  return 0;
}


/**
 * Process connection input.
 **/
static void
on_connection(int fd) {
  char* filename = "payload.elf";
  char uri[PATH_MAX+1] = {0};
  uint32_t input_len = 0;
  uint8_t* buf = 0;
  char input[192];
  size_t len = 0;
  int optval = 1;
  char* args = "";
  char* pipe = "";
  int tracked = 0;
  int client = fd;
  int magic = 0;

  if(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval)) < 0) {
    LOG_PERROR("setsockopt");
    return;
  }

  if(recv(fd, &magic, sizeof(magic), MSG_PEEK | MSG_WAITALL) != sizeof(magic)) {
    LOG_PERROR("recv");
    write(fd, "[elfldr.elf] Unknown payload format\n\r\0", 38);
    return;
  }

  if(magic == PAYLOAD_MAGIC_TRACK) {
    if(track_read(fd, input, sizeof(input), &input_len) ||
       recv(fd, &magic, sizeof(magic), MSG_PEEK | MSG_WAITALL) != sizeof(magic)) {
      LOG_PERROR("track_read");
      return;
    }
    tracked = 1;
  }

  if(magic == PAYLOAD_MAGIC_URI_FILE || magic == PAYLOAD_MAGIC_URI_HTTP) {
    if(payload_readuri(fd, uri, PATH_MAX) || uri_get_content(uri, &buf, &len)) {
      LOG_PERROR("payload_readuri");
      write(fd, "[elfldr.elf] Error reading URI payload\n\r\0", 41);
    }

  } else if(magic == PAYLOAD_MAGIC_HTTP_GET) {
    if(payload_readhttp(fd, uri, PATH_MAX) || uri_get_content(uri, &buf, &len)) {
      LOG_PERROR("payload_readhttp");
      write(fd, "[elfldr.elf] Error reading HTTP payload\n\r\0", 42);
    }

  } else if(magic == PAYLOAD_MAGIC_ELF) {
    if(elfldr_read(fd, &buf, &len)) {
      LOG_PERROR("elfldr_read");
      write(fd, "[elfldr.elf] Error reading ELF payload\n\r\0", 41);
    }

  } else if(magic == PAYLOAD_MAGIC_PS4_SELF || magic == PAYLOAD_MAGIC_PS5_SELF) {
    if(selfldr_read(fd, &buf, &len)) {
      LOG_PERROR("selfldr_read");
      write(fd, "[elfldr.elf] Error reading SELF payload\n\r\0", 42);
    }
  } else {
    write(fd, "[elfldr.elf] Unknown payload format\n\r\0", 38);
  }

  if(buf) {
    if(!(filename=uri_get_filename(uri))) {
      filename = strdup("payload.elf");
    }
    if(!(args=uri_get_param(uri, "args"))) {
      args = strdup("");
    }
    if(!(pipe=uri_get_param(uri, "pipe"))) {
      pipe = strdup("1");
    }

    if(!strcmp(pipe, "0") ||
       !strcasecmp(pipe, "false") ||
       !strcasecmp(pipe, "no")) {
      fd = -1;
    }

    if(tracked) {
      track_spawn(filename, args, client, buf, len, input, input_len);
    } else if(payload_spawn(filename, args, fd, buf, len) < 0) {
      write(fd, "[elfldr.elf] Error spawning payload\n\r\0", 38);
    }
    free(filename);
    free(pipe);
    free(args);
    free(buf);
  }
}


/**
 * Serve ELF loader via a socket.
 **/
static int
serve_elfldr(uint16_t port) {
  struct sockaddr_in srvaddr;
  struct sockaddr_in cliaddr;
  socklen_t socklen;
  int connfd;
  int srvfd;

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    LOG_PERROR("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    LOG_PERROR("setsockopt");
    return -1;
  }

  memset(&srvaddr, 0, sizeof(srvaddr));
  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  srvaddr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) != 0) {
    LOG_PERROR("bind");
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    LOG_PERROR("listen");
    return -1;
  }

  while(1) {
    socklen = sizeof(cliaddr);
    if((connfd=accept(srvfd, (struct sockaddr*)&cliaddr, &socklen)) < 0) {
      LOG_PERROR("accept");
      break;
    }

    on_connection(connfd);
    close(connfd);
  }

  return close(srvfd);
}


static int
notify_address(const char* prefix, int port) {
  char ip[INET_ADDRSTRLEN] = "127.0.0.1";
  struct ifaddrs *ifaddr;

  if(getifaddrs(&ifaddr) == -1) {
    LOG_PERROR("getifaddrs");
    return -1;
  }

  // Enumerate all AF_INET IPs
  for(struct ifaddrs *ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next) {
    if(ifa->ifa_addr == NULL) {
      continue;
    }

    if(ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    // skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // skip interfaces without an ip
    if(!strncmp("0.", ip, 2)) {
      continue;
    }
  }

  freeifaddrs(ifaddr);

  notify("%s %s:%d", prefix, ip, port);
  LOG_PRINTF("%s %s:%d\n", prefix, ip, port);

  return 0;
}


/**
 *
 **/
int main() {
  int port = 9021;
  pid_t pid;

  LOG_PRINTF("Socket server was compiled at %s %s\n", __DATE__, __TIME__);

  if(chdir("/")) {
    LOG_PERROR("chdir");
    return -1;
  }

  syscall(SYS_setsid);
  while((pid=elfldr_find_pid("elfldr.elf")) > 0) {
    if(kill(pid, SIGKILL)) {
      LOG_PERROR("kill");
      _exit(-1);
    }
    sleep(1);
  }

  syscall(SYS_thr_set_name, -1, "elfldr.elf");
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  notify_address("Serving ELF loader on", port);
  while(1) {
    serve_elfldr(port);
    sleep(3);
  }

  return 0;
}
