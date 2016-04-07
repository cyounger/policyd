#include <arpa/inet.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uv.h>

// What a socket policy request should look like
const char *request = "<policy-file-request/>\0";
const size_t request_len = 23;

// Will contain the policy file contents when read
char *policy = NULL;
size_t policy_len = 0;

uv_loop_t *loop;

void usage(void)
{
  printf("Usage: policyd [options]\n\n"
         "A flash socket policy server using libuv\n\n"
         "Options:\n"
         "  -l IP, --listen=IP       The IP to listen on; defaults to "
         "0.0.0.0\n"
         "  -p PORT, --port=PORT     The port to listen on; defaults to 843\n"
         "  -c FILE, --config=FILE   The socket policy configuration file\n"
         );
}

/**
 * Show a message, including the client IP
 */
void message(uv_tcp_t *handle, const char *fmt, ...)
{
  va_list lst;
  va_start(lst, fmt);
  if (handle != NULL) {
    struct sockaddr_in addr;
    int len = sizeof(addr);
    uv_tcp_getsockname(handle, (struct sockaddr *)&addr, &len);
    char name[INET_ADDRSTRLEN] = { 0 };
    uv_ip4_name(&addr, name, sizeof(name));
    fprintf(stderr, "[%s] ", name);
  }
  vfprintf(stderr, fmt, lst);
  va_end(lst);
  fprintf(stderr, "\n");
}

#ifdef DEBUG
#define debug(client, ...) message((uv_tcp_t *) (client), __VA_ARGS__);
#else
#define debug(...)
#endif
#define warn(client, ...) message((uv_tcp_t *) (client), __VA_ARGS__);

/**
 * Allocate a buffer for reading a socket policy request.
 */
void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
  // Policy requests are very small and should be discarded if they're
  // too big. So allocate a smallish buffeer.
  const size_t len = 64;
  buf->base = malloc(len); // freed at end of request_read
  buf->len = len;
}

/**
 * Read the contents of the socket policy file, and allocate a buffer
 * for it. The caller is responsible for freeing the policy buffer if
 * *policy has changed.
 */
int read_policy(const char *filename, char **buffer)
{
  struct stat ss;
  if (stat(filename, &ss) == -1) {
    perror("stat");
    return -1;
  }

  int fd;
  if ((fd = open(filename, O_RDONLY)) == -1) {
    perror("open");
    return -1;
  }

  int size = ss.st_size + 1;
  *buffer = malloc(size); // freed in main when done
  memset(*buffer, 0, size);
  if (read(fd, *buffer, size-1) == -1) {
    perror("read");
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}

/**
 * Change to an unprivileged user.
 */
int drop_privileges(void)
{
  struct passwd *pw = getpwnam("nobody");
  if (!pw) {
    perror("getpwnam");
    return -1;
  }
  if (setgid(pw->pw_gid) == -1) {
    perror("setgid");
    return -1;
  }
  if (setuid(pw->pw_uid) == -1) {
    perror("setuid");
    return -1;
  }
  if (chdir("/") == -1) {
    perror("chdir");
    return -1;
  }
  if (getuid() == 0) {
    return -1;
  }

  return 0;
}

/**
 * Callback for after the reply has been written.
 */
void reply_written(uv_write_t *req, int status)
{
  if (status) {
    warn(NULL, "write error: %s", uv_strerror(status));
  }
  debug(req->handle, "write complete");
  free(req);
}

/**
 * Callback for when the socket policy request is being
 * requested. This may be called multiple times.
 */
void request_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
  if (nread < 0) {
    if (nread != UV_EOF) {
      warn(client, "read error: %s", uv_err_name(nread));
    }
    debug(client, "closing");
    uv_close((uv_handle_t *) client, (uv_close_cb) free);
  } else if (nread > 0) {
    debug(client, "read %d bytes", nread);
    // Use the context storage to keep track of the number of bytes
    // matching the expected socket policy request string so far.
    size_t sofar = (size_t) client->data;
    if (sofar + nread > request_len ||
        memcmp(request + sofar, buf->base, nread) != 0) {
      // The request is invalid or too long; ignore them
      debug(client, "invalid request; closing");
      uv_close((uv_handle_t *) client, (uv_close_cb) free);
    } else {
      client->data += nread;
      if ((size_t) client->data == request_len) {
        debug(client, "valid request; writing reply");
        uv_write_t *req = malloc(sizeof(uv_write_t)); // freed in reply_written
        uv_buf_t wrbuf = uv_buf_init(policy, policy_len);
        uv_write(req, client, &wrbuf, 1, reply_written);
      }
    }
  }

  if (buf->base) {
    free(buf->base);
  }
}

/**
 * Callback for when a new client is connecting.
 */
void new_connection(uv_stream_t *server, int status)
{
  if (status) {
    warn(NULL, "connection error: %s", uv_strerror(status));
    return;
  }

  uv_tcp_t *client = malloc(sizeof(uv_tcp_t)); // freed when closed
  uv_tcp_init(loop, client);
  client->data = 0;
  if (uv_accept(server, (uv_stream_t *) client) == 0) {
    uv_read_start((uv_stream_t *) client, alloc_buffer, request_read);
    debug(client, "new connection");
  }
  else {
    warn(NULL, "accept error");
    uv_close((uv_handle_t *) client, (uv_close_cb) free);
  }
}

int init(const char *address, const uint16_t port, const char *filename)
{
  uv_tcp_t server;
  int r, ret = -1;

  // Read the socket policy that will be sent in response to any
  // requests
  if (read_policy(filename, &policy) == -1) {
    warn(NULL, "failed to read policy file");
    goto cleanup;
  }
  policy_len = strlen(policy);

  loop = uv_default_loop();
  uv_tcp_init(loop, &server);

  struct sockaddr_in addr;
  uv_ip4_addr(address, port, &addr);
  if ((r = uv_tcp_bind(&server, (const struct sockaddr *)&addr, 0))) {
    warn(NULL, "failed to bind: %s", uv_strerror(r));
    goto cleanup;
  }

  debug(NULL, "listening on %s:%d", address, port);

  if (getuid() == 0) {
    if (drop_privileges() == -1) {
      warn(NULL, "failed to drop privileges");
      goto cleanup;
    }
  }

  // Listen for new connections with a backlog length of 128
  if ((r = uv_listen((uv_stream_t *) &server, 128, new_connection))) {
    warn(NULL, "listen error: %s", uv_strerror(r));
    goto cleanup;
  }

  uv_run(loop, UV_RUN_DEFAULT);
  uv_close((uv_handle_t *) &server, NULL);

  ret = 0;

 cleanup:
  uv_loop_delete(loop);
  if (policy != NULL) {
    free(policy);
  }
  return ret;
}

int main(int argc, char **argv)
{
  char address[INET_ADDRSTRLEN] = { 0 };
  uint16_t port = 843;
  char filename[1024] = { 0 };

  const struct option longopts[] = {
    { "listen", required_argument, 0, 'l' },
    { "port",   required_argument, 0, 'p' },
    { "config", required_argument, 0, 'c' },
  };

  int c;
  while ((c = getopt_long(argc, argv, "l:p:c:", longopts, NULL)) != -1) {
    switch (c) {
    case 'l':
      strncpy(address, optarg, sizeof(address));
      break;
    case 'p':
      port = atoi(optarg);
      break;
    case 'c':
      strncpy(filename, optarg, sizeof(filename));
      break;
    default:
      usage();
      exit(EXIT_FAILURE);
    }
  }

  if (address[0] == '\0') {
    strncpy(address, "0.0.0.0", sizeof(address));
  }

  if (filename[0] == '\0') {
    usage();
    exit(EXIT_FAILURE);
  }

  return init(address, port, filename);
}
