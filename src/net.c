/* HTTPS GET for payloads on a jailbroken PS5, independent of the console's
 * DNS (which is usually pointed at a jailbreak DNS that can't resolve normal
 * sites): resolve names ourselves over UDP, connect by IP with a Host header,
 * follow redirects by hand.  Uses libSceHttp (v1). */
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "net.h"

int sceNetInit(void);
int sceNetPoolCreate(const char *, int, int);
int sceNetPoolDestroy(int);
int sceSslInit(size_t);
int sceSslTerm(int);
int sceHttpInit(int, int, size_t);
int sceHttpTerm(int);
int sceHttpCreateTemplate(int, const char *, int, int);
int sceHttpDeleteTemplate(int);
int sceHttpSetResponseHeaderMaxSize(int, size_t);
int sceHttpSetAutoRedirect(int, int);
int sceHttpsSetSslCallback(int, void *, void *);
int sceHttpCreateConnectionWithURL(int, const char *, int);
int sceHttpDeleteConnection(int);
int sceHttpSetConnectTimeOut(int, unsigned int);
int sceHttpSetResolveTimeOut(int, unsigned int);
int sceHttpSetSendTimeOut(int, unsigned int);
int sceHttpSetRecvTimeOut(int, unsigned int);
int sceHttpGetAllResponseHeaders(int, char **, size_t *);
int sceHttpCreateRequestWithURL(int, int, const char *, uint64_t);
int sceHttpAddRequestHeader(int, const char *, const char *, unsigned int);
int sceHttpSendRequest(int, const void *, size_t);
int sceHttpGetStatusCode(int, int *);
int sceHttpGetResponseContentLength(int, int *, uint64_t *);
int sceHttpReadData(int, void *, size_t);
int sceHttpDeleteRequest(int);
int sceHttpAbortRequest(int);

#define TIMEOUT_US (20u * 1000u * 1000u)
#define MAX_HOPS 6

char net_log[2048];
static void nlog(const char *fmt, ...) {
  size_t l = strlen(net_log);
  if (l + 8 >= sizeof(net_log))
    return;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(net_log + l, sizeof(net_log) - l, fmt, ap);
  va_end(ap);
}

/* The server certificate can't be checked against the name once we connect
 * by IP, so it is accepted here; downloads are checked by SHA-256 instead. */
static unsigned int last_verify_err;
static int ssl_cb(int ctx, unsigned int verify_err, void *const certs[], int n, void *arg) {
  last_verify_err = verify_err;
  return 0;
}

/* ---------- DNS over UDP ---------- */
static int dns_query(const char *server, const char *host, char *ip, size_t il) {
  uint8_t q[300], r[1500];
  uint16_t id = (uint16_t)(getpid() ^ (uintptr_t)host ^ (uint16_t)time(NULL));
  size_t n = 0;
  q[n++] = id >> 8; q[n++] = id & 0xff;
  q[n++] = 0x01; q[n++] = 0x00;              /* recursion desired */
  q[n++] = 0; q[n++] = 1;                    /* 1 question */
  memset(q + n, 0, 6); n += 6;
  const char *p = host;
  while (*p) {
    const char *dot = strchr(p, '.');
    size_t ll = dot ? (size_t)(dot - p) : strlen(p);
    if (ll == 0 || ll > 63 || n + ll + 6 > sizeof(q))
      return -1;
    q[n++] = (uint8_t)ll;
    memcpy(q + n, p, ll);
    n += ll;
    p += ll;
    if (*p == '.')
      p++;
  }
  q[n++] = 0;
  q[n++] = 0; q[n++] = 1;                    /* type A */
  q[n++] = 0; q[n++] = 1;                    /* class IN */

  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0)
    return -1;
  struct timeval tv = {3, 0};
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  struct sockaddr_in a = {0};
  a.sin_family = AF_INET;
  a.sin_port = htons(53);
  a.sin_addr.s_addr = inet_addr(server);
  int got = -1;
  for (int attempt = 0; attempt < 2 && got < 0; attempt++) {
    if (sendto(s, q, n, 0, (struct sockaddr *)&a, sizeof(a)) != (ssize_t)n)
      break;
    ssize_t k = recv(s, r, sizeof(r), 0);
    if (k < 12 || r[0] != q[0] || r[1] != q[1] || (r[3] & 0x0f))
      continue;
    size_t off = 12;
    int qd = r[4] << 8 | r[5], an = r[6] << 8 | r[7];
    for (int i = 0; i < qd; i++) {             /* skip questions */
      while (off < (size_t)k && r[off]) {
        if ((r[off] & 0xc0) == 0xc0) { off++; break; }
        off += r[off] + 1;
      }
      off += 5;
    }
    for (int i = 0; i < an && off + 10 < (size_t)k; i++) {
      if ((r[off] & 0xc0) == 0xc0)
        off += 2;
      else {
        while (off < (size_t)k && r[off])
          off += r[off] + 1;
        off++;
      }
      if (off + 10 > (size_t)k)
        break;
      int type = r[off] << 8 | r[off + 1];
      int rdlen = r[off + 8] << 8 | r[off + 9];
      off += 10;
      if (type == 1 && rdlen == 4 && off + 4 <= (size_t)k) {
        snprintf(ip, il, "%u.%u.%u.%u", r[off], r[off + 1], r[off + 2], r[off + 3]);
        got = 0;
        break;
      }
      off += rdlen;                              /* CNAME etc. */
    }
  }
  close(s);
  return got;
}

/* public DNS first (the console's DNS is often a jailbreak DNS), then the system resolver */
static int resolve(const char *host, char *ip, size_t il) {
  static const char *servers[] = {"1.1.1.1", "8.8.8.8", "9.9.9.9"};
  struct in_addr tmp;
  if (inet_pton(AF_INET, host, &tmp) == 1) {
    snprintf(ip, il, "%s", host);
    return 0;
  }
  for (int i = 0; i < 3; i++)
    if (dns_query(servers[i], host, ip, il) == 0) {
      nlog("dns %s -> %s (via %s)\n", host, ip, servers[i]);
      return 0;
    }
  struct addrinfo hints = {0}, *res = NULL;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
    inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, il);
    freeaddrinfo(res);
    nlog("dns %s -> %s (system resolver)\n", host, ip);
    return 0;
  }
  nlog("dns %s: FAILED (public DNS and system resolver)\n", host);
  return -1;
}

/* split "https://host:port/path" */
static int split_url(const char *url, char *scheme, size_t sl, char *host, size_t hl,
                     const char **rest) {
  const char *s = strstr(url, "://");
  if (!s)
    return -1;
  snprintf(scheme, sl, "%.*s", (int)(s - url), url);
  const char *h = s + 3, *e = h;
  while (*e && *e != '/' && *e != ':' && *e != '?')
    e++;
  if (e == h || (size_t)(e - h) >= hl)
    return -1;
  snprintf(host, hl, "%.*s", (int)(e - h), h);
  *rest = e;
  return 0;
}

static void set_timeouts(int id) {
  sceHttpSetResolveTimeOut(id, TIMEOUT_US);
  sceHttpSetConnectTimeOut(id, TIMEOUT_US);
  sceHttpSetSendTimeOut(id, TIMEOUT_US);
  sceHttpSetRecvTimeOut(id, TIMEOUT_US);
}

void hc_init(hc_t *h) {
  h->pool = h->ssl = h->http = h->tmpl = h->conn = h->req = -1;
}

static void close_req(hc_t *h) {
  if (h->req >= 0)
    sceHttpDeleteRequest(h->req);
  if (h->conn >= 0)
    sceHttpDeleteConnection(h->conn);
  h->req = h->conn = -1;
}

void hc_close(hc_t *h) {
  close_req(h);
  if (h->tmpl >= 0)
    sceHttpDeleteTemplate(h->tmpl);
  if (h->http >= 0)
    sceHttpTerm(h->http);
  if (h->ssl >= 0)
    sceSslTerm(h->ssl);
  if (h->pool >= 0)
    sceNetPoolDestroy(h->pool);
  hc_init(h);
}

/* one request; by_ip: connect to the resolved IP and send Host */
static int send_one(hc_t *h, const char *url, int by_ip, uint64_t from, int *status,
                    char *err, size_t el) {
  char scheme[8], host[256], ip[64], u2[1400];
  const char *rest;
  const char *use = url;
  if (split_url(url, scheme, sizeof(scheme), host, sizeof(host), &rest)) {
    snprintf(err, el, "bad link");
    return -1;
  }
  if (by_ip) {
    if (resolve(host, ip, sizeof(ip)))
      return -1;
    snprintf(u2, sizeof(u2), "%s://%s%s", scheme, ip, rest);
    use = u2;
  }
  h->conn = sceHttpCreateConnectionWithURL(h->tmpl, use, 0);
  if (h->conn < 0) {
    nlog("connection %s: 0x%08x\n", by_ip ? "by IP" : "by name", (unsigned)h->conn);
    snprintf(err, el, "couldn't connect (0x%08x)", (unsigned)h->conn);
    return -1;
  }
  set_timeouts(h->conn);
  h->req = sceHttpCreateRequestWithURL(h->conn, 0 /* GET */, use, 0);
  if (h->req < 0) {
    snprintf(err, el, "bad request (0x%08x)", (unsigned)h->req);
    return -1;
  }
  set_timeouts(h->req);
  if (by_ip)
    sceHttpAddRequestHeader(h->req, "Host", host, 0);
  if (from) {
    char range[48];
    snprintf(range, sizeof(range), "bytes=%llu-", (unsigned long long)from);
    sceHttpAddRequestHeader(h->req, "Range", range, 0);
  }
  last_verify_err = 0;
  int rc = sceHttpSendRequest(h->req, NULL, 0);
  if (rc != 0) {
    nlog("send %s %s: 0x%08x\n", by_ip ? "by IP" : "by name", host, (unsigned)rc);
    snprintf(err, el, "couldn't connect to %s (0x%08x)", host, (unsigned)rc);
    return -1;
  }
  *status = 0;
  sceHttpGetStatusCode(h->req, status);
  nlog("GET %s%s -> HTTP %d%s\n", host, by_ip ? " (by IP)" : "", *status,
       last_verify_err ? " (cert not verified)" : "");
  return 0;
}

static int location(int req, const char *base, char *out, size_t ol) {
  char *hd = NULL;
  size_t hl = 0;
  if (sceHttpGetAllResponseHeaders(req, &hd, &hl) != 0 || !hd)
    return -1;
  const char *end = hd + hl;
  for (const char *l = hd; l < end;) {
    const char *eol = memchr(l, '\n', (size_t)(end - l));
    size_t n = eol ? (size_t)(eol - l) : (size_t)(end - l);
    while (n && (l[n - 1] == '\r' || l[n - 1] == ' '))
      n--;
    if (n > 9 && strncasecmp(l, "location:", 9) == 0) {
      const char *v = l + 9;
      size_t vn = n - 9;
      while (vn && (*v == ' ' || *v == '\t')) {
        v++;
        vn--;
      }
      if (!vn || vn >= ol)
        return -1;
      if (v[0] != '/') {
        snprintf(out, ol, "%.*s", (int)vn, v);
        return 0;
      }
      const char *se = strstr(base, "://");
      if (!se)
        return -1;
      const char *he = se + 3;
      while (*he && *he != '/')
        he++;
      snprintf(out, ol, "%.*s%.*s", (int)(he - base), base, (int)vn, v);
      return 0;
    }
    if (!eol)
      break;
    l = eol + 1;
  }
  return -1;
}

int hc_get(hc_t *h, const char *url, uint64_t from, int *status, uint64_t *len,
           int *len_known, char *err, size_t el) {
  int rc;
  err[0] = 0;
  *len = 0;
  *len_known = 0;
  sceNetInit();
  if ((h->pool = sceNetPoolCreate("linuxflasher", 512 * 1024, 0)) < 0) {
    snprintf(err, el, "network setup failed (0x%08x)", (unsigned)h->pool);
    return -1;
  }
  if ((h->ssl = sceSslInit(384 * 1024)) < 0) {
    snprintf(err, el, "SSL setup failed (0x%08x)", (unsigned)h->ssl);
    return -1;
  }
  if ((h->http = sceHttpInit(h->pool, h->ssl, 256 * 1024)) < 0) {
    snprintf(err, el, "HTTP setup failed (0x%08x)", (unsigned)h->http);
    return -1;
  }
  if ((h->tmpl = sceHttpCreateTemplate(h->http, "LinuxFlasher/1.4 (PS5)", 2, 1)) < 0) {
    snprintf(err, el, "HTTP setup failed (0x%08x)", (unsigned)h->tmpl);
    return -1;
  }
  sceHttpSetResponseHeaderMaxSize(h->tmpl, 0x4000);
  sceHttpSetAutoRedirect(h->tmpl, 0); /* redirects are resolved by us */
  set_timeouts(h->tmpl);
  if ((rc = sceHttpsSetSslCallback(h->tmpl, (void *)ssl_cb, NULL)) != 0)
    nlog("ssl callback: 0x%08x\n", (unsigned)rc);

  char cur[1400];
  snprintf(cur, sizeof(cur), "%s", url);
  for (int hop = 0; hop < MAX_HOPS; hop++) {
    if (strncmp(cur, "https://", 8) && strncmp(cur, "http://", 7)) {
      snprintf(err, el, "unsupported link");
      return -1;
    }
    /* by IP first (bypasses the console DNS), by name as the fallback:
     * some CDNs refuse a connection without the name (SNI) */
    if (send_one(h, cur, 1, from, status, err, el) != 0) {
      close_req(h);
      if (send_one(h, cur, 0, from, status, err, el) != 0)
        return -1;
    }
    if (*status >= 300 && *status < 400) {
      char next[1400];
      if (location(h->req, cur, next, sizeof(next)) == 0) {
        snprintf(cur, sizeof(cur), "%s", next);
        close_req(h);
        continue;
      }
    }
    int t = -1;
    *len_known = sceHttpGetResponseContentLength(h->req, &t, len) == 0 && t == 0;
    return 0;
  }
  snprintf(err, el, "too many redirects");
  return -1;
}

int hc_read(hc_t *h, void *buf, size_t n) { return sceHttpReadData(h->req, buf, n); }

void hc_abort(hc_t *h) {
  if (h->req >= 0)
    sceHttpAbortRequest(h->req);
}
