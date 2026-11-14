/* lite.h - a tiny Flask-like web framework for C.
 * Single header. Include it in ONE .c file. Needs gcc or clang.
 * Build: gcc -Wall -o app app.c
 */
#ifndef LITE_H
#define LITE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LITE_MAX_PARAMS  32
#define LITE_MAX_REQUEST (8 * 1024 * 1024)
#ifndef LITE_MAX_HEADER
#define LITE_MAX_HEADER 16384u
#endif
#ifndef LITE_MAX_HEADER_COUNT
#define LITE_MAX_HEADER_COUNT 100u
#endif

/* ---------- types ---------- */

typedef enum { LITE_GET, LITE_POST } Method;

typedef struct {
    char *k[LITE_MAX_PARAMS];
    char *v[LITE_MAX_PARAMS];
    int n;
} PList;

typedef struct {
    Method method;
    char path[1024];
    PList query, form, params, cookies;
    const unsigned char *body;
    size_t body_len;
    char content_type[256];
    char csrf_header[128]; /* X-Lite-CSRF-Token for fetch/AJAX */
    char range_header[128]; /* HTTP byte range for media seeking */
    char client_ip[INET_ADDRSTRLEN];
} Request;

typedef struct {
    int status;
    char type[64];
    char location[512];
    char **cookies;
    size_t ncookies;
    size_t cookie_capacity;
    int cookie_error;
    char *body;
    size_t len;
    int file_fd;
    off_t file_offset;
    off_t file_length;
    off_t file_total;
    int range_invalid;
} Response;

/* A handler returns the HTTP status (0 = 200). text/html/render/redirect return it for you. */
typedef int (*Handler)(void);
typedef struct { Method method; const char *pattern; Handler fn; } Route;

static Route *lite_routes = NULL;
static size_t lite_nroutes = 0;
static size_t lite_route_capacity = 0;
static int lite_route_error = 0;

typedef struct {
    char path[1024];
    unsigned int max_requests;
    unsigned int window_seconds;
} LiteRateLimitRule;

typedef struct {
    char path[1024];
    char client_ip[INET_ADDRSTRLEN];
    time_t window_start;
    unsigned int requests;
} LiteRateLimitBucket;

static LiteRateLimitRule *lite_rate_rules = NULL;
static size_t lite_rate_rule_count = 0;
static size_t lite_rate_rule_capacity = 0;
static LiteRateLimitBucket *lite_rate_buckets = NULL;
static size_t lite_rate_bucket_count = 0;
static size_t lite_rate_bucket_capacity = 0;
static int lite_rate_error = 0;
static Request  *lite_req = NULL;   /* the request being handled */
static Response *lite_res = NULL;   /* the response being built  */
static char lite_file_name[256], lite_file_type[128], lite_file_ext[32];
static size_t lite_file_size = 0;

static inline const char *upload_name(void) { return lite_file_name; }
static inline const char *upload_type(void) { return lite_file_type; }
static inline const char *upload_ext(void)  { return lite_file_ext; }
static inline size_t upload_size(void)      { return lite_file_size; }

/* ---------- param lists ---------- */

static inline void plist_add(PList *l, char *k, char *v) {
    if (!l || !k || !v || l->n < 0 || l->n >= LITE_MAX_PARAMS) {
        free(k); free(v); return;
    }
    l->k[l->n] = k;
    l->v[l->n] = v;
    l->n++;
}

static inline const char *plist_get(PList *l, const char *k) {
    if (!l || !k) return "";
    for (int i = 0; i < l->n && i < LITE_MAX_PARAMS; i++)
        if (l->k[i] && !strcmp(l->k[i], k)) return l->v[i] ? l->v[i] : "";
    return "";
}

static inline void plist_free(PList *l) {
    if (!l) return;
    int n = l->n;
    if (n < 0) n = 0;
    if (n > LITE_MAX_PARAMS) n = LITE_MAX_PARAMS;
    for (int i = 0; i < n; i++) { free(l->k[i]); free(l->v[i]); l->k[i] = l->v[i] = NULL; }
    l->n = 0;
}

/* ---------- request helpers (use these in routes) ---------- */

/* Read by name OR by position (0 = first one):
 *   form("name")     form(0)     POSTed form field
 *   query("q")       query(0)    value from ?q=...
 *   param("name")    param(0)    value from /user/<name>
 *   cookie("theme")  cookie(0)   cookie sent by the browser
 * Missing or out of range gives "".  form_count() / query_count() tell you how many there are. */
static inline const char *plist_by_name(PList *l, const char *k) { return plist_get(l, k); }
static inline const char *plist_by_index(PList *l, long long i) { return (l && i >= 0 && i < l->n) ? (l->v[i] ? l->v[i] : "") : ""; }

#define LITE_PICK(list, k) _Generic((k),                                      \
    char *: plist_by_name, const char *: plist_by_name,                       \
    short: plist_by_index, int: plist_by_index, long: plist_by_index,         \
    long long: plist_by_index, unsigned int: plist_by_index,                  \
    unsigned long: plist_by_index)((list), (k))

/* Same four readers, with a scanf-style second argument (see "scanf-style reads" below):
 *   form("name")                 -> text, "" if missing
 *   form("age", &age)            -> fills age, returns 1 on success, 0 if missing/invalid
 *   form("name", buf)            -> char buf[64]: copies the text, always NUL-terminated
 *   form("name", ptr, size)      -> same for a char* when you give the buffer size */
#define LITE_RD1(list, k)        LITE_PICK(list, k)
#define LITE_RD2(list, k, p)     LITE_SCAN(LITE_PICK(list, k), p)
#define LITE_RD3(list, k, p, n)  lite_scan_str(LITE_PICK(list, k), (char *)(p), (size_t)(n))
#define LITE_RD_PICK(_1, _2, _3, NAME, ...) NAME
#define LITE_READ(list, ...) \
    LITE_RD_PICK(__VA_ARGS__, LITE_RD3, LITE_RD2, LITE_RD1, 0)(list, __VA_ARGS__)

#define form(...)   LITE_READ(&lite_req->form, __VA_ARGS__)
#define query(...)  LITE_READ(&lite_req->query, __VA_ARGS__)
#define param(...)  LITE_READ(&lite_req->params, __VA_ARGS__)
#define cookie(...) LITE_READ(&lite_req->cookies, __VA_ARGS__)
#define form_count()  (lite_req->form.n)
#define query_count() (lite_req->query.n)


/* ---------- file uploads ---------- */

/* Save one multipart file field. Returns 1 on success, 0 on failure.
 * The public macro lets applications pass an ordinary int variable. */
static inline int lite_upload_save(const char *field, int *status, const char *dir) {
    if (status) *status = 0;
    lite_file_name[0] = lite_file_type[0] = lite_file_ext[0] = 0;
    lite_file_size = 0;
    if (!lite_req || !lite_req->body || !field || !dir || !*dir) return 0;

    const char *ct = lite_req->content_type;
    const char *bp = strcasestr(ct, "boundary=");
    if (!bp) return 0;
    bp += 9;
    char boundary[200];
    size_t bn = 0;
    if (*bp == '"') {
        bp++;
        while (bp[bn] && bp[bn] != '"' && bn < sizeof boundary - 1) bn++;
    } else {
        while (bp[bn] && bp[bn] != ';' && bp[bn] != ' ' &&
               bp[bn] != '\r' && bp[bn] != '\n' && bn < sizeof boundary - 1) bn++;
    }
    if (!bn || bn >= sizeof boundary - 1) return 0;
    memcpy(boundary, bp, bn);
    boundary[bn] = 0;

    char marker[210];
    snprintf(marker, sizeof marker, "--%s", boundary);
    size_t mn = strlen(marker);
    const unsigned char *p = lite_req->body;
    const unsigned char *end = p + lite_req->body_len;

    while ((size_t)(end - p) >= mn) {
        const unsigned char *m = (const unsigned char *)memmem(p, (size_t)(end - p), marker, mn);
        if (!m) break;
        p = m + mn;
        if ((size_t)(end - p) >= 2 && p[0] == '-' && p[1] == '-') break;
        if ((size_t)(end - p) >= 2 && p[0] == '\r' && p[1] == '\n') p += 2;

        const unsigned char *hend = (const unsigned char *)memmem(p, (size_t)(end - p), "\r\n\r\n", 4);
        if (!hend) break;
        size_t hlen = (size_t)(hend - p);
        char *headers = strndup((const char *)p, hlen);
        if (!headers) return 0;

        char *name = strcasestr(headers, "name=\"");
        char *filename = strcasestr(headers, "filename=\"");
        int had_filename = filename != NULL;
        char *part_type = strcasestr(headers, "Content-Type:");
        char mime[128] = "application/octet-stream";
        if (part_type) {
            part_type += 13;
            while (*part_type == ' ') part_type++;
            char *te = strstr(part_type, "\r\n");
            size_t tn = te ? (size_t)(te - part_type) : strlen(part_type);
            if (tn >= sizeof mime) tn = sizeof mime - 1;
            memcpy(mime, part_type, tn);
            mime[tn] = 0;
        }
        int match = 0;
        char *filecopy = NULL;
        if (name) {
            name += 6;
            char *q = strchr(name, '"');
            if (q) { *q = 0; match = !strcmp(name, field); }
        }
        if (match && filename) {
            filename += 10;
            char *q = strchr(filename, '"');
            if (q && q > filename) filecopy = strndup(filename, (size_t)(q - filename));
        }
        free(headers);
        if (match && had_filename && !filecopy) return 0;

        const unsigned char *data = hend + 4;
        char *next = NULL;
        /* Find the next delimiter without treating file bytes as a C string. */
        char delim[212];
        snprintf(delim, sizeof delim, "\r\n%s", marker);
        next = (char *)memmem(data, (size_t)(end - data), delim, strlen(delim));
        if (!next) { free(filecopy); break; }

        if (match && filecopy && *filecopy) {
            /* Keep only a safe basename; never accept client directory paths. */
            char *base = filecopy;
            for (char *q = filecopy; *q; q++)
                if (*q == '/' || *q == '\\') base = q + 1;
            char safe[256];
            size_t j = 0;
            for (const unsigned char *q = (const unsigned char *)base;
                 *q && j < sizeof safe - 1; q++) {
                if (isalnum(*q) || *q == '.' || *q == '_' || *q == '-') safe[j++] = (char)*q;
                else safe[j++] = '_';
            }
            safe[j] = 0;
            if (j && strcmp(safe, ".") && strcmp(safe, "..")) {
                size_t dl = strlen(dir);
                char path[1024];
                int n = snprintf(path, sizeof path, "%s%s%s", dir,
                                 (dl && dir[dl - 1] == '/') ? "" : "/", safe);
                if (n > 0 && (size_t)n < sizeof path) {
                    mkdir(dir, 0755);
                    FILE *f = fopen(path, "wb");
                    if (f) {
                        size_t bytes = (size_t)(next - (const char *)data);
                        int ok = fwrite(data, 1, bytes, f) == bytes;
                        if (fclose(f) != 0) ok = 0;
                        if (ok) {
                            size_t bytes = (size_t)(next - (const char *)data);
                            snprintf(lite_file_name, sizeof lite_file_name, "%s", safe);
                            snprintf(lite_file_type, sizeof lite_file_type, "%s", mime);
                            char *dot = strrchr(safe, '.');
                            if (dot && dot[1]) snprintf(lite_file_ext, sizeof lite_file_ext, "%s", dot + 1);
                            lite_file_size = bytes;
                            if (status) *status = 1;
                            free(filecopy);
                            return 1;
                        }
                        remove(path);
                    }
                }
            }
        }
        free(filecopy);
        p = (const unsigned char *)next + 2 + mn;
    }
    return 0;
}

#define upload_save(field, status, directory) \
    lite_upload_save((field), &(status), (directory))

/* to_int("42") -> 42    Safe text-to-number: gives 0 for empty, invalid or too-big text.
 * Use it on session("n"), query("page"), form("age"), ... */
static inline int to_int(const char *s) {
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (end == s || *end != 0 || errno == ERANGE || v > INT_MAX || v < INT_MIN) return 0;
    return (int)v;
}


/* ---------- scanf-style reads: form("age", &age) ----------
 *   int age = 18;  double price;  char name[64];  bool ok;
 *   if (form("age", &age)) ...          // 1 = got a valid number, 0 = missing or not a number
 *   form("price", &price);              // any C type: short int long long long, unsigned versions,
 *   form("name", name);                 //   float double, long double, bool, char buffers
 * The pointer's type decides how the text is read, just like scanf. On failure the variable
 * is left untouched, so give it a default first. Spaces around a number are ignored.
 * Also works with query(), param() and cookie(). */

static inline const char *lite_skip(const char *t) { while (isspace((unsigned char)*t)) t++; return t; }
static inline int lite_end_ok(const char *e) { return *lite_skip(e) == 0; }

#define LITE_DEF_SIGNED(name, type, lo, hi)                                   \
static inline int name(const char *t, type *out) {                            \
    char *e; errno = 0;                                                       \
    long long v = strtoll(t, &e, 10);                                         \
    if (e == t || !lite_end_ok(e) || errno == ERANGE || v < (lo) || v > (hi)) return 0; \
    *out = (type)v; return 1;                                                 \
}
#define LITE_DEF_UNSIGNED(name, type, hi)                                     \
static inline int name(const char *t, type *out) {                            \
    char *e; errno = 0;                                                       \
    const char *s = lite_skip(t);                                             \
    if (*s == '-') return 0;                    /* strtoull would wrap "-1" */\
    unsigned long long v = strtoull(s, &e, 10);                               \
    if (e == s || !lite_end_ok(e) || errno == ERANGE || v > (hi)) return 0;   \
    *out = (type)v; return 1;                                                 \
}
LITE_DEF_SIGNED(lite_scan_short, short, SHRT_MIN, SHRT_MAX)
LITE_DEF_SIGNED(lite_scan_int,   int,   INT_MIN,  INT_MAX)
LITE_DEF_SIGNED(lite_scan_long,  long,  LONG_MIN, LONG_MAX)
LITE_DEF_SIGNED(lite_scan_ll,    long long, LLONG_MIN, LLONG_MAX)
LITE_DEF_UNSIGNED(lite_scan_ushort, unsigned short, USHRT_MAX)
LITE_DEF_UNSIGNED(lite_scan_uint,   unsigned int,   UINT_MAX)
LITE_DEF_UNSIGNED(lite_scan_ulong,  unsigned long,  ULONG_MAX)
LITE_DEF_UNSIGNED(lite_scan_ull,    unsigned long long, ULLONG_MAX)

static inline int lite_scan_double(const char *t, double *out) {
    char *e; errno = 0;
    double v = strtod(t, &e);
    if (e == t || !lite_end_ok(e) || errno == ERANGE) return 0;
    *out = v; return 1;
}
static inline int lite_scan_float(const char *t, float *out) {
    char *e; errno = 0;
    float v = strtof(t, &e);
    if (e == t || !lite_end_ok(e) || errno == ERANGE) return 0;
    *out = v; return 1;
}
static inline int lite_scan_ldouble(const char *t, long double *out) {
    char *e; errno = 0;
    long double v = strtold(t, &e);
    if (e == t || !lite_end_ok(e) || errno == ERANGE) return 0;
    *out = v; return 1;
}
/* checkbox-friendly: 1/true/on/yes and 0/false/off/no (any case) */
static inline int lite_scan_bool(const char *t, _Bool *out) {
    t = lite_skip(t);
    static const char *yes[] = { "1", "true", "on", "yes" };
    static const char *no[]  = { "0", "false", "off", "no" };
    for (int i = 0; i < 4; i++) {
        size_t n = strlen(yes[i]);
        if (!strncasecmp(t, yes[i], n) && lite_end_ok(t + n)) { *out = 1; return 1; }
        n = strlen(no[i]);
        if (!strncasecmp(t, no[i], n) && lite_end_ok(t + n)) { *out = 0; return 1; }
    }
    return 0;
}
/* text into a buffer: always NUL-terminated, fails (returns 0) when empty or too long */
static inline int lite_scan_str(const char *t, char *buf, size_t size) {
    if (!t || !buf || size == 0 || !*t) return 0;
    size_t n = strlen(t);
    if (n >= size) return 0;
    memcpy(buf, t, n + 1);
    return 1;
}
/* A char* with no known size can't be filled safely; this only exists to keep the unused
 * branch compiling. Use a char array, or form(k, ptr, size). */
static inline int lite_scan_nosize(const char *t, char *buf) { (void)t; (void)buf; return 0; }

#define LITE_IS_ARRAY(p) (!__builtin_types_compatible_p(__typeof__(p), __typeof__(&(p)[0])))

#define LITE_SCAN_NUM(t, p) _Generic((p),                                     \
    short *: lite_scan_short,    int *: lite_scan_int,                        \
    long *: lite_scan_long,      long long *: lite_scan_ll,                   \
    unsigned short *: lite_scan_ushort, unsigned int *: lite_scan_uint,       \
    unsigned long *: lite_scan_ulong,   unsigned long long *: lite_scan_ull,  \
    float *: lite_scan_float,    double *: lite_scan_double,                  \
    long double *: lite_scan_ldouble, _Bool *: lite_scan_bool,                \
    char *: lite_scan_nosize)((t), (p))

#define LITE_SCAN(t, p) __builtin_choose_expr(LITE_IS_ARRAY(p),               \
    lite_scan_str((t), (char *)(void *)(p), sizeof(p)),                       \
    LITE_SCAN_NUM(t, p))

/* ---------- url decoding / form parsing ---------- */

static inline void percent_decode(char *s, int plus_is_space) {
    if (!s) return;
    char *readp = s, *writep = s;
    while (*readp) {
        if (*readp == '+' && plus_is_space) {
            *writep++ = ' ';
            readp++;
        } else if (*readp == '%' && readp[1] && readp[2] &&
                   isxdigit((unsigned char)readp[1]) &&
                   isxdigit((unsigned char)readp[2])) {
            unsigned char hi = (unsigned char)readp[1];
            unsigned char lo = (unsigned char)readp[2];
            hi = (unsigned char)(isdigit(hi) ? hi - '0' : tolower(hi) - 'a' + 10);
            lo = (unsigned char)(isdigit(lo) ? lo - '0' : tolower(lo) - 'a' + 10);
            *writep++ = (char)((hi << 4) | lo);
            readp += 3;
        } else {
            *writep++ = *readp++;
        }
    }
    *writep = 0;
}

static inline void url_decode(char *s) { percent_decode(s, 1); }

static inline void url_encode(const char *s, char *out, size_t cap) {
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    if (!out || cap == 0) return;
    if (!s) s = "";
    for (; *s && cap - o > 3; s++) {
        unsigned char c = (unsigned char)*s;
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out[o++] = (char)c;
        else { out[o++] = '%'; out[o++] = hex[c >> 4]; out[o++] = hex[c & 15]; }
    }
    out[o] = 0;
}

static inline void parse_urlencoded(PList *l, const char *s) {
    if (!l || !s) return;
    char *copy = strdup(s), *save = NULL;
    if (!copy) return;
    for (char *pair = strtok_r(copy, "&", &save); pair; pair = strtok_r(NULL, "&", &save)) {
        if (l->n >= LITE_MAX_PARAMS) break;
        char *eq = strchr(pair, '='), *v = (char *)"";
        if (eq) { *eq = 0; v = eq + 1; }
        char *dk = strdup(pair), *dv = strdup(v);
        if (!dk || !dv) { free(dk); free(dv); break; }
        url_decode(dk); url_decode(dv);
        plist_add(l, dk, dv);
    }
    free(copy);
}

static inline void parse_cookies(PList *l, const char *header) {
    if (!l || !header) return;
    char *copy = strdup(header), *save = NULL;
    if (!copy) return;
    for (char *p = strtok_r(copy, ";", &save); p; p = strtok_r(NULL, ";", &save)) {
        if (l->n >= LITE_MAX_PARAMS) break;
        while (*p == ' ') p++;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = strdup(p), *v = strdup(eq + 1);
        if (!k || !v) { free(k); free(v); break; }
        percent_decode(v, 0);
        plist_add(l, k, v);
    }
    free(copy);
}

/* ---------- growable buffer ---------- */

typedef struct { char *d; size_t len, cap; int failed; } Buf;

/* Reserve space without losing the old allocation if realloc fails. */
static inline int buf_reserve(Buf *b, size_t extra) {
    if (!b || b->failed) return 0;
    if (b->len == SIZE_MAX || extra > SIZE_MAX - b->len - 1) { b->failed = 1; return 0; }
    size_t need = b->len + extra + 1;
    if (need <= b->cap) return 1;
    size_t cap = b->cap ? b->cap : 128;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) { cap = need; break; }
        cap *= 2;
    }
    char *next = (char *)realloc(b->d, cap);
    if (!next) { b->failed = 1; return 0; }
    b->d = next;
    b->cap = cap;
    if (b->len == 0) b->d[0] = 0;
    return 1;
}

static inline void buf_add(Buf *b, const char *s, size_t n) {
    if (!b || (!s && n)) { if (b) b->failed = 1; return; }
    if (!n) return;
    if (!buf_reserve(b, n) || !b->d) return;
    memcpy(b->d + b->len, s, n);
    b->len += n;
    b->d[b->len] = 0;
}

static inline void buf_add_escaped(Buf *b, const char *s) {
    for (; *s; s++) {
        switch (*s) {
            case '<':  buf_add(b, "&lt;", 4);   break;
            case '>':  buf_add(b, "&gt;", 4);   break;
            case '&':  buf_add(b, "&amp;", 5);  break;
            case '"':  buf_add(b, "&quot;", 6); break;
            case '\'': buf_add(b, "&#39;", 5);  break;
            default:   buf_add(b, s, 1);
        }
    }
}

static inline void buf_addf(Buf *b, const char *fmt, ...) {
    if (!b || !fmt || b->failed) return;
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n > SIZE_MAX - 1) {
        va_end(ap2); b->failed = 1; return;
    }
    size_t size = (size_t)n + 1;
    char *line = (char *)malloc(size);
    if (!line) { va_end(ap2); b->failed = 1; return; }
    int written = vsnprintf(line, size, fmt, ap2);
    va_end(ap2);
    if (written != n) b->failed = 1;
    else buf_add(b, line, (size_t)n);
    free(line);
}

/* ---------- fmt ----------
 * fmt("%d", 25) -> "25"     fmt("%.2f", 9.5) -> "9.50"     fmt("%d items", n)
 * printf-style text you can pass straight to render(). Valid for this request only. */

#define LITE_MAX_TEMP 64
static char *lite_temp[LITE_MAX_TEMP];
static int lite_ntemp = 0;

static inline const char *fmt(const char *f, ...) {
    va_list ap, ap2;
    va_start(ap, f);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, f, ap);
    va_end(ap);
    if (n < 0 || lite_ntemp >= LITE_MAX_TEMP) { va_end(ap2); return ""; }
    if ((size_t)n == SIZE_MAX) { va_end(ap2); return ""; }
    char *s = (char *)malloc((size_t)n + 1);
    if (!s) { va_end(ap2); return ""; }
    if (vsnprintf(s, (size_t)n + 1, f, ap2) != n) {
        va_end(ap2); free(s); return "";
    }
    va_end(ap2);
    lite_temp[lite_ntemp++] = s;
    return s;
}

static inline void temp_free(void) {
    int n = lite_ntemp;
    if (n < 0) n = 0;
    if (n > LITE_MAX_TEMP) n = LITE_MAX_TEMP;
    for (int i = 0; i < n; i++) { free(lite_temp[i]); lite_temp[i] = NULL; }
    lite_ntemp = 0;
}


/* ---------- values: text OR numbers ----------
 * render(), session_set() and set_cookie() accept strings and numbers directly:
 *     render("page.html", "name", "Ali", "age", 25, "price", 9.5);
 * Whole numbers print as-is. Decimals print the short way (9.5, not 9.50);
 * use fmt("%.2f", price) when you need an exact format. Needs C11 (gcc/clang default). */

typedef struct { int t; const char *s; long long i; double d; } lite_val;   /* t: 1 text, 2 int, 3 double, -1 end */

static inline lite_val lite_vs(const char *s) { lite_val v = {0}; v.t = 1; v.s = s; return v; }
static inline lite_val lite_vi(long long i)   { lite_val v = {0}; v.t = 2; v.i = i; return v; }
static inline lite_val lite_vd(double d)      { lite_val v = {0}; v.t = 3; v.d = d; return v; }
static inline lite_val lite_vend(void)        { lite_val v = {0}; v.t = -1; return v; }

#define LITE_V(x) _Generic((x),                                              \
    char *: lite_vs, const char *: lite_vs, void *: lite_vs,                 \
    _Bool: lite_vi, signed char: lite_vi, short: lite_vi, int: lite_vi,      \
    long: lite_vi, long long: lite_vi, unsigned char: lite_vi,               \
    unsigned short: lite_vi, unsigned int: lite_vi, unsigned long: lite_vi,  \
    unsigned long long: lite_vi, float: lite_vd, double: lite_vd)(x)

static inline const char *lite_str(lite_val v) {
    if (v.t == 1) return v.s ? v.s : "";
    if (v.t == 2) return fmt("%lld", v.i);
    if (v.t == 3) return fmt("%.15g", v.d);
    return "";
}

/* keep a malloc'd string until the end of the request */
static inline const char *lite_keep(char *s) {
    if (!s) return "";
    if (lite_ntemp < 0 || lite_ntemp >= LITE_MAX_TEMP) { free(s); return ""; }
    lite_temp[lite_ntemp++] = s;
    return s;
}

/* Escape untrusted text before inserting it into HTML.
 * The returned string is kept until the current request finishes.
 * Use in HTML text or quoted-attribute contexts, not inside JavaScript/CSS. */
static inline const char *html_escape(const char *input) {
    if (!input) input = "";

    size_t needed = 0;
    for (const unsigned char *p = (const unsigned char *)input; *p; p++) {
        size_t add = (*p == '&') ? 5 :
                     (*p == '<' || *p == '>') ? 4 :
                     (*p == '"') ? 6 :
                     (*p == '\'') ? 5 : 1;
        if (needed > (size_t)-1 - add) return "";
        needed += add;
    }

    if (needed == SIZE_MAX) return "";
    char *out = (char *)malloc(needed + 1);
    if (!out) return "";

    char *q = out;
    for (const char *p = input; *p; p++) {
        const char *replacement = NULL;
        switch (*p) {
            case '&':  replacement = "&amp;";  break;
            case '<':  replacement = "&lt;";   break;
            case '>':  replacement = "&gt;";   break;
            case '"': replacement = "&quot;"; break;
            case '\'': replacement = "&#39;";  break;
            default: *q++ = *p; break;
        }
        if (replacement) {
            size_t n = strlen(replacement);
            memcpy(q, replacement, n);
            q += n;
        }
    }
    *q = '\0';
    return lite_keep(out);
}

static inline char *lite_salloc(const char *f, ...) {
    va_list ap, ap2;
    va_start(ap, f);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, f, ap);
    va_end(ap);
    char *s = NULL;
    if (n >= 0 && (size_t)n < SIZE_MAX) {
        s = (char *)malloc((size_t)n + 1);
        if (s && vsnprintf(s, (size_t)n + 1, f, ap2) != n) { free(s); s = NULL; }
    }
    va_end(ap2);
    return s;
}

/* Applies a printf-style format (written by you in render's name, e.g. "price %.2f")
 * to a value. Returns NULL when the format is not usable, so the plain value is shown.
 * Only ONE conversion is allowed (d i u x X o f F e E g G s) plus %% and normal text.
 * The format comes from your name text, never from a value, so user input is safe. */
static inline const char *lite_formatted(const char *f, lite_val v) {
    char tmp[256];
    size_t o = 0;
    int cls = 0;                                   /* 1 signed int, 2 unsigned int, 3 float, 4 text */
    if (strlen(f) > 200) return NULL;
    while (*f) {
        if (*f != '%') { tmp[o++] = *f++; continue; }
        if (f[1] == '%') { tmp[o++] = '%'; tmp[o++] = '%'; f += 2; continue; }
        if (cls) return NULL;                      /* only one value per format */
        tmp[o++] = *f++;
        while (*f && strchr("-+ #0", *f)) tmp[o++] = *f++;
        int digits = 0;
        while (isdigit((unsigned char)*f)) { if (++digits > 3) return NULL; tmp[o++] = *f++; }
        if (*f == '.') {
            tmp[o++] = *f++;
            digits = 0;
            while (isdigit((unsigned char)*f)) { if (++digits > 3) return NULL; tmp[o++] = *f++; }
        }
        while (*f == 'h' || *f == 'l' || *f == 'z' || *f == 'j' || *f == 't' || *f == 'L') f++;
        char c = *f;
        if (c == 'd' || c == 'i') cls = 1;
        else if (c == 'u' || c == 'x' || c == 'X' || c == 'o') cls = 2;
        else if (c && strchr("fFeEgG", c)) cls = 3;
        else if (c == 's') cls = 4;
        else return NULL;
        if (cls == 1 || cls == 2) { tmp[o++] = 'l'; tmp[o++] = 'l'; }
        tmp[o++] = c;
        f++;
    }
    tmp[o] = 0;
    if (!cls) return NULL;

    if (cls == 4) return lite_keep(lite_salloc(tmp, lite_str(v)));

    if (cls == 3) {
        double d;
        if (v.t == 3) d = v.d;
        else if (v.t == 2) d = (double)v.i;
        else { char *e; d = strtod(v.s ? v.s : "", &e); if (e == v.s || *e) return NULL; }
        return lite_keep(lite_salloc(tmp, d));
    }

    long long x;
    if (v.t == 2) x = v.i;
    else if (v.t == 3) x = (long long)v.d;
    else { char *e; x = strtoll(v.s ? v.s : "", &e, 10); if (e == v.s || *e) return NULL; }
    if (cls == 2) return lite_keep(lite_salloc(tmp, (unsigned long long)x));
    return lite_keep(lite_salloc(tmp, x));
}

/* applies f to every argument (up to 33) */
#define LITE_JOIN2(a, b) a##b
#define LITE_JOIN(a, b) LITE_JOIN2(a, b)
#define LITE_ARG_N(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,_21,_22,_23,_24,_25,_26,_27,_28,_29,_30,_31,_32,_33,N,...) N
#define LITE_NARGS(...) LITE_ARG_N(__VA_ARGS__, 33,32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0)
#define LITE_MAP_1(f, a) f(a)
#define LITE_MAP_2(f, a, ...) f(a), LITE_MAP_1(f, __VA_ARGS__)
#define LITE_MAP_3(f, a, ...) f(a), LITE_MAP_2(f, __VA_ARGS__)
#define LITE_MAP_4(f, a, ...) f(a), LITE_MAP_3(f, __VA_ARGS__)
#define LITE_MAP_5(f, a, ...) f(a), LITE_MAP_4(f, __VA_ARGS__)
#define LITE_MAP_6(f, a, ...) f(a), LITE_MAP_5(f, __VA_ARGS__)
#define LITE_MAP_7(f, a, ...) f(a), LITE_MAP_6(f, __VA_ARGS__)
#define LITE_MAP_8(f, a, ...) f(a), LITE_MAP_7(f, __VA_ARGS__)
#define LITE_MAP_9(f, a, ...) f(a), LITE_MAP_8(f, __VA_ARGS__)
#define LITE_MAP_10(f, a, ...) f(a), LITE_MAP_9(f, __VA_ARGS__)
#define LITE_MAP_11(f, a, ...) f(a), LITE_MAP_10(f, __VA_ARGS__)
#define LITE_MAP_12(f, a, ...) f(a), LITE_MAP_11(f, __VA_ARGS__)
#define LITE_MAP_13(f, a, ...) f(a), LITE_MAP_12(f, __VA_ARGS__)
#define LITE_MAP_14(f, a, ...) f(a), LITE_MAP_13(f, __VA_ARGS__)
#define LITE_MAP_15(f, a, ...) f(a), LITE_MAP_14(f, __VA_ARGS__)
#define LITE_MAP_16(f, a, ...) f(a), LITE_MAP_15(f, __VA_ARGS__)
#define LITE_MAP_17(f, a, ...) f(a), LITE_MAP_16(f, __VA_ARGS__)
#define LITE_MAP_18(f, a, ...) f(a), LITE_MAP_17(f, __VA_ARGS__)
#define LITE_MAP_19(f, a, ...) f(a), LITE_MAP_18(f, __VA_ARGS__)
#define LITE_MAP_20(f, a, ...) f(a), LITE_MAP_19(f, __VA_ARGS__)
#define LITE_MAP_21(f, a, ...) f(a), LITE_MAP_20(f, __VA_ARGS__)
#define LITE_MAP_22(f, a, ...) f(a), LITE_MAP_21(f, __VA_ARGS__)
#define LITE_MAP_23(f, a, ...) f(a), LITE_MAP_22(f, __VA_ARGS__)
#define LITE_MAP_24(f, a, ...) f(a), LITE_MAP_23(f, __VA_ARGS__)
#define LITE_MAP_25(f, a, ...) f(a), LITE_MAP_24(f, __VA_ARGS__)
#define LITE_MAP_26(f, a, ...) f(a), LITE_MAP_25(f, __VA_ARGS__)
#define LITE_MAP_27(f, a, ...) f(a), LITE_MAP_26(f, __VA_ARGS__)
#define LITE_MAP_28(f, a, ...) f(a), LITE_MAP_27(f, __VA_ARGS__)
#define LITE_MAP_29(f, a, ...) f(a), LITE_MAP_28(f, __VA_ARGS__)
#define LITE_MAP_30(f, a, ...) f(a), LITE_MAP_29(f, __VA_ARGS__)
#define LITE_MAP_31(f, a, ...) f(a), LITE_MAP_30(f, __VA_ARGS__)
#define LITE_MAP_32(f, a, ...) f(a), LITE_MAP_31(f, __VA_ARGS__)
#define LITE_MAP_33(f, a, ...) f(a), LITE_MAP_32(f, __VA_ARGS__)
#define LITE_MAP(f, ...) LITE_JOIN(LITE_MAP_, LITE_NARGS(__VA_ARGS__))(f, __VA_ARGS__)

/* ---------- templates ----------
 *   {{ name }}                      value (HTML-escaped automatically)
 *   {% if name %} ... {% endif %}   shown when name is set and not empty
 *   {% if name %} ... {% else %} ... {% endif %}
 * Files are loaded from the templates/ folder.
 */

static inline char *read_file(const char *name) {
    if (!name || !*name) return NULL;
    char path[512];
    int pn = snprintf(path, sizeof path, "templates/%s", name);
    if (pn < 0 || (size_t)pn >= sizeof path) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long end = ftell(f);
    if (end < 0 || (unsigned long)end > LITE_MAX_REQUEST) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    size_t n = (size_t)end;
    if (n == SIZE_MAX) { fclose(f); return NULL; }
    char *s = (char *)malloc(n + 1);
    if (!s) { fclose(f); return NULL; }
    size_t got = fread(s, 1, n, f);
    int failed = ferror(f);
    fclose(f);
    if (failed || got != n) { free(s); return NULL; }
    s[n] = 0;
    return s;
}

static inline const char *vars_get(const char **kv, int n, const char *k) {
    for (int i = 0; i + 1 < n; i += 2)
        if (!strcmp(kv[i], k)) return kv[i + 1];
    return "";
}

static inline void tag_text(const char *s, const char *e, char *out, size_t cap) {
    if (!out || cap == 0 || !s || !e || e < s) return;
    while (s < e && isspace((unsigned char)*s)) s++;
    while (e > s && isspace((unsigned char)e[-1])) e--;
    size_t n = (size_t)(e - s);
    if (n >= cap) n = cap - 1;
    memcpy(out, s, n);
    out[n] = 0;
}

static inline char *tpl_render(const char *src, const char **kv, int n) {
    Buf b = {0};
    int prev[16], cond[16], depth = 0, active = 1;
    const char *p = src;
    while (*p) {
        if (p[0] == '{' && p[1] == '{') {
            const char *end = strstr(p + 2, "}}");
            if (end) {
                char name[128];
                tag_text(p + 2, end, name, sizeof name);
                if (active) buf_add_escaped(&b, vars_get(kv, n, name));
                p = end + 2;
                continue;
            }
        } else if (p[0] == '{' && p[1] == '%') {
            const char *end = strstr(p + 2, "%}");
            if (end) {
                char tag[128];
                tag_text(p + 2, end, tag, sizeof tag);
                if (!strncmp(tag, "if ", 3)) {
                    const char *name = tag + 3;
                    while (*name == ' ') name++;
                    int c = *vars_get(kv, n, name) != 0;
                    if (depth < 16) { prev[depth] = active; cond[depth] = c; depth++; }
                    active = active && c;
                } else if (!strcmp(tag, "else")) {
                    if (depth > 0) active = prev[depth - 1] && !cond[depth - 1];
                } else if (!strcmp(tag, "endif")) {
                    if (depth > 0) active = prev[--depth];
                }
                p = end + 2;
                continue;
            }
        }
        if (active) buf_add(&b, p, 1);
        p++;
    }
    if (b.failed) { free(b.d); return NULL; }
    if (b.d) return b.d;
    return strdup("");
}

/* ---------- responses (use with: return ...;) ---------- */

static inline void res_vprintf(Response *res, const char *type, const char *fmt, va_list ap) {
    if (!res || !fmt || !type) return;
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    if (n < 0 || (size_t)n == SIZE_MAX) {
        va_end(ap2); res->status = 500; return;
    }
    char *body = (char *)malloc((size_t)n + 1);
    if (!body) { va_end(ap2); res->status = 500; return; }
    if (vsnprintf(body, (size_t)n + 1, fmt, ap2) != n) {
        va_end(ap2); free(body); res->status = 500; return;
    }
    va_end(ap2);
    free(res->body);
    res->body = body;
    res->len = (size_t)n;
    snprintf(res->type, sizeof res->type, "%s", type);
}

/* return text("Hello %s", name);   plain text, printf style */
static inline int text(const char *fmt, ...) {
    if (!lite_res) return 500;
    va_list ap; va_start(ap, fmt);
    res_vprintf(lite_res, "text/plain; charset=utf-8", fmt, ap);
    va_end(ap);
    return 200;
}

/* return html("<h1>%s</h1>", x);   HTML, printf style (NOT escaped) */
static inline int html(const char *fmt, ...) {
    if (!lite_res) return 500;
    va_list ap; va_start(ap, fmt);
    res_vprintf(lite_res, "text/html; charset=utf-8", fmt, ap);
    va_end(ap);
    return 200;
}

/* return render("page.html", "key", "value", "age", 25, "price %.2f", 9.5);
 * Pairs of name + value (text or number). Values are HTML-escaped in the template.
 * Add a printf format after the name to control how a value looks:
 *     "price %.2f"  "id %05d"  "score %d%%"  "tag %-8s"  "money $%.2f"  */
static inline int render_(lite_val file, ...) {
    const char *kv[LITE_MAX_PARAMS * 2];
    int n = 0;
    va_list ap;
    va_start(ap, file);
    while (n < LITE_MAX_PARAMS * 2 - 2) {
        lite_val k = va_arg(ap, lite_val);
        if (k.t == -1) break;
        lite_val v = va_arg(ap, lite_val);
        if (v.t == -1) break;
        const char *key = lite_str(k), *val = NULL, *pct = strchr(key, '%');
        if (pct) {                                  /* "price %.2f": name, then a format */
            const char *sep = key;
            while (sep < pct && *sep != ' ' && *sep != ':') sep++;
            if (sep < pct && sep > key) {
                const char *f = sep + 1;
                while (*f == ' ') f++;
                val = lite_formatted(f, v);
                key = fmt("%.*s", (int)(sep - key), key);
            }
        }
        kv[n++] = key;
        kv[n++] = val ? val : lite_str(v);
    }
    va_end(ap);

    const char *name = lite_str(file);
    char *src = read_file(name);
    if (!src) { text("Template not found: templates/%s", name); return 500; }
    char *out = tpl_render(src, kv, n);
    free(src);
    if (!out) { lite_res->status = 500; return 500; }
    free(lite_res->body);
    lite_res->body = out;
    lite_res->len = strlen(out);
    snprintf(lite_res->type, sizeof lite_res->type, "text/html; charset=utf-8");
    return 200;
}
#define render(...) render_(LITE_MAP(LITE_V, __VA_ARGS__), lite_vend())

/* return redirect("/somewhere"); */
static inline int redirect(const char *url) {
    if (!lite_res || !url) return 500;
    char *empty = strdup("");
    if (!empty) { lite_res->status = 500; return 500; }
    snprintf(lite_res->location, sizeof lite_res->location, "%s", url);
    free(lite_res->body);
    lite_res->body = empty;
    lite_res->len = 0;
    return 302;
}

/* ---------- cookies ----------
 *   cookie("theme")                          read a cookie ("" if missing)
 *   set_cookie("theme", "dark")              lasts until the browser closes
 *   set_cookie_age("theme", "dark", 86400)   lasts 86400 seconds (1 day)
 *   delete_cookie("theme")
 *   cookie_secure(1)                          add the Secure flag to all cookies
 * Cookies are HttpOnly + SameSite=Lax by default. Enable Secure only when
 * the app is served over HTTPS. Keep values small (under ~300 bytes). */

static int lite_cookie_secure_flag = 0;

/* Configure whether cookies include the Secure attribute. */
static inline void cookie_secure(int enabled) {
    lite_cookie_secure_flag = !!enabled;
}

static inline void cookie_add(const char *name, const char *value, long max_age) {
    if (!lite_res || !name || !*name || !value) return;

    char enc[400];
    url_encode(value, enc, sizeof enc);

    char *cookie = malloc(512);
    if (!cookie) { lite_res->cookie_error = 1; return; }

    int n;
    const char *secure = lite_cookie_secure_flag ? "; Secure" : "";
    if (max_age >= 0)
        n = snprintf(cookie, 512, "%s=%s; Path=/; HttpOnly; SameSite=Lax%s; Max-Age=%ld", name, enc, secure, max_age);
    else
        n = snprintf(cookie, 512, "%s=%s; Path=/; HttpOnly; SameSite=Lax%s", name, enc, secure);
    if (n <= 0 || n >= 512) {
        free(cookie);
        lite_res->cookie_error = 1;
        return;
    }

    if (lite_res->ncookies == lite_res->cookie_capacity) {
        size_t cap = lite_res->cookie_capacity ? lite_res->cookie_capacity * 2 : 8;
        if (cap < lite_res->cookie_capacity || cap > SIZE_MAX / sizeof(*lite_res->cookies)) {
            free(cookie);
            lite_res->cookie_error = 1;
            return;
        }
        char **items = realloc(lite_res->cookies, cap * sizeof(*items));
        if (!items) {
            free(cookie);
            lite_res->cookie_error = 1;
            return;
        }
        lite_res->cookies = items;
        lite_res->cookie_capacity = cap;
    }

    lite_res->cookies[lite_res->ncookies++] = cookie;
}

static inline void set_cookie_(const char *name, const char *value) { cookie_add(name, value, -1); }
static inline void set_cookie_age_(const char *name, const char *value, long seconds) { cookie_add(name, value, seconds); }
static inline void delete_cookie(const char *name) { cookie_add(name, "", 0); }

/* ---------- sessions ----------
 *   session("user")              legacy read ("" if missing)
 *   session_get("user")          read a value (NULL if missing or empty)
 *   session_set("user", "Ali")   store a value (creates the session on first use)
 *   session_clear()              log out: delete the whole session
 * Data lives in server memory, so sessions are lost when the app restarts. */

typedef struct {
    char id[33];
    char **k;
    char **v;
    size_t n;
    size_t capacity;
    time_t expires_at; /* 0 = no expiration */
} Session;

static Session **lite_sessions = NULL;
static size_t lite_session_count = 0;
static size_t lite_session_capacity = 0;
static Session *lite_sess = NULL;   /* this request's session, or NULL */

static inline void session_free(Session *s) {
    if (!s) return;
    for (size_t i = 0; i < s->n; i++) {
        free(s->k[i]);
        free(s->v[i]);
    }
    free(s->k);
    free(s->v);
    memset(s, 0, sizeof *s);
}

static inline Session *session_find(const char *id) {
    if (!*id) return NULL;
    time_t now = time(NULL);
    for (size_t i = 0; i < lite_session_count; i++) {
        Session *s = lite_sessions[i];
        if (s->id[0] && !strcmp(s->id, id)) {
            if (s->expires_at && now >= s->expires_at) {
                session_free(s);
                return NULL;
            }
            return s;
        }
    }
    return NULL;
}

static inline int random_id(char *out) {
    unsigned char r[16];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t got = fread(r, 1, sizeof r, f);
    fclose(f);
    if (got != sizeof r) return 0;
    for (int i = 0; i < 16; i++) snprintf(out + i * 2, 3, "%02x", r[i]);
    return 1;
}

static inline Session *session_new(void) {
    Session *s = NULL;
    for (size_t i = 0; i < lite_session_count; i++) {
        if (!lite_sessions[i]->id[0]) {
            s = lite_sessions[i];
            break;
        }
    }
    if (!s) {
        if (lite_session_count == lite_session_capacity) {
            size_t cap = lite_session_capacity ? lite_session_capacity * 2 : 16;
            if (cap < lite_session_capacity || cap > SIZE_MAX / sizeof(*lite_sessions))
                return NULL;
            Session **items = realloc(lite_sessions, cap * sizeof(*items));
            if (!items) return NULL;
            lite_sessions = items;
            lite_session_capacity = cap;
        }
        s = calloc(1, sizeof(*s));
        if (!s) return NULL;
        lite_sessions[lite_session_count++] = s;
    }
    if (!random_id(s->id)) {
        session_free(s);
        return NULL;
    }
    return s;
}

/* Rotate the current session ID without losing its stored data.
 * Call after successful authentication to prevent session fixation.
 * Returns 1 on success, 0 if a new ID could not be generated/allocated.
 */
static inline int session_regenerate(void) {
    if (!lite_sess) {
        lite_sess = session_new();
        if (!lite_sess) return 0;
    } else {
        char fresh[33];
        if (!random_id(fresh)) return 0;
        memcpy(lite_sess->id, fresh, sizeof fresh);
    }
    set_cookie_("lite_sid", lite_sess->id);
    return 1;
}

static inline const char *session_by_name(const char *key) {
    if (!lite_sess || !key) return "";
    for (size_t i = 0; i < lite_sess->n; i++)
        if (!strcmp(lite_sess->k[i], key)) return lite_sess->v[i];
    return "";
}
static inline const char *session_by_index(long long i) {
    return (lite_sess && i >= 0 && (unsigned long long)i < lite_sess->n)
        ? lite_sess->v[(size_t)i] : "";
}

/* Grow one session's key/value arrays together, preserving existing entries. */
static inline int session_reserve(Session *s, size_t needed) {
    if (!s) return 0;
    if (needed <= s->capacity) return 1;

    size_t cap = s->capacity ? s->capacity : 8;
    while (cap < needed) {
        if (cap > SIZE_MAX / 2) { cap = needed; break; }
        cap *= 2;
    }
    if (cap > SIZE_MAX / sizeof(*s->k) ||
        cap > SIZE_MAX / sizeof(*s->v)) return 0;

    char **keys = calloc(cap, sizeof(*keys));
    char **values = calloc(cap, sizeof(*values));
    if (!keys || !values) {
        free(keys);
        free(values);
        return 0;
    }
    if (s->n) {
        memcpy(keys, s->k, s->n * sizeof(*keys));
        memcpy(values, s->v, s->n * sizeof(*values));
    }
    free(s->k);
    free(s->v);
    s->k = keys;
    s->v = values;
    s->capacity = cap;
    return 1;
}
/* Public read: NULL means missing/empty; a non-empty value is truthy in if(). */
static inline const char *session_get_value(const char *key) {
    const char *value = session_by_name(key);
    return (value && *value) ? value : NULL;
}
/* session("user") or session(0) */
#define session(k) _Generic((k),                                              \
    char *: session_by_name, const char *: session_by_name,                   \
    short: session_by_index, int: session_by_index, long: session_by_index,   \
    long long: session_by_index, unsigned int: session_by_index,              \
    unsigned long: session_by_index)(k)

static inline void session_set_(const char *key, const char *value) {
    if (!key || !*key || !value) return;
    if (!lite_sess) {
        lite_sess = session_new();
        if (!lite_sess) return;
        set_cookie_("lite_sid", lite_sess->id);
    }
    Session *s = lite_sess;
    for (size_t i = 0; i < s->n; i++) {
        if (!strcmp(s->k[i], key)) {
            char *nv = strdup(value);
            if (!nv) return;
            free(s->v[i]);
            s->v[i] = nv;
            return;
        }
    }

    char *nk = strdup(key);
    char *nv = strdup(value);
    if (!nk || !nv) { free(nk); free(nv); return; }
    if (s->n == SIZE_MAX || !session_reserve(s, s->n + 1)) {
        free(nk);
        free(nv);
        return;
    }
    s->k[s->n] = nk;
    s->v[s->n] = nv;
    s->n++;
}

/* Optional expiry: session_set("user", value, "-e", seconds).
 * A regular two-argument session_set() keeps the session non-expiring. */
static inline void session_set_expiring_(const char *key, const char *value,
                                         const char *option, long seconds) {
    session_set_(key, value);
    if (lite_sess && option && !strcmp(option, "-e") && seconds > 0)
        lite_sess->expires_at = time(NULL) + (time_t)seconds;
}

static inline void session_clear(void) {
    if (!lite_sess) return;
    session_free(lite_sess);
    lite_sess = NULL;
    delete_cookie("lite_sid");
}

/* session_int("visits") -> the stored number (0 if missing). Pair it with session_set("visits", 5). */
static inline int session_int(const char *key) { return to_int(session(key)); }

/* ---------- automatic CSRF protection ----------
 * POST forms receive a hidden field; HTML pages expose a meta token for fetch/AJAX.
 * URL-encoded and multipart form fields, or X-Lite-CSRF-Token, are accepted.
 * Every POST request must return the session-bound token or it receives HTTP 403. */
static inline int lite_csrf_equal(const char *a, const char *b) {
    if (!a || !b) return 0;
    size_t na = strlen(a), nb = strlen(b);
    if (na != nb) return 0;
    unsigned char diff = 0;
    for (size_t i = 0; i < na; i++) diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    return diff == 0;
}

static inline const char *lite_csrf_token(void) {
    const char *token = session_by_name("_lite_csrf");
    if (token && *token) return token;
    char fresh[33];
    if (!random_id(fresh)) return NULL;
    session_set_("_lite_csrf", fresh);
    token = session_by_name("_lite_csrf");
    return (token && *token) ? token : NULL;
}

/* Parse a form's opening tag. Only same-origin/relative POST forms get a token;
 * absolute and protocol-relative actions are deliberately left untouched. */
static inline int lite_csrf_post_form(const char *tag, size_t len) {
    if (!tag || len < 6) return 0;
    const char *p = tag + 5, *end = tag + len;
    int is_post = 0, unsafe_action = 0;
    while (p < end && *p != '>') {
        while (p < end && (isspace((unsigned char)*p) || *p == '/')) p++;
        const char *name = p;
        while (p < end && (isalnum((unsigned char)*p) || *p == '-' || *p == '_' || *p == ':')) p++;
        if (p == name) { p++; continue; }
        size_t name_len = (size_t)(p - name);
        while (p < end && isspace((unsigned char)*p)) p++;
        const char *value = NULL;
        size_t value_len = 0;
        if (p < end && *p == '=') {
            p++;
            while (p < end && isspace((unsigned char)*p)) p++;
            if (p < end && (*p == '\'' || *p == '"')) {
                char quote = *p++;
                value = p;
                while (p < end && *p != quote) p++;
                value_len = (size_t)(p - value);
                if (p < end) p++;
            } else {
                value = p;
                while (p < end && !isspace((unsigned char)*p) && *p != '>') p++;
                value_len = (size_t)(p - value);
            }
        }
        if (value && name_len == 6 && !strncasecmp(name, "method", 6) &&
            value_len == 4 && !strncasecmp(value, "post", 4)) is_post = 1;
        if (value && name_len == 6 && !strncasecmp(name, "action", 6) && value_len) {
            if ((value_len >= 2 && value[0] == '/' && value[1] == '/') ||
                (value_len >= 7 && !strncasecmp(value, "http://", 7)) ||
                (value_len >= 8 && !strncasecmp(value, "https://", 8)) ||
                (value_len >= 11 && !strncasecmp(value, "javascript:", 11)))
                unsafe_action = 1;
            for (size_t i = 0; i < value_len; i++) {
                if (value[i] == ':' && (i == 0 ||
                    (value[i-1] != '/' && value[i-1] != '?' && value[i-1] != '#'))) {
                    unsafe_action = 1;
                    break;
                }
                if (value[i] == '/' || value[i] == '?' || value[i] == '#') break;
            }
        }
    }
    return is_post && !unsafe_action;
}

static inline const char *lite_csrf_find_form(const char *html) {
    if (!html) return NULL;
    const char *p = html;
    while ((p = strcasestr(p, "<form")) != NULL) {
        unsigned char next = (unsigned char)p[5];
        if (next && (isspace(next) || next == '>' || next == '/')) return p;
        p += 5;
    }
    return NULL;
}

static inline int lite_csrf_html_forms(Response *res) {
    if (!res || !res->body || strncasecmp(res->type, "text/html", 9)) return 1;

    const char *token = lite_csrf_token();
    if (!token) return 0;

    Buf out = {0};
    const char *p = res->body;
    int meta_present = strcasestr(p, "name=\"lite-csrf-token\"") != NULL ||
                       strcasestr(p, "name='lite-csrf-token'") != NULL;
    if (!meta_present) {
        const char *head = strcasestr(p, "<head");
        if (head) {
            const char *end = head;
            char quote = 0;
            while (*end) {
                if (quote) { if (*end == quote) quote = 0; }
                else if (*end == '\'' || *end == '"') quote = *end;
                else if (*end == '>') break;
                end++;
            }
            if (*end == '>') {
                buf_add(&out, p, (size_t)(end + 1 - p));
                buf_addf(&out, "<meta name=\"lite-csrf-token\" content=\"%s\">", token);
                p = end + 1;
            }
        }
        if (p == res->body)
            buf_addf(&out, "<meta name=\"lite-csrf-token\" content=\"%s\">", token);
    }

    const char *scan;
    while ((scan = lite_csrf_find_form(p)) != NULL) {
        const char *end = scan;
        char quote = 0;
        while (*end) {
            if (quote) { if (*end == quote) quote = 0; }
            else if (*end == '\'' || *end == '"') quote = *end;
            else if (*end == '>') break;
            end++;
        }
        if (!*end) break;
        size_t tag_len = (size_t)(end - scan) + 1;
        buf_add(&out, p, (size_t)(scan - p));
        buf_add(&out, scan, tag_len);
        if (lite_csrf_post_form(scan, tag_len))
            buf_addf(&out, "<input type=\"hidden\" name=\"_lite_csrf\" value=\"%s\">", token);
        p = end + 1;
    }
    if (out.failed) { free(out.d); return 0; }
    buf_add(&out, p, strlen(p));
    if (out.failed || !out.d) { free(out.d); return 0; }
    free(res->body);
    res->body = out.d;
    res->len = out.len;
    return 1;
}

/* Read the automatically inserted CSRF field from multipart/form-data.
 * This lets ordinary HTML file-upload forms work without custom JavaScript. */
static inline int lite_csrf_multipart_valid(const char *expected) {
    if (!lite_req || !lite_req->body || !expected || !*expected ||
        strncasecmp(lite_req->content_type, "multipart/form-data", 19))
        return 0;

    const char *bp = strcasestr(lite_req->content_type, "boundary=");
    if (!bp) return 0;
    bp += 9;

    char boundary[200];
    size_t bn = 0;
    if (*bp == '"') {
        bp++;
        while (bp[bn] && bp[bn] != '"' && bn < sizeof boundary - 1) bn++;
    } else {
        while (bp[bn] && bp[bn] != ';' && bp[bn] != ' ' &&
               bp[bn] != '\r' && bp[bn] != '\n' &&
               bn < sizeof boundary - 1) bn++;
    }
    if (!bn || bn >= sizeof boundary - 1) return 0;
    memcpy(boundary, bp, bn);
    boundary[bn] = 0;

    char marker[210], delimiter[212];
    int mn = snprintf(marker, sizeof marker, "--%s", boundary);
    int dn = snprintf(delimiter, sizeof delimiter, "\r\n--%s", boundary);
    if (mn <= 0 || (size_t)mn >= sizeof marker ||
        dn <= 0 || (size_t)dn >= sizeof delimiter) return 0;

    const unsigned char *p = lite_req->body;
    const unsigned char *end = p + lite_req->body_len;
    size_t expected_len = strlen(expected);

    while ((size_t)(end - p) >= (size_t)mn) {
        const unsigned char *mark =
            (const unsigned char *)memmem(p, (size_t)(end - p), marker, (size_t)mn);
        if (!mark) break;

        p = mark + mn;
        if ((size_t)(end - p) >= 2 && p[0] == '-' && p[1] == '-') break;
        if ((size_t)(end - p) < 2 || p[0] != '\r' || p[1] != '\n') break;
        p += 2;

        const unsigned char *hend =
            (const unsigned char *)memmem(p, (size_t)(end - p), "\r\n\r\n", 4);
        if (!hend) break;

        size_t hlen = (size_t)(hend - p);
        char *headers = strndup((const char *)p, hlen);
        if (!headers) return 0;

        char *name = strcasestr(headers, "name=\"");
        int is_token_field = 0;
        if (name && !strcasestr(headers, "filename=\"")) {
            name += 6;
            char *quote = strchr(name, '"');
            if (quote) {
                *quote = 0;
                is_token_field = !strcmp(name, "_lite_csrf");
            }
        }
        free(headers);

        const unsigned char *data = hend + 4;
        const unsigned char *next =
            (const unsigned char *)memmem(data, (size_t)(end - data),
                                          delimiter, (size_t)dn);
        if (!next) break;

        if (is_token_field) {
            size_t value_len = (size_t)(next - data);
            return value_len == expected_len &&
                   lite_csrf_equal(expected, (const char *)data);
        }
        p = next + 2 + (size_t)mn;
    }
    return 0;
}

static inline int lite_csrf_valid(void) {
    const char *expected = session_by_name("_lite_csrf");
    const char *provided = plist_get(&lite_req->form, "_lite_csrf");
    if (!provided || !*provided) provided = lite_req->csrf_header;

    if (expected && *expected && provided && *provided)
        return lite_csrf_equal(expected, provided);

    return lite_csrf_multipart_valid(expected);
}

/* ---------- typed reads: assign straight to a variable ----------
 *   const char *name = form_get("name", "guest");
 *   int    age   = form_get("age", 0);
 *   double price = form_get("price", 0.0);
 * The second value is your DEFAULT, and its type decides what you get back (text, int, long,
 * long long, float or double). If the value is missing or not valid for that type, you get
 * your default. Works for: form_get, query_get, session_get, cookie_get, param_get.
 * With one argument you just get the text:  const char *name = form_get("name");  */

#define LITE_WUR __attribute__((warn_unused_result))

static inline LITE_WUR int lite_gi(const char *t, int d) {
    if (!t) return d;
    char *e; errno = 0;
    long v = strtol(t, &e, 10);
    return (e != t && !*e && errno != ERANGE && v >= INT_MIN && v <= INT_MAX) ? (int)v : d;
}
static inline LITE_WUR long lite_gl(const char *t, long d) {
    if (!t) return d;
    char *e; errno = 0;
    long v = strtol(t, &e, 10);
    return (e != t && !*e && errno != ERANGE) ? v : d;
}
static inline LITE_WUR long long lite_gll(const char *t, long long d) {
    if (!t) return d;
    char *e; errno = 0;
    long long v = strtoll(t, &e, 10);
    return (e != t && !*e && errno != ERANGE) ? v : d;
}
static inline LITE_WUR double lite_gd(const char *t, double d) {
    if (!t) return d;
    char *e; errno = 0;
    double v = strtod(t, &e);
    return (e != t && !*e && errno != ERANGE) ? v : d;
}
static inline LITE_WUR float lite_gf(const char *t, float d) { return (float)lite_gd(t, d); }
static inline LITE_WUR const char *lite_gs(const char *t, const char *d) { return (t && *t) ? t : d; }

#define LITE_GETAS(t, d) _Generic((d),                                        \
    int: lite_gi, long: lite_gl, long long: lite_gll,                         \
    double: lite_gd, float: lite_gf,                                          \
    char *: lite_gs, const char *: lite_gs, void *: lite_gs)((t), (d))

#define LITE_G1(src, k)    src(k)
#define LITE_G2(src, k, d) LITE_GETAS(src(k), d)
#define LITE_G_PICK(_1, _2, NAME, ...) NAME
#define LITE_GET(src, ...) LITE_G_PICK(__VA_ARGS__, LITE_G2, LITE_G1, 0)(src, __VA_ARGS__)

#define form_get(...)    LITE_GET(form, __VA_ARGS__)
#define query_get(...)   LITE_GET(query, __VA_ARGS__)
#define param_get(...)   LITE_GET(param, __VA_ARGS__)
#define cookie_get(...)  LITE_GET(cookie, __VA_ARGS__)

/* session_get("user") returns NULL when missing or empty, so it works in if().
 * session_get("age", 0) returns a typed value with a default. */
#define session_get(...) LITE_GET(session_get_value, __VA_ARGS__)

/* text or numbers:
 *   session_set("n", 5);                    no expiration
 *   session_set("user", name, "-e", 6000);  expires after 6000 seconds
 */
#define LITE_SESSION_SET2(k, v)       session_set_(k, lite_str(LITE_V(v)))
#define LITE_SESSION_SET4(k, v, opt, secs) \
    session_set_expiring_(k, lite_str(LITE_V(v)), opt, (long)(secs))
/* Three arguments are deliberately rejected: "-e" must have a duration. */
#define LITE_SESSION_SET_INVALID(...) \
    _Static_assert(0, "session_set: -e requires an expiration value")
#define LITE_SESSION_SET_PICK(_1, _2, _3, _4, NAME, ...) NAME
#define session_set(...) \
    LITE_SESSION_SET_PICK(__VA_ARGS__, LITE_SESSION_SET4, \
                          LITE_SESSION_SET_INVALID, LITE_SESSION_SET2)(__VA_ARGS__)
#define set_cookie(k, v)           set_cookie_(k, lite_str(LITE_V(v)))
#define set_cookie_age(k, v, secs) set_cookie_age_(k, lite_str(LITE_V(v)), secs)

/* ---------- rate limiting ---------- */

static inline void lite_rate_limit_add(const char *path, unsigned int max_requests,
                                       unsigned int window_seconds) {
    if (!path || !*path || strlen(path) >= sizeof(((LiteRateLimitRule *)0)->path) ||
        max_requests == 0 || window_seconds == 0) {
        lite_rate_error = 1;
        return;
    }
    for (size_t i = 0; i < lite_rate_rule_count; i++) {
        if (!strcmp(lite_rate_rules[i].path, path)) {
            lite_rate_error = 1; /* one policy per path; avoid ambiguous limits */
            return;
        }
    }
    if (lite_rate_rule_count == lite_rate_rule_capacity) {
        size_t cap = lite_rate_rule_capacity ? lite_rate_rule_capacity * 2 : 8;
        if (cap < lite_rate_rule_capacity || cap > SIZE_MAX / sizeof(*lite_rate_rules)) {
            lite_rate_error = 1;
            return;
        }
        LiteRateLimitRule *p = realloc(lite_rate_rules, cap * sizeof(*p));
        if (!p) { lite_rate_error = 1; return; }
        lite_rate_rules = p;
        lite_rate_rule_capacity = cap;
    }
    LiteRateLimitRule *rule = &lite_rate_rules[lite_rate_rule_count++];
    snprintf(rule->path, sizeof rule->path, "%s", path);
    rule->max_requests = max_requests;
    rule->window_seconds = window_seconds;
}

static inline int lite_rate_limit_allow(const char *path, const char *client_ip) {
    LiteRateLimitRule *rule = NULL;
    for (size_t i = 0; i < lite_rate_rule_count; i++) {
        if (!strcmp(lite_rate_rules[i].path, path)) { rule = &lite_rate_rules[i]; break; }
    }
    if (!rule) return 1;

    time_t now = time(NULL);
    if (now == (time_t)-1) return 0; /* fail closed if the clock is unavailable */

    /* Reclaim buckets whose configured time window has expired. */
    for (size_t i = 0; i < lite_rate_bucket_count; ) {
        LiteRateLimitBucket *b = &lite_rate_buckets[i];
        unsigned int lifetime = 0;
        for (size_t r = 0; r < lite_rate_rule_count; r++) {
            if (!strcmp(lite_rate_rules[r].path, b->path)) {
                lifetime = lite_rate_rules[r].window_seconds;
                break;
            }
        }
        if (!lifetime || now < b->window_start ||
            (uintmax_t)(now - b->window_start) >= lifetime) {
            lite_rate_buckets[i] = lite_rate_buckets[lite_rate_bucket_count - 1];
            lite_rate_bucket_count--;
            continue;
        }
        i++;
    }

    size_t slot = lite_rate_bucket_count;
    for (size_t i = 0; i < lite_rate_bucket_count; i++) {
        LiteRateLimitBucket *b = &lite_rate_buckets[i];
        if (!strcmp(b->path, path) && !strcmp(b->client_ip, client_ip)) {
            slot = i;
            break;
        }
    }

    if (slot == lite_rate_bucket_count) {
        if (lite_rate_bucket_count == lite_rate_bucket_capacity) {
            size_t cap = lite_rate_bucket_capacity ? lite_rate_bucket_capacity * 2 : 32;
            if (cap < lite_rate_bucket_capacity || cap > SIZE_MAX / sizeof(*lite_rate_buckets))
                return 0;
            LiteRateLimitBucket *p = realloc(lite_rate_buckets, cap * sizeof(*p));
            if (!p) return 0;
            lite_rate_buckets = p;
            lite_rate_bucket_capacity = cap;
        }
        slot = lite_rate_bucket_count++;
        memset(&lite_rate_buckets[slot], 0, sizeof lite_rate_buckets[slot]);
        snprintf(lite_rate_buckets[slot].path, sizeof lite_rate_buckets[slot].path, "%s", path);
        snprintf(lite_rate_buckets[slot].client_ip, sizeof lite_rate_buckets[slot].client_ip,
                 "%s", client_ip);
        lite_rate_buckets[slot].window_start = now;
        lite_rate_buckets[slot].requests = 1;
        return 1;
    }

    LiteRateLimitBucket *bucket = &lite_rate_buckets[slot];
    if (now < bucket->window_start ||
        (uintmax_t)(now - bucket->window_start) >= rule->window_seconds) {
        bucket->window_start = now;
        bucket->requests = 1;
        return 1;
    }
    if (bucket->requests >= rule->max_requests) return 0;
    bucket->requests++;
    return 1;
}

#define LITE_RATE_LIMIT_REGISTER(path, max_requests, window_seconds, id) \
    __attribute__((constructor)) static void LITE_CAT(lite_rate_register_, id)(void) { \
        lite_rate_limit_add((path), (unsigned int)(max_requests), \
                            (unsigned int)(window_seconds)); \
    }
#define RATE_LIMIT(path, max_requests, window_seconds) \
    LITE_RATE_LIMIT_REGISTER(path, max_requests, window_seconds, __COUNTER__)

/* ---------- routing ---------- */

static inline void route_add(const char *pattern, Method m, Handler fn) {
    if (!pattern || !fn) {
        lite_route_error = 1;
        return;
    }

    if (lite_nroutes == lite_route_capacity) {
        size_t new_capacity = lite_route_capacity ? lite_route_capacity * 2 : 16;

        if (new_capacity < lite_route_capacity ||
            new_capacity > SIZE_MAX / sizeof(*lite_routes)) {
            lite_route_error = 1;
            return;
        }

        Route *new_routes = realloc(lite_routes,
                                    new_capacity * sizeof(*lite_routes));
        if (!new_routes) {
            lite_route_error = 1;
            return;
        }

        lite_routes = new_routes;
        lite_route_capacity = new_capacity;
    }

    lite_routes[lite_nroutes++] = (Route){ m, pattern, fn };
}

#define LITE_CAT2(a, b) a##b
#define LITE_CAT(a, b) LITE_CAT2(a, b)

/* Defines the handler and registers it before main() runs. */
#define LITE_ROUTE(method, path, id)                                              \
    static int LITE_CAT(lite_handler_, id)(void);                                 \
    __attribute__((constructor)) static void LITE_CAT(lite_register_, id)(void) { \
        route_add(path, method, LITE_CAT(lite_handler_, id));                     \
    }                                                                             \
    static int LITE_CAT(lite_handler_, id)(void)

#define GET(path)  LITE_ROUTE(LITE_GET,  path, __COUNTER__)
#define POST(path) LITE_ROUTE(LITE_POST, path, __COUNTER__)

static inline int route_match(const char *pat, const char *path, Request *req) {
    if (!pat || !path || !req) return 0;
    while (*pat && *path) {
        if (*pat == '<') {
            const char *e = strchr(pat, '>');
            if (!e || e == pat + 1 || req->params.n >= LITE_MAX_PARAMS) return 0;
            size_t name_len = (size_t)(e - pat - 1);
            const char *start = path;
            while (*path && *path != '/') path++;
            size_t value_len = (size_t)(path - start);
            char *name = strndup(pat + 1, name_len);
            char *val = strndup(start, value_len);
            if (!name || !val) { free(name); free(val); return 0; }
            percent_decode(val, 0);
            plist_add(&req->params, name, val);
            pat = e + 1;
        } else if (*pat == *path) { pat++; path++; }
        else return 0;
    }
    return *pat == 0 && *path == 0;
}

/* ---------- server ---------- */

static inline const char *status_text(int c) {
    switch (c) {
        case 200: return "OK";
        case 206: return "Partial Content";
        case 201: return "Created";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 429: return "Too Many Requests";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 416: return "Range Not Satisfiable";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        default:  return "OK";
    }
}

static inline void write_all(int fd, const char *s, size_t n) {
    if (!s && n) return;
    while (n > 0) {
        ssize_t w = write(fd, s, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return;
        s += (size_t)w; n -= (size_t)w;
    }
}

/* Strict HTTP/1.x request parsing. The public liteC route/request API is unchanged. */
static inline int lite_http_token_char(unsigned char c) {
    if (isalnum(c)) return 1;
    return strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static inline int lite_parse_http_headers(
    char *buf, size_t header_len,
    char *method, size_t method_cap,
    char *target, size_t target_cap,
    char *content_type, size_t content_type_cap,
    char *cookie, size_t cookie_cap,
    char *csrf_header, size_t csrf_header_cap,
    char *range_header, size_t range_header_cap,
    size_t *content_length, int *error_status)
{
    if (error_status) *error_status = 400;
    if (!buf || !method || !target || !content_type || !cookie || !csrf_header || !range_header ||
        !content_length || header_len < 4) return 0;
    if (header_len > LITE_MAX_HEADER) { if (error_status) *error_status = 431; return 0; }
    if (memchr(buf, '\0', header_len) != NULL) return 0;
    if (memcmp(buf + header_len - 4, "\r\n\r\n", 4) != 0) return 0;

    char *limit = buf + header_len - 2; /* points at final empty line */
    char *line_end = strstr(buf, "\r\n");
    if (!line_end || line_end >= limit) return 0;
    *line_end = 0;

    char *a = buf;
    char *sp1 = strchr(a, ' ');
    if (!sp1 || sp1 == a) return 0;
    *sp1++ = 0;
    char *sp2 = strchr(sp1, ' ');
    if (!sp2 || sp2 == sp1) return 0;
    *sp2++ = 0;
    if (!*sp2 || strchr(sp2, ' ') || strchr(sp2, '\t')) return 0;
    if (strlen(a) >= method_cap) return 0;
    if (strlen(sp1) >= target_cap) { if (error_status) *error_status = 414; return 0; }
    for (const unsigned char *q = (const unsigned char *)a; *q; q++)
        if (!lite_http_token_char(*q)) return 0;
    for (const unsigned char *q = (const unsigned char *)sp1; *q; q++)
        if (*q <= 0x20 || *q == 0x7f || *q == '#') return 0;
    if (sp1[0] != '/') return 0; /* origin-form only; no absolute-form or authority-form */
    if (strcmp(sp2, "HTTP/1.0") && strcmp(sp2, "HTTP/1.1")) return 0;
    strcpy(method, a);
    strcpy(target, sp1);

    content_type[0] = 0;
    cookie[0] = 0;
    csrf_header[0] = 0;
    range_header[0] = 0;
    *content_length = 0;
    int seen_cl = 0, seen_ct = 0, seen_cookie = 0, seen_csrf = 0, seen_range = 0, seen_host = 0;
    unsigned int count = 0;
    char *line = line_end + 2;
    while (line < limit) {
        char *e = strstr(line, "\r\n");
        if (!e || e > limit) return 0;
        if (e == line) break;
        if (++count > LITE_MAX_HEADER_COUNT) return 0;
        if (*line == ' ' || *line == '\t') return 0; /* reject obsolete folding */
        *e = 0;
        char *colon = strchr(line, ':');
        if (!colon || colon == line) return 0;
        *colon++ = 0;
        for (const unsigned char *q = (const unsigned char *)line; *q; q++)
            if (!lite_http_token_char(*q)) return 0;
        while (*colon == ' ' || *colon == '\t') colon++;
        char *v_end = e;
        while (v_end > colon && (v_end[-1] == ' ' || v_end[-1] == '\t')) *--v_end = 0;
        for (const unsigned char *q = (const unsigned char *)colon; *q; q++)
            if ((*q < 0x20 && *q != '\t') || *q == 0x7f) return 0;

        if (!strcasecmp(line, "Content-Length")) {
            if (seen_cl++) return 0; /* duplicate lengths are rejected, even if equal */
            if (!*colon) return 0;
            size_t n = 0;
            for (const unsigned char *q = (const unsigned char *)colon; *q; q++) {
                if (*q < '0' || *q > '9') return 0;
                unsigned int digit = (unsigned int)(*q - '0');
                if (n > (SIZE_MAX - digit) / 10) return 0;
                n = n * 10 + digit;
                if (n > LITE_MAX_REQUEST) { if (error_status) *error_status = 413; return 0; }
            }
            *content_length = n;
        } else if (!strcasecmp(line, "Transfer-Encoding")) {
            return 0; /* chunked is intentionally unsupported; reject TE to prevent ambiguity */
        } else if (!strcasecmp(line, "Content-Type")) {
            if (seen_ct++ || strlen(colon) >= content_type_cap) return 0;
            strcpy(content_type, colon);
        } else if (!strcasecmp(line, "Cookie")) {
            if (seen_cookie++ || strlen(colon) >= cookie_cap) return 0;
            strcpy(cookie, colon);
        } else if (!strcasecmp(line, "X-Lite-CSRF-Token")) {
            if (seen_csrf++ || strlen(colon) >= csrf_header_cap) return 0;
            strcpy(csrf_header, colon);
        } else if (!strcasecmp(line, "Range")) {
            if (seen_range++ || strlen(colon) >= range_header_cap) return 0;
            strcpy(range_header, colon);
        } else if (!strcasecmp(line, "Host")) {
            if (seen_host++ || !*colon) return 0;
        }
        line = e + 2;
    }
    if (!strcmp(sp2, "HTTP/1.1") && !seen_host) return 0;
    return 1;
}


/* ---------- static files ---------- */
/*
 * Configure once before run():
 *     LITE_STATIC_FILES("/static", "static");
 * URL /static/images/a.jpg maps to ./static/images/a.jpg.
 */
static char lite_static_url[128] = "";
static char lite_static_dir[PATH_MAX] = "";

static inline int static_files(const char *url_prefix, const char *directory) {
    if (!url_prefix || !directory || url_prefix[0] != '/' ||
        !url_prefix[1] || strchr(url_prefix, '?') || strchr(url_prefix, '#') ||
        strlen(url_prefix) >= sizeof lite_static_url ||
        strlen(directory) >= sizeof lite_static_dir)
        return 0;

    char resolved[PATH_MAX];
    if (!realpath(directory, resolved))
        return 0;

    struct stat st;
    if (stat(resolved, &st) || !S_ISDIR(st.st_mode))
        return 0;

    strcpy(lite_static_url, url_prefix);
    strcpy(lite_static_dir, resolved);
    return 1;
}

static inline const char *lite_mime_type(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (!strcasecmp(dot, ".html") || !strcasecmp(dot, ".htm")) return "text/html; charset=utf-8";
    if (!strcasecmp(dot, ".css")) return "text/css; charset=utf-8";
    if (!strcasecmp(dot, ".js") || !strcasecmp(dot, ".mjs")) return "text/javascript; charset=utf-8";
    if (!strcasecmp(dot, ".json")) return "application/json";
    if (!strcasecmp(dot, ".txt")) return "text/plain; charset=utf-8";
    if (!strcasecmp(dot, ".svg")) return "image/svg+xml";
    if (!strcasecmp(dot, ".png")) return "image/png";
    if (!strcasecmp(dot, ".jpg") || !strcasecmp(dot, ".jpeg")) return "image/jpeg";
    if (!strcasecmp(dot, ".gif")) return "image/gif";
    if (!strcasecmp(dot, ".webp")) return "image/webp";
    if (!strcasecmp(dot, ".ico")) return "image/x-icon";
    if (!strcasecmp(dot, ".mp3")) return "audio/mpeg";
    if (!strcasecmp(dot, ".wav")) return "audio/wav";
    if (!strcasecmp(dot, ".ogg")) return "audio/ogg";
    if (!strcasecmp(dot, ".m4a")) return "audio/mp4";
    if (!strcasecmp(dot, ".mp4") || !strcasecmp(dot, ".m4v")) return "video/mp4";
    if (!strcasecmp(dot, ".webm")) return "video/webm";
    if (!strcasecmp(dot, ".ogv")) return "video/ogg";
    if (!strcasecmp(dot, ".pdf")) return "application/pdf";
    if (!strcasecmp(dot, ".wasm")) return "application/wasm";
    if (!strcasecmp(dot, ".woff")) return "font/woff";
    if (!strcasecmp(dot, ".woff2")) return "font/woff2";
    if (!strcasecmp(dot, ".ttf")) return "font/ttf";
    return "application/octet-stream";
}

static inline int lite_parse_range(const char *header, off_t size,
                                   off_t *start, off_t *length) {
    if (!header || !*header) {
        *start = 0;
        *length = size;
        return 1;
    }
    if (strncmp(header, "bytes=", 6) != 0 || strchr(header + 6, ',')) return 0;
    const char *p = header + 6;
    if (!*p) return 0;

    char *end = NULL;
    errno = 0;
    if (*p == '-') {
        unsigned long long suffix = strtoull(p + 1, &end, 10);
        if (errno || end == p + 1 || *end || suffix == 0 || size == 0) return 0;
        if (suffix > (unsigned long long)size) suffix = (unsigned long long)size;
        *start = size - (off_t)suffix;
        *length = (off_t)suffix;
        return 1;
    }

    unsigned long long first = strtoull(p, &end, 10);
    if (errno || end == p || *end != '-' || first >= (unsigned long long)size) return 0;
    p = end + 1;
    unsigned long long last = (unsigned long long)size - 1;
    if (*p) {
        last = strtoull(p, &end, 10);
        if (errno || end == p || *end || last < first) return 0;
        if (last >= (unsigned long long)size) last = (unsigned long long)size - 1;
    }
    *start = (off_t)first;
    *length = (off_t)(last - first + 1);
    return 1;
}

static inline int lite_static_serve(Request *req, Response *res) {
    if (!lite_static_url[0] || !req || !res ||
        (req->method != LITE_GET) ||
        strncmp(req->path, lite_static_url, strlen(lite_static_url)) != 0)
        return 0;

    size_t prefix_len = strlen(lite_static_url);
    if (req->path[prefix_len] != '/' || !req->path[prefix_len + 1]) {
        res->status = 404;
        return 1;
    }

    const char *relative = req->path + prefix_len + 1;
    /* Reject encoded paths and traversal/separator tricks rather than guessing. */
    if (strchr(relative, '%') || strchr(relative, '\\') ||
        relative[0] == '/' || strstr(relative, "..")) {
        res->status = 403;
        return 1;
    }

    char candidate[PATH_MAX];
    int n = snprintf(candidate, sizeof candidate, "%s/%s", lite_static_dir, relative);
    if (n < 0 || (size_t)n >= sizeof candidate) {
        res->status = 404;
        return 1;
    }

    char resolved[PATH_MAX];
    if (!realpath(candidate, resolved)) {
        res->status = 404;
        return 1;
    }

    size_t root_len = strlen(lite_static_dir);
    if (strncmp(resolved, lite_static_dir, root_len) != 0 ||
        (resolved[root_len] != '/' && resolved[root_len] != '\0')) {
        res->status = 403;
        return 1;
    }

    struct stat st;
    if (stat(resolved, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) {
        res->status = 404;
        return 1;
    }

    int file = open(resolved, O_RDONLY);
    if (file < 0) {
        res->status = 404;
        return 1;
    }

    off_t offset = 0, length = st.st_size;
    int partial = req->range_header[0] != '\0';
    if (!lite_parse_range(req->range_header, st.st_size, &offset, &length)) {
        close(file);
        res->status = 416;
        res->file_total = st.st_size;
        res->range_invalid = 1;
        snprintf(res->type, sizeof res->type, "text/plain; charset=utf-8");
        return 1;
    }

    res->file_fd = file;
    res->file_offset = offset;
    res->file_length = length;
    res->file_total = st.st_size;
    res->len = 0;
    res->status = partial ? 206 : 200;
    snprintf(res->type, sizeof res->type, "%s", lite_mime_type(resolved));
    return 1;
}

static inline void lite_send_file(int fd, Response *res) {
    char buffer[32768];
    off_t offset = res->file_offset;
    off_t remaining = res->file_length;

    while (remaining > 0) {
        size_t want = remaining > (off_t)sizeof buffer
            ? sizeof buffer : (size_t)remaining;
        ssize_t got = pread(res->file_fd, buffer, want, offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        write_all(fd, buffer, (size_t)got);
        offset += got;
        remaining -= got;
    }
}

#define LITE_STATIC_FILES(url, directory)                                      \
    __attribute__((constructor)) static void LITE_CAT(lite_static_init_, __COUNTER__)(void) { \
        if (!static_files(url, directory))                                      \
            fprintf(stderr, "lite: unable to configure static directory: %s\\n", directory); \
    }

static inline void handle_client(int fd) {
    const size_t total_cap = (size_t)LITE_MAX_HEADER + (size_t)LITE_MAX_REQUEST;
    char *buf = (char *)malloc(total_cap + 1);
    if (!buf) {
        static const char failure[] = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        write_all(fd, failure, sizeof failure - 1);
        return;
    }

    size_t got = 0, header_len = 0, content_length = 0;
    int request_error = 400;
    char method[16] = {0}, target[1024] = {0};
    char content_type[256] = {0}, cookie_header[2048] = {0};
    char csrf_header[128] = {0};
    char range_header[128] = {0};
    int bad_request = 0, headers_parsed = 0;

    /* Read only until the complete header is available, with a hard header cap. */
    while (got < (size_t)LITE_MAX_HEADER) {
        ssize_t r = read(fd, buf + got, (size_t)LITE_MAX_HEADER - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
        buf[got] = 0;
        char *hend = (char *)memmem(buf, got, "\r\n\r\n", 4);
        if (hend) {
            header_len = (size_t)(hend + 4 - buf);
            if (!lite_parse_http_headers(buf, header_len, method, sizeof method,
                                         target, sizeof target, content_type,
                                         sizeof content_type, cookie_header,
                                         sizeof cookie_header, csrf_header,
                                         sizeof csrf_header, range_header,
                                         sizeof range_header, &content_length, &request_error))
                bad_request = 1;
            else headers_parsed = 1;
            break;
        }
    }
    if (!header_len) {
        bad_request = 1; /* incomplete or oversized header */
        if (got >= (size_t)LITE_MAX_HEADER) request_error = 431;
    }

    char *body = header_len ? buf + header_len : NULL;
    if (headers_parsed && !strcmp(method, "GET") && content_length != 0)
        bad_request = 1;
    if (headers_parsed && content_length > LITE_MAX_REQUEST)
        bad_request = 1;

    size_t expected = header_len + content_length;
    if (expected > total_cap) bad_request = 1;
    while (!bad_request && got < expected) {
        ssize_t r = read(fd, buf + got, expected - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { bad_request = 1; break; }
        got += (size_t)r;
    }
    if (!bad_request && body) {
        if (got < expected) bad_request = 1;
        else body[content_length] = 0;
    }

    Request req = {0};
    Response res = {0};
    res.file_fd = -1;
    res.status = bad_request ? request_error : 200;
    snprintf(res.type, sizeof res.type, "text/html; charset=utf-8");
    lite_req = &req;
    lite_res = &res;
    snprintf(req.csrf_header, sizeof req.csrf_header, "%s", csrf_header);
    snprintf(req.range_header, sizeof req.range_header, "%s", range_header);
    struct sockaddr_in peer_addr;
    socklen_t peer_len = sizeof peer_addr;
    if (getpeername(fd, (struct sockaddr *)&peer_addr, &peer_len) == 0)
        inet_ntop(AF_INET, &peer_addr.sin_addr, req.client_ip, sizeof req.client_ip);
    if (!req.client_ip[0]) snprintf(req.client_ip, sizeof req.client_ip, "unknown");
    lite_sess = NULL;

    if (!bad_request && cookie_header[0]) {
        parse_cookies(&req.cookies, cookie_header);
        lite_sess = session_find(plist_get(&req.cookies, "lite_sid"));
    }

    int csrf_failed = 0;
    if (!bad_request && (!strcmp(method, "GET") || !strcmp(method, "POST"))) {
        req.method = !strcmp(method, "POST") ? LITE_POST : LITE_GET;
        char *q = strchr(target, '?');
        if (q) { *q = 0; parse_urlencoded(&req.query, q + 1); }
        if (strlen(target) >= sizeof req.path) bad_request = 1;
        else strcpy(req.path, target);

        if (!bad_request && req.method == LITE_POST) {
            req.body = (const unsigned char *)body;
            req.body_len = content_length;
            snprintf(req.content_type, sizeof req.content_type, "%s", content_type);
            if (!strncasecmp(req.content_type, "application/x-www-form-urlencoded", 33)) {
                if (memchr(body, '\0', content_length) != NULL) bad_request = 1;
                else parse_urlencoded(&req.form, body);
            }
            if (!bad_request && !lite_csrf_valid()) csrf_failed = 1;
        }

        if (!bad_request && !csrf_failed) {
            int static_handled = lite_static_serve(&req, &res);
            int found = static_handled, path_only = 0;
            for (size_t i = 0; i < lite_nroutes && !found; i++) {
                if (route_match(lite_routes[i].pattern, req.path, &req)) {
                    if (lite_routes[i].method == req.method) {
                        if (!lite_rate_limit_allow(req.path, req.client_ip)) {
                            res.status = 429;
                        } else {
                            int st = lite_routes[i].fn();
                            if (st) res.status = st;
                        }
                        found = 1;
                        break;
                    }
                    path_only = 1;
                }
                plist_free(&req.params);
            }
            if (!found) res.status = path_only ? 405 : 404;
        } else if (csrf_failed) res.status = 403;
        else res.status = 400;
    } else if (!bad_request) {
        res.status = 405;
    }

    if (res.cookie_error) res.status = 500;
    if (res.status < 400 && !lite_csrf_html_forms(&res)) res.status = 500;

    if (!res.body) {
        if (res.status >= 400) text("%d %s", res.status, status_text(res.status));
        else { res.body = strdup(""); res.len = 0; }
    }
    if (!res.body) { res.status = 500; res.len = 0; }

    Buf out = {0};
    size_t response_length = res.file_fd >= 0
        ? (size_t)res.file_length : res.len;
    buf_addf(&out, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nAccept-Ranges: bytes\r\nConnection: close\r\n",
             res.status, status_text(res.status), res.type, response_length);
    if (res.file_fd >= 0 && res.status == 206)
        buf_addf(&out, "Content-Range: bytes %lld-%lld/%lld\r\n",
                 (long long)res.file_offset,
                 (long long)(res.file_offset + res.file_length - 1),
                 (long long)res.file_total);
    if (res.location[0]) buf_addf(&out, "Location: %s\r\n", res.location);
    for (size_t i = 0; i < res.ncookies; i++) buf_addf(&out, "Set-Cookie: %s\r\n", res.cookies[i]);
    buf_add(&out, "\r\n", 2);
    if (!out.failed && out.d) write_all(fd, out.d, out.len);
    free(out.d);

    if (res.file_fd >= 0) {
        if (res.status < 400) lite_send_file(fd, &res);
        close(res.file_fd);
    } else if (res.len && res.body) {
        write_all(fd, res.body, res.len);
    }

    plist_free(&req.query); plist_free(&req.form); plist_free(&req.params); plist_free(&req.cookies);
    temp_free();
    free(res.body);
    for (size_t i = 0; i < res.ncookies; i++) free(res.cookies[i]);
    free(res.cookies);
    free(buf);
    lite_req = NULL;
    lite_res = NULL;
    lite_sess = NULL;
}

static inline void lite_run(int port) {
    if (lite_route_error || lite_rate_error) {
        fprintf(stderr, "lite: unable to register routes (out of memory or invalid route)\\n");
        free(lite_routes);
        lite_routes = NULL;
        lite_nroutes = lite_route_capacity = 0;
        free(lite_rate_rules); lite_rate_rules = NULL;
        lite_rate_rule_count = lite_rate_rule_capacity = 0;
        free(lite_rate_buckets); lite_rate_buckets = NULL;
        lite_rate_bucket_count = lite_rate_bucket_capacity = 0;
        return;
    }

    signal(SIGPIPE, SIG_IGN);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("lite socket"); return; }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((unsigned short)port);

    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 64) < 0) {
        perror("lite");
        exit(1);
    }
    printf("Running on http://127.0.0.1:%d (Ctrl+C to quit)\n", port);

    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        struct timeval tv = { 5, 0 };
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        handle_client(c);
        close(c);
    }
}

/* run(8080);  put this at the bottom of your file. It writes main() for you. */
#define run(port)                                   \
    int main(void) { lite_run(port); return 0; }    \
    typedef int lite_end_of_file_t

#endif /* LITE_H */
