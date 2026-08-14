#define _POSIX_C_SOURCE 200809L

/*
 * Reactive Web Firewall - local privileged helper
 *
 * Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Runs on the same host as Apache/mod_rwf (normally the reverse proxy).
 * Receives trusted AF_UNIX/SOCK_DGRAM events from mod_rwf and performs the
 * privileged blocking workflow locally. Two backends are supported:
 *
 *   local-only:
 *     whitelist -> marker -> nftables using the rule policy -> socket kill
 *
 *   openwrt:
 *     whitelist -> marker -> short local fallback -> socket kill -> SSH OpenWrt
 *     -> second socket kill -> remove local fallback after remote confirmation
 *
 * If OpenWrt is unavailable, the local fallback is deliberately retained until
 * its timeout. Recognition/classification is intentionally NOT performed here:
 * the rule and policy supplied by mod_rwf are authoritative.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define RWF_DEFAULT_SOCKET        "/run/reactive-web-firewall/helper.sock"
#define RWF_DEFAULT_WHITELIST     "/etc/reactive-web-firewall/whitelist.conf"
#define RWF_DEFAULT_FASTBAN       "/usr/local/sbin/custom-web-fastban"
#define RWF_DEFAULT_FASTBAN_TTL   "5m"
#define RWF_DEFAULT_SS            "/usr/bin/ss"
#define RWF_DEFAULT_SSH           "/usr/bin/ssh"
#define RWF_DEFAULT_SSH_KEY       "/etc/reactive-web-firewall/openwrt_rwf_ed25519"
#define RWF_DEFAULT_KNOWN_HOSTS   "/etc/reactive-web-firewall/openwrt_known_hosts"
#define RWF_DEFAULT_FIREWALL      ""
#define RWF_DEFAULT_CONTROL       "/run/reactive-web-firewall/openwrt-ssh-%C"
#define RWF_DEFAULT_ACTIVE_DIR    "/run/custom-web-ban/active"
#define RWF_DEFAULT_LFD_SUPPRESS  90
#define RWF_DEFAULT_MAX_WORKERS   32
#define RWF_DEFAULT_SSH_PORT      22
#define RWF_DEFAULT_REMOTE_MODE   0
#define RWF_EVENT_MAX             4096
#define RWF_IP_MAX                INET6_ADDRSTRLEN
#define RWF_FIELD_SMALL           128
#define RWF_FIELD_MEDIUM          256
#define RWF_FIELD_URI             1024
#define RWF_PATH_MAX              512

static volatile sig_atomic_t rwf_running = 1;
static volatile sig_atomic_t rwf_sigchld = 0;
static int rwf_active_workers = 0;

typedef struct {
    const char *socket_path;
    const char *whitelist_path;
    const char *fastban_path;
    const char *fastban_ttl;
    const char *ss_path;
    const char *ssh_path;
    const char *ssh_key;
    const char *known_hosts;
    const char *firewall;
    const char *control_path;
    const char *active_dir;
    unsigned int lfd_suppress_seconds;
    unsigned int ssh_port;
    int remote_enabled;
    int max_workers;
} rwf_config;

typedef struct {
    char ip[RWF_IP_MAX];
    char host[RWF_FIELD_MEDIUM];
    char method[32];
    char uri[RWF_FIELD_URI];
    char rule[RWF_FIELD_SMALL];
    char policy[64];
    int permanent;
    unsigned int seconds;
    int disabled;
    int64_t source_ts_us;
} rwf_event;

typedef struct {
    pid_t pid;
    char ip[RWF_IP_MAX];
    int64_t started_us;
} rwf_worker;

static rwf_worker *workers = NULL;
static int workers_len = 0;

static int64_t realtime_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return ((int64_t) ts.tv_sec * 1000000LL) + (ts.tv_nsec / 1000);
}

static int64_t monotonic_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return ((int64_t) ts.tv_sec * 1000000LL) + (ts.tv_nsec / 1000);
}

static void on_term(int signo)
{
    (void) signo;
    rwf_running = 0;
}

static void on_chld(int signo)
{
    (void) signo;
    rwf_sigchld = 1;
}

static char *trim(char *s)
{
    char *end;

    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') {
        ++s;
    }

    if (*s == '\0') {
        return s;
    }

    end = s + strlen(s) - 1;

    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end-- = '\0';
    }

    return s;
}

static int prefix_match(const unsigned char *addr,
                        const unsigned char *net,
                        unsigned int prefix,
                        unsigned int total_bits)
{
    unsigned int full_bytes;
    unsigned int rem_bits;
    unsigned int i;

    if (prefix > total_bits) {
        return 0;
    }

    full_bytes = prefix / 8;
    rem_bits = prefix % 8;

    for (i = 0; i < full_bytes; ++i) {
        if (addr[i] != net[i]) {
            return 0;
        }
    }

    if (rem_bits != 0) {
        unsigned char mask = (unsigned char) (0xffu << (8u - rem_bits));
        if ((addr[full_bytes] & mask) != (net[full_bytes] & mask)) {
            return 0;
        }
    }

    return 1;
}

/*
 *  1 = whitelisted
 *  0 = not whitelisted
 * -1 = whitelist cannot be evaluated safely -> fail-safe, do not ban
 */
static int ip_whitelisted(const char *filename, const char *ip)
{
    FILE *fh;
    char line[1024];
    unsigned char ipbuf[16];
    int family;
    unsigned int total_bits;

    if (inet_pton(AF_INET, ip, ipbuf) == 1) {
        family = AF_INET;
        total_bits = 32;
    }
    else if (inet_pton(AF_INET6, ip, ipbuf) == 1) {
        family = AF_INET6;
        total_bits = 128;
    }
    else {
        return -1;
    }

    fh = fopen(filename, "r");
    if (fh == NULL) {
        syslog(LOG_ERR,
               "whitelist-open-failed file=%s errno=%d error=%s action=drop-event",
               filename, errno, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fh) != NULL) {
        char *p;
        char *hash;
        char *spec;
        char work[256];
        char *slash;
        char *endptr;
        long prefix_long;
        unsigned int prefix;
        unsigned char netbuf[16];
        int net_family;

        hash = strchr(line, '#');
        if (hash != NULL) {
            *hash = '\0';
        }

        p = trim(line);
        if (*p == '\0') {
            continue;
        }

        if (strncmp(p, "RwfWhitelistIP", 14) != 0 ||
            (p[14] != ' ' && p[14] != '\t')) {
            syslog(LOG_ERR,
                   "whitelist-invalid-line file=%s line=[%s] action=drop-event",
                   filename, p);
            fclose(fh);
            return -1;
        }

        spec = trim(p + 14);
        if (*spec == '\0' || strlen(spec) >= sizeof(work)) {
            fclose(fh);
            return -1;
        }

        snprintf(work, sizeof(work), "%s", spec);
        slash = strrchr(work, '/');

        if (slash != NULL) {
            *slash++ = '\0';
            errno = 0;
            prefix_long = strtol(slash, &endptr, 10);
            if (errno != 0 || *slash == '\0' || *endptr != '\0' || prefix_long < 0) {
                fclose(fh);
                return -1;
            }
            prefix = (unsigned int) prefix_long;
        }
        else {
            prefix = strchr(work, ':') != NULL ? 128u : 32u;
        }

        if (inet_pton(AF_INET, work, netbuf) == 1) {
            net_family = AF_INET;
            if (prefix > 32u) {
                fclose(fh);
                return -1;
            }
        }
        else if (inet_pton(AF_INET6, work, netbuf) == 1) {
            net_family = AF_INET6;
            if (prefix > 128u) {
                fclose(fh);
                return -1;
            }
        }
        else {
            fclose(fh);
            return -1;
        }

        if (family == net_family && prefix_match(ipbuf, netbuf, prefix, total_bits)) {
            fclose(fh);
            return 1;
        }
    }

    if (ferror(fh)) {
        fclose(fh);
        return -1;
    }

    fclose(fh);
    return 0;
}

static int extract_field(const char *event,
                         const char *key,
                         char *out,
                         size_t out_size)
{
    const char *p = event;
    size_t key_len = strlen(key);

    if (out_size == 0) {
        return 0;
    }

    out[0] = '\0';

    while (*p != '\0') {
        const char *end = strchr(p, '\t');
        size_t len = end != NULL ? (size_t) (end - p) : strlen(p);

        if (len > key_len + 1 &&
            memcmp(p, key, key_len) == 0 &&
            p[key_len] == '=') {

            size_t value_len = len - key_len - 1;

            if (value_len >= out_size) {
                return 0;
            }

            memcpy(out, p + key_len + 1, value_len);
            out[value_len] = '\0';
            return 1;
        }

        if (end == NULL) {
            break;
        }

        p = end + 1;
    }

    return 0;
}

static int valid_rule_name(const char *rule)
{
    const unsigned char *p;

    if (rule == NULL || *rule == '\0') {
        return 0;
    }

    p = (const unsigned char *) rule;
    while (*p != '\0') {
        if (!isalnum(*p) && *p != '_' && *p != '-' && *p != '.') {
            return 0;
        }
        ++p;
    }

    return 1;
}

static int parse_policy(const char *raw,
                        int *disabled,
                        int *permanent,
                        unsigned int *seconds)
{
    char work[64];
    size_t len;
    char suffix = '\0';
    unsigned long long n;
    unsigned long long mult = 1;
    char *endptr;

    *disabled = 0;
    *permanent = 0;
    *seconds = 0;

    if (raw == NULL || *raw == '\0' || strlen(raw) >= sizeof(work)) {
        return 0;
    }

    snprintf(work, sizeof(work), "%s", raw);

    for (len = 0; work[len] != '\0'; ++len) {
        work[len] = (char) tolower((unsigned char) work[len]);
    }

    if (strcmp(work, "off") == 0 || strcmp(work, "0") == 0 ||
        strcmp(work, "disabled") == 0) {
        *disabled = 1;
        return 1;
    }

    if (strcmp(work, "permanent") == 0 || strcmp(work, "perm") == 0 ||
        strcmp(work, "1") == 0 || strcmp(work, "forever") == 0) {
        *permanent = 1;
        return 1;
    }

    len = strlen(work);
    if (len == 0) {
        return 0;
    }

    if (isalpha((unsigned char) work[len - 1])) {
        suffix = work[len - 1];
        work[len - 1] = '\0';
    }

    errno = 0;
    n = strtoull(work, &endptr, 10);
    if (errno != 0 || *work == '\0' || *endptr != '\0' || n == 0) {
        return 0;
    }

    switch (suffix) {
        case '\0': mult = 1; break;
        case 's': mult = 1; break;
        case 'm': mult = 60; break;
        case 'h': mult = 3600; break;
        case 'd': mult = 86400; break;
        case 'w': mult = 604800; break;
        default: return 0;
    }

    if (n > 4294967295ULL / mult) {
        return 0;
    }

    n *= mult;
    if (n == 0 || n > 4294967295ULL) {
        return 0;
    }

    *seconds = (unsigned int) n;
    return 1;
}

static int parse_event(const char *raw, rwf_event *ev)
{
    char version[16];
    char tsbuf[64];
    char *endptr;
    long long ts;
    unsigned char packed[16];

    memset(ev, 0, sizeof(*ev));

    if (!extract_field(raw, "v", version, sizeof(version)) || strcmp(version, "1") != 0) {
        return 0;
    }

    if (!extract_field(raw, "ip", ev->ip, sizeof(ev->ip)) ||
        (inet_pton(AF_INET, ev->ip, packed) != 1 && inet_pton(AF_INET6, ev->ip, packed) != 1)) {
        return 0;
    }

    if (!extract_field(raw, "host", ev->host, sizeof(ev->host)) ||
        !extract_field(raw, "method", ev->method, sizeof(ev->method)) ||
        !extract_field(raw, "uri", ev->uri, sizeof(ev->uri)) ||
        !extract_field(raw, "rule", ev->rule, sizeof(ev->rule)) ||
        !extract_field(raw, "policy", ev->policy, sizeof(ev->policy))) {
        return 0;
    }

    if (!valid_rule_name(ev->rule)) {
        return 0;
    }

    if (!parse_policy(ev->policy, &ev->disabled, &ev->permanent, &ev->seconds)) {
        return 0;
    }

    ev->source_ts_us = 0;
    if (extract_field(raw, "ts_us", tsbuf, sizeof(tsbuf))) {
        errno = 0;
        ts = strtoll(tsbuf, &endptr, 10);
        if (errno == 0 && *tsbuf != '\0' && *endptr == '\0' && ts > 0) {
            ev->source_ts_us = (int64_t) ts;
        }
    }

    return 1;
}

static int ensure_dir(const char *path, mode_t mode)
{
    struct stat st;

    if (stat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            errno = ENOTDIR;
            return -1;
        }
        (void) chmod(path, mode);
        return 0;
    }

    if (errno != ENOENT) {
        return -1;
    }

    if (mkdir(path, mode) != 0 && errno != EEXIST) {
        return -1;
    }

    (void) chmod(path, mode);
    return 0;
}

static int marker_path(char *out, size_t out_size, const rwf_config *cfg, const char *ip)
{
    int n = snprintf(out, out_size, "%s/%s", cfg->active_dir, ip);
    return n > 0 && (size_t) n < out_size;
}

static int write_marker(const rwf_config *cfg,
                        const rwf_event *ev,
                        time_t expires,
                        const char *mode)
{
    char path[RWF_PATH_MAX];
    char tmp[RWF_PATH_MAX + 64];
    FILE *fh;
    int n;

    if (!marker_path(path, sizeof(path), cfg, ev->ip)) {
        return -1;
    }

    n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long) getpid());
    if (n <= 0 || (size_t) n >= sizeof(tmp)) {
        return -1;
    }

    fh = fopen(tmp, "w");
    if (fh == NULL) {
        return -1;
    }

    fprintf(fh,
            "%lld\t%s\t%s\t%lld\trwf:%s\n",
            (long long) expires,
            ev->rule,
            mode,
            (long long) time(NULL),
            ev->rule);

    if (fclose(fh) != 0) {
        unlink(tmp);
        return -1;
    }

    (void) chmod(tmp, 0600);

    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }

    return 0;
}

static void remove_marker(const rwf_config *cfg, const char *ip)
{
    char path[RWF_PATH_MAX];

    if (marker_path(path, sizeof(path), cfg, ip)) {
        (void) unlink(path);
    }
}

static int run_quiet(char *const argv[])
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0) {
        return 255;
    }

    if (pid == 0) {
        int nullfd = open("/dev/null", O_RDWR);
        if (nullfd >= 0) {
            (void) dup2(nullfd, STDOUT_FILENO);
            (void) dup2(nullfd, STDERR_FILENO);
            if (nullfd > STDERR_FILENO) {
                close(nullfd);
            }
        }

        execv(argv[0], argv);
        _exit(127);
    }

    do {
        if (waitpid(pid, &status, 0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 255;
        }
        break;
    } while (1);

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    return 255;
}

static int local_fastban(const rwf_config *cfg,
                         const char *action,
                         const char *ip,
                         const char *ttl)
{
    char *argv_add[] = {
        (char *) cfg->fastban_path,
        "add",
        (char *) ip,
        (char *) ttl,
        NULL
    };
    char *argv_del[] = {
        (char *) cfg->fastban_path,
        "del",
        (char *) ip,
        NULL
    };

    return run_quiet(strcmp(action, "add") == 0 ? argv_add : argv_del);
}

static void event_local_ttl(const rwf_event *ev, char *out, size_t out_size)
{
    if (ev->permanent) {
        snprintf(out, out_size, "permanent");
    }
    else {
        snprintf(out, out_size, "%us", ev->seconds);
    }
}

static time_t ttl_expiry_from_policy(const char *policy, time_t now)
{
    int disabled = 0;
    int permanent = 0;
    unsigned int seconds = 0;

    if (!parse_policy(policy, &disabled, &permanent, &seconds) || disabled) {
        return now;
    }
    if (permanent) {
        return 0;
    }
    return now + (time_t) seconds;
}

static int kill_sockets_one(const rwf_config *cfg, const char *ip, const char *port)
{
    char port_expr[16];
    char *argv[] = {
        (char *) cfg->ss_path,
        "-K",
        "-H",
        "-n",
        "-t",
        "state",
        "connected",
        "dst",
        (char *) ip,
        "sport",
        "=",
        port_expr,
        NULL
    };

    snprintf(port_expr, sizeof(port_expr), ":%s", port);
    return run_quiet(argv);
}

static int kill_sockets(const rwf_config *cfg,
                        const rwf_event *ev,
                        const char *phase,
                        int64_t *elapsed_us)
{
    static const char *ports[] = { "80", "443" };
    int failures = 0;
    int i;
    int64_t started = monotonic_us();

    for (i = 0; i < 2; ++i) {
        int rc = kill_sockets_one(cfg, ev->ip, ports[i]);
        if (rc != 0) {
            ++failures;
        }
    }

    *elapsed_us = monotonic_us() - started;

    syslog(failures ? LOG_WARNING : LOG_NOTICE,
           "socket-kill ip=%s phase=%s ports=80,443 attempts=2 failures=%d rc=%d elapsed_us=%lld",
           ev->ip,
           phase,
           failures,
           failures ? 1 : 0,
           (long long) *elapsed_us);

    return failures ? 1 : 0;
}

static int run_remote(const rwf_config *cfg,
                      const rwf_event *ev,
                      char *command,
                      size_t command_size,
                      int64_t *elapsed_us)
{
    char known_opt[RWF_PATH_MAX + 64];
    char control_opt[RWF_PATH_MAX + 64];
    char seconds_buf[32];
    char source[RWF_FIELD_SMALL + 16];
    char *argv[40];
    int argc = 0;
    int rc;
    int64_t started;

    if (ev->permanent) {
        snprintf(command, command_size, "sync-add %s", ev->ip);
    }
    else {
        size_t i;
        snprintf(seconds_buf, sizeof(seconds_buf), "%u", ev->seconds);
        snprintf(source, sizeof(source), "RWF_%s", ev->rule);
        for (i = 0; source[i] != '\0'; ++i) {
            if (!isalnum((unsigned char) source[i]) && source[i] != '_') {
                source[i] = '_';
            }
        }
        snprintf(command,
                 command_size,
                 "temp-add %s %s proxy %s",
                 ev->ip,
                 seconds_buf,
                 source);
    }

    snprintf(known_opt, sizeof(known_opt), "UserKnownHostsFile=%s", cfg->known_hosts);
    snprintf(control_opt, sizeof(control_opt), "ControlPath=%s", cfg->control_path);

    argv[argc++] = (char *) cfg->ssh_path;
    argv[argc++] = "-F";
    argv[argc++] = "/dev/null";
    argv[argc++] = "-i";
    argv[argc++] = (char *) cfg->ssh_key;
    argv[argc++] = "-p";
    snprintf(seconds_buf, sizeof(seconds_buf), "%u", cfg->ssh_port);
    argv[argc++] = seconds_buf;
    argv[argc++] = "-o";
    argv[argc++] = "IdentitiesOnly=yes";
    argv[argc++] = "-o";
    argv[argc++] = "BatchMode=yes";
    argv[argc++] = "-o";
    argv[argc++] = "StrictHostKeyChecking=yes";
    argv[argc++] = "-o";
    argv[argc++] = known_opt;
    argv[argc++] = "-o";
    argv[argc++] = "ConnectTimeout=2";
    argv[argc++] = "-o";
    argv[argc++] = "ConnectionAttempts=1";
    argv[argc++] = "-o";
    argv[argc++] = "ServerAliveInterval=2";
    argv[argc++] = "-o";
    argv[argc++] = "ServerAliveCountMax=1";
    argv[argc++] = "-o";
    argv[argc++] = "ControlMaster=auto";
    argv[argc++] = "-o";
    argv[argc++] = "ControlPersist=600";
    argv[argc++] = "-o";
    argv[argc++] = control_opt;
    argv[argc++] = "-o";
    argv[argc++] = "LogLevel=ERROR";
    argv[argc++] = (char *) cfg->firewall;
    argv[argc++] = command;
    argv[argc] = NULL;

    started = monotonic_us();
    rc = run_quiet(argv);
    *elapsed_us = monotonic_us() - started;

    return rc;
}

static void process_event(const rwf_config *cfg, const rwf_event *ev)
{
    int wl;
    int fastban_rc;
    int fastban_active;
    int fastban_del_rc = 0;
    int remote_rc = 0;
    int64_t worker_start_us;
    int64_t fastban_us;
    int64_t socket_pre_us = 0;
    int64_t remote_us = 0;
    int64_t socket_post_us = 0;
    int64_t fastban_del_us = 0;
    int64_t worker_total_us;
    int64_t source_to_local_block_us = -1;
    int64_t source_to_remote_done_us = -1;
    int64_t started;
    time_t now;
    time_t marker_expiry;
    char remote_command[512];
    char local_ttl[64];
    const char *mode;
    const char *backend;

    worker_start_us = monotonic_us();

    wl = ip_whitelisted(cfg->whitelist_path, ev->ip);
    if (wl != 0) {
        if (wl > 0) {
            syslog(LOG_WARNING,
                   "whitelist-hit ip=%s rule=%s action=refuse-ban",
                   ev->ip,
                   ev->rule);
        }
        return;
    }

    if (ev->disabled) {
        syslog(LOG_NOTICE,
               "event-skipped ip=%s rule=%s policy=%s reason=policy-off",
               ev->ip,
               ev->rule,
               ev->policy);
        return;
    }

    now = time(NULL);
    if (write_marker(cfg, ev, now + 30, "pending") != 0) {
        syslog(LOG_ERR,
               "marker-write-failed ip=%s rule=%s phase=pending errno=%d error=%s action=abort-ban",
               ev->ip,
               ev->rule,
               errno,
               strerror(errno));
        return;
    }

    mode = ev->permanent ? "permanent" : "temporary";
    backend = cfg->remote_enabled ? "openwrt" : "local";
    if (cfg->remote_enabled) {
        snprintf(local_ttl, sizeof(local_ttl), "%s", cfg->fastban_ttl);
    }
    else {
        event_local_ttl(ev, local_ttl, sizeof(local_ttl));
    }

    syslog(LOG_WARNING,
           "match ip=%s rule=%s policy=%s mode=%s backend=%s host=%s method=%s uri=[%s] source_ts_us=%lld",
           ev->ip,
           ev->rule,
           ev->policy,
           mode,
           backend,
           ev->host,
           ev->method,
           ev->uri,
           (long long) ev->source_ts_us);

    started = monotonic_us();
    fastban_rc = local_fastban(cfg, "add", ev->ip, local_ttl);
    fastban_us = monotonic_us() - started;
    fastban_active = fastban_rc == 0;

    if (fastban_active && ev->source_ts_us > 0) {
        int64_t now_real = realtime_us();
        if (now_real >= ev->source_ts_us) {
            source_to_local_block_us = now_real - ev->source_ts_us;
        }
    }

    syslog(fastban_active ? LOG_NOTICE : LOG_WARNING,
           "local-fastban-add ip=%s ttl=%s backend=%s active=%d rc=%d elapsed_us=%lld source_to_local_block_us=%lld",
           ev->ip,
           local_ttl,
           backend,
           fastban_active,
           fastban_rc,
           (long long) fastban_us,
           (long long) source_to_local_block_us);

    (void) kill_sockets(cfg, ev, "pre", &socket_pre_us);

    if (!cfg->remote_enabled) {
        worker_total_us = monotonic_us() - worker_start_us;
        if (fastban_active) {
            now = time(NULL);
            marker_expiry = ev->permanent ? 0 : now + (time_t) ev->seconds;
            if (write_marker(cfg, ev, marker_expiry, mode) != 0) {
                syslog(LOG_ERR,
                       "marker-write-failed ip=%s rule=%s phase=local-confirmed errno=%d error=%s",
                       ev->ip,
                       ev->rule,
                       errno,
                       strerror(errno));
            }
            syslog(LOG_NOTICE,
                   "ban-applied ip=%s rule=%s policy=%s mode=%s backend=local rc=0 local_ttl=%s "
                   "source_to_local_block_us=%lld local_fastban_us=%lld socket_pre_us=%lld worker_total_us=%lld",
                   ev->ip,
                   ev->rule,
                   ev->policy,
                   mode,
                   local_ttl,
                   (long long) source_to_local_block_us,
                   (long long) fastban_us,
                   (long long) socket_pre_us,
                   (long long) worker_total_us);
        }
        else {
            remove_marker(cfg, ev->ip);
            syslog(LOG_ERR,
                   "ban-failed ip=%s rule=%s policy=%s mode=%s backend=local rc=%d local_ttl=%s "
                   "source_to_local_block_us=%lld local_fastban_us=%lld socket_pre_us=%lld worker_total_us=%lld",
                   ev->ip,
                   ev->rule,
                   ev->policy,
                   mode,
                   fastban_rc,
                   local_ttl,
                   (long long) source_to_local_block_us,
                   (long long) fastban_us,
                   (long long) socket_pre_us,
                   (long long) worker_total_us);
        }
        return;
    }

    remote_command[0] = '\0';
    remote_rc = run_remote(cfg, ev, remote_command, sizeof(remote_command), &remote_us);

    if (ev->source_ts_us > 0) {
        int64_t now_real = realtime_us();
        if (now_real >= ev->source_ts_us) {
            source_to_remote_done_us = now_real - ev->source_ts_us;
        }
    }

    if (remote_rc == 0) {
        (void) kill_sockets(cfg, ev, "post", &socket_post_us);

        if (fastban_active) {
            started = monotonic_us();
            fastban_del_rc = local_fastban(cfg, "del", ev->ip, local_ttl);
            fastban_del_us = monotonic_us() - started;

            syslog(fastban_del_rc == 0 ? LOG_NOTICE : LOG_WARNING,
                   "local-fastban-del ip=%s reason=remote-confirmed rc=%d elapsed_us=%lld",
                   ev->ip,
                   fastban_del_rc,
                   (long long) fastban_del_us);
        }

        now = time(NULL);
        if (write_marker(cfg,
                         ev,
                         now + (time_t) cfg->lfd_suppress_seconds,
                         mode) != 0) {
            syslog(LOG_ERR,
                   "marker-write-failed ip=%s rule=%s phase=confirmed errno=%d error=%s",
                   ev->ip,
                   ev->rule,
                   errno,
                   strerror(errno));
        }

        worker_total_us = monotonic_us() - worker_start_us;

        syslog(LOG_NOTICE,
               "ban-applied ip=%s rule=%s policy=%s mode=%s backend=openwrt rc=0 remote_command=[%s] "
               "source_to_local_block_us=%lld source_to_remote_done_us=%lld "
               "local_fastban_us=%lld socket_pre_us=%lld remote_us=%lld socket_post_us=%lld "
               "local_fastban_del_us=%lld worker_total_us=%lld lfd_suppress=%us",
               ev->ip,
               ev->rule,
               ev->policy,
               mode,
               remote_command,
               (long long) source_to_local_block_us,
               (long long) source_to_remote_done_us,
               (long long) fastban_us,
               (long long) socket_pre_us,
               (long long) remote_us,
               (long long) socket_post_us,
               (long long) fastban_del_us,
               (long long) worker_total_us,
               cfg->lfd_suppress_seconds);
    }
    else {
        now = time(NULL);
        if (fastban_active) {
            marker_expiry = ttl_expiry_from_policy(cfg->fastban_ttl, now);
            if (write_marker(cfg, ev, marker_expiry, "fallback-local") != 0) {
                syslog(LOG_ERR,
                       "marker-write-failed ip=%s rule=%s phase=fallback errno=%d error=%s",
                       ev->ip,
                       ev->rule,
                       errno,
                       strerror(errno));
            }
        }
        else {
            remove_marker(cfg, ev->ip);
        }
        worker_total_us = monotonic_us() - worker_start_us;

        syslog(LOG_ERR,
               "ban-failed ip=%s rule=%s policy=%s mode=%s backend=openwrt rc=%d remote_command=[%s] "
               "local_fastban_active=%d local_fastban_retained=%d fallback_ttl=%s "
               "source_to_local_block_us=%lld source_to_remote_done_us=%lld "
               "local_fastban_us=%lld socket_pre_us=%lld remote_us=%lld worker_total_us=%lld",
               ev->ip,
               ev->rule,
               ev->policy,
               mode,
               remote_rc,
               remote_command,
               fastban_active,
               fastban_active ? 1 : 0,
               cfg->fastban_ttl,
               (long long) source_to_local_block_us,
               (long long) source_to_remote_done_us,
               (long long) fastban_us,
               (long long) socket_pre_us,
               (long long) remote_us,
               (long long) worker_total_us);
    }
}

static void worker_add(pid_t pid, const char *ip, int64_t started_us)
{
    int i;

    for (i = 0; i < workers_len; ++i) {
        if (workers[i].pid == 0) {
            workers[i].pid = pid;
            snprintf(workers[i].ip, sizeof(workers[i].ip), "%s", ip);
            workers[i].started_us = started_us;
            ++rwf_active_workers;
            return;
        }
    }
}

static void worker_complete(pid_t pid, int status)
{
    int i;

    for (i = 0; i < workers_len; ++i) {
        if (workers[i].pid == pid) {
            int rc = 255;
            int64_t elapsed_us = monotonic_us() - workers[i].started_us;

            if (WIFEXITED(status)) {
                rc = WEXITSTATUS(status);
            }
            else if (WIFSIGNALED(status)) {
                rc = 128 + WTERMSIG(status);
            }

            syslog(rc == 0 ? LOG_DEBUG : LOG_ERR,
                   "worker-complete ip=%s pid=%ld rc=%d elapsed_us=%lld",
                   workers[i].ip,
                   (long) pid,
                   rc,
                   (long long) elapsed_us);

            workers[i].pid = 0;
            workers[i].ip[0] = '\0';
            workers[i].started_us = 0;

            if (rwf_active_workers > 0) {
                --rwf_active_workers;
            }
            return;
        }
    }
}

static void reap_workers(int blocking_one)
{
    int status;
    pid_t pid;

    do {
        pid = waitpid(-1, &status, blocking_one ? 0 : WNOHANG);
        if (pid > 0) {
            worker_complete(pid, status);
            blocking_one = 0;
        }
    } while (pid > 0);

    rwf_sigchld = 0;
}

static int spawn_worker(const rwf_config *cfg, const rwf_event *ev)
{
    pid_t pid;
    int64_t started_us;

    while (rwf_active_workers >= cfg->max_workers && rwf_running) {
        reap_workers(1);
    }

    if (!rwf_running) {
        return -1;
    }

    started_us = monotonic_us();
    pid = fork();

    if (pid < 0) {
        syslog(LOG_ERR,
               "fork-failed ip=%s errno=%d error=%s",
               ev->ip,
               errno,
               strerror(errno));
        return -1;
    }

    if (pid == 0) {
        process_event(cfg, ev);
        _exit(0);
    }

    worker_add(pid, ev->ip, started_us);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --mode local-only|openwrt\n"
            "  --socket PATH\n"
            "  --whitelist FILE\n"
            "  --fastban FILE\n"
            "  --fastban-ttl DURATION\n"
            "  --ss FILE\n"
            "  --ssh FILE\n"
            "  --ssh-port PORT\n"
            "  --ssh-key FILE\n"
            "  --known-hosts FILE\n"
            "  --firewall TARGET\n"
            "  --control-path PATH\n"
            "  --active-dir PATH\n"
            "  --lfd-suppress SECONDS\n"
            "  --max-workers N\n",
            prog);
}

int main(int argc, char **argv)
{
    rwf_config cfg;
    int fd;
    int rcvbuf = 1024 * 1024;
    struct sockaddr_un addr;
    struct sigaction sa_term;
    struct sigaction sa_chld;
    int opt;
    int option_index = 0;

    static const struct option long_options[] = {
        { "mode", required_argument, NULL, 'M' },
        { "socket", required_argument, NULL, 's' },
        { "whitelist", required_argument, NULL, 'w' },
        { "fastban", required_argument, NULL, 'f' },
        { "fastban-ttl", required_argument, NULL, 't' },
        { "ss", required_argument, NULL, 'q' },
        { "ssh", required_argument, NULL, 'S' },
        { "ssh-port", required_argument, NULL, 'P' },
        { "ssh-key", required_argument, NULL, 'k' },
        { "known-hosts", required_argument, NULL, 'K' },
        { "firewall", required_argument, NULL, 'F' },
        { "control-path", required_argument, NULL, 'c' },
        { "active-dir", required_argument, NULL, 'a' },
        { "lfd-suppress", required_argument, NULL, 'l' },
        { "max-workers", required_argument, NULL, 'm' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    memset(&cfg, 0, sizeof(cfg));
    cfg.socket_path = RWF_DEFAULT_SOCKET;
    cfg.whitelist_path = RWF_DEFAULT_WHITELIST;
    cfg.fastban_path = RWF_DEFAULT_FASTBAN;
    cfg.fastban_ttl = RWF_DEFAULT_FASTBAN_TTL;
    cfg.ss_path = RWF_DEFAULT_SS;
    cfg.ssh_path = RWF_DEFAULT_SSH;
    cfg.ssh_key = RWF_DEFAULT_SSH_KEY;
    cfg.known_hosts = RWF_DEFAULT_KNOWN_HOSTS;
    cfg.firewall = RWF_DEFAULT_FIREWALL;
    cfg.control_path = RWF_DEFAULT_CONTROL;
    cfg.active_dir = RWF_DEFAULT_ACTIVE_DIR;
    cfg.lfd_suppress_seconds = RWF_DEFAULT_LFD_SUPPRESS;
    cfg.ssh_port = RWF_DEFAULT_SSH_PORT;
    cfg.remote_enabled = RWF_DEFAULT_REMOTE_MODE;
    cfg.max_workers = RWF_DEFAULT_MAX_WORKERS;

    while ((opt = getopt_long(argc, argv, "M:s:w:f:t:q:S:P:k:K:F:c:a:l:m:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'M':
                if (strcmp(optarg, "local-only") == 0 || strcmp(optarg, "local") == 0) {
                    cfg.remote_enabled = 0;
                }
                else if (strcmp(optarg, "openwrt") == 0 || strcmp(optarg, "remote") == 0) {
                    cfg.remote_enabled = 1;
                }
                else {
                    fprintf(stderr, "Invalid --mode: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                break;
            case 's': cfg.socket_path = optarg; break;
            case 'w': cfg.whitelist_path = optarg; break;
            case 'f': cfg.fastban_path = optarg; break;
            case 't': cfg.fastban_ttl = optarg; break;
            case 'q': cfg.ss_path = optarg; break;
            case 'S': cfg.ssh_path = optarg; break;
            case 'P': {
                char *endptr;
                unsigned long n;
                errno = 0;
                n = strtoul(optarg, &endptr, 10);
                if (errno != 0 || *optarg == '\0' || *endptr != '\0' || n < 1 || n > 65535) {
                    fprintf(stderr, "Invalid --ssh-port: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                cfg.ssh_port = (unsigned int) n;
                break;
            }
            case 'k': cfg.ssh_key = optarg; break;
            case 'K': cfg.known_hosts = optarg; break;
            case 'F': cfg.firewall = optarg; break;
            case 'c': cfg.control_path = optarg; break;
            case 'a': cfg.active_dir = optarg; break;
            case 'l': {
                char *endptr;
                unsigned long n;
                errno = 0;
                n = strtoul(optarg, &endptr, 10);
                if (errno != 0 || *optarg == '\0' || *endptr != '\0' || n < 10 || n > 600) {
                    fprintf(stderr, "Invalid --lfd-suppress: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                cfg.lfd_suppress_seconds = (unsigned int) n;
                break;
            }
            case 'm': {
                char *endptr;
                long n;
                errno = 0;
                n = strtol(optarg, &endptr, 10);
                if (errno != 0 || *optarg == '\0' || *endptr != '\0' || n < 1 || n > 256) {
                    fprintf(stderr, "Invalid --max-workers: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                cfg.max_workers = (int) n;
                break;
            }
            case 'h': usage(argv[0]); return EXIT_SUCCESS;
            default: usage(argv[0]); return EXIT_FAILURE;
        }
    }

    if (cfg.socket_path[0] != '/' || strlen(cfg.socket_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "Invalid socket path: %s\n", cfg.socket_path);
        return EXIT_FAILURE;
    }

    if (access(cfg.whitelist_path, R_OK) != 0 ||
        access(cfg.fastban_path, X_OK) != 0 ||
        access(cfg.ss_path, X_OK) != 0) {
        perror("RwF helper preflight");
        return EXIT_FAILURE;
    }

    if (cfg.remote_enabled &&
        (cfg.firewall == NULL || cfg.firewall[0] == '\0')) {
        fprintf(stderr, "RwF helper OpenWrt preflight: --firewall TARGET is required in openwrt mode\n");
        return EXIT_FAILURE;
    }

    if (cfg.remote_enabled &&
        (access(cfg.ssh_path, X_OK) != 0 ||
         access(cfg.ssh_key, R_OK) != 0 ||
         access(cfg.known_hosts, R_OK) != 0)) {
        perror("RwF helper OpenWrt preflight");
        return EXIT_FAILURE;
    }

    if (ensure_dir("/run/custom-web-ban", 0700) != 0 ||
        ensure_dir(cfg.active_dir, 0700) != 0) {
        perror("RwF helper runtime directory");
        return EXIT_FAILURE;
    }

    workers_len = cfg.max_workers;
    workers = calloc((size_t) workers_len, sizeof(*workers));
    if (workers == NULL) {
        perror("calloc");
        return EXIT_FAILURE;
    }

    memset(&sa_term, 0, sizeof(sa_term));
    sa_term.sa_handler = on_term;
    sigemptyset(&sa_term.sa_mask);

    memset(&sa_chld, 0, sizeof(sa_chld));
    sa_chld.sa_handler = on_chld;
    sigemptyset(&sa_chld.sa_mask);

    if (sigaction(SIGTERM, &sa_term, NULL) != 0 ||
        sigaction(SIGINT, &sa_term, NULL) != 0 ||
        sigaction(SIGCHLD, &sa_chld, NULL) != 0) {
        perror("sigaction");
        free(workers);
        return EXIT_FAILURE;
    }

    signal(SIGPIPE, SIG_IGN);
    openlog("rwf-helper", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        syslog(LOG_ERR, "socket-failed errno=%d error=%s", errno, strerror(errno));
        free(workers);
        closelog();
        return EXIT_FAILURE;
    }

    (void) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", cfg.socket_path);

    unlink(cfg.socket_path);

    if (bind(fd, (const struct sockaddr *) &addr, sizeof(addr)) != 0) {
        syslog(LOG_ERR,
               "bind-failed socket=%s errno=%d error=%s",
               cfg.socket_path,
               errno,
               strerror(errno));
        close(fd);
        free(workers);
        closelog();
        return EXIT_FAILURE;
    }

    if (chmod(cfg.socket_path, 0660) != 0) {
        syslog(LOG_ERR,
               "chmod-failed socket=%s errno=%d error=%s",
               cfg.socket_path,
               errno,
               strerror(errno));
        close(fd);
        unlink(cfg.socket_path);
        free(workers);
        closelog();
        return EXIT_FAILURE;
    }

    if (cfg.remote_enabled) {
        syslog(LOG_NOTICE,
               "ready socket=%s whitelist=%s backend=openwrt firewall=%s ssh_port=%u fastban=%s fallback_ttl=%s max_workers=%d",
               cfg.socket_path,
               cfg.whitelist_path,
               cfg.firewall,
               cfg.ssh_port,
               cfg.fastban_path,
               cfg.fastban_ttl,
               cfg.max_workers);
    }
    else {
        syslog(LOG_NOTICE,
               "ready socket=%s whitelist=%s backend=local-only fastban=%s policy_driven_local_bans=1 max_workers=%d",
               cfg.socket_path,
               cfg.whitelist_path,
               cfg.fastban_path,
               cfg.max_workers);
    }

    while (rwf_running) {
        char raw[RWF_EVENT_MAX + 1];
        rwf_event ev;
        ssize_t n;
        int64_t rx_us;
        int wl;

        if (rwf_sigchld) {
            reap_workers(0);
        }

        n = recv(fd, raw, RWF_EVENT_MAX, 0);
        rx_us = realtime_us();

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            syslog(LOG_ERR, "recv-failed errno=%d error=%s", errno, strerror(errno));
            continue;
        }

        if (n == 0 || n > RWF_EVENT_MAX || memchr(raw, '\0', (size_t) n) != NULL) {
            syslog(LOG_WARNING,
                   "event-invalid bytes=%ld reason=length-or-nul action=drop",
                   (long) n);
            continue;
        }

        raw[n] = '\0';

        if (!parse_event(raw, &ev)) {
            syslog(LOG_WARNING,
                   "event-invalid bytes=%ld reason=protocol action=drop",
                   (long) n);
            continue;
        }

        wl = ip_whitelisted(cfg.whitelist_path, ev.ip);
        if (wl != 0) {
            if (wl > 0) {
                syslog(LOG_NOTICE,
                       "whitelist-hit ip=%s rule=%s action=drop-event",
                       ev.ip,
                       ev.rule);
            }
            continue;
        }

        if (ev.source_ts_us > 0 && rx_us >= ev.source_ts_us) {
            syslog(LOG_NOTICE,
                   "event-received ip=%s rule=%s policy=%s bytes=%ld source_ts_us=%lld helper_rx_us=%lld socket_delivery_us=%lld",
                   ev.ip,
                   ev.rule,
                   ev.policy,
                   (long) n,
                   (long long) ev.source_ts_us,
                   (long long) rx_us,
                   (long long) (rx_us - ev.source_ts_us));
        }
        else {
            syslog(LOG_NOTICE,
                   "event-received ip=%s rule=%s policy=%s bytes=%ld source_ts_us=%lld helper_rx_us=%lld socket_delivery_us=na",
                   ev.ip,
                   ev.rule,
                   ev.policy,
                   (long) n,
                   (long long) ev.source_ts_us,
                   (long long) rx_us);
        }

        if (spawn_worker(&cfg, &ev) != 0) {
            syslog(LOG_ERR,
                   "worker-start-failed ip=%s rule=%s action=drop-event",
                   ev.ip,
                   ev.rule);
        }
    }

    syslog(LOG_NOTICE, "stopping active_workers=%d", rwf_active_workers);

    close(fd);
    unlink(cfg.socket_path);

    while (rwf_active_workers > 0) {
        reap_workers(1);
    }

    free(workers);
    closelog();
    return EXIT_SUCCESS;
}
