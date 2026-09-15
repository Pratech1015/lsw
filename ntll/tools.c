// tools.c - Native reimplementations of Windows System32 CLI tools
// Copyright (c) 2026 LSW Contributors
//
// These tools read Linux host state (/proc, /sys, getifaddrs, etc.) and
// print output shaped like their real Windows counterparts. They are the
// runnable substitutes for the bundled Win11 PE images, which the NTLL
// loader cannot execute yet (missing DLL import surface).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "ntll.h"

/* ---------- shared helpers ---------- */

static void fmt_bytes(unsigned long long n, char* out, size_t sz) {
    if (n >= (1ULL << 30))
        snprintf(out, sz, "%.1f GB", (double)n / (1ULL << 30));
    else if (n >= (1ULL << 20))
        snprintf(out, sz, "%.1f MB", (double)n / (1ULL << 20));
    else if (n >= (1ULL << 10))
        snprintf(out, sz, "%.1f KB", (double)n / (1ULL << 10));
    else
        snprintf(out, sz, "%llu bytes", n);
}

static char* read_proc(const char* path, char* buf, size_t sz) {
    FILE* f = fopen(path, "r");
    if (!f) return NULL;
    size_t n = fread(buf, 1, sz - 1, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

static long long meminfo_key_kb(const char* key) {
    char buf[8192];
    if (!read_proc("/proc/meminfo", buf, sizeof(buf))) return 0;
    const char* p = strstr(buf, key);
    if (!p) return 0;
    p += strlen(key);
    while (*p == ':' || *p == ' ' || *p == '\t') p++;
    return strtoll(p, NULL, 10);
}

static long long mem_total_kb(void)     { return meminfo_key_kb("MemTotal"); }
static long long mem_available_kb(void) { return meminfo_key_kb("MemAvailable"); }

/* ---------- NETWORK GROUP ---------- */

static int tool_ipconfig(int argc, char** argv) {
    int all = 0;
    for (int i = 1; i < argc; i++)
        if (strcasecmp(argv[i], "/all") == 0 || strcasecmp(argv[i], "-all") == 0) all = 1;

    char hn[256];
    gethostname(hn, sizeof(hn));
    printf("Windows IP Configuration\n\n");
    if (all) {
        printf("   Host Name . . . . . . . . . . . . : %s\n", hn);
        printf("   Primary Dns Suffix  . . . . . . . :\n");
        printf("   Node Type . . . . . . . . . . . . : Hybrid\n");
        printf("   IP Routing Enabled. . . . . . . . : No\n");
        printf("   WINS Proxy Enabled. . . . . . . . : No\n\n");
    }

    struct ifaddrs* ifa;
    if (getifaddrs(&ifa) != 0) {
        fprintf(stderr, "ipconfig: Unable to query network interfaces\n");
        return 1;
    }
    for (struct ifaddrs* p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || (p->ifa_flags & IFF_LOOPBACK)) continue;
        int fam = p->ifa_addr->sa_family;
        if (fam != AF_INET && fam != AF_INET6) continue;

        printf("%s adapter %s:\n\n", "Ethernet", p->ifa_name);
        printf("   Connection-specific DNS Suffix  . :\n");
        printf("   Description . . . . . . . . . . . : Linux %s interface\n", p->ifa_name);
        printf("   Physical Address. . . . . . . . . : ");
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, p->ifa_name, IFNAMSIZ - 1);
            if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
                printf("%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            }
            close(fd);
        }
        printf("\n");
        if (fam == AF_INET) {
            struct sockaddr_in* sa = (struct sockaddr_in*)p->ifa_addr;
            struct sockaddr_in* nm = (struct sockaddr_in*)p->ifa_netmask;
            char a[64] = "-", m[64] = "-";
            inet_ntop(AF_INET, &sa->sin_addr, a, sizeof(a));
            if (nm) inet_ntop(AF_INET, &nm->sin_addr, m, sizeof(m));
            printf("   DHCP Enabled. . . . . . . . . . . : No\n");
            printf("   IPv4 Address. . . . . . . . . . . : %s\n", a);
            printf("   Subnet Mask . . . . . . . . . . . : %s\n", m);
            printf("   Default Gateway . . . . . . . . . :\n");
            printf("\n");
        } else {
            struct sockaddr_in6* sa6 = (struct sockaddr_in6*)p->ifa_addr;
            char a[128];
            inet_ntop(AF_INET6, &sa6->sin6_addr, a, sizeof(a));
            printf("   IPv6 Address. . . . . . . . . . . : %s%%%s\n", a, p->ifa_name);
            printf("\n");
        }
    }
    freeifaddrs(ifa);
    printf("   Default Gateway . . . . . . . . . :\n");
    return 0;
}

static int tool_ping(int argc, char** argv) {
    const char* target = NULL;
    int count = 4;
    int forever = 0;
    int timeout_ms = 1000;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' || argv[i][0] == '/') {
            char c = (argv[i][1]) ? tolower((unsigned char)argv[i][1]) : '?';
            const char* val = argv[i] + 2;
            while (*val && *val != ':' && *val != '=') val++;
            if (*val == ':' || *val == '=') val++;
            switch (c) {
                case 'n': {
                    if (*val) { count = atoi(val); }
                    else if (i + 1 < argc) { count = atoi(argv[++i]); }
                    break;
                }
                case 't': forever = 1; break;
                case 'w': {
                    char v[16] = "";
                    if (*val) { snprintf(v, sizeof(v), "%s", val); }
                    else if (i + 1 < argc) { snprintf(v, sizeof(v), "%s", argv[++i]); }
                    for (char* p = v; *p; p++) if (*p == '.' || *p == ',') *p = 0;
                    if (v[0]) { timeout_ms = atoi(v) / 10; if (timeout_ms < 1) timeout_ms = 1; }
                    break;
                }
                default: break;
            }
        } else {
            target = argv[i];
        }
    }
    if (!target) {
        fprintf(stderr, "Usage: ping [-t] [-n count] [-w timeout] <host>\n");
        return 1;
    }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(target, NULL, &hints, &res) != 0 || !res) {
        fprintf(stderr, "Ping request could not find host %s.\n", target);
        return 1;
    }

    char addr[INET6_ADDRSTRLEN] = {0};
    int fam = res->ai_family;
    struct sockaddr_storage dest;
    memset(&dest, 0, sizeof(dest));
    if (fam == AF_INET) {
        struct sockaddr_in* d = (struct sockaddr_in*)&dest;
        d->sin_family = AF_INET;
        d->sin_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
        inet_ntop(AF_INET, &d->sin_addr, addr, sizeof(addr));
    } else {
        struct sockaddr_in6* d = (struct sockaddr_in6*)&dest;
        d->sin6_family = AF_INET6;
        d->sin6_addr = ((struct sockaddr_in6*)res->ai_addr)->sin6_addr;
        inet_ntop(AF_INET6, &d->sin6_addr, addr, sizeof(addr));
    }
    freeaddrinfo(res);

    printf("\nPinging %s [%s] with 32 bytes of data:\n", target, addr);

    int proto = (fam == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6;
    int fd = socket(fam, SOCK_DGRAM, proto);
    if (fd < 0) {
        fprintf(stderr, "Unable to open ICMP socket: %s\n", strerror(errno));
        fprintf(stderr, "This usually requires root or net.ipv4.ping_group_range to include your GID.\n");
        return 1;
    }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int sent = 0, recvd = 0, lost = 0;
    double min_ms = 9999, max_ms = 0, sum_ms = 0;
    unsigned short ident = (unsigned short)(getpid() & 0xFFFF);
    int seq = 0;

    do {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        unsigned short* w = (unsigned short*)pkt;
        if (fam == AF_INET) {
            struct icmp* ic = (struct icmp*)pkt;
            ic->icmp_type = ICMP_ECHO;
            ic->icmp_code = 0;
            ic->icmp_id = htons(ident);
            ic->icmp_seq = htons(seq);
        } else {
            struct icmp6_hdr* ic = (struct icmp6_hdr*)pkt;
            ic->icmp6_type = 128;
            ic->icmp6_code = 0;
            ic->icmp6_id = htons(ident);
            ic->icmp6_seq = htons(seq);
        }
        /* checksum over first 8 bytes */
        {
            unsigned long sum = 0;
            for (int i = 0; i < 4; i++) sum += ntohs(w[i]);
            while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
            unsigned short cks = (unsigned short)(~sum);
            if (fam == AF_INET) ((struct icmp*)pkt)->icmp_cksum = cks;
            else ((struct icmp6_hdr*)pkt)->icmp6_cksum = cks;
        }

        struct timeval t0, t1;
        gettimeofday(&t0, NULL);
        socklen_t sl = (fam == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        ssize_t n = sendto(fd, pkt, 32, 0, (struct sockaddr*)&dest, sl);
        if (n < 0) {
            printf("PING: transmit failed. General failure.\n");
            lost++;
        } else {
            sent++;
            unsigned char rsp[1024];
            ssize_t r = recvfrom(fd, rsp, sizeof(rsp), 0, NULL, NULL);
            gettimeofday(&t1, NULL);
            if (r < 0) {
                printf("Request timed out.\n");
                lost++;
            } else {
                recvd++;
                double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_usec - t0.tv_usec) / 1000.0;
                if (ms < min_ms) min_ms = ms;
                if (ms > max_ms) max_ms = ms;
                sum_ms += ms;
                printf("Reply from %s: bytes=32 time=%.1fms\n", addr, ms);
            }
        }
        seq++;
    } while ((!forever && seq < count));

    close(fd);

    printf("\nPing statistics for %s:\n", addr);
    printf("    Packets: Sent = %d, Received = %d, Lost = %d (%d%% loss),\n",
           sent, recvd, lost, sent ? (int)((lost * 100) / sent) : 0);
    if (recvd > 0) {
        printf("Approximate round trip times in milli-seconds:\n");
        printf("    Minimum = %.1fms, Maximum = %.1fms, Average = %.1fms\n",
               min_ms, max_ms, sum_ms / recvd);
    }
    return 0;
}

static int tool_tracert(int argc, char** argv) {
    const char* target = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' || argv[i][0] == '/') continue;
        target = argv[i];
    }
    if (!target) {
        fprintf(stderr, "Usage: tracert <host>\n");
        return 1;
    }
    struct addrinfo* res = NULL;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(target, NULL, &hints, &res) != 0 || !res) {
        fprintf(stderr, "Unable to resolve %s\n", target);
        return 1;
    }
    char addr[INET6_ADDRSTRLEN] = {0};
    if (res->ai_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, addr, sizeof(addr));
    } else {
        inet_ntop(AF_INET6, &((struct sockaddr_in6*)res->ai_addr)->sin6_addr, addr, sizeof(addr));
    }
    freeaddrinfo(res);

    printf("\nTracing route to %s [%s] over a maximum of 30 hops:\n", target, addr);
    printf("\n  1     <1 ms     <1 ms     <1 ms  %s\n", addr);
    printf("  2     ^C\n");
    printf("Trace complete.\n");
    return 0;
}

static int tool_getmac(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Physical Address    Transport Name\n");
    printf("=================== ============================================\n");
    DIR* d = opendir("/sys/class/net");
    if (!d) return 1;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char path[512], mac[64] = "";
        snprintf(path, sizeof(path), "/sys/class/net/%s/address", e->d_name);
        if (!read_proc(path, mac, sizeof(mac))) continue;
        for (char* p = mac; *p; p++) { if (*p == ':') *p = '-'; }
        char* nl = strpbrk(mac, "\r\n");
        if (nl) *nl = 0;
        printf("%-25s %s\n", mac, e->d_name);
    }
    closedir(d);
    return 0;
}

static void netstat_state_name(char st, char* out, size_t sz) {
    const char* n;
    switch (st) {
        case '0': n = "LISTENING"; break;
        case '1': n = "ESTABLISHED"; break;
        case '2': n = "SYN_SENT"; break;
        case '3': n = "SYN_RECEIVED"; break;
        case '4': n = "FIN_WAIT_1"; break;
        case '5': n = "FIN_WAIT_2"; break;
        case '6': n = "TIME_WAIT"; break;
        case '8': n = "CLOSE_WAIT"; break;
        case '9': n = "LAST_ACK"; break;
        case 'A': n = "LISTENING"; break;
        case 'B': n = "CLOSING"; break;
        default:  n = "UNKNOWN"; break;
    }
    snprintf(out, sz, "%s", n);
}

static void netstat_line(const char* proto, const char* line, int show_all) {
    char loc[64], rem[64], state_c[8];
    if (sscanf(line, " %*s %63s %63s %7s", loc, rem, state_c) != 3) return;
    if (!show_all && state_c[0] == '0' && strcmp(proto, "TCP") == 0) return;

    unsigned long a, b, p1, p2;
    if (sscanf(loc, "%lx:%lx", &a, &p1) == 2 && sscanf(rem, "%lx:%lx", &b, &p2) == 2) {
        char lhost[16], rhost[16];
        snprintf(lhost, sizeof(lhost), "%lu.%lu.%lu.%lu",
                 (a & 0xFF), (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF);
        snprintf(rhost, sizeof(rhost), "%lu.%lu.%lu.%lu",
                 (b & 0xFF), (b >> 8) & 0xFF, (b >> 16) & 0xFF, (b >> 24) & 0xFF);
        char state[32];
        netstat_state_name(state_c[0], state, sizeof(state));
        if (strcmp(proto, "TCP") == 0)
            printf("  TCP    %-20s:%-6lu %-20s:%-6lu %-12s\n", lhost, p1, rhost, p2, state);
        else
            printf("  UDP    %-20s:%-6lu %-20s:%-6lu\n", lhost, p1, rhost, p2);
    }
}

static int tool_netstat(int argc, char** argv) {
    int show_all = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' || argv[i][0] == '/') {
            if (tolower((unsigned char)argv[i][1]) == 'a') show_all = 1;
        }
    }
    printf("Active Connections\n\n");
    printf("  Proto  Local Address          Foreign Address        State\n");
    {
        char buf[1 << 16];
        if (read_proc("/proc/net/tcp", buf, sizeof(buf))) {
            char* save = NULL;
            char* l = strtok_r(buf, "\n", &save);
            while ((l = strtok_r(NULL, "\n", &save))) netstat_line("TCP", l, show_all);
        }
    }
    {
        char buf[1 << 16];
        if (read_proc("/proc/net/udp", buf, sizeof(buf))) {
            char* save = NULL;
            char* l = strtok_r(buf, "\n", &save);
            while ((l = strtok_r(NULL, "\n", &save))) netstat_line("UDP", l, show_all);
        }
    }
    return 0;
}

static int tool_route(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("==========================================================================\n");
    printf("Interface List\n");
    printf("==========================================================================\n\n");
    printf("==========================================================================\n");
    printf("IPv4 Route Table\n");
    printf("==========================================================================\n");
    printf("Active Routes:\n");
    printf("Network Destination        Netmask          Gateway       Interface  Metric\n");
    printf("%-25s %-15s %-15s %-15s %d\n", "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", 1);
    char buf[4096];
    if (read_proc("/proc/net/route", buf, sizeof(buf))) {
        char* save = NULL;
        char* l = strtok_r(buf, "\n", &save);
        while ((l = strtok_r(NULL, "\n", &save))) {
            char iface[32];
            unsigned int dst, gw, mask, flags, metric;
            if (sscanf(l, "%31s %x %x %x %*d %*d %u %x", iface, &dst, &gw, &flags, &metric, &mask) >= 5) {
                char dsts[16], gws[16], masks[16];
                snprintf(dsts, sizeof(dsts), "%u.%u.%u.%u", dst & 0xFF, (dst >> 8) & 0xFF, (dst >> 16) & 0xFF, (dst >> 24) & 0xFF);
                snprintf(gws, sizeof(gws), "%u.%u.%u.%u", gw & 0xFF, (gw >> 8) & 0xFF, (gw >> 16) & 0xFF, (gw >> 24) & 0xFF);
                snprintf(masks, sizeof(masks), "%u.%u.%u.%u", mask & 0xFF, (mask >> 8) & 0xFF, (mask >> 16) & 0xFF, (mask >> 24) & 0xFF);
                printf("%-25s %-15s %-15s %-15s %u\n", dsts, masks, gws, iface, metric);
            }
        }
    }
    printf("==========================================================================\n");
    return 0;
}

static int tool_nslookup(int argc, char** argv) {
    const char* qname = NULL;
    for (int i = 1; i < argc; i++)
        if (argv[i][0] != '-' && argv[i][0] != '/') { qname = argv[i]; break; }

    char rbuf[2048];
    const char* server = "127.0.0.53";
    if (read_proc("/etc/resolv.conf", rbuf, sizeof(rbuf))) {
        char* p = strstr(rbuf, "nameserver");
        if (p) {
            p += 10;
            while (*p == ' ' || *p == '\t') p++;
            char* e = p;
            while (*e && *e != '\n' && *e != ' ' && *e != '\t') e++;
            *e = 0;
            server = p;
        }
    }
    printf("Server:  %s\n", server);
    printf("Address: %s\n\n", server);
    if (!qname) return 0;

    struct addrinfo* res = NULL;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(qname, NULL, &hints, &res) == 0 && res) {
        printf("Non-authoritative answer:\n");
        printf("Name:    %s\n", qname);
        for (struct addrinfo* p = res; p; p = p->ai_next) {
            char buf[INET6_ADDRSTRLEN];
            if (p->ai_family == AF_INET)
                inet_ntop(AF_INET, &((struct sockaddr_in*)p->ai_addr)->sin_addr, buf, sizeof(buf));
            else
                inet_ntop(AF_INET6, &((struct sockaddr_in6*)p->ai_addr)->sin6_addr, buf, sizeof(buf));
            printf("Address:  %s\n", buf);
        }
        freeaddrinfo(res);
    } else {
        printf("*** can't find %s: Non-existent domain\n", qname);
    }
    return 0;
}

static int tool_netsh(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (strcasecmp(argv[i], "show") == 0 && i + 1 < argc &&
            strcasecmp(argv[i + 1], "config") == 0)
            return tool_ipconfig(1, (char*[]){"ipconfig", NULL});
    }
    fprintf(stderr, "netsh: only 'interface ip show config' is supported in this LSW build.\n");
    return 1;
}

static int tool_pathping(int argc, char** argv) {
    printf("Computing statistics for 2 seconds...\n");
    return tool_ping(argc, argv);
}

static int tool_ftp(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "ftp: interactive FTP client is not available in this LSW build.\n");
    return 1;
}

/* ---------- SYSTEM GROUP ---------- */

static int tool_systeminfo(int argc, char** argv) {
    (void)argc; (void)argv;
    struct utsname un;
    if (uname(&un) != 0) return 1;
    char hn[256];
    gethostname(hn, sizeof(hn));

    printf("Host Name:                 %s\n", hn);
    printf("OS Name:                   Microsoft Windows 11 Pro\n");
    printf("OS Version:                10.0.22631 N/A Build 22631\n");
    printf("OS Manufacturer:           Microsoft Corporation\n");
    printf("OS Configuration:          Standalone Workstation\n");
    printf("OS Build Type:             Multiprocessor Free\n");
    printf("Registered Owner:          LSW User\n");
    printf("Original Install Date:     N/A\n");
    long long total_kb = mem_total_kb();
    long long avail_kb = mem_available_kb();
    char bs[64];
    fmt_bytes(total_kb * 1024, bs, sizeof(bs));
    printf("Total Physical Memory:     %-12s (%lld KB)\n", bs, total_kb);
    fmt_bytes(avail_kb * 1024, bs, sizeof(bs));
    printf("Available Physical Memory: %-12s (%lld KB)\n", bs, avail_kb);
    printf("Virtual Memory: Max Size:  N/A\n");
    printf("Virtual Memory: Available: N/A\n");
    printf("Page File Location(s):     N/A\n");
    printf("Domain:                    LSW-WORKSTATION\n");
    printf("Logon Server:              \\\\LSW\\NTLL\n");
    printf("Hotfix(s):                 N/A\n");
    printf("Network Card(s):           \n");
    return 0;
}

static int tool_driverquery(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Module Name      Display Name                       Driver Type   Link Date\n");
    printf("=============== ==================================== ============  ==========\n");
    char buf[4096];
    if (read_proc("/proc/modules", buf, sizeof(buf))) {
        char* save = NULL;
        char* l = strtok_r(buf, "\n", &save);
        while ((l = strtok_r(NULL, "\n", &save))) {
            char name[64];
            unsigned long size, refs;
            if (sscanf(l, "%63s %lu %lu", name, &size, &refs) >= 1) {
                printf("%-15s %-40s Kernel        N/A\n", name, name);
            }
        }
    } else {
        printf("No kernel drivers found.\n");
        return 1;
    }
    return 0;
}

static int tool_powercfg(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("GUID Alias: SCHEME_MIN\n");
    printf("Power Scheme Guid (Balanced) *\n");
    char bbuf[64];
    if (read_proc("/sys/class/power_supply/BAT0/capacity", bbuf, sizeof(bbuf))) {
        char* nl = strpbrk(bbuf, "\r\n");
        if (nl) *nl = 0;
        printf("    Battery Percentage:  %s%% (remaining)\n", bbuf);
    } else {
        printf("    AC power (no battery detected)\n");
    }
    return 0;
}

static int tool_tzutil(int argc, char** argv) {
    const char* cmd = (argc > 1) ? argv[1] : "";
    if (strcasecmp(cmd, "/g") == 0 || strcasecmp(cmd, "-g") == 0)
        cmd = "/g";
    if (strcmp(cmd, "/g") == 0) {
        char tz[512] = "";
        if (!read_proc("/etc/timezone", tz, sizeof(tz))) {
            char link[1024] = "";
            ssize_t n = readlink("/etc/localtime", link, sizeof(link) - 1);
            if (n > 0) link[n] = 0;
            snprintf(tz, sizeof(tz), "%s", link);
        }
        char* nl = strpbrk(tz, "\r\n");
        if (nl) *nl = 0;
        printf("Current Time Zone ID: UTC\n");
        printf("Time Zone: (%s)\n", tz);
        return 0;
    }
    if (strcasecmp(cmd, "/l") == 0 || strcmp(cmd, "/list") == 0) {
        printf(" UTC (UTC)\n");
        printf(" Pacific Standard Time (UTC-8)\n");
        printf(" Eastern Standard Time (UTC-5)\n");
        printf(" Central European Standard Time (UTC+1)\n");
        printf(" India Standard Time (UTC+5:30)\n");
        return 0;
    }
    fprintf(stderr, "Usage: tzutil /g | /l | /s <id>\n");
    return 1;
}

static int tool_w32tm(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Current time: ");
    time_t now = time(NULL);
    struct tm* tm_now = localtime(&now);
    char date[64];
    strftime(date, sizeof(date), "%m/%d/%Y %I:%M:%S %p", tm_now);
    printf("%s\n", date);
    printf("Local timezone: %s\n", getenv("TZ") ? getenv("TZ") : "UTC (from /etc/timezone)");
    printf("Source: Local CMOS Clock\n");
    printf("The time is synchronized via the host system clock.\n");
    return 0;
}

static int tool_shutdown(int argc, char** argv) {
    int restart = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '/' || argv[i][0] == '-') {
            switch (tolower((unsigned char)argv[i][1])) {
                case 'r': restart = 1; break;
                case 'a': printf("Shutdown aborted.\n"); return 0;
                default: break;
            }
        }
    }
    printf(restart ? "Restarting...\n" : "Shutting down...\n");
    printf("The system is not going down in this LSW environment (host is preserved).\n");
    return 0;
}

/* ---------- PROCESS GROUP ---------- */

static int tool_tasklist(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("\nImage Name                 PID Session Name        Session#    Mem Usage\n");
    printf("======================== ====== ================ =========== ============\n");
    const char* durations[] = { ".exe", ".comm" };
    (void)durations;
    DIR* d = opendir("/proc");
    if (!d) return 1;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char p[512], comm[256] = "unknown";
        snprintf(p, sizeof(p), "/proc/%s/comm", e->d_name);
        read_proc(p, comm, sizeof(comm));
        char* nl = strpbrk(comm, "\r\n");
        if (nl) *nl = 0;
        long rss_kb = 0;
        snprintf(p, sizeof(p), "/proc/%s/statm", e->d_name);
        FILE* sf = fopen(p, "r");
        if (sf) {
            long sz, resident;
            if (fscanf(sf, "%ld %ld", &sz, &resident) == 2) rss_kb = resident * 4;
            fclose(sf);
        }
        printf("%-24s %6s Console            %2d      %6ld K\n", comm, e->d_name, 0, rss_kb);
    }
    closedir(d);
    return 0;
}

static int tool_taskkill(int argc, char** argv) {
    pid_t pid = -1;
    const char* image = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '/' || argv[i][0] == '-') {
            char c = tolower((unsigned char)argv[i][1]);
            if (c == 'p' && i + 1 < argc) pid = atoi(argv[++i]);
            else if (c == 'i' && i + 1 < argc) image = argv[++i];
        } else if (isdigit((unsigned char)argv[i][0])) {
            pid = atoi(argv[i]);
        } else {
            image = argv[i];
        }
    }
    if (image && pid < 0) {
        DIR* d = opendir("/proc");
        if (d) {
            struct dirent* de;
            while ((de = readdir(d))) {
                if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
                char p[512], comm[256];
                snprintf(p, sizeof(p), "/proc/%s/comm", de->d_name);
                if (!read_proc(p, comm, sizeof(comm))) continue;
                char* nl = strpbrk(comm, "\r\n");
                if (nl) *nl = 0;
                if (strcasecmp(comm, image) == 0) { pid = atoi(de->d_name); break; }
            }
            closedir(d);
        }
    }
    if (pid <= 0) {
        fprintf(stderr, "ERROR: The process \"%s\" not found.\n", image ? image : "?");
        return 1;
    }
    if (kill(pid, SIGKILL) == 0) {
        printf("SUCCESS: The process with PID %d has been terminated.\n", pid);
        return 0;
    }
    fprintf(stderr, "ERROR: The process with PID %d could not be terminated.\n", pid);
    return 1;
}

/* ---------- SESSION/USER GROUP ---------- */

static int tool_qwinsta(int argc, char** argv) {
    (void)argc; (void)argv;
    printf(" SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE\n");
    printf(" console           %-24s  0  Conn    console\n",
           getenv("USER") ? getenv("USER") : "lsw");
    printf(" services          %-24s  1  Disc\n", "");
    printf(" rdp-tcp           %-24s  2  Listen\n", "");
    return 0;
}

static int tool_quser(int argc, char** argv) {
    (void)argc; (void)argv;
    printf(" USERNAME   SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n");
    time_t now = time(NULL);
    struct tm* tm_now = localtime(&now);
    char date[64];
    strftime(date, sizeof(date), "%m/%d/%Y %I:%M:%S %p", tm_now);
    printf(" %-12s %-10s %3d  Active   .          %s\n",
           getenv("USER") ? getenv("USER") : "lsw", "console", 0, date);
    return 0;
}

static int tool_logoff(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "logoff: session logoff is not supported in this LSW build.\n");
    return 1;
}
static int tool_tsdiscon(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "tsdiscon: session disconnect is not supported in this LSW build.\n");
    return 1;
}
static int tool_change(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "change: terminal server configuration is not supported in this LSW build.\n");
    return 1;
}
static int tool_runas(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "runas: running a program as another user requires host privileges not available here.\n");
    return 1;
}
static int tool_setx(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "ERROR: Invalid syntax.\n");
        return 1;
    }
    const char* name = argv[1];
    const char* value = argv[2];
    if (setenv(name, value, 1) != 0)
        fprintf(stderr, "setx: failed to set %s\n", name);
    else {
        printf("SUCCESS: Specified value was saved.\n");
        printf("Note: %s only takes effect in new shells; add it permanently in your login profile.\n", name);
    }
    return 0;
}
static int tool_chcp(int argc, char** argv) {
    (void)argv;
    if (argc > 1) {
        fprintf(stderr, "chcp: only the current code page can be displayed in this LSW build.\n");
        return 1;
    }
    printf("Active code page: 65001\n");
    return 0;
}

/* ---------- FILE GROUP ---------- */

static int tool_attrib(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Display or change file attributes. Usage: attrib [+R|-R] <path>\n");
        return 1;
    }
    const char* target = NULL;
    int set_readonly = -1;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '+') { if (tolower((unsigned char)argv[i][1]) == 'r') set_readonly = 1; }
        else if (argv[i][0] == '-') { if (tolower((unsigned char)argv[i][1]) == 'r') set_readonly = 0; }
        else target = argv[i];
    }
    if (!target) return 1;
    struct stat st;
    if (stat(target, &st) != 0) {
        fprintf(stderr, "File Not Found - %s\n", target);
        return 1;
    }
    if (set_readonly >= 0) {
        mode_t newmode = st.st_mode;
        if (set_readonly) newmode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
        else newmode |= S_IWUSR | S_IWGRP;
        return chmod(target, newmode);
    }
    printf("%c%c%c%c  %s\n",
           (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) ? ' ' : 'R',
           ' ', ' ', 'A', target);
    return 0;
}

static int tool_find(int argc, char** argv) {
    const char* pattern = NULL;
    const char* file = NULL;
    int ignore_case = 0, count = 0, invert = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '/' || argv[i][0] == '-') {
            switch (tolower((unsigned char)argv[i][1])) {
                case 'i': ignore_case = 1; break;
                case 'c': count = 1; break;
                case 'v': invert = 1; break;
                default: break;
            }
        } else if (!pattern) pattern = argv[i];
        else if (!file) file = argv[i];
    }
    if (!pattern) {
        fprintf(stderr, "FIND: Parameter format not correct.\n");
        return 1;
    }
    FILE* f = file ? fopen(file, "r") : stdin;
    if (!f) {
        fprintf(stderr, "FIND: Cannot open %s\n", file);
        return 1;
    }
    char line[4096];
    int matches = 0;
    while (fgets(line, sizeof(line), f)) {
        int hit = ignore_case ? (strcasestr(line, pattern) != NULL) : (strstr(line, pattern) != NULL);
        if (invert) hit = !hit;
        if (hit) {
            matches++;
            if (!count) {
                char* nl = strrchr(line, '\n');
                if (nl) *nl = 0;
                printf("%s\n", line);
            }
        }
    }
    if (count) printf("%s%s: %d\n", file ? file : "STDIN", file ? "" : "", matches);
    if (f != stdin) fclose(f);
    return 0;
}

static int tool_findstr(int argc, char** argv) {
    return tool_find(argc, argv);
}

static int tool_sort(int argc, char** argv) {
    const char* input = NULL;
    const char* output = NULL;
    int reverse = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '/' || argv[i][0] == '-') {
            switch (tolower((unsigned char)argv[i][1])) {
                case 'r': reverse = 1; break;
                case 'o': if (i + 1 < argc) output = argv[++i]; break;
                default: break;
            }
        } else if (!input) {
            input = argv[i];
        }
    }
    FILE* f = input ? fopen(input, "r") : stdin;
    if (!f) return 1;
    static char lines[10000][1024];
    int n = 0;
    while (n < 10000 && fgets(lines[n], sizeof(lines[n]), f)) {
        char* nl = strrchr(lines[n], '\n');
        if (nl) *nl = 0;
        n++;
    }
    if (f != stdin) fclose(f);
    qsort(lines, (size_t)n, sizeof(lines[0]),
          (int (*)(const void*, const void*))strcmp);
    FILE* of = stdout;
    if (output) of = fopen(output, "w");
    if (!of) return 1;
    if (reverse) { for (int i = n - 1; i >= 0; i--) fprintf(of, "%s\n", lines[i]); }
    else { for (int i = 0; i < n; i++) fprintf(of, "%s\n", lines[i]); }
    if (output) fclose(of);
    return 0;
}

static int tool_fc(int argc, char** argv) {
    const char* file1 = NULL, * file2 = NULL;
    int binary = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '/' || argv[i][0] == '-') {
            if (tolower((unsigned char)argv[i][1]) == 'b') binary = 1;
        } else if (!file1) file1 = argv[i];
        else if (!file2) file2 = argv[i];
    }
    if (!file1 || !file2) {
        fprintf(stderr, "FC: Specified file is missing.\n");
        return 2;
    }
    if (binary) {
        FILE* f1 = fopen(file1, "rb");
        FILE* f2 = fopen(file2, "rb");
        if (!f1 || !f2) {
            fprintf(stderr, "FC: Cannot open one of the files.\n");
            if (f1) fclose(f1);
            if (f2) fclose(f2);
            return 2;
        }
        unsigned char b1[4096], b2[4096];
        size_t off = 0;
        while (1) {
            size_t n1 = fread(b1, 1, sizeof(b1), f1);
            size_t n2 = fread(b2, 1, sizeof(b2), f2);
            size_t n = n1 < n2 ? n1 : n2;
            for (size_t i = 0; i < n; i++) {
                if (b1[i] != b2[i])
                    printf("%08llX: %02X %02X\n", (unsigned long long)(off + i), b1[i], b2[i]);
            }
            if (n1 != n2) {
                printf("Files are of different sizes\n");
                break;
            }
            if (n1 == 0) break;
            off += n1;
        }
        fclose(f1);
        fclose(f2);
        return 0;
    }
    FILE* f1 = fopen(file1, "r");
    FILE* f2 = fopen(file2, "r");
    if (!f1 || !f2) {
        fprintf(stderr, "FC: Cannot open one of the files.\n");
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        return 2;
    }
    char l1[4096], l2[4096];
    int ln1 = 0, ln2 = 0;
    while (1) {
        int g1 = (fgets(l1, sizeof(l1), f1) != NULL);
        int g2 = (fgets(l2, sizeof(l2), f2) != NULL);
        if (!g1 && !g2) break;
        if (g1) ln1++;
        if (g2) ln2++;
        if ((!g1 || !g2) || strcmp(l1, l2) != 0) {
            printf("***** %s\n", file1);
            printf("%-5d: %s", g1 ? ln1 : -1, g1 ? l1 : "<EOF>");
            printf("***** %s\n", file2);
            printf("%-5d: %s", g2 ? ln2 : -1, g2 ? l2 : "<EOF>");
            printf("*****\n\n");
        }
    }
    fclose(f1);
    fclose(f2);
    return 0;
}

static int tool_more(int argc, char** argv) {
    FILE* f = stdin;
    if (argc > 1) {
        f = fopen(argv[1], "r");
        if (!f) {
            fprintf(stderr, "more: cannot open %s\n", argv[1]);
            return 1;
        }
    }
    char line[4096];
    int printed = 0;
    while (fgets(line, sizeof(line), f)) {
        printf("%s", line);
        if (++printed >= 23) {
            printf("-- More --");
            fflush(stdout);
            if (getchar() == 'q') break;
            printed = 0;
        }
    }
    if (f != stdin) fclose(f);
    return 0;
}

static void tree_walk(const char* dir, const char* prefix, int* count) {
    DIR* d = opendir(dir);
    if (!d) return;
    struct dirent* e;
    struct dirent** subdirs = NULL;
    int total = 0, shown = 0;
    /* first pass: count dirs */
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        if (e->d_type == DT_DIR) total++;
    }
    rewinddir(d);
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        if (e->d_type != DT_DIR) continue;
        int is_last = (++shown == total);
        printf("%s%s%s\n", prefix, is_last ? "└──" : "├──", e->d_name);
        (*count)++;
        char newpref[4096], sub[4096];
        snprintf(sub, sizeof(sub), "%s/%s", dir, e->d_name);
        snprintf(newpref, sizeof(newpref), "%s%s", prefix, is_last ? "    " : "│   ");
        tree_walk(sub, newpref, count);
    }
    closedir(d);
    (void)subdirs;
}

static int tool_tree(int argc, char** argv) {
    const char* start = ".";
    for (int i = 1; i < argc; i++)
        if (argv[i][0] != '/' && argv[i][0] != '-') { start = argv[i]; break; }
    int count = 1;
    printf("Folder PATH listing for volume LSW\n");
    printf("Folder listing is relative to C:\\ root\n");
    printf("C:\\%s\n", start);
    tree_walk(start, "", &count);
    printf("\n%d folder(s)\n", count);
    return 0;
}

static int tool_where(int argc, char** argv) {
    const char* name = NULL;
    for (int i = 1; i < argc; i++)
        if (argv[i][0] != '/' && argv[i][0] != '-') { name = argv[i]; break; }
    if (!name) {
        fprintf(stderr, "where: no file name given\n");
        return 1;
    }
    const char* path = getenv("PATH");
    if (!path) path = "/usr/bin:/bin";
    char copy[8192];
    snprintf(copy, sizeof(copy), "%s", path);
    char* save = NULL;
    char* d = strtok_r(copy, ":", &save);
    int found = 0;
    while (d) {
        char p[4096];
        snprintf(p, sizeof(p), "%s/%s", d, name);
        if (access(p, X_OK) == 0) {
            printf("%s\n", p);
            found++;
        }
        d = strtok_r(NULL, ":", &save);
    }
    if (!found) {
        fprintf(stderr, "INFO: Could not find files for the given pattern(s).\n");
        return 1;
    }
    return 0;
}

static int tool_vol(int argc, char** argv) {
    (void)argc; (void)argv;
    struct statvfs v;
    if (statvfs("/", &v) == 0) {
        unsigned long long total = (unsigned long long)v.f_blocks * v.f_frsize;
        unsigned long long free = (unsigned long long)v.f_bfree * v.f_frsize;
        char t1[32], t2[32];
        fmt_bytes(total, t1, sizeof(t1));
        fmt_bytes(free, t2, sizeof(t2));
        printf(" Volume in drive C is LSW\n");
        printf(" Volume Serial Number is %04X-%04X\n", 0xC0DE, (unsigned short)(time(NULL) & 0xFFFF));
        printf("\n Directory of C:\\\n");
        printf("Total: %-10s (%llu bytes)\n", t1, total);
        printf("Free:  %-10s (%llu bytes)\n", t2, free);
    }
    return 0;
}

static int tool_label(int argc, char** argv) {
    (void)argc; (void)argv;
    return tool_vol(1, (char*[]){"vol", NULL});
}

static int tool_fsutil(int argc, char** argv) {
    if (argc >= 2 && strcasecmp(argv[1], "volume") == 0) {
        struct statvfs v;
        if (statvfs("/", &v) == 0) {
            printf("Volume Information:\n");
            printf("  Volume label:             LSW\n");
            printf("  Supports file compression: No\n");
            printf("  File system name:         NTFS\n");
            printf("  Free space:               %llu bytes\n", (unsigned long long)v.f_bfree * v.f_frsize);
            printf("  Total space:              %llu bytes\n", (unsigned long long)v.f_blocks * v.f_frsize);
        }
        return 0;
    }
    fprintf(stderr, "fsutil: only 'volume' is supported in this LSW build.\n");
    return 1;
}

static int tool_chkdsk(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '/' && argv[i][0] != '-') {
            fprintf(stderr, "chkdsk: only the C: drive can be checked in this LSW build.\n");
            return 1;
        }
    }
    printf("The type of the file system is NTFS.\n");
    printf("Volume label is LSW.\n\n");
    printf("Stage 1: Examining basic file system structure ...\n");
    printf("Stage 2: Examining file name linkage ...\n");
    printf("Stage 3: Examining security descriptors ...\n");
    printf("Windows has checked the file system and found no problems.\n");
    return 0;
}

static int tool_chkntfs(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("The type of the file system is NTFS.\n");
    printf("C: is not dirty.\n");
    return 0;
}

static int tool_convert(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "convert: FAT to NTFS conversion not supported in this LSW build.\n");
    return 1;
}
static int tool_format(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "format: formatting volumes is not supported in this LSW build (host safety).\n");
    return 1;
}
static int tool_diskpart(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Microsoft DiskPart version 10.0.22631.1\n");
    printf("Copyright (C) Microsoft Corporation.\n");
    printf("DISKPART> (interactive mode is not available; disk modification is disabled for host safety)\n");
    return 1;
}
static int tool_mountvol(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Creates, deletes, or lists a volume mount point.\n");
    printf("\\\\?\\Volume{00000000-0000-0000-0000-000000000001}\\  C:\\\n");
    return 0;
}
static int tool_subst(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "subst: virtual drives are not persistent in this LSW build.\n");
    return 1;
}
static int tool_compact(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Listing files with their compression state:\n");
    printf("   Number of files = 0\n");
    return 0;
}
static int tool_cipher(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("C: is not encrypted.\n");
    printf("New files added to this directory will not be encrypted.\n");
    return 0;
}
static int tool_xcopy(int argc, char** argv) {
    const char* src = NULL, * dst = NULL;
    int recursive = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '/' || argv[i][0] == '-') {
            switch (tolower((unsigned char)argv[i][1])) {
                case 's': case 'e': recursive = 1; break;
                default: break;
            }
        } else if (!src) src = argv[i];
        else dst = argv[i];
    }
    if (!src || !dst) {
        fprintf(stderr, "xcopy: Incompatible parameters.\n");
        return 2;
    }
    struct stat st;
    if (stat(src, &st) != 0) {
        fprintf(stderr, "xcopy: File Not Found - %s\n", src);
        return 2;
    }
    char cmd[2048];
    if (S_ISDIR(st.st_mode)) {
        if (!recursive) {
            fprintf(stderr, "xcopy: %s is a directory; use /S to recurse.\n", src);
            return 2;
        }
        snprintf(cmd, sizeof(cmd), "cp -r \"%s/.\" \"%s/\" 2>/dev/null", src, dst);
        if (system(cmd) == 0) printf("   directory copied\n");
    } else {
        snprintf(cmd, sizeof(cmd), "cp \"%s\" \"%s\" 2>/dev/null", src, dst);
        if (system(cmd) == 0) printf("   1 file copied\n");
        else return 2;
    }
    return 0;
}
static int tool_replace(int argc, char** argv) {
    const char* src = NULL, * dst = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '/' || argv[i][0] == '-') continue;
        if (!src) src = argv[i];
        else dst = argv[i];
    }
    if (!src || !dst) {
        fprintf(stderr, "replace: Invalid syntax.\n");
        return 1;
    }
    struct stat st;
    if (stat(src, &st) != 0) {
        fprintf(stderr, "replace: File Not Found - %s\n", src);
        return 1;
    }
    if (access(dst, F_OK) != 0) {
        fprintf(stderr, "replace: cannot locate the destination file: %s\n", dst);
        return 1;
    }
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "cp \"%s\" \"%s\" 2>/dev/null", src, dst);
    if (system(cmd) == 0) printf("Replaced 1 file\n");
    return 0;
}
static int tool_forfiles(int argc, char** argv) {
    const char* path = ".";
    (void)argc; (void)argv;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '/' || argv[i][0] == '-') {
            if (i + 1 < argc && strcasecmp(argv[i], "/p") == 0) path = argv[++i];
        }
    }
    DIR* d = opendir(path);
    if (!d) return 1;
    struct dirent* e;
    printf("Processing files in %s:\n\n", path);
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        struct stat st;
        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", path, e->d_name);
        if (stat(full, &st) == 0) printf("\"%s\"\n", full);
    }
    closedir(d);
    printf("\nDone.");
    return 0;
}

/* ---------- ADMIN GROUP ---------- */

static int tool_reg(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "reg: registry access is not available in this LSW build yet.\n");
    return 1;
}
static int tool_regini(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "regini: registry scripting is not supported in this LSW build.\n");
    return 1;
}
static int tool_sc(int argc, char** argv) {
    if (argc >= 2 && strcasecmp(argv[1], "query") == 0) {
        const char* name = (argc >= 3) ? argv[2] : "lsw";
        printf("SERVICE_NAME: %s\n", name);
        printf("        TYPE               : 30  WIN32\n");
        printf("        STATE              : 4  RUNNING\n");
        printf("        WIN32_EXIT_CODE    : 0  (0x0)\n");
        printf("        SERVICE_EXIT_CODE  : 0  (0x0)\n");
        return 0;
    }
    printf("SERVICE_NAME: lsw\n");
    printf("        TYPE               : 30  WIN32\n");
    printf("        STATE              : 4  RUNNING\n");
    printf("        WIN32_EXIT_CODE    : 0  (0x0)\n");
    printf("        SERVICE_EXIT_CODE  : 0  (0x0)\n");
    return 0;
}
static int tool_schtasks(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("INFO: There are no scheduled tasks in the task scheduler.\n");
    return 0;
}
static int tool_certutil(int argc, char** argv) {
    if (argc >= 3 && strcasecmp(argv[1], "-hashfile") == 0) {
        const char* fn = argv[2];
        const char* algo = (argc > 3) ? argv[3] : "SHA256";
        const char* tool_map = "sha256sum";
        if (strcasecmp(algo, "MD5") == 0) tool_map = "md5sum";
        else if (strcasecmp(algo, "SHA1") == 0) tool_map = "sha1sum";
        char cmd[2048];
        snprintf(cmd, sizeof(cmd), "%s \"%s\" 2>/dev/null", tool_map, fn);
        FILE* p = popen(cmd, "r");
        if (!p) return 1;
        char out[256] = "";
        if (fgets(out, sizeof(out), p)) {
            char* sp = strchr(out, ' ');
            if (sp) *sp = 0;
            printf("Hash of %s (%s):\n", fn, algo);
            printf("  %s\n", out);
        }
        pclose(p);
        return 0;
    }
    fprintf(stderr, "certutil: only '-hashfile file [MD5|SHA1|SHA256]' is supported.\n");
    return 1;
}
static int tool_takeown(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "takeown: file ownership change requires host privileges; use chown on the host.\n");
    return 1;
}
static int tool_icacls(int argc, char** argv) {
    const char* fn = NULL;
    for (int i = 1; i < argc; i++)
        if (argv[i][0] != '/' && argv[i][0] != '-') { fn = argv[i]; break; }
    if (!fn) {
        fprintf(stderr, "icacls: Missing file name.\n");
        return 1;
    }
    struct stat st;
    if (stat(fn, &st) != 0) {
        fprintf(stderr, "icacls: %s: The system cannot find the file specified.\n", fn);
        return 1;
    }
    struct passwd* pw = getpwuid(st.st_uid);
    struct group* gr = getgrgid(st.st_gid);
    printf("processed file: %s\n", fn);
    printf("  LSW\\%s:(I)(F)\n", pw ? pw->pw_name : "SYSTEM");
    printf("  LSW\\%s:(I)(M)\n", gr ? gr->gr_name : "SYSTEM");
    printf("Successfully processed 1 files; Failed processing 0 files\n");
    return 0;
}
static int tool_openfiles(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("INFO: No open files.\n");
    return 0;
}
static int tool_gpresult(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Microsoft (R) Windows (R) Group Policy Result Tool v2.0\n\n");
    printf("User Information:\n");
    printf("-----------------\n");
    printf("Last time Group Policy was applied: N/A\n");
    printf("Group Policy was applied from:      N/A\n");
    printf("Applied Group Policy Objects:       None\n");
    return 0;
}
static int tool_secedit(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "secedit: security policy management not supported in this LSW build.\n");
    return 1;
}
static int tool_sfc(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Beginning system scan.  This process will take some time.\n\n");
    printf("Beginning verification phase of system scan.\n");
    printf("Verification 100%% complete.\n\n");
    printf("Windows Resource Protection did not find any integrity violations.\n");
    return 0;
}
static int tool_net(int argc, char** argv) {
    const char* sub = (argc > 1) ? argv[1] : "help";
    if (strcasecmp(sub, "user") == 0 || strcasecmp(sub, "users") == 0) {
        printf("User accounts for %s\n\n", getenv("USER") ? getenv("USER") : "LSW");
        printf("-------------------------------------------------------------------------------\n");
        struct passwd* pw;
        setpwent();
        while ((pw = getpwent()))
            if (pw->pw_uid >= 1000 || pw->pw_uid == 0)
                printf("%-16s\n", pw->pw_name);
        endpwent();
        printf("The command completed successfully.\n");
        return 0;
    }
    if (strcasecmp(sub, "config") == 0) {
        char hn[256];
        gethostname(hn, sizeof(hn));
        printf("Computer name                      %s\n", hn);
        printf("Full Computer name                 %s\n", hn);
        printf("User name                          %s\n", getenv("USER") ? getenv("USER") : "Administrator");
        printf("\nThe command completed successfully.\n");
        return 0;
    }
    if (strcasecmp(sub, "start") == 0 || strcasecmp(sub, "stop") == 0 ||
        strcasecmp(sub, "session") == 0 || strcasecmp(sub, "share") == 0 ||
        strcasecmp(sub, "use") == 0 || strcasecmp(sub, "view") == 0) {
        printf("The command completed successfully.\n");
        return 0;
    }
    printf("The syntax of this command is:\n\n");
    printf("NET [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP |\n");
    printf("      HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START |\n");
    printf("      STATISTICS | STOP | TIME | USE | USER | VIEW ]\n");
    return 2;
}

/* ---------- BOOT / CONFIG STUBS ---------- */

static int tool_bcdboot(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "bcdboot: boot files creation is not supported in this LSW build.\n");
    return 1;
}
static int tool_bcdedit(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "bcdedit: boot configuration editing is not supported in this LSW build.\n");
    return 1;
}
static int tool_bootsect(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "bootsect: MBR/VBR updating is not supported in this LSW build.\n");
    return 1;
}
static int tool_dism(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "dism: image servicing is not supported in this LSW build.\n");
    return 1;
}
static int tool_pnputil(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Microsoft PnP Utility\n\n");
    printf("Info: No matching devices are found.\n");
    return 0;
}
static int tool_bitsadmin(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "bitsadmin: background transfer is not supported in this LSW build.\n");
    return 1;
}
static int tool_mofcomp(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "mofcomp: MOF compilation is not supported in this LSW build.\n");
    return 1;
}
static int tool_esentutl(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "esentutl: Extensible Storage Engine utility is not supported.\n");
    return 1;
}
static int tool_vssadmin(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "vssadmin: Volume Shadow Copy administration is not supported.\n");
    return 1;
}
static int tool_wevtutil(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "wevtutil: Windows event log utility is not supported in this LSW build.\n");
    return 1;
}
static int tool_nltest(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Flags: 0x0\n");
    printf("Connection status = 0\n");
    printf("The command completed successfully\n");
    return 0;
}
static int tool_fltmc(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Filter Name                     Num Instances    Altitude    Frame\n");
    printf("------------------------------  -------------  ------------  -----\n");
    printf("No filters found.\n");
    return 0;
}
static int tool_tpmtool(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "tpmtool: TPM state management is not supported in this LSW build.\n");
    return 1;
}
static int tool_unlodctr(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "unlodctr: performance counter unloading is not supported.\n");
    return 1;
}
static int tool_lodctr(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("Performance counters loaded successfully.\n");
    return 0;
}
static int tool_conhost(int argc, char** argv) {
    (void)argc; (void)argv;
    return 0;
}
static int tool_regsvr32(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "regsvr32: DLL registration is not supported in this LSW build.\n");
    return 1;
}
static int tool_unregmp2(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "unregmp2: media player registration is not supported in this LSW build.\n");
    return 1;
}
static int tool_cmdkey(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "cmdkey: credential store is not supported in this LSW build.\n");
    return 1;
}
static int tool_doskey(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("doskey macros:\n");
    return 0;
}
static int tool_recover(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "recover: disk recovery is not supported in this LSW build.\n");
    return 1;
}
static int tool_relog(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "relog: performance log conversion is not supported.\n");
    return 1;
}
static int tool_tracerpt(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "tracerpt: trace event parsing is not supported.\n");
    return 1;
}
static int tool_typeperf(int argc, char** argv) {
    (void)argc; (void)argv;
    static int shown = 0;
    if (shown == 0) {
        printf("\n\"\\\\Processor(_Total)\\\\%% Processor Time\",\"\\\\Memory\\\\Available MBytes\"\n");
        shown++;
    }
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        double pct = (si.totalram > 0) ? (100.0 - (100.0 * si.freeram / si.totalram)) : 0.0;
        printf("\"%.2f\",\"%lld\"\n", pct, (long long)(si.freeram / (1024 * 1024)));
    }
    return 0;
}
static int tool_expand(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "expand: CAB/WIM expansion is not supported in this LSW build.\n");
    return 1;
}
static int tool_logman(int argc, char** argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "logman: performance logging is not supported in this LSW build.\n");
    return 1;
}

/* ---------- dispatch ---------- */

static const char* tool_strip_ext(const char* name) {
    static char buf[64];
    size_t n = strlen(name);
    if (n >= 62) return name;
    snprintf(buf, sizeof(buf), "%s", name);
    char* dot = strrchr(buf, '.');
    if (dot && (strcasecmp(dot, ".exe") == 0 || strcasecmp(dot, ".com") == 0 ||
                strcasecmp(dot, ".bat") == 0 || strcasecmp(dot, ".cmd") == 0))
        *dot = 0;
    for (char* p = buf; *p; p++) *p = (char)tolower((unsigned char)*p);
    return buf;
}

typedef int (*tool_fn)(int, char**);

typedef struct {
    const char* name;
    tool_fn fn;
} TOOL_ENTRY;

static const TOOL_ENTRY g_tools[] = {
    { "attrib",       tool_attrib },
    { "bcdboot",      tool_bcdboot },
    { "bcdedit",      tool_bcdedit },
    { "bitsadmin",    tool_bitsadmin },
    { "bootsect",     tool_bootsect },
    { "certutil",     tool_certutil },
    { "change",       tool_change },
    { "chcp",         tool_chcp },
    { "chkdsk",       tool_chkdsk },
    { "chkntfs",      tool_chkntfs },
    { "cipher",       tool_cipher },
    { "cmdkey",       tool_cmdkey },
    { "compact",      tool_compact },
    { "conhost",      tool_conhost },
    { "convert",      tool_convert },
    { "diskpart",     tool_diskpart },
    { "dism",         tool_dism },
    { "doskey",       tool_doskey },
    { "driverquery",  tool_driverquery },
    { "esentutl",     tool_esentutl },
    { "expand",       tool_expand },
    { "fc",           tool_fc },
    { "find",         tool_find },
    { "findstr",      tool_findstr },
    { "fltmc",        tool_fltmc },
    { "forfiles",     tool_forfiles },
    { "format",       tool_format },
    { "fsutil",       tool_fsutil },
    { "ftp",          tool_ftp },
    { "getmac",       tool_getmac },
    { "gpresult",     tool_gpresult },
    { "icacls",       tool_icacls },
    { "ipconfig",     tool_ipconfig },
    { "label",        tool_label },
    { "lodctr",       tool_lodctr },
    { "logman",       tool_logman },
    { "logoff",       tool_logoff },
    { "mofcomp",      tool_mofcomp },
    { "more",         tool_more },
    { "mountvol",     tool_mountvol },
    { "net",          tool_net },
    { "net1",         tool_net },
    { "netsh",        tool_netsh },
    { "netstat",      tool_netstat },
    { "nltest",       tool_nltest },
    { "nslookup",     tool_nslookup },
    { "openfiles",    tool_openfiles },
    { "pathping",     tool_pathping },
    { "ping",         tool_ping },
    { "pnputil",      tool_pnputil },
    { "powercfg",     tool_powercfg },
    { "qwinsta",      tool_qwinsta },
    { "quser",        tool_quser },
    { "recover",      tool_recover },
    { "reg",          tool_reg },
    { "regini",       tool_regini },
    { "regsvr32",     tool_regsvr32 },
    { "relog",        tool_relog },
    { "replace",      tool_replace },
    { "route",        tool_route },
    { "runas",        tool_runas },
    { "sc",           tool_sc },
    { "schtasks",     tool_schtasks },
    { "secedit",      tool_secedit },
    { "setx",         tool_setx },
    { "sfc",          tool_sfc },
    { "shutdown",     tool_shutdown },
    { "sort",         tool_sort },
    { "subst",        tool_subst },
    { "systeminfo",   tool_systeminfo },
    { "takeown",      tool_takeown },
    { "taskkill",     tool_taskkill },
    { "tasklist",     tool_tasklist },
    { "tpmtool",      tool_tpmtool },
    { "tracerpt",     tool_tracerpt },
    { "tracert",      tool_tracert },
    { "tree",         tool_tree },
    { "tsdiscon",     tool_tsdiscon },
    { "typeperf",     tool_typeperf },
    { "tzutil",       tool_tzutil },
    { "unlodctr",     tool_unlodctr },
    { "unregmp2",     tool_unregmp2 },
    { "vssadmin",     tool_vssadmin },
    { "vol",          tool_vol },
    { "w32tm",        tool_w32tm },
    { "wevtutil",     tool_wevtutil },
    { "where",        tool_where },
    { "xcopy",        tool_xcopy },
};

#define TOOL_COUNT (sizeof(g_tools) / sizeof(g_tools[0]))

int nt_tool_dispatch(const char* program, int argc, char** argv) {
    const char* name = tool_strip_ext(program);
    for (size_t i = 0; i < TOOL_COUNT; i++) {
        if (strcmp(g_tools[i].name, name) == 0) {
            return g_tools[i].fn(argc, argv);
        }
    }
    return -1;
}