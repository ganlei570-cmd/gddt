#import <Foundation/Foundation.h>
#import <sys/sysctl.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <substrate.h>
#import "bypass.h"

static const char * const kJailPaths[] = {
    "/Applications/Cydia.app", "/Applications/Sileo.app",
    "/Library/MobileSubstrate", "/usr/sbin/sshd",
    "/etc/apt", "/private/var/lib/apt",
    "/usr/lib/TweakInject", "/usr/lib/ellekit",
    "systemhook", "ElleKit", "frida", "cynject", NULL
};
static const char * const kInjKw[] = {
    "ellekit", "substrate", "tweakinject",
    "cynject", "frida", "systemhook", NULL
};

static BOOL isJailPath(const char *p) {
    if (!p) return NO;
    for (int i = 0; kJailPaths[i]; i++)
        if (strstr(p, kJailPaths[i])) return YES;
    return NO;
}
static BOOL isInjDylib(const char *n) {
    if (!n) return NO;
    for (int i = 0; kInjKw[i]; i++)
        if (strcasestr(n, kInjKw[i])) return YES;
    return NO;
}

static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int hook_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    return (req == 31) ? 0 : orig_ptrace(req, pid, addr, data);
}

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hook_sysctl(int *mib, u_int nl, void *old, size_t *osz, void *n, size_t nsz) {
    int r = orig_sysctl(mib, nl, old, osz, n, nsz);
    if (r == 0 && nl >= 2 && mib[0] == 1 && mib[1] == 14 && old)
        *(uint32_t *)((char *)old + 32) &= ~0x800u;
    return r;
}

static kern_return_t (*orig_task_info)(task_t, task_flavor_t, integer_t *, mach_msg_type_number_t *);
static kern_return_t hook_task_info(task_t t, task_flavor_t f, integer_t *o, mach_msg_type_number_t *c) {
    return orig_task_info(t, f, o, c);
}


static uint32_t (*orig_dyld_count)(void);
static const char *(*orig_dyld_name)(uint32_t);

static uint32_t hook_dyld_count(void) {
    uint32_t tot = orig_dyld_count(), n = 0;
    for (uint32_t i = 0; i < tot; i++)
        if (!isInjDylib(orig_dyld_name(i))) n++;
    return n;
}
static const char *hook_dyld_name(uint32_t idx) {
    uint32_t tot = orig_dyld_count(), n = 0;
    for (uint32_t i = 0; i < tot; i++) {
        const char *nm = orig_dyld_name(i);
        if (!isInjDylib(nm) && n++ == idx) return nm;
    }
    return "";
}

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int hook_connect(int fd, const struct sockaddr *sa, socklen_t sl) {
    if (sa && sa->sa_family == AF_INET) {
        uint16_t port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
        if (port == 27042 || port == 27043) return -1;
    }
    return orig_connect(fd, sa, sl);
}

static int (*orig_access)(const char *, int);
static int hook_access(const char *p, int m) { return isJailPath(p) ? -1 : orig_access(p, m); }

static FILE *(*orig_fopen)(const char *, const char *);
static FILE *hook_fopen(const char *p, const char *m) { return isJailPath(p) ? NULL : orig_fopen(p, m); }

static int (*orig_stat)(const char *, struct stat *);
static int hook_stat(const char *p, struct stat *s) { return isJailPath(p) ? -1 : orig_stat(p, s); }

static char *(*orig_getenv)(const char *);
static char *hook_getenv(const char *k) {
    if (k && (!strcmp(k, "DYLD_INSERT_LIBRARIES") || !strcmp(k, "DYLD_LIBRARY_PATH")))
        return NULL;
    return orig_getenv(k);
}

static FILE *hook_popen(const char *c, const char *m) { return NULL; }
static int hook_system(const char *c) { return 0; }

static void *(*orig_dlopen)(const char *, int);
static void *hook_dlopen(const char *p, int f) { return isInjDylib(p) ? NULL : orig_dlopen(p, f); }

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int hook_sysctlbyname(const char *n, void *o, size_t *sz, void *ne, size_t nsz) {
    if (n && strstr(n, "proc")) return -1;
    return orig_sysctlbyname(n, o, sz, ne, nsz);
}


#define MH(sym, hook, orig) MSHookFunction(dlsym(RTLD_DEFAULT, sym), (void *)(hook), (void **)(orig))
#define MHN(sym, hook)      MSHookFunction(dlsym(RTLD_DEFAULT, sym), (void *)(hook), NULL)

static void hookAntiDebug(void) {
    MH("ptrace",  hook_ptrace,  &orig_ptrace);
    MH("sysctl",  hook_sysctl,  &orig_sysctl);
    MH("task_info", hook_task_info, &orig_task_info);
    MH("_dyld_image_count",   hook_dyld_count, &orig_dyld_count);
    MH("_dyld_get_image_name", hook_dyld_name,  &orig_dyld_name);
    MH("sysctlbyname", hook_sysctlbyname, &orig_sysctlbyname);
}

static void hookEnvDetect(void) {
    MH("connect", hook_connect, &orig_connect);
    MH("access",  hook_access,  &orig_access);
    MH("fopen",   hook_fopen,   &orig_fopen);
    void *sfn = dlsym(RTLD_DEFAULT, "stat64") ?: dlsym(RTLD_DEFAULT, "stat");
    if (sfn) MSHookFunction(sfn, (void *)hook_stat, (void **)&orig_stat);
    MH("getenv",  hook_getenv,  &orig_getenv);
    MHN("popen",  hook_popen);
    MHN("system", hook_system);
    MH("dlopen",  hook_dlopen,  &orig_dlopen);
}

void installBypassHooks(void) {
    hookAntiDebug();
    hookEnvDetect();
}
