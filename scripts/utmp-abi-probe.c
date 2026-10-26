/* Developer-only Linux ABI experiment. Never opens an accounting file or calls
 * getutent/pututline. Emits two synthetic objects and measured header layout.
 * Compile natively: cc -std=c11 -Wall -Wextra -Werror utmp-abi-probe.c -o probe
 * This is NOT evidence of the ABI used by an existing file's writer. */
#define _GNU_SOURCE
#ifndef __linux__
#error "This probe must be built with Linux headers and run on that target"
#endif
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <utmp.h>

#if defined(__aarch64__)
#define PROBE_ARCH "aarch64"
#elif defined(__x86_64__)
#define PROBE_ARCH "x86_64"
#else
#define PROBE_ARCH "unidentified"
#endif

#define SIGNED(v) _Generic((v), signed char: 1, short: 1, int: 1, long: 1, long long: 1, default: 0)
#define FIELD(key, field, sign) printf("\"%s\":{\"offset\":%zu,\"size\":%zu,\"signed\":%s}", key, offsetof(struct utmp, field), sizeof(u.field), (sign) ? "true" : "false")
#define NUMBER(key, field) FIELD(key, field, SIGNED(u.field))
#define ARRAY(key, field) FIELD(key, field, 0)

static void fill(void *target, size_t size, unsigned seed) {
    unsigned char *p = target;
    for (size_t i = 0; i < size; ++i) p[i] = (unsigned char)(seed + 17 * i);
}

static void sample(int negative) {
    struct utmp u;
    memset(&u, 0, sizeof(u)); /* Include padding, never uninitialized memory. */
    u.ut_type = negative ? -1 : 0x1234;
    u.ut_pid = negative ? -2 : 0x01020304;
    u.ut_session = negative ? -3 : 0x10203040;
    u.ut_tv.tv_sec = negative ? -4 : 1700000000;
    u.ut_tv.tv_usec = negative ? -5 : 123456;
    fill(u.ut_line, sizeof(u.ut_line), 11);
    fill(u.ut_id, sizeof(u.ut_id), 22);
    fill(u.ut_user, sizeof(u.ut_user), 33);
    fill(u.ut_host, sizeof(u.ut_host), 44);
    fill(u.ut_addr_v6, sizeof(u.ut_addr_v6), 55);
    const unsigned char *bytes = (const unsigned char *)&u;
    putchar('"');
    for (size_t i = 0; i < sizeof(u); ++i) printf("%02x", bytes[i]);
    putchar('"');
}

int main(void) {
    struct utmp u;
    uint32_t endian = UINT32_C(0x01020304);
    unsigned char first = *(unsigned char *)&endian;
    const char *order = first == 4 ? "little" : first == 1 ? "big" : "unsupported";
    printf("{\"schema\":\"ir-utmp-abi-probe-v1\",\"architecture\":\"%s\",\"byte_order\":\"%s\",", PROBE_ARCH, order);
#ifdef __GLIBC__
    printf("\"libc_headers\":\"glibc-%d.%d\",", __GLIBC__, __GLIBC_MINOR__);
#else
    /* Absence of __GLIBC__ does NOT identify musl or the file writer. */
    printf("\"libc_headers\":\"unidentified\",");
#endif
    printf("\"record_size\":%zu,\"alignment\":%zu,\"fields\":{", sizeof(u), _Alignof(struct utmp));
    NUMBER("type", ut_type); putchar(',');
    NUMBER("pid", ut_pid); putchar(',');
    NUMBER("session", ut_session); putchar(',');
    NUMBER("seconds", ut_tv.tv_sec); putchar(',');
    NUMBER("microseconds", ut_tv.tv_usec); putchar(',');
    ARRAY("line", ut_line); putchar(',');
    ARRAY("id", ut_id); putchar(',');
    ARRAY("user", ut_user); putchar(',');
    ARRAY("host", ut_host); putchar(',');
    ARRAY("address_bytes", ut_addr_v6);
    printf("},\"constants\":{\"user_process\":%d,\"login_process\":%d,\"dead_process\":%d,\"boot_time\":%d},\"samples\":[", USER_PROCESS, LOGIN_PROCESS, DEAD_PROCESS, BOOT_TIME);
    sample(0); putchar(','); sample(1);
    puts("]}");
    return ferror(stdout) ? 1 : 0;
}
