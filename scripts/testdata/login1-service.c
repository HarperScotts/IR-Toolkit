/* Synthetic private-bus test peer, NOT logind. No login, process or session
 * management. Minimal public libsystemd declarations avoid a development-header
 * requirement in the existing test image. Never link into the production tool.
 * Public API: systemd/src/systemd/sd-bus.h. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct sd_bus sd_bus;
typedef struct sd_bus_message sd_bus_message;
typedef struct sd_bus_slot sd_bus_slot;
typedef struct sd_bus_error sd_bus_error;
typedef int (*handler)(sd_bus_message *, void *, sd_bus_error *);
extern int sd_bus_new(sd_bus **);
extern int sd_bus_set_address(sd_bus *, const char *);
extern int sd_bus_set_bus_client(sd_bus *, int);
extern int sd_bus_start(sd_bus *);
extern int sd_bus_add_filter(sd_bus *, sd_bus_slot **, handler, void *);
extern int sd_bus_request_name(sd_bus *, const char *, uint64_t);
extern int sd_bus_process(sd_bus *, sd_bus_message **);
extern int sd_bus_wait(sd_bus *, uint64_t);
extern int sd_bus_message_is_method_call(sd_bus_message *, const char *, const char *);
extern int sd_bus_message_get_auto_start(sd_bus_message *);
extern int sd_bus_message_get_allow_interactive_authorization(sd_bus_message *);
extern int sd_bus_reply_method_return(sd_bus_message *, const char *, ...);
extern int sd_bus_reply_method_errorf(sd_bus_message *, const char *, const char *, ...);

static int reply(sd_bus_message *message, void *userdata, sd_bus_error *error) {
    (void)error;
    const char *mode = userdata;
    int list = sd_bus_message_is_method_call(message, "org.freedesktop.login1.Manager", "ListSessions");
    int properties = sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "GetAll");
    if (!list && !properties) return 0;
    if (sd_bus_message_get_auto_start(message) || sd_bus_message_get_allow_interactive_authorization(message))
        return sd_bus_reply_method_errorf(message, "org.freedesktop.DBus.Error.AccessDenied", "unsafe call flags");
    if (list) {
        if (strcmp(mode, "empty") == 0) return sd_bus_reply_method_return(message, "a(susso)", 0);
        return sd_bus_reply_method_return(message, "a(susso)", 1, "s1", (uint32_t)1000, "Alice", "", "/org/freedesktop/login1/session/s1");
    }
    if (strcmp(mode, "deny") == 0)
        return sd_bus_reply_method_errorf(message, "org.freedesktop.DBus.Error.AccessDenied", "synthetic denied properties");
    if (strcmp(mode, "vanish") == 0)
        return sd_bus_reply_method_errorf(message, "org.freedesktop.DBus.Error.UnknownObject", "synthetic vanished object");
    return sd_bus_reply_method_return(message, "a{sv}", 3, "Active", "b", 0, "Leader", "u", (uint32_t)42, "State", "s", "online");
}

int main(int argc, char **argv) {
    if (argc != 3 || strncmp(argv[1], "unix:path=/tmp/", 15) != 0) return 2;
    alarm(30);
    sd_bus *bus = NULL;
    if (sd_bus_new(&bus) < 0 || sd_bus_set_address(bus, argv[1]) < 0 || sd_bus_set_bus_client(bus, 1) < 0 ||
        sd_bus_start(bus) < 0 || sd_bus_add_filter(bus, NULL, reply, argv[2]) < 0 ||
        sd_bus_request_name(bus, "org.freedesktop.login1", 0) < 0) return 1;
    puts("ready"); fflush(stdout);
    for (;;) {
        int r = sd_bus_process(bus, NULL);
        if (r < 0) return 1;
        if (r == 0 && sd_bus_wait(bus, UINT64_C(1000000)) < 0) return 1;
    }
}
