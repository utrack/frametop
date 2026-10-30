// Keep one KWin window's PipeWire stream alive. The parent consumes the stream;
// stdout gives its node and serial. No display capture or virtual output is used.
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <wayland-client.h>

#include "screencast-client.h"

static struct zkde_screencast_unstable_v1 *manager;
static bool stopped;
static uint64_t object_serial;

static void closed(void *data, struct zkde_screencast_stream_unstable_v1 *stream) {
    (void)data;
    (void)stream;
    fprintf(stderr, "KWin closed the window stream\n");
    stopped = true;
}

static void created(void *data, struct zkde_screencast_stream_unstable_v1 *stream, uint32_t node) {
    (void)data;
    (void)stream;
    printf("{\"node\":%u,\"serial\":%" PRIu64 "}\n", node, object_serial);
    fflush(stdout);
}

static void failed(void *data, struct zkde_screencast_stream_unstable_v1 *stream, const char *error) {
    (void)data;
    (void)stream;
    fprintf(stderr, "KWin window capture: %s\n", error);
    stopped = true;
}

static void serial(void *data, struct zkde_screencast_stream_unstable_v1 *stream, uint32_t hi, uint32_t lo) {
    (void)data;
    (void)stream;
    object_serial = ((uint64_t)hi << 32) | lo;
}

static const struct zkde_screencast_stream_unstable_v1_listener stream_listener = {
    .closed = closed, .created = created, .failed = failed, .serial = serial,
};

static void global(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version) {
    (void)data;
    if (strcmp(interface, zkde_screencast_unstable_v1_interface.name) == 0) {
        manager = wl_registry_bind(registry, name, &zkde_screencast_unstable_v1_interface, version < 6 ? version : 6);
    }
}

static void removed(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data;
    (void)registry;
    (void)name;
}

int main(int argc, char **argv) {
    if (argc != 2 || !argv[1][0]) {
        fprintf(stderr, "usage: ft-wincast KWIN_WINDOW_UUID\n");
        return 2;
    }
    // A dead exporter must not leave a capture session behind.
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || getppid() == 1) return 1;
    struct wl_display *display = wl_display_connect(NULL);
    if (!display) {
        fprintf(stderr, "Cannot connect to the existing Wayland session: %s\n", strerror(errno));
        return 1;
    }
    struct wl_registry *registry = wl_display_get_registry(display);
    const struct wl_registry_listener listener = {.global = global, .global_remove = removed};
    wl_registry_add_listener(registry, &listener, NULL);
    if (wl_display_roundtrip(display) < 0 || !manager) {
        fprintf(stderr, "KWin screencast interface unavailable; check this helper's desktop permission entry\n");
        wl_registry_destroy(registry);
        wl_display_disconnect(display);
        return 1;
    }
    struct zkde_screencast_stream_unstable_v1 *stream =
        zkde_screencast_unstable_v1_stream_window(manager, argv[1], ZKDE_SCREENCAST_UNSTABLE_V1_POINTER_EMBEDDED);
    zkde_screencast_stream_unstable_v1_add_listener(stream, &stream_listener, NULL);
    while (!stopped && wl_display_dispatch(display) >= 0) {}
    zkde_screencast_stream_unstable_v1_close(stream);
    zkde_screencast_unstable_v1_destroy(manager);
    wl_registry_destroy(registry);
    wl_display_flush(display);
    wl_display_disconnect(display);
    return 0;
}
