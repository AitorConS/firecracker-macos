// SPDX-License-Identifier: Apache-2.0
// TEST-ONLY power-loss journal for native/devices.c. Enabled only with
//   CFLAGS="-DHVF_CRASH_JOURNAL -I<this directory>"
// Release builds (build.sh, build-native.sh) never define HVF_CRASH_JOURNAL.
//
// Every successful guest pwrite() is appended (with its data) to a journal, and
// every successful F_FULLFSYNC appends a durability point. crash_replay.py then
// rebuilds the disk a host power cut could leave behind: the image before boot
// plus all writes up to the last durability point, optionally with any ordered
// subset of later writes. Killing the VMM alone keeps the host page cache and
// cannot show this loss.
//
// Records are written before devices.c publishes the request completion, so a
// FLUSH the guest saw acknowledged always has its durability point journaled.
// HVF_CRASH_JOURNAL_LIE=1 is a negative control: FLUSH still succeeds for the
// guest but no durability point is recorded, like storage that ignores flushes.
//
// The journal is opened from devices_init(): after the exec'd VMM closes all
// ambient descriptors (inherited.rs) and before the Seatbelt sandbox is
// installed. Disk identities are also captured there, so no path or metadata
// lookups are needed once the guest runs.
#include <sys/param.h>
#include <sys/uio.h>
#include <time.h>
#define CRASH_JOURNAL_MAGIC 0x4a435648u /* "HVCJ" */
struct crash_record {
    uint32_t magic;
    uint8_t type; /* 'P' path, 'W' write+data, 'F' durable point, 'E' flush error */
    uint8_t pad[3];
    uint64_t dev, ino, seq, offset;
    uint32_t len;
    int32_t error;
};
static int crash_journal_fd = -1;
static int crash_journal_lie;
static uint64_t crash_journal_seq;
static struct { int fd; uint64_t dev, ino; } crash_journal_disks[8];
static unsigned crash_journal_disk_count;
static void crash_journal_fail(const char *why) {
    fprintf(stderr, "crash journal: %s; aborting to avoid an incomplete journal\n", why);
    _exit(98);
}
static void crash_journal_append(const struct crash_record *record, const void *data) {
    struct iovec iov[2] = {{(void *)record, sizeof(*record)}, {(void *)data, data ? record->len : 0}};
    size_t total = iov[0].iov_len + iov[1].iov_len;
    ssize_t n;
    do n = writev(crash_journal_fd, iov, data ? 2 : 1); while (n < 0 && errno == EINTR);
    if (n != (ssize_t)total) crash_journal_fail("append failed");
}
static void crash_journal_open(void) {
    if (crash_journal_fd >= 0) return;
    const char *dir = getenv("HVF_CRASH_JOURNAL_DIR");
    if (!dir || !*dir) crash_journal_fail("test build requires HVF_CRASH_JOURNAL_DIR");
    char path[1024];
    snprintf(path, sizeof(path), "%s/journal-%d-%ld.bin", dir, (int)getpid(), (long)time(NULL));
    crash_journal_fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC, 0600);
    if (crash_journal_fd < 0) crash_journal_fail("cannot create journal");
    const char *lie = getenv("HVF_CRASH_JOURNAL_LIE");
    crash_journal_lie = lie && !strcmp(lie, "1");
    fprintf(stderr, "HVF CRASH JOURNAL TEST BUILD: %s%s\n", path, crash_journal_lie ? " (flush-lie control)" : "");
}
static void crash_journal_register(int fd) {
    struct stat st;
    if (crash_journal_disk_count >= 8 || fstat(fd, &st)) crash_journal_fail("cannot register disk");
    crash_journal_disks[crash_journal_disk_count].fd = fd;
    crash_journal_disks[crash_journal_disk_count].dev = (uint64_t)st.st_dev;
    crash_journal_disks[crash_journal_disk_count].ino = (uint64_t)st.st_ino;
    crash_journal_disk_count++;
    char name[MAXPATHLEN] = {0};
    if (fcntl(fd, F_GETPATH, name)) strcpy(name, "?");
    struct crash_record p = {.magic = CRASH_JOURNAL_MAGIC, .type = 'P', .dev = (uint64_t)st.st_dev,
                             .ino = (uint64_t)st.st_ino, .len = (uint32_t)strlen(name)};
    crash_journal_append(&p, name);
}
static void crash_journal_identity(int fd, struct crash_record *record) {
    for (unsigned i = 0; i < crash_journal_disk_count; i++) {
        if (crash_journal_disks[i].fd == fd) {
            record->dev = crash_journal_disks[i].dev;
            record->ino = crash_journal_disks[i].ino;
            return;
        }
    }
    crash_journal_fail("I/O on an unregistered descriptor");
}
// Write-ahead: the intent (with data) is journaled before pwrite(), so a VMM
// kill can never leave a disk write the journal lacks. A short or failed write
// is followed by an 'S' record giving the bytes actually applied. At most the
// final intent can be missing from the disk (killed before or during pwrite).
//
// The buffer is guest RAM that the guest may still modify while a request is in
// flight. Copy it once, and journal and write that identical copy, so the
// journal can never disagree with the bytes that reached the host file.
static ssize_t crash_journal_pwrite(int fd, const void *guest_buffer, size_t count, off_t offset) {
    uint8_t *buffer = malloc(count ? count : 1);
    if (!buffer) crash_journal_fail("cannot copy write buffer");
    memcpy(buffer, guest_buffer, count);
    struct crash_record record = {.magic = CRASH_JOURNAL_MAGIC, .type = 'W'};
    crash_journal_identity(fd, &record);
    record.seq = ++crash_journal_seq;
    record.offset = (uint64_t)offset;
    record.len = (uint32_t)count;
    crash_journal_append(&record, buffer);
    ssize_t n = pwrite(fd, buffer, count, offset);
    int write_errno = errno;
    free(buffer);
    errno = write_errno;
    if (n != (ssize_t)count) {
        int saved = errno;
        struct crash_record applied = record;
        applied.type = 'S';
        applied.len = n > 0 ? (uint32_t)n : 0;
        applied.error = n < 0 ? saved : 0;
        crash_journal_append(&applied, NULL);
        errno = saved;
    }
    return n;
}
static int crash_journal_fcntl(int fd, int command) {
    if (command != F_FULLFSYNC) crash_journal_fail("unexpected fcntl");
    int result = fcntl(fd, F_FULLFSYNC);
    int saved = errno;
    struct crash_record record = {.magic = CRASH_JOURNAL_MAGIC, .type = result ? 'E' : 'F'};
    crash_journal_identity(fd, &record);
    record.seq = ++crash_journal_seq;
    record.error = result ? saved : 0;
    if (result || !crash_journal_lie) crash_journal_append(&record, NULL);
    errno = saved;
    return result;
}
#define pwrite crash_journal_pwrite
#define fcntl crash_journal_fcntl
