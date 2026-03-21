# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The time namespace virtualizes selected clocks, especially **`CLOCK_MONOTONIC`** and **`CLOCK_BOOTTIME`**. It is a newer and more specialized namespace than mount, PID, network, or user namespaces, and it is rarely the first thing an operator thinks about when discussing container hardening. Even so, it is part of the modern namespace family and worth understanding conceptually.

The main purpose is to let a process observe controlled offsets for certain clocks without changing the host's global time view. This is useful for checkpoint/restore workflows, deterministic testing, and some advanced runtime behavior. It is not usually a headline isolation control in the same way as mount or user namespaces, but it still contributes to making the process environment more self-contained.

## Lab

If the host kernel and userspace support it, you can inspect the namespace with:

```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```

Support varies by kernel and tool versions, so this page is more about understanding the mechanism than expecting it to be visible in every lab environment.

### Time Offsets

Linux time namespaces virtualize offsets for `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`. The current per-namespace offsets are exposed through `/proc/<pid>/timens_offsets`, which on supporting kernels can also be modified by a process that holds `CAP_SYS_TIME` inside the relevant namespace:

```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```

The file contains nanosecond deltas. Adjusting `monotonic` by two days changes uptime-like observations inside that namespace without changing the host wall clock.

### `unshare` Helper Flags

Recent `util-linux` versions provide convenience flags that write the offsets automatically:

```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```

These flags are mostly a usability improvement, but they also make it easier to recognize the feature in documentation and testing.

## Runtime Usage

Time namespaces are newer and less universally exercised than mount or PID namespaces. OCI Runtime Specification v1.1 added explicit support for the `time` namespace and the `linux.timeOffsets` field, and newer `runc` releases implement that part of the model. A minimal OCI fragment looks like:

```json
{
  "linux": {
    "namespaces": [
      { "type": "time" }
    ],
    "timeOffsets": {
      "monotonic": 86400,
      "boottime": 600
    }
  }
}
```

This matters because it turns time namespacing from a niche kernel primitive into something that runtimes can request portably.

## Security Impact

There are fewer classic breakout stories centered on the time namespace than on other namespace types. The risk here is usually not that the time namespace directly enables escape, but that readers ignore it completely and therefore miss how advanced runtimes may be shaping process behavior. In specialized environments, altered clock views can affect checkpoint/restore, observability, or forensic assumptions.

## Abuse

There is usually no direct breakout primitive here, but altered clock behavior can still be useful for understanding the execution environment and identifying advanced runtime features:

```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```

If you are comparing two processes, differences here can help explain odd timing behavior, checkpoint/restore artifacts, or environment-specific logging mismatches.

Impact:

- almost always reconnaissance or environment understanding
- useful for explaining logging, uptime, or checkpoint/restore anomalies
- not normally a direct container-escape mechanism by itself

The important abuse nuance is that time namespaces do not virtualize `CLOCK_REALTIME`, so they do not by themselves let an attacker falsify the host wall clock or directly break certificate-expiry checks system-wide. Their value is mostly in confusing monotonic-time-based logic, reproducing environment-specific bugs, or understanding advanced runtime behavior.

## Checks

These checks are mostly about confirming whether the runtime is using a private time namespace at all.

```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```

What is interesting here:

- In many environments these values will not lead to an immediate security finding, but they do tell you whether a specialized runtime feature is in play.
- If you are comparing two processes, differences here may explain confusing timing or checkpoint/restore behavior.

For most container breakouts, the time namespace is not the first control you will investigate. Still, a complete container-security section should mention it because it is part of the modern kernel model and occasionally matters in advanced runtime scenarios.
