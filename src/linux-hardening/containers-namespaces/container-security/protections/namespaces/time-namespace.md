# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The time namespace virtualizes selected monotonic-style clocks instead of the host wall clock. In practice this means private offsets for **`CLOCK_MONOTONIC`** and **`CLOCK_BOOTTIME`**, plus the closely related **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, and **`CLOCK_BOOTTIME_ALARM`** views. It does **not** virtualize **`CLOCK_REALTIME`**, so `date` and certificate-expiry logic still observe the host wall clock unless some other mechanism interferes.

The main purpose is to let a process observe controlled elapsed-time offsets without changing the host's global time view. This is useful for checkpoint/restore workflows, deterministic testing, and advanced runtime behavior. It is not usually a headline isolation control in the same way as mount or user namespaces, but it still contributes to making the process environment more self-contained.

From an offensive point of view, this namespace is usually more relevant for **reconnaissance, timer skew, and runtime understanding** than for a direct breakout. Still, it matters because more container runtimes and checkpoint/restore workflows are now able to request it explicitly.

## Lab

If the host kernel and userspace support it, you can inspect the namespace with:

```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```

Support varies by kernel and tool versions, so this page is more about understanding the mechanism than expecting it to be visible in every lab environment. The important observation is that `date` should still reflect the host wall clock, while monotonic/boottime-based values are the ones that change when nonzero offsets are configured.

### Creation Nuance

Time namespaces are slightly unusual compared to mount, PID, or network namespaces:

- `unshare(CLONE_NEWTIME)` creates a new time namespace for **future children**.
- The calling task stays in its current time namespace.
- `/proc/<pid>/ns/time_for_children` is therefore often more interesting than `/proc/<pid>/ns/time` when debugging runtime setup.

The write window is also special. Offsets in `/proc/<pid>/timens_offsets` must be written before the new time namespace is fully populated with running tasks; in practice runtimes do this during the narrow setup window between namespace creation and starting the final payload. Once a task is already running there, later writes fail with `EACCES`. This is why low-level runtimes handle time-namespace setup as an early bootstrap step instead of trying to patch offsets from inside an already-started container process.

### Time Offsets

Linux time namespaces expose the per-namespace offsets through `/proc/<pid>/timens_offsets`. The format is a set of clock names or IDs plus second/nanosecond deltas relative to the initial time namespace.

In practice, the most reliable user-facing workflow is to let `unshare` write those offsets for you:

```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```

The important point is not the exact command syntax but the behavior: a container can observe a different uptime-like view without changing the host wall clock.

### `unshare` Helper Flags

Recent `util-linux` versions provide convenience flags that write the offsets automatically during namespace creation:

```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```

These flags are mostly a usability improvement, but they also make it easier to recognize the feature in documentation, test harnesses, and runtime wrappers.

## Runtime Usage

Time namespaces are newer and less universally exercised than mount or PID namespaces. OCI Runtime Specification v1.1 added explicit support for the `time` namespace and the `linux.timeOffsets` field, and modern runtimes can map that data into the kernel bootstrap flow. A minimal OCI fragment looks like:

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

This matters because it turns time namespacing from a niche kernel primitive into something that runtimes can request portably. It also explains why runtime internals need an explicit synchronization step: the offset must be written to `/proc/<pid>/timens_offsets` before the container payload fully enters the new namespace.

Checkpoint/restore stacks such as CRIU are one of the main real-world reasons this exists at all. Without time namespaces, restoring a paused workload would make monotonic and boot-time clocks jump by the amount of time the workload spent suspended.

## Security Impact

There are fewer classic breakout stories centered on the time namespace than on other namespace types. The risk here is usually not that the time namespace directly enables escape, but that readers ignore it completely and therefore miss how advanced runtimes may be shaping process behavior.

In specialized environments, altered monotonic or boottime views can affect:

- timeout and retry behavior
- watchdogs and lease logic
- `timerfd`, `nanosleep`, and `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry and uptime-based heuristics

So while this is rarely the first namespace you abuse, it can absolutely explain "impossible" timing behavior during an assessment.

## Abuse

There is usually no direct breakout primitive here, but altered clock behavior can still be useful for understanding the execution environment, identifying advanced runtime features, and spotting timer-based logic that is measured against monotonic clocks instead of wall clock time:

```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```

If you are comparing two processes, differences here can help explain odd timing behavior, checkpoint/restore artifacts, or environment-specific logging mismatches.

Practical attacker-relevant angles:

- confuse backoff, sleep, or watchdog logic implemented with monotonic clocks
- explain why `/proc/uptime` and timer-driven behavior disagree with host-side wall-clock expectations
- recognize CRIU/checkpoint-restore workflows and other advanced runtime features
- spot environments where joining a target time namespace with `nsenter -T -t <pid> -- ...` may reproduce container-local timer behavior for debugging or post-exploitation

Impact:

- almost always reconnaissance or environment understanding
- useful for explaining logging, uptime, or checkpoint/restore anomalies
- useful for analyzing monotonic-time-based sleeps, retries, and timers
- not normally a direct container-escape mechanism by itself

The important abuse nuance is that time namespaces do not virtualize `CLOCK_REALTIME`, so they do not by themselves let an attacker falsify the host wall clock or directly break certificate-expiry checks system-wide. Their value is mostly in confusing monotonic-time-based logic, reproducing environment-specific bugs, or understanding advanced runtime behavior.

## Checks

These checks are mostly about confirming whether the runtime is using a private time namespace at all and whether it actually set nonzero offsets.

```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```

What is interesting here:

- In many environments these values will not lead to an immediate security finding, but they do tell you whether a specialized runtime feature is in play.
- If `time_for_children` differs from `time`, the caller may have prepared a child-only time namespace that it has not entered itself.
- If `date` matches the host but monotonic/boottime-based values do not, you are probably looking at time namespacing rather than wall-clock tampering.
- If you are comparing two processes, differences here may explain confusing timing or checkpoint/restore behavior.

For most container breakouts, the time namespace is not the first control you will investigate. Still, a complete container-security section should mention it because it is part of the modern kernel model and occasionally matters in advanced runtime scenarios.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
