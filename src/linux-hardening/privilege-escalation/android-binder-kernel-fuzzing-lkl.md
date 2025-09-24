# Android Binder Driver Fuzzing with LKL (Stateful Grammar + Race Reproduction)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Android Binder is the core IPC mechanism in Android. Many historical local privilege escalations in Android arise from logic/race bugs in Binder’s complex state machine (reference counting, cross-client work queues, object lifetimes), not just malformed payloads. While coverage-guided fuzzers like syzkaller reach high line/edge coverage for Binder ioctls, they can miss bugs that require:

- Multi-client, stateful sequences (e.g., valid handles, buffers reused across commands)
- Strict protocol rules (sync replies, no self-send, single context manager)
- Precise thread interleavings around lock/unlock windows

This page distills a practical approach to find and reproduce such bugs using Linux Kernel Library (LKL): a userspace-build of the Linux kernel that lets a custom fuzzing harness call real kernel code via lkl_syscall, with deterministic control and easy instrumentation.

Key ideas:
- Stateful, structure-aware grammar for 3 actors (context manager + 2 clients)
- Scatter–gather correctness for binder_buffer_object groups to avoid shallow validation loops
- Harness-managed per-client state (handles, buffer pointers) and default reply handlers
- Randomized, harness-controlled scheduler by inserting schedule() near Binder lock/unlock to explore interleavings
- Exact reproduction of known races (e.g., CVE-2020-0423) and PoC seed for CVE-2023-20938

---

## Why coverage ≠ state exploration (limits of syzkaller on Binder)

syzkaller provides structure-aware, coverage-guided fuzzing and has found critical Binder bugs (e.g., CVE‑2019‑2215 “Bad Binder”). However, Binder bugs often hinge on:
- Data dependencies: coherent binder_buffer_object sets that describe pointer relationships and offsets for complex flattened objects.
- State dependencies: operations like BC_FREE_BUFFER require pointers/handles produced by prior ioctls; transactions are synchronous and obey rules (no self-send, single pending per target).
- Multi-process coordination: a single context manager per boot, realistic cross-process routing across multiple clients.

Result: you can hit the line with the bug but still fail to trigger the corruption if you don’t orchestrate the exact multi-client sequence and interleaving.

---

## Binder dependencies your harness must model

1) Structure-aware scatter–gather
- Flattened objects are accompanied by binder_buffer_object metadata describing child pointers and offsets. Naive mutation breaks invariants and stalls in validation.

Example user object with two pointers:

```c
struct object {
  char *x_ptr;
  char *y_ptr;
};
```

A valid transaction needs three coherent binder_buffer_object entries (parent + two children) with consistent sizes/offsets so unmarshalling succeeds.

2) Stateful protocol rules
- Synchronous transactions require default reply handlers to progress.
- No self-send; no multiple pending transactions to the same target.
- Operations like BC_FREE_BUFFER need a buffer pointer returned by an earlier ioctl; the harness must track and reuse it.

3) Multi-process topology
- Only one process can register as context manager per boot (BINDER_SET_CONTEXT_MGR). Keep a persistent context manager and drive two additional clients (T1/T2) per testcase for realistic cross-process IPC.

---

## LKL-based Binder fuzzing: design and build

LKL compiles the Linux kernel into a userspace library and exposes syscalls via lkl_syscall. That enables fast iteration, deterministic control, and convenient instrumentation without a VM.

- Upstream fuzzer: tools/lkl/fuzzers/binder (randomized scheduler not upstreamed)
- Grammar/mutation: libprotobuf‑mutator generates protobuf testcases; harness parses textproto for deterministic reproduction
- Sanitizers: KASAN enabled in LKL build; UBSAN recommended for declared‑bounds issues

Build (from LKL README):

```bash
# 1) Build libprotobuf‑mutator and bundled protobuf once
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

# 2) Build Binder fuzzer (replace X with jobs)
make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -jX
# Binary at: tools/lkl/fuzzers/binder/binder-fuzzer
```

Reproduce CVE‑2023‑20938 with the provided seed (after source rollback per README):

```bash
# After applying the rollback patches documented upstream, rebuild and run seed
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

See upstream README for exact patch snippets and expected KASAN report.

---

## Stateful grammar: three actors and per-client state

Define a protobuf “program” describing sequences across 3 actors:
- C0: persistent context manager (does BINDER_SET_CONTEXT_MGR once per boot)
- C1/C2: clients that issue ioctls and Binder commands

Harness responsibilities:
- Enforce Binder rules (sync replies, no self-send, no multi‑pending)
- Maintain per‑client state: service handles, buffer addresses (for BC_FREE_BUFFER), pending transactions
- Auto‑reply with minimal valid Parcels so sessions move beyond error paths
- Expose testcases as textproto for debugging/reproduction

This moves the fuzzer from “random syscalls” to “valid multi‑client sessions,” letting it explore deep logic/state transitions instead of bouncing on validators.

---

## Race exploration via randomized scheduler (instrumented Binder)

LKL runs a syscall to completion on a single kernel thread—no preemption. To explore interleavings:
- Insert schedule() at key Binder lock/unlock edges (e.g., around binder_work and buffer lifetime transitions)
- When reached, the kernel yields to a harness-controlled scheduler selecting the next client thread (randomized or enumerated)
- Replaying the same logical testcase with many schedules amplifies racy windows and surfaces UAFs/double‑frees

Note: The upstreamed fuzzer does not include the randomized scheduler; you can carry a small patchset locally while triaging races.

---

## Case study: Reproducing CVE‑2020‑0423 (binder_work UAF)

Required cross-client sequence:

1) T1 → T2 sends a transaction containing BINDER_TYPE_WEAK_BINDER
2) T1 issues BINDER_THREAD_EXIT ioctl
3) Kernel (T1) enters binder_release_work to clean T1’s binder_work before exit
4) T2 issues BC_FREE_BUFFER to free the received transaction buffer
5) Kernel (T2) binder_transaction_buffer_release frees the buffer; the embedded binder_work from the weak binder is freed
6) Kernel (T1) later in binder_release_work touches the already‑freed binder_work → use‑after‑free

Why fuzzers struggle: demands two linked clients, valid stateful inputs (a real buffer pointer), and a tight interleaving near lock boundaries. The instrumented-scheduler approach lets you systematically hit the UAF window.

---

## Practical checklist

- Use a persistent context manager (BINDER_SET_CONTEXT_MGR once per boot)
- Drive two clients (T1/T2) per testcase; ensure default reply handlers
- Track and reuse per-client state (handles; buffer pointers for BC_FREE_BUFFER)
- Generate coherent binder_buffer_object groups to preserve data invariants
- Add schedule() near Binder lock/unlock to explore interleavings; drive a randomized scheduler from the harness
- Run with KASAN; add UBSAN for declared‑bounds errors; triage with textproto reproducers
- Use the public seed to reproduce CVE‑2023‑20938; study the CVE‑2020‑0423 race template for other work‑queue/lifetime bugs

---

## References

- [Binder Fuzzing with LKL (Android Offensive Security Blog)](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [LKL Binder fuzzer (PR #564)](https://github.com/lkl/linux/pull/564)
- [Seed and README for reproducing CVE‑2023‑20938](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md#reproducing-cve-2023-20938)
- [CVE‑2020‑0423 analysis (Longterm Security)](https://www.longterm.io/cve-2020-0423.html)
- [syzkaller](https://github.com/google/syzkaller) and [syzbot dashboard](https://syzkaller.appspot.com)
- [Project Zero – Bad Binder (CVE‑2019‑2215)](https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html)
- [SockFuzzer – P0 design notes](https://googleprojectzero.blogspot.com/2021/04/designing-sockfuzzer-network-syscall.html)
- [LKL fuzzing talk (Linux Foundation)](https://www.youtube.com/watch?v=Wxmi-2ROYNk&list=PLbzoR-pLrL6pAblvRXHaIYY0VE6ZjObV9&index=5)

{{#include ../../banners/hacktricks-training.md}}