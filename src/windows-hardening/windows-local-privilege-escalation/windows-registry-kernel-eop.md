# Windows Registry Kernel EoP Attack Surface

{{#include ../../banners/hacktricks-training.md}}

## Why the registry is a prime local kernel target

The Windows Registry lives inside `ntoskrnl.exe` (Configuration Manager). Every medium-integrity process can reach hundreds of syscalls (`NtCreateKey`, `NtSetValueKey`, transactions, virtualization helpers, etc.), so any bug in the registry code is a **kernel-privilege primitive** that bypasses mitigations such as Win32k lockdown. The codebase mixes 30-year-old logic, manual memory management, ad-hoc parsers for on-disk "regf" blobs, and security-critical semantics (ACLs, SAM secrets, service configuration). That combination yields both **memory corruption** (UAF, OOB, pool spraying) and **logic/data-only** flaws (improper ACL enforcement, unauthorized value edits) that lead to local EoP.

Key properties defenders/offenders can leverage:
- Attack surface is **strictly local** but exposed to any process that can open a handle to a hive or load an app hive from disk.
- Almost all code executes in the kernel with no user/kernel boundary once the syscall is dispatched, so **one bug == kernel R/W**.
- The subsystem is **hard to fuzz**: it requires stateful sequences, on-disk hive crafting, and feature combinations (virtualization, layered keys, transactions) that are poorly documented and rarely tested.

## Core bug families inside the Configuration Manager

| Bug family | What to look for | Typical primitives |
| --- | --- | --- |
| Hive memory corruption | Cells are variable-length chunks referenced by logical indexes. Any mis-sized allocation/free, stale index, or unchecked arithmetic in `HvAllocateCell/HvReallocateCell` paths yields OOB R/W or UAF fully inside the hive mapping. | Arbitrary kernel read/write, KCB poisoning |
| Pool memory corruption | Temporary structures (KCBs, delayed close entries, hive log caches) live in paged/NP pool. Classic UAF, double-free, dangling pointers provide kernel heap exploitation. | Pool metadata overwrite → shellcode or token theft |
| Information disclosure | Large buffers copied via `NtQuery*Key/Value` or log replay paths often leak uninitialized pool/stack bytes when not zeroed. | Kernel ASLR defeat, KASLR bypass |
| Race conditions | Registry APIs run concurrently; poor locking or double-fetch of user buffers before probing lets attackers win TOCTOU races. | Arbitrary value injection / pointer reuse |
| Logic/ACL bugs | Keys store service configs, SAM/SYSTEM secrets, AppLocker policies, etc. Wrong ACL inheritance, virtualization mishandling, or misinterpreted predefined handles let low-priv users read/modify privileged data. | Direct privilege escalation without memory corruption |
| Inter-process abuse | Privileged services rely on registry state. Weak ACLs, racey multi-key updates, or non-atomic rewrite sequences let an attacker influence how SYSTEM services start up. | Code execution under SYSTEM via misconfiguration |

## Shared security descriptors & refcount pitfalls

Security descriptors live in `_CM_KEY_SECURITY` cells and are shared per hive through a 32-bit `ReferenceCount`. Manual reference counting introduces systemic vulnerabilities:

### Attacker-controlled on-disk refcounts
- App hives loaded via `RegLoadAppKey` or privileged services start with whatever `ReferenceCount` value is stored on disk. Loader repair code (`CmCheckRegistry` → `CmpCheckAndFixSecurityCellsRefcount`) attempts to recompute counts, but malformed regf structures can desynchronize real references from the stored value.
- A descriptor whose refcount is underestimated is freed once it decrements to 0 even though keys still point to its cell → hive-memory UAF reachable from user-mode operations (as seen in CVE-2022-34707 / CVE-2023-38139).
- **Testing tip:** craft templates where multiple keys reuse a descriptor but the on-disk refcount is small, then trigger descriptor decrements via rename/delete operations.

### Overflow-prone increments
- Historically any code updating `ReferenceCount` wrote directly to the field with no overflow checks. Forcing >`0xFFFFFFFF` increments wraps the count to 0, immediately freeing an in-use descriptor.
- Attackers can script hive mutations (mass key creation, ACL reassignment loops) to share one descriptor, induce wraparound, and reclaim the freed cell for malicious data (CVE-2023-28248 / CVE-2024-43641 before Microsoft funnelled updates through `CmpKeySecurityIncrement/DecrementReferenceCount`).

### Special key types and missing refcounts
- Predefined handles (e.g., `HKEY_LOCAL_MACHINE`), tombstones from layered hives, and the virtual `KEY_HIVE_EXIT` path do not behave like normal nodes. Historically, KCB refresh logic freed descriptors without touching refcounts or never refcounted tombstones at all (CVE-2023-35356/35382).
- Mixing these features (rename + virtualization + predefined handle) is a reliable way to create descriptors whose lifetime is not tracked, leaving dangling pointers.

### Irreversible frees in multi-step flows
- Once `ReferenceCount` hits zero and the cell is freed, there is no guarantee that the same cell index can be reallocated. Some code freed the old descriptor first, then attempted to allocate a replacement; if the allocation failed (Hive OOM/global quota), the key ended up with **no security descriptor** (CVE-2023-21772 in virtualization code).
- **Rule of thumb:** in complex updates, perform all allocation steps (which may fail) *before* decrementing/freeing shared descriptors.

## Loader self-healing & unenforced regf invariants

The hive loader (`CmCheckRegistry` plus `CmpCheck*` helpers) tries to "self-heal" corrupted hives so Windows keeps booting. For attackers, this error-repair logic is an *additional parser* that runs on untrusted regf data:
- Crafted hives trigger deep repair paths (rebuilding linked lists, fixing refcounts, trimming bad cells). Each path is large, under-tested, and often assumes non-adversarial corruption.
- Bugs such as CVE-2023-38139 occur when the repair code partially fixes a structure but leaves inconsistent metadata that later causes UAF when normal operations walk the hive.

### Hard requirements vs. conventions
The only true specification is what the loader rejects. Anything else can be attacker-controlled:
- **Duplicate value names** or **duplicate security descriptors** are accepted even though runtime code assumes uniqueness and reuses existing descriptors.
- **ASCII-only names stored uncompressed** are permitted although runtime toggles `KEY_COMP_NAME` and assumes packed encoding when calculating name length.
- **Allocated-but-unreferenced cells** (including descriptors with `ReferenceCount==0`) historically survived load.

Violating unstated assumptions directly leads to memory corruption when runtime code performs shrink/split operations:
- **Misaligned large cells** → shrink-in-place logic relocates them unexpectedly (CVE-2022-37988).
- **Pathological subkey list counts** (`_CM_KEY_INDEX.Count = 0xFFFF`) overflow 16-bit arithmetic when a list is split beyond 511/1012 entries (CVE-2022-37956) — achievable even via repeated `reg.exe` loops.
- **Version/structure mismatches** (e.g., regf 1.3 hive embedding 1.5-only list formats) cause parsers compiled for the older layout to index past buffers (CVE-2022-38037).

**Auditing approach:** when reverse engineering registry code, write down every invariant it *assumes* (alignment, uniqueness, bounded counts, descriptor sharing rules) and cross-check whether `CmpCheck*` enforces it. Any unchecked invariant becomes a fuzzing target.

## Forcing hive/global OOM to reach fragile error paths

Registry allocations come from two independent pools:
- Per-hive stable storage ≤ 2 GiB (backed by hive files) and volatile storage ≤ 2 GiB (memory-only data, very fast to fill).
- Global registry quota enforced by `CmpClaimGlobalQuota` caps the sum of all hives at 4 GiB.

An attacker can fill writable keys (many under `HKLM\SOFTWARE` or `HKLM\SYSTEM`) to **precisely induce allocation failures** in API handlers such as `CmpAddSubKeyEx`, rename commit, or hive unload. When developers forget to roll back every intermediate change, OOM faults create dangling references (e.g., CVE-2023-23421 rename rollback UAF, CVE-2023-21747 unload corruption, CVE-2024-26181 SAM quota exhaustion).

Example volatile-filler loop to starve a hive:
```powershell
$blob = ,([byte]0x41) * 1048576   # 1 MiB
$i = 0
while ($true) {
    $path = "HKCU:\Software\QuotaBleed"
    New-Item -Path $path -Name "K$i" -Force | Out-Null
    New-ItemProperty -Path "$path\K$i" -Name Pad -PropertyType Binary -Value $blob -Force | Out-Null
    $i++
}
```
Run the filler while a second thread performs high-risk operations (rename, transaction commit, virtualization ACL change). The moment `HvAllocateCell/HvReallocateCell` returns `STATUS_INSUFFICIENT_RESOURCES`, watch for inconsistent subkey lists or freed descriptors that remain referenced.

## Partial-success helpers vs. NTSTATUS/BOOL semantics

Many helpers (e.g., `CmpAddSubKeyToList`, log replay functions) are designed as "best effort" routines: they mutate some state, then bubble up the last failure as `FALSE` or a negative `NTSTATUS`. Callers typically assume `failure == no change` and skip cleanup. When the helper already reallocated a list or advanced a pointer, the caller's metadata now refers to **stale cell indexes**, yielding immediate UAF.

Pattern to identify:
1. Helper mutates hive state (reallocates cell, updates list entries).
2. Later step fails (often OOM) → helper returns `FALSE`/error without undoing earlier mutations.
3. Caller ignores partial progress and keeps referencing the pre-operation cell index.

CVE-2024-26182 is a textbook case: `CmpAddSubKeyToList` successfully moves a list to a new cell, then hits OOM and returns `FALSE`; `CmpAddSubKeyEx` never updates its bookkeeping, so subsequent traversals touch freed memory.

## Composing advanced registry features for logic breakage

Modern Windows layered features rarely interact cleanly:
- **Predefined keys** are handle aliases whose security descriptors are stored elsewhere.
- **Symbolic links** redirect access to a different path.
- **Virtualization** silently redirects writes to per-user/app hives or merges multiple data sources.
- **Transactions** maintain isolated views that must be reconciled with global state at commit time.
- **Layered/differencing hives** introduce tombstones (key exists but is logically deleted) and merge-unbacked keys (logically present without on-disk nodes).

Attackers intentionally combine these dimensions (e.g., open a predefined key inside a transaction that touches a virtualized + layered path) to expose assumptions about which hive or descriptor a handle really targets. Resulting bugs include missing ACL propagation, descriptors freed while still referenced, or visibility glitches where restricted keys become writable.

**Testing approach:** build harnesses that stack multiple features for every operation (open, rename, delete, security change) and verify that descriptors, KCB state, and virtualization routing behave as documented.

## Entry point: controlled hive loading workflow

1. Craft a regf blob with precise structures (duplicate values, oversized lists, malformed descriptors). Tools such as Registry Explorer or custom Python scripts can emit arbitrary cells.
2. From medium IL, call `RegLoadAppKey`/`NtLoadKeyEx` to map the hive under `HKU\AppKey_####`.
3. Optionally trigger loader repair routines by deliberately corrupting refcounts or list headers so `CmCheckRegistry` runs deep recovery code paths.
4. After the hive loads, execute ordinary APIs (create key/value, rename, transaction commit, virtualization access). Bugs usually manifest during these **follow-up operations**, not during load itself.
5. When corruption is achieved (dangling cell index, freed descriptor), pivot to kernel R/W via hive memory spraying or escalate via logic flaw (tamper with protected keys).

## Research & auditing checklist

- Enumerate all registry entry points reachable from user mode and map them to backend helpers (e.g., `NtRenameKey` → `CmpCommitRenameKeyUoW`).
- For each helper, document the invariants it assumes about hive structures and confirm whether loader checks enforce them.
- Instrument `HvAllocateCell/HvReallocateCell` failure paths and ensure every caller rolls back partially applied mutations before propagating the error.
- Track reference counting for `_CM_KEY_SECURITY` objects, especially when special keys (predefined, tombstone, KEY_HIVE_EXIT) are involved.
- When auditing OOM handling, remember the attacker fully controls hive/global quota exhaustion timing.

## References

- [Project Zero – The Windows Registry Adventure #7: Attack Surface and Bug Patterns](https://projectzero.google/2025/05/the-windows-registry-adventure-7-attack-surface.html)

{{#include ../../banners/hacktricks-training.md}}
