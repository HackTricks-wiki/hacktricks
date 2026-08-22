# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Why stretching the race window matters

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. On modern hardware a cold `NtOpenEvent`/`NtOpenSection` resolves a short name in ~2 µs, leaving almost no time to flip the checked state before the secure action happens. By deliberately forcing the Object Manager Namespace (OMNS) lookup in step 2 to take tens of microseconds, the attacker gains enough time to consistently win otherwise flaky races without needing thousands of attempts.<sup>[[1]](#references)</sup>

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Names such as `\BaseNamedObjects\Foo` are resolved directory-by-directory. Each component causes the kernel to find/open an *Object Directory* and compare Unicode strings. Symbolic links (e.g., drive letters) may be traversed en route.
* **UNICODE_STRING limit** – OM paths are carried inside a `UNICODE_STRING` whose `Length` is a 16-bit value. The absolute limit is 65 535 bytes (32 767 UTF-16 codepoints). With prefixes like `\BaseNamedObjects\`, an attacker still controls ≈32 000 characters.
* **Attacker prerequisites** – Any user can create objects underneath writable directories such as `\BaseNamedObjects`. When the vulnerable code uses a name inside, or follows a symbolic link that lands there, the attacker controls the lookup performance with no special privileges.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

The cost of resolving a component is roughly linear with its length because the kernel must perform a Unicode comparison against every entry in the parent directory. Creating an event with a 32 kB-long name immediately increases the `NtOpenEvent` latency from ~2 µs to ~35 µs on Windows 11 24H2 (Snapdragon X Elite testbed).

```cpp
std::wstring path;
while (path.size() <= 32000) {
    auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
    printf("%zu,%f\n", path.size(), result);
    path += std::wstring(500, 'A');
}
```

*Practical notes*

- You can hit the length limit using any named kernel object (events, sections, semaphores…).
- Symbolic links or reparse points can point a short “victim” name to this giant component so the slowdown is applied transparently.
- Because everything lives in user-writable namespaces, the payload works from a standard user integrity level.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Deep recursive directories

A more aggressive variant allocates a chain of thousands of directories (`\BaseNamedObjects\A\A\...\X`). Each hop triggers directory resolution logic (ACL checks, hash lookups, reference counting), so the per-level latency is higher than a single string compare. With ~16 000 levels (limited by the same `UNICODE_STRING` size), empirical timings surpass the 35 µs barrier achieved by long single components.

```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
    dirs.emplace_back(CreateDirectory(L"A", last_dir));
    last_dir = dirs.back().get();
    if ((i % 500) == 0) {
        auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
        printf("%d,%f\n", i + 1, result);
    }
}
```

Tips:

* Alternate the character per level (`A/B/C/...`) if the parent directory starts rejecting duplicates.
* Keep a handle array so you can delete the chain cleanly after exploitation to avoid polluting the namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories support **shadow directories** (fallback lookups) and bucketed hash tables for entries. Abuse both plus the 64-component symbolic-link reparse limit to multiply slowdown without exceeding the `UNICODE_STRING` length:

1. Create two directories under `\BaseNamedObjects`, e.g. `A` (shadow) and `A\A` (target). Create the second using the first as the shadow directory (`NtCreateDirectoryObjectEx`), so missing lookups in `A` fall through to `A\A`.
2. Fill each directory with thousands of **colliding names** that land in the same hash bucket (e.g., varying trailing digits while keeping the same `RtlHashUnicodeString` value). Lookups now degrade to O(n) linear scans inside a single directory.
3. Build a chain of ~63 **object manager symbolic links** that repeatedly reparse into the long `A\A\…` suffix, consuming the reparse budget. Each reparse restarts parsing from the top, multiplying the collision cost.
4. Lookup of the final component (`...\\0`) now takes **minutes** on Windows 11 when 16 000 collisions are present per directory, providing a practically guaranteed race win for one-shot kernel LPEs.

```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```

*Why it matters*: A minutes-long slowdown turns one-shot race-based LPEs into deterministic exploits.<sup>[[1]](#references)</sup>

### 2025 retest notes & ready-made tooling

- James Forshaw republished the technique with updated timings on Windows 11 24H2 (ARM64). Baseline opens remain ~2 µs; a 32 kB component raises this to ~35 µs, and shadow-dir + collision + 63-reparse chains still reach ~3 minutes, confirming the primitives survive current builds. Source code and perf harness are in the refreshed Project Zero post.<sup>[[1]](#references)</sup>
- You can script setup using the public `symboliclink-testing-tools` bundle: `CreateObjectDirectory.exe` to spawn the shadow/target pair and `NativeSymlink.exe` in a loop to emit the 63-hop chain. This avoids hand-written `NtCreate*` wrappers and keeps ACLs consistent.<sup>[[2]](#references)</sup>

## Measuring your race window

Embed a quick harness inside your exploit to measure how large the window becomes on the victim hardware. The snippet below opens the target object `iterations` times and returns the average per-open cost using `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>

```cpp
static double RunTest(const std::wstring name, int iterations,
        std::wstring create_name = L"", HANDLE root = nullptr) {
    if (create_name.empty()) {
        create_name = name;
    }
    ScopedHandle event_handle = CreateEvent(create_name, root);
    ObjectAttributes obja(name);
    std::vector<ScopedHandle> handles;
    Timer timer;
    for (int i = 0; i < iterations; ++i) {
        HANDLE open_handle;
        Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
        handles.emplace_back(open_handle);
    }
    return timer.GetTime(iterations);
}
```

The results feed directly into your race orchestration strategy (e.g., number of worker threads needed, sleep intervals, how early you need to flip the shared state).

## Exploitation workflow

1. **Locate the vulnerable open** – Trace the kernel path (via symbols, ETW, hypervisor tracing, or reversing) until you find an `NtOpen*`/`ObOpenObjectByName` call that walks an attacker-controlled name or a symbolic link in a user-writable directory.
2. **Replace that name with a slow path**
   - Create the long component or directory chain under `\BaseNamedObjects` (or another writable OM root).
   - Create a symbolic link so that the name the kernel expects now resolves to the slow path. You can point the vulnerable driver’s directory lookup to your structure without touching the original target.
3. **Trigger the race**
   - Thread A (victim) executes the vulnerable code and blocks inside the slow lookup.
   - Thread B (attacker) flips the guarded state (e.g., swaps a file handle, rewrites a symbolic link, toggles object security) while Thread A is occupied.
   - When Thread A resumes and performs the privileged action, it observes stale state and performs the attacker-controlled operation.
4. **Clean up** – Delete the directory chain and symbolic links to avoid leaving suspicious artifacts or breaking legitimate IPC users.<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), published as a bypass for RoguePlanet (CVE-2026-50656), demonstrates a broader exploitation pattern: make a privileged scanner classify one representation of a logical file, then change both its bytes and namespace resolution before remediation uses it. The PoC combines a Cloud Files hydration TOCTOU, an Object Manager shadow-directory fallback, CLFS-generated-name capture, and a local administrative-share link to turn Defender cleanup into a protected DLL write.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substitute content through Cloud Files hydration

Register an attacker-writable directory as a Cloud Files sync root, connect a `CF_CALLBACK_TYPE_FETCH_DATA` callback, and create a placeholder whose advertised size matches a deterministic detection trigger such as the EICAR ZIP. The first fetch returns the trigger and flips callback state; later fetches return the payload. After the scanner has classified the first representation, obtain the transfer key and restart hydration with payload-sized metadata, then force hydration to EOF.<sup>[[4]](#references)</sup>

```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```

The security boundary fails if scan, verdict, and remediation refer only to a pathname or placeholder identity: neither guarantees that a later hydration returns the bytes that were inspected.<sup>[[4]](#references)</sup>

### 2. Switch an invariant path through a shadow-directory fallback

Create a target Object Manager directory and a second directory with `NtCreateDirectoryObjectEx`, passing the target handle as its shadow/fallback directory. Put a same-named `WD_SCAN` entry in both resolution layers: the visible entry points to the normal working directory, while the fallback entry points to `\CLFS\??\<working-directory>`. Supply Defender only the invariant path below; deleting the visible link while the operation is active makes the same string fall through to the CLFS-backed entry.<sup>[[4]](#references)</sup>

```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```

This is distinct from using shadow directories only to slow lookup: the attacker changes the **meaning** of a previously accepted path without modifying its string.<sup>[[4]](#references)</sup>

### 3. Capture the generated name and install a filename-specific link

Monitor the working directory with `ReadDirectoryChangesW`. On the first `FILE_ACTION_ADDED`, remove the visible `WD_SCAN` link to activate fallback lookup. Capture the second generated filename, open that CLFS-related file, and lock the range `0..MAXLONGLONG` with `LockFileEx`. While the privileged operation is stalled, replace `WD_SCAN` in the visible directory with a real Object Manager directory and create a child symbolic link named from the observed filename (the PoC strips its final four characters). Point it to the protected destination through local SMB:<sup>[[4]](#references)</sup>

```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```

The unprivileged process cannot write that destination itself, but Defender's SYSTEM context can traverse the loopback administrative share. Combining generated-name observation with a filename-specific Object Manager link avoids having to predict the remediation artifact in advance.<sup>[[4]](#references)</sup>

### 4. Stabilize the cleanup race and trigger a privileged loader

Before scanning, the PoC stores a valid PE (`ntdll.dll`) in the placeholder's `:stream` NTFS alternate data stream. After redirection creates the protected base file, it opens `phoneinfo.dll:stream` with execute access and keeps a `PAGE_EXECUTE_READ | SEC_IMAGE` mapping alive while cleanup resumes; the live file/section objects constrain deletion or replacement during the final race. The restarted hydration now returns the payload DLL rather than EICAR, so the protected base file contains attacker-controlled code.<sup>[[4]](#references)</sup>

A protected write is then converted to SYSTEM execution by placing a crafted `Report.wer` under `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` and invoking `\Microsoft\Windows\Windows Error Reporting\QueueReporting` through the Task Scheduler COM API. In this chain, privileged WER processing loads the planted `C:\Windows\System32\phoneinfo.dll`; a named-pipe connection is used as the payload execution signal.<sup>[[4]](#references)</sup>

### Detection pivots

Useful correlations are more specific than any single temporary filename and cover all namespace transitions in the chain:<sup>[[4]](#references)</sup>

- A newly registered Cloud Files provider followed by EICAR detection and `CF_OPERATION_TYPE_RESTART_HYDRATION` on the same placeholder.
- Object Manager paths containing `WD_TARGET_*`, `WD_SHADOW_*`, or `WD_SCAN`, especially a scan path below `\\.\globalroot\BaseNamedObjects\Restricted\`.
- CLFS file creation followed by an exclusive whole-file lock and loopback access to `\\127.0.0.1\C$\Windows\System32\*.dll` from a privileged security process.
- Creation of a System32 DLL together with an NTFS ADS, followed by `SEC_IMAGE` mapping of the stream.
- An attacker-created WER queue entry followed by an unusual manual run of `\Microsoft\Windows\Windows Error Reporting\QueueReporting` and an image load of the planted DLL.

## Operational considerations

- **Combine primitives** – You can use a long name *per level* in a directory chain for even higher latency until you exhaust the `UNICODE_STRING` size.
- **One-shot bugs** – The expanded window (tens of microseconds to minutes) makes “single trigger” bugs realistic when paired with CPU affinity pinning or hypervisor-assisted preemption.
- **Side effects** – The slowdown only affects the malicious path, so overall system performance remains unaffected; defenders will rarely notice unless they monitor namespace growth.
- **Cleanup** – Keep handles to every directory/object you create so you can call `NtMakeTemporaryObject`/`NtClose` afterwards. Unbounded directory chains may persist across reboots otherwise.
- **File-system races** – If the vulnerable path ultimately resolves through NTFS, you can stack an Oplock (e.g., `SetOpLock.exe` from the same toolkit) on the backing file while the OM slowdown runs, freezing the consumer for additional milliseconds without altering the OM graph.<sup>[[2]](#references)</sup>

## Defensive notes

- Kernel code that relies on named objects should re-validate security-sensitive state *after* the open, or take a reference before the check (closing the TOCTOU gap).
- Enforce upper bounds on OM path depth/length before dereferencing user-controlled names. Rejecting overly long names forces attackers back into the microsecond window.
- Instrument object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) to detect suspicious thousands-of-components chains under `\BaseNamedObjects`.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)

{{#include ../../banners/hacktricks-training.md}}
