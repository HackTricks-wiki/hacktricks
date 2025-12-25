# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Why stretching the race window matters

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. On modern hardware a cold `NtOpenEvent`/`NtOpenSection` resolves a short name in ~2 µs, leaving almost no time to flip the checked state before the secure action happens. By deliberately forcing the Object Manager Namespace (OMNS) lookup in step 2 to take tens of microseconds, the attacker gains enough time to consistently win otherwise flaky races without needing thousands of attempts.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Names such as `\BaseNamedObjects\Foo` are resolved directory-by-directory. Each component causes the kernel to find/open an *Object Directory* and compare Unicode strings. Symbolic links (e.g., drive letters) may be traversed en route.
* **UNICODE_STRING limit** – OM paths are carried inside a `UNICODE_STRING` whose `Length` is a 16-bit value. The absolute limit is 65 535 bytes (32 767 UTF-16 codepoints). With prefixes like `\BaseNamedObjects\`, an attacker still controls ≈32 000 characters.
* **Attacker prerequisites** – Any user can create objects underneath writable directories such as `\BaseNamedObjects`. When the vulnerable code uses a name inside, or follows a symbolic link that lands there, the attacker controls the lookup performance with no special privileges.

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
- Because everything lives in user-writable namespaces, the payload works from a standard user integrity level.

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
* Keep a handle array so you can delete the chain cleanly after exploitation to avoid polluting the namespace.

## Measuring your race window

Embed a quick harness inside your exploit to measure how large the window becomes on the victim hardware. The snippet below opens the target object `iterations` times and returns the average per-open cost using `QueryPerformanceCounter`.

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
4. **Clean up** – Delete the directory chain and symbolic links to avoid leaving suspicious artifacts or breaking legitimate IPC users.

## Operational considerations

- **Combine primitives** – You can use a long name *per level* in a directory chain for even higher latency until you exhaust the `UNICODE_STRING` size.
- **One-shot bugs** – The expanded window (tens of microseconds) makes “single trigger” bugs realistic when paired with CPU affinity pinning or hypervisor-assisted preemption.
- **Side effects** – The slowdown only affects the malicious path, so overall system performance remains unaffected; defenders will rarely notice unless they monitor namespace growth.
- **Cleanup** – Keep handles to every directory/object you create so you can call `NtMakeTemporaryObject`/`NtClose` afterwards. Unbounded directory chains may persist across reboots otherwise.

## Defensive notes

- Kernel code that relies on named objects should re-validate security-sensitive state *after* the open, or take a reference before the check (closing the TOCTOU gap).
- Enforce upper bounds on OM path depth/length before dereferencing user-controlled names. Rejecting overly long names forces attackers back into the microsecond window.
- Instrument object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) to detect suspicious thousands-of-components chains under `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
