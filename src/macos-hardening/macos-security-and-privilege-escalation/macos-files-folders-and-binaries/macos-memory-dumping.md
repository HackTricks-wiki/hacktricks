# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, such as `/private/var/vm/swapfile0`, serve as **caches when the physical memory is full**. When there's no more room in physical memory, its data is transferred to a swap file and then brought back to physical memory as needed. Multiple swap files might be present, with names like swapfile0, swapfile1, and so on.

### Hibernate Image

The file located at `/private/var/vm/sleepimage` is crucial during **hibernation mode**. **Data from memory is stored in this file when OS X hibernates**. Upon waking the computer, the system retrieves memory data from this file, allowing the user to continue where they left off.

It's worth noting that on modern MacOS systems, this file is typically encrypted for security reasons, making recovery difficult.

- To check if encryption is enabled for the sleepimage, the command `sysctl vm.swapusage` can be run. This will show if the file is encrypted.

### Memory Pressure Logs

Another important memory-related file in MacOS systems is the **memory pressure log**. These logs are located in `/var/log` and contain detailed information about the system's memory usage and pressure events. They can be particularly useful for diagnosing memory-related issues or understanding how the system manages memory over time.

## Dumping memory with osxpmem

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: This is mostly a **legacy workflow** now. `osxpmem` depends on loading a kernel extension, the [Rekall](https://github.com/google/rekall) project is archived, the latest release is from **2017**, and the published binary targets **Intel Macs**. On current macOS releases, especially on **Apple Silicon**, kext-based full-RAM acquisition is usually blocked by modern kernel-extension restrictions, SIP, and platform-signing requirements. In practice, on modern systems you will more often end up doing a **process-scoped dump** instead of a whole-RAM image.

```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```

If you find this error: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` You can fix it doing:

```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```

**Other errors** might be fixed by **allowing the load of the kext** in "Security & Privacy --> General", just **allow** it.

You can also use this **oneliner** to download the application, load the kext and dump the memory:

```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```

## Live process dumping with LLDB

For **recent macOS versions**, the most practical approach is usually to dump the memory of a **specific process** instead of trying to image all physical memory.

LLDB can save a Mach-O core file from a live target:

```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```

By default this usually creates a **skinny core**. To force LLDB to include all mapped process memory:

```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```

Useful follow-up commands before dumping:

```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```

This is usually enough when the goal is to recover:

- Decrypted configuration blobs
- In-memory tokens, cookies, or credentials
- Plaintext secrets that are only protected at rest
- Decrypted Mach-O pages after unpacking / JIT / runtime patching

If the target is protected by the **hardened runtime**, or if `taskgated` denies the attach, you typically need one of these conditions:

- The target carries **`get-task-allow`**
- Your debugger is signed with the proper **debugger entitlement**
- You are **root** and the target is a non-hardened third-party process

For more background on obtaining a task port and what can be done with it:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

Before spending time on LLDB/Frida, quickly verify whether the target is realistically **dumpable**:

```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
  egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```

Operationally, this usually means:

- A third-party app shipped with **`get-task-allow`** is often directly dumpable with LLDB, and the resulting dump may expose TCC-protected data that the app already accessed.
- A **hardened** target without `get-task-allow` will commonly reject attaches, even as `root`, unless you control the relevant debugger entitlements / policy path.
- Unhardened third-party processes are still the easiest place to use `lldb`, `vmmap`, Frida, or custom `task_for_pid`/`vm_read` readers.

## Selective dumps with Frida or userland readers

When a full core is too noisy, dumping only **interesting readable ranges** is often faster. Frida is especially useful because it works well for **targeted extraction** once you can attach to the process.

Example approach:

1. Enumerate readable/writable ranges
2. Filter by module, heap, stack, or anonymous memory
3. Dump only the regions that contain candidate strings, keys, protobufs, plist/XML blobs, or decrypted code/data

Minimal Frida example to dump all readable anonymous ranges:

```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
  try {
    if (range.file) return;
    var dump = range.base.readByteArray(range.size);
    var f = new File('/tmp/' + range.base + '.bin', 'wb');
    f.write(dump);
    f.close();
  } catch (e) {}
});
```

This is useful when you want to avoid giant core files and only collect:

- App heap chunks containing secrets
- Anonymous regions created by custom packers or loaders
- JIT / unpacked code pages after changing protections

Older userland tools such as [`readmem`](https://github.com/gdbinit/readmem) also exist, but they are mainly useful as **source references** for direct `task_for_pid`/`vm_read` style dumping and are not well-maintained for modern Apple Silicon workflows.

## Heap / VM snapshots with `.memgraph`

If you mainly care about **heap objects**, **allocation provenance**, or a snapshot that can be moved to another machine, a `.memgraph` is often more practical than a giant Mach-O core. The `leaks` tooling can generate one from a live process:

```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```

Then triage it offline with standard Apple tooling:

```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```

`stringdups` is the main reason to keep a `-fullContent` capture around, because the labels describing memory contents are omitted from a minimal `.memgraph`.

This is especially useful when:

- You want a **smaller, shareable snapshot** instead of a full core
- `MallocStackLogging` was enabled and you want **allocation backtraces**
- You already know an **interesting heap address** and want to pivot with `malloc_history`
- You need a quick **VM/heap breakdown** before deciding whether a full dump is worth the noise

## Swift-heavy targets: `swift-inspect`

For applications that keep high-value data inside **Swift runtime objects**, `swift-inspect` can be a good complement to LLDB or Frida. Instead of dumping everything first, you can query specific Swift runtime structures from a live process:

```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```

This is handy to identify:

- Large Swift arrays buffering interesting data
- Metadata allocations that reveal types loaded at runtime
- Swift concurrency state (`Task`, actor, thread relationships) before doing a more targeted dump

For more object-level runtime triage once you can already inspect the process, check [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Quick triage notes

- `sysctl vm.swapusage` is still a quick way to check **swap usage** and whether swap is **encrypted**.
- `sleepimage` remains relevant mainly for **hibernate/safe sleep** scenarios, but modern systems commonly protect it, so it should be treated as an **artifact source to check**, not as a reliable acquisition path.
- On recent macOS releases, **process-level dumping** is generally more realistic than **full physical memory imaging** unless you control boot policy, SIP state, and kext loading.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}


