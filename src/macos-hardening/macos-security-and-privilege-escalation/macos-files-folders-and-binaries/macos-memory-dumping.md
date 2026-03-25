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

## Quick triage notes

- `sysctl vm.swapusage` is still a quick way to check **swap usage** and whether swap is **encrypted**.
- `sleepimage` remains relevant mainly for **hibernate/safe sleep** scenarios, but modern systems commonly protect it, so it should be treated as an **artifact source to check**, not as a reliable acquisition path.
- On recent macOS releases, **process-level dumping** is generally more realistic than **full physical memory imaging** unless you control boot policy, SIP state, and kext loading.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}


