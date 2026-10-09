# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## Scope

A post-compromise implant can load a signed kernel driver as a service and expose a user-mode control plane through `IRP_MJ_DEVICE_CONTROL`. Driver signing only establishes that Windows accepts the image; it does not make the IOCTL authorization, memory operations, callbacks, or hooks safe. One analyzed rootkit used three handlers during normal operation but exposed dozens of additional post-exploitation primitives, so reverse engineering must cover the complete dispatcher rather than only the requests observed in a malware trace.<sup>[[1]](#references)</sup>

## Signed-driver and IOCTL triage

Start at `DriverEntry`, record device objects and DOS symbolic links, locate the `MajorFunction[IRP_MJ_DEVICE_CONTROL]` routine, and map every comparison/table entry that reaches a handler. Cross-check the names opened by user mode against the names actually created by the driver: one observed chain opened `\\.\msagent`, while its driver created `\Device\ToolTool` and `\DosDevices\ToolTool`. This mismatch can identify another sample/configuration, missing setup logic, or an analysis inconsistency.<sup>[[1]](#references)</sup>

Decode each control code before reconstructing its input structure.<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

These three codes decode as `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS`, and `METHOD_BUFFERED`. That does **not** prove an unprivileged caller can reach them: also inspect the device DACL, create/open dispatch, per-request caller checks, expected buffer lengths, embedded pointers, PID lifetime handling, and whether the handler trusts a caller-supplied PID or flag.<sup>[[1]](#references)</sup>

When the implant uses only a subset of commands, group the remaining handlers by primitive rather than dismissing them as dead code. A single multifunction driver has exposed all of the following classes:<sup>[[1]](#references)</sup>

- **Control/configuration:** toggle rootkit state; add, remove, query, or clear protected paths, processes, and C2 addresses.
- **Process manipulation:** terminate a PID, unmap its image, inject with `NtCreateThreadEx`, hide/restore processes or user modules, and remove PPL protection.
- **Kernel manipulation:** unlink a loaded driver, enumerate/disable/restore notification callbacks, manually map another driver, and write to an arbitrary kernel address.
- **Object manipulation:** delete/decrypt files and create or modify registry values.

## Trusted-process exemptions

A useful design pattern is an IOCTL that registers a PID plus a **trusted** flag. The same trust lookup is then consulted by file, registry, process, and thread filters: untrusted tools receive filtered enumeration results, reduced handle rights, or `STATUS_ACCESS_DENIED`, while the implant can still update its own hidden objects. Treat this as an authorization boundary and verify how entries are authenticated, synchronized, and removed after process exit or PID reuse.<sup>[[1]](#references)</sup>

Rootkits can persist policy in `REG_MULTI_SZ` values and compile file, directory, registry-key, registry-value, ignored-image, protected-image, and hidden-image lists into AVL trees. During analysis, trace every reader and writer of these shared trees; it links registry configuration, IOCTLs, callbacks, and filtering logic even when function names are stripped.<sup>[[1]](#references)</sup>

## DKOM process and module hiding

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks` offsets vary by Windows build. A version-tolerant rootkit can test known candidates and then scan `EPROCESS` for a self-consistent `LIST_ENTRY` whose neighbors point back to the candidate. It retains the discovered offset, hides a process by reconnecting its neighbors' `Flink`/`Blink`, and preserves state to relink the entry later. The process continues running but disappears from enumerators that walk the active-process list.<sup>[[1]](#references)</sup>

This is **DKOM**, not termination. Detection should compare list-based results with independent evidence such as pool/object scans, thread ownership, handle tables, scheduler artifacts, and kernel memory inspection. A process visible to a scan but absent from the canonical list is more meaningful than either view alone.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

The equivalent module-hiding primitive finds the target entry in `PsLoadedModuleList` and patches adjacent `Flink`/`Blink` pointers. The driver remains mapped and executable, but list-backed module queries omit it. Compare the loader list with executable kernel mappings, pool tags, device/driver objects, service keys, callback addresses, and dispatch pointers that land outside a listed image.<sup>[[1]](#references)</sup>

## Callback-based protection and cloaking

A rootkit can layer documented callback frameworks with DKOM and hooks:<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` pre-operation handlers for `PsProcessType` and `PsThreadType` remove rights used for termination, VM access, duplication, or thread manipulation when an untrusted caller opens a protected target. Record the callback altitude and resolve each callback address to its owning module.
- `PsSetCreateProcessNotifyRoutineEx` and `PsSetLoadImageNotifyRoutine` maintain protected/ignored/hidden process state as processes and images appear; a one-time process walk can backfill objects that existed before registration.
- A filesystem minifilter denies access to configured paths. An unusual implementation may create its `Instances` key, choose an altitude dynamically, and increment/retry when `FltRegisterFilter` reports a collision.
- A `CmRegisterCallbackEx` routine can suppress protected names from enumeration and deny direct open, rename, set, or delete operations while exempting registered trusted processes.

Correlate `ObRegisterCallbacks` registrations, registry-callback altitudes, `fltmc filters` output, service `Instances` keys, and callback addresses. If normal tools are being filtered, inspect these structures from an offline memory image or another trusted acquisition layer.<sup>[[1]](#references)</sup>

## Nsiproxy result filtering

Network concealment can target `\Driver\Nsiproxy`: obtain the driver object with `ObReferenceObjectByName`, save a handler pointer, replace it with a wrapper, and remove returned IPv4 records matching an IOCTL-managed C2 list before user mode receives them. Applications backed by the filtered NSI data may no longer display the connection even though the traffic still exists.<sup>[[1]](#references)</sup>

Compare host connection views with packet capture, WFP/ETW telemetry, and kernel-memory network objects. Also inspect `Nsiproxy` dispatch/handler pointers and confirm that each resolves inside the expected signed module; a pointer into an unlisted mapping can connect network filtering with `PsLoadedModuleList` DKOM.<sup>[[1]](#references)</sup>

## Investigation checklist

The strongest signal is disagreement between layers, not one filename or hash. Correlate:<sup>[[1]](#references)</sup>

1. Kernel-service creation and a signed driver whose certificate age, publisher, or path is inconsistent with the installed product.
2. Device creation, DOS links, and IOCTL traffic, including mismatched user-mode and kernel device names.
3. A PID registration request followed by failures from other processes to open, enumerate, modify, or delete the same objects.
4. Object/registry/process/image callbacks, minifilter instances, and hooks whose addresses do not belong to a normally enumerated driver.
5. Differences between list-based and scan-based process, module, callback, and network inventories.

## References

- [1] [Kaspersky Securelist - HoneyMyte Enhances CoolClient with a Signed Windows Kernel Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)

{{#include ../../banners/hacktricks-training.md}}
