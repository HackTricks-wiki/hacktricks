# Windows MDL-Mapped User Buffer Double-Fetch

{{#include ../../banners/hacktricks-training.md}}

A Windows kernel driver creates a double-fetch when it validates data in caller-backed pages and later passes a pointer into those same pages to a security-sensitive API. Locking and mapping the pages does not make their contents immutable. CVE-2025-55680 in `cldflt.sys` illustrates this pattern: the driver validated a Cloud Files placeholder's relative name, then created the object while still referencing the caller's mutable buffer.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` creates files or directories below a registered Cloud Files sync root. In the vulnerable path, changing the name after validation could redirect privileged creation outside that root.<sup>[[1]](#references)[[2]](#references)</sup>

## Why locking the pages did not lock the data

The vulnerable `HsmpOpCreatePlaceholders()` path allocated an MDL for the caller's payload, called `ProbeForRead()` and `MmProbeAndLockPages()`, and mapped those pages into kernel virtual address space. An MDL describes and locks the physical pages so that they remain resident. It does **not** snapshot their bytes. User mode can therefore modify the same physical memory while the driver reads it through the system mapping.<sup>[[1]](#references)[[3]](#references)</sup>

The relevant request and use path was:<sup>[[1]](#references)</sup>

1. `cldapi.dll` sent Cloud Files control code `0x903BC` with tag `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) and create-placeholder operation `0xC0000001`.
2. Each payload record contained 16-bit offset/length pairs for the relative name and file identity. Most fixed fields were copied to a stack record, but the variable-length name remained in the mapped user pages.
3. The driver scanned the UTF-16 name and rejected a backslash or colon.
4. It then built a `UNICODE_STRING` whose `Buffer` still pointed into the mapped payload and assigned it to `OBJECT_ATTRIBUTES.ObjectName`.
5. `FltCreateFileEx2()` read that pointer again. A concurrent writer could therefore make validation observe one string and file creation observe another.

This is a **double-fetch** even though both reads use a kernel virtual address: the security boundary depends on the backing storage, not on which virtual mapping the driver dereferences.<sup>[[1]](#references)</sup>

## Cloud Files race layout

The disclosed exploit strategy used repeated requests, mutator threads, and a junction to turn the double-fetch into path redirection:<sup>[[1]](#references)</sup>

1. Register an attacker-controlled directory with `CfRegisterSyncRoot()` and create `JUSTASTRING` below it as a junction to a protected destination.
2. Prepare a shared placeholder record with the valid single-component name `JUSTASTRINGDnewfile.dll`.
3. Have mutator threads toggle the UTF-16 `D` code unit between `D` and `\`. The second representation is `JUSTASTRING\newfile.dll`.
4. In parallel, have worker threads repeatedly submit create-placeholder requests that reference the same payload, while a monitor checks the protected destination.
5. A winning iteration validates the separator-free representation, then follows the junction when the later create sees the representation containing `\`.

The primitive only establishes protected file or directory creation. Turning it into code execution still requires control of the created file's contents and a privileged consumer, such as a suitable DLL side-loading target. The original analysis used this final class of chain but did not publish the loader, payload, or a complete standalone exploit.<sup>[[1]](#references)</sup>

For complementary techniques that deliberately widen Windows path-lookup races, see [Kernel Race Condition Exploitation via Object Manager Slow Paths](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence - Microsoft Windows Cloud Files Minifilter TOCTOU Privilege Escalation](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - CfCreatePlaceholders function](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - MmProbeAndLockPages function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)

{{#include ../../banners/hacktricks-training.md}}
