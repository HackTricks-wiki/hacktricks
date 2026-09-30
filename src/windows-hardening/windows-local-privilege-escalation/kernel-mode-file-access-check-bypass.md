# Kernel-Mode File Access Check Bypasses

{{#include ../../banners/hacktricks-training.md}}

## Vulnerable driver pattern

A driver does not preserve a caller's security boundary merely by impersonating that caller. Kernel-mode object opens normally bypass access checks. `OBJ_KERNEL_HANDLE` only makes the resulting handle accessible from kernel mode. When a driver opens or manipulates an object on behalf of user mode, it must also use `OBJ_FORCE_ACCESS_CHECK` so the Object Manager evaluates the requested access against the effective token.<sup>[[3]](#references)[[4]](#references)</sup>

Audit file-handling IOCTLs and create callbacks for this sequence:<sup>[[3]](#references)[[4]](#references)</sup>

1. User mode supplies a path, source handle, desired access, or operation type.
2. The driver impersonates the caller, but calls `IoCreateFileEx`, `ZwCreateFile`, or a similar routine without `OBJ_FORCE_ACCESS_CHECK`.
3. A kernel-only file or directory handle is saved in per-handle state.
4. A later operation decides whether to impersonate from attacker-influenced state such as the access mask requested during the first open.
5. The privileged branch performs a rename or link with a `BypassAccessCheck` information class.

This is a **confused-deputy file primitive**, not necessarily memory corruption. A particularly dangerous state inversion is “write requested means impersonate; no write requested means remain privileged.” In that design, deliberately requesting only read access can unlock the more powerful path.<sup>[[3]](#references)</sup>

## vSMB example: privileged root plus privileged rename

`storvsp.sys` implements Virtual Server Message Block (vSMB). When the **Virtual Machine Platform** feature is enabled, user mode can reach `\Device\STORVSP` through `\\.\STORVSP`. A vSMB filesystem path has the form `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 and CVE-2025-64673 showed how two inconsistent access-control decisions could turn this interface into local privilege escalation.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

The source's function-to-CVE mapping comes from reverse engineering of the patched binary rather than Microsoft source. The researchers warn that the two identifiers may map to the opposite functions.<sup>[[3]](#references)</sup>

### 1. Create a read-only share rooted at a protected directory

The vulnerable create path recorded requested rights in persistent flags such as `HasReadAccess`, `HasWriteAccess`, and `HasAppendAccess`. It then opened the backing path with `OBJ_KERNEL_HANDLE` but without `OBJ_FORCE_ACCESS_CHECK`. The attempted impersonation therefore did not make the file open respect the caller's NTFS permissions.<sup>[[3]](#references)[[4]](#references)</sup>

Request only `FILE_READ_DATA`. This leaves `HasWriteAccess` clear while still obtaining a share whose internal root is a protected directory:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

The important artifact is not a user-mode System32 directory handle. It is a vSMB device handle associated with driver state that contains a privileged kernel root handle.<sup>[[3]](#references)</sup>

### 2. Turn the state mismatch into protected file replacement

IOCTL `0x240330` accepted a source file handle, an information class, and a variable-length information buffer:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

The vulnerable handler accepted `FileRenameInformation`, `FileLinkInformation`, and `FileRenameInformationEx`. For a normal rename path it split the parent path from the final component, then opened the parent relative to the stored root handle. That open again used `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` without `OBJ_FORCE_ACCESS_CHECK`. A nonzero attacker-supplied `RootDirectory` inside the rename structure was rejected, so the driver supplied its own privileged directory handle.<sup>[[3]](#references)</sup>

The exploitable branch was selected by **not** requesting write access during stage 1:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: impersonate the saved root security context.
- `HasWriteAccess == 0`: skip impersonation and convert `FileRenameInformation` or `FileRenameInformationEx` to its `BypassAccessCheck` variant.

The handler duplicated the attacker-supplied source handle into `PsInitialSystemProcess`, referenced it as a file object, installed the privileged target-directory handle in the rename structure, and called `ZwSetInformationFile`. With `ReplaceIfExists = TRUE`, a file controlled by the caller could therefore replace an existing file below the protected root.<sup>[[3]](#references)</sup>

When reviewing a similar handler, track **both handle provenance and security context** across every branch. Input validation, integer-overflow checks, `IO_STOP_ON_SYMLINK`, and restricting the accepted information classes do not compensate for a privileged root handle combined with an access-check-bypass operation.<sup>[[3]](#references)</sup>

## From protected write to SYSTEM execution

A protected file-replacement primitive becomes code execution when a privileged process later loads the replaced module. In the demonstrated chain, the destination was `C:\Windows\System32\wuapi.dll`. Activating the local-server COM class `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` for interface `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` and calling `IWaaSRemediation::LaunchDetectionOnly()` caused a SYSTEM process to load that DLL.<sup>[[3]](#references)</sup>

This COM call is an **activation trigger**, not [COM registry hijacking](com-hijacking.md). The file primitive supplies the planted module and the privileged loader supplies execution. For other protected-write chains, identify the exact image, DLL path, signature policy, bitness, exported functions, and reliable trigger before choosing a target. See [DLL hijacking](dll-hijacking/README.md) for loader-analysis and proxy-DLL considerations.<sup>[[3]](#references)</sup>

### Moving a Session 0 token to the interactive desktop

A payload loaded by a service normally executes in Session 0. To create an interactive process, it can obtain the active console session with `WTSGetActiveConsoleSessionId`, enable the required token privileges, duplicate the current SYSTEM token as a primary token, and set its `TokenSessionId` to the active session. `CreateProcessAsUserW` then uses that token with `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` is required to set a token's session ID in this scenario. The interactive window station and desktop must also grant the token access. See [token duplication from Session 0](sedebug-+-seimpersonate-copy-token.md) for the broader token-copy workflow.<sup>[[3]](#references)[[5]](#references)</sup>

## Patch and review guidance

Microsoft's December 2025 updates fixed the demonstrated chain. Reverse engineering found that the patched vSMB create path rejects untrusted callers that request a share root without `FILE_WRITE_DATA`. Relevant operations also gained forced access checking. This blocks the state inversion before an unprivileged caller can obtain the privileged root.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

For driver code, apply these rules:<sup>[[3]](#references)[[4]](#references)</sup>

- Add `OBJ_FORCE_ACCESS_CHECK` whenever an object is opened on behalf of a user-mode request. Do not treat `OBJ_KERNEL_HANDLE` as an authorization control.<sup>[[4]](#references)</sup>
- Capture and validate the requestor mode and effective subject context. Do not let requested rights select a more privileged execution branch.
- Validate user handles with the correct object type, access mask, and `UserMode`. Duplicating a handle into the system process does not validate the authority of the requested operation.
- Keep target resolution relative to a trusted handle, but ensure that the trusted handle itself was opened under the requestor's enforced access check.
- Avoid `File*BypassAccessCheck` classes for user-driven operations. If internal code genuinely needs them, gate that path with an authorization decision independent of user-controlled access flags.
- Patch affected systems. The vulnerable surface is relevant when Virtual Machine Platform loads `storvsp.sys`.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - From Virtual Share to Physical Shell: Leveraging Windows' Inconsistent Access Control for LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Object Handles](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - CreateProcessAsUserW function](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)

{{#include ../../banners/hacktricks-training.md}}
