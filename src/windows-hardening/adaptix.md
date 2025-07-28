# Adaptix C2 Framework

{{#include ../banners/hacktricks-training.md}}

## Overview
Adaptix is a cross-platform, modular Command-and-Control (C2) framework that ships with multiple agents (Windows – *Beacon* and *Gopher*) and an **Extension-Kit** full of Beacon Object Files (BOFs).  Version **v0.7** introduced a completely new scripting layer (**AxScript**) and several post-exploitation enhancements that make Adaptix a powerful alternative to commercial C2s.

The framework is split into 3 big components:

* **AdaptixC2 (Teamserver / Client)** – management console, listeners and AxScript runtime
* **Agents** – in-memory implants that receive jobs and return output (Beacon, Gopher …)
* **Extension-Kit** – collection of BOF post-exploitation modules that can be hot-loaded by the agents

> Most commands shown below are executed from the Adaptix interactive client unless explicitly noted.

---

## 1.  AxScript Scripting Engine  (NEW in v0.7)
AxScript is a tiny Run-time scripting language that lets the operator change **menus, listeners and agent behaviour at run-time** – no recompilation needed.

```axscript
# Listen on HTTP 0.0.0.0:8080 and show a custom menu on callback
autoListener 'http' {
  onConnect {
    showMenu('Upload', 'Download', 'Execute')
  }
}

# Dynamically add a "Kill" context action to FileBrowser
action FileBrowser {
  addContextAction('Kill', 'taskkill /PID ${pid} /F')
}
```

Key AxScript helpers:
* `listen '<proto>' { … }`  – create listener & assign handlers
* `onConnect { … }`         – code executed on new agent check-in
* `showMenu(<items…>)`       – render custom right-click actions
* `registerListener()` / `registerAgent()` – expose Go listeners/agents to the runtime

This replaces the previous Go-plugin mechanism making new functionality accessible through one-line scripts.

---

## 2. Credential Manager
A lightweight **encrypted vault** to store domain / local credentials obtained during operations.

```text
credmgr add "corp\\svc_backup : SuperS3cret!"
credmgr list                 # display stored creds
credmgr get corp\\svc_backup  # copy to clipboard
```
Entries are AES-GCM protected on disk and transparently decrypted when queried.

---

## 3. Agents

### 3.1 Beacon (Windows x64)
* **DLL Stager via Rundll32** – Beacon can now be built as a DLL and executed completely **in-memory**:
  ```powershell
  rundll32.exe beacon.dll,BeaconsEntryPoint  # loads DLL and jumps to exported function
  ```
  No file is dropped to disk reducing AV/EDR visibility.
* **Re-implemented BOF Loader** – tighter integrity checks & faster RWX section mapping.
* **Extra hardening** – strict length/type validation of C2 job payloads, crash-free `BeaconFormatAlloc`.

### 3.2 Gopher (Windows)
* Added support for **reflective BOF execution** – same in-memory loader used by Beacon.
* `ps` output is now rendered **as a parent/child process tree**.
* New `rev2self` job – calls the WinAPI `RevertToSelf()` to drop an impersonated token and revert to the original user context.

---

## 4.  Extension-Kit  – BOF Modules

| BOF             | Capability | Quick One-Liner |
|-----------------|------------|-----------------|
| `no-consolation`| Command execution by **process-hollowing-free** technique | `bof no-consolation "C:\Windows\System32\notepad.exe"` |
| `nanodump`      | **LSASS mini-dump** using `MiniDumpWriteDump()` (OPSEC safe) | `bof nanodump full` |
| `potato-dcom`   | SYSTEM privilege escalation abusing **DCOM COMElevationPrivilege** | `bof potato-dcom"` |
| `token_make` / `token_steal` / `getsystem_token` | Manipulate / impersonate Windows tokens | `bof token_steal <pid>` |
| `hashdump`      | Extract NTDS.dit & SYSTEM hive remotely | `bof hashdump` |
| `screenshot`    | GDI desktop capture | `bof screenshot` |

All modules are **loaded reflectively** – nothing touches disk.

---

## 5.  Trade-craft Notes

### 5.1  In-Memory DLL Execution with Rundll32
`rundll32.exe` is a signed Microsoft LOLBIN that can call an **exported function** from any DLL:

```powershell
rundll32.exe <malware>.dll,<Export> [arguments]
```

If the DLL is **reflectively loaded** (either via a staging shell-code or a previously loaded implant), the bytes never hit disk.  AV engines rely heavily on file I/O hooks, so this method bypasses many signatures while blending in with legitimate rundll32 activity.

**Hints**
1. The exported function must use the `stdcall` calling convention and signature `void CALLBACK ExportName(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)`
2. Use `beacon.dll,BeaconsEntryPoint` when generating Adaptix beacons.
3. Couple with `suspend-thread -> patch AMSI` BOF before running further payloads.

### 5.2  Reflective BOF Execution
BOFs are tiny Position-Independent C snippets compiled with the **COFF** tool-chain.  They run inside the agent process without requiring the Visual C Runtime.  Adaptix loads them by:
1. Allocating RWX memory
2. Copying the COFF sections
3. Resolving imports / relocations
4. Jumping to `go()` entry-point

Operating fully **in-memory** keeps the footprint minimal and allows shipping fresh functionality to already deployed beacons.

### 5.3  Dropping Impersonation Tokens  – `rev2self`
When privilege escalation BOFs return an **impersonation handle**, command execution happens under the stolen context.  Calling:
```text
rev2self
```
restores the original token (internally invoking `RevertToSelf()`)

---

## References
* [Adaptix Framework – v0.6 → v0.7 Changelog](https://adaptix-framework.gitbook.io/adaptix-framework/changelog-and-updates/v0.6-greater-than-v0.7)
* [Adaptix-Framework on GitHub](https://github.com/Adaptix-Framework)

{{#include ../banners/hacktricks-training.md}}