# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**In this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) are explained several vulnerabilities that allowed to compromised the kernel compromising the software updater.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild Kernel 0-days (CVE-2024-23225 & CVE-2024-23296)

Apple patched two memory-corruption bugs that were actively exploited against iOS and macOS in March 2024 (fixed in macOS 14.4/13.6.5/12.7.4).

* **CVE-2024-23225 – Kernel**  
  • Out-of-bounds write in the XNU virtual-memory subsystem allows an unprivileged process to obtain arbitrary read/write in the kernel address space, bypassing PAC/KTRR.  
  • Triggered from userspace via a crafted XPC message that overflows a buffer in `libxpc`, then pivots into the kernel when the message is parsed.  
* **CVE-2024-23296 – RTKit**  
  • Memory corruption in the Apple Silicon RTKit (real-time co-processor).  
  • Exploitation chains observed used CVE-2024-23225 for kernel R/W and CVE-2024-23296 to escape the secure co-processor sandbox and disable PAC.

Patch level detection:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
If upgrading is not possible, mitigate by disabling vulnerable services:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```

---

## 2023: MIG Type-Confusion – CVE-2023-41075

`mach_msg()` requests sent to an unprivileged IOKit user client lead to a **type confusion** in the MIG generated glue-code. When the reply message is re-interpreted with a larger out-of-line descriptor than was originally allocated, an attacker can achieve a controlled **OOB write** into kernel heap zones and eventually
escalate to `root`.

Primitive outline (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Public exploits weaponise the bug by:
1. Spraying `ipc_kmsg` buffers with active port pointers.  
2. Overwriting `ip_kobject` of a dangling port.  
3. Jumping to shellcode mapped at a PAC-forged address using `mprotect()`.

---

## 2024-2025: SIP Bypass through Third-party Kexts – CVE-2024-44243 (aka “Sigma”)

Security researchers from Microsoft showed that the high-privileged daemon `storagekitd` can be coerced to load an **unsigned kernel extension** and thus completely disable **System Integrity Protection (SIP)** on fully patched macOS (prior to 15.2). The attack flow is:

1. Abuse the private entitlement `com.apple.storagekitd.kernel-management` to spawn a helper under attacker control.
2. The helper calls `IOService::AddPersonalitiesFromKernelModule` with a crafted info-dictionary pointing to a malicious kext bundle.
3. Because SIP trust checks are performed *after* the kext is staged by `storagekitd`, code executes in ring-0 before validation and SIP can be turned off with `csr_set_allow_all(1)`.

Detection tips:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
Immediate remediation is to update to macOS Sequoia 15.2 or later.

---

### Quick Enumeration Cheatsheet

```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```

---

## Fuzzing & Research Tools

* **Luftrauser** – Mach message fuzzer that targets MIG subsystems (`github.com/preshing/luftrauser`).  
* **oob-executor** – IPC out-of-bounds primitive generator used in CVE-2024-23225 research.  
* **kmutil inspect** – Built-in Apple utility (macOS 11+) to statically analyse kexts before loading: `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “About the security content of macOS Sonoma 14.4.” https://support.apple.com/en-us/120895  
* Microsoft Security Blog. “Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
