# Anti-forensiese tegnieke

{{#include ../../banners/hacktricks-training.md}}

## Tydstempels

’n Aanvaller kan daarin belangstel om **die tydstempels van lêers te verander** om opsporing te vermy.\
Dit is moontlik om die tydstempels in die MFT te vind in die attributte `$STANDARD_INFORMATION` \_\_ en \_\_ `$FILE_NAME`.

Albei attributte het 4 tydstempels: **Modification**, **access**, **creation** en **MFT registry modification** (MACE of MACB).

**Windows Explorer** en ander nutsmiddels wys die inligting uit **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensiese nutsmiddel

Hierdie nutsmiddel **wysig** die tydstempelinligting in **`$STANDARD_INFORMATION`**, **maar** **nie** die inligting in **`$FILE_NAME`** nie. Daarom is dit moontlik om **verdagte aktiwiteit** **te identifiseer**.

### Usnjrnl

Die **USN Journal** (Update Sequence Number Journal) is ’n kenmerk van NTFS (Windows NT-lêerstelsel) wat volumeveranderinge dophou. Die [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)-nutsmiddel maak dit moontlik om hierdie veranderinge te ondersoek.

![TimeStomp - Anti-forensiese nutsmiddel - Usnjrnl: Die USN Journal (Update Sequence Number Journal) is ’n kenmerk van NTFS (Windows NT-lêerstelsel) wat volumeveranderinge dophou. Die...](<../../images/image (801).png>)

Die vorige afbeelding wys die **afvoer** van die **nutsmiddel**, waar gesien kan word dat sommige **veranderinge aan die lêer aangebring is**.

### $LogFile

**Alle metadataveranderinge aan ’n lêerstelsel word aangeteken** in ’n proses wat as [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) bekend staan. Die aangetekende metadata word gehou in ’n lêer met die naam `**$LogFile**`, wat in die wortelgids van ’n NTFS-lêerstelsel geleë is. Nutsmiddels soos [LogFileParser](https://github.com/jschicht/LogFileParser) kan gebruik word om hierdie lêer te ontleed en veranderinge te identifiseer.

![Usnjrnl - $LogFile: Alle metadataveranderinge aan ’n lêerstelsel word aangeteken in ’n proses wat as write-ahead logging bekend staan. Die aangetekende metadata word gehou in ’n lêer met die naam $LogFile , wat in die wortel...](<../../images/image (137).png>)

Weereens is dit moontlik om in die afvoer van die nutsmiddel te sien dat **sommige veranderinge aangebring is**.

Met dieselfde nutsmiddel is dit moontlik om te identifiseer **na watter tyd die tydstempels verander is**:

![Usnjrnl - $LogFile: Met dieselfde nutsmiddel is dit moontlik om te identifiseer na watter tyd die tydstempels verander is](<../../images/image (1089).png>)

- CTIME: Lêer se skeppingstyd
- ATIME: Lêer se wysigingstyd
- MTIME: Lêer se MFT-registerwysiging
- RTIME: Lêer se toegangstyd

### Vergelyking van `$STANDARD_INFORMATION` en `$FILE_NAME`

Nog ’n manier om verdagte gewysigde lêers te identifiseer, is om die tyd in albei attributte te vergelyk en na **teenstrydighede** te soek.

### Nanosekondes

**NTFS**-tydstempels het ’n **presisie** van **100 nanosekondes**. Daarom is dit baie verdag om lêers met tydstempels soos 2010-10-10 10:10:**00.000:0000 te vind**.

### SetMace - Anti-forensiese nutsmiddel

Hierdie nutsmiddel kan albei attributte, `$STARNDAR_INFORMATION` en `$FILE_NAME`, wysig. Vanaf Windows Vista is ’n lewendige OS egter nodig om hierdie inligting te wysig.

## Dataverberging

NFTS gebruik ’n cluster en die minimum inligtingsgrootte. Dit beteken dat as ’n lêer een en ’n half cluster beslaan, die **oorblywende helfte nooit gebruik sal word** totdat die lêer uitgevee word. Dit is dus moontlik om **data in hierdie slack space te versteek**.

Daar is nutsmiddels soos slacker waarmee data in hierdie "versteekte" ruimte weggesteek kan word. ’n Ontleding van `$logfile` en `$usnjrnl` kan egter wys dat data bygevoeg is:

![SetMace - Anti-forensiese nutsmiddel - Dataverberging: Daar is nutsmiddels soos slacker waarmee data in hierdie "versteekte" ruimte weggesteek kan word. ’n Ontleding van $logfile en $usnjrnl kan egter wys dat...](<../../images/image (1060).png>)

Dit is dus moontlik om die slack space met nutsmiddels soos FTK Imager te herwin. Let daarop dat hierdie soort nutsmiddel die inhoud geobfuskateer of selfs geënkripteer kan stoor.

## UsbKill

Dit is ’n nutsmiddel wat **die rekenaar afskakel as enige verandering aan die USB**-poorte bespeur word.\
Een manier om dit te ontdek, is om die lopende prosesse te inspekteer en **elke lopende Python-skrip na te gaan**.

## Live Linux-verspreidings

Hierdie verspreidings word **in die RAM-geheue uitgevoer**. Die enigste manier om hulle op te spoor, is **indien die NTFS-lêerstelsel met skryftoestemmings gemonteer is**. As dit slegs met leestoestemmings gemonteer is, sal dit nie moontlik wees om die indringing op te spoor nie.

## Veilige uitwissing

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Uitgestelde selfuitwissing in Windows

’n Lopende Windows-image kan gesluit wees terwyl die proses daarvan aktief is. ’n Proses kan die uitwissing aan ’n kindproses `cmd.exe` oorlaat, `choice` as ’n timer gebruik en afsluit voordat die shell by `del` uitkom. Die vertraging laat die oorspronklike proses sy image-hanteerder vrystel; aanhalingstekens om die volledige pad is nodig as dit spasies bevat.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Wanneer hierdie string direk as die argument aan `cmd.exe` verskaf word, eerder as om dit vanaf ’n ander interaktiewe `cmd`-prompt in te tik, gebruik `&` in plaas van `^&` en `>nul` in plaas van `^>nul`. Dit verwyder die gidsinskrywing; dit is **nie veilige uitwissing nie** en verwyder nie uitvoerings-, taak-, lêerstelseljoernaal- of ander forensiese spore nie. Soek na kortstondige `cmd.exe`-kindprosesse waarvan die opdragreël `choice /T`, `Del` en die ouerproses se beeldpad kombineer.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows-konfigurasie

Dit is moontlik om verskeie Windows-logmetodes te deaktiveer om forensiese ondersoeke baie moeiliker te maak.

### Deaktiveer tydstempels - UserAssist

Dit is ’n registersleutel wat die datums en tye byhou waarop die gebruiker elke uitvoerbare lêer laat loop het.

Om UserAssist te deaktiveer, is twee stappe nodig:

1. Stel twee registersleutels, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` en `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, albei op nul om aan te dui dat ons UserAssist gedeaktiveer wil hê.
2. Vee jou register-subbome uit wat soos `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` lyk.

### Deaktiveer tydstempels - Prefetch

Dit stoor inligting oor die toepassings wat uitgevoer is, met die doel om die werkverrigting van die Windows-stelsel te verbeter. Dit kan egter ook nuttig wees vir forensiese ondersoeke.

- Voer `regedit` uit
- Kies die lêerpad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Regskliek op beide `EnablePrefetcher` en `EnableSuperfetch`
- Kies Modify op elk hiervan om die waarde van 1 (of 3) na 0 te verander
- Herbegin

### Deaktiveer tydstempels - Laaste toegangstyd

Wanneer ’n vouer vanaf ’n NTFS-volume op ’n Windows NT-bediener oopgemaak word, teken die stelsel die tyd aan om **’n tydstempelveld op elke gelyste vouer by te werk**, wat die laaste toegangstyd genoem word. Op ’n NTFS-volume wat swaar gebruik word, kan dit werkverrigting beïnvloed.

1. Maak die Registry Editor (Regedit.exe) oop.
2. Blaai na `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Soek `NtfsDisableLastAccessUpdate`. As dit nie bestaan nie, voeg hierdie DWORD by en stel sy waarde op 1 om die proses te deaktiveer.
4. Maak die Registry Editor toe en herbegin die bediener.

### Vee USB-geskiedenis uit

Al die **USB-toestelinskrywings** word in die Windows-register gestoor onder die **USBSTOR**-registersleutel, wat subsleutels bevat wat geskep word wanneer jy ’n USB-toestel by jou rekenaar of skootrekenaar inprop. Jy kan hierdie sleutel hier vind: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **As jy dit uitvee**, vee jy die USB-geskiedenis uit.\
Jy kan ook die nutsding [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) gebruik om seker te maak dat jy dit uitgevee het (en om dit uit te vee).

Nog ’n lêer wat inligting oor USB-toestelle stoor, is die lêer `setupapi.dev.log` in `C:\Windows\INF`. Dit moet ook uitgevee word.

### Deaktiveer skadukopieë

**Lys** skadukopieë met `vssadmin list shadowstorage`\
**Vee** hulle uit deur `vssadmin delete shadow` uit te voer

Jy kan hulle ook via die GUI uitvee deur die stappe te volg wat voorgestel word in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Om skadukopieë te deaktiveer, volg [die stappe hier](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Maak die Services-program oop deur "services" in die tekssoekkassie in te tik nadat jy op die Windows-startknoppie geklik het.
2. Soek "Volume Shadow Copy" in die lys, kies dit en kry dan toegang tot Properties deur regs te klik.
3. Kies Disabled in die "Startup type"-aftrekkieslys en bevestig dan die verandering deur Apply en OK te klik.

Dit is ook moontlik om in die register die konfigurasie te wysig van watter lêers in die skadukopie gekopieer gaan word: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Oorskryf geskrapte lêers

- Jy kan ’n **Windows-nutsding** gebruik: `cipher /w:C`. Dit gee cipher opdrag om enige data uit die beskikbare ongebruikte skyfspasie op die C-skyf te verwyder.
- Jy kan ook nutsmiddels soos [**Eraser**](https://eraser.heidi.ie) gebruik.

### Vee Windows-gebeurtenislogboeke uit

- Windows + R --> eventvwr.msc --> Vou "Windows Logs" uit --> Regskliek op elke kategorie en kies "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Deaktiveer Windows-gebeurtenislogboeke

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Deaktiveer die diens "Windows Event Log" in die services-afdeling
- `WEvtUtil.exec clear-log` of `WEvtUtil.exe cl`

### Deaktiveer $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Gevorderde logboekregistrasie- en spoorpeuterwerk (2023-2025)

### PowerShell ScriptBlock/Module Logging

Onlangse weergawes van Windows 10/11 en Windows Server hou **omvattende PowerShell-forensiese artefakte** in
`Microsoft-Windows-PowerShell/Operational` (gebeurtenisse 4104/4105/4106).  
Aanvallers kan dit onmiddellik deaktiveer of uitvee:

```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
                 -Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
                 -Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
  Remove-WinEvent               # requires admin & Win11 23H2+
```

Verdedigers moet monitor vir veranderinge aan daardie registry-sleutels en die massaverwydering van PowerShell-gebeurtenisse.

### ETW (Event Tracing for Windows) Patch

Endpoint-sekuriteitsprodukte maak sterk staat op ETW. ’n Gewilde ontduikingsmetode in 2024 is om `ntdll!EtwEventWrite`/`EtwEventWriteFull` in die geheue te patch, sodat elke ETW-oproep `STATUS_SUCCESS` teruggee sonder om die gebeurtenis uit te stuur:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Openbare PoCs (bv. `EtwTiSwallow`) implementeer dieselfde primitive in PowerShell of C++.  
Omdat die patch **proseslokaal** is, kan EDRs wat binne ander prosesse loop, dit miskyk.<sup>[[5]](#references)</sup>
Opsporing: vergelyk `ntdll` in die geheue met die kopie op skyf, of hook vóór user-mode.

### Herlewing van Alternate Data Streams (ADS)

Daar is gesien dat malware-veldtogte in 2023 (bv. **FIN12**-loaders) second-stage binaries
binne ADS plaas om buite die sig van tradisionele scanners te bly:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Enumereer strome met `dir /R`, `Get-Item -Stream *` of Sysinternals `streams64.exe`.
As die gasheerlêer na FAT/exFAT of via SMB gekopieer word, word die versteekte stroom verwyder; ondersoekers kan dit gebruik
om die payload te herwin.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver word nou gereeld vir **anti-forensics** in ransomware-inbrake gebruik.  
Die oopbronnutsding **AuKill** laai ’n getekende maar kwesbare driver (`procexp152.sys`) om EDR- en forensiese sensors op te skort of te beëindig **voor enkripsie en logvernietiging**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Die driver word daarna verwyder, wat minimale artefakte agterlaat.<sup>[[1]](#references)</sup>  
Versagtingsmaatreëls: aktiveer Microsoft se vulnerable-driver blocklist (HVCI/SAC), en stel waarskuwings in vir die skep van kernel-dienste vanaf paaie wat deur gebruikers geskryf kan word.

---

## Linux Anti-Forensics: Self-Patching en Cloud C2 (2023–2025)

### Self-patching van gekompromitteerde dienste om opsporing te verminder (Linux)
Aanvallers “self-patch” toenemend ’n diens onmiddellik nadat hulle dit uitgebuit het, om verdere uitbuiting te voorkom en kwesbaarheid-gebaseerde opsporing te onderdruk. Die idee is om kwesbare komponente met die nuutste wettige upstream-binaries/JARs te vervang, sodat skandeerders rapporteer dat die gasheer gelap is terwyl persistence en C2 voortduur.<sup>[[3]](#references)</sup>

Voorbeeld: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Ná post-exploitation het aanvallers wettige JARs vanaf Maven Central (repo1.maven.org) afgelaai, kwesbare JARs in die ActiveMQ-installasie verwyder en die broker herbegin.
- Dit het die aanvanklike RCE toegemaak terwyl ander footholds behoue gebly het (cron, veranderinge aan SSH-konfigurasie, afsonderlike C2-implants).

Operasionele voorbeeld (ter illustrasie)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```

Forensiese/soektogwenke
- Gaan diensgidse na vir ongeskeduleerde vervangings van binaries/JAR-lêers:
  - Debian/Ubuntu: `dpkg -V activemq` en vergelyk lêer-hashes/-paaie met repo-spieëls.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Soek na JAR-weergawes wat op skyf voorkom, maar nie deur die package manager besit word nie, of na simboliese skakels wat buite die gewone proses opgedateer is.
- Tydlyn: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` om ctime/mtime met die kompromitteringsvenster te korreleer.
- Shell-geskiedenis/proses-telemetrie: bewyse van `curl`/`wget` na `repo1.maven.org` of ander artifact-CDN's onmiddellik ná die aanvanklike uitbuiting.
- Veranderingsbestuur: bevestig wie die “patch” toegepas het en waarom, nie net dat ’n gepatchte weergawe teenwoordig is nie.

### C2 via wolkdienste met bearer tokens en anti-analise-stagers
Waargenome tradecraft het verskeie langtermyn-C2-paaie en anti-analise-verpakking gekombineer:<sup>[[3]](#references)</sup>
- Wagwoordbeskermde PyInstaller ELF-loaders om sandboxing en statiese analise te bemoeilik (bv. geënkripteerde PYZ, tydelike onttrekking onder `/_MEI*`).
  - Aanwysers: `strings`-treffers soos `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Looptyd-artefakte: onttrekking na `/tmp/_MEI*` of pasgemaakte `--runtime-tmpdir`-paaie.
- Dropbox-gesteunde C2 met hardgekodeerde OAuth Bearer tokens
  - Netwerkmerkers: `api.dropboxapi.com` / `content.dropboxapi.com` met `Authorization: Bearer <token>`.
  - Soek in proxy/NetFlow/Zeek/Suricata vir uitgaande HTTPS na Dropbox-domeine vanaf bedienerwerkladings wat gewoonlik nie lêers sinkroniseer nie.
- Parallelle/rugsteun-C2 via tonneling (bv. Cloudflare Tunnel `cloudflared`), sodat beheer behoue bly as een kanaal geblokkeer word.
  - Gasheer-IOC's: `cloudflared`-prosesse/eenhede, konfigurasie by `~/.cloudflared/*.json`, uitgaande 443-verbindings na Cloudflare-randpunte.

### Volharding en “terugdraai van verharding” om toegang te behou (Linux-voorbeelde)
Aanvallers kombineer dikwels self-patching met volhoubare toegangspaaie:<sup>[[3]](#references)</sup>
- Cron/Anacron: wysigings aan die `0anacron`-stub in elke `/etc/cron.*/`-gids vir periodieke uitvoering.
  - Soek:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Terugdraai van SSH-konfigurasieverharding: aktiveer root-aanmeldings en verander verstekdoppe vir laevoorreg-rekeninge.
  - Soek na root-aanmeldingsaktivering:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Soek na verdagte interaktiewe shells op stelselrekeninge (bv. `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Willekeurige, kortbenoemde beacon-artefakte (8 alfabetiese karakters) wat na skyf geskryf word en ook met cloud C2 kommunikeer:
  - Hunt:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Verdedigers behoort hierdie artefakte met eksterne blootstelling en dienspleistergebeurtenisse te korreleer om anti-forensiese selfremediëring te ontbloot wat gebruik word om aanvanklike uitbuiting te verberg.

## References

- [1] [Sophos X-Ops – AuKill: ’n Gewapende Kwesbare Driver om EDR te Deaktiveer (Maart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – EtwEventWrite Patching vir Stealth: Bespeuring en Jag (Junie 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching vir Volharding: Hoe DripDropper Linux-malware deur die cloud beweeg](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Versteek jou .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Ontdekking van ’n SectopRAT-variant wat in Wettige Sagteware Ingebed is](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice-opdrag](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del-opdrag](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
