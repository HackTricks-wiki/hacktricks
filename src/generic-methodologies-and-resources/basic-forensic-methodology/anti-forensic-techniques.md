# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

'n Aanvaller mag belangstel in **die verandering van die tydstempels van lêers** om nie opgespoor te word nie.\
Dit is moontlik om die tydstempels binne die MFT in die eienskappe `$STANDARD_INFORMATION` \_\_ en \_\_ `$FILE_NAME` te vind.

Albei eienskappe het 4 tydstempels: **Wysiging**, **toegang**, **skepping**, en **MFT registrasie wysiging** (MACE of MACB).

**Windows verkenner** en ander gereedskap wys die inligting van **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Hierdie gereedskap **wysig** die tydstempel inligting binne **`$STANDARD_INFORMATION`** **maar** **nie** die inligting binne **`$FILE_NAME`** nie. Daarom is dit moontlik om **verdagte** **aktiwiteit** te **identifiseer**.

### Usnjrnl

Die **USN Journal** (Update Sequence Number Journal) is 'n kenmerk van die NTFS (Windows NT lêerstelsel) wat volume veranderinge opneem. Die [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) gereedskap maak dit moontlik om hierdie veranderinge te ondersoek.

![](<../../images/image (801).png>)

Die vorige beeld is die **uitset** wat deur die **gereedskap** gewys word waar dit waargeneem kan word dat sommige **veranderinge gemaak is** aan die lêer.

### $LogFile

**Alle metadata veranderinge aan 'n lêerstelsel word gelog** in 'n proses bekend as [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Die gelogde metadata word in 'n lêer genaamd `**$LogFile**` gehou, geleë in die wortelgids van 'n NTFS lêerstelsel. Gereedskap soos [LogFileParser](https://github.com/jschicht/LogFileParser) kan gebruik word om hierdie lêer te ontleed en veranderinge te identifiseer.

![](<../../images/image (137).png>)

Weer eens, in die uitset van die gereedskap is dit moontlik om te sien dat **sommige veranderinge gemaak is**.

Met dieselfde gereedskap is dit moontlik om te identifiseer **tot watter tyd die tydstempels gewysig is**:

![](<../../images/image (1089).png>)

- CTIME: Lêer se skeppingstyd
- ATIME: Lêer se wysigingstyd
- MTIME: Lêer se MFT registrasie wysiging
- RTIME: Lêer se toegangstyd

### `$STANDARD_INFORMATION` en `$FILE_NAME` vergelyking

'n Ander manier om verdagte gewysigde lêers te identifiseer, sou wees om die tyd op albei eienskappe te vergelyk op soek na **ongelykhede**.

### Nanoseconds

**NTFS** tydstempels het 'n **presisie** van **100 nanosekondes**. Dan, om lêers met tydstempels soos 2010-10-10 10:10:**00.000:0000 te vind, is baie verdag**.

### SetMace - Anti-forensic Tool

Hierdie gereedskap kan albei eienskappe `$STARNDAR_INFORMATION` en `$FILE_NAME` wysig. egter, vanaf Windows Vista, is dit nodig vir 'n lewende OS om hierdie inligting te wysig.

## Data Hiding

NFTS gebruik 'n kluster en die minimum inligting grootte. Dit beteken dat as 'n lêer 'n kluster en 'n half gebruik, die **oorblywende half nooit gebruik gaan word** totdat die lêer verwyder word. Dan is dit moontlik om **data in hierdie slack ruimte te verberg**.

Daar is gereedskap soos slacker wat toelaat om data in hierdie "verborge" ruimte te verberg. egter, 'n ontleding van die `$logfile` en `$usnjrnl` kan wys dat sommige data bygevoeg is:

![](<../../images/image (1060).png>)

Dan is dit moontlik om die slack ruimte te herstel met gereedskap soos FTK Imager. Let daarop dat hierdie tipe gereedskap die inhoud obfuskeer of selfs versleuteld kan stoor.

## UsbKill

Dit is 'n gereedskap wat die **rekenaar sal afskakel as enige verandering in die USB** poorte opgespoor word.\
'n Manier om dit te ontdek, sou wees om die lopende prosesse te inspekteer en **elke python skrip wat loop te hersien**.

## Live Linux Distributions

Hierdie distros word **binne die RAM** geheue uitgevoer. Die enigste manier om hulle te ontdek, is **as die NTFS lêerstelsel met skryf toestemmings gemonteer is**. As dit net met lees toestemmings gemonteer is, sal dit nie moontlik wees om die indringing te ontdek nie.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Dit is moontlik om verskeie Windows logging metodes te deaktiveer om die forensiese ondersoek baie moeiliker te maak.

### Disable Timestamps - UserAssist

Dit is 'n registriesleutel wat datums en ure behou wanneer elke uitvoerbare lêer deur die gebruiker uitgevoer is.

Om UserAssist te deaktiveer, is twee stappe nodig:

1. Stel twee registriesleutels in, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` en `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, albei op nul om aan te dui dat ons wil hê UserAssist moet gedeaktiveer word.
2. Maak jou registriesubbome skoon wat lyk soos `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Dit sal inligting oor die toepassings wat uitgevoer is, stoor met die doel om die prestasie van die Windows stelsel te verbeter. egter, dit kan ook nuttig wees vir forensiese praktyke.

- Voer `regedit` uit
- Kies die lêer pad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Regsklik op beide `EnablePrefetcher` en `EnableSuperfetch`
- Kies Wysig op elkeen van hierdie om die waarde van 1 (of 3) na 0 te verander
- Herbegin

### Disable Timestamps - Last Access Time

Wanneer 'n gids vanaf 'n NTFS volume op 'n Windows NT bediener geopen word, neem die stelsel die tyd om **'n tydstempel veld op elke gelysde gids op te dateer**, wat die laaste toegangstyd genoem word. Op 'n swaar gebruikte NTFS volume kan dit die prestasie beïnvloed.

1. Maak die Registrie Redigeerder (Regedit.exe) oop.
2. Blaai na `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Soek na `NtfsDisableLastAccessUpdate`. As dit nie bestaan nie, voeg hierdie DWORD by en stel die waarde op 1, wat die proses sal deaktiveer.
4. Sluit die Registrie Redigeerder, en herbegin die bediener.

### Delete USB History

Alle **USB Device Entries** word in die Windows Registrie onder die **USBSTOR** registriesleutel gestoor wat sub sleutels bevat wat geskep word wanneer jy 'n USB toestel in jou rekenaar of skootrekenaar inprop. Jy kan hierdie sleutel hier vind `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Deletie hiervan** sal die USB geskiedenis verwyder.\
Jy kan ook die gereedskap [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) gebruik om seker te maak jy het hulle verwyder (en om hulle te verwyder).

'n Ander lêer wat inligting oor die USB's stoor, is die lêer `setupapi.dev.log` binne `C:\Windows\INF`. Dit moet ook verwyder word.

### Disable Shadow Copies

**Lys** skaduwe copies met `vssadmin list shadowstorage`\
**Verwyder** hulle deur `vssadmin delete shadow` te loop

Jy kan hulle ook via GUI verwyder deur die stappe voor te stel in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Om skaduwe copies te deaktiveer [stappe van hier](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Maak die Dienste program oop deur "dienste" in die teks soekboks te tik nadat jy op die Windows begin knoppie geklik het.
2. Vind "Volume Shadow Copy" in die lys, kies dit, en toegang eienskappe deur regsklik.
3. Kies Gedeaktiveer van die "Opstart tipe" keuselys, en bevestig die verandering deur Toepas en OK te klik.

Dit is ook moontlik om die konfigurasie van watter lêers in die skaduwee kopie gaan wees, in die registrie `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` te wysig.

### Overwrite deleted files

- Jy kan 'n **Windows gereedskap** gebruik: `cipher /w:C` Dit sal cipher aanwys om enige data uit die beskikbare ongebruikte skyf ruimte binne die C skyf te verwyder.
- Jy kan ook gereedskap soos [**Eraser**](https://eraser.heidi.ie) gebruik.

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> Brei "Windows Logs" uit --> Regsklik op elke kategorie en kies "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Binne die dienste afdeling deaktiveer die diens "Windows Event Log"
- `WEvtUtil.exec clear-log` of `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Onlangs weergawes van Windows 10/11 en Windows Server hou **ryke PowerShell forensiese artefakte** onder
`Microsoft-Windows-PowerShell/Operational` (geleenthede 4104/4105/4106).
Aanvallers kan dit deaktiveer of op die vlug verwyder:
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
Verdedigers moet toesig hou oor veranderinge aan daardie registriesleutels en hoë-volume verwydering van PowerShell-gebeurtenisse.

### ETW (Event Tracing for Windows) Patch

Eindpunt-sekuriteitsprodukte staat baie op ETW. 'n Gewilde ontwykingsmetode in 2024 is om `ntdll!EtwEventWrite`/`EtwEventWriteFull` in geheue te patch sodat elke ETW-oproep `STATUS_SUCCESS` teruggee sonder om die gebeurtenis uit te stuur:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Publieke PoCs (bv. `EtwTiSwallow`) implementeer dieselfde primitiewe in PowerShell of C++.
Omdat die patch **proses-lokaal** is, mag EDR's wat binne ander prosesse loop dit misloop.
Detectie: vergelyk `ntdll` in geheue teenoor op skyf, of hook voor gebruikersmodus.

### Alternatiewe Gegevensstrome (ADS) Herlewing

Malwareveldtogte in 2023 (bv. **FIN12** loaders) is gesien wat tweede-fase binêre binne ADS stoor om buite sig van tradisionele skanners te bly:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerate streams with `dir /R`, `Get-Item -Stream *`, or Sysinternals `streams64.exe`. Copying the host file to FAT/exFAT or via SMB will strip the hidden stream and can be used by investigators to recover the payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver is now routinely used for **anti-forensics** in ransomware intrusions. The open-source tool **AuKill** loads a signed but vulnerable driver (`procexp152.sys`) to suspend or terminate EDR and forensic sensors **before encryption & log destruction**:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Die bestuurder word daarna verwyder, wat minimale artefakte agterlaat.  
Mitigasies: aktiveer die Microsoft kwesbare-bestuurder blokkelys (HVCI/SAC),  
en waarsku oor kern-diens skepping vanaf gebruikers-skryfbare paaie.  

---  

## Linux Anti-Forensics: Self-Patching en Cloud C2 (2023–2025)  

### Self‑patching gecompromitteerde dienste om opsporing te verminder (Linux)  
Teenstanders "self‑patch" toenemend 'n diens reg na die uitbuiting daarvan om beide her-uitbuiting te voorkom en kwesbaarheid-gebaseerde opsporings te onderdruk. Die idee is om kwesbare komponente te vervang met die nuutste wettige opwaartse binêre/JARs, sodat skandeerders die gasheer as gepatchte rapporteer terwyl volharding en C2 bly.  

Voorbeeld: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- Na die uitbuiting het aanvallers wettige JARs van Maven Central (repo1.maven.org) afgelaai, kwesbare JARs in die ActiveMQ installasie verwyder, en die broker herbegin.  
- Dit het die aanvanklike RCE gesluit terwyl ander voetstukke (cron, SSH konfigurasiewijzigings, aparte C2 implante) gehandhaaf is.  

Operasionele voorbeeld (illustreer)
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
Forensiese/jag wenke
- Hersien diensgidsen vir ongeskeduleerde binêre/JAR vervangings:
- Debian/Ubuntu: `dpkg -V activemq` en vergelyk lêer hashes/paaie met repo spieëls.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Soek na JAR weergawes wat op skyf teenwoordig is wat nie deur die pakketbestuurder besit word nie, of simboliese skakels wat buite band opgedateer is.
- Tydlyn: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` om ctime/mtime met kompromie venster te korreleer.
- Shell geskiedenis/proses telemetrie: bewys van `curl`/`wget` na `repo1.maven.org` of ander artefak CDN's onmiddellik na die aanvanklike eksploitatie.
- Veranderingsbestuur: valideer wie die “patch” toegepas het en hoekom, nie net dat 'n gepatchte weergawe teenwoordig is nie.

### Wolkdiens C2 met draer tokens en anti-analise stagers
Geobserveerde handelsvaardighede gekombineer verskeie langafstand C2 paaie en anti-analise verpakking:
- Wagwoord-beskermde PyInstaller ELF laders om sandboks en statiese analise te hinder (bv., versleutelde PYZ, tydelike onttrekking onder `/_MEI*`).
- Aanwysers: `strings` treffers soos `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Tydren artefakte: onttrekking na `/tmp/_MEI*` of pasgemaakte `--runtime-tmpdir` paaie.
- Dropbox-ondersteunde C2 wat hardgecodeerde OAuth Draer tokens gebruik
- Netwerkmerkers: `api.dropboxapi.com` / `content.dropboxapi.com` met `Authorization: Bearer <token>`.
- Jag in proxy/NetFlow/Zeek/Suricata vir uitgaande HTTPS na Dropbox domeine van bediener werklas wat normaalweg nie lêers sinkroniseer nie.
- Parallel/backup C2 via tonneling (bv., Cloudflare Tunnel `cloudflared`), hou beheer as een kanaal geblokkeer is.
- Gasheer IOCs: `cloudflared` prosesse/eenhede, konfigurasie by `~/.cloudflared/*.json`, uitgaande 443 na Cloudflare kante.

### Volharding en “hardening rollback” om toegang te behou (Linux voorbeelde)
Aanvallers paar dikwels self-patching met duursame toegangspaaie:
- Cron/Anacron: wysigings aan die `0anacron` stub in elke `/etc/cron.*/` gids vir periodieke uitvoering.
- Jag:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH konfigurasie hardening rollback: aktivering van wortel aanmeldings en verandering van standaard skale vir laag-geprivilegieerde rekeninge.
- Jag vir wortel aanmeldings aktivering:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# vlag waardes soos "yes" of oormatig toelaatbare instellings
```
- Jag vir verdagte interaktiewe skale op stelsels rekeninge (bv., `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Willekeurige, kort-gemerk beacon artefakte (8 alfabetiese karakters) wat na skyf gelaat word wat ook met wolk C2 kontak maak:
- Jag:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Verdedigers moet hierdie artefakte korreleer met eksterne blootstelling en diens patching gebeurtenisse om anti-forensiese self-remediëring wat gebruik word om aanvanklike eksploitatie te verberg, te ontdek.

## Verwysings

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (Maart 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (Junie 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
