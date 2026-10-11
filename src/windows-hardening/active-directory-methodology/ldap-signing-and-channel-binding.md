# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno

LDAP relay/MITM napadi prosleđuju autentifikaciju kontroleru domena da bi dobili autentifikovani LDAP kontekst. Dve povezane kontrole smanjuju ove mogućnosti:

- **LDAP channel binding (CBT)** vezuje odgovarajuću autentifikaciju za TLS serverski sertifikat/kanal koji koristi LDAPS i otežava relay između kanala.
- **LDAP signing** zahteva zaštitu integriteta za SASL LDAP bindove. Ne dodaje poverljivost; koristite TLS kada je potrebno i šifrovanje LDAP sadržaja.<sup>[[2]](#references)</sup>

**Brza provera stanja**: alati kao što je `netexec ldap <dc> -u user -p pass` prikazuju uočene smernice za signing i channel binding. `(signing:None)` i `(channel binding:Never)` ukazuju na nedostatak kontrola, ali uspešan relay i dalje zavisi od tipa uhvaćene autentifikacije, ponašanja EPA, privilegija naloga, ciljnog protokola i zaštite od relay napada. Kada prosleđeni principal ima potrebna prava, alati kao što je KrbRelayUp mogu da upišu `msDS-AllowedToActOnBehalfOfOtherIdentity`, podese delegiranje ograničeno na resurse (RBCD) i iskoriste tako dobijeni put delegiranja za lažno predstavljanje privilegovanog principal-a.<sup>[[4]](#references)</sup>

**Server 2025 DC-ovi** uvode novu GPO smernicu (**LDAP server signing requirements Enforcement**) koja podrazumevano koristi **Require Signing** kada je postavljena na **Not Configured**. Da biste izbegli primenu smernice, morate je izričito postaviti na **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (samo LDAPS)

- **Zahtevi**:
  - Zakrpa za CVE-2017-8563 (2017) dodaje podršku za Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) dodaje LDAPS CBT telemetriju „what-if“.<sup>[[2]](#references)</sup>
- **GPO (DC-ovi)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (podrazumevano, bez CBT-a)
  - `When Supported` (delimična primena: klijenti koji podržavaju CBT moraju da dostave važeći token; klijenti bez podrške za CBT i dalje mogu da se povežu, a generišu se događaji revizije)
  - `Always` (primena: odbacuju se LDAPS bindovi bez važećeg CBT-a)<sup>[[1]](#references)</sup>
- **Revizija**: postavite na **When Supported** da biste uočili:
  - **3074** – LDAPS bind ne bi prošao CBT proveru da je smernica primenjena.
  - **3075** – LDAPS bind nije sadržao CBT podatke i bio bi odbijen da je smernica primenjena.
  - (Događaj **3039** i dalje označava CBT greške u starijim verzijama.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Primena**: postavite na **Always** kada LDAPS klijenti počnu da šalju CBT; deluje samo na **LDAPS** (ne na sirovi port 389).<sup>[[1]](#references)</sup>

`When Supported` nije samo za reviziju: proverava CBT kod klijenata koji ga podržavaju, a dozvoljava povezivanje klijentima bez podrške za CBT. [Microsoft referenca za smernice](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) opisuje podrazumevane vrednosti koje zavise od verzije. LDAP signing se primenjuje na odgovarajuće bindove preko LDAP/389; channel binding se primenjuje na TLS-om zaštićenu LDAP autentifikaciju.

## LDAP Signing

- **GPO klijenta**: `Network security: LDAP client signing requirements` = `Require signing` (za razliku od podrazumevanog `Negotiate signing` u modernom Windows-u).<sup>[[1]](#references)</sup>
- **GPO DC-a**:
  - Nasleđena postavka: `Domain controller: LDAP server signing requirements` = `Require signing` (podrazumevana vrednost je `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: ostavite nasleđenu smernicu na `None` i postavite `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` podrazumevano znači da se smernica primenjuje; postavite na `Disabled` da biste to izbegli).<sup>[[1]](#references)</sup>
- **Kompatibilnost**: popišite uređaje i aplikacije koji nisu Windows i koriste simple bindove ili nepotpisane SASL bindove. Microsoft dokumentuje podršku za održavane verzije Windows-a; tvrdnje o kompatibilnosti sa starijim klijentima treba proveriti u odnosu na konkretni stek klijenta, umesto da se svedu na prag verzije XP-a.<sup>[[2]](#references)</sup>

## Uvođenje uz prvo sprovođenje revizije (preporučeno oko 30 dana)

1. Omogućite LDAP interface diagnostics na svakom DC-u da biste beležili nepotpisane bindove (događaj **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Podesite DC GPO `LDAP server channel binding token requirements` = **When Supported** za delimično sprovođenje CBT-a i telemetriju; prvo proverite kompatibilnost sa starijim klijentima.<sup>[[1]](#references)</sup>
3. Pratite događaje Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – bindovi bez potpisa / dozvoljeni bindovi bez potpisa (nisu usklađeni sa zahtevom za potpisivanje).
   - **3074/3075** – LDAPS bindovi koji bi bili odbijeni ili izostavili CBT (zahteva KB4520412 na verzijama 2019/2022 i prethodni korak 2).
4. Sprovedite u odvojenim izmenama:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC-ovi).
   - `LDAP client signing requirements` = **Require signing** (klijenti).
   - `LDAP server signing requirements` = **Require signing** (DC-ovi) **ili** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - LDAP vezivanje kanala i potpisivanje LDAP-a](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Zahtevi za vezivanje kanala i potpisivanje LDAP-a](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Ažuriranje za ublažavanje LDAP relay napada](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (onemogućeno LDAP potpisivanje → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
