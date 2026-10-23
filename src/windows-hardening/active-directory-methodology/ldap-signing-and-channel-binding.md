# Ojačavanje LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno

LDAP relay/MITM napadi prosleđuju autentifikaciju kontroleru domena kako bi dobili autentifikovani LDAP kontekst. [Pregled trovanja razrešavanja imena i relay napada](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) obuhvata širi tok napada. Dve povezane kontrole smanjuju ove mogućnosti:

- **LDAP channel binding (CBT)** vezuje odgovarajuću autentifikaciju za TLS serverski sertifikat/kanal koji koristi LDAPS, čime otežava relay između različitih kanala.
- **LDAP signing** zahteva zaštitu integriteta za SASL LDAP bind-ove. Ne dodaje poverljivost; koristite TLS kada je potrebno i šifrovanje LDAP sadržaja.<sup>[[2]](#references)</sup>

**Brza provera stanja**: alati kao što je `netexec ldap <dc> -u user -p pass` prikazuju uočene smernice za signing i channel binding. `(signing:None)` i `(channel binding:Never)` ukazuju na nedostajuće kontrole, ali uspešan relay i dalje zavisi od tipa presretnute autentifikacije, EPA ponašanja, privilegija naloga, ciljnog protokola i zaštite od relay napada. Kada prosleđeni principal ima potrebna prava, alati kao što je KrbRelayUp mogu da upišu `msDS-AllowedToActOnBehalfOfOtherIdentity`, konfigurišu delegiranje sa ograničenjima zasnovano na resursima (RBCD) i iskoriste dobijeni put delegiranja za imitiranje privilegovanog principala.<sup>[[4]](#references)</sup>

**Server 2025 DCs** uvode novu GPO smernicu (**LDAP server signing requirements Enforcement**) koja podrazumevano koristi **Require Signing** kada je ostavljena na **Not Configured**. Da biste izbegli sprovođenje smernice, morate je eksplicitno postaviti na **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (samo LDAPS)

- **Zahtevi**:
  - Zakrpa za CVE-2017-8563 (2017) dodaje podršku za Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) dodaje LDAPS CBT „what-if“ telemetriju.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (podrazumevano, bez CBT-a)
  - `When Supported` (delimično sprovođenje: klijenti koji podržavaju CBT moraju da dostave važeći token; klijenti bez podrške za CBT i dalje mogu da se povežu, a audit događaji se beleže)
  - `Always` (sprovođenje: odbacuju se LDAPS bind-ovi bez važećeg CBT-a)<sup>[[1]](#references)</sup>
- **Audit**: postavite na **When Supported** da biste uočili:
  - **3074** – LDAPS bind ne bi prošao CBT validaciju da je smernica bila sprovedena.
  - **3075** – LDAPS bind nije sadržao CBT podatke i bio bi odbijen da je smernica bila sprovedena.
  - (Događaj **3039** i dalje signalizira CBT greške u starijim verzijama.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Sprovođenje**: postavite na **Always** kada LDAPS klijenti šalju CBT; deluje samo na **LDAPS** (ne na sirovi port 389).<sup>[[1]](#references)</sup>

`When Supported` nije samo za audit: proverava CBT kod klijenata koji ga podržavaju, a istovremeno dozvoljava povezivanje klijenata bez podrške za CBT. [Microsoft referenca za smernicu](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) opisuje podrazumevane vrednosti koje zavise od verzije. LDAP signing se primenjuje na odgovarajuće bind-ove preko LDAP/389; channel binding se primenjuje na autentifikaciju LDAP-a zaštićenu TLS-om.

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (za razliku od podrazumevane vrednosti `Negotiate signing` u modernom Windows-u).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Zastarelo: `Domain controller: LDAP server signing requirements` = `Require signing` (podrazumevana vrednost je `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: ostavite zastarelu smernicu na `None` i postavite `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` podrazumevano znači da se smernica sprovodi; postavite `Disabled` da biste to izbegli).<sup>[[1]](#references)</sup>
- **Kompatibilnost**: napravite inventar uređaja i aplikacija koji nisu Windows, a koriste simple bind-ove ili nepotpisane SASL bind-ove. Microsoft dokumentuje podršku u održavanim verzijama Windows-a; tvrdnje o kompatibilnosti sa zastarelim klijentima treba proveriti u odnosu na stvarni client stack, umesto da se svedu na prag verzije XP-a.<sup>[[2]](#references)</sup>

## Uvođenje uz prvo praćenje (preporučeno oko 30 dana)

1. Omogućite LDAP interface diagnostics na svakom DC-u da biste beležili nepotpisane bind-ove (događaj **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Postavite DC GPO `LDAP server channel binding token requirements` = **When Supported** za delimično sprovođenje CBT-a i telemetriju; prvo proverite kompatibilnost sa starijim klijentima.<sup>[[1]](#references)</sup>
3. Pratite događaje Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – bind-ovi bez potpisa / bind-ovi dozvoljeni bez potpisa (nisu usklađeni sa zahtevima za potpisivanje).
   - **3074/3075** – LDAPS bind-ovi koji bi bili neuspešni ili izostavili CBT (zahteva KB4520412 na verzijama 2019/2022 i prethodni korak).
4. Sprovodite u odvojenim izmenama:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC-ovi).
   - `LDAP client signing requirements` = **Require signing** (klijenti).
   - `LDAP server signing requirements` = **Require signing** (DC-ovi) **ili** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - LDAP povezivanje kanala i LDAP potpisivanje](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Zahtevi za LDAP channel binding i potpisivanje](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Ažuriranje za ublažavanje LDAP relay napada](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP potpisivanje onemogućeno → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
