# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno

LDAP relay/MITM napadi prosleđuju autentifikaciju kontroleru domena kako bi dobili autentifikovani LDAP kontekst. [Pregled name-resolution poisoning i relay napada](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) obuhvata širi tok napada. Dve povezane kontrole smanjuju ove mogućnosti:

- **LDAP channel binding (CBT)** povezuje primenljivu autentifikaciju sa TLS serverskim sertifikatom/kanalom koji koristi LDAPS i otežava relay između različitih kanala.
- **LDAP signing** zahteva zaštitu integriteta za SASL LDAP bind-ove. Ne obezbeđuje poverljivost; koristite TLS kada je potrebno i šifrovanje LDAP sadržaja.<sup>[[2]](#references)</sup>

**Brza provera stanja**: alati kao što je `netexec ldap <dc> -u user -p pass` prikazuju uočene smernice za signing i channel binding. `(signing:None)` i `(channel binding:Never)` ukazuju na nedostajuće kontrole, ali uspešan relay i dalje zavisi od uhvaćenog tipa autentifikacije, ponašanja EPA, privilegija naloga, ciljnog protokola i zaštita od relay napada. Kada prosleđeni principal ima potrebna prava, alati kao što je KrbRelayUp mogu da upišu `msDS-AllowedToActOnBehalfOfOtherIdentity`, podese delegiranje ograničeno na resurse (RBCD) i iskoriste dobijenu putanju delegiranja za lažno predstavljanje privilegovanog principala.<sup>[[4]](#references)</sup>

**Server 2025 DC-ovi** uvode novi GPO (**LDAP server signing requirements Enforcement**) koji podrazumevano zahteva **Require Signing** kada je podešen na **Not Configured**. Da biste izbegli sprovođenje, tu smernicu morate izričito da podesite na **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (samo LDAPS)

- **Zahtevi**:
  - Zakrpa za CVE-2017-8563 (2017) dodaje podršku za Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) dodaje LDAPS CBT telemetriju u režimu „what-if“.<sup>[[2]](#references)</sup>
- **GPO (DC-ovi)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (podrazumevano, bez CBT-a)
  - `When Supported` (delimično sprovođenje: klijenti koji podržavaju CBT moraju da obezbede važeći token; klijenti bez podrške za CBT i dalje mogu da se povežu, a audit događaji se beleže)
  - `Always` (sprovođenje: odbacuju se LDAPS bind-ovi bez važećeg CBT-a)<sup>[[1]](#references)</sup>
- **Audit**: podesite **When Supported** da biste uočili:
  - **3074** – LDAPS bind ne bi prošao CBT validaciju da je sprovođenje uključeno.
  - **3075** – LDAPS bind nije sadržao CBT podatke i bio bi odbijen da je sprovođenje uključeno.
  - (Događaj **3039** i dalje označava CBT greške u starijim verzijama.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Sprovođenje**: podesite **Always** kada LDAPS klijenti počnu da šalju CBT-ove; ovo važi samo za **LDAPS** (ne za običan port 389).<sup>[[1]](#references)</sup>

`When Supported` nije samo za audit: proverava CBT kod klijenata koji ga podržavaju, a dozvoljava povezivanje klijentima bez podrške za CBT. [Microsoft dokumentacija za smernicu](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) opisuje podrazumevane vrednosti koje zavise od verzije. LDAP signing važi za odgovarajuće bind-ove preko LDAP/389; channel binding važi za autentifikaciju LDAP-a zaštićenu TLS-om.


## LDAP Signing

- **Klijentski GPO**: `Network security: LDAP client signing requirements` = `Require signing` (umesto podrazumevanog `Negotiate signing` u modernom Windows-u).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Nasleđena postavka: `Domain controller: LDAP server signing requirements` = `Require signing` (podrazumevana vrednost je `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: ostavite nasleđenu smernicu na `None` i podesite `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` podrazumevano znači da se smernica sprovodi; podesite `Disabled` da biste to izbegli).<sup>[[1]](#references)</sup>
- **Kompatibilnost**: popišite uređaje i aplikacije koje nisu Windows, a koriste simple bind-ove ili nepotpisane SASL bind-ove. Microsoft dokumentuje podršku za održavane verzije Windows-a; tvrdnje o kompatibilnosti sa starijim klijentima treba proveriti u odnosu na stvarni klijentski stack, umesto svoditi ih na prag verzije XP-a.<sup>[[2]](#references)</sup>

## Relay putanje i ponovna autentifikacija potpisanim SASL-om

Ako se zahteva **samo signing**, relay na LDAPS i dalje može da funkcioniše kada se channel binding ne sprovodi: TLS obezbeđuje integritet transporta. Ako se zahteva **samo channel binding**, običan LDAP nema TLS kanal za povezivanje; relay može da se autentifikuje preko TCP porta 389, a zatim koristi StartTLS za operacije kojima je potreban TLS, pod uslovom da prosleđeni identitet ima potrebna prava. Sprovođenje obe kontrole zatvara ove uobičajene alternative, ali nije zaustavilo sledeći propust na nezakrpljenim kontrolerima domena.<sup>[[5]](#references)</sup>

### Dodavanje LDAP operacije nakon prosleđenog Bind-a

Na pogođenim kontrolerima domena Windows Server 2016–2025, prvo uspostavite **potpisanu NTLM SASL LDAP vezu** preko TCP porta 389 kao identitet X, koristeći akreditive čiji session key poznajete (ili anonimni NTLM SASL kontekst, ako je prihvaćen). Naterajte identitet Y da se autentifikuje **preko SMB-a** na relay-u. Prosledite Y-jev NTLM NEGOTIATE i DC-jev CHALLENGE kroz GSS-SPNEGO Bind zahteve na postojećoj LDAP vezi identiteta X. Windows SMB klijent postavlja `NTLMSSP_NEGOTIATE_SIGN`, pa je za rezultujući LDAP bind potreban potpisani SASL sloj; razmena koja potiče od HTTP/WebDAV-a uglavnom nema tu zastavicu i ovde nije zamenljiva.<sup>[[5]](#references)</sup>

Kada Y pošalje NTLM AUTHENTICATE, stavite **dve različite LDAP poruke u jedan SASL zapis sa prefiksom dužine**: BindRequest koji sadrži taj odgovor, a zatim ModifyRequest. Potpišite ceo zapis poznatim ključem identiteta X. Ranjivi DC proverava zapis pomoću ključa X, dovršava Bind i prebacuje autorizaciju veze na Y, a zatim izvršava preostali ModifyRequest kao Y, bez ponovne provere zapisa pomoću Y-jevog ključa. Time se ne otkrivaju Y-jeva lozinka ni session key; kasniji zapis potpisan ključem X neće proći. RBCD upis u `msDS-AllowedToActOnBehalfOfOtherIdentity` ili upis shadow credential-a u `msDS-KeyCredentialLink` i dalje zahteva da Y ima dozvolu nad ciljnim objektom. Pogledajte [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md) i, kada se relay vrši pomoću DC computer account-a, [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

Ovo je zaobilaženje za **običan LDAP**, a ne zaobilaženje LDAPS channel binding-a. Na LDAPS-u TLS štiti vezu, a Windows ne uspostavlja NTLM SASL signing sloj sa ključem X koji je potreban za ovaj put sa povezivanjem zapisa. Ako TCP port 389 nije dostupan, tehnika se ne može jednostavno preneti na TCP port 636. Bezbednosna ažuriranja iz oktobra 2026. sprečavaju operaciju sa istim zapisom tako što odbacuju preostale podatke nakon što Bind promeni identitet veze.<sup>[[5]](#references)</sup> KB5126646 je ažuriranje za Windows Server 2025; ostala pogođena izdanja Server-a imaju različite KB brojeve.<sup>[[7]](#references)</sup>

Istraživačev [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) obavija izmenjeni `ntlmrelayx.py` za ovaj tok rada. Potrebni su izvor za prisiljavanje autentifikacije **preko SMB-a**, određena verzija Impacket stabla koja izlaže LDAP signing/security-context API-je (Impacket 0.13.1 sa PyPI-ja nije dovoljan) i nalog pod kontrolom napadača za početni potpisani bind. Za RBCD upis navedite DN žrtvinog objekta i SID kontrolisanog delegirajućeg računara; koristite `-attribute` uz `-value` ili `-value-hex` za drugi dozvoljeni upis. Potvrdite rezultat nezavisnim potpisanim očitavanjem pomoću alata, umesto da poruku `FAILED` sa relay strane smatrate dokazom da ModifyRequest nije uspeo.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Zasebno pokrenite SMB autentifikaciju; pogledajte [forcing privileged NTLM authentication](printers-spooler-service-abuse.md) za jednu površinu za prinudu, a [relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) za ostale. Komanda alata i njegova implementacija dokumentovane su u njegovom repozitorijumu.<sup>[[6]](#references)</sup>

## Uvođenje uz prvo sprovođenje revizije (preporučeno ~30 dana)

1. Omogućite dijagnostiku LDAP interfejsa na svakom DC-u da biste beležili nepotpisane bind-ove (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Podesite DC GPO `LDAP server channel binding token requirements` = **When Supported** za delimičnu primenu CBT-a i telemetriju; prvo proverite kompatibilnost sa starijim klijentima.<sup>[[1]](#references)</sup>
3. Pratite događaje u Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – bind-ovi bez potpisa / dozvoljeni bind-ovi bez potpisa (nisu usklađeni sa zahtevima za potpisivanje).
   - **3074/3075** – LDAPS bind-ovi koji bi bili neuspešni ili bi izostavili CBT (zahteva KB4520412 na verzijama 2019/2022 i prethodno navedeni korak 2).
4. Sprovedite uvođenje kroz odvojene izmene:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC-ovi).
   - `LDAP client signing requirements` = **Require signing** (klijenti).
   - `LDAP server signing requirements` = **Require signing** (DC-ovi) **ili** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Povezivanje LDAP kanala i LDAP potpisivanje](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Zahtevi za LDAP channel binding i potpisivanje](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Ažuriranje za ublažavanje LDAP relay napada](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP potpisivanje onemogućeno → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Potpisano, zapečaćeno i relayed, u NTLM stilu](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [Dokaz koncepta LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Informacije o izdanjima Windows Server-a](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
