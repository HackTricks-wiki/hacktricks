# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.<sup>[[1]](#references)</sup>

Istnieją dwie powszechne techniki wykrywania użycia golden tickets:

- Szukanie TGS-REQs, które nie mają odpowiadającego im AS-REQ.
- Szukanie TGTs zawierających absurdalne wartości, takich jak domyślny 10-letni czas życia używany przez Mimikatz.

**Diamond ticket** jest tworzony przez **modyfikowanie pól legalnego TGT wydanego przez DC**. Osiąga się to poprzez **zażądanie** **TGT**, **odszyfrowanie** go za pomocą hasha krbtgt domeny, **zmodyfikowanie** żądanych pól ticketu, a następnie **ponowne zaszyfrowanie go**. Pozwala to **przezwyciężyć dwa wspomniane wcześniej ograniczenia** golden ticket, ponieważ:<sup>[[1]](#references)</sup>

- TGS-REQs będą miały poprzedzający je AS-REQ.
- TGT został wydany przez DC, więc będzie zawierał wszystkie prawidłowe szczegóły wynikające z polityki Kerberos domeny. Chociaż można je dokładnie sfałszować w golden ticket, jest to bardziej złożone i podatne na błędy.

### Wymagania i przebieg

- **Materiał kryptograficzny**: klucz AES256 krbtgt (preferowany) lub hash NTLM w celu odszyfrowania i ponownego podpisania TGT.
- **Legalny blob TGT**: uzyskany za pomocą `/tgtdeleg`, `asktgt`, `s4u` lub przez wyeksportowanie ticketów z pamięci.
- **Dane kontekstowe**: RID docelowego użytkownika, grupowe RIDs/SIDs oraz (opcjonalnie) atrybuty PAC pobrane przez LDAP.
- **Klucze usług** (tylko jeśli planujesz ponownie utworzyć service tickets): klucz AES docelowego service SPN, którego tożsamość ma zostać podszyta.

1. Uzyskaj TGT dla dowolnego kontrolowanego użytkownika za pomocą AS-REQ (Rubeus `/tgtdeleg` jest wygodny, ponieważ zmusza klienta do wykonania wymiany Kerberos GSS-API bez poświadczeń).
2. Odszyfruj otrzymany TGT za pomocą klucza krbtgt i zmodyfikuj atrybuty PAC (użytkownik, grupy, informacje logowania, SIDs, device claims itd.).
3. Ponownie zaszyfruj/podpisz ticket za pomocą tego samego klucza krbtgt i wstrzyknij go do bieżącej sesji logowania (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcjonalnie powtórz ten proces dla service ticket, dostarczając prawidłowy blob TGT oraz klucz docelowej usługi, aby zachować skrytość w sieci.

### Zaktualizowana praktyka Rubeus (2024+)

Najnowsze prace Huntress zmodernizowały akcję `diamond` w Rubeus poprzez przeniesienie usprawnień `/ldap` i `/opsec`, które wcześniej istniały wyłącznie dla golden/silver tickets. `/ldap` pobiera teraz rzeczywisty kontekst PAC poprzez odpytywanie LDAP **oraz** montowanie SYSVOL w celu wyodrębnienia atrybutów kont/grup oraz polityki Kerberos/hasła (np. `GptTmpl.inf`), podczas gdy `/opsec` sprawia, że przepływ AS-REQ/AS-REP odpowiada działaniu Windows, wykonując dwuetapową wymianę preauth i wymuszając wyłącznie AES oraz realistyczne KDCOptions. Znacząco ogranicza to oczywiste wskaźniki, takie jak brakujące pola PAC lub czasy życia niezgodne z polityką.<sup>[[3]](#references)</sup>
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (z opcjonalnymi `/ldapuser` i `/ldappassword`) odpytuje AD i SYSVOL, aby odwzorować dane zasad PAC użytkownika docelowego.
- `/opsec` wymusza retry AS-REQ przypominający zachowanie Windows, zerując głośne flagi i ograniczając się do AES256.
- `/tgtdeleg` nie ujawnia hasła w cleartext ani klucza NTLM/AES ofiary, a jednocześnie nadal zwraca możliwy do odszyfrowania TGT.

### Ponowne tworzenie service ticketów

Ta sama aktualizacja Rubeus dodała możliwość zastosowania diamond technique do blobów TGS. Przekazując do `diamond` **zakodowany w base64 TGT** (z `asktgt`, `/tgtdeleg` lub wcześniej sfałszowanego TGT), **service SPN** oraz **service AES key**, możesz tworzyć realistyczne service tickety bez komunikacji z KDC — skutecznie uzyskując bardziej stealthowy silver ticket.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ten workflow jest idealny, gdy masz już kontrolę nad kluczem konta usługi (np. zrzucanym za pomocą `lsadump::lsa /inject` lub `secretsdump.py`) i chcesz wygenerować jednorazowy TGS, który dokładnie odpowiada zasadom AD, osi czasu i danym PAC, bez wykonywania żadnego nowego ruchu AS/TGS.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Nowsza odmiana, czasami nazywana **sapphire ticket**, łączy bazę „prawdziwego TGT” techniki Diamond z **S4U2self+U2U**, aby wykraść uprzywilejowany PAC i wstawić go do własnego TGT. Zamiast wymyślać dodatkowe SID-y, żądasz biletu U2U S4U2self dla użytkownika o wysokich uprawnieniach, gdzie `sname` wskazuje użytkownika żądającego o niskich uprawnieniach; KRB_TGS_REQ przenosi TGT użytkownika żądającego w `additional-tickets` i ustawia `ENC-TKT-IN-SKEY`, umożliwiając odszyfrowanie biletu usługi za pomocą klucza tego użytkownika. Następnie wyodrębniasz uprzywilejowany PAC i wstawiasz go do legalnego TGT, po czym ponownie podpisujesz go kluczem krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket obsługuje teraz sapphire za pomocą `-impersonate` + `-request` (wymiana z działającym KDC):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` accepts a username or SID; `-request` requires live user creds plus krbtgt key material (AES/NTLM) to decrypt/patch tickets.

Key OPSEC tells when using this variant:<sup>[[5]](#references)</sup>

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — rare in normal traffic.
- `sname` often equals the requesting user (self-service access) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (low-priv requester vs. privileged PAC owner).

### Uwagi dotyczące OPSEC i wykrywania

- Traditional hunter heuristics (TGS without AS, decade-long lifetimes) still apply to golden tickets, but diamond tickets mainly surface when the **PAC content or group mapping looks impossible**. Populate every PAC field (logon hours, user profile paths, device IDs) so automated comparisons do not immediately flag the forgery.<sup>[[3]](#references)</sup>
- **Do not oversubscribe groups/RIDs**. If you only need `512` (Domain Admins) and `519` (Enterprise Admins), stop there and make sure the target account plausibly belongs to those groups elsewhere in AD. Excessive `ExtraSids` is a giveaway.
- Sapphire-style swaps leave U2U fingerprints: `ENC-TKT-IN-SKEY` + `additional-tickets` plus a `sname` that points at a user (often the requester) in 4769, and a follow-up 4624 logon sourced from the forged ticket. Correlate those fields instead of only looking for no-AS-REQ gaps.<sup>[[5]](#references)</sup>
- Microsoft started phasing out **RC4 service ticket issuance** because of CVE-2026-20833; enforcing AES-only etypes on the KDC both hardens the domain and aligns with diamond/sapphire tooling (/opsec already forces AES). Mixing RC4 into forged PACs will increasingly stick out.<sup>[[6]](#references)</sup>
- Splunk's Security Content project distributes attack-range telemetry for diamond tickets plus detections such as *Windows Domain Admin Impersonation Indicator*, which correlates unusual Event ID 4768/4769/4624 sequences and PAC group changes. Replaying that dataset (or generating your own with the commands above) helps validate SOC coverage for T1558.001 while giving you concrete alert logic to evade.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
