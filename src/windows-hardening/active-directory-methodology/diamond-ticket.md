# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. Golden ticket jest fałszowany całkowicie offline, szyfrowany za pomocą hasha krbtgt tej domeny, a następnie wstrzykiwany do sesji logowania w celu użycia. Ponieważ kontrolery domeny nie śledzą TGT, które (lub które) wydały legalnie, chętnie zaakceptują TGT zaszyfrowane własnym hashem krbtgt.

Istnieją dwie powszechne techniki wykrywania użycia golden tickets:

- Szukaj TGS-REQ, które nie mają odpowiadającego AS-REQ.
- Szukaj TGT z dziwnymi wartościami, takimi jak domyślny 10‑letni okres ważności w Mimikatz.

A diamond ticket powstaje przez modyfikację pól legalnego TGT wydanego przez DC. Osiąga się to przez żądanie TGT, odszyfrowanie go za pomocą hasha krbtgt domeny, modyfikację żądanych pól biletu, a następnie ponowne zaszyfrowanie. To niweluje dwie wspomniane wcześniej wady golden ticket, ponieważ:

- TGS-REQ będą miały poprzedzający je AS-REQ.
- TGT został wydany przez DC, co oznacza, że będzie zawierał wszystkie poprawne szczegóły wynikające z polityki Kerberos domeny. Chociaż w golden ticket można to dokładnie sfabrykować, jest to bardziej skomplikowane i podatne na błędy.

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Uzyskaj TGT dla dowolnego kontrolowanego użytkownika poprzez AS-REQ (Rubeus `/tgtdeleg` jest wygodny, ponieważ zmusza klienta do wykonania Kerberos GSS-API dance bez poświadczeń).
2. Odszyfruj zwrócony TGT za pomocą klucza krbtgt, załatkuj/załatkuj PAC attributes (user, groups, logon info, SIDs, device claims, itd.).
3. Ponownie zaszyfruj/podpisz bilet tym samym kluczem krbtgt i wstrzyknij go do bieżącej sesji logowania (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcjonalnie powtórz proces dla service ticket, dostarczając ważny TGT blob oraz docelowy service key, aby pozostać ukrytym na łączu.

### Updated Rubeus tradecraft (2024+)

Ostatnie prace Huntress zmodernizowały akcję `diamond` w Rubeus, przenosząc udoskonalenia `/ldap` i `/opsec`, które wcześniej istniały tylko dla golden/silver tickets. `/ldap` teraz automatycznie wypełnia dokładne PAC attributes bezpośrednio z AD (user profile, logon hours, sidHistory, domain policies), podczas gdy `/opsec` sprawia, że przepływ AS-REQ/AS-REP jest nieodróżnialny od klienta Windows przez wykonanie dwustopniowej sekwencji pre-auth i wymuszenie AES-only crypto. To dramatycznie zmniejsza oczywiste wskaźniki, takie jak puste device IDs czy nierealistyczne okna ważności.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (z opcjonalnymi `/ldapuser` & `/ldappassword`) wykonuje zapytania do AD i SYSVOL, aby odzwierciedlić dane polityki PAC docelowego użytkownika.
- `/opsec` wymusza ponowną próbę AS-REQ podobną do Windows, zerując flagi generujące hałas i używając AES256.
- `/tgtdeleg` nie wymaga dostępu do hasła w postaci jawnej ani klucza NTLM/AES ofiary, a mimo to zwraca odszyfrowywalny TGT.

### Przeróbka ticketów serwisowych

Ta sama aktualizacja Rubeus dodała możliwość zastosowania techniki diamond do blobów TGS. Podając `diamond` **base64-encoded TGT** (z `asktgt`, `/tgtdeleg`, lub wcześniej sfałszowanego TGT), **service SPN**, i **service AES key**, możesz wygenerować realistyczne service tickets bez kontaktu z KDC — w praktyce bardziej ukryty silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ten workflow jest idealny, gdy już kontrolujesz service account key (np. pozyskany przy użyciu `lsadump::lsa /inject` lub `secretsdump.py`) i chcesz wygenerować jednorazowy TGS, który idealnie odpowiada polityce AD, ramom czasowym i danym PAC bez wysyłania nowego ruchu AS/TGS.

### OPSEC & uwagi dotyczące wykrywania

- Tradycyjne heurystyki łowców (TGS without AS, decade-long lifetimes) nadal mają zastosowanie do golden tickets, ale diamond tickets ujawniają się głównie, gdy **zawartość PAC lub mapowanie grup wygląda na niemożliwe**. Wypełnij każde pole PAC (logon hours, user profile paths, device IDs), aby automatyczne porównania nie oznaczyły fałszerstwa od razu.
- **Nie przypisuj zbyt wielu grup/RIDs**. Jeśli potrzebujesz tylko `512` (Domain Admins) i `519` (Enterprise Admins), zatrzymaj się na tym i upewnij się, że konto docelowe wiarygodnie należy do tych grup gdzie indziej w AD. Nadmierna liczba `ExtraSids` zdradza fałszerstwo.
- Splunk's Security Content project distributes attack-range telemetry for diamond tickets plus detections such as *Windows Domain Admin Impersonation Indicator*, which correlates unusual Event ID 4768/4769/4624 sequences and PAC group changes. Odtworzenie tego zestawu danych (lub wygenerowanie własnego przy użyciu powyższych poleceń) pomaga zweryfikować pokrycie SOC dla T1558.001, jednocześnie dając konkretne reguły alertów, których można się nauczyć, by je obejść.

## Źródła

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
