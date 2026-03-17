# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Podobnie jak golden ticket**, diamond ticket jest TGT, który może być użyty do **dostępu do dowolnej usługi jako dowolny użytkownik**. Golden ticket jest sfałszowany całkowicie offline, zaszyfrowany hashem krbtgt tej domeny i następnie wstrzyknięty do sesji logowania do użycia. Ponieważ kontrolery domeny nie śledzą TGT, które prawidłowo wydały, chętnie zaakceptują TGT zaszyfrowane ich własnym hashem krbtgt.

Istnieją dwie powszechne techniki wykrywania użycia golden ticket:

- Szukaj TGS-REQ, które nie mają odpowiadającego AS-REQ.
- Szukaj TGT z dziwnymi wartościami, takimi jak domyślny 10-letni okres ważności Mimikatz.

A **diamond ticket** powstaje przez **zmodyfikowanie pól prawidłowego TGT wydanego przez DC**. Dokonuje się tego przez **zażądanie** **TGT**, **odszyfrowanie** go za pomocą hasha krbtgt domeny, **zmodyfikowanie** pożądanych pól biletu, a następnie jego **ponowne zaszyfrowanie**. To **niweluje dwie wcześniej wspomniane wady** golden ticket, ponieważ:

- TGS-REQ będą miały poprzedzające AS-REQ.
- TGT został wydany przez DC, co oznacza, że będzie zawierał wszystkie poprawne szczegóły z polityki Kerberos domeny. Chociaż w golden ticket można je dokładnie sfałszować, jest to bardziej skomplikowane i podatne na błędy.

### Wymagania i przebieg

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Uzyskaj TGT dla dowolnego kontrolowanego użytkownika przez AS-REQ (Rubeus `/tgtdeleg` jest wygodny, ponieważ zmusza klienta do wykonania wymiany Kerberos GSS-API bez poświadczeń).
2. Odszyfruj zwrócony TGT przy użyciu klucza krbtgt, zmodyfikuj atrybuty PAC (użytkownik, grupy, informacje o logowaniu, SIDs, device claims itd.).
3. Ponownie zaszyfruj/podpisz bilet tym samym kluczem krbtgt i wstrzyknij go do bieżącej sesji logowania (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcjonalnie, powtórz proces dla service ticket, dostarczając ważny blob TGT oraz docelowy klucz usługi, aby pozostać niewykrywalnym w ruchu sieciowym.

### Zaktualizowane techniki Rubeus (2024+)

Ostatnie prace Huntress zmodernizowały akcję `diamond` w Rubeus przez przeniesienie ulepszeń `/ldap` i `/opsec`, które wcześniej istniały tylko dla golden/silver tickets. `/ldap` teraz pobiera rzeczywisty kontekst PAC przez zapytania do LDAP **i** montowanie SYSVOL w celu wyciągnięcia atrybutów kont/grup oraz polityki Kerberos/hasła (np. `GptTmpl.inf`), podczas gdy `/opsec` sprawia, że przepływ AS-REQ/AS-REP odpowiada Windows poprzez wykonanie dwustopniowej wymiany preauth i wymuszenie AES-only + realistycznych KDCOptions. To dramatycznie zmniejsza oczywiste wskaźniki, takie jak brakujące pola PAC czy niezgodne z polityką okresy ważności.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) zapytuje AD i SYSVOL, aby odzwierciedlić dane polityki PAC docelowego użytkownika.
- `/opsec` wymusza próbę AS-REQ podobną do Windows, zerując noisy flags i trzymając się AES256.
- `/tgtdeleg` pozwala nie ujawniać cleartext password ani klucza NTLM/AES ofiary, a jednocześnie zwraca odszyfrowalny TGT.

### Przeróbka service-ticket

Ta aktualizacja Rubeus dodała możliwość zastosowania diamond technique do TGS blobs. Podając do `diamond` **base64-encoded TGT** (z `asktgt`, `/tgtdeleg` lub uprzednio sfałszowanego TGT), **service SPN**, i **service AES key**, możesz wygenerować realistyczne service tickets bez dotykania KDC — w praktyce bardziej dyskretny silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ten przepływ pracy jest idealny, gdy już kontrolujesz klucz konta usługi (np. wydobyty przy użyciu `lsadump::lsa /inject` lub `secretsdump.py`) i chcesz wystawić jednorazowy TGS, który idealnie pasuje do polityki AD, ram czasowych i danych PAC, bez wysyłania nowego ruchu AS/TGS.

### Sapphire-style PAC swaps (2025)

A newer twist sometimes called a **sapphire ticket** combines Diamond's "real TGT" base with **S4U2self+U2U** to steal a privileged PAC and drop it into your own TGT. Zamiast wymyślać dodatkowe SIDs, żądasz biletu U2U S4U2self dla użytkownika o wysokich uprawnieniach, w którym `sname` celuje w niskouprawnionego żądającego; KRB_TGS_REQ przenosi TGT żądającego w `additional-tickets` i ustawia `ENC-TKT-IN-SKEY`, co umożliwia odszyfrowanie biletu serwisowego przy użyciu klucza tego użytkownika. Następnie wyciągasz uprzywilejowany PAC i wstawiasz go do swojego prawidłowego TGT przed ponownym podpisaniem kluczem krbtgt.

Impacket's `ticketer.py` teraz zawiera wsparcie dla sapphire za pomocą `-impersonate` + `-request` (wymiana na żywo z KDC):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` przyjmuje nazwę użytkownika lub SID; `-request` wymaga live user creds oraz materiału klucza krbtgt (AES/NTLM) do odszyfrowania/patchowania ticketów.

Key OPSEC tells when using this variant:

- TGS-REQ będzie zawierać `ENC-TKT-IN-SKEY` i `additional-tickets` (victim TGT) — rzadkie w normalnym ruchu.
- `sname` często równa się użytkownikowi żądającemu (self-service access), a Event ID 4769 pokazuje wywołującego i cel jako ten sam SPN/użytkownik.
- Oczekuj sparowanych wpisów 4768/4769 z tym samym komputerem klienckim, ale różnymi CNAMES (żądający o niskich uprawnieniach vs. uprzywilejowany właściciel PAC).

### OPSEC & uwagi dotyczące wykrywania

- Tradycyjne heurystyki hunterów (TGS without AS, dziesięcioletnie okresy ważności) nadal mają zastosowanie do golden tickets, ale diamond tickets ujawniają się głównie, gdy **zawartość PAC lub mapowanie grup wygląda na niemożliwe**. Wypełnij każde pole PAC (logon hours, user profile paths, device IDs), aby automatyczne porównania nie oznaczyły fałszerstwa od razu.
- **Nie przypisuj nadmiernej liczby grup/RID-ów**. Jeśli potrzebujesz tylko `512` (Domain Admins) i `519` (Enterprise Admins), zatrzymaj się na nich i upewnij się, że konto docelowe prawdopodobnie należy do tych grup w innych miejscach w AD. Nadmierne `ExtraSids` są podejrzane.
- Sapphire-style swaps pozostawiają odciski U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` oraz `sname`, który w 4769 wskazuje na użytkownika (często żądającego), a potem następuje logon 4624 pochodzący z sfałszowanego ticketu. Koreluj te pola zamiast patrzeć tylko na luki no-AS-REQ.
- Microsoft zaczął wycofywać **RC4 service ticket issuance** z powodu CVE-2026-20833; wymuszanie na KDC tylko etypów AES zarówno wzmacnia domenę, jak i dopasowuje się do diamond/sapphire tooling (/opsec already forces AES). Mieszanie RC4 w sfałszowanych PACach będzie coraz bardziej rzucać się w oczy.
- Projekt Splunk Security Content dystrybuuje telemetrykę attack-range dla diamond tickets oraz detekcje takie jak *Windows Domain Admin Impersonation Indicator*, które korelują nietypowe sekwencje Event ID 4768/4769/4624 i zmiany grup w PAC. Odtwarzanie tego zbioru danych (lub wygenerowanie własnego za pomocą powyższych komend) pomaga zweryfikować pokrycie SOC dla T1558.001, jednocześnie dając konkretne reguły alertów do ominięcia.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
