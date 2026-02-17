# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Szukaj TGS-REQ, które nie mają odpowiadającego AS-REQ.
- Szukaj TGT z podejrzanymi wartościami, np. domyślnym 10-letnim okresem ważności używanym przez Mimikatz.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Wymagania & przebieg

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Prawidłowy blob TGT**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Dane kontekstowe**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Uzyskaj TGT dla dowolnego kontrolowanego użytkownika poprzez AS-REQ (Rubeus `/tgtdeleg` jest wygodny, ponieważ zmusza klienta do wykonania Kerberos GSS-API dance bez poświadczeń).
2. Odszyfruj zwrócony TGT przy użyciu klucza krbtgt, popraw atrybuty PAC (user, groups, logon info, SIDs, device claims itp.).
3. Ponownie zaszyfruj/podpisz ticket tym samym kluczem krbtgt i wstrzykni go do bieżącej sesji logowania (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcjonalnie powtórz proces dla service ticket, dostarczając ważny blob TGT oraz docelowy klucz usługi, aby pozostać dyskretnym na sieci.

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now auto-populates accurate PAC attributes straight from AD (user profile, logon hours, sidHistory, domain policies), while `/opsec` makes the AS-REQ/AS-REP flow indistinguishable from a Windows client by performing the two-step pre-auth sequence and enforcing AES-only crypto. This dramatically reduces obvious indicators such as blank device IDs or unrealistic validity windows.
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
- `/ldap` (z opcjonalnymi `/ldapuser` i `/ldappassword`) wykonuje zapytania do AD i SYSVOL, aby odzwierciedlić dane polityki PAC docelowego użytkownika.
- `/opsec` wymusza ponowną próbę AS-REQ w stylu Windows, zerując 'noisy flags' i używając AES256.
- `/tgtdeleg` pozwala nie mieć dostępu do hasła w postaci jawnej ani klucza NTLM/AES ofiary, a jednocześnie zwraca odszyfrowywalny TGT.

### Service-ticket recutting

Ta sama aktualizacja Rubeus dodała możliwość zastosowania techniki diamond do TGS blobs. Podając `diamond` **base64-encoded TGT** (z `asktgt`, `/tgtdeleg` lub wcześniej sfałszowanego TGT), **service SPN**, i **service AES key**, możesz wygenerować realistyczne service tickets bez kontaktu z KDC — w praktyce bardziej ukryty silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ten sposób postępowania jest idealny, gdy już kontrolujesz service account key (np. zrzucany przy użyciu `lsadump::lsa /inject` lub `secretsdump.py`) i chcesz wygenerować pojedynczy TGS, który idealnie odpowiada polityce AD, ramom czasowym i danym PAC, bez wysyłania nowego ruchu AS/TGS.

### Sapphire-style PAC swaps (2025)

Nowszy wariant, czasem nazywany **sapphire ticket**, łączy bazę 'real TGT' Diamond z **S4U2self+U2U**, aby ukraść uprzywilejowany PAC i wstawić go do własnego TGT. Zamiast wymyślać dodatkowe SIDs, żądasz biletu U2U S4U2self dla użytkownika o wysokich uprawnieniach, wyodrębniasz ten PAC i wstawiasz go do swojego prawidłowego TGT przed ponownym podpisaniem kluczem krbtgt. Ponieważ U2U ustawia `ENC-TKT-IN-SKEY`, otrzymany przepływ wygląda jak legalna wymiana użytkownik–użytkownik.

Minimalna reprodukcja po stronie Linuksa z załatanym `ticketer.py` Impacket (dodaje obsługę sapphire):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Kluczowe wskazówki OPSEC przy użyciu tej odmiany:

- TGS-REQ będzie zawierać `ENC-TKT-IN-SKEY` i `additional-tickets` (TGT ofiary) — rzadko spotykane w normalnym ruchu.
- `sname` często równa się użytkownikowi żądającemu (dostęp samoobsługowy), a Event ID 4769 pokazuje wywołującego i cel jako ten sam SPN/użytkownik.
- Spodziewaj się sparowanych wpisów 4768/4769 z tym samym komputerem klienta, ale różnymi CNAMES (żądający z niskimi uprawnieniami vs. uprzywilejowany właściciel PAC).

### OPSEC i uwagi dotyczące wykrywania

- Tradycyjne heurystyki hunterów (TGS without AS, decade-long lifetimes) nadal mają zastosowanie do golden tickets, ale diamond tickets ujawniają się głównie wtedy, gdy **PAC content or group mapping looks impossible**. Wypełnij każde pole PAC (logon hours, user profile paths, device IDs), aby automatyczne porównania nie oznaczyły od razu fałszerstwa.
- **Nie przypisuj nadmiernie grup/RIDs**. Jeśli potrzebujesz tylko `512` (Domain Admins) i `519` (Enterprise Admins), zatrzymaj się na tym i upewnij się, że konto docelowe wiarygodnie należy do tych grup w innych miejscach w AD. Nadmierne `ExtraSids` zdradza.
- Sapphire-style swaps pozostawiają U2U odciski palców: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` w 4769 oraz następujący logon 4624 wynikający z sfałszowanego ticketu. Koreluj te pola zamiast tylko szukać luk typu no-AS-REQ.
- Microsoft zaczął wycofywać **RC4 service ticket issuance** z powodu CVE-2026-20833; wymuszanie wyłącznie AES etypes na KDC zarówno wzmacnia domenę, jak i dopasowuje się do narzędzi diamond/sapphire (/opsec już wymusza AES). Mieszanie RC4 w sfałszowanych PAC będzie coraz bardziej rzucać się w oczy.
- Projekt Splunk Security Content udostępnia telemetry attack-range dla diamond tickets oraz wykrycia takie jak *Windows Domain Admin Impersonation Indicator*, które koreluje nietypowe sekwencje Event ID 4768/4769/4624 i zmiany grup w PAC. Odtwarzanie tego zestawu danych (lub wygenerowanie własnego przy użyciu powyższych poleceń) pomaga zweryfikować pokrycie SOC dla T1558.001, jednocześnie dostarczając konkretnej logiki alertów, którą możesz wykorzystać do obchodzenia wykrywania.

## Źródła

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
