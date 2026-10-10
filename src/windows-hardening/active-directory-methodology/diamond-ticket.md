# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Podobnie jak golden ticket**, diamond ticket to TGT, którego można użyć do **uzyskania dostępu do dowolnej usługi jako dowolny użytkownik**. Golden ticket jest fałszowany całkowicie offline, szyfrowany hashem krbtgt tej domeny, a następnie przekazywany do sesji logowania w celu użycia. Ponieważ kontrolery domeny nie śledzą TGT, które legalnie wystawiły, chętnie akceptują TGT zaszyfrowane własnym hashem krbtgt.<sup>[[1]](#references)</sup>

Istnieją dwie popularne techniki wykrywania użycia golden tickets:

- Wyszukiwanie TGS-REQ bez odpowiadającego mu AS-REQ.
- Wyszukiwanie TGT z absurdalnymi wartościami, takimi jak domyślny 10-letni okres ważności w Mimikatz.

**Diamond ticket** tworzy się przez **modyfikację pól legalnego TGT wystawionego przez DC**. Osiąga się to przez **zażądanie** **TGT**, **odszyfrowanie** go hashem krbtgt domeny, **zmodyfikowanie** wybranych pól ticketu, a następnie **ponowne zaszyfrowanie go**. Pozwala to **uniknąć dwóch wspomnianych wcześniej wad** golden ticket, ponieważ:<sup>[[1]](#references)</sup>

- TGS-REQ będą poprzedzone przez AS-REQ.
- TGT został wystawiony przez DC, więc będzie zawierał wszystkie poprawne szczegóły wynikające z zasad Kerberos domeny. Choć można je dokładnie sfałszować w golden ticket, jest to bardziej złożone i podatne na błędy.

### Wymagania i przebieg pracy

- **Materiał kryptograficzny**: klucz AES256 krbtgt (preferowany) lub hash NTLM, potrzebny do odszyfrowania i ponownego podpisania TGT.
- **Legalny blob TGT**: uzyskany przez `/tgtdeleg`, `asktgt`, `s4u` lub przez eksport ticketów z pamięci.
- **Dane kontekstowe**: RID docelowego użytkownika, RID/SID grup oraz (opcjonalnie) atrybuty PAC uzyskane z LDAP.
- **Klucze usług** (tylko jeśli planujesz ponownie wystawić tickety usługowe): klucz AES docelowego SPN usługi, pod którą chcesz się podszyć.

1. Uzyskaj TGT dla dowolnego kontrolowanego użytkownika przez AS-REQ (`/tgtdeleg` w Rubeus jest wygodny, ponieważ wymusza na kliencie wykonanie wymiany Kerberos GSS-API bez poświadczeń).
2. Odszyfruj otrzymany TGT kluczem krbtgt i zmodyfikuj atrybuty PAC (użytkownik, grupy, informacje logowania, SID-y, deklaracje urządzenia itd.).
3. Ponownie zaszyfruj/podpisz ticket tym samym kluczem krbtgt i wstrzyknij go do bieżącej sesji logowania (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcjonalnie powtórz ten proces dla ticketu usługi, podając prawidłowy blob TGT i klucz docelowej usługi, aby zachować dyskrecję w ruchu sieciowym.

### Zaktualizowane techniki Rubeus (2024+)

Niedawne prace Huntress unowocześniły akcję `diamond` w Rubeus, przenosząc usprawnienia `/ldap` i `/opsec`, które wcześniej były dostępne tylko dla golden/silver tickets. `/ldap` pobiera teraz rzeczywisty kontekst PAC przez zapytania LDAP **oraz** montowanie SYSVOL w celu odczytania atrybutów kont/grup i zasad Kerberos/hasła (np. `GptTmpl.inf`), a `/opsec` sprawia, że przebieg AS-REQ/AS-REP odpowiada zachowaniu Windows: wykonuje dwuetapową wymianę preauth oraz wymusza użycie wyłącznie AES i realistycznych wartości KDCOptions. Znacznie ogranicza to oczywiste wskaźniki, takie jak brakujące pola PAC lub okresy ważności niezgodne z zasadami.<sup>[[3]](#references)</sup>

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

- `/ldap` (z opcjonalnymi `/ldapuser` i `/ldappassword`) odpytuje AD i SYSVOL, aby skopiować dane zasad PAC użytkownika docelowego.
- `/opsec` wymusza ponowienie AS-REQ w stylu Windows, zerując charakterystyczne flagi i używając AES256.
- `/tgtdeleg` pozwala uniknąć dostępu do hasła w postaci jawnej lub klucza NTLM/AES ofiary, a jednocześnie zwraca odszyfrowywalny TGT.

### Ponowne tworzenie biletów usługowych

Ta sama aktualizacja Rubeus dodała możliwość zastosowania techniki diamond do blobów TGS. Przekazując `diamond` **zakodowany w base64 TGT** (z `asktgt`, `/tgtdeleg` lub wcześniej sfałszowany TGT), **SPN usługi** i **klucz AES usługi**, możesz wystawiać realistyczne bilety usługowe bez kontaktu z KDC — w praktyce tworząc bardziej ukryty silver ticket.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Ten workflow sprawdza się idealnie, gdy masz już klucz konta usługi (np. zrzutowany za pomocą `lsadump::lsa /inject` lub `secretsdump.py`) i chcesz wygenerować jednorazowy TGS, który dokładnie odpowiada zasadom AD, osi czasu i danym PAC, bez wysyłania jakiegokolwiek nowego ruchu AS/TGS.<sup>[[3]](#references)</sup>

### Zamiana PAC w stylu Sapphire (2025)

Nowsza odmiana, czasami nazywana **sapphire ticket**, łączy bazę w postaci „rzeczywistego TGT” z techniką **S4U2self+U2U**, aby wykraść uprzywilejowany PAC i umieścić go we własnym TGT. Zamiast wymyślać dodatkowe identyfikatory SID, żądasz biletu U2U S4U2self dla użytkownika o wysokich uprawnieniach, przy czym `sname` wskazuje żądającego o niskich uprawnieniach; KRB_TGS_REQ zawiera TGT żądającego w `additional-tickets` i ustawia `ENC-TKT-IN-SKEY`, co pozwala odszyfrować bilet usługi za pomocą klucza tego użytkownika. Następnie wyodrębniasz uprzywilejowany PAC i wstawiasz go do swojego legalnego TGT, po czym ponownie podpisujesz go kluczem krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket obsługuje teraz Sapphire w `ticketer.py` za pomocą `-impersonate` + `-request` (wymiana z działającym KDC):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` przyjmuje nazwę użytkownika lub SID; `-request` wymaga aktywnych poświadczeń użytkownika oraz materiału klucza krbtgt (AES/NTLM), aby odszyfrować/zmodyfikować bilety.

Najważniejsze wskazówki OPSEC podczas używania tego wariantu:<sup>[[5]](#references)</sup>

- TGS-REQ będzie zawierać `ENC-TKT-IN-SKEY` i `additional-tickets` (TGT ofiary) — rzadko spotykane w normalnym ruchu.
- `sname` często odpowiada nazwie użytkownika wysyłającego żądanie (dostęp samoobsługowy), a Event ID 4769 pokazuje, że wywołujący i cel mają ten sam SPN/użytkownika.
- Spodziewaj się sparowanych wpisów 4768/4769 z tym samym komputerem klienckim, ale różnymi CNAMES (użytkownik o niskich uprawnieniach wysyłający żądanie vs. uprzywilejowany właściciel PAC).

### Uwagi dotyczące OPSEC i wykrywania

- Tradycyjne heurystyki wyszukiwania (TGS bez AS, okresy ważności liczone w dekadach) nadal mają zastosowanie do golden tickets, ale diamond tickets wychodzą na jaw głównie wtedy, gdy **zawartość PAC lub mapowanie grup wygląda na niemożliwe**. Wypełnij każde pole PAC (godziny logowania, ścieżki profilu użytkownika, identyfikatory urządzeń), aby zautomatyzowane porównania nie wykryły od razu fałszerstwa.<sup>[[3]](#references)</sup>
- **Nie przypisuj nadmiernej liczby grup/RID**. Jeśli potrzebujesz tylko `512` (Domain Admins) i `519` (Enterprise Admins), poprzestań na nich i upewnij się, że konto docelowe wiarygodnie należy do tych grup w innych miejscach AD. Nadmiarowe `ExtraSids` wzbudzają podejrzenia.
- Podmiany w stylu Sapphire pozostawiają ślady U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` oraz `sname` wskazujące na użytkownika (często osobę wysyłającą żądanie) w 4769, a także następujące po nich logowanie 4624 pochodzące ze sfałszowanego biletu. Koreluj te pola, zamiast szukać wyłącznie luk w sekwencjach bez AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft rozpoczął wycofywanie **wystawiania biletów usługowych RC4** z powodu CVE-2026-20833; wymuszanie w KDC wyłącznie typów szyfrowania AES zarówno wzmacnia zabezpieczenia domeny, jak i jest zgodne z narzędziami diamond/sapphire (/opsec już wymusza AES). Używanie RC4 w sfałszowanych PAC będzie coraz bardziej rzucać się w oczy.<sup>[[6]](#references)</sup>
- Projekt Splunk Security Content udostępnia telemetrię attack-range dla diamond tickets oraz wykrycia, takie jak *Windows Domain Admin Impersonation Indicator*, które koreluje nietypowe sekwencje Event ID 4768/4769/4624 i zmiany grup w PAC. Odtworzenie tego zbioru danych (lub wygenerowanie własnego za pomocą powyższych poleceń) pomaga zweryfikować pokrycie SOC dla T1558.001, a jednocześnie dostarcza konkretną logikę alertów do omijania.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Kamienie szlachetne: nowa generacja ataków Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Uwielbiamy bawić się biletami (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Ponowne szlifowanie Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Dane o ataku Diamond Ticket i wykrycia (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Ciemna strona klejnotów: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Wymuszanie biletów usługowych RC4 dla CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
