# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Podobnie jak golden ticket**, diamond ticket to TGT, którego można użyć, aby **uzyskać dostęp do dowolnej usługi jako dowolny użytkownik**. Golden ticket jest fałszowany całkowicie offline, szyfrowany hashem krbtgt danej domeny, a następnie przekazywany do sesji logowania w celu użycia. Ponieważ kontrolery domeny nie śledzą TGT, które legalnie wystawiły, chętnie akceptują TGT szyfrowane własnym hashem krbtgt.<sup>[[1]](#references)</sup>

Istnieją dwie powszechne techniki wykrywania użycia golden tickets:

- Wyszukaj TGS-REQ, które nie mają odpowiadającego im AS-REQ.
- Wyszukaj TGT z absurdalnymi wartościami, takimi jak domyślny 10-letni okres ważności Mimikatz.

**Diamond ticket** tworzy się przez **modyfikację pól legalnego TGT wystawionego przez DC**. Osiąga się to przez **zażądanie** **TGT**, **odszyfrowanie** go hashem krbtgt domeny, **zmodyfikowanie** wybranych pól biletu, a następnie **ponowne jego zaszyfrowanie**. Pozwala to **uniknąć dwóch wspomnianych wcześniej wad** golden ticket, ponieważ:<sup>[[1]](#references)</sup>

- TGS-REQ będą poprzedzone przez AS-REQ.
- TGT został wystawiony przez DC, więc będzie zawierał wszystkie prawidłowe szczegóły wynikające z polityki Kerberos domeny. Można je dokładnie podrobić w golden ticket, ale jest to bardziej skomplikowane i zwiększa ryzyko błędów.

### Wymagania i przebieg

- **Materiał kryptograficzny**: klucz krbtgt AES256 (preferowany) lub hash NTLM, potrzebny do odszyfrowania i ponownego podpisania TGT.
- **Blob legalnego TGT**: uzyskany za pomocą `/tgtdeleg`, `asktgt`, `s4u` lub przez wyeksportowanie biletów z pamięci.
- **Dane kontekstowe**: RID docelowego użytkownika, RID/SID grup oraz (opcjonalnie) atrybuty PAC uzyskane z LDAP.
- **Klucze usług** (tylko jeśli planujesz ponownie tworzyć bilety usług): klucz AES usługi SPN, której tożsamość ma zostać podszyta.

1. Uzyskaj TGT dla dowolnego kontrolowanego użytkownika za pomocą AS-REQ (Rubeus `/tgtdeleg` jest wygodny, ponieważ wymusza na kliencie wykonanie wymiany Kerberos GSS-API bez poświadczeń).
2. Odszyfruj zwrócony TGT kluczem krbtgt i zmodyfikuj atrybuty PAC (użytkownika, grupy, informacje logowania, SID, oświadczenia urządzenia itp.).
3. Ponownie zaszyfruj/podpisz bilet tym samym kluczem krbtgt i wstrzyknij go do bieżącej sesji logowania (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcjonalnie powtórz ten proces dla biletu usługi, podając prawidłowy blob TGT i klucz docelowej usługi, aby zachować większą dyskrecję w ruchu sieciowym.

### Zaktualizowane tradecraft Rubeus (2024+)

Nowsze prace Huntress unowocześniły akcję `diamond` w Rubeus, przenosząc do niej ulepszenia `/ldap` i `/opsec`, które wcześniej były dostępne tylko dla golden/silver tickets. Opcja `/ldap` pobiera teraz rzeczywisty kontekst PAC, odpytując LDAP **i** montując SYSVOL, aby odczytać atrybuty kont/grup oraz politykę Kerberos/haseł (np. `GptTmpl.inf`), a opcja `/opsec` sprawia, że przepływ AS-REQ/AS-REP odpowiada zachowaniu Windows: wykonuje dwuetapową wymianę preauth i wymusza wyłącznie AES oraz realistyczne KDCOptions. Znacznie ogranicza to oczywiste wskaźniki, takie jak brakujące pola PAC lub okresy ważności niezgodne z polityką.<sup>[[3]](#references)</sup>

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

- `/ldap` (z opcjonalnymi `/ldapuser` i `/ldappassword`) odpytuje AD i SYSVOL, aby odtworzyć dane zasad PAC użytkownika docelowego.
- `/opsec` wymusza ponowienie AS-REQ w stylu Windows, zerując charakterystyczne flagi i używając wyłącznie AES256.
- `/tgtdeleg` pozwala uniknąć dostępu do hasła ofiary w postaci jawnej oraz jej klucza NTLM/AES, a mimo to zwraca TGT, który można odszyfrować.

### Ponowne tworzenie biletów usługowych

Ta sama aktualizacja Rubeus dodała możliwość zastosowania techniki diamond do blobów TGS. Przekazując `diamond` **TGT zakodowany w base64** (z `asktgt`, `/tgtdeleg` lub wcześniej sfałszowany TGT), **SPN usługi** oraz **klucz AES usługi**, można tworzyć realistyczne bilety usługowe bez kontaktu z KDC — w praktyce jest to bardziej skryty silver ticket.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Ten workflow jest idealny, gdy masz już klucz konta usługi (np. zrzutowany za pomocą `lsadump::lsa /inject` lub `secretsdump.py`) i chcesz wystawić jednorazowy TGS, który dokładnie odpowiada zasadom AD, osi czasu i danym PAC, bez generowania nowego ruchu AS/TGS.<sup>[[3]](#references)</sup>

### Podmiany PAC w stylu Sapphire (2025)

Nowsza odmiana, czasem nazywana **sapphire ticket**, łączy bazę w postaci „prawdziwego TGT” Diamond z **S4U2self+U2U**, aby wykraść uprzywilejowany PAC i wstawić go do własnego TGT. Zamiast wymyślać dodatkowe SID-y, żądasz biletu U2U S4U2self dla użytkownika o wysokich uprawnieniach, przy czym `sname` wskazuje użytkownika żądającego o niskich uprawnieniach; KRB_TGS_REQ przenosi TGT użytkownika żądającego w `additional-tickets` i ustawia `ENC-TKT-IN-SKEY`, co pozwala odszyfrować bilet usługi za pomocą klucza tego użytkownika. Następnie wyodrębniasz uprzywilejowany PAC i wstawiasz go do swojego prawidłowego TGT, po czym ponownie podpisujesz go kluczem krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

`ticketer.py` z Impacket obsługuje teraz sapphire za pomocą `-impersonate` + `-request` (wymiana na żywo z KDC):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` przyjmuje nazwę użytkownika lub SID; `-request` wymaga aktywnych poświadczeń użytkownika oraz materiału klucza krbtgt (AES/NTLM), aby odszyfrować i zmodyfikować bilety.

Kluczowe sygnały OPSEC przy użyciu tego wariantu:<sup>[[5]](#references)</sup>

- TGS-REQ będzie zawierać `ENC-TKT-IN-SKEY` i `additional-tickets` (TGT ofiary) — rzadko spotykane w normalnym ruchu.
- `sname` często jest taki sam jak użytkownik wysyłający żądanie (dostęp samoobsługowy), a Event ID 4769 pokazuje tego samego SPN/użytkownika jako wywołującego i cel.
- Spodziewaj się powiązanych wpisów 4768/4769 z tym samym komputerem klienckim, ale różnymi CNAMES (użytkownik wysyłający żądanie o niskich uprawnieniach vs. uprzywilejowany właściciel PAC).

### Uwagi dotyczące OPSEC i wykrywania

- Tradycyjne heurystyki wykorzystywane przez hunterów (TGS bez AS, okresy ważności liczone w dekadach) nadal mają zastosowanie do golden tickets, ale diamond tickets są wykrywane głównie wtedy, gdy **zawartość PAC lub mapowanie grup wydają się niemożliwe**. Wypełnij każde pole PAC (godziny logowania, ścieżki profilu użytkownika, identyfikatory urządzeń), aby automatyczne porównania nie wykryły od razu fałszerstwa.<sup>[[3]](#references)</sup>
- **Nie przypisuj zbyt wielu grup/RID**. Jeśli potrzebujesz tylko `512` (Domain Admins) i `519` (Enterprise Admins), poprzestań na nich i upewnij się, że konto docelowe wiarygodnie należy do tych grup także w innych miejscach AD. Nadmiarowe `ExtraSids` rzucają się w oczy.
- Podmiany w stylu Sapphire pozostawiają ślady U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` oraz `sname` wskazujące na użytkownika (często osobę wysyłającą żądanie) w 4769, a także następujące po nich logowanie 4624 pochodzące ze sfałszowanego biletu. Koreluj te pola, zamiast szukać wyłącznie luk w sekwencji bez AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft rozpoczął stopniowe wycofywanie **wystawiania biletów usługi RC4** z powodu CVE-2026-20833; wymuszanie wyłącznie etypów AES na KDC zarówno wzmacnia domenę, jak i zapewnia zgodność z narzędziami diamond/sapphire (`/opsec` już wymusza AES). Dodawanie RC4 do sfałszowanych PAC będzie coraz bardziej rzucać się w oczy.<sup>[[6]](#references)</sup>
- Projekt Splunk Security Content udostępnia telemetrię attack-range dla diamond tickets oraz detekcje, takie jak *Windows Domain Admin Impersonation Indicator*, które korelują nietypowe sekwencje zdarzeń 4768/4769/4624 i zmiany grup PAC. Odtworzenie tego zbioru danych (lub wygenerowanie własnego za pomocą powyższych poleceń) pomaga zweryfikować pokrycie SOC dla T1558.001, a jednocześnie dostarcza konkretnych reguł alertów, które można omijać.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Kamienie szlachetne: nowa generacja ataków Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: uwielbiamy bawić się biletami (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Ponowne cięcie biletu Kerberos Diamond (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Dane o ataku Diamond Ticket i detekcje (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Ciemna strona klejnotów: bilety Diamond i Sapphire (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Wymuszanie biletów usługi RC4 dla CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
