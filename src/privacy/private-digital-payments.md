# Prywatne płatności cyfrowe

{{#include ../banners/hacktricks-training.md}}

Prywatność płatności to kontrolowane ujawnianie danych transakcji. Nie jest to sposób na nadanie nielegalnym środkom pozorów legalności, uchylanie się od podatków lub sankcji, obchodzenie KYC, używanie fałszywych tożsamości ani ukrywanie nieautoryzowanego zaangażowania. Płatność może być prywatna z perspektywy sprzedawcy, pozostając w pełni widoczna dla wystawcy, sieci, pracodawcy, organu podatkowego lub śledczego.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) to ustandaryzowany katalog zawierający `Pros`, `Cons`, zgodną z prawem `Procedure` krok po kroku oraz `Detection` dla każdej rodziny technik. Ta strona rozwija temat konwencjonalnych metod płatności.

{% hint style="danger" %}
Nigdy nie używaj skradzionych kont, syntetycznych tożsamości, money mules, fikcyjnego miejsca zamieszkania ani fałszywych oświadczeń dotyczących źródła środków, nie dziel transakcji („structuring”) i nie korzystaj z nieprzejrzystych pośredników oferujących „no-KYC card”. Sprawdź aktualne przepisy i warunki dostawcy w każdej właściwej jurysdykcji.
{% endhint %}

## Zdefiniuj właściwość prywatności

Określ obserwatora przed wyborem rail:

| Obserwator | Typowe dane | Przydatna kontrola | Co pozostaje |
|---|---|---|---|
| Sprzedawca | Imię i nazwisko, e-mail, adres, token karty, IP/urządzenie, koszyk | Zakupy jako gość, minimum opcjonalnych danych, merchant-specific virtual card | Dostawa, dane konta i telemetria dotycząca fraud |
| Wystawca/payment processor | Tożsamość prawna, źródło finansowania, sprzedawca, kwota, czas, urządzenie | Wybór regulowanego dostawcy z dobrymi warunkami prywatności/bezpieczeństwa | Dostawca nadal przetwarza dane i może przechowywać/ujawniać dokumentację |
| Pracodawca/właściciel zaangażowania | Wydatek, operator i cel | Oddzielny budżet zaangażowania i ledger z kontrolą dostępu | Prawidłowe zarządzanie wymaga wewnętrznego przypisania |
| Publiczny obserwator blockchain | Adresy, przepływy, kwoty i czas, zależnie od chaina | Odpowiedni protokół i dyscyplina korzystania z walleta | Nabycie, punkty końcowe i późniejsze wydatki mogą ponownie powiązać aktywność |
| Operator sieci/RPC/node | IP, zapytania walleta, rozgłaszanie transakcji | Local node lub odpowiednia sieć prywatności | Czas i zachowanie punktu końcowego nadal mogą umożliwiać korelację |
| Obserwator fizyczny | Twarz, lokalizacja, pojazd, CCTV, paragon | Zwykła prywatność sytuacyjna | Gotówka nie czyni osoby fizycznie niewidoczną |

CFPB opisuje aplikacje płatnicze jako zdolne do gromadzenia danych dotyczących tożsamości, urządzenia, lokalizacji, kontaktów, transakcji i zachowania; stanowe przepisy dotyczące prywatności nie muszą zapobiegać monetyzacji ani każdemu wtórnemu wykorzystaniu danych.<sup>[[1]](#references)</sup> Zapoznaj się z rzeczywistą polityką dostawcy, zamiast wnioskować o prywatności na podstawie nazwy produktu.

## Porównaj metody płatności

| Metoda | Korzyść prywatności | Główni obserwatorzy/powiązania | Odpowiednie zastosowanie |
|---|---|---|---|
| Gotówka | Brak rejestru sieci płatniczej | Odbiorca, kamery, świadkowie, zasady raportowania gotówki | Zgodne z prawem lokalne zakupy, jeśli są akceptowane |
| Open-loop prepaid/gift card | Oddziela numer karty od głównej karty | Sprzedawca, dostawca aktywacji/rejestracji, źródło finansowania, merchant | Budżetowanie lub ograniczona compartmentalization wobec merchantów |
| Virtual/one-time card number | Ukrywa wielokrotnego użytku PAN przed merchantem; umożliwia łatwe unieważnienie | Wystawca nadal zna tożsamość i transakcję | compartmentalization wobec merchantów online |
| Mobile-wallet token | Urządzenie/merchant otrzymuje token zamiast bazowego PAN | Dostawca walleta, wystawca, payment network i merchant | Bezpieczeństwo credentiala, nie anonimowość |
| Bank transfer/app | Wygodny audit trail | Bank/aplikacja, kontrahent i powiązana tożsamość | Rozliczalne płatności organizacyjne |
| Cryptocurrency | Zależy od protokołu; self-custody może ograniczyć ujawnienie danych custodianowi | Public ledger lub privacy protocol, exchange, punkt końcowy, kontrahent | Zgodne z prawem transfery po analizie właściwej dla protokołu |

## Gotówka

Gotówka nadal jest postrzegana jako ważna dla prywatności i inkluzji oraz pozwala uniknąć rejestru sieci płatniczej.<sup>[[2]](#references)</sup> Nie eliminuje CCTV, świadków, lokalizacji urządzenia, paragonów, śledzenia numerów seryjnych w szczególnych przypadkach ani obowiązków prawnych dotyczących raportowania.

### Zgodna z prawem procedura

1. Przed transakcją sprawdź akceptację gotówki i lokalne limity. Limity różnią się zależnie od kraju i rodzaju strony oraz zmieniają się w czasie.
2. Dokonaj zwykłego zakupu w jednej uczciwej transakcji. **Nigdy nie dziel jej**, aby uniknąć progu lub raportowania.
3. Odrzuć opcjonalne śledzenie lojalnościowe lub gromadzenie danych marketingowych. Podaj prawdziwe dane wymagane do gwarancji, bezpieczeństwa, dostawy, celów podatkowych lub prawnych.
4. Przechowuj niezbędny dowód zakupu i wymagane dokumenty księgowe w zaszyfrowanym miejscu, z określoną datą retencji.
5. W organizacji korzystaj z zatwierdzonej procedury zwrotu kosztów i rejestruj operatora, autoryzację, cel, kwotę, datę i paragon.

W Stanach Zjednoczonych niektóre podmioty gospodarcze składają Form 8300 w przypadku otrzymania ponad 10 000 USD w gotówce, w tym w przypadku transakcji powiązanych; celowe rozbijanie transakcji może samo w sobie stanowić niezgodne z prawem structuring.<sup>[[3]](#references)</sup> Inne jurysdykcje mają odmienne zasady — na przykład Hiszpania publikuje własne ustawowe ograniczenia dotyczące płatności gotówkowych.<sup>[[4]](#references)</sup>

## Karty prepaid i gift card

„Prepaid” nie oznacza anonimowości. Sklep, wystawca, program manager, bank finansujący i merchant mogą korelować zakup, aktywację, urządzenie, IP, lokalizację i wydatki. Doładowania, dostęp do ATM, użycie międzynarodowe, wyższe limity lub ochrona w przypadku utraty zwykle wymagają rejestracji.

Amerykańskie wytyczne dla konsumentów wyjaśniają, że wystawcy mogą żądać danych tożsamości w celu weryfikacji wymaganej prawem i mogą odrzucić zarejestrowaną kartę, gdy weryfikacja się nie powiedzie.<sup>[[5]](#references)</sup> Zasady FinCEN określają, które programy prepaid i ich uczestnicy mają obowiązki AML.<sup>[[6]](#references)</sup> W UE wąskie wyjątki dotyczące anonimowego e-money zostały ograniczone przez Directive (EU) 2018/843; Regulation (EU) 2024/1624 ponownie zmienia te ramy, ale zasadniczo ma zastosowanie od **10 July 2027**, dlatego nie opisuj go jako już obowiązującego w 2026 roku.<sup>[[7]](#references)</sup>

Korzystaj z wartości prepaid wyłącznie wtedy, gdy została zgodnie z prawem uzyskana od identyfikowalnego wystawcy, jego warunki zezwalają na zamierzone użycie, a korzyścią jest budżetowanie lub oddzielenie od podstawowego credentiala płatniczego. Unikaj rynków odsprzedaży i brokerów reklamujących nieweryfikowalne karty „no-name”: środki mogą być skradzione, już wykorzystane, ograniczone geograficznie lub podlegać zajęciu.

## Virtual cards i wallet tokens

Virtual card number (VCN) jest zwykle wydawany w ramach rzeczywistego, zweryfikowanego konta. Numery przypisane do konkretnego merchantа lub jednorazowe ograniczają skutki breach i korelację PAN między merchantami; **nie** ukrywają transakcji przed wystawcą. Network tokenization podobnie zastępuje credential karty ograniczonym tokenem.<sup>[[8]](#references)</sup>

### Procedura z compartmentalization wobec merchantа

1. Otwórz konto u regulowanego wystawcy, używając prawdziwych danych dotyczących tożsamości, miejsca zamieszkania i finansowania.
2. Zabezpiecz je unikalnym hasłem, odpornym na phishing MFA, jeśli jest dostępne, alertami logowania oraz kodami odzyskiwania przechowywanymi offline.
3. Wygeneruj merchant-locked lub jednorazowy VCN. Ustaw rozsądny limit kwoty/czasu, jeśli jest obsługiwany.
4. Skorzystaj z zakupów jako gość i pomiń wyłącznie **opcjonalne** pola profilu, lojalnościowe i marketingowe. Podaj prawdziwe dane rozliczeniowe, dostawy i podatkowe, gdy są wymagane.
5. Unikaj logowania do niezwiązanych identity providers; używaj przeglądarkowego compartmentu dla zaangażowania/konta oraz zatwierdzonej ścieżki sieciowej.
6. Zapisz paragon i mapowanie VCN-do-celu w zaszyfrowanym wewnętrznym ledgerze.
7. Zamroź lub unieważnij numer po zakończeniu okresu refund/chargeback; monitoruj konto nadrzędne pod kątem nieoczekiwanych autoryzacji.

Capital One i Google dokumentują, że virtual numbers pozostają powiązane z bazowym kontem, natomiast EMVCo/Visa opisują tokenization jako substytucję credentiala i ograniczenie domeny, a nie anonimowość płatnika.<sup>[[8]](#references)</sup>

## Dostawa, konta i refundy

Płatność jest tylko jednym połączeniem w grafie powiązań:

- Unikalna karta traci swoją wartość, gdy ponownie użyjesz prywatnego e-maila, numeru telefonu, profilu przeglądarki, adresu IP lub konta lojalnościowego.
- Dostawa fizyczna zwykle wymaga zgodnego z prawem odbiorcy i lokalizacji. Nie używaj adresu osoby niezwiązanej ze sprawą ani nie podszywaj się pod mieszkańca. Zatwierdzone firmowe usługi receiving są bezpieczniejsze niż zmyślone dane.
- Produkty cyfrowe mogą rejestrować tożsamość konta, IP, fingerprint urządzenia, aktywację licencji i pobrania.
- Refundy zwykle wracają tą samą drogą. Prośby o otrzymanie środków i przekazanie/refund ich w inne miejsce są ostrzeżeniem przed fraud i money mule.
- Opisy merchantów, treść faktur i powiadomienia o wysyłce mogą ujawnić wrażliwy zakup delegatom konta; celowo skonfiguruj dostęp i alerty.

## Autoryzowane zakupy red-team

Zaangażowanie powinno być dyskretne zewnętrznie i rozliczalne wewnętrznie:

1. Uzyskaj pisemny zakres, cel, limit wydatków, osobę zatwierdzającą, dozwolonych merchantów/assetów oraz zasadę zwrotu kosztów.
2. Używaj kontrolowanego przez organizację konta płatniczego oraz oddzielnego VCN lub subkonta dla każdego zaangażowania lub merchanta.
3. Zachowuj prawdziwe dane rozliczeniowe i rejestracyjne u dostawców. Prywatność rejestracji publicznej może ograniczyć ujawnienie danych, ale nie jest pozwoleniem na kłamstwo.
4. Prowadź zaszyfrowany ledger operatora, zatwierdzenia, celu, daty, kwoty, kontrahenta, identyfikatora assetu i paragonu.
5. Weryfikuj kontrahentów zgodnie z wymaganiami oraz przestrzegaj obowiązków dostawcy, sankcji, podatków i raportowania.
6. Przyznawaj działowi finansowemu tylko wymagany dostęp, a operatorom wyłącznie potrzebne, ograniczone uprawnienia do wydatków.
7. Podczas teardown zamknij lub zamroź credentiale płatnicze, uzgodnij oczekujące obciążenia/refundy i przechowuj dokumentację zgodnie z polityką.

W przypadku wyborów dotyczących crypto przejdź do [Cryptocurrency Privacy](cryptocurrency-privacy.md). Informacje o infrastrukturze obsługującej te zakupy znajdziesz w [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Lista kontrolna weryfikacji

- [ ] Pożądana właściwość prywatności i obserwatorzy są zapisani.
- [ ] Niedawno sprawdzono zasady dostawcy, merchanta i jurysdykcji.
- [ ] Oświadczenia dotyczące tożsamości i źródła środków są prawdziwe.
- [ ] Opcjonalne dane merchanta są ograniczone bez obchodzenia wymaganej weryfikacji.
- [ ] Powiązania dotyczące finansowania, urządzenia, sieci, konta, dostawy i refundu są zrozumiałe.
- [ ] Nie występuje unikanie progów, zabroniony kontrahent, mule, skradziony credential ani tożsamość osoby trzeciej.
- [ ] Wymagane paragony, zatwierdzenia, dokumentacja podatkowa i informacje odzyskiwania są zaszyfrowane oraz objęte kontrolą dostępu.

## References

- [1] [US CFPB — Wniosek o informacje dotyczące gromadzenia, wykorzystywania i monetyzacji danych konsumentów dotyczących płatności i innych osobistych danych finansowych](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Badanie postaw konsumentów wobec płatności w strefie euro (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Instrukcje dotyczące Form 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Raportowanie płatności gotówkowych](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Dlaczego prosi się mnie o dane osobowe w celu aktywacji lub rejestracji karty prepaid?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) oraz [Czy można odmówić mi wydania karty prepaid?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Ostateczna zasada dotycząca Prepaid Access](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Korzystanie z virtual credit cards](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
