# Prywatne płatności cyfrowe

Prywatność płatności oznacza kontrolowane ujawnianie danych transakcji. Nie jest sposobem na legalizowanie nielegalnych środków, unikanie podatków lub sankcji, obchodzenie KYC, używanie fałszywych tożsamości ani ukrywanie nieautoryzowanego zaangażowania. Płatność może być prywatna względem sprzedawcy, pozostając w pełni widoczna dla wystawcy, sieci, pracodawcy, organu podatkowego lub śledczego.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) to ujednolicony katalog zawierający `Pros`, `Cons`, zgodną z prawem `Procedure` krok po kroku oraz `Detection` dla każdej rodziny technik. Ta strona rozwija temat konwencjonalnych metod płatności.

{% hint style="danger" %}
Nigdy nie używaj skradzionych kont, syntetycznych tożsamości, money mules, fikcyjnego miejsca zamieszkania ani oświadczeń dotyczących źródła środków, transakcyjnego dzielenia płatności („structuring”) lub nieprzejrzystych pośredników oferujących „no-KYC card”. Sprawdź aktualne przepisy i warunki usługodawcy w każdej właściwej jurysdykcji.
{% endhint %}

## Zdefiniuj właściwość prywatności

Określ obserwatora przed wyborem metody płatności:

| Obserwator | Typowe dane | Przydatna kontrola | Co pozostaje |
|---|---|---|---|
| Sprzedawca | Imię i nazwisko, e-mail, adres, token karty, IP/urządzenie, koszyk | Zakupy bez logowania, minimum opcjonalnych danych, karta wirtualna przypisana do konkretnego sprzedawcy | Dostawa, dane konta i telemetryka dotycząca fraud |
| Wystawca/operator płatności | Tożsamość prawna, źródło finansowania, sprzedawca, kwota, czas, urządzenie | Wybór regulowanego dostawcy z dobrymi warunkami prywatności/bezpieczeństwa | Dostawca nadal przetwarza dane i może przechowywać/ujawniać rejestry |
| Pracodawca/właściciel engagementu | Wydatek, operator i cel | Oddzielny budżet engagementu i ledger z kontrolą dostępu | Prawidłowe zarządzanie wymaga wewnętrznego przypisania |
| Publiczny obserwator blockchaina | Adresy, przepływy, kwoty i czas, zależnie od chaina | Odpowiedni protokół i właściwa dyscyplina korzystania z walleta | Nabycie, punkty końcowe i późniejsze wydatki mogą ponownie powiązać aktywność |
| Operator sieci/RPC/node'a | IP, zapytania walleta, rozgłaszane transakcje | Local node lub odpowiednia privacy network | Czas i zachowanie punktów końcowych nadal mogą być skorelowane |
| Obserwator fizyczny | Twarz, lokalizacja, pojazd, CCTV, paragon | Zwykła prywatność sytuacyjna | Gotówka nie sprawia, że osoba staje się fizycznie niewidoczna |

CFPB opisuje aplikacje płatnicze jako zdolne do gromadzenia danych dotyczących tożsamości, urządzenia, lokalizacji, kontaktów, transakcji i zachowania; stanowe przepisy dotyczące prywatności niekoniecznie zapobiegają monetyzacji ani każdemu wtórnemu wykorzystaniu danych.<sup>[[1]](#references)</sup> Przeczytaj rzeczywistą politykę dostawcy zamiast wyciągać wnioski o prywatności z nazwy produktu.

## Porównaj metody płatności

| Metoda | Korzyść dla prywatności | Główni obserwatorzy/powiązania | Odpowiednie zastosowanie |
|---|---|---|---|
| Gotówka | Brak rejestru sieci płatniczej | Odbiorca, kamery, świadkowie, przepisy dotyczące raportowania gotówki | Zgodne z prawem lokalne zakupy tam, gdzie gotówka jest akceptowana |
| Open-loop prepaid/gift card | Oddziela numer karty od głównej karty | Sprzedawca, dostawca aktywacji/rejestracji, źródło finansowania, merchant | Budżetowanie lub ograniczona separacja względem merchantów |
| Wirtualny/jednorazowy numer karty | Ukrywa wielokrotnego użytku PAN przed merchantem; łatwe unieważnienie | Wystawca nadal zna tożsamość i transakcję | Separacja względem merchantów online |
| Token mobile-wallet | Urządzenie/merchant otrzymuje token zamiast bazowego PAN | Dostawca walleta, wystawca, sieć płatnicza i merchant | Bezpieczeństwo danych uwierzytelniających, nie anonimowość |
| Przelew bankowy/aplikacja | Wygodny ślad audytowy | Bank/aplikacja, kontrahent i powiązana tożsamość | Odpowiedzialne płatności organizacyjne |
| Kryptowaluta | Zależnie od protokołu; self-custody może ograniczyć ekspozycję wobec custodianów | Publiczny ledger lub privacy protocol, exchange, punkt końcowy, kontrahent | Zgodne z prawem transfery po analizie właściwej dla danego protokołu |

## Gotówka

Gotówka jest nadal postrzegana jako istotna dla prywatności i inkluzji oraz pozwala uniknąć rejestru sieci płatniczej.<sup>[[2]](#references)</sup> Nie eliminuje CCTV, świadków, lokalizacji urządzenia, paragonów, śledzenia numerów seryjnych w szczególnych przypadkach ani obowiązków prawnych dotyczących raportowania.

### Zgodna z prawem procedura

1. Przed transakcją sprawdź, czy gotówka jest akceptowana, oraz lokalne limity płatności gotówkowych. Limity różnią się zależnie od kraju i rodzaju strony oraz zmieniają się z czasem.
2. Dokonaj zwykłego zakupu w ramach jednej uczciwej transakcji. **Nigdy jej nie dziel**, aby uniknąć progu lub raportowania.
3. Odrzuć opcjonalne śledzenie programu lojalnościowego lub gromadzenie danych marketingowych. Podaj prawdziwe dane wymagane w związku z gwarancją, bezpieczeństwem, dostawą, podatkami lub przepisami prawa.
4. Przechowuj niezbędny dowód zakupu i wymagane rejestry księgowe w zaszyfrowanym storage z datą retencji.
5. W organizacji korzystaj z zatwierdzonego procesu zwrotu kosztów i rejestruj operatora, autoryzację, cel, kwotę, datę oraz paragon.

W Stanach Zjednoczonych niektóre firmy i przedsiębiorstwa składają formularz 8300 w przypadku otrzymania ponad 10 000 USD w gotówce, w tym w ramach powiązanych transakcji; celowe rozdzielanie transakcji może samo w sobie stanowić niezgodne z prawem structuring.<sup>[[3]](#references)</sup> Inne jurysdykcje mają odmienne przepisy — na przykład Hiszpania publikuje własne ustawowe ograniczenia dotyczące płatności gotówkowych.<sup>[[4]](#references)</sup>

## Karty prepaid i gift cards

„Prepaid” nie oznacza anonimowości. Sklep, wystawca, operator programu, bank finansujący i merchant mogą korelować zakup, aktywację, urządzenie, IP, lokalizację i wydatki. Doładowania, dostęp do ATM, użycie międzynarodowe, wyższe limity lub ochrona w przypadku utraty zwykle wymagają rejestracji.

Amerykańskie wytyczne dla konsumentów wyjaśniają, że wystawcy mogą żądać danych tożsamości w celu weryfikacji prawnej i mogą odmówić zarejestrowanej karty, gdy weryfikacja zakończy się niepowodzeniem.<sup>[[5]](#references)</sup> Przepisy FinCEN określają, które programy prepaid i ich uczestnicy mają obowiązki AML.<sup>[[6]](#references)</sup> W UE wąskie wyjątki dotyczące anonimowego pieniądza elektronicznego zostały ograniczone przez dyrektywę (UE) 2018/843; rozporządzenie (UE) 2024/1624 ponownie zmienia te ramy, ale zasadniczo będzie stosowane od **10 lipca 2027 r.**, dlatego nie opisuj go jako już obowiązującego w 2026 r.<sup>[[7]](#references)</sup>

Korzystaj z wartości prepaid wyłącznie wtedy, gdy została legalnie uzyskana od identyfikowalnego wystawcy, jego warunki zezwalają na zamierzone użycie, a korzyścią jest budżetowanie lub oddzielenie od podstawowych danych uwierzytelniających płatności. Unikaj rynków odsprzedaży i brokerów reklamujących nieweryfikowalne karty „no-name”: wartość może być skradziona, już wykorzystana, ograniczona geograficznie lub podlegać zajęciu.

## Karty wirtualne i tokeny walletów

Wirtualny numer karty (VCN) jest zwykle wydawany w ramach rzeczywistego, zweryfikowanego konta. Numery przypisane do konkretnego merchanta lub jednorazowe ograniczają ryzyko breach i korelację PAN między merchantami; **nie** ukrywają transakcji przed wystawcą. Tokenizacja sieciowa podobnie zastępuje dane uwierzytelniające karty ograniczonym tokenem.<sup>[[8]](#references)</sup>

### Procedura separacji względem merchanta

1. Otwórz konto u regulowanego wystawcy, używając prawidłowych danych tożsamości, miejsca zamieszkania i finansowania.
2. Zabezpiecz je unikalnym hasłem, odpornym na phishing MFA, jeśli jest dostępne, alertami logowania oraz kodami odzyskiwania przechowywanymi offline.
3. Wygeneruj VCN przypisany do merchanta lub jednorazowy. Ustaw rozsądny limit kwoty/czasu, jeśli funkcja jest obsługiwana.
4. Skorzystaj z zakupów bez logowania i pomiń wyłącznie **opcjonalne** pola profilu, programu lojalnościowego i marketingowe. Podaj prawidłowe dane rozliczeniowe, dostawy i podatkowe, gdy są wymagane.
5. Unikaj logowania do niezwiązanych identity providerów; używaj browser compartment dla danego engagementu/konta oraz zatwierdzonej ścieżki sieciowej.
6. Zapisz paragon oraz powiązanie VCN z celem w zaszyfrowanym wewnętrznym ledgerze.
7. Zablokuj lub unieważnij numer po upływie okresu zwrotu/chargebacku; monitoruj konto nadrzędne pod kątem nieoczekiwanych autoryzacji.

Capital One i Google dokumentują, że numery wirtualne pozostają powiązane z bazowym kontem, natomiast EMVCo/Visa opisują tokenizację jako zastąpienie danych uwierzytelniających i ograniczenie domeny, a nie anonimowość płatnika.<sup>[[8]](#references)</sup>

## Dostawa, konta i zwroty

Płatność jest tylko jednym z ogniw w grafie powiązań:

- Unikalna karta traci swoją wartość, jeśli ponownie użyjesz prywatnego e-maila, numeru telefonu, profilu browsera, adresu IP lub konta lojalnościowego.
- Dostawa fizyczna zwykle wymaga prawidłowego odbiorcy i lokalizacji. Nie używaj adresu osoby niezwiązanej ze sprawą ani nie podszywaj się pod mieszkańca. Zatwierdzone firmowe usługi odbioru są bezpieczniejsze niż zmyślone dane.
- Produkty cyfrowe mogą rejestrować tożsamość konta, IP, fingerprint urządzenia, aktywację licencji i pobrania.
- Zwroty zwykle trafiają do pierwotnej metody płatności. Prośby o otrzymanie środków i przekazanie ich lub zwrócenie inną drogą są sygnałem fraud i money mule.
- Opisy transakcji u merchantów, treść faktur i powiadomienia o wysyłce mogą ujawnić wrażliwy zakup delegatom konta; celowo ustaw dostęp i alerty.

## Autoryzowane zakupy red-team

Engagement powinien być dyskretny zewnętrznie i rozliczalny wewnętrznie:

1. Uzyskaj pisemny zakres, cel, limit wydatków, zatwierdzającego, dozwolonych merchantów/zasobów oraz zasadę zwrotu kosztów.
2. Używaj kontrolowanego przez organizację konta płatniczego oraz oddzielnego VCN lub subkonta dla każdego engagementu albo merchanta.
3. Zachowuj prawidłowe dane rozliczeniowe i dane rejestracyjne u dostawców. Prywatność rejestracji publicznej może ograniczać ekspozycję, ale nie jest zgodą na kłamstwo.
4. Prowadź zaszyfrowany ledger operatora, zatwierdzenia, celu, daty, kwoty, kontrahenta, identyfikatora zasobu i paragonu.
5. Weryfikuj kontrahentów zgodnie z wymaganiami i przestrzegaj obowiązków dostawcy, sankcji, podatków oraz raportowania.
6. Udostępniaj finansom wyłącznie wymagany dostęp; operatorom przyznawaj tylko potrzebne, ograniczone możliwości wydawania środków.
7. Podczas teardown zamknij lub zablokuj dane uwierzytelniające płatności, uzgodnij oczekujące obciążenia/zwroty i przechowuj rejestry zgodnie z polityką.

W przypadku wyborów specyficznych dla crypto przejdź do [Cryptocurrency Privacy](cryptocurrency-privacy.md). Informacje o infrastrukturze obsługiwanej przez te zakupy znajdziesz w [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Lista kontrolna weryfikacji

- [ ] Pożądana właściwość prywatności i obserwatorzy zostały zapisani.
- [ ] Niedawno sprawdzono zasady dostawcy, merchanta i jurysdykcji.
- [ ] Oświadczenia dotyczące tożsamości i źródła środków są prawdziwe.
- [ ] Opcjonalne dane merchanta są ograniczone bez obchodzenia wymaganej weryfikacji.
- [ ] Powiązania finansowania, urządzenia, sieci, konta, dostawy i zwrotu są zrozumiałe.
- [ ] Nie występuje unikanie progów, zakazany kontrahent, mule, skradzione dane uwierzytelniające ani tożsamość osoby trzeciej.
- [ ] Wymagane paragony, zatwierdzenia, rejestry podatkowe i informacje odzyskiwania są zaszyfrowane i objęte kontrolą dostępu.

## References

- [1] [US CFPB — Wniosek o informacje dotyczące gromadzenia, wykorzystywania i monetyzacji danych konsumentów dotyczących płatności oraz innych osobistych danych finansowych](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [Europejski Bank Centralny — Badanie postaw konsumentów wobec płatności w strefie euro (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Instrukcje dotyczące formularza 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Hiszpańska Agencja Podatkowa — Raportowanie płatności gotówkowych](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Dlaczego prosi się mnie o dane osobowe w celu aktywacji lub rejestracji karty prepaid?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) oraz [Czy można odmówić mi wydania karty prepaid?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Ostateczna reguła dotycząca Prepaid Access](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Dyrektywa (UE) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Korzystanie z wirtualnych kart kredytowych](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
