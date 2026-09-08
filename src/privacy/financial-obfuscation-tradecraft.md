# Taktyki obfuskacji finansowej

Prywatność płatności to problem atrybucji, a nie problem marki płatniczej. Operacja pozostawia dowody, gdy wartość jest pozyskiwana, przemieszczana, konwertowana, wydawana i dostarczana. Adres w publicznym blockchainie może być pseudonimowy, ale giełda, wystawca karty, sprzedawca, urządzenie mobilne lub kamera monitoringu przesyłek mogą zidentyfikować osobę, która się za nim kryje.

Ta strona wyjaśnia wzorce obfuskacji finansowej wykorzystywane w cyberprzestępczości i operacjach powiązanych z państwami, aby obrońcy mogli je rozpoznawać. **Nie** przedstawia procedury prania pieniędzy, obchodzenia sankcji, używania fałszywej tożsamości ani omijania KYC.

## Kompleksowy graf przepływu wartości
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Aktor próbuje uniemożliwić jakiemukolwiek obserwatorowi zobaczenie obu końców. Śledczy robią odwrotnie: zachowują rejestry na każdej granicy, normalizują czas/wartość/opłaty i identyfikują **punkt ponownej konwergencji**, w którym oddzielne persony ponownie korzystają z jednego pośrednika, urządzenia, konta, sprzedawcy lub miejsca docelowego.

## Instrumenty i ich rzeczywiści obserwatorzy

| Instrument | Ukryte przed sprzedawcą/publicznością | Nadal widoczne dla |
|---|---|---|
| Wirtualna karta/token wystawcy | podstawowy numer karty | wystawca, sieć/dostawca tokena, wallet, konto sprzedawcy i systemy dostawy |
| Wartość prepaid/gift | czasami dane prawne podczas zwykłego zakupu | sprzedawca/rail płatniczy, usługa aktywacji/realizacji, kamery, urządzenie i dostawa |
| Gotówka | publiczny rejestr i zdalny wystawca | kontrahenci, kamery, kontrole wypłat/numerów seryjnych, jeśli mają zastosowanie, przeszukanie fizyczne |
| Bitcoin/nowy adres | bezpośrednie dane prawne | każdy obserwator blockchaina; peery walleta/sieci; usługi nabycia i off-ramp |
| CoinJoin/PayJoin | proste heurystyki wspólnych wejść/płatności | publiczna transakcja, metadane koordynatora/peera/sieci oraz późniejsze zachowanie związane z wydawaniem |
| Privacy coin | publiczny nadawca/odbiorca/kwota, zależnie od protokołu | usługa nabycia/off-ramp, endpoint walleta, obserwator sieci i kontrahent |
| Scentralizowany mixer | bezpośrednie powiązanie wpłaty z wypłatą | operator/logi mixera, zbiory wejść/wyjść blockchaina i kontrahenci |
| Cross-chain bridge/swap | ciągłość na jednym łańcuchu | oba łańcuchy, usługa bridge/swap, ograniczenia czasowe/wartościowe i płynnościowe |
| Broker OTC/P2P | bezpośrednie konto giełdowe w niektórych przypadkach | broker, komunikacja, przepływ środków bankowych/gotówki, kontrahenci i urządzenia |

## Karty, wartość prepaid, nominaci i mule

### Karty wirtualne i maskowane

Wystawca może utworzyć numer karty przypisany do sprzedawcy lub jednorazowy. Ogranicza to ekspozycję wobec sprzedawcy i ponowne użycie numeru u wielu sprzedawców. Wystawca nadal mapuje go na klienta, konto finansujące, urządzenie, adres IP i transakcję. Deskryptory rozliczeniowe, konto sprzedawcy, adres wysyłki i dane przeglądarki pozostają możliwe do powiązania.

Marketing kart „bez nazwiska” nie oznacza anonimowego rozliczenia. Wystawcy i dystrybutorzy podlegający regulacjom mogą przeprowadzać kontrole tożsamości, przechowywać rejestry, nakładać ograniczenia geograficzne/kwotowe oraz odpowiadać na żądania prawne. Karta uzyskana przy użyciu skradzionej tożsamości oznacza dodatkowo kradzież tożsamości; nie usuwa telemetrii wystawcy/urządzenia/sprzedawcy.

### Wartość prepaid i gift

Karty prepaid i kody gift oddzielają późniejszą realizację od pierwotnego instrumentu płatniczego, ale tworzą ponumerowany obiekt z rejestrami zakupu, aktywacji, sprawdzania salda i realizacji. Znaczenie mają wzorce obejmujące zakupy hurtowe, powtarzające się nominały tuż poniżej limitów kontrolnych, szybką realizację w odległym miejscu, jedno urządzenie sprawdzające wiele sald lub wiele kart zbiegających się u jednego sprzedawcy/konta.

### Nominaci, money mule i podstawione firmy handlowe

Nominat lub mule dostarcza konto i tożsamość prawną, które znajdują się pomiędzy operatorem a usługą. Sieci mogą nakładać na siebie rekruterów, posiadaczy kont, procesorów płatności, firmy fasadowe i brokerów cash-out. Tworzy to dystans, ale każdy uczestnik dodaje komunikację, opłaty, niespójność behawioralną i potencjalnego świadka współpracującego z organami. Firmy fasadowe pozostawiają rejestry założenia, podatkowe, bankowe, dyrektorskie, fakturowe, hostingowe i wysyłkowe.

Obrońcy powinni badać współdzielone urządzenia/adresy IP, ponowne użycie beneficjentów, sprzeczności geolokalizacyjne, częstotliwość transakcji niespójną z historią konta, transfery okrężne, wielu niezależnych nadawców zbiegających się w jednym miejscu oraz natychmiastowy dalszy przepływ środków. Nie należy zakładać, że wskazany posiadacz konta jest aktorem sprawującym kontrolę; należy traktować go jako węzeł wymagający ustalenia roli.

## Wzorce obfuskacji transakcji w publicznym łańcuchu

### Rotacja adresów i kontrola monet

Tworzenie nowego adresu dla każdego wpływu zapobiega prostemu ponownemu użyciu adresu, ale transakcje nadal mogą zostać połączone przez wspólne wejścia, wykrywanie reszty, dokładną wartość/czas oraz późniejszą konsolidację. **Kontrola monet** pozwala walletowi wybrać, które outputy wydać, i unikać łączenia przedziałów. Poprawia higienę; nie może usunąć już publicznego powiązania.

### Łańcuchy peel

Łańcuch peel wielokrotnie wydaje duże saldo, wysyłając mniejszą kwotę na zewnątrz i zwracając resztę na nowy adres:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Adres zmienia się na każdym etapie, ale ciągłość wartości, częstotliwość i struktura transakcji często tworzą rozpoznawalny łańcuch. Legalne hot wallety giełd mogą działać podobnie, dlatego atrybucja wymaga dowodów dotyczących usługi/kontekstu. DOJ wykorzystywał analizę peel-chain w sprawach dotyczących przepadku mienia powiązanego z DPRK.<sup>[[1]](#references)</sup>

### Structuring and fan-out/fan-in

- **Fan-out:** jedno źródło rozdziela środki na wiele adresów, aby zwiększyć nakład pracy śledczej lub przygotować równoległą konwersję.
- **Fan-in:** wiele źródeł konsoliduje środki u jednego odbiorcy, ujawniając wspólną kontrolę lub usługę.
- **Structuring:** powtarzające się mniejsze transfery mają na celu uniknięcie progów kontroli lub wtopienie się w zwykły wolumen.
- **Commingling:** środki nielegalne i niezwiązane ze sprawą dzielą wallety, poole lub usługi, przez co uproszczone twierdzenia proporcjonalne są niebezpieczne.

Kształt grafu jest wskazówką, a nie dowodem. Analitycy powinni uwzględniać opłaty, model UTXO/account, zachowanie usługi oraz konwencje dotyczące reszty.

### CoinJoin and PayJoin

W typowym CoinJoin kilku uczestników wnosi inputy i otrzymuje outputy w ramach jednej wspólnej transakcji, często o jednakowych nominałach outputów. Podważa to założenie, że każdy input i output w transakcji ma jednego właściciela. Zbiór anonimowości jest ograniczony liczbą uczestników i późniejszym zachowaniem: nierówna reszta, toxic change, konsolidacja lub przejście przez znaną usługę mogą ponownie ujawnić powiązania.

PayJoin modyfikuje zwykłą płatność tak, aby zarówno płatnik, jak i odbiorca wnosili inputy, bezpośrednio unieważniając heurystykę wspólnego właściciela inputów dla tej transakcji. Jest przede wszystkim protokołem ochrony prywatności płatności, a nie usługą masowego prania pieniędzy. Wykrywanie powinno unikać uznawania wszystkich inputów za należące do jednego właściciela oraz wyrażać niepewność zamiast wymuszać fałszywy klaster.

### Centralized mixers and tumblers

Scentralizowany mixer przyjmuje depozyty, a później wypłaca inne monety ze wspólnej rezerwy, często po pobraniu opłat i z opóźnieniem. Jego prywatność zależy od wielkości puli, zasad wypłat, logów, uczciwości operatora oraz odporności na przejęcie. Analiza czasu i wartości wejść oraz wyjść, adresy depozytowe, klastrowanie walletów usługi i dokumentacja mogą zawęzić zbiór możliwości. Operatorzy mogą ukraść środki lub zachować pełne mapowanie.

Ryzyko prawne jest znaczne i zależy od jurysdykcji. Sprawy DOJ przeciwko ChipMixer, Samourai Wallet oraz twórcom/operatorom Tornado Cash, a także zmieniające się postępowania dotyczące sankcji pokazują, że znaczenie mają fakty dotyczące protokołu, powiernictwa, kontroli i przekazywania pieniędzy; określenie takie jak „zdecentralizowany” nie stanowi wniosku prawnego.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps and bridges

Chain hopping konwertuje aktywo lub przenosi je przez bridge, przerywając zapytanie obejmujące jedną księgę, ale nie ciągłość ekonomiczną:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Analitycy korelują kontrakty bridge/adresy depozytowe usług, kolejność transakcji, przedział czasowy, kurs wymiany, opłaty, płynność i unikalną kwotę. Powtarzające się swapy mogą zwiększać niejednoznaczność, jednocześnie dodając telemetrykę dostawcy/API/wallet. FATF wskazuje chain hopping, mixery, usługi peer-to-peer i waluty ze zwiększoną anonimowością jako wskaźniki ryzyka, gdy występują w podejrzanym kontekście.<sup>[[3]](#references)</sup>

### NFTs, hazard i zakupy u merchantów

Transakcje NFT zawierane z samym sobą lub w zmowie mogą nadawać środkom pozorną narrację sprzedaży; hazard może wymieniać depozyty na wypłaty; towary mogą przekształcać wartość cyfrową w zapasy możliwe do odsprzedaży. Ścieżki te pozostawiają konta marketplace, powiązania z twórcami/royalties, grafy wash trading, historię kursów/gry, logi urządzeń, dowody dostawy i odsprzedaży. Strata lub opłata nie stanowi dowodu, że pochodzenie środków zniknęło.

## Kryptowaluty chroniące prywatność

Protokoły privacy różnią się technicznie:

- **Monero** wykorzystuje jednorazowe adresy, ring signatures i poufne kwoty, ograniczając publiczną widoczność nadawcy/odbiorcy/kwoty. Obserwacja sieci, przejęcie walleta, dane dotyczące nabycia/off-ramp oraz dane kontrahentów pozostają poza ochroną zapewnianą on-chain.
- **Zcash shielded pools** mogą ukrywać nadawcę, odbiorcę i kwotę, gdy używane są shielded transactions; transparent addresses i przejścia między poolami pozostają publiczne, a wzorce użycia wpływają na faktyczny anonymity set.
- **Bitcoin** jest domyślnie transparentny. New addresses, CoinJoin, PayJoin i Lightning zmieniają określone założenia dotyczące linkowania, ale nie zapewniają prywatności wszystkim warstwom.

Technologia privacy ma uzasadnione zastosowania związane z bezpieczeństwem i działalnością komercyjną. Z perspektywy dochodzeniowej, gdy ledger dostarcza mniej informacji, większego znaczenia nabierają dowody dotyczące endpointów, usług, sieci i ludzi. Nigdy nie wnioskuj o przestępczości wyłącznie na podstawie wyboru protokołu chroniącego prywatność.

## Wielowarstwowy model sprawy DPRK

Publiczne zarzuty DOJ i działania forfeiture opisują złożony proces, a nie pojedynczą sztuczkę:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. pracownicy używali fikcyjnych/skradzionych materiałów tożsamości oraz VPN-ów, aby uzyskać zdalne zatrudnienie;
2. pracodawcy wypłacali cryptocurrency, w tym stablecoins;
3. środki były przenoszone w mniejszych kwotach, przechodziły między chainami lub tokenami, służyły do zakupu NFTs albo były mieszane z innymi środkami;
4. inne skradzione środki trafiały do mixerów;
5. traderzy OTC i front companies zamieniały wartość na płatności fiat lub towary;
6. powtarzający się facilitators, konta i ścieżki blockchain pozwalały śledczym ponownie połączyć warstwy.

Treasury stwierdziło, że Lazarus używał Blender.io do przetworzenia części środków ze steal’u Axie Infinity/Ronin, natomiast FBI opublikowało adresy i wezwało bridges, exchanges, operatorów RPC oraz firmy analityczne do blokowania środków powiązanych z późniejszymi kradzieżami TraderTraitor.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Wniosek działa w obu kierunkach: aktorzy państwowi korzystają ze zwykłych usług komercyjnych/przestępczych, a publiczne blockchains pozwalają obrońcom śledzić wartość, nawet gdy nazwiska są początkowo nieznane.

## Workflow wykrywania

1. **Zachowaj surowe identyfikatory transakcji i rekordy.** Screenshots i zaokrąglone wartości fiat są niewystarczające.
2. **Normalizuj aktywa i czas.** Zapisuj chain, kontrakt tokena, jednostki, czas bloku, strefę czasową usługi, opłaty i źródło kursu wymiany.
3. **Oznaczaj poziom pewności dowodów.** Rozróżniaj adres opublikowany przez usługę, deterministyczne zdarzenie kontraktu, heurystykę klastrowania i zewnętrzne intelligence.
4. **Śledź oba kierunki.** Znajdź źródło finansowania, natychmiastowe rozproszenie, ponowną konwergencję, wyjścia z bridge, depozyty w usługach oraz wydatki/dostawy.
5. **Połącz dowody off-chain.** KYC konta, dane urządzenia, IP, zgłoszenia do supportu, klucze API, dane bankowe/płatnicze, wysyłkowe i komunikacyjne często usuwają niejednoznaczność.
6. **Testuj alternatywne wyjaśnienia.** Exchanges, custodians, payroll i protokoły privacy mogą generować fan-in/out lub co-spends bez wspólnej własności beneficjenta.
7. **Monitoruj zamiast przedwcześnie zamykać sprawę.** Uśpiony output może stać się możliwy do przypisania, gdy później trafi do usługi.
8. **Stosuj aktualne obowiązki sankcyjne/AML w porozumieniu z prawnikiem.** Zasady i designations ulegają zmianom; historyczne powiązanie nie zastępuje aktualnej analizy prawnej.

## Bezpieczny model procurement dla red teamu

Autoryzowany zespół może potrzebować, aby docelowy SOC nie rozpoznał płatności za hosting, podczas gdy kontroler engagementu zachowuje odpowiedzialność:

- używaj karty organizacji przeznaczonej dla danego engagementu lub udokumentowanego corporate wallet;
- utrzymuj prawidłowe dane billingowe, podatkowe i dane dostawcy;
- oddziel operatora od obowiązków procurement i ogranicz dostęp do mapy atrybucji;
- nigdy nie używaj mula, fałszywej tożsamości, skradzionej karty, obejścia sankcji ani nielicencjonowanego exchangera;
- rejestruj aktywo, kwotę, właściciela, usługę, datę, ścieżkę refundacji i dowody teardown;
- po ćwiczeniu ujawnij kontrolerowi istotne wskaźniki płatności/dostawcy.

Tworzy to **ślepotę na uczestnika ćwiczenia**, a nie ślepotę na prawo, dostawcę lub governance.

## References

- [1] [US DOJ — Framework egzekwowania przepisów dotyczących Cryptocurrency (przykład peel-chain i dochodzenia DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Likwidacja ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Wskaźniki ostrzegawcze dotyczące Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Przedstawiciel North Korean Foreign Trade Bank oskarżony o spiski związane z praniem środków w crypto](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Skarga o forfeiture dotycząca 7,74 mln USD rzekomo wypranych na rzecz DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sankcje wobec Blender.io i środki Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — North Korea odpowiada za kradzież z Bybit w 2025 roku](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Zastosowanie przepisów do użytkowników, administratorów i exchangerów virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
