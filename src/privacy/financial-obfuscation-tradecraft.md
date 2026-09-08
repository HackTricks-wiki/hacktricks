# Taktyki zaciemniania śladów finansowych

{{#include ../banners/hacktricks-training.md}}

Prywatność płatności to problem atrybucji, a nie problem marki płatniczej. Operacja pozostawia dowody, gdy wartość jest pozyskiwana, przenoszona, konwertowana, wydawana i dostarczana. Adres w publicznym łańcuchu może być pseudonimowy, ale giełda, wydawca karty, sprzedawca, urządzenie mobilne lub kamera monitoringu wysyłki mogą ujawnić osobę, która się za nim kryje.

Ta strona wyjaśnia wzorce zaciemniania śladów finansowych stosowane w cyberprzestępczości i operacjach powiązanych z państwami, aby obrońcy mogli je rozpoznawać. Nie zawiera procedury prania pieniędzy, obchodzenia sankcji, posługiwania się fałszywą tożsamością ani omijania KYC.

## Kompleksowy graf przepływu wartości
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Aktor próbuje uniemożliwić obserwatorowi zobaczenie obu końców. Śledczy robią odwrotnie: zachowują rekordy na każdej granicy, normalizują czas/wartość/opłaty i identyfikują **punkt ponownej konwergencji**, w którym odrębne persony ponownie korzystają z tego samego pośrednika, urządzenia, konta, merchanta lub miejsca docelowego.

## Instrumenty i ich rzeczywiści obserwatorzy

| Instrument | Ukryte przed merchantem/publicznością | Nadal widoczne dla |
|---|---|---|
| Wirtualna karta/token wydawcy | właściwy numer karty | wydawca, sieć/dostawca tokena, wallet, konto merchanta i systemy dostawy |
| Wartość prepaid/gift | czasami legalne nazwisko przy zwykłym zakupie | retailer/rail płatniczy, usługa aktywacji/realizacji, kamery, urządzenie i dostawa |
| Gotówka | publiczny rejestr i zdalny wydawca | kontrahenci, kamery, kontrola wypłat/numerów seryjnych, jeśli ma zastosowanie, przeszukanie fizyczne |
| Bitcoin/nowy adres | bezpośrednie legalne nazwisko | każdy obserwator blockchaina; peery walleta/sieci; usługi nabycia/off-ramp |
| CoinJoin/PayJoin | proste heurystyki wspólnych wejść/płatności | publiczna transakcja, metadane koordynatora/peera/sieci oraz późniejsze zachowanie związane z wydawaniem |
| Privacy coin | publiczny nadawca/odbiorca/kwota, zależnie od protokołu | nabycie/off-ramp, endpoint walleta, obserwator sieci i kontrahent |
| Scentralizowany mixer | bezpośrednie powiązanie wpłaty z wypłatą | operator/logi mixera, zbiory wejść/wyjść blockchaina i kontrahenci |
| Cross-chain bridge/swap | ciągłość na jednym chainie | oba chainy, usługa bridge/swap, ograniczenia czasowe/wartościowe i płynnościowe |
| Broker OTC/P2P | bezpośrednie konto giełdowe w niektórych przypadkach | broker, komunikacja, przepływ środków bankowych/gotówki, kontrahenci i urządzenia |

## Karty, wartość prepaid, nominowani i mule

### Wirtualne i maskowane karty

Wydawca może utworzyć numer karty przypisany do konkretnego merchanta lub jednorazowy. Ogranicza to ekspozycję wobec merchanta i ponowne użycie numeru u różnych merchantów. Wydawca nadal mapuje go na klienta, konto finansujące, urządzenie, IP i transakcję. Opisy rozliczeń, konto merchanta, adres wysyłki i dane przeglądarki pozostają możliwe do powiązania.

Marketing kart „bez nazwiska” nie oznacza anonimowego rozliczenia. Regulowani wydawcy i dystrybutorzy mogą przeprowadzać weryfikację tożsamości, przechowywać records, nakładać ograniczenia geograficzne/kwotowe i odpowiadać na legal process. Karta uzyskana przy użyciu skradzionej tożsamości oznacza identity theft; nie usuwa telemetry wydawcy/urządzenia/merchanta.

### Wartość prepaid i gift

Karty prepaid i kody gift oddzielają późniejszą realizację od pierwotnego instrumentu płatniczego, ale tworzą numerowany obiekt ze zdarzeniami zakupu, aktywacji, sprawdzania salda i realizacji. Istotne wzorce obejmują zakupy hurtowe, powtarzające się nominały tuż poniżej limitów kontrolnych, szybką realizację w odległym miejscu, jedno urządzenie sprawdzające wiele sald lub wiele kart zbiegających się u jednego merchanta/konta.

### Nominowani, mule finansowe i przykrywki handlowe

Nominowany lub mule dostarcza konto i legalną tożsamość, które znajdują się pomiędzy operatorem a usługą. Sieci mogą obejmować rekruterów, posiadaczy kont, procesory płatności, fikcyjnych merchantów i brokerów cash-out. Tworzy to dystans, ale każdy uczestnik dodaje komunikację, opłaty, niespójność behawioralną i potencjalnego świadka współpracującego. Spółki przykrywki dodają records dotyczące rejestracji, podatków, bankowości, dyrektorów, faktur, hostingu i przesyłek.

Obrońcy powinni badać współdzielone urządzenia/IP, ponowne użycie beneficjentów, sprzeczności geolokalizacyjne, velocity niespójne z historią konta, transfery cyrkularne, wielu niezależnych nadawców zbiegających się w jednym miejscu oraz natychmiastowy dalszy przepływ środków. Nie należy zakładać, że wskazany posiadacz konta jest aktorem kontrolującym; należy traktować go jako węzeł wymagający określenia roli.

## Wzorce obfuskacji transakcji w publicznym chainie

### Rotacja adresów i coin control

Tworzenie nowego adresu dla każdego otrzymanego transferu zapobiega trywialnemu ponownemu użyciu adresu, ale transakcje nadal mogą zostać połączone przez wspólne wejścia, wykrywanie reszty, dokładną wartość/czas i późniejszą konsolidację. **Coin control** pozwala walletowi wybrać, które outputy wydać, i uniknąć łączenia compartmentów. Poprawia higienę; nie może usunąć już publicznego powiązania.

### Peel chains

Peel chain wielokrotnie wydaje duże saldo, wysyłając mniejszą kwotę na zewnątrz i zwracając resztę na nowy adres:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Adres zmienia się na każdym etapie, ale ciągłość wartości, rytm i struktura transakcji często tworzą rozpoznawalny łańcuch. Hot wallets należące do legalnych giełd mogą działać podobnie, dlatego atrybucja wymaga dowodów związanych z usługą i kontekstem. DOJ wykorzystywał analizę peel-chain w sprawach dotyczących przepadku mienia powiązanego z DPRK.<sup>[[1]](#references)</sup>

### Structuring i fan-out/fan-in

- **Fan-out:** jedno źródło rozdziela środki na wiele adresów, aby zwiększyć nakład pracy śledczej lub przygotować równoległą konwersję.
- **Fan-in:** wiele źródeł konsoliduje środki na jednym adresie zbiorczym, ujawniając wspólną kontrolę lub usługę.
- **Structuring:** powtarzające się mniejsze transfery mają na celu uniknięcie progów kontroli lub wtopienie się w zwykły wolumen.
- **Commingling:** środki nielegalne i niezwiązane z nimi współdzielą wallets, pools lub services, przez co uproszczone twierdzenia proporcjonalne są ryzykowne.

Kształt grafu jest wskazówką, a nie dowodem. Analitycy powinni uwzględniać opłaty, UTXO/account model, zachowanie usługi oraz konwencje dotyczące reszty.

### CoinJoin i PayJoin

W typowym CoinJoin kilku uczestników dostarcza inputs i otrzymuje outputs w ramach jednej wspólnej transakcji, często z outputs o takich samych nominałach. Podważa to założenie, że każdy input i output w transakcji ma jednego właściciela. Zbiór anonimowości jest ograniczony liczbą uczestników i ich późniejszym zachowaniem: nierówna change, toxic change, konsolidacja lub przejście przez znaną usługę mogą ponownie ujawnić powiązania.

PayJoin modyfikuje zwykłą płatność tak, aby zarówno płatnik, jak i odbiorca dostarczyli inputs, bezpośrednio unieważniając heurystykę wspólnego właściciela inputs dla tej transakcji. Jest przede wszystkim protokołem ochrony prywatności płatności, a nie usługą masowego prania pieniędzy. Detection powinien unikać uznawania wszystkich inputs za wspólnie posiadane i wyrażać niepewność zamiast wymuszać fałszywe klastrowanie.

### Centralized mixers i tumblers

Centralized mixer przyjmuje deposits, a później wypłaca inne coins ze wspólnej rezerwy, często po pobraniu opłat i z opóźnieniem. Jego prywatność zależy od rozmiaru pool, zasad wypłat, logs, uczciwości operatora oraz odporności na seizure. Analiza czasu i wartości wejścia oraz wyjścia, adresów deposits, klastrowania service wallets i records może zawęzić zbiór. Operatorzy mogą ukraść środki lub zachować pełne mapowanie.

Ryzyko prawne jest znaczne i zależne od jurysdykcji. Sprawy DOJ przeciwko ChipMixer, Samourai Wallet oraz twórcom/operatorom Tornado Cash, a także zmieniające się postępowania dotyczące sanctions pokazują, że znaczenie mają fakty dotyczące protokołu, custody, kontroli i money transmission; określenie takie jak „decentralized” nie jest wnioskiem prawnym.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps i bridges

Chain hopping konwertuje asset lub przenosi go przez bridge, przerywając zapytanie dotyczące jednej ledger, ale nie ciągłość ekonomiczną:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Analitycy korelują kontrakty bridge/adresy depozytowe usług, kolejność transakcji, przedział czasowy, kurs wymiany, opłaty, płynność i unikalną kwotę. Powtarzane swapy mogą zwiększać niejednoznaczność, jednocześnie dodając telemetrykę dostawcy/API/wallet. FATF wskazuje chain hopping, mixery, usługi peer-to-peer i anonymity-enhanced currencies jako wskaźniki ryzyka, gdy występują w połączeniu z podejrzanym kontekstem.<sup>[[3]](#references)</sup>

### NFTs, hazard i zakupy u merchantów

Transakcje NFT zawierane z samym sobą lub w zmowie mogą nadawać środkom pozorną historię sprzedaży; hazard może wymieniać depozyty na wypłaty; towary mogą przekształcać wartość cyfrową w odsprzedawalne zapasy. Ścieżki te pozostawiają konta marketplace, powiązania z twórcami/royalties, grafy wash-tradingu, historię kursów/gier, logi urządzeń, dowody dostawy i odsprzedaży. Strata lub opłata nie stanowi dowodu, że pochodzenie środków zniknęło.

## Kryptowaluty zachowujące prywatność

Protokoły prywatności różnią się technicznie:

- **Monero** używa jednorazowych adresów, ring signatures i poufnych kwot, ograniczając publiczną widoczność nadawcy/odbiorcy/kwoty. Obserwacja sieci, kompromitacja walleta, pozyskanie środków/off-ramp oraz rejestry kontrahentów pozostają poza tymi zabezpieczeniami on-chain.
- **Zcash shielded pools** mogą ukrywać nadawcę, odbiorcę i kwotę, gdy używane są shielded transactions; transparent addresses i przejścia między pulami pozostają publiczne, a wzorce użycia wpływają na efektywny anonymity set.
- **Bitcoin** jest domyślnie transparentny. New addresses, CoinJoin, PayJoin i Lightning zmieniają określone założenia dotyczące powiązań, ale nie zapewniają prywatności wszystkim warstwom.

Technologia prywatności ma uzasadnione zastosowania w zakresie bezpieczeństwa i działalności komercyjnej. Z perspektywy dochodzeniowej, gdy ledger dostarcza mniej informacji, większego znaczenia nabierają dowody dotyczące endpointów, usług, sieci i ludzi. Nigdy nie wyciągaj wniosku o przestępczości wyłącznie na podstawie wyboru protokołu zachowującego prywatność.

## Model wielowarstwowej sprawy DPRK

Publiczne zarzuty DOJ i działania forfeiture opisują złożony proces, a nie pojedynczą sztuczkę:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. pracownicy używali fikcyjnych/skradzionych materiałów tożsamości oraz VPN-ów, aby uzyskać zdalne zatrudnienie;
2. pracodawcy płacili kryptowalutami, w tym stablecoinami;
3. środki były przenoszone w mniejszych kwotach, przechodziły między chainami lub tokenami, służyły do zakupu NFT albo były mieszane z innymi środkami;
4. inne skradzione środki trafiały do mixerów;
5. traderzy OTC i spółki fasadowe zamieniali wartość na płatności fiat lub towary;
6. powtarzający się facilitatorzy, konta i ścieżki blockchain pozwalały śledczym ponownie połączyć poszczególne warstwy.

Treasury oświadczyło, że Lazarus używał Blender.io do przetwarzania części środków ze kradzieży Axie Infinity/Ronin, natomiast FBI opublikowało adresy i wezwało bridges, exchanges, operatorów RPC oraz firmy analityczne do blokowania środków powiązanych z późniejszymi kradzieżami TraderTraitor.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Wniosek działa w obu kierunkach: aktorzy państwowi korzystają ze zwykłych usług komercyjnych/przestępczych, a publiczne blockchains pozwalają obrońcom śledzić przepływ wartości, nawet gdy nazwy są początkowo nieznane.

## Workflow wykrywania

1. **Zachowaj surowe identyfikatory transakcji i rejestry.** Zrzuty ekranu i zaokrąglone wartości fiat są niewystarczające.
2. **Normalizuj aktywa i czas.** Zapisuj chain, kontrakt tokena, jednostki, czas bloku, strefę czasową usługi, opłaty i źródło kursu wymiany.
3. **Oznacz poziom pewności dowodów.** Rozróżniaj adres opublikowany przez usługę, deterministyczne zdarzenie kontraktu, heuristicę klastrowania i zewnętrzne intelligence.
4. **Śledź oba kierunki.** Ustal źródło finansowania, natychmiastowe rozproszenie, ponowną konwergencję, wyjścia z bridge, depozyty w usługach oraz wydatki/dostawę.
5. **Połącz dowody off-chain.** KYC konta, urządzenia, IP, zgłoszenia do supportu, klucze API, dane bankowe/płatnicze, wysyłkowe i komunikacyjne często usuwają niejednoznaczność.
6. **Testuj alternatywne wyjaśnienia.** Exchanges, custodians, payroll i protokoły prywatności mogą powodować fan-in/out lub co-spends bez wspólnej własności beneficjalnej.
7. **Monitoruj zamiast przedwcześnie zamykać sprawę.** Uśpiony output może stać się możliwy do przypisania, gdy później trafi do usługi.
8. **Stosuj aktualne obowiązki sankcyjne/AML w konsultacji z prawnikiem.** Zasady i designations ulegają zmianom; historyczne powiązanie nie zastępuje bieżącej analizy prawnej.

## Bezpieczny model procurementu red-team

Autoryzowany zespół może potrzebować, aby docelowy SOC nie rozpoznał płatności za hosting, podczas gdy controller zaangażowania zachowuje odpowiedzialność:

- użyj karty organizacji przeznaczonej dla danego engagementu lub udokumentowanego corporate wallet;
- prowadź prawidłową dokumentację billingową, podatkową i dostawcy;
- oddziel operatora od obowiązków procurementowych i ogranicz dostęp do mapy atrybucji;
- nigdy nie używaj mula, fałszywej tożsamości, skradzionej karty, obejścia sankcji ani nielicencjonowanego exchangera;
- rejestruj aktywo, kwotę, właściciela, usługę, datę, ścieżkę refundu i dowody teardownu;
- po zakończeniu ćwiczenia ujawnij controllerowi odpowiednie wskaźniki płatności/dostawcy.

Tworzy to **ślepotę wobec uczestnika ćwiczenia**, a nie ślepotę wobec prawa, dostawcy lub governance.

## References

- [1] [US DOJ — Ramy egzekwowania przepisów dotyczących kryptowalut (przykład peel-chain i dochodzenia DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Likwidacja ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Wskaźniki ostrzegawcze dotyczące Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Przedstawiciel Foreign Trade Bank DPRK oskarżony o udział w spiskach związanych z praniem kryptowalut](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Skarga dotycząca forfeiture 7,74 mln USD rzekomo wypranych na rzecz DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sankcje wobec Blender.io i środki Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Korea Północna odpowiada za kradzież z Bybit w 2025 roku](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Zastosowanie przepisów do użytkowników, administratorów i exchangerów virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
