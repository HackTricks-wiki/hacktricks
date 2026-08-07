# Red Teaming Web3 skoncentrowany na wartości (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Macierz MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) opisuje zachowania attackerów, którzy manipulują wartością cyfrową, a nie tylko infrastrukturą. Traktuj ją jako **fundament modelowania zagrożeń**: zinwentaryzuj każdy komponent, który może emitować, wyceniać, autoryzować lub kierować aktywami, przyporządkuj te punkty styku do technik AADAPT, a następnie przeprowadź scenariusze red-teamowe mierzące, czy środowisko jest odporne na nieodwracalne straty ekonomiczne.

## 1. Zainwentaryzuj komponenty przechowujące wartość
Utwórz mapę wszystkiego, co może wpływać na stan wartości, nawet jeśli znajduje się poza blockchainem.<sup>[[1]](#references)</sup>

- **Usługi podpisywania powierniczego** (klastry HSM/KMS, Vault/KMaaS, API podpisywania używane przez boty lub zadania back-office). Zapisz identyfikatory kluczy, zasady, tożsamości automatyzacji i przepływy zatwierdzania.
- **Ścieżki administracyjne i upgrade'ów** kontraktów (administratorzy proxy, timelocki governance, klucze awaryjnego wstrzymania, rejestry parametrów). Uwzględnij, kto/co może je wywoływać oraz przy jakim quorum lub opóźnieniu.
- **Logika protokołów on-chain** obsługująca lending, AMM, vaulty, staking, bridge'e lub szyny rozliczeniowe. Udokumentuj założone przez nią niezmienniki (ceny oracle, współczynniki zabezpieczenia, częstotliwość rebalansowania…).
- **Automatyzacja off-chain**, która buduje transakcje (boty market-making, pipeline'y CI/CD, zadania cron, funkcje serverless). Często przechowuje ona API keys lub service principals mogące żądać podpisów.
- **Oracle i data feedy** (skład agregatora, quorum, progi odchylenia, częstotliwość aktualizacji). Odnotuj każde źródło upstream, od którego zależy automatyczna logika ryzyka.
- **Bridge'e i routery cross-chain** (kontrakty lock/mint, relayerzy, zadania rozliczeniowe) łączące chainy lub stosy powiernicze.

Rezultat: diagram przepływu wartości pokazujący, jak przemieszczają się aktywa, kto autoryzuje ich transfer oraz które sygnały zewnętrzne wpływają na logikę biznesową.

## 2. Przyporządkuj komponenty do zachowań AADAPT
Przełóż taksonomię AADAPT na konkretne kandydatury ataków dla każdego komponentu.<sup>[[1]](#references)</sup>

| Komponent | Główny zakres AADAPT |
| --- | --- |
| Środowiska signing/KMS | Kradzież poświadczeń, obejście zasad, nadużycie podpisywania, przejęcie governance |
| Oracle/data feedy | Zatrucie danych wejściowych, manipulacja agregacją, obejście progów odchylenia |
| Protokoły on-chain | Ekonomiczna manipulacja za pomocą flash loan, łamanie niezmienników, rekonfiguracja parametrów |
| Pipeline'y automatyzacji | Przejęte tożsamości botów/CI, replay batchy, nieautoryzowane wdrożenie |
| Bridge'e/routery | Obejście cross-chain, szybkie pranie wieloetapowe, desynchronizacja rozliczeń |

To mapowanie zapewnia, że testujesz nie tylko kontrakty, ale również każdą tożsamość/automatyzację, która może pośrednio sterować wartością.

## 3. Ustal priorytety według wykonalności dla attackera i wpływu na biznes

1. **Słabości operacyjne**: ujawnione poświadczenia CI, nadmiernie uprzywilejowane role IAM, błędnie skonfigurowane zasady KMS, konta automatyzacji mogące żądać dowolnych podpisów, publiczne buckety z konfiguracjami bridge'y itd.
2. **Słabości specyficzne dla wartości**: delikatne parametry oracle, upgrade'owalne kontrakty bez zatwierdzeń wielu stron, płynność podatna na flash loan, działania governance omijające timelocki.

Pracuj z kolejką jak adversary: zacznij od operacyjnych przyczółków, które mogą zadziałać już dziś, a następnie przejdź do głębokich ścieżek manipulacji protokołem i ekonomią.<sup>[[1]](#references)</sup>

## 4. Przeprowadzaj działania w kontrolowanych środowiskach realistycznych dla produkcji
- **Forkowane mainnety / izolowane testnety**: odtwórz bytecode, storage i płynność, aby ścieżki flash loan, dryf oracle oraz przepływy bridge działały end-to-end bez dotykania rzeczywistych środków.<sup>[[1]](#references)</sup>
- **Planowanie blast radius**: przed uruchomieniem scenariusza zdefiniuj circuit breakery, moduły możliwe do wstrzymania, runbooki rollbacku oraz klucze administracyjne przeznaczone wyłącznie do testów.
- **Koordynacja interesariuszy**: powiadom custodianów, operatorów oracle, partnerów bridge i compliance, aby ich zespoły monitorujące spodziewały się tego ruchu.
- **Akceptacja prawna**: udokumentuj zakres, autoryzację i warunki zatrzymania, gdy symulacje mogą obejmować regulowane szyny płatnicze.

## 5. Telemetria dostosowana do technik AADAPT
Skonfiguruj strumienie telemetrii tak, aby każdy scenariusz generował użyteczne dane detekcyjne.<sup>[[1]](#references)</sup>

- **Trace'y na poziomie chaina**: pełne grafy wywołań, zużycie gasu, nonce transakcji, znaczniki czasu bloków — aby odtwarzać bundlowane transakcje flash loan, struktury podobne do reentrancy oraz przeskoki między kontraktami.
- **Logi aplikacyjne/API**: powiąż każdą transakcję on-chain z tożsamością człowieka lub automatyzacji (identyfikator sesji, klient OAuth, API key, identyfikator zadania CI), wraz z adresami IP i metodami uwierzytelniania.
- **Logi KMS/HSM**: identyfikator klucza, principal wywołujący, wynik zastosowania zasady, adres docelowy i kody przyczyn dla każdego podpisu. Ustal baseline dla okien zmian i operacji wysokiego ryzyka.
- **Metadane oracle/data feedów**: skład źródeł danych dla każdej aktualizacji, zgłoszona wartość, odchylenie od średnich kroczących, uruchomione progi oraz użyte ścieżki failover.
- **Trace'y bridge/swap**: koreluj zdarzenia lock/mint/unlock między chainami za pomocą identyfikatorów korelacji, identyfikatorów chainów, tożsamości relayerów i czasu przejścia między hopami.
- **Znaczniki anomalii**: metryki pochodne, takie jak skoki slippage, nietypowe współczynniki zabezpieczenia, niezwykła gęstość gasu lub szybkość przepływu cross-chain.

Oznacz wszystko identyfikatorami scenariuszy lub syntetycznymi identyfikatorami użytkowników, aby analitycy mogli powiązać obserwowalne dane z testowaną techniką AADAPT.

## 6. Pętla purple-team i metryki dojrzałości
1. Uruchom scenariusz w kontrolowanym środowisku i zarejestruj detekcje (alerty, dashboardy, powiadomionych responderów).<sup>[[1]](#references)</sup>
2. Przyporządkuj każdy krok do konkretnych technik AADAPT oraz obserwowalnych danych generowanych w warstwach chain, aplikacji, KMS, oracle i bridge.
3. Sformułuj i wdroż hipotezy detekcyjne (reguły progowe, wyszukiwanie korelacji, kontrole niezmienników).
4. Powtarzaj testy, aż średni czas wykrycia (MTTD) i średni czas ograniczenia skutków (MTTC) osiągną biznesowe wartości tolerancji, a playbooki będą niezawodnie zatrzymywać utratę wartości.

Śledź dojrzałość programu w trzech wymiarach:<sup>[[1]](#references)</sup>
- **Widoczność**: każda krytyczna ścieżka wartości ma telemetrię w każdej warstwie.
- **Pokrycie**: odsetek priorytetowych technik AADAPT przetestowanych end-to-end.
- **Reakcja**: zdolność do wstrzymania kontraktów, unieważnienia kluczy lub zamrożenia przepływów przed nieodwracalną stratą.

Typowe kamienie milowe: (1) ukończona inwentaryzacja wartości i mapowanie AADAPT, (2) pierwszy scenariusz end-to-end z wdrożonymi detekcjami, (3) kwartalne cykle purple-team rozszerzające pokrycie i obniżające MTTD/MTTC.<sup>[[1]](#references)</sup>

## 7. Szablony scenariuszy
Korzystaj z tych powtarzalnych wzorców do projektowania symulacji bezpośrednio mapujących się na zachowania AADAPT.<sup>[[1]](#references)</sup>

### Scenariusz A — Ekonomiczna manipulacja za pomocą flash loan
- **Cel**: pożyczyć kapitał tymczasowy w ramach jednej transakcji, aby zniekształcić ceny/płynność AMM i wywołać błędnie wycenione pożyczki, likwidacje lub mintowanie przed spłatą.
- **Wykonanie**:
1. Sforkuj docelowy chain i zasil pule płynnością przypominającą produkcyjną.
2. Pożycz dużą kwotę nominalną za pomocą flash loan.
3. Wykonaj skalibrowane swapy, aby przekroczyć granice cenowe/progowe wykorzystywane przez logikę lendingu, vaultu lub instrumentu pochodnego.
4. Natychmiast po zniekształceniu wywołaj kontrakt ofiary (pożycz, przeprowadź likwidację, wykonaj mint) i spłać flash loan.
- **Pomiar**: Czy udało się naruszyć niezmiennik? Czy uruchomiły się monitory slippage/odchylenia ceny, circuit breakery lub hooki wstrzymania governance? Ile czasu minęło, zanim analityka wykryła nietypowy wzorzec gasu/grafu wywołań?

### Scenariusz B — Zatrucie oracle/data feedu
- **Cel**: ustalić, czy zmanipulowane feedy mogą wywołać destrukcyjne działania automatyczne (masowe likwidacje, nieprawidłowe rozliczenia).
- **Wykonanie**:
1. Na forku/testnecie wdroż złośliwy feed albo zmień wagi agregatora/quorum/częstotliwość aktualizacji poza tolerowanym odchyleniem.
2. Pozwól zależnym kontraktom pobrać zatrute wartości i wykonać standardową logikę.
- **Pomiar**: Alerty out-of-band na poziomie feedu, aktywacja zapasowego oracle, egzekwowanie ograniczeń min/max oraz opóźnienie między pojawieniem się anomalii a reakcją operatora.

### Scenariusz C — Nadużycie poświadczeń/podpisywania
- **Cel**: sprawdzić, czy przejęcie pojedynczego signera lub tożsamości automatyzacji umożliwia nieautoryzowane upgrade'y, zmiany parametrów lub opróżnienie treasury.
- **Wykonanie**:
1. Zainwentaryzuj tożsamości z wrażliwymi uprawnieniami do podpisywania (operatorzy, tokeny CI, konta usług wywołujące KMS/HSM, uczestnicy multisig).
2. Zasymuluj przejęcie (ponownie wykorzystaj ich poświadczenia/klucze w zakresie laboratorium).
3. Podejmij uprzywilejowane działania: wykonaj upgrade proxy, zmień parametry ryzyka, wykonaj mint/wstrzymanie aktywów lub uruchom propozycje governance.
- **Pomiar**: Czy logi KMS/HSM generują alerty anomalii (pora dnia, zmiana adresu docelowego, seria operacji wysokiego ryzyka)? Czy zasady lub progi multisig zapobiegają jednostronnemu nadużyciu? Czy egzekwowane są throttling/rate limits lub dodatkowe zatwierdzenia?

### Scenariusz D — Obejście cross-chain i luki w śledzeniu
- **Cel**: ocenić, jak skutecznie obrońcy mogą śledzić i przechwytywać aktywa szybko prane za pośrednictwem bridge'y, routerów DEX i hopów privacy.
- **Wykonanie**:
1. Połącz operacje lock/mint na popularnych bridge'ach, przeplataj swapy/mixery na każdym hopie i zachowuj identyfikatory korelacji dla poszczególnych hopów.
2. Przyspiesz transfery, aby obciążyć opóźnienia monitoringu (wiele hopów w ciągu minut/bloków).
- **Pomiar**: Czas korelacji zdarzeń w telemetrii i komercyjnej analityce chainów, kompletność odtworzonej ścieżki, możliwość identyfikacji punktów kontrolnych do zamrożenia podczas rzeczywistego incydentu oraz trafność alertów dotyczących nietypowej szybkości/wartości przepływów cross-chain.

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
