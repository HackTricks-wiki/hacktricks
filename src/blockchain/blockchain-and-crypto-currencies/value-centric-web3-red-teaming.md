# Red teaming Web3 skoncentrowany na wartości (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) kategoryzuje działania i techniki przeciwników wymierzone w systemy aktywów cyfrowych.<sup>[[1]](#references)</sup> Traktuj go jako **fundament modelowania zagrożeń**: zinwentaryzuj każdy komponent, który może emitować, wyceniać, autoryzować lub kierować aktywami, przyporządkuj te punkty styku do technik AADAPT, a następnie opracuj scenariusze red team, które zmierzą, czy środowisko jest odporne na nieodwracalne straty ekonomiczne.

## 1. Inwentaryzacja komponentów przechowujących wartość
Utwórz mapę wszystkiego, co może wpływać na stan wartości, nawet jeśli znajduje się poza łańcuchem.<sup>[[2]](#references)</sup>

- **Usługi powierniczego podpisywania** (klastry HSM/KMS, Vault/KMaaS, signing APIs używane przez boty lub zadania back-office). Zapisz identyfikatory kluczy, policies, tożsamości automatyzacji i workflows zatwierdzania.
- **Ścieżki administracyjne i upgrade'ów** kontraktów (proxy admins, governance timelocks, emergency pause keys, rejestry parametrów). Uwzględnij, kto/co może je wywoływać oraz przy jakim quorum lub opóźnieniu.
- **Logika protokołów on-chain** obsługująca lending, AMMs, vaults, staking, bridges lub settlement rails. Udokumentuj założone przez nią invariants (ceny oracle, współczynniki zabezpieczenia, częstotliwość rebalansowania…).
- **Automatyzacja off-chain**, która buduje transactions (boty market-making, pipelines CI/CD, cron jobs, serverless functions). Często przechowują one API keys lub service principals, które mogą żądać podpisów.
- **Oracles i data feeds** (skład agregatora, quorum, progi odchyleń, częstotliwość aktualizacji). Odnotuj każde upstream source, od którego zależy zautomatyzowana logika ryzyka.
- **Bridges i cross-chain routers** (kontrakty lock/mint, relayers, zadania settlement) łączące chainy lub stosy powiernicze.

Rezultat: diagram przepływu wartości pokazujący, jak przemieszczają się aktywa, kto autoryzuje ich transfer oraz które sygnały zewnętrzne wpływają na logikę biznesową.

## 2. Mapowanie komponentów na zachowania AADAPT
Przełóż taksonomię AADAPT na konkretne kandydatury ataków dla każdego komponentu.<sup>[[2]](#references)</sup>

| Komponent | Główny obszar AADAPT |
| --- | --- |
| Środowiska signing/KMS | Kradzież credentials, obejście policy, nadużycie podpisywania, przejęcie governance |
| Oracles/feeds | Zatruwanie danych wejściowych, manipulacja agregacją, omijanie progów odchyleń |
| Protokoły on-chain | Ekonomiczna manipulacja za pomocą flash loan, łamanie invariants, rekonfiguracja parametrów |
| Pipelines automatyzacji | Przejęte tożsamości botów/CI, batch replay, nieautoryzowane deploymenty |
| Bridges/routers | Omijanie zabezpieczeń cross-chain, szybkie pranie przez kolejne hop, desynchronizacja settlement |

To mapowanie gwarantuje, że testujesz nie tylko contracts, ale również każdą identity/automation, która może pośrednio sterować wartością.

## 3. Priorytetyzacja według wykonalności dla atakującego i wpływu na biznes

1. **Słabości operacyjne**: ujawnione credentials CI, nadmiernie uprzywilejowane role IAM, błędnie skonfigurowane policies KMS, konta automatyzacji mogące żądać dowolnych podpisów, publiczne buckets z konfiguracjami bridges itp.
2. **Słabości specyficzne dla wartości**: kruche parametry oracle, upgradable contracts bez zatwierdzeń wielu stron, liquidity podatna na flash loan, działania governance omijające timelocks.

Realizuj kolejkę jak przeciwnik: zacznij od operacyjnych footholds, które mogą zadziałać już dziś, a następnie przejdź do głębokich ścieżek manipulacji protokołem i ekonomią.<sup>[[2]](#references)</sup>

## 4. Wykonywanie działań w kontrolowanych, realistycznych środowiskach produkcyjnych
- **Forked mainnets / isolated testnets**: odtwórz bytecode, storage i liquidity, aby ścieżki flash loan, odchylenia oracle i przepływy bridge działały end-to-end bez dotykania rzeczywistych środków.<sup>[[2]](#references)</sup>
- **Planowanie blast radius**: zdefiniuj circuit breakers, pausable modules, runbooks rollbacku oraz klucze administracyjne przeznaczone wyłącznie do testów przed uruchomieniem scenariusza.
- **Koordynacja interesariuszy**: powiadom custodians, operatorów oracle, partnerów bridge i compliance, aby ich zespoły monitorujące oczekiwały tego ruchu.
- **Zatwierdzenie prawne**: udokumentuj zakres, autoryzację i warunki zatrzymania, gdy symulacje mogą obejmować regulowane rails.

## 5. Telemetria dostosowana do technik AADAPT
Skonfiguruj strumienie telemetrii tak, aby każdy scenariusz dostarczał użytecznych danych detekcyjnych.<sup>[[2]](#references)</sup>

- **Ślady na poziomie chain**: pełne grafy wywołań, zużycie gas, nonces transakcji, timestamps bloków — w celu odtworzenia bundles flash loan, struktur podobnych do reentrancy oraz hopów między contracts.
- **Logi aplikacji/API**: powiąż każdą transakcję on-chain z tożsamością człowieka lub automatyzacji (session ID, OAuth client, API key, CI job ID), wraz z adresami IP i metodami uwierzytelniania.
- **Logi KMS/HSM**: key ID, caller principal, wynik policy, adres docelowy i reason codes dla każdego podpisu. Ustal baseline dla okien zmian i operacji wysokiego ryzyka.
- **Metadane oracle/feed**: skład źródeł danych dla każdej aktualizacji, zgłoszona wartość, odchylenie od średnich kroczących, uruchomione progi oraz wykorzystane ścieżki failover.
- **Ślady bridge/swap**: koreluj zdarzenia lock/mint/unlock między chainami za pomocą correlation IDs, chain IDs, tożsamości relayerów i czasu między hopami.
- **Znaczniki anomalii**: metryki pochodne, takie jak skoki slippage, nietypowe współczynniki collateralization, niezwykła gęstość gas lub velocity cross-chain.

Oznacz wszystko identyfikatorami scenariuszy lub syntetycznymi identyfikatorami użytkowników, aby analitycy mogli powiązać obserwowalne dane z badaną techniką AADAPT.

## 6. Pętla purple team i metryki dojrzałości
1. Uruchom scenariusz w kontrolowanym środowisku i zarejestruj detections (alerty, dashboards, powiadomionych responders).<sup>[[2]](#references)</sup>
2. Przyporządkuj każdy krok do konkretnych technik AADAPT oraz obserwowalnych danych generowanych w warstwach chain/app/KMS/oracle/bridge.
3. Sformułuj i wdroż detection hypotheses (reguły progowe, correlation searches, checks invariants).
4. Powtarzaj testy, aż mean time to detect (MTTD) i mean time to contain (MTTC) osiągną biznesowe tolerancje, a playbooks będą niezawodnie zatrzymywać utratę wartości.

Śledź dojrzałość programu w trzech wymiarach:<sup>[[2]](#references)</sup>
- **Visibility**: każda krytyczna ścieżka wartości ma telemetrię w każdej warstwie.
- **Coverage**: odsetek priorytetowych technik AADAPT testowanych end-to-end.
- **Response**: zdolność do wstrzymywania contracts, odwoływania keys lub zamrażania przepływów przed nieodwracalną stratą.

Typowe kamienie milowe: (1) ukończona inwentaryzacja wartości + mapowanie AADAPT, (2) pierwszy scenariusz end-to-end z zaimplementowanymi detections, (3) kwartalne cykle purple team rozszerzające coverage i skracające MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Szablony scenariuszy
Użyj tych powtarzalnych blueprintów do projektowania symulacji, które bezpośrednio mapują się na zachowania AADAPT.<sup>[[2]](#references)</sup>

### Scenariusz A – Ekonomiczna manipulacja za pomocą flash loan
- **Cel**: pożyczyć kapitał tymczasowy w ramach jednej transakcji, aby zniekształcić ceny/liquidity AMM i uruchomić błędnie wycenione borrows, liquidations lub mints przed spłatą.
- **Wykonanie**:
1. Zforkuj docelowy chain i zasil pools liquidity zbliżoną do produkcyjnej.
2. Pożycz dużą wartość nominalną za pomocą flash loan.
3. Wykonaj skalibrowane swaps, aby przekroczyć granice cen/progów, na których opiera się logika lending, vault lub derivatives.
4. Wywołaj victim contract natychmiast po zniekształceniu (borrow, liquidate, mint) i spłać flash loan.
- **Pomiar**: Czy naruszenie invariant zakończyło się powodzeniem? Czy monitory slippage/odchyleń cenowych, circuit breakers lub hooks wstrzymania governance zostały uruchomione? Ile czasu minęło, zanim analytics wykryły nietypowy wzorzec gas/call graph?

### Scenariusz B – Zatruwanie oracle/data feed
- **Cel**: określić, czy zmanipulowane feeds mogą uruchomić destrukcyjne działania automatyczne (masowe liquidations, nieprawidłowe settlements).
- **Wykonanie**:
1. W fork/testnet wdroż malicious feed lub zmień wagi agregatora/quorum/częstotliwość aktualizacji poza tolerowane odchylenie.
2. Pozwól zależnym contracts pobrać zatrute wartości i wykonać standardową logikę.
- **Pomiar**: Alerty out-of-band na poziomie feed, aktywacja fallback oracle, egzekwowanie ograniczeń min/max oraz opóźnienie między pojawieniem się anomalii a reakcją operatora.

### Scenariusz C – Nadużycie credentials/podpisywania
- **Cel**: sprawdzić, czy kompromitacja pojedynczego signera lub identity automatyzacji umożliwia nieautoryzowane upgrade'y, zmiany parametrów lub drenaż treasury.
- **Wykonanie**:
1. Zinwentaryzuj identities z wrażliwymi uprawnieniami do podpisywania (operators, tokens CI, service accounts wywołujące KMS/HSM, uczestnicy multisig).
2. Zasymuluj kompromitację (ponownie użyj ich credentials/keys w zakresie laboratorium).
3. Spróbuj wykonać uprzywilejowane działania: upgrade proxies, zmianę parametrów ryzyka, mint/pause assets lub uruchomienie proposals governance.
- **Pomiar**: Czy logi KMS/HSM generują alerty anomalii (pora dnia, zmiana destination, seria operacji wysokiego ryzyka)? Czy policies lub progi multisig zapobiegają nadużyciu jednostronnemu? Czy egzekwowane są throttles/rate limits lub dodatkowe approvals?

### Scenariusz D – Omijanie zabezpieczeń cross-chain i luki w traceability
- **Cel**: ocenić, jak skutecznie defenders mogą śledzić i przechwytywać aktywa szybko prane za pośrednictwem bridges, DEX routers i privacy hops.
- **Wykonanie**:
1. Połącz operacje lock/mint w ramach popularnych bridges, przeplataj swaps/mixers na każdym hopie i utrzymuj correlation IDs dla poszczególnych hopów.
2. Przyspiesz transfers, aby obciążyć opóźnienia monitoringu (multi-hop w ciągu minut/bloków).
- **Pomiar**: Czas korelacji zdarzeń między telemetrią a komercyjnymi chain analytics, kompletność odtworzonej ścieżki, możliwość identyfikacji choke points do zamrożenia w rzeczywistym incydencie oraz jakość alertów dotyczących nietypowego velocity/value cross-chain.

## References

- [1] [Framework cyberzagrożeń AADAPT(TM) dla aktywów cyfrowych (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Framework MITRE AADAPT jako roadmapa dla Red Team (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
