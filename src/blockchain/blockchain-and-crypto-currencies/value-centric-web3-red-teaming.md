# Red Teaming Web3 skoncentrowany na wartości (MITRE AADAPT)

Framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) kategoryzuje działania i techniki adversarial wymierzone w systemy aktywów cyfrowych.<sup>[[1]](#references)</sup> Traktuj go jako **szkielet modelowania zagrożeń**: zinwentaryzuj każdy komponent, który może emitować, wyceniać, autoryzować lub routować aktywa, zmapuj te punkty styku na techniki AADAPT, a następnie przeprowadź scenariusze red-team, które zmierzą, czy środowisko jest odporne na nieodwracalną stratę ekonomiczną.

## 1. Inwentaryzacja komponentów przenoszących wartość
Zbuduj mapę wszystkiego, co może wpływać na stan wartości, nawet jeśli znajduje się off-chain.<sup>[[2]](#references)</sup>

- **Usługi custodial signing** (klastry HSM/KMS, Vault/KMaaS, signing APIs używane przez boty lub zadania back-office). Zapisz identyfikatory kluczy, policies, automation identities oraz approval workflows.
- **Ścieżki administracyjne i upgrade** kontraktów (proxy admins, governance timelocks, emergency pause keys, parameter registries). Uwzględnij, kto/co może je wywoływać oraz przy jakim quorum lub opóźnieniu.
- **Logika protokołów on-chain** obsługująca lending, AMM-y, vaulty, staking, bridge’e lub settlement rails. Udokumentuj założone przez nią invariants (ceny oracle, współczynniki collateral, częstotliwość rebalancingu…).
- **Automatyzacja off-chain**, która tworzy transakcje (boty market-making, pipelines CI/CD, zadania cron, funkcje serverless). Często przechowują one API keys lub service principals, które mogą żądać signatures.
- **Oracles i data feeds** (skład agregatora, quorum, progi odchyleń, częstotliwość aktualizacji). Zapisz każde upstream, od którego zależy automatyczna logika ryzyka.
- **Bridge’e i cross-chain routers** (lock/mint contracts, relayers, settlement jobs) łączące chainy lub stosy custodial.

Rezultat: diagram przepływu wartości pokazujący, jak przemieszczają się aktywa, kto autoryzuje ich transfer oraz które sygnały zewnętrzne wpływają na logikę biznesową.

## 2. Mapowanie komponentów na zachowania AADAPT
Przełóż taksonomię AADAPT na konkretne kandydatury ataków dla każdego komponentu.<sup>[[2]](#references)</sup>

| Komponent | Główny obszar AADAPT |
| --- | --- |
| Środowiska signing/KMS | Kradzież credentials, obejście policy, signing abuse, przejęcie governance |
| Oracles/feeds | Zatruwanie inputu, manipulacja agregacją, obchodzenie progów odchyleń |
| Protokoły on-chain | Manipulacja ekonomiczna za pomocą flash loan, łamanie invariantów, rekonfiguracja parametrów |
| Pipelines automatyzacji | Przejęte bot/CI identities, replay batchy, nieautoryzowane deploymenty |
| Bridge’e/routers | Evasion cross-chain, szybkie laundering przez hop’y, desynchronizacja settlementu |

To mapowanie zapewnia, że testujesz nie tylko kontrakty, lecz także każdą identity/automatyzację, która może pośrednio sterować wartością.

## 3. Priorytetyzacja według wykonalności dla attackera i wpływu na biznes

1. **Słabości operacyjne**: ujawnione credentials CI, nadmiernie uprzywilejowane role IAM, błędnie skonfigurowane policies KMS, konta automatyzacji mogące żądać dowolnych signatures, publiczne buckety z konfiguracjami bridge’y itd.
2. **Słabości specyficzne dla wartości**: kruche parametry oracle, upgradable contracts bez zatwierdzeń wielu stron, liquidity wrażliwa na flash loan, działania governance omijające timelocks.

Pracuj nad kolejką jak adversary: zacznij od operacyjnych footholds, które mogą zadziałać już dziś, a następnie przechodź do zaawansowanych ścieżek manipulacji protokołami i ekonomią.<sup>[[2]](#references)</sup>

## 4. Wykonywanie w kontrolowanych, realistycznych środowiskach produkcyjnych
- **Forked mainnets / isolated testnets**: odtwórz bytecode, storage i liquidity, aby ścieżki flash loan, odchylenia oracle oraz przepływy bridge działały end-to-end bez dotykania rzeczywistych środków.<sup>[[2]](#references)</sup>
- **Planowanie blast radius**: zdefiniuj circuit breakers, pausable modules, rollback runbooks i test-only admin keys przed uruchomieniem scenariusza.
- **Koordynacja stakeholderów**: powiadom custodians, operatorów oracle, partnerów bridge oraz compliance, aby ich zespoły monitoringowe spodziewały się tego ruchu.
- **Akceptacja prawna**: udokumentuj zakres, autoryzację i warunki przerwania, gdy symulacje mogą objąć regulowane rails.

## 5. Telemetria dopasowana do technik AADAPT
Instrumentuj strumienie telemetryczne tak, aby każdy scenariusz generował użyteczne dane detekcyjne.<sup>[[2]](#references)</sup>

- **Traces na poziomie chaina**: pełne grafy wywołań, zużycie gasu, nonce transakcji, timestamps bloków — do odtworzenia flash-loan bundles, struktur podobnych do reentrancy oraz hopów między kontraktami.
- **Logi aplikacji/API**: powiąż każdą transakcję on-chain z identity człowieka lub automatyzacji (session ID, OAuth client, API key, CI job ID), wraz z adresami IP i metodami auth.
- **Logi KMS/HSM**: key ID, caller principal, wynik policy, adres docelowy oraz reason codes dla każdej signature. Zbuduj baseline dla change windows i operacji wysokiego ryzyka.
- **Metadane oracle/feed**: skład źródeł danych dla każdej aktualizacji, zgłoszona wartość, odchylenie od średnich kroczących, uruchomione progi oraz użyte ścieżki failover.
- **Traces bridge/swap**: koreluj zdarzenia lock/mint/unlock między chainami za pomocą correlation IDs, chain IDs, identity relayera i czasu trwania hopów.
- **Znaczniki anomalii**: metryki pochodne, takie jak skoki slippage, nietypowe współczynniki collateralization, niezwykła gęstość gasu lub cross-chain velocity.

Oznacz wszystko scenario IDs lub synthetic user IDs, aby analitycy mogli powiązać obserwowalne zdarzenia z testowaną techniką AADAPT.

## 6. Pętla purple-team i metryki dojrzałości
1. Uruchom scenariusz w kontrolowanym środowisku i zarejestruj detekcje (alerty, dashboardy, powiadomionych responderów).<sup>[[2]](#references)</sup>
2. Zmapuj każdy krok na konkretne techniki AADAPT oraz obserwowalne dane wygenerowane w warstwach chain/app/KMS/oracle/bridge.
3. Sformułuj i wdroż hipotezy detekcyjne (reguły progowe, correlation searches, checks invariantów).
4. Powtarzaj testy, aż mean time to detect (MTTD) i mean time to contain (MTTC) spełnią tolerancje biznesowe, a playbooki będą niezawodnie zatrzymywać utratę wartości.

Śledź dojrzałość programu w trzech osiach:<sup>[[2]](#references)</sup>
- **Widoczność**: każda krytyczna ścieżka wartości ma telemetrię w każdej warstwie.
- **Pokrycie**: odsetek priorytetyzowanych technik AADAPT testowanych end-to-end.
- **Response**: zdolność do wstrzymywania kontraktów, unieważniania kluczy lub zamrażania przepływów przed nieodwracalną stratą.

Typowe kamienie milowe: (1) ukończona inwentaryzacja wartości i mapowanie AADAPT, (2) pierwszy scenariusz end-to-end z wdrożonymi detekcjami, (3) kwartalne cykle purple-team rozszerzające pokrycie i skracające MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Szablony scenariuszy
Użyj tych powtarzalnych blueprintów do projektowania symulacji, które mapują się bezpośrednio na zachowania AADAPT.<sup>[[2]](#references)</sup>

### Scenariusz A – Manipulacja ekonomiczna za pomocą flash loan
- **Cel**: pożyczyć kapitał tymczasowy w ramach jednej transakcji, aby zniekształcić ceny/liquidity AMM i wywołać błędnie wycenione borrow, liquidations lub mints przed spłatą.
- **Wykonanie**:
1. Zrób fork docelowego chaina i zasil poole liquidity zbliżoną do produkcyjnej.
2. Pożycz dużą wartość nominalną za pomocą flash loan.
3. Wykonaj skalibrowane swapy przekraczające granice cen/progów, na których opiera się logika lending, vault lub instrumentów pochodnych.
4. Natychmiast po zniekształceniu wywołaj victim contract (borrow, liquidate, mint) i spłać flash loan.
- **Pomiar**: Czy udało się naruszyć invariant? Czy uruchomiły się monitory slippage/price-deviation, circuit breakers lub governance pause hooks? Ile czasu minęło do wykrycia przez analytics nietypowego wzorca gas/call graph?

### Scenariusz B – Zatruwanie oracle/data feed
- **Cel**: określić, czy zmanipulowane feeds mogą wywołać destrukcyjne działania automatyczne (masowe liquidations, nieprawidłowe settlements).
- **Wykonanie**:
1. W fork/testnet wdroż malicious feed lub zmień wagi agregatora/quorum/częstotliwość aktualizacji poza tolerowane odchylenie.
2. Pozwól zależnym kontraktom wykorzystać zatrute wartości i wykonać standardową logikę.
- **Pomiar**: Alerty out-of-band na poziomie feed, aktywacja fallback oracle, egzekwowanie granic min/max oraz opóźnienie między pojawieniem się anomalii a reakcją operatora.

### Scenariusz C – Nadużycie credentials/signing
- **Cel**: sprawdzić, czy przejęcie jednego signera lub identity automatyzacji umożliwia nieautoryzowane upgrades, zmiany parametrów lub drenaż treasury.
- **Wykonanie**:
1. Zainwentaryzuj identities z wrażliwymi uprawnieniami signing (operatorzy, tokeny CI, service accounts wywołujące KMS/HSM, uczestnicy multisig).
2. Zasymuluj compromise (ponownie użyj ich credentials/keys w zakresie laboratorium).
3. Spróbuj wykonać uprzywilejowane działania: upgrade proxy, zmianę parametrów ryzyka, mint/pause assets lub uruchomienie governance proposals.
- **Pomiar**: Czy logi KMS/HSM generują alerty anomalii (pora dnia, zmiana adresu docelowego, seria operacji wysokiego ryzyka)? Czy policies lub progi multisig zapobiegają jednostronnemu nadużyciu? Czy wymuszane są throttles/rate limits lub dodatkowe approvals?

### Scenariusz D – Evasion cross-chain i luki w traceability
- **Cel**: ocenić, jak skutecznie obrońcy mogą śledzić i przechwytywać aktywa szybko launderingowane przez bridge’e, DEX routers i privacy hops.
- **Wykonanie**:
1. Połącz operacje lock/mint na popularnych bridge’ach, przeplataj swapy/mixers na każdym hopie i utrzymuj correlation IDs dla poszczególnych hopów.
2. Przyspiesz transfery, aby obciążyć monitoring latency (multi-hop w ciągu minut/bloków).
- **Pomiar**: Czas korelacji zdarzeń między telemetrią a komercyjnymi chain analytics, kompletność odtworzonej ścieżki, zdolność do identyfikacji choke points umożliwiających zamrożenie środków w rzeczywistym incydencie oraz jakość alertów dotyczących nietypowej cross-chain velocity/value.

## References

- [1] [AADAPT(TM) Cyber Threat Framework for Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
