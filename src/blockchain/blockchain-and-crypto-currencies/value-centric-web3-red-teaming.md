# Red Teaming Web3 skoncentrowany na wartości (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Macierz MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) opisuje zachowania atakujących, które manipulują wartością cyfrową zamiast tylko infrastrukturą. Traktuj ją jako **szkielet modelowania zagrożeń**: wylicz każdy komponent, który może mintować, wyceniać, autoryzować lub routować aktywa, odwzoruj te punkty styku na techniki AADAPT, a następnie zaprojektuj scenariusze red-teamowe, które zmierzą, czy środowisko potrafi oprzeć się nieodwracalnym stratom ekonomicznym.

## 1. Inwentaryzacja komponentów niosących wartość
Zbuduj mapę wszystkiego, co może wpływać na stan wartości, nawet gdy znajduje się off-chain.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs używane przez boty lub zadania back-office). Zbierz identyfikatory kluczy, polityki, tożsamości automatyzacji i workflowy zatwierdzania.
- **Ścieżki admin & upgrade** dla kontraktów (proxy admins, governance timelocks, emergency pause keys, parameter registries). Uwzględnij kto/co może ich wywołać i przy jakim quorum lub opóźnieniu.
- **Logika protokołu on-chain** obsługująca lending, AMMs, vaults, staking, bridges lub settlement rails. Udokumentuj inwarianty, które zakładają (oracle prices, collateral ratios, rebalance cadence…).
- **Automatyzacja off-chain** budująca transakcje (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Te często przechowują API keys lub service principals, które mogą żądać podpisów.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Zanotuj każdy upstream, na którym polega automatyczna logika ryzyka.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) łączące łańcuchy lub stosy custodial.

Rezultat: diagram przepływu wartości pokazujący, jak aktywa się przemieszczają, kto autoryzuje ruch i które sygnały zewnętrzne wpływają na logikę biznesową.

## 2. Mapowanie komponentów na zachowania AADAPT
Przekształć taksonomię AADAPT w konkretne kandydatury ataków dla każdego komponentu.

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Kradzież poświadczeń, obejście polityk, nadużycie podpisów, przejęcie governance |
| Oracles/feeds | Input poisoning, manipulacja agregacją, obejście progów odchylenia |
| On-chain protocols | Flash-loan economic manipulation, łamanie inwariantów, rekonfiguracja parametrów |
| Automation pipelines | Kompromitowane tożsamości botów/CI, batch replay, nieautoryzowane deploye |
| Bridges/routers | Cross-chain evasion, szybkie hop laundering, desynchronizacja settlementów |

To odwzorowanie zapewnia testowanie nie tylko kontraktów, ale wszystkich tożsamości/automatyzacji, które pośrednio mogą sterować wartością.

## 3. Priorytetyzacja według wykonalności atakującego vs. wpływu biznesowego

1. **Słabości operacyjne**: ujawnione credy CI, naduprzywilejowane role IAM, błędnie skonfigurowane polityki KMS, konta automatyzacji mogące żądać dowolnych podpisów, publiczne bucket’y z konfiguracjami bridge itp.
2. **Słabości specyficzne dla wartości**: kruche parametry oracle, upgradable kontrakty bez wielostronnych aprob, płynność wrażliwa na flash-loan, akcje governance omijające timelocki.

Pracuj kolejką jak przeciwnik: zacznij od operacyjnych punktów zaczepienia, które mogłyby się powieść dzisiaj, a potem przejdź do głębszych ścieżek manipulacji protokołem/ekonomią.

## 4. Wykonanie w kontrolowanych, produkcyjnie realistycznych środowiskach
- **Forked mainnets / isolated testnets**: replikuj bytecode, storage i liquidity tak, aby ścieżki flash-loan, dryfty oracle i przepływy bridge działały end-to-end bez dotykania prawdziwych funduszy.
- **Planowanie blast-radius**: zdefiniuj circuit breakers, pausable modules, rollback runbooks i test-only admin keys przed detonacją scenariusza.
- **Koordynacja ze stakeholderami**: powiadom custodians, operatorów oracle, partnerów bridge i compliance, aby ich zespoły monitoringu spodziewały się ruchu.
- **Podpis prawny**: udokumentuj zakres, autoryzację i warunki zatrzymania, gdy symulacje mogą przekroczyć regulowane tory.

## 5. Telemetria dopasowana do technik AADAPT
Zaimplementuj strumienie telemetrii tak, by każdy scenariusz generował użyteczne dane detekcyjne.

- **Chain-level traces**: pełne grafy wywołań, zużycie gas, nonces transakcji, timestamps bloków — do rekonstruowania flash-loan bundle’ów, struktur przypominających reentrancy i cross-contract hopów.
- **Application/API logs**: powiąż każdą on-chain tx z tożsamością człowieka lub automatu (session ID, OAuth client, API key, CI job ID) wraz z IP i metodami auth.
- **KMS/HSM logs**: key ID, caller principal, wynik polityki, adres docelowy i kody powodów dla każdego podpisu. Ustal okna zmian bazowych i operacje wysokiego ryzyka.
- **Oracle/feed metadata**: dla każdej aktualizacji skład źródeł danych, raportowana wartość, odchylenie od średnich kroczących, wyzwolone progi i ćwiczone ścieżki failover.
- **Bridge/swap traces**: koreluj lock/mint/unlock events między łańcuchami z correlation IDs, chain IDs, tożsamością relayera i timingiem hopów.
- **Anomaly markers**: metryki pochodne, takie jak skoki slippage, nietypowe ratios kolateralizacji, nietypowa gęstość gas albo cross-chain velocity.

Otaguj wszystko ID scenariusza lub syntetycznymi użytkownikami, aby analitycy mogli powiązać obserwable z techniką AADAPT, którą ćwiczono.

## 6. Purple-team loop & metryki dojrzałości
1. Uruchom scenariusz w kontrolowanym środowisku i zbierz detekcje (alerty, dashboardy, reagenci paged).
2. Mapuj każdy krok do konkretnych technik AADAPT oraz obserwowalnych w plane chain/app/KMS/oracle/bridge.
3. Formułuj i wdrażaj hipotezy detekcyjne (reguły progowe, wyszukiwania korelacyjne, sprawdzenia inwariantów).
4. Powtarzaj aż mean time to detect (MTTD) i mean time to contain (MTTC) spełnią tolerancje biznesowe, a playbooki niezawodnie powstrzymają utratę wartości.

Śledź dojrzałość programu na trzech osiach:
- **Visibility**: każda krytyczna ścieżka wartości ma telemetrię w każdym plane.
- **Coverage**: odsetek priorytetowych technik AADAPT ćwiczonych end-to-end.
- **Response**: zdolność do zatrzymania kontraktów, cofnięcia kluczy lub zamrożenia przepływów przed nieodwracalną stratą.

Typowe kamienie milowe: (1) ukończona inwentaryzacja wartości + mapowanie AADAPT, (2) pierwszy scenariusz end-to-end z wdrożonymi detekcjami, (3) kwartalne cykle purple-team rozszerzające coverage i redukujące MTTD/MTTC.

## 7. Szablony scenariuszy
Użyj tych powtarzalnych blueprintów do projektowania symulacji, które mapują się bezpośrednio na zachowania AADAPT.

### Scenario A – Flash-loan economic manipulation
- **Objective**: borrow transient capital inside one transaction to distort AMM prices/liquidity and trigger mispriced borrows, liquidations, or mints before repaying.
- **Execution**:
1. Fork the target chain and seed pools with production-like liquidity.
2. Borrow large notional via flash loan.
3. Perform calibrated swaps to cross price/threshold boundaries relied on by lending, vault, or derivative logic.
4. Invoke the victim contract immediately after the distortion (borrow, liquidate, mint) and repay the flash loan.
- **Measurement**: Czy naruszenie inwariantu się powiodło? Czy monitory slippage/price-deviation, circuit breakers lub governance pause hooks zostały uruchomione? Ile czasu minęło, zanim analityka zgłosiła nietypowy pattern gas/call graph?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: determine whether manipulated feeds can trigger destructive automated actions (mass liquidations, incorrect settlements).
- **Execution**:
1. In the fork/testnet, deploy a malicious feed or adjust aggregator weights/quorum/update cadence beyond tolerated deviation.
2. Let dependent contracts consume the poisoned values and execute their standard logic.
- **Measurement**: Alerty na poziomie feedu out-of-band, aktywacja fallback oracle, egzekwowanie min/max bound oraz opóźnienie między początkiem anomalii a reakcją operatora.

### Scenario C – Credential/signing abuse
- **Objective**: test whether compromising a single signer or automation identity enables unauthorized upgrades, parameter changes, or treasury drains.
- **Execution**:
1. Enumerate identities with sensitive signing rights (operators, CI tokens, service accounts invoking KMS/HSM, multisig participants).
2. Simulate compromise (re-use their credentials/keys within the lab scope).
3. Attempt privileged actions: upgrade proxies, change risk parameters, mint/pause assets, or trigger governance proposals.
- **Measurement**: Czy KMS/HSM logs podnoszą alerty anomalii (czas operacji, destination drift, burst operacji wysokiego ryzyka)? Czy polityki lub progi multisig zapobiegają jednostronnemu nadużyciu? Czy throttles/rate limits albo dodatkowe zatwierdzenia są egzekwowane?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: evaluate how well defenders can trace and interdict assets rapidly laundered across bridges, DEX routers, and privacy hops.
- **Execution**:
1. Chain together lock/mint operations across common bridges, interleave swaps/mixers on each hop, and maintain per-hop correlation IDs.
2. Accelerate transfers to stress monitoring latency (multi-hop within minutes/blocks).
- **Measurement**: Czas korelacji eventów między telemetriami + commercial chain analytics, kompletność odtworzonej ścieżki, zdolność do identyfikacji choke points do zamrożenia w realnym incydencie oraz trafność alertów dla nietypowej cross-chain velocity/value.

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
