# Red Teaming Web3, орієнтований на цінність (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Матриця MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) охоплює поведінку зловмисників, які маніпулюють цифровою цінністю, а не лише інфраструктурою. Розглядайте її як **основу threat modeling**: перелічіть кожен компонент, який може випускати, оцінювати, авторизувати або маршрутизувати активи, зіставте ці точки взаємодії з техніками AADAPT, а потім створюйте red-team сценарії, що вимірюють здатність середовища протистояти незворотним економічним збиткам.

## 1. Інвентаризація компонентів, що містять цінність
Створіть карту всього, що може впливати на стан цінності, навіть якщо воно перебуває поза chain.<sup>[[1]](#references)</sup>

- **Custodial signing services** (кластери HSM/KMS, Vault/KMaaS, signing APIs, які використовують боти або back-office jobs). Зафіксуйте key IDs, policies, automation identities і approval workflows.
- **Admin & upgrade paths** для контрактів (proxy admins, governance timelocks, emergency pause keys, parameter registries). Вкажіть, хто або що може їх викликати та за якого quorum або delay.
- **On-chain protocol logic**, що обробляє lending, AMMs, vaults, staking, bridges або settlement rails. Задокументуйте інваріанти, на які вони покладаються (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation**, що створює транзакції (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Вони часто містять API keys або service principals, які можуть запитувати підписи.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Зазначте кожне upstream-джерело, від якого залежить автоматизована risk logic.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs), що поєднують chain або custodial stacks.

Результат: діаграма flow цінності, яка показує, як переміщуються активи, хто авторизує переміщення та які зовнішні сигнали впливають на business logic.

## 2. Зіставлення компонентів із поведінкою AADAPT
Перетворіть таксономію AADAPT на конкретні attack candidates для кожного компонента.<sup>[[1]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Це зіставлення гарантує, що ви тестуєте не лише контракти, а й кожну identity/automation, яка може опосередковано спрямовувати цінність.

## 3. Пріоритизація за здійсненністю атаки та впливом на бізнес

1. **Operational weaknesses**: exposed CI credentials, over-privileged IAM roles, misconfigured KMS policies, automation accounts, які можуть запитувати довільні підписи, public buckets із bridge configs тощо.
2. **Value-specific weaknesses**: ненадійні oracle parameters, upgradable contracts без multi-party approvals, flash-loan sensitive liquidity, governance actions, які обходять timelocks.

Опрацьовуйте чергу як зловмисник: починайте з operational footholds, які можуть спрацювати вже сьогодні, а потім переходьте до складних protocol/economic manipulation paths.<sup>[[1]](#references)</sup>

## 4. Виконання у контрольованих середовищах, наближених до production
- **Forked mainnets / isolated testnets**: відтворіть bytecode, storage і liquidity, щоб flash-loan paths, oracle drifts і bridge flows виконувалися end-to-end без використання реальних коштів.<sup>[[1]](#references)</sup>
- **Blast-radius planning**: визначте circuit breakers, pausable modules, rollback runbooks і test-only admin keys до запуску сценарію.
- **Stakeholder coordination**: повідомте custodians, oracle operators, bridge partners і compliance, щоб їхні monitoring teams очікували цей трафік.
- **Legal sign-off**: задокументуйте scope, authorization і stop conditions, якщо simulations можуть перетнути regulated rails.

## 5. Telemetry, узгоджена з техніками AADAPT
Налаштуйте telemetry streams так, щоб кожен сценарій створював дані для actionable detection.<sup>[[1]](#references)</sup>

- **Chain-level traces**: повні call graphs, gas usage, transaction nonces, block timestamps — для відновлення flash-loan bundles, reentrancy-like structures і cross-contract hops.
- **Application/API logs**: пов’яжіть кожну on-chain tx із human або automation identity (session ID, OAuth client, API key, CI job ID), включно з IP і auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address і reason codes для кожного підпису. Визначте baseline для change windows і high-risk operations.
- **Oracle/feed metadata**: для кожного update — data source composition, reported value, deviation від rolling averages, triggered thresholds і використані failover paths.
- **Bridge/swap traces**: зіставляйте lock/mint/unlock events між chain за допомогою correlation IDs, chain IDs, relayer identity і hop timing.
- **Anomaly markers**: похідні метрики, як-от slippage spikes, abnormal collateralization ratios, unusual gas density або cross-chain velocity.

Позначайте все scenario IDs або synthetic user IDs, щоб аналітики могли зіставляти observables із технікою AADAPT, яка перевіряється.

## 6. Purple-team loop і метрики зрілості
1. Запустіть сценарій у контрольованому середовищі та зафіксуйте detections (alerts, dashboards, paged responders).<sup>[[1]](#references)</sup>
2. Зіставте кожен крок із конкретними техніками AADAPT та observables, отриманими на chain/app/KMS/oracle/bridge planes.
3. Сформулюйте та впровадьте detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Повторюйте запуск, доки mean time to detect (MTTD) і mean time to contain (MTTC) не відповідатимуть бізнес-допускам, а playbooks стабільно не зупинятимуть втрату цінності.

Відстежуйте зрілість програми за трьома напрямами:<sup>[[1]](#references)</sup>
- **Visibility**: кожен критичний value path має telemetry на кожній plane.
- **Coverage**: частка пріоритизованих технік AADAPT, перевірених end-to-end.
- **Response**: здатність призупиняти контракти, відкликати ключі або заморожувати flows до незворотної втрати.

Типові етапи: (1) завершені value inventory + AADAPT mapping, (2) перший end-to-end сценарій із реалізованими detections, (3) щоквартальні purple-team cycles із розширенням coverage та зменшенням MTTD/MTTC.<sup>[[1]](#references)</sup>

## 7. Шаблони сценаріїв
Використовуйте ці повторювані blueprints для створення simulations, які безпосередньо відповідають поведінці AADAPT.<sup>[[1]](#references)</sup>

### Сценарій A — Flash-loan economic manipulation
- **Objective**: позичити тимчасовий капітал у межах однієї транзакції, щоб спотворити AMM prices/liquidity і запустити mispriced borrows, liquidations або mints до повернення позики.
- **Execution**:
1. Зробіть fork цільового chain і наповніть pools liquidity, подібною до production.
2. Позичте великий notional через flash loan.
3. Виконайте калібровані swaps, щоб перетнути price/threshold boundaries, на які спирається lending, vault або derivative logic.
4. Негайно викличте victim contract після спотворення (borrow, liquidate, mint) і поверніть flash loan.
- **Measurement**: Чи вдалося порушити invariant? Чи спрацювали slippage/price-deviation monitors, circuit breakers або governance pause hooks? Скільки часу знадобилося analytics для виявлення abnormal gas/call graph pattern?

### Сценарій B — Oracle/data-feed poisoning
- **Objective**: визначити, чи можуть manipulated feeds запускати destructive automated actions (mass liquidations, incorrect settlements).
- **Execution**:
1. У fork/testnet розгорніть malicious feed або змініть aggregator weights/quorum/update cadence за межі допустимого deviation.
2. Дозвольте dependent contracts використати poisoned values і виконати стандартну logic.
- **Measurement**: Feed-level out-of-band alerts, активація fallback oracle, застосування min/max bounds і latency між початком anomaly та реакцією оператора.

### Сценарій C — Credential/signing abuse
- **Objective**: перевірити, чи дає компрометація одного signer або automation identity змогу виконувати unauthorized upgrades, parameter changes або treasury drains.
- **Execution**:
1. Перелічіть identities із чутливими signing rights (operators, CI tokens, service accounts, що викликають KMS/HSM, multisig participants).
2. Імітуйте компрометацію (повторно використайте їхні credentials/keys у межах lab scope).
3. Спробуйте privileged actions: upgrade proxies, змінити risk parameters, mint/pause assets або ініціювати governance proposals.
- **Measurement**: Чи створюють KMS/HSM logs anomaly alerts (time-of-day, destination drift, burst of high-risk operations)? Чи можуть policies або multisig thresholds запобігти unilateral abuse? Чи застосовуються throttles/rate limits або додаткові approvals?

### Сценарій D — Cross-chain evasion & traceability gaps
- **Objective**: оцінити, наскільки добре defenders можуть відстежувати та швидко блокувати assets, laundered через bridges, DEX routers і privacy hops.
- **Execution**:
1. Об’єднайте lock/mint operations через поширені bridges, чергуючи swaps/mixers на кожному hop, і зберігайте per-hop correlation IDs.
2. Прискорте transfers, щоб створити навантаження на monitoring latency (multi-hop протягом хвилин/blocks).
- **Measurement**: Час для кореляції events між telemetry та commercial chain analytics, повнота reconstructed path, здатність визначити choke points для freezing у реальному incident і alert fidelity для abnormal cross-chain velocity/value.

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
