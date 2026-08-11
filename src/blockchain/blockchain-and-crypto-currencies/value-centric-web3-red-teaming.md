# Red Teaming Web3, орієнтований на цінність (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Фреймворк MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) класифікує adversarial actions і techniques, спрямовані на системи цифрових активів.<sup>[[1]](#references)</sup> Розглядайте його як **основу threat modeling**: перелічіть кожен компонент, який може здійснювати mint, визначати ціну, авторизувати або маршрутизувати активи, зіставте ці точки взаємодії з техніками AADAPT, а потім створюйте red-team сценарії, які вимірюють, чи здатне середовище протистояти незворотним економічним збиткам.

## 1. Інвентаризація компонентів, що несуть цінність
Створіть карту всього, що може впливати на стан цінності, навіть якщо воно перебуває поза блокчейном.<sup>[[2]](#references)</sup>

- **Сервіси custodial signing** (кластери HSM/KMS, Vault/KMaaS, signing APIs, які використовують боти або back-office jobs). Зафіксуйте key IDs, policies, automation identities і approval workflows.
- **Admin- і upgrade-шляхи** для контрактів (proxy admins, governance timelocks, emergency pause keys, parameter registries). Вкажіть, хто або що може їх викликати та за якого quorum або delay.
- **On-chain protocol logic**, що обробляє lending, AMMs, vaults, staking, bridges або settlement rails. Задокументуйте інваріанти, які вони припускають (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation**, що створює транзакції (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Вони часто містять API keys або service principals, які можуть запитувати підписи.
- **Oracles і data feeds** (склад агрегатора, quorum, deviation thresholds, update cadence). Зафіксуйте кожне upstream-джерело, від якого залежить automated risk logic.
- **Bridges і cross-chain routers** (lock/mint contracts, relayers, settlement jobs), які поєднують мережі або custodial stacks.

Результат: діаграма value flow, що показує, як переміщуються активи, хто авторизує переміщення та які зовнішні сигнали впливають на business logic.

## 2. Зіставлення компонентів із поведінками AADAPT
Перетворіть таксономію AADAPT на конкретні attack candidates для кожного компонента.<sup>[[2]](#references)</sup>

| Компонент | Основний фокус AADAPT |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Таке зіставлення гарантує, що ви тестуєте не лише контракти, а й кожну identity/automation, яка може опосередковано спрямовувати цінність.

## 3. Пріоритизація за здійсненністю для атакувальника та впливом на бізнес

1. **Операційні слабкості**: exposed CI credentials, over-privileged IAM roles, misconfigured KMS policies, automation accounts, які можуть запитувати довільні підписи, public buckets із bridge configs тощо.
2. **Специфічні для цінності слабкості**: нестійкі oracle parameters, upgradable contracts без multi-party approvals, flash-loan sensitive liquidity, governance actions, які обходять timelocks.

Опрацьовуйте чергу як adversary: починайте з operational footholds, які можуть спрацювати вже сьогодні, а потім переходьте до складних шляхів protocol/economic manipulation.<sup>[[2]](#references)</sup>

## 4. Виконання у контрольованих середовищах, наближених до production
- **Forked mainnets / isolated testnets**: відтворіть bytecode, storage і liquidity, щоб flash-loan paths, oracle drifts і bridge flows виконувалися end-to-end без доступу до реальних коштів.<sup>[[2]](#references)</sup>
- **Планування blast radius**: визначте circuit breakers, pausable modules, rollback runbooks і test-only admin keys до запуску сценарію.
- **Координація зі stakeholders**: повідомте custodians, oracle operators, bridge partners і compliance, щоб їхні monitoring teams очікували цей трафік.
- **Legal sign-off**: задокументуйте scope, authorization і stop conditions, якщо simulation може перетнути регульовані rails.

## 5. Telemetry, узгоджена з техніками AADAPT
Інструментуйте telemetry streams так, щоб кожен сценарій створював придатні для дій detection data.<sup>[[2]](#references)</sup>

- **Chain-level traces**: повні call graphs, gas usage, transaction nonces, block timestamps — для відтворення flash-loan bundles, reentrancy-like structures і cross-contract hops.
- **Application/API logs**: пов’яжіть кожну on-chain tx із human або automation identity (session ID, OAuth client, API key, CI job ID), включно з IPs і auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address і reason codes для кожного підпису. Створіть baseline для change windows і high-risk operations.
- **Oracle/feed metadata**: для кожного update — склад data sources, reported value, відхилення від rolling averages, triggered thresholds і використані failover paths.
- **Bridge/swap traces**: зіставляйте lock/mint/unlock events між мережами за допомогою correlation IDs, chain IDs, relayer identity і hop timing.
- **Anomaly markers**: похідні метрики, такі як slippage spikes, abnormal collateralization ratios, unusual gas density або cross-chain velocity.

Позначайте все scenario IDs або synthetic user IDs, щоб analysts могли зіставити observables із технікою AADAPT, яка перевіряється.

## 6. Purple-team loop і метрики зрілості
1. Запустіть сценарій у контрольованому середовищі та зафіксуйте detections (alerts, dashboards, responders paged).<sup>[[2]](#references)</sup>
2. Зіставте кожен крок із конкретними техніками AADAPT та observables, отриманими у chain/app/KMS/oracle/bridge planes.
3. Сформулюйте та розгорніть detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Повторюйте запуск, доки mean time to detect (MTTD) і mean time to contain (MTTC) не відповідатимуть бізнес-толерантності, а playbooks надійно не зупинятимуть втрату цінності.

Відстежуйте зрілість програми за трьома осями:<sup>[[2]](#references)</sup>
- **Visibility**: кожен критичний value path має telemetry у кожному plane.
- **Coverage**: частка пріоритетних технік AADAPT, перевірених end-to-end.
- **Response**: здатність призупиняти контракти, відкликати ключі або заморожувати flows до незворотної втрати.

Типові етапи: (1) завершені value inventory + AADAPT mapping, (2) перший end-to-end сценарій із реалізованими detections, (3) щоквартальні purple-team cycles із розширенням coverage і зменшенням MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Шаблони сценаріїв
Використовуйте ці повторювані blueprints для розробки simulations, які безпосередньо відповідають поведінкам AADAPT.<sup>[[2]](#references)</sup>

### Сценарій A — Flash-loan economic manipulation
- **Мета**: позичити transient capital у межах однієї транзакції, щоб спотворити AMM prices/liquidity і запустити mispriced borrows, liquidations або mints до повернення позики.
- **Виконання**:
1. Створіть fork цільового ланцюга та наповніть pools liquidity, наближеною до production.
2. Позичте великий notional через flash loan.
3. Виконайте calibrated swaps, щоб перетнути price/threshold boundaries, на які спирається lending, vault або derivative logic.
4. Одразу після distortion викличте victim contract (borrow, liquidate, mint) і поверніть flash loan.
- **Вимірювання**: Чи вдалося порушити інваріант? Чи спрацювали slippage/price-deviation monitors, circuit breakers або governance pause hooks? Скільки часу знадобилося analytics, щоб виявити abnormal gas/call graph pattern?

### Сценарій B — Oracle/data-feed poisoning
- **Мета**: визначити, чи можуть manipulated feeds запускати destructive automated actions (mass liquidations, incorrect settlements).
- **Виконання**:
1. У fork/testnet розгорніть malicious feed або змініть aggregator weights/quorum/update cadence за межі допустимого deviation.
2. Дозвольте dependent contracts використати poisoned values і виконати свою стандартну logic.
- **Вимірювання**: out-of-band alerts на рівні feed, активація fallback oracle, enforcement min/max bounds і latency між початком anomaly та response оператора.

### Сценарій C — Credential/signing abuse
- **Мета**: перевірити, чи дає compromise одного signer або automation identity змогу виконувати unauthorized upgrades, parameter changes або treasury drains.
- **Виконання**:
1. Перелічіть identities із sensitive signing rights (operators, CI tokens, service accounts, що викликають KMS/HSM, multisig participants).
2. Simulate compromise (повторно використайте їхні credentials/keys у межах lab scope).
3. Спробуйте privileged actions: upgrade proxies, змінити risk parameters, mint/pause assets або запустити governance proposals.
- **Вимірювання**: Чи створюють KMS/HSM logs anomaly alerts (time-of-day, destination drift, burst of high-risk operations)? Чи можуть policies або multisig thresholds запобігти unilateral abuse? Чи застосовуються throttles/rate limits або додаткові approvals?

### Сценарій D — Cross-chain evasion & traceability gaps
- **Мета**: оцінити, наскільки добре defenders можуть відстежувати та швидко блокувати assets, які відмиваються через bridges, DEX routers і privacy hops.
- **Виконання**:
1. Поєднайте lock/mint operations через поширені bridges, interleave swaps/mixers на кожному hop і зберігайте per-hop correlation IDs.
2. Прискорте transfers, щоб створити навантаження на monitoring latency (multi-hop протягом хвилин/блоків).
- **Вимірювання**: Час для correlation events між telemetry та commercial chain analytics, повнота reconstructed path, здатність визначати choke points для freezing під час реального incident і alert fidelity для abnormal cross-chain velocity/value.

## References

- [1] [AADAPT(TM) Cyber Threat Framework for Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Фреймворк MITRE AADAPT як дорожня карта для Red Team (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
