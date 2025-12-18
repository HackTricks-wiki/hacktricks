# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Матріца MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) фіксує поведінку нападників, що маніпулюють цифровою вартістю, а не лише інфраструктурою. Розглядайте її як каркас для threat-modeling: перелікуйте кожен компонент, що може mint, price, authorize або route assets, зіставляйте ці точки дотику з техніками AADAPT і будьте готові проводити red-team сценарії, які вимірюють здатність середовища протистояти незворотним економічним втратам.

## 1. Inventory value-bearing components
Побудуйте карту всього, що може впливати на стан вартості, навіть якщо це off-chain.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). Зафіксуйте key IDs, політики, automation identities і approval workflows.
- **Admin & upgrade paths** для контрактів (proxy admins, governance timelocks, emergency pause keys, parameter registries). Включіть хто/що може їх викликати і за яким quorum або delay.
- **On-chain protocol logic** що обробляє lending, AMMs, vaults, staking, bridges або settlement rails. Документуйте інваріанти, на яких вони ґрунтуються (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** що створює транзакції (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Часто вони тримають API keys або service principals, які можуть запитувати підписи.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Занотуйте кожне upstream, на яке спирається автоматизована логіка ризику.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs), що зв'язують ланцюги або custodial stacks.

Deliverable: value-flow діаграма, яка показує, як пересуваються assets, хто авторизує рух і які зовнішні сигнали впливають на бізнес-логіку.

## 2. Map components to AADAPT behaviors
Перетворіть таксономію AADAPT на конкретні кандидати для атак по кожному компоненту.

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Це зіставлення гарантує, що ви тестуєте не лише контракти, але й кожну ідентичність/автоматизацію, яка може опосередковано керувати вартістю.

## 3. Prioritize by attacker feasibility vs. business impact

1. **Operational weaknesses**: відкриті CI credentials, over-privileged IAM roles, misconfigured KMS policies, automation accounts, що можуть request arbitrary signatures, public buckets з bridge configs тощо.
2. **Value-specific weaknesses**: крихкі oracle parameters, upgradable contracts без multi-party approvals, liquidity чутлива до flash-loan, governance actions що обходять timelocks.

Працюйте чергою як нападник: почніть з operational footholds, які можуть спрацювати сьогодні, а потім просувайтесь до глибших протокол/економічних маніпуляцій.

## 4. Execute in controlled, production-realistic environments
- **Forked mainnets / isolated testnets**: відтворіть bytecode, storage і liquidity, щоб flash-loan paths, oracle drifts і bridge flows працювали end-to-end без втручання в реальні кошти.
- **Blast-radius planning**: визначте circuit breakers, pausable modules, rollback runbooks і test-only admin keys перед запуском сценарію.
- **Stakeholder coordination**: повідомте custodians, oracle operators, bridge partners і compliance, щоб їхні monitoring teams очікували трафік.
- **Legal sign-off**: задокументуйте scope, authorization і stop conditions, коли симуляції можуть перетинати регульовані межі.

## 5. Telemetry aligned with AADAPT techniques
Інструментуйте telemetry streams так, щоб кожен сценарій давав придатні для дій дані виявлення.

- **Chain-level traces**: повні call graphs, gas usage, transaction nonces, block timestamps — щоб реконструювати flash-loan bundles, reentrancy-like структури і cross-contract hops.
- **Application/API logs**: зв’язуйте кожну on-chain tx з людиною або automation identity (session ID, OAuth client, API key, CI job ID) з IP і auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address і reason codes для кожного підпису. Базуйте вікна змін і high-risk операції.
- **Oracle/feed metadata**: для кожного оновлення — composition джерел, reported value, відхилення від rolling averages, thresholds що спрацювали, і failover paths, які були задіяні.
- **Bridge/swap traces**: корелюйте lock/mint/unlock події між ланцюгами з correlation IDs, chain IDs, relayer identity і hop timing.
- **Anomaly markers**: виведені метрики, такі як slippage spikes, аномальні collateralization ratios, незвична gas density або cross-chain velocity.

Позначайте все scenario IDs або synthetic user IDs, щоб аналітики могли зіставити спостережуване з технікою AADAPT, що відпрацьовується.

## 6. Purple-team loop & maturity metrics
1. Запустіть сценарій у контрольованому середовищі й зафіксуйте detections (alerts, dashboards, responders paged).
2. Зіставте кожен крок зі специфічними техніками AADAPT плюс observable-ми в chain/app/KMS/oracle/bridge площинах.
3. Сформулюйте й розгорніть detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Повторюйте, поки mean time to detect (MTTD) і mean time to contain (MTTC) не відповідатимуть бізнес-толерансам і playbooks надійно не зупинятимуть втрату вартості.

Відстежуйте зрілість програми по трьох осях:
- **Visibility**: кожен критичний value path має telemetry в кожній площині.
- **Coverage**: частка пріоритетних технік AADAPT, відпрацьованих end-to-end.
- **Response**: здатність призупинити контракти, revoke keys або freeze flows до незворотних втрат.

Типові milestones: (1) completed value inventory + AADAPT mapping, (2) перший end-to-end сценарій з реалізованими детекціями, (3) квартальні purple-team цикли, що розширюють coverage і зменшують MTTD/MTTC.

## 7. Scenario templates
Використовуйте ці повторювані шаблони для дизайну симуляцій, що безпосередньо відповідають поведінці AADAPT.

### Scenario A – Flash-loan economic manipulation
- **Objective**: borrow transient capital inside one transaction, щоб спотворити AMM prices/liquidity і спровокувати mispriced borrows, liquidations або mints перед repayment.
- **Execution**:
1. Fork the target chain і seed pools production-like liquidity.
2. Borrow large notional via flash loan.
3. Виконати калібровані swaps, щоб перетнути price/threshold boundaries, на які спираються lending, vault або derivative logic.
4. Викликати victim contract відразу після distortion (borrow, liquidate, mint) і repay flash loan.
- **Measurement**: Чи вдалося порушити інваріанти? Чи спрацювали slippage/price-deviation monitors, circuit breakers або governance pause hooks? Скільки часу знадобилося аналітиці, щоб помітити аномальну gas/call graph pattern?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: перевірити, чи можуть маніпульовані feeds спровокувати руйнівні автоматизовані дії (масові liquidations, incorrect settlements).
- **Execution**:
1. У fork/testnet розгорнути malicious feed або відкоригувати aggregator weights/quorum/update cadence поза tolerated deviation.
2. Дозволити dependent contracts споживати отруєні значення і виконувати стандартну логіку.
- **Measurement**: Feed-level out-of-band alerts, активація fallback oracle, enforcement min/max bounds і латентність між onset аномалії і operator response.

### Scenario C – Credential/signing abuse
- **Objective**: протестувати, чи дозволяє компрометація одного signer або automation identity виконувати unauthorized upgrades, parameter changes або treasury drains.
- **Execution**:
1. Перелічити identities з чутливими signing rights (operators, CI tokens, service accounts, що викликають KMS/HSM, multisig participants).
2. Симулювати compromise (re-use їхні credentials/keys в межах лабораторного scope).
3. Спробувати привілейовані дії: upgrade proxies, change risk parameters, mint/pause assets або запустити governance proposals.
- **Measurement**: Чи генерують KMS/HSM logs anomaly alerts (time-of-day, destination drift, burst of high-risk operations)? Чи можуть policies або multisig thresholds запобігти unilateral abuse? Чи є throttles/rate limits або додаткові approvals?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: оцінити, наскільки оперативно defenders можуть трасувати і перешкоджати rapid laundering assets через bridges, DEX routers і privacy hops.
- **Execution**:
1. З'єднати lock/mint operations через поширені bridges, interleave swaps/mixers на кожному hop і зберігати per-hop correlation IDs.
2. Прискорити трансфери, щоб навантажити monitoring latency (multi-hop within minutes/blocks).
- **Measurement**: Час на кореляцію подій через telemetry + commercial chain analytics, повнота реконструйованого шляху, здатність ідентифікувати choke points для freeze в реальному інциденті і fidelity alert-ів для аномальної cross-chain velocity/value.

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
