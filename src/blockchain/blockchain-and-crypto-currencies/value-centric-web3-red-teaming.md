# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

The MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrix captures attacker behaviors that manipulate digital value rather than just infrastructure. Treat it as a **threat-modeling backbone**: enumerate every component that can mint, price, authorize, or route assets, map those touchpoints to AADAPT techniques, and then drive red-team scenarios that measure whether the environment can resist irreversible economic loss.

## 1. Inventory value-bearing components
Build a map of everything that can influence value state, even if it is off-chain.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). Capture key IDs, policies, automation identities, and approval workflows.
- **Admin & upgrade paths** for contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). Include who/what can call them, and under which quorum or delay.
- **On-chain protocol logic** handling lending, AMMs, vaults, staking, bridges, or settlement rails. Document the invariants they assume (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** that builds transactions (market-making bots, CI/CD pipelines, cron jobs, serverless functions). These often hold API keys or service principals that can request signatures.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Note every upstream relied on by automated risk logic.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) tying chains or custodial stacks together.

Deliverable: a value-flow diagram showing how assets move, who authorizes movement, and which external signals influence business logic.

## 2. Map components to AADAPT behaviors
Translate the AADAPT taxonomy into concrete attack candidates per component.

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

This mapping ensures you test not just the contracts, but every identity/automation that can indirectly steer value.

## 3. Prioritize by attacker feasibility vs. business impact

1. **Operational weaknesses**: exposed CI credentials, over-privileged IAM roles, misconfigured KMS policies, automation accounts that can request arbitrary signatures, public buckets with bridge configs, etc.
2. **Value-specific weaknesses**: fragile oracle parameters, upgradable contracts without multi-party approvals, flash-loan sensitive liquidity, governance actions that bypass timelocks.

Work the queue like an adversary: start with the operational footholds that could succeed today, then progress into deep protocol/economic manipulation paths.

## 4. Execute in controlled, production-realistic environments
- **Forked mainnets / isolated testnets**: replicate bytecode, storage, and liquidity so flash-loan paths, oracle drifts, and bridge flows run end-to-end without touching real funds.
- **Blast-radius planning**: define circuit breakers, pausable modules, rollback runbooks, and test-only admin keys before detonating a scenario.
- **Stakeholder coordination**: notify custodians, oracle operators, bridge partners, and compliance so their monitoring teams expect the traffic.
- **Legal sign-off**: document scope, authorization, and stop conditions when simulations could cross regulated rails.

## 5. Telemetry aligned with AADAPT techniques
Instrument telemetry streams so every scenario produces actionable detection data.

- **Chain-level traces**: full call graphs, gas usage, transaction nonces, block timestamps—to reconstruct flash-loan bundles, reentrancy-like structures, and cross-contract hops.
- **Application/API logs**: tie each on-chain tx back to a human or automation identity (session ID, OAuth client, API key, CI job ID) with IPs and auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address, and reason codes for every signature. Baseline change windows and high-risk operations.
- **Oracle/feed metadata**: per-update data source composition, reported value, deviation from rolling averages, thresholds triggered, and failover paths exercised.
- **Bridge/swap traces**: correlate lock/mint/unlock events across chains with correlation IDs, chain IDs, relayer identity, and hop timing.
- **Anomaly markers**: derived metrics such as slippage spikes, abnormal collateralization ratios, unusual gas density, or cross-chain velocity.

Tag everything with scenario IDs or synthetic user IDs so analysts can align observables with the AADAPT technique being exercised.

## 6. Purple-team loop & maturity metrics
1. Run the scenario in the controlled environment and capture detections (alerts, dashboards, responders paged).
2. Map each step to the specific AADAPT techniques plus the observables produced in chain/app/KMS/oracle/bridge planes.
3. Formulate and deploy detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Re-run until mean time to detect (MTTD) and mean time to contain (MTTC) meet business tolerances and playbooks reliably halt the value loss.

Track program maturity on three axes:
- **Visibility**: every critical value path has telemetry in each plane.
- **Coverage**: proportion of prioritized AADAPT techniques exercised end-to-end.
- **Response**: ability to pause contracts, revoke keys, or freeze flows before irreversible loss.

Typical milestones: (1) completed value inventory + AADAPT mapping, (2) first end-to-end scenario with detections implemented, (3) quarterly purple-team cycles expanding coverage and driving down MTTD/MTTC.

## 7. Scenario templates
Use these repeatable blueprints to design simulations that map directly to AADAPT behaviors.

### Scenario A – Flash-loan economic manipulation
- **Objective**: borrow transient capital inside one transaction to distort AMM prices/liquidity and trigger mispriced borrows, liquidations, or mints before repaying.
- **Execution**:
1. Fork the target chain and seed pools with production-like liquidity.
2. Borrow large notional via flash loan.
3. Perform calibrated swaps to cross price/threshold boundaries relied on by lending, vault, or derivative logic.
4. Invoke the victim contract immediately after the distortion (borrow, liquidate, mint) and repay the flash loan.
- **Measurement**: Did the invariant violation succeed? Were slippage/price-deviation monitors, circuit breakers, or governance pause hooks triggered? How long until analytics flagged the abnormal gas/call graph pattern?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: determine whether manipulated feeds can trigger destructive automated actions (mass liquidations, incorrect settlements).
- **Execution**:
1. In the fork/testnet, deploy a malicious feed or adjust aggregator weights/quorum/update cadence beyond tolerated deviation.
2. Let dependent contracts consume the poisoned values and execute their standard logic.
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement, and latency between anomaly onset and operator response.

### Scenario C – Credential/signing abuse
- **Objective**: test whether compromising a single signer or automation identity enables unauthorized upgrades, parameter changes, or treasury drains.
- **Execution**:
1. Enumerate identities with sensitive signing rights (operators, CI tokens, service accounts invoking KMS/HSM, multisig participants).
2. Simulate compromise (re-use their credentials/keys within the lab scope).
3. Attempt privileged actions: upgrade proxies, change risk parameters, mint/pause assets, or trigger governance proposals.
- **Measurement**: Do KMS/HSM logs raise anomaly alerts (time-of-day, destination drift, burst of high-risk operations)? Can policies or multisig thresholds prevent unilateral abuse? Are throttles/rate limits or additional approvals enforced?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: evaluate how well defenders can trace and interdict assets rapidly laundered across bridges, DEX routers, and privacy hops.
- **Execution**:
1. Chain together lock/mint operations across common bridges, interleave swaps/mixers on each hop, and maintain per-hop correlation IDs.
2. Accelerate transfers to stress monitoring latency (multi-hop within minutes/blocks).
- **Measurement**: Time to correlate events across telemetry + commercial chain analytics, completeness of the reconstructed path, ability to identify choke points for freezing in a real incident, and alert fidelity for abnormal cross-chain velocity/value.

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
