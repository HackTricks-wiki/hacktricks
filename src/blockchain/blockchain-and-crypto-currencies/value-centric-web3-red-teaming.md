# Wertzentriertes Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Die MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) Matrix erfasst Angreiferverhalten, das digitalen Wert manipuliert statt nur Infrastruktur. Betrachte sie als ein **Rückgrat für die Bedrohungsmodellierung**: liste jede Komponente auf, die Assets minten, bepreisen, autorisieren oder routen kann, mappe diese Touchpoints auf AADAPT-Techniken und leite daraus Red-Team-Szenarien ab, die messen, ob die Umgebung irreversible wirtschaftliche Verluste verhindern kann.

## 1. Inventar werttragender Komponenten
Erstelle eine Karte von allem, was den Wertzustand beeinflussen kann, auch wenn es off-chain ist.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). Erfasse Key-IDs, Policies, Automation-Identitäten und Approval-Workflows.
- **Admin & upgrade paths** für Contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). Schließe ein, wer/was sie aufrufen kann und unter welchem Quorum oder Delay.
- **On-chain protocol logic** die Lending, AMMs, vaults, Staking, Bridges oder Settlement-Rails handhabt. Dokumentiere die angenommenen Invarianten (oracle prices, collateral ratios, rebalance cadence …).
- **Off-chain automation** die Transaktionen baut (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Diese halten oft API-Keys oder Service-Principals, die Signaturen anfordern können.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Notiere jedes Upstream, auf das automatisierte Risk-Logik vertraut.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs), die Chains oder Custodial-Stacks verbinden.

Deliverable: ein Value-Flow-Diagramm, das zeigt, wie Assets sich bewegen, wer Bewegungen autorisiert und welche externen Signale die Geschäftslogik beeinflussen.

## 2. Komponenten zu AADAPT-Verhalten mappen
Übersetze die AADAPT-Taxonomie in konkrete Angriffskandidaten pro Komponente.

| Komponente | Primärer AADAPT-Fokus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Dieses Mapping stellt sicher, dass du nicht nur die Contracts testest, sondern jede Identität/Automation, die indirekt Wert steuern kann.

## 3. Priorisieren nach Angreifer-Findbarkeit vs. Business-Impact

1. **Operational weaknesses**: exponierte CI-Credentials, over-privileged IAM-Rollen, falsch konfigurierte KMS-Policies, Automation-Accounts, die beliebige Signaturen anfordern können, public buckets mit Bridge-Konfigurationen, etc.
2. **Value-specific weaknesses**: fragile Oracle-Parameter, upgradable Contracts ohne Multi-Party-Approvals, flash-loan-anfällige Liquidität, Governance-Aktionen, die Timelocks umgehen.

Arbeite die Queue wie ein Adversary: beginne mit den operationalen Fußfassen, die heute funktionieren könnten, und arbeite dich zu tiefgreifenden Protokoll-/ökonomischen Manipulationspfaden vor.

## 4. In kontrollierten, produktionsrealistischen Umgebungen ausführen
- **Forked mainnets / isolated testnets**: repliziere Bytecode, Storage und Liquidity, sodass flash-loan-Pfade, oracle-drifts und Bridge-Flows end-to-end laufen, ohne echte Funds zu berühren.
- **Blast-radius planning**: definiere Circuit Breakers, pausable Modules, Rollback-Runbooks und Test-only-Admin-Keys bevor du ein Szenario detonierst.
- **Stakeholder coordination**: informiere Custodians, Oracle-Operatoren, Bridge-Partner und Compliance, damit deren Monitoring-Teams den Traffic erwarten.
- **Legal sign-off**: dokumentiere Scope, Authorization und Stop-Conditions, wenn Simulationen regulierte Schienen überschreiten könnten.

## 5. Telemetrie ausrichten auf AADAPT-Techniken
Instrumentiere Telemetrie-Streams so, dass jedes Szenario verwertbare Detection-Daten liefert.

- **Chain-level traces**: komplette Call-Graphs, Gas-Usage, Transaction-Nonces, Block-Timestamps — um flash-loan-Bundles, reentrancy-ähnliche Strukturen und Cross-Contract-Hops zu rekonstruieren.
- **Application/API logs**: verknüpfe jede on-chain tx mit einer menschlichen oder automatisierten Identität (Session-ID, OAuth-Client, API-Key, CI-Job-ID) inklusive IPs und Auth-Methoden.
- **KMS/HSM logs**: Key-ID, Caller-Principal, Policy-Result, Destination-Address und Reason-Codes für jede Signatur. Baseline-Änderungsfenster und High-Risk-Operationen erfassen.
- **Oracle/feed metadata**: pro-Update Datenquellenkomposition, reported value, Abweichung von rollierenden Durchschnitten, ausgelöste Thresholds und ausgeübte Failover-Pfade.
- **Bridge/swap traces**: korreliere lock/mint/unlock-Events über Chains hinweg mit Correlation-IDs, Chain-IDs, Relayer-Identität und Hop-Timing.
- **Anomaly markers**: abgeleitete Metriken wie Slippage-Spikes, abnormale Collateralization-Ratios, ungewöhnliche Gas-Dichte oder Cross-Chain-Velocity.

Tagge alles mit Scenario-IDs oder synthetic User-IDs, damit Analysten Observables mit der geübten AADAPT-Technik abgleichen können.

## 6. Purple-team loop & Reife-Metriken
1. Führe das Szenario in der kontrollierten Umgebung aus und erfasse Detections (Alerts, Dashboards, Pager an Responders).
2. Mappe jeden Schritt zu spezifischen AADAPT-Techniken plus zu den in Chain/App/KMS/Oracle/Bridge erzeugten Observables.
3. Formuliere und deploye Detection-Hypothesen (Threshold-Rules, Correlation-Searches, Invariant-Checks).
4. Wiederhole, bis Mean Time to Detect (MTTD) und Mean Time to Contain (MTTC) die Business-Toleranzen erfüllen und Playbooks zuverlässig den Wertverlust stoppen.

Verfolge Programmreife an drei Achsen:
- **Visibility**: jeder kritische Wertpfad hat Telemetrie in jedem Plane.
- **Coverage**: Anteil prioritärer AADAPT-Techniken, die end-to-end geübt wurden.
- **Response**: Fähigkeit, Contracts zu pausieren, Keys zu widerrufen oder Flows zu frieren bevor irreversible Verluste entstehen.

Typische Meilensteine: (1) abgeschlossenes Value-Inventar + AADAPT-Mapping, (2) erstes End-to-End-Szenario mit implementierten Detections, (3) vierteljährliche Purple-Team-Zyklen zur Erweiterung der Coverage und Reduktion von MTTD/MTTC.

## 7. Szenario-Templates
Nutze diese wiederholbaren Blaupausen, um Simulationen zu entwerfen, die direkt auf AADAPT-Verhalten abbilden.

### Szenario A – Flash-loan economic manipulation
- **Objective**: borrow transient capital inside one transaction to distort AMM prices/liquidity and trigger mispriced borrows, liquidations, or mints before repaying.
- **Execution**:
1. Forke die Ziel-Chain und seed Pools mit produktionsähnlicher Liquidity.
2. Borrow large notional via flash loan.
3. Führe kalibrierte Swaps durch, um Preis-/Threshold-Grenzen zu überschreiten, auf die Lending-, Vault- oder Derivate-Logik vertraut.
4. Rufe das Victim-Contract unmittelbar nach der Verzerrung auf (borrow, liquidate, mint) und repaie den flash loan.
- **Measurement**: Ist die Invariant-Verletzung gelungen? Wurden Slippage/Price-Deviation-Monitore, Circuit-Breaker oder Governance-Pause-Hooks ausgelöst? Wie lange bis Analytics das abnorme Gas-/Call-Graph-Muster gemeldet hat?

### Szenario B – Oracle/data-feed poisoning
- **Objective**: determine whether manipulated feeds can trigger destructive automated actions (mass liquidations, incorrect settlements).
- **Execution**:
1. Deploy in der Fork/Testnet eine malicious feed oder passe Aggregator-Gewichte/quorum/update cadence außerhalb tolerierter Deviationen an.
2. Lasse abhängige Contracts die vergifteten Werte konsumieren und ihre Standard-Logik ausführen.
- **Measurement**: Feed-Level Out-of-Band-Alerts, Activation von Fallback-Oracles, Durchsetzung von Min/Max-Bounds und Latenz zwischen Anomalie-Beginn und Operator-Response.

### Szenario C – Credential/signing abuse
- **Objective**: test whether compromising a single signer or automation identity enables unauthorized upgrades, parameter changes, or treasury drains.
- **Execution**:
1. Enumeriere Identitäten mit sensitiven Signing-Rechten (Operatoren, CI-Tokens, Service-Accounts, die KMS/HSM aufrufen, multisig-Teilnehmer).
2. Simuliere Kompromittierung (Wiederverwendung ihrer Credentials/Keys im Lab-Scope).
3. Versuche privilegierte Aktionen: upgrade Proxies, change Risk-Parameter, mint/pause Assets oder trigger Governance-Proposals.
- **Measurement**: Melden KMS/HSM-Logs Anomalie-Alerts (Time-of-Day, Destination-Drift, Burst von High-Risk-Operationen)? Können Policies oder multisig-Thresholds unilateralen Missbrauch verhindern? Werden Throttles/Rate-Limits oder zusätzliche Approvals durchgesetzt?

### Szenario D – Cross-chain evasion & traceability gaps
- **Objective**: evaluate how well defenders can trace and interdict assets rapidly laundered across bridges, DEX routers, and privacy hops.
- **Execution**:
1. Verkette lock/mint-Operationen über gängige Bridges, interleive Swaps/Mixer in jedem Hop und halte per-hop Correlation-IDs.
2. Beschleunige Transfers, um Monitoring-Latenz zu stressen (multi-hop innerhalb von Minuten/Blocks).
- **Measurement**: Zeit, Events über Telemetrie + kommerzielle Chain-Analytics zu korrelieren, Vollständigkeit des rekonstruierten Pfads, Fähigkeit, in einem echten Vorfall Choke-Points zum Einfrieren zu identifizieren, und Alert-Fidelity für abnormale Cross-Chain-Velocity/Value.

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
