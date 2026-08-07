# Web3 Red Teaming με επίκεντρο την αξία (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Το matrix MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) καταγράφει συμπεριφορές attackers που χειραγωγούν ψηφιακή αξία και όχι μόνο υποδομές. Αντιμετωπίστε το ως **βασικό πλαίσιο threat modeling**: καταγράψτε κάθε component που μπορεί να κάνει mint, να τιμολογήσει, να εξουσιοδοτήσει ή να δρομολογήσει assets, αντιστοιχίστε αυτά τα touchpoints σε τεχνικές AADAPT και, στη συνέχεια, σχεδιάστε red-team scenarios που μετρούν αν το περιβάλλον μπορεί να αντέξει μη αναστρέψιμες οικονομικές απώλειες.

## 1. Καταγράψτε τα components που περιέχουν αξία
Δημιουργήστε έναν χάρτη όλων όσων μπορούν να επηρεάσουν την κατάσταση αξίας, ακόμη και αν βρίσκονται off-chain.<sup>[[1]](#references)</sup>

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs που χρησιμοποιούνται από bots ή back-office jobs). Καταγράψτε key IDs, policies, automation identities και approval workflows.
- **Admin & upgrade paths** για contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries). Συμπεριλάβετε ποιος/τι μπορεί να τα καλέσει και υπό ποιο quorum ή delay.
- **On-chain protocol logic** που χειρίζεται lending, AMMs, vaults, staking, bridges ή settlement rails. Καταγράψτε τα invariants που θεωρούν δεδομένα (oracle prices, collateral ratios, cadence του rebalance…).
- **Off-chain automation** που δημιουργεί transactions (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Αυτά συχνά διαθέτουν API keys ή service principals που μπορούν να ζητήσουν signatures.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Σημειώστε κάθε upstream πηγή στην οποία βασίζεται η automated risk logic.
- **Bridges και cross-chain routers** (lock/mint contracts, relayers, settlement jobs) που συνδέουν chains ή custodial stacks.

Παραδοτέο: ένα value-flow diagram που δείχνει πώς μετακινούνται τα assets, ποιος εξουσιοδοτεί τη μετακίνηση και ποια external signals επηρεάζουν τη business logic.

## 2. Αντιστοιχίστε τα components σε AADAPT behaviors
Μετατρέψτε την ταξινομία AADAPT σε συγκεκριμένους attack candidates για κάθε component.<sup>[[1]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Αυτή η αντιστοίχιση διασφαλίζει ότι ελέγχετε όχι μόνο τα contracts, αλλά και κάθε identity/automation που μπορεί έμμεσα να κατευθύνει αξία.

## 3. Ιεραρχήστε με βάση τη feasibility του attacker και το business impact

1. **Operational weaknesses**: εκτεθειμένα CI credentials, υπερβολικά προνομιούχοι IAM roles, λανθασμένα ρυθμισμένα KMS policies, automation accounts που μπορούν να ζητήσουν arbitrary signatures, public buckets με bridge configs κ.λπ.
2. **Value-specific weaknesses**: εύθραυστες oracle parameters, upgradable contracts χωρίς approvals από πολλαπλά parties, flash-loan sensitive liquidity, governance actions που παρακάμπτουν timelocks.

Δουλέψτε την ουρά όπως ένας adversary: ξεκινήστε από τα operational footholds που θα μπορούσαν να επιτύχουν σήμερα και, στη συνέχεια, προχωρήστε σε βαθύτερα protocol/economic manipulation paths.<sup>[[1]](#references)</sup>

## 4. Εκτελέστε σε controlled, production-realistic environments
- **Forked mainnets / isolated testnets**: αναπαραγάγετε bytecode, storage και liquidity, ώστε τα flash-loan paths, τα oracle drifts και τα bridge flows να εκτελούνται end-to-end χωρίς να αγγίζουν πραγματικά funds.<sup>[[1]](#references)</sup>
- **Blast-radius planning**: ορίστε circuit breakers, pausable modules, rollback runbooks και test-only admin keys πριν από την ενεργοποίηση ενός scenario.
- **Stakeholder coordination**: ενημερώστε custodians, oracle operators, bridge partners και compliance, ώστε οι monitoring teams τους να αναμένουν την κίνηση.
- **Legal sign-off**: τεκμηριώστε το scope, την authorization και τις stop conditions όταν οι simulations ενδέχεται να διασχίσουν regulated rails.

## 5. Telemetry ευθυγραμμισμένο με τις τεχνικές AADAPT
Εγκαταστήστε telemetry streams, ώστε κάθε scenario να παράγει actionable detection data.<sup>[[1]](#references)</sup>

- **Chain-level traces**: πλήρη call graphs, gas usage, transaction nonces, block timestamps — για την ανακατασκευή flash-loan bundles, reentrancy-like structures και cross-contract hops.
- **Application/API logs**: συνδέστε κάθε on-chain tx με ένα human ή automation identity (session ID, OAuth client, API key, CI job ID), μαζί με IPs και auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address και reason codes για κάθε signature. Δημιουργήστε baseline για change windows και high-risk operations.
- **Oracle/feed metadata**: σύνθεση data source ανά update, reported value, deviation από rolling averages, thresholds που ενεργοποιήθηκαν και failover paths που χρησιμοποιήθηκαν.
- **Bridge/swap traces**: συσχετίστε lock/mint/unlock events μεταξύ chains με correlation IDs, chain IDs, relayer identity και hop timing.
- **Anomaly markers**: derived metrics όπως slippage spikes, abnormal collateralization ratios, unusual gas density ή cross-chain velocity.

Προσθέστε παντού scenario IDs ή synthetic user IDs, ώστε οι analysts να μπορούν να ευθυγραμμίζουν τα observables με την AADAPT technique που δοκιμάζεται.

## 6. Purple-team loop & maturity metrics
1. Εκτελέστε το scenario στο controlled environment και καταγράψτε τα detections (alerts, dashboards, responders που ειδοποιήθηκαν).<sup>[[1]](#references)</sup>
2. Αντιστοιχίστε κάθε βήμα στις συγκεκριμένες AADAPT techniques και στα observables που παρήχθησαν στα chain/app/KMS/oracle/bridge planes.
3. Διατυπώστε και αναπτύξτε detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Εκτελέστε ξανά μέχρι το mean time to detect (MTTD) και το mean time to contain (MTTC) να ικανοποιούν τα business tolerances και τα playbooks να σταματούν αξιόπιστα την απώλεια αξίας.

Παρακολουθήστε την ωριμότητα του προγράμματος σε τρεις άξονες:<sup>[[1]](#references)</sup>
- **Visibility**: κάθε critical value path διαθέτει telemetry σε κάθε plane.
- **Coverage**: ποσοστό των prioritized AADAPT techniques που δοκιμάζονται end-to-end.
- **Response**: δυνατότητα παύσης contracts, ανάκλησης keys ή παγώματος flows πριν από μη αναστρέψιμη απώλεια.

Τυπικά milestones: (1) ολοκληρωμένο value inventory + AADAPT mapping, (2) πρώτο end-to-end scenario με υλοποιημένα detections, (3) quarterly purple-team cycles που επεκτείνουν το coverage και μειώνουν τα MTTD/MTTC.<sup>[[1]](#references)</sup>

## 7. Scenario templates
Χρησιμοποιήστε αυτά τα επαναχρησιμοποιήσιμα blueprints για να σχεδιάσετε simulations που αντιστοιχούν άμεσα σε AADAPT behaviors.<sup>[[1]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: δανειστείτε transient capital μέσα σε ένα transaction, ώστε να παραμορφώσετε AMM prices/liquidity και να ενεργοποιήσετε mispriced borrows, liquidations ή mints πριν από την αποπληρωμή.
- **Execution**:
1. Κάντε fork το target chain και τροφοδοτήστε τα pools με production-like liquidity.
2. Δανειστείτε μεγάλο notional μέσω flash loan.
3. Εκτελέστε calibrated swaps για να περάσετε τα price/threshold boundaries στα οποία βασίζεται η lending, vault ή derivative logic.
4. Καλέστε το victim contract αμέσως μετά την παραμόρφωση (borrow, liquidate, mint) και αποπληρώστε το flash loan.
- **Measurement**: Επιτεύχθηκε η παραβίαση του invariant; Ενεργοποιήθηκαν slippage/price-deviation monitors, circuit breakers ή governance pause hooks; Πόσος χρόνος χρειάστηκε μέχρι τα analytics να επισημάνουν το abnormal gas/call graph pattern;

### Scenario B – Oracle/data-feed poisoning
- **Objective**: προσδιορίστε αν manipulated feeds μπορούν να ενεργοποιήσουν destructive automated actions (mass liquidations, incorrect settlements).
- **Execution**:
1. Στο fork/testnet, αναπτύξτε ένα malicious feed ή προσαρμόστε τα aggregator weights/quorum/update cadence πέρα από το tolerated deviation.
2. Αφήστε τα dependent contracts να καταναλώσουν τις poisoned values και να εκτελέσουν τη standard logic τους.
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement και latency μεταξύ anomaly onset και operator response.

### Scenario C – Credential/signing abuse
- **Objective**: ελέγξτε αν η παραβίαση ενός signer ή automation identity επιτρέπει unauthorized upgrades, parameter changes ή treasury drains.
- **Execution**:
1. Καταγράψτε τα identities με sensitive signing rights (operators, CI tokens, service accounts που καλούν KMS/HSM, multisig participants).
2. Προσομοιώστε compromise (επαναχρησιμοποιήστε τα credentials/keys τους εντός του lab scope).
3. Επιχειρήστε privileged actions: upgrade proxies, change risk parameters, mint/pause assets ή trigger governance proposals.
- **Measurement**: Προκαλούν τα KMS/HSM logs anomaly alerts (time-of-day, destination drift, burst of high-risk operations); Μπορούν τα policies ή τα multisig thresholds να αποτρέψουν unilateral abuse; Εφαρμόζονται throttles/rate limits ή additional approvals;

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: αξιολογήστε πόσο αποτελεσματικά μπορούν οι defenders να εντοπίσουν και να ανακόψουν assets που γίνονται rapidly laundered μέσω bridges, DEX routers και privacy hops.
- **Execution**:
1. Συνδέστε lock/mint operations σε common bridges, παρεμβάλλετε swaps/mixers σε κάθε hop και διατηρήστε per-hop correlation IDs.
2. Επιταχύνετε τα transfers για να πιέσετε το monitoring latency (multi-hop μέσα σε λεπτά/blocks).
- **Measurement**: Χρόνος για τη συσχέτιση events μεταξύ telemetry και commercial chain analytics, πληρότητα του reconstructed path, δυνατότητα εντοπισμού choke points για freezing σε πραγματικό incident και alert fidelity για abnormal cross-chain velocity/value.

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
