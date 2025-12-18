# Web3 Red Teaming με επίκεντρο την αξία (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Το MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrix αποτυπώνει συμπεριφορές επιτιθέμενων που χειραγωγούν ψηφιακή αξία αντί απλώς την υποδομή. Θεωρήστε το ως ένα backbone για threat-modeling: καταγράψτε κάθε στοιχείο που μπορεί να mint, τιμολογήσει, εξουσιοδοτήσει ή δρομολογήσει assets, αντιστοιχίστε αυτά τα touchpoints σε τεχνικές AADAPT και σχεδιάστε red-team σενάρια που μετρούν αν το περιβάλλον μπορεί να αντισταθεί σε μόνιμη οικονομική απώλεια.

## 1. Καταγραφή συστατικών που φέρουν αξία
Χαρτογραφήστε τα πάντα που μπορούν να επηρεάσουν την κατάσταση αξίας, ακόμα κι αν είναι off-chain.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). Καταγράψτε key IDs, policies, automation identities και approval workflows.
- **Admin & upgrade paths** για συμβόλαια (proxy admins, governance timelocks, emergency pause keys, parameter registries). Συμπεριλάβετε ποιος/τι μπορεί να τα καλέσει και υπό ποιο quorum ή delay.
- **On-chain protocol logic** που χειρίζεται lending, AMMs, vaults, staking, bridges, ή settlement rails. Τεκμηριώστε τα invariants που υποθέτουν (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** που κατασκευάζει transactions (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Συχνά αυτά κρατούν API keys ή service principals που μπορούν να αιτηθούν signatures.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Σημειώστε κάθε upstream σε όποιο βασίζεται η αυτοματοποιημένη λογική ρίσκου.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) που συνδέουν chains ή custodial stacks.

Παράδοση: ένα value-flow διάγραμμα που δείχνει πώς κινούνται τα assets, ποιος εξουσιοδοτεί την κίνηση και ποια εξωτερικά σήματα επηρεάζουν τη business logic.

## 2. Αντιστοίχιση συστατικών σε συμπεριφορές AADAPT
Μεταφράστε την ταξινόμηση AADAPT σε συγκεκριμένους υποψήφιους επιθέσεων ανά συστατικό.

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Αυτή η αντιστοίχιση διασφαλίζει ότι δοκιμάζετε όχι μόνο τα contracts, αλλά και κάθε identity/automation που μπορεί έμμεσα να οδηγήσει την αξία.

## 3. Ιεράρχηση με βάση τη δυνατότητα επιτιθέμενου vs. επιχειρησιακή επίπτωση

1. **Operational weaknesses**: εκτεθειμένα CI credentials, over-privileged IAM roles, misconfigured KMS policies, automation accounts που μπορούν να αιτηθούν arbitrary signatures, public buckets με bridge configs, κ.λπ.
2. **Value-specific weaknesses**: ευπαθή oracle parameters, upgradable contracts χωρίς multi-party approvals, flash-loan sensitive liquidity, governance actions που παρακάμπτουν timelocks.

Επεξεργαστείτε τη λίστα όπως θα έκανε ένας αντίπαλος: ξεκινήστε με τα operational footholds που θα μπορούσαν να πετύχουν σήμερα και μετά προχωρήστε σε βαθύτερες διαδρομές πρωτοκόλλου/οικονομικής χειραγώγησης.

## 4. Εκτέλεση σε ελεγχόμενα, παραγωγικά ρεαλιστικά περιβάλλοντα
- **Forked mainnets / isolated testnets**: αναπαραχθείτε bytecode, storage και liquidity ώστε flash-loan paths, oracle drifts και bridge flows να τρέξουν end-to-end χωρίς να αγγίξουν πραγματικά funds.
- **Blast-radius planning**: ορίστε circuit breakers, pausable modules, rollback runbooks και test-only admin keys πριν εκτελέσετε ένα σενάριο.
- **Stakeholder coordination**: ενημερώστε custodians, oracle operators, bridge partners και compliance ώστε οι monitoring teams να περιμένουν την κίνηση.
- **Legal sign-off**: τεκμηριώστε scope, authorization και stop conditions όταν οι προσομοιώσεις μπορούν να διασχίσουν regulated rails.

## 5. Telemetry ευθυγραμμισμένη με τεχνικές AADAPT
Εξοπλίστε streams telemetry ώστε κάθε σενάριο να παράγει αξιοποιήσιμα detection δεδομένα.

- **Chain-level traces**: πλήρη call graphs, gas usage, transaction nonces, block timestamps—για να ανασυνθέσετε flash-loan bundles, reentrancy-like δομές και cross-contract hops.
- **Application/API logs**: συνδέστε κάθε on-chain tx με ανθρώπινη ή αυτοματοποιημένη identity (session ID, OAuth client, API key, CI job ID) με IPs και auth methods.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address και reason codes για κάθε signature. Καταγράψτε baseline change windows και high-risk operations.
- **Oracle/feed metadata**: ανά-update σύνθεση δεδομένων, αναφερόμενη τιμή, απόκλιση από rolling averages, thresholds που ενεργοποιήθηκαν και failover paths που δοκιμάστηκαν.
- **Bridge/swap traces**: συσχετίστε lock/mint/unlock events across chains με correlation IDs, chain IDs, relayer identity και hop timing.
- **Anomaly markers**: παράγωγα metrics όπως slippage spikes, abnormal collateralization ratios, ασυνήθης gas density ή cross-chain velocity.

Επισυνάψτε tags σε όλα με scenario IDs ή synthetic user IDs ώστε οι αναλυτές να ευθυγραμμίσουν observables με την τεχνική AADAPT που εξετάζεται.

## 6. Purple-team loop & μετρικές ωριμότητας
1. Τρέξτε το σενάριο στο ελεγχόμενο περιβάλλον και καταγράψτε detections (alerts, dashboards, responders paged).
2. Αντιστοιχίστε κάθε βήμα στις συγκεκριμένες τεχνικές AADAPT καθώς και στα observables που παρήχθησαν σε chain/app/KMS/oracle/bridge επίπεδα.
3. Διατυπώστε και αναπτύξτε detection hypotheses (threshold rules, correlation searches, invariant checks).
4. Επαναλάβετε μέχρι το mean time to detect (MTTD) και το mean time to contain (MTTC) να πληρούν τις επιχειρησιακές απαιτήσεις και τα playbooks να σταματούν αξιόπιστα την απώλεια αξίας.

Παρακολουθήστε την ωριμότητα του προγράμματος σε τρεις άξονες:
- **Visibility**: κάθε κρίσιμη διαδρομή αξίας έχει telemetry σε κάθε plane.
- **Coverage**: ποσοστό προτεραιοποιημένων τεχνικών AADAPT που έχουν ασκηθεί end-to-end.
- **Response**: ικανότητα να pause contracts, revoke keys ή freeze flows πριν από μη αναστρέψιμη απώλεια.

Τυπικά ορόσημα: (1) ολοκληρωμένη καταγραφή αξίας + AADAPT mapping, (2) πρώτο end-to-end σενάριο με υλοποιημένες detections, (3) quarterly purple-team κύκλοι που επεκτείνουν την κάλυψη και μειώνουν MTTD/MTTC.

## 7. Πρότυπα σεναρίων
Χρησιμοποιήστε αυτά τα επαναλήψιμα blueprints για να σχεδιάσετε προσομοιώσεις που αντιστοιχούν άμεσα σε συμπεριφορές AADAPT.

### Scenario A – Flash-loan economic manipulation
- **Objective**: δανειστείτε transient κεφάλαια μέσα σε ένα transaction για να παραμορφώσετε AMM prices/liquidity και να προκαλέσετε mispriced borrows, liquidations ή mints πριν την επιστροφή.
- **Execution**:
1. Fork τον στόχο chain και τροφοδοτήστε pools με παραγωγική-όμοια liquidity.
2. Δανειστείτε μεγάλο notional μέσω flash loan.
3. Εκτελέστε calibrated swaps για να διασχίσετε price/threshold boundaries πάνω στα οποία βασίζονται lending, vault, ή derivative logic.
4. Καλέστε το victim contract αμέσως μετά την παραμόρφωση (borrow, liquidate, mint) και επιστρέψτε το flash loan.
- **Measurement**: Η invariant violation πέτυχε; Ενεργοποιήθηκαν slippage/price-deviation monitors, circuit breakers ή governance pause hooks; Πόσος χρόνος πέρασε μέχρι τα analytics να σηματοδοτήσουν το ασυνήθιστο gas/call graph pattern;

### Scenario B – Oracle/data-feed poisoning
- **Objective**: προσδιορίστε αν χειραγωγημένες feeds μπορούν να ενεργοποιήσουν καταστροφικές αυτοματοποιημένες ενέργειες (μαζικές liquidations, incorrect settlements).
- **Execution**:
1. Στο fork/testnet, αναπτύξτε ένα malicious feed ή προσαρμόστε aggregator weights/quorum/update cadence πέρα από την αποδεκτή απόκλιση.
2. Αφήστε τα dependent contracts να καταναλώσουν τα poisoned values και να εκτελέσουν την κανονική τους λογική.
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, εφαρμογή min/max bounds και καθυστέρηση ανάμεσα στην έναρξη της ανωμαλίας και την ανταπόκριση του operator.

### Scenario C – Credential/signing abuse
- **Objective**: ελέγξτε αν ο συμβιβασμός ενός μεμονωμένου signer ή automation identity επιτρέπει unauthorized upgrades, parameter changes ή treasury drains.
- **Execution**:
1. Καταγράψτε identities με ευαίσθητα signing rights (operators, CI tokens, service accounts που καλούν KMS/HSM, multisig participants).
2. Προσομοιώστε compromise (επαναχρησιμοποιήστε τα credentials/keys τους εντός του lab scope).
3. Προσπαθήστε privileged actions: upgrade proxies, αλλάξτε risk parameters, mint/pause assets, ή ενεργοποιήστε governance proposals.
- **Measurement**: Αναφέρουν τα KMS/HSM logs anomaly alerts (time-of-day, destination drift, burst of high-risk operations); Μπορούν πολιτικές ή multisig thresholds να αποτρέψουν unilateral abuse; Υπάρχουν throttles/rate limits ή επιπλέον approvals;

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: αξιολογήστε πόσο καλά οι defenders μπορούν να εντοπίσουν και να παρεμποδίσουν assets που γρήγορα ξεπλένονται μέσω bridges, DEX routers και privacy hops.
- **Execution**:
1. Αλυσοδέστε lock/mint operations σε κοινά bridges, παρεμβάλλετε swaps/mixers σε κάθε hop και διατηρήστε per-hop correlation IDs.
2. Επιταχύνετε τις μεταφορές για να πιέσετε τη monitoring latency (multi-hop μέσα σε λεπτά/blocks).
- **Measurement**: Χρόνος για συσχέτιση events across telemetry + commercial chain analytics, πληρότητα του ανασυσταθέντος μονοπατιού, ικανότητα να εντοπιστούν choke points για freezing σε πραγματικό περιστατικό και ποιότητα alerts για abnormal cross-chain velocity/value.

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
