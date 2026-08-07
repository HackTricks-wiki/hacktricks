# Wertzentriertes Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Die MITRE-Matrix „Adversarial Actions in Digital Asset Payment Techniques“ (AADAPT) erfasst Angreiferverhalten, das digitalen Wert manipuliert und nicht nur die Infrastruktur. Behandle sie als **Grundlage für das Threat-Modeling**: Liste jede Komponente auf, die Assets erstellen, bewerten, autorisieren oder weiterleiten kann, ordne diese Berührungspunkte den AADAPT-Techniken zu und führe anschließend Red-Team-Szenarien durch, mit denen gemessen wird, ob die Umgebung unwiederbringliche wirtschaftliche Verluste verhindern kann.

## 1. Inventarisierung werttragender Komponenten
Erstelle eine Übersicht über alles, was den Wertstatus beeinflussen kann, auch wenn es off-chain ist.<sup>[[1]](#references)</sup>

- **Custodial Signing Services** (HSM/KMS-Cluster, Vault/KMaaS, Signing APIs, die von Bots oder Backoffice-Jobs verwendet werden). Erfasse Key-IDs, Policies, Automatisierungsidentitäten und Genehmigungsabläufe.
- **Admin- und Upgrade-Pfade** für Contracts (Proxy-Admins, Governance-Timelocks, Emergency-Pause-Keys, Parameter-Registries). Berücksichtige, wer oder was sie aufrufen kann und unter welchem Quorum oder welcher Verzögerung.
- **On-Chain-Protokolllogik**, die Lending, AMMs, Vaults, Staking, Bridges oder Settlement-Rails verarbeitet. Dokumentiere die vorausgesetzten Invarianten (Oracle-Preise, Collateral Ratios, Rebalance-Intervalle …).
- **Off-Chain-Automatisierung**, die Transactions erstellt (Market-Making-Bots, CI/CD-Pipelines, Cron-Jobs, serverless Functions). Diese enthalten häufig API-Keys oder Service Principals, die Signaturen anfordern können.
- **Oracles und Data Feeds** (Zusammensetzung der Aggregatoren, Quorum, Abweichungsschwellen, Aktualisierungsintervall). Vermerke jede Upstream-Quelle, auf die sich die automatisierte Risk-Logik stützt.
- **Bridges und Cross-Chain-Router** (Lock/Mint-Contracts, Relayer, Settlement-Jobs), die Chains oder Custodial-Stacks miteinander verbinden.

Ergebnis: ein Value-Flow-Diagramm, das zeigt, wie Assets bewegt werden, wer die Bewegungen autorisiert und welche externen Signale die Business-Logik beeinflussen.

## 2. Zuordnung der Komponenten zu AADAPT-Verhaltensmustern
Übertrage die AADAPT-Taxonomie in konkrete Angriffskandidaten für jede Komponente.<sup>[[1]](#references)</sup>

| Komponente | Primärer AADAPT-Fokus |
| --- | --- |
| Signing/KMS-Umgebungen | Credential Theft, Policy Bypass, Signing Abuse, Governance Takeover |
| Oracles/Feeds | Input Poisoning, Manipulation der Aggregation, Umgehung von Abweichungsschwellen |
| On-Chain-Protokolle | Wirtschaftliche Manipulation durch Flash Loans, Brechen von Invarianten, Neukonfiguration von Parametern |
| Automatisierungs-Pipelines | Kompromittierte Bot-/CI-Identitäten, Batch Replay, Unbefugtes Deployment |
| Bridges/Router | Cross-Chain-Evasion, schnelles Hop-Laundering, Desynchronisierung des Settlements |

Diese Zuordnung stellt sicher, dass du nicht nur die Contracts testest, sondern auch jede Identität und Automatisierung, die den Wert indirekt steuern kann.

## 3. Priorisierung nach Angreifer-Machbarkeit und Geschäftsauswirkung

1. **Operative Schwachstellen**: offengelegte CI-Credentials, übermäßig privilegierte IAM-Rollen, falsch konfigurierte KMS-Policies, Automatisierungskonten, die beliebige Signaturen anfordern können, öffentliche Buckets mit Bridge-Konfigurationen usw.
2. **Wertspezifische Schwachstellen**: fragile Oracle-Parameter, upgradebare Contracts ohne Genehmigungen durch mehrere Parteien, für Flash Loans anfällige Liquidität, Governance-Aktionen, die Timelocks umgehen.

Arbeite die Warteschlange wie ein Angreifer ab: Beginne mit den operativen Einstiegspunkten, die heute erfolgreich ausgenutzt werden könnten, und gehe anschließend zu tiefgreifenden Protokoll- und Wirtschaftmanipulationspfaden über.<sup>[[1]](#references)</sup>

## 4. Durchführung in kontrollierten, produktionsnahen Umgebungen
- **Geforkte Mainnets / isolierte Testnets**: Repliziere Bytecode, Storage und Liquidität, damit Flash-Loan-Pfade, Oracle-Abweichungen und Bridge-Flows vollständig ausgeführt werden können, ohne echte Gelder zu berühren.<sup>[[1]](#references)</sup>
- **Planung des Blast Radius**: Definiere Circuit Breakers, pausierbare Module, Rollback-Runbooks und ausschließlich für Tests vorgesehene Admin-Keys, bevor du ein Szenario auslöst.
- **Koordination der Stakeholder**: Informiere Custodians, Oracle-Betreiber, Bridge-Partner und Compliance, damit ihre Monitoring-Teams den Traffic erwarten.
- **Rechtliche Freigabe**: Dokumentiere Scope, Autorisierung und Abbruchbedingungen, wenn Simulationen regulierte Rails berühren könnten.

## 5. An AADAPT-Techniken ausgerichtete Telemetrie
Instrumentiere Telemetrie-Streams so, dass jedes Szenario verwertbare Detection-Daten erzeugt.<sup>[[1]](#references)</sup>

- **Traces auf Chain-Ebene**: vollständige Call Graphs, Gas-Verbrauch, Transaction-Nonces und Block-Timestamps, um Flash-Loan-Bundles, Reentrancy-ähnliche Strukturen und Cross-Contract-Hops zu rekonstruieren.
- **Application-/API-Logs**: Verknüpfe jede On-Chain-TX mit einer menschlichen oder automatisierten Identität (Session-ID, OAuth-Client, API-Key, CI-Job-ID) einschließlich IPs und Auth-Methoden.
- **KMS-/HSM-Logs**: Key-ID, aufrufendes Principal, Policy-Ergebnis, Zieladresse und Reason Codes für jede Signatur. Erstelle eine Baseline für Änderungsfenster und risikoreiche Operationen.
- **Oracle-/Feed-Metadaten**: Zusammensetzung der Datenquellen pro Update, gemeldeter Wert, Abweichung von gleitenden Durchschnitten, ausgelöste Schwellenwerte und verwendete Failover-Pfade.
- **Bridge-/Swap-Traces**: Korrelieren von Lock-/Mint-/Unlock-Events über Chains hinweg mit Correlation-IDs, Chain-IDs, Relayer-Identität und Hop-Timing.
- **Anomalie-Markierungen**: abgeleitete Metriken wie Slippage-Spitzen, ungewöhnliche Collateralization Ratios, ungewöhnliche Gas-Dichte oder Cross-Chain-Velocity.

Verknüpfe alles mit Scenario-IDs oder synthetischen User-IDs, damit Analysten die Observables der jeweils getesteten AADAPT-Technik zuordnen können.

## 6. Purple-Team-Schleife und Reifegradmetriken
1. Führe das Szenario in der kontrollierten Umgebung aus und erfasse Detections (Alerts, Dashboards, benachrichtigte Responder).<sup>[[1]](#references)</sup>
2. Ordne jeden Schritt den spezifischen AADAPT-Techniken sowie den erzeugten Observables in den Chain-, App-, KMS-, Oracle- und Bridge-Ebenen zu.
3. Formuliere und implementiere Detection-Hypothesen (Threshold Rules, Correlation Searches, Invariant Checks).
4. Wiederhole den Vorgang, bis Mean Time to Detect (MTTD) und Mean Time to Contain (MTTC) den geschäftlichen Toleranzen entsprechen und Playbooks den Wertverlust zuverlässig stoppen.

Verfolge die Programmreife anhand von drei Achsen:<sup>[[1]](#references)</sup>
- **Visibility**: Jeder kritische Value Path verfügt in jeder Ebene über Telemetrie.
- **Coverage**: Anteil der priorisierten AADAPT-Techniken, die End-to-End getestet wurden.
- **Response**: Fähigkeit, Contracts zu pausieren, Keys zu widerrufen oder Flows vor einem unwiederbringlichen Verlust einzufrieren.

Typische Meilensteine: (1) abgeschlossene Werterfassung und AADAPT-Zuordnung, (2) erstes End-to-End-Szenario mit implementierten Detections, (3) vierteljährliche Purple-Team-Zyklen, die die Abdeckung erweitern und MTTD/MTTC senken.<sup>[[1]](#references)</sup>

## 7. Szenario-Templates
Verwende diese wiederholbaren Blueprints, um Simulationen zu entwerfen, die direkt auf AADAPT-Verhaltensmuster abgebildet werden.<sup>[[1]](#references)</sup>

### Szenario A – Wirtschaftliche Manipulation durch Flash Loans
- **Ziel**: innerhalb einer Transaction vorübergehend Kapital leihen, um AMM-Preise bzw. Liquidität zu verzerren und falsch bewertete Borrows, Liquidations oder Mints auszulösen, bevor das Darlehen zurückgezahlt wird.
- **Ausführung**:
1. Forke die Ziel-Chain und befülle Pools mit produktionsnaher Liquidität.
2. Leihe einen hohen Nominalbetrag per Flash Loan.
3. Führe kalibrierte Swaps aus, um Preis- oder Schwellenwertgrenzen zu überschreiten, auf die sich Lending-, Vault- oder Derivative-Logik stützt.
4. Rufe den betroffenen Contract unmittelbar nach der Verzerrung auf (Borrow, Liquidate, Mint) und zahle den Flash Loan zurück.
- **Messung**: Konnte die Invariant-Verletzung erfolgreich ausgenutzt werden? Wurden Slippage-/Price-Deviation-Monitore, Circuit Breakers oder Governance-Pause-Hooks ausgelöst? Wie lange dauerte es, bis Analytics das anomale Gas-/Call-Graph-Muster erkannte?

### Szenario B – Poisoning von Oracle/Data Feeds
- **Ziel**: Feststellen, ob manipulierte Feeds schädliche automatisierte Aktionen auslösen können (Massenliquidationen, fehlerhafte Settlements).
- **Ausführung**:
1. Deploye im Fork/Testnet einen bösartigen Feed oder passe Aggregator-Gewichte, Quorum oder Aktualisierungsintervall so an, dass die tolerierte Abweichung überschritten wird.
2. Lass abhängige Contracts die vergifteten Werte übernehmen und ihre Standardlogik ausführen.
- **Messung**: Out-of-Band-Alerts auf Feed-Ebene, Aktivierung des Fallback-Oracles, Durchsetzung von Min-/Max-Grenzen sowie Latenz zwischen Beginn der Anomalie und der Reaktion des Operators.

### Szenario C – Credential-/Signing-Abuse
- **Ziel**: Testen, ob die Kompromittierung eines einzelnen Signers oder einer Automatisierungsidentität unbefugte Upgrades, Parameteränderungen oder Treasury-Drains ermöglicht.
- **Ausführung**:
1. Liste Identitäten mit sensiblen Signing-Rechten auf (Operators, CI-Tokens, Service Accounts, die KMS/HSM aufrufen, Multisig-Teilnehmer).
2. Simuliere eine Kompromittierung (Wiederverwendung ihrer Credentials/Keys innerhalb des Lab-Scope).
3. Versuche privilegierte Aktionen: Proxy-Upgrades, Änderung von Risk-Parametern, Mint/Pause von Assets oder Auslösen von Governance-Proposals.
- **Messung**: Lösen KMS-/HSM-Logs Anomalie-Alerts aus (Tageszeit, Änderung des Ziels, Häufung risikoreicher Operationen)? Können Policies oder Multisig-Schwellenwerte einen einseitigen Missbrauch verhindern? Werden Throttles/Rate Limits oder zusätzliche Genehmigungen durchgesetzt?

### Szenario D – Cross-Chain-Evasion und Lücken bei der Nachverfolgbarkeit
- **Ziel**: Bewerten, wie gut Verteidiger Assets nachverfolgen und unterbinden können, die schnell über Bridges, DEX-Router und Privacy-Hops gewaschen werden.
- **Ausführung**:
1. Verkette Lock-/Mint-Operationen über verbreitete Bridges, füge Swaps/Mixer auf jedem Hop ein und verwende pro Hop Correlation-IDs.
2. Beschleunige Transfers, um die Monitoring-Latenz zu belasten (Multi-Hop innerhalb weniger Minuten/Blocks).
- **Messung**: Zeit zur Korrelation von Events über Telemetrie und kommerzielle Chain-Analytics hinweg, Vollständigkeit des rekonstruierten Pfads, Fähigkeit zur Identifizierung von Choke Points für das Einfrieren in einem realen Incident sowie Alert-Fidelity bei ungewöhnlicher Cross-Chain-Velocity bzw. ungewöhnlichem Cross-Chain-Value.

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
