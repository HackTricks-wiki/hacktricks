# Value-Centric Web3 Red Teaming (MITRE AADAPT)

Das MITRE-Framework Adversarial Actions in Digital Asset Payment Techniques (AADAPT) kategorisiert gegnerische Aktionen und Techniken, die auf Digital-Asset-Systeme abzielen.<sup>[[1]](#references)</sup> Betrachte es als **Grundlage für Threat Modeling**: Erfasse jede Komponente, die Assets erzeugen, bewerten, autorisieren oder weiterleiten kann, ordne diese Kontaktpunkte AADAPT-Techniken zu und entwickle anschließend Red-Team-Szenarien, mit denen gemessen wird, ob die Umgebung unwiederbringliche wirtschaftliche Verluste verhindern kann.

## 1. Komponenten mit Wertbezug inventarisieren
Erstelle eine Übersicht über alles, was den Wertstatus beeinflussen kann, auch wenn es off-chain liegt.<sup>[[2]](#references)</sup>

- **Custodial Signing Services** (HSM/KMS-Cluster, Vault/KMaaS, Signing-APIs, die von Bots oder Back-Office-Jobs verwendet werden). Erfasse Key IDs, Policies, Automatisierungsidentitäten und Genehmigungs-Workflows.
- **Admin- und Upgrade-Pfade** für Contracts (Proxy-Admins, Governance-Timelocks, Emergency-Pause-Keys, Parameter-Registries). Führe auf, wer oder was sie aufrufen kann und unter welchem Quorum oder welcher Verzögerung.
- **On-Chain-Protokolllogik**, die Lending, AMMs, Vaults, Staking, Bridges oder Settlement-Rails verarbeitet. Dokumentiere die angenommenen Invarianten (Oracle-Preise, Collateral Ratios, Rebalance-Rhythmus …).
- **Off-Chain-Automatisierung**, die Transaktionen erstellt (Market-Making-Bots, CI/CD-Pipelines, Cron-Jobs, Serverless Functions). Diese enthalten häufig API-Keys oder Service Principals, die Signaturen anfordern können.
- **Oracles und Data Feeds** (Zusammensetzung der Aggregatoren, Quorum, Deviation Thresholds, Aktualisierungsrhythmus). Vermerke jede Upstream-Quelle, auf die sich die automatisierte Risikologik stützt.
- **Bridges und Cross-Chain-Router** (Lock/Mint-Contracts, Relayer, Settlement-Jobs), die Chains oder Custodial-Stacks miteinander verbinden.

Ergebnis: ein Value-Flow-Diagramm, das zeigt, wie Assets bewegt werden, wer die Bewegung autorisiert und welche externen Signale die Business-Logik beeinflussen.

## 2. Komponenten AADAPT-Verhaltensweisen zuordnen
Übertrage die AADAPT-Taxonomie auf konkrete Angriffskandidaten pro Komponente.<sup>[[2]](#references)</sup>

| Komponente | Primärer AADAPT-Fokus |
| --- | --- |
| Signing/KMS-Umgebungen | Diebstahl von Credentials, Policy-Umgehung, Missbrauch von Signaturen, Übernahme der Governance |
| Oracles/Feeds | Input Poisoning, Manipulation der Aggregation, Umgehung von Deviation Thresholds |
| On-Chain-Protokolle | Wirtschaftliche Manipulation durch Flash Loans, Brechen von Invarianten, Rekonfiguration von Parametern |
| Automatisierungs-Pipelines | Kompromittierte Bot-/CI-Identitäten, Batch-Replay, nicht autorisiertes Deployment |
| Bridges/Router | Cross-Chain-Umgehung, schnelles Hop-Laundering, Desynchronisierung des Settlements |

Durch dieses Mapping testest du nicht nur die Contracts, sondern jede Identität und Automatisierung, die den Wert indirekt steuern kann.

## 3. Nach Angreifer-Machbarkeit und Geschäftsauswirkung priorisieren

1. **Operative Schwachstellen**: offengelegte CI-Credentials, überprivilegierte IAM-Rollen, falsch konfigurierte KMS-Policies, Automatisierungskonten, die beliebige Signaturen anfordern können, öffentliche Buckets mit Bridge-Konfigurationen usw.
2. **Wertspezifische Schwachstellen**: fragile Oracle-Parameter, upgradable Contracts ohne Genehmigungen durch mehrere Parteien, für Flash Loans anfällige Liquidität, Governance-Aktionen, die Timelocks umgehen.

Arbeite die Warteschlange wie ein Angreifer ab: Beginne mit den operativen Einstiegspunkten, die bereits heute erfolgreich ausgenutzt werden könnten, und gehe anschließend zu tiefgreifenden Protokoll- und Wirtschaftsmanipulationspfaden über.<sup>[[2]](#references)</sup>

## 4. In kontrollierten, produktionsnahen Umgebungen ausführen
- **Geforkte Mainnets / isolierte Testnets**: Repliziere Bytecode, Storage und Liquidität, damit Flash-Loan-Pfade, Oracle-Abweichungen und Bridge-Flows vollständig ausgeführt werden können, ohne echte Gelder zu berühren.<sup>[[2]](#references)</sup>
- **Planung des Blast Radius**: Definiere Circuit Breakers, pausierbare Module, Rollback-Runbooks und ausschließlich für Tests vorgesehene Admin-Keys, bevor du ein Szenario auslöst.
- **Koordination der Stakeholder**: Informiere Custodians, Oracle-Betreiber, Bridge-Partner und Compliance, damit ihre Monitoring-Teams den Datenverkehr erwarten.
- **Rechtliche Freigabe**: Dokumentiere Scope, Autorisierung und Abbruchbedingungen, wenn Simulationen regulierte Rails berühren könnten.

## 5. An AADAPT-Techniken ausgerichtete Telemetrie
Instrumentiere Telemetrie-Streams so, dass jedes Szenario verwertbare Detection-Daten erzeugt.<sup>[[2]](#references)</sup>

- **Traces auf Chain-Ebene**: vollständige Call-Graphs, Gas-Verbrauch, Transaction Nonces und Block-Timestamps, um Flash-Loan-Bundles, Reentrancy-ähnliche Strukturen und Cross-Contract-Hops zu rekonstruieren.
- **Application-/API-Logs**: Verknüpfe jede On-Chain-TX mit einer menschlichen oder automatisierten Identität (Session ID, OAuth Client, API-Key, CI-Job-ID), einschließlich IPs und Authentifizierungsmethoden.
- **KMS-/HSM-Logs**: Key ID, aufrufendes Principal, Policy-Ergebnis, Zieladresse und Reason Codes für jede Signatur. Baseline für Änderungsfenster und risikoreiche Operationen erstellen.
- **Oracle-/Feed-Metadaten**: Zusammensetzung der Datenquellen pro Update, gemeldeter Wert, Abweichung von gleitenden Mittelwerten, ausgelöste Thresholds und verwendete Failover-Pfade.
- **Bridge-/Swap-Traces**: Verknüpfe Lock-/Mint-/Unlock-Events über Chains hinweg mit Correlation IDs, Chain IDs, Relayer-Identität und Hop-Zeitpunkten.
- **Anomalie-Markierungen**: Abgeleitete Metriken wie Slippage-Spikes, ungewöhnliche Collateralization Ratios, ungewöhnliche Gas-Dichte oder Cross-Chain-Velocity.

Versehen alle Daten mit Scenario IDs oder synthetischen User IDs, damit Analysten die Observables der jeweils getesteten AADAPT-Technik zuordnen können.

## 6. Purple-Team-Schleife und Reifegradmetriken
1. Führe das Szenario in der kontrollierten Umgebung aus und erfasse die Detections (Alerts, Dashboards, benachrichtigte Responder).<sup>[[2]](#references)</sup>
2. Ordne jeden Schritt den spezifischen AADAPT-Techniken sowie den erzeugten Observables in den Chain-, Application-, KMS-, Oracle- und Bridge-Ebenen zu.
3. Formuliere und implementiere Detection-Hypothesen (Threshold-Regeln, Correlation Searches, Invariant Checks).
4. Wiederhole den Vorgang, bis Mean Time to Detect (MTTD) und Mean Time to Contain (MTTC) die geschäftlichen Toleranzen erfüllen und Playbooks den Wertverlust zuverlässig stoppen.

Verfolge die Reife des Programms anhand von drei Achsen:<sup>[[2]](#references)</sup>
- **Sichtbarkeit**: Jeder kritische Value Path verfügt in jeder Ebene über Telemetrie.
- **Abdeckung**: Anteil der priorisierten AADAPT-Techniken, die durchgängig ausgeführt wurden.
- **Response**: Fähigkeit, Contracts zu pausieren, Keys zu widerrufen oder Flows vor einem irreversiblen Verlust einzufrieren.

Typische Meilensteine: (1) abgeschlossene Value-Inventarisierung und AADAPT-Zuordnung, (2) erstes durchgängiges Szenario mit implementierten Detections, (3) vierteljährliche Purple-Team-Zyklen, die die Abdeckung erweitern und MTTD/MTTC reduzieren.<sup>[[2]](#references)</sup>

## 7. Szenario-Templates
Verwende diese wiederholbaren Blueprints, um Simulationen zu entwerfen, die direkt auf AADAPT-Verhaltensweisen abgebildet werden.<sup>[[2]](#references)</sup>

### Szenario A – Wirtschaftliche Manipulation durch Flash Loans
- **Ziel**: Innerhalb einer Transaktion vorübergehend Kapital leihen, um AMM-Preise und Liquidität zu verzerren und falsch bewertete Borrows, Liquidationen oder Mints auszulösen, bevor der Flash Loan zurückgezahlt wird.
- **Ausführung**:
1. Forke die Ziel-Chain und versehe Pools mit produktionsnaher Liquidität.
2. Leihe einen hohen Nominalbetrag über einen Flash Loan.
3. Führe kalibrierte Swaps aus, um Preis-/Threshold-Grenzen zu überschreiten, auf die sich Lending-, Vault- oder Derivative-Logik stützt.
4. Rufe den betroffenen Contract unmittelbar nach der Verzerrung auf (Borrow, Liquidate, Mint) und zahle den Flash Loan zurück.
- **Messung**: Konnte die Invariant-Verletzung erfolgreich ausgenutzt werden? Wurden Slippage-/Price-Deviation-Monitoring, Circuit Breakers oder Governance-Pause-Hooks ausgelöst? Wie lange dauerte es, bis Analytics das ungewöhnliche Gas-/Call-Graph-Muster erkannten?

### Szenario B – Poisoning von Oracle/Data Feeds
- **Ziel**: Feststellen, ob manipulierte Feeds destruktive automatisierte Aktionen auslösen können (Massenliquidationen, fehlerhafte Settlements).
- **Ausführung**:
1. Deploye im Fork/Testnet einen bösartigen Feed oder passe Aggregator-Gewichte, Quorum oder Aktualisierungsrhythmus so an, dass die tolerierte Abweichung überschritten wird.
2. Lass abhängige Contracts die manipulierten Werte übernehmen und ihre Standardlogik ausführen.
- **Messung**: Out-of-Band-Alerts auf Feed-Ebene, Aktivierung des Fallback-Oracles, Durchsetzung von Min-/Max-Grenzen und Latenz zwischen Beginn der Anomalie und der Reaktion des Operators.

### Szenario C – Missbrauch von Credentials/Signaturen
- **Ziel**: Testen, ob die Kompromittierung eines einzelnen Signers oder einer Automatisierungsidentität nicht autorisierte Upgrades, Parameteränderungen oder Treasury-Drains ermöglicht.
- **Ausführung**:
1. Erfasse Identitäten mit sensiblen Signing-Rechten (Operatoren, CI-Tokens, Service Accounts, die KMS/HSM aufrufen, Multisig-Teilnehmer).
2. Simuliere eine Kompromittierung (verwende ihre Credentials/Keys innerhalb des Lab-Scope erneut).
3. Versuche privilegierte Aktionen: Proxy-Upgrades, Änderung von Risiko-Parametern, Mint/Pause von Assets oder Auslösen von Governance-Proposals.
- **Messung**: Lösen KMS-/HSM-Logs Anomalie-Alerts aus (Tageszeit, Abweichung der Zieladresse, Häufung risikoreicher Operationen)? Können Policies oder Multisig-Thresholds einen einseitigen Missbrauch verhindern? Werden Throttles/Rate Limits oder zusätzliche Genehmigungen durchgesetzt?

### Szenario D – Cross-Chain-Umgehung und Lücken bei der Nachverfolgbarkeit
- **Ziel**: Bewerten, wie gut Verteidiger Assets nachverfolgen und stoppen können, die schnell über Bridges, DEX-Router und Privacy-Hops gewaschen werden.
- **Ausführung**:
1. Verknüpfe Lock-/Mint-Operationen über gängige Bridges hinweg, füge auf jedem Hop Swaps/Mixer ein und verwende pro Hop Correlation IDs.
2. Beschleunige Transfers, um die Monitoring-Latenz zu belasten (Multi-Hop innerhalb von Minuten/Blocks).
- **Messung**: Zeit zur Korrelation von Events über Telemetrie und kommerzielle Chain-Analytics hinweg, Vollständigkeit des rekonstruierten Pfads, Fähigkeit zur Identifizierung von Choke Points für ein Einfrieren in einem realen Incident sowie Alert-Genauigkeit bei ungewöhnlicher Cross-Chain-Velocity bzw. ungewöhnlichem Cross-Chain-Value.

## References

- [1] [AADAPT(TM) Cyber Threat Framework for Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE-AADAPT-Framework als Red-Team-Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
