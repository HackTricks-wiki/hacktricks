# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Das MITRE-Framework Adversarial Actions in Digital Asset Payment Techniques (AADAPT) kategorisiert gegnerische Aktionen und Techniken, die auf Systeme für digitale Assets abzielen.<sup>[[1]](#references)</sup> Betrachte es als **Grundgerüst für Threat Modeling**: Zähle jede Komponente auf, die Assets erstellen, bewerten, autorisieren oder routen kann, ordne diese Berührungspunkte den AADAPT-Techniken zu und entwickle anschließend Red-Team-Szenarien, mit denen gemessen wird, ob die Umgebung unwiederbringliche wirtschaftliche Verluste abwehren kann.

## 1. Inventar der wertbehafteten Komponenten
Erstelle eine Übersicht über alles, was den Wertstatus beeinflussen kann, auch wenn es off-chain ist.<sup>[[2]](#references)</sup>

- **Custodial Signing Services** (HSM/KMS-Cluster, Vault/KMaaS, Signing-APIs, die von Bots oder Backoffice-Jobs verwendet werden). Erfasse Key-IDs, Policies, Automatisierungsidentitäten und Freigabe-Workflows.
- **Admin- und Upgrade-Pfade** für Contracts (Proxy-Admins, Governance-Timelocks, Emergency-Pause-Keys, Parameter-Registries). Führe auf, wer oder was sie aufrufen kann und unter welchem Quorum oder welcher Verzögerung.
- **On-Chain-Protokolllogik**, die Lending, AMMs, Vaults, Staking, Bridges oder Settlement-Rails verarbeitet. Dokumentiere die angenommenen Invarianten (Oracle-Preise, Collateral Ratios, Rebalance-Frequenz …).
- **Off-Chain-Automatisierung**, die Transaktionen erstellt (Market-Making-Bots, CI/CD-Pipelines, Cron-Jobs, serverless Functions). Diese enthalten häufig API-Keys oder Service Principals, die Signaturen anfordern können.
- **Oracles und Data Feeds** (Zusammensetzung des Aggregators, Quorum, Abweichungsschwellenwerte, Aktualisierungsfrequenz). Vermerke jede Upstream-Quelle, auf die sich die automatisierte Risikologik stützt.
- **Bridges und Cross-Chain-Router** (Lock/Mint-Contracts, Relayer, Settlement-Jobs), die Chains oder Custodial-Stacks miteinander verbinden.

Ergebnis: ein Value-Flow-Diagramm, das zeigt, wie Assets bewegt werden, wer die Bewegung autorisiert und welche externen Signale die Geschäftslogik beeinflussen.

## 2. Komponenten den AADAPT-Verhaltensweisen zuordnen
Übertrage die AADAPT-Taxonomie in konkrete Angriffskandidaten pro Komponente.<sup>[[2]](#references)</sup>

| Komponente | Primärer AADAPT-Fokus |
| --- | --- |
| Signing/KMS-Umgebungen | Credential Theft, Policy Bypass, Signing Abuse, Governance Takeover |
| Oracles/Feeds | Input Poisoning, Manipulation der Aggregation, Umgehung von Abweichungsschwellenwerten |
| On-Chain-Protokolle | Wirtschaftliche Manipulation durch Flash Loans, Brechen von Invarianten, Rekonfiguration von Parametern |
| Automatisierungs-Pipelines | Kompromittierte Bot-/CI-Identitäten, Batch Replay, nicht autorisiertes Deployment |
| Bridges/Router | Cross-Chain-Evasion, schnelles Hop-Laundering, Desynchronisierung des Settlements |

Dieses Mapping stellt sicher, dass du nicht nur die Contracts testest, sondern auch jede Identität und Automatisierung, die den Wert indirekt steuern kann.

## 3. Nach Angreifer-Machbarkeit und Geschäftsauswirkung priorisieren

1. **Operative Schwachstellen**: offengelegte CI-Credentials, überprivilegierte IAM-Rollen, falsch konfigurierte KMS-Policies, Automatisierungskonten, die beliebige Signaturen anfordern können, öffentliche Buckets mit Bridge-Konfigurationen usw.
2. **Wertspezifische Schwachstellen**: fragile Oracle-Parameter, upgradable Contracts ohne Freigaben durch mehrere Parteien, gegenüber Flash Loans empfindliche Liquidität, Governance-Aktionen, die Timelocks umgehen.

Bearbeite die Warteschlange wie ein Angreifer: Beginne mit den operativen Einstiegsvektoren, die heute erfolgreich sein könnten, und gehe anschließend zu tiefgreifenden Protokoll- und wirtschaftlichen Manipulationspfaden über.<sup>[[2]](#references)</sup>

## 4. In kontrollierten, produktionsnahen Umgebungen ausführen
- **Geforkte Mainnets / isolierte Testnets**: Repliziere Bytecode, Storage und Liquidität, damit Flash-Loan-Pfade, Oracle-Abweichungen und Bridge-Flows End-to-End ausgeführt werden können, ohne echte Gelder zu berühren.<sup>[[2]](#references)</sup>
- **Planung des Explosionsradius**: Definiere Circuit Breakers, pausierbare Module, Rollback-Runbooks und Admin-Keys ausschließlich für Tests, bevor du ein Szenario auslöst.
- **Koordination der Stakeholder**: Informiere Custodians, Oracle-Betreiber, Bridge-Partner und Compliance, damit ihre Monitoring-Teams den Traffic erwarten.
- **Rechtliche Freigabe**: Dokumentiere Scope, Autorisierung und Abbruchbedingungen, wenn Simulationen regulierte Rails berühren könnten.

## 5. An AADAPT-Techniken ausgerichtete Telemetrie
Instrumentiere Telemetrie-Streams so, dass jedes Szenario verwertbare Detection-Daten erzeugt.<sup>[[2]](#references)</sup>

- **Traces auf Chain-Ebene**: vollständige Call-Graphs, Gas-Verbrauch, Transaction Nonces und Block-Timestamps, um Flash-Loan-Bundles, reentrancy-ähnliche Strukturen und Cross-Contract-Hops zu rekonstruieren.
- **Application-/API-Logs**: Verknüpfe jede On-Chain-TX mit einer menschlichen oder automatisierten Identität (Session-ID, OAuth-Client, API-Key, CI-Job-ID) einschließlich IPs und Auth-Methoden.
- **KMS-/HSM-Logs**: Key-ID, aufrufendes Principal, Policy-Ergebnis, Zieladresse und Reason Codes für jede Signatur. Erstelle Baselines für Änderungsfenster und risikoreiche Vorgänge.
- **Oracle-/Feed-Metadaten**: Zusammensetzung der Datenquellen pro Update, gemeldeter Wert, Abweichung von gleitenden Durchschnitten, ausgelöste Schwellenwerte und verwendete Failover-Pfade.
- **Bridge-/Swap-Traces**: Korreliere Lock-/Mint-/Unlock-Events über Chains hinweg mit Correlation-IDs, Chain-IDs, Relayer-Identität und Hop-Timing.
- **Anomalie-Markierungen**: abgeleitete Metriken wie Slippage-Spikes, ungewöhnliche Collateralization Ratios, ungewöhnliche Gas-Dichte oder Cross-Chain-Geschwindigkeit.

Versehe alles mit Scenario-IDs oder synthetischen User-IDs, damit Analysten die Observables mit der jeweils getesteten AADAPT-Technik abgleichen können.

## 6. Purple-Team-Schleife und Reifegradmetriken
1. Führe das Szenario in der kontrollierten Umgebung aus und erfasse die Detections (Alerts, Dashboards, benachrichtigte Responder).<sup>[[2]](#references)</sup>
2. Ordne jeden Schritt den spezifischen AADAPT-Techniken sowie den erzeugten Observables in den Chain-, App-, KMS-, Oracle- und Bridge-Ebenen zu.
3. Formuliere und implementiere Detection-Hypothesen (Schwellenwertregeln, Correlation Searches, Invariant Checks).
4. Wiederhole den Vorgang, bis Mean Time to Detect (MTTD) und Mean Time to Contain (MTTC) den geschäftlichen Toleranzen entsprechen und Playbooks den Wertverlust zuverlässig stoppen.

Verfolge den Reifegrad des Programms entlang drei Achsen:<sup>[[2]](#references)</sup>
- **Visibility**: Jeder kritische Value Path verfügt in jeder Ebene über Telemetrie.
- **Coverage**: Anteil der priorisierten AADAPT-Techniken, die End-to-End getestet wurden.
- **Response**: Fähigkeit, Contracts zu pausieren, Keys zu widerrufen oder Flows vor einem unwiederbringlichen Verlust einzufrieren.

Typische Meilensteine: (1) abgeschlossenes Value Inventory plus AADAPT-Mapping, (2) erstes End-to-End-Szenario mit implementierten Detections, (3) vierteljährliche Purple-Team-Zyklen, die die Coverage erweitern und MTTD/MTTC reduzieren.<sup>[[2]](#references)</sup>

## 7. Szenario-Templates
Verwende diese wiederholbaren Vorlagen, um Simulationen zu entwerfen, die direkt auf AADAPT-Verhaltensweisen abgebildet werden.<sup>[[2]](#references)</sup>

### Szenario A – Wirtschaftliche Manipulation durch Flash Loans
- **Ziel**: Innerhalb einer Transaktion vorübergehend Kapital zu leihen, um AMM-Preise oder Liquidität zu verzerren und fehlbewertete Borrows, Liquidationen oder Mints auszulösen, bevor das Darlehen zurückgezahlt wird.
- **Ausführung**:
1. Forke die Ziel-Chain und versehe Pools mit produktionsnaher Liquidität.
2. Leihe einen großen Nominalbetrag über einen Flash Loan.
3. Führe kalibrierte Swaps aus, um Preis- oder Schwellenwertgrenzen zu überschreiten, auf die sich Lending-, Vault- oder Derivative-Logik stützt.
4. Rufe den betroffenen Contract unmittelbar nach der Verzerrung auf (Borrow, Liquidate, Mint) und zahle den Flash Loan zurück.
- **Messung**: Konnte die Invariant-Verletzung erfolgreich ausgenutzt werden? Wurden Slippage-/Price-Deviation-Monitore, Circuit Breakers oder Governance-Pause-Hooks ausgelöst? Wie lange dauerte es, bis Analytics das ungewöhnliche Gas-/Call-Graph-Muster markierte?

### Szenario B – Poisoning von Oracle-/Data-Feeds
- **Ziel**: Festzustellen, ob manipulierte Feeds schädliche automatisierte Aktionen auslösen können (Massenliquidationen, fehlerhafte Settlements).
- **Ausführung**:
1. Deploye im Fork/Testnet einen bösartigen Feed oder passe Aggregator-Gewichte, Quorum oder Aktualisierungsfrequenz über die tolerierte Abweichung hinaus an.
2. Lass abhängige Contracts die vergifteten Werte verwenden und ihre Standardlogik ausführen.
- **Messung**: Out-of-Band-Alerts auf Feed-Ebene, Aktivierung des Fallback-Oracles, Durchsetzung von Min-/Max-Grenzen und Latenz zwischen Beginn der Anomalie und der Reaktion des Operators.

### Szenario C – Credential-/Signing-Abuse
- **Ziel**: Zu testen, ob die Kompromittierung eines einzelnen Signers oder einer Automatisierungsidentität nicht autorisierte Upgrades, Parameteränderungen oder Treasury-Drains ermöglicht.
- **Ausführung**:
1. Zähle Identitäten mit sensiblen Signing-Rechten auf (Operators, CI-Tokens, Service Accounts, die KMS/HSM aufrufen, Multisig-Teilnehmer).
2. Simuliere eine Kompromittierung (verwende ihre Credentials/Keys innerhalb des Laborscopes erneut).
3. Versuche privilegierte Aktionen: Upgrade von Proxies, Änderung von Risikoparametern, Mint/Pause von Assets oder Auslösen von Governance-Proposals.
- **Messung**: Lösen KMS-/HSM-Logs Anomalie-Alerts aus (Tageszeit, Abweichung des Ziels, Häufung risikoreicher Vorgänge)? Können Policies oder Multisig-Schwellenwerte einen alleinigen Missbrauch verhindern? Sind Throttles/Rate Limits oder zusätzliche Freigaben durchgesetzt?

### Szenario D – Cross-Chain-Evasion und Lücken bei der Nachverfolgbarkeit
- **Ziel**: Zu bewerten, wie gut Verteidiger Assets verfolgen und abfangen können, die schnell über Bridges, DEX-Router und Privacy-Hops gewaschen werden.
- **Ausführung**:
1. Verkette Lock-/Mint-Operationen über gängige Bridges, füge auf jedem Hop Swaps/Mixer ein und führe pro Hop Correlation-IDs weiter.
2. Beschleunige Transfers, um die Monitoring-Latenz zu belasten (Multi-Hop innerhalb von Minuten/Blocks).
- **Messung**: Zeit zur Korrelation von Events über Telemetrie und kommerzielle Chain-Analytics hinweg, Vollständigkeit des rekonstruierten Pfads, Fähigkeit zur Identifizierung von Choke Points für das Einfrieren in einem realen Incident sowie Alert-Treue bei ungewöhnlicher Cross-Chain-Geschwindigkeit und ungewöhnlichem Cross-Chain-Wert.

## References

- [1] [AADAPT(TM) Cyber Threat Framework for Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
