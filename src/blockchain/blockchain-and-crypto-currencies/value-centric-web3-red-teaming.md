# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Das MITRE-Framework Adversarial Actions in Digital Asset Payment Techniques (AADAPT) kategorisiert adversariale Aktionen und Techniken, die auf Digital-Asset-Systeme abzielen.<sup>[[1]](#references)</sup> Betrachte es als **Grundlage für das Threat Modeling**: Liste jede Komponente auf, die Assets erzeugen, bewerten, autorisieren oder weiterleiten kann, ordne diese Kontaktpunkte den AADAPT-Techniken zu und entwickle anschließend Red-Team-Szenarien, mit denen sich messen lässt, ob die Umgebung unwiederbringlichen wirtschaftlichen Verlusten standhalten kann.

## 1. Komponenten mit Wertbezug erfassen
Erstelle eine Übersicht über alles, was den Wertzustand beeinflussen kann, auch wenn es off-chain ist.<sup>[[2]](#references)</sup>

- **Verwahrungs- und Signaturdienste** (HSM/KMS-Cluster, Vault/KMaaS, Signatur-APIs für Bots oder Backoffice-Jobs). Erfasse Key-IDs, Richtlinien, Automatisierungsidentitäten und Genehmigungsabläufe.
- **Admin- und Upgrade-Pfade** für Contracts (Proxy-Admins, Governance-Timelocks, Notfall-Pause-Keys, Parameter-Registries). Erfasse, wer oder was sie aufrufen kann und mit welchem Quorum oder welcher Verzögerung.
- **On-chain-Protokolllogik** für Lending, AMMs, Vaults, Staking, Bridges oder Settlement-Rails. Dokumentiere die vorausgesetzten Invarianten (Oracle-Preise, Collateral Ratios, Rebalancing-Taktung …).
- **Off-chain-Automatisierung**, die Transaktionen erstellt (Market-Making-Bots, CI/CD-Pipelines, Cron-Jobs, Serverless Functions). Diese verfügen oft über API-Keys oder Service Principals, die Signaturen anfordern können.
- **Oracles und Datenfeeds** (Zusammensetzung der Aggregatoren, Quorum, Abweichungsschwellen, Aktualisierungstaktung). Notiere jede vorgelagerte Datenquelle, auf die sich automatisierte Risikologik stützt.
- **Bridges und Cross-Chain-Router** (Lock/Mint-Contracts, Relayer, Settlement-Jobs), die Chains oder Verwahrungs-Stacks miteinander verbinden.

Ergebnis: ein Wertflussdiagramm, das zeigt, wie Assets bewegt werden, wer Bewegungen autorisiert und welche externen Signale die Geschäftslogik beeinflussen.

## 2. Komponenten den AADAPT-Verhaltensweisen zuordnen
Übertrage die AADAPT-Taxonomie in konkrete Angriffskandidaten für jede Komponente.<sup>[[2]](#references)</sup>

| Komponente | AADAPT-Schwerpunkt |
| --- | --- |
| Signatur-/KMS-Umgebungen | Diebstahl von Zugangsdaten, Umgehung von Richtlinien, Missbrauch von Signaturen, Übernahme der Governance |
| Oracles/Feeds | Manipulation von Eingaben, Manipulation der Aggregation, Umgehung von Abweichungsschwellen |
| On-chain-Protokolle | Wirtschaftliche Manipulation durch Flash Loans, Bruch von Invarianten, Neukonfiguration von Parametern |
| Automatisierungs-Pipelines | Kompromittierte Bot-/CI-Identitäten, Batch-Replay, nicht autorisierte Deployments |
| Bridges/Router | Umgehung über Cross-Chain, schnelles Hopping zur Geldwäsche, Desynchronisierung des Settlements |

Mit dieser Zuordnung testest du nicht nur die Contracts, sondern auch alle Identitäten und Automatisierungen, die den Wert indirekt steuern können.

## 3. Nach Angreifbarkeit und geschäftlichen Auswirkungen priorisieren

1. **Operative Schwachstellen**: offengelegte CI-Zugangsdaten, überprivilegierte IAM-Rollen, falsch konfigurierte KMS-Richtlinien, Automatisierungskonten, die beliebige Signaturen anfordern können, öffentliche Buckets mit Bridge-Konfigurationen usw.
2. **Wertspezifische Schwachstellen**: fragile Oracle-Parameter, upgradefähige Contracts ohne Mehrparteiengenehmigungen, anfällige Liquidität für Flash Loans, Governance-Aktionen, die Timelocks umgehen.

Arbeite die Liste wie ein Angreifer ab: Beginne mit den operativen Einstiegspunkten, die heute erfolgreich sein könnten, und gehe dann zu komplexen Protokoll- und Wirtschaftsmanipulationspfaden über.<sup>[[2]](#references)</sup>

## 4. In kontrollierten, produktionsnahen Umgebungen ausführen
- **Forks von Mainnets / isolierte Testnets**: Repliziere Bytecode, Storage und Liquidität, damit Flash-Loan-Pfade, Oracle-Abweichungen und Bridge-Flows vollständig durchgespielt werden können, ohne echte Gelder anzutasten.<sup>[[2]](#references)</sup>
- **Planung des Wirkungsradius**: Lege Circuit Breakers, pausierbare Module, Rollback-Runbooks und Admin-Keys nur für Tests fest, bevor du ein Szenario auslöst.
- **Abstimmung mit Stakeholdern**: Informiere Verwahrer, Oracle-Betreiber, Bridge-Partner und Compliance, damit ihre Monitoring-Teams mit dem Traffic rechnen.
- **Rechtliche Genehmigung**: Dokumentiere Umfang, Autorisierung und Abbruchbedingungen für Simulationen, die regulierte Rails berühren könnten.

## 5. Telemetrie an AADAPT-Techniken ausrichten
Richte Telemetrie-Streams so ein, dass jedes Szenario verwertbare Erkennungsdaten liefert.<sup>[[2]](#references)</sup>

- **Chain-Traces**: vollständige Call Graphs, Gasverbrauch, Transaktions-Nonces, Block-Zeitstempel – zur Rekonstruktion von Flash-Loan-Bundles, reentrancy-ähnlichen Strukturen und Cross-Contract-Hops.
- **Anwendungs-/API-Logs**: Verknüpfe jede On-chain-Tx mit einer menschlichen oder automatisierten Identität (Session-ID, OAuth-Client, API-Key, CI-Job-ID) sowie IPs und Authentifizierungsmethoden.
- **KMS/HSM-Logs**: Key-ID, aufrufender Principal, Richtlinienergebnis, Zieladresse und Reason Codes für jede Signatur. Erfasse übliche Änderungsfenster und risikoreiche Vorgänge als Baseline.
- **Oracle-/Feed-Metadaten**: Zusammensetzung der Datenquellen pro Update, gemeldeter Wert, Abweichung von gleitenden Durchschnitten, ausgelöste Schwellenwerte und genutzte Failover-Pfade.
- **Bridge-/Swap-Traces**: Verknüpfe Lock-/Mint-/Unlock-Ereignisse über Chains hinweg mit Correlation IDs, Chain-IDs, Relayer-Identität und Hop-Zeitpunkten.
- **Anomalieindikatoren**: abgeleitete Kennzahlen wie Slippage-Spitzen, ungewöhnliche Collateral Ratios, ungewöhnliche Gas-Dichte oder Cross-Chain-Geschwindigkeit.

Kennzeichne alles mit Szenario-IDs oder synthetischen Benutzer-IDs, damit Analysten beobachtbare Daten der jeweils getesteten AADAPT-Technik zuordnen können.

## 6. Purple-Team-Zyklus und Reifegradmetriken
1. Führe das Szenario in der kontrollierten Umgebung aus und erfasse Erkennungen (Alarme, Dashboards, benachrichtigte Einsatzkräfte).<sup>[[2]](#references)</sup>
2. Ordne jeden Schritt den konkreten AADAPT-Techniken sowie den in Chain-, App-, KMS-, Oracle- und Bridge-Ebenen erzeugten Beobachtungsdaten zu.
3. Formuliere und implementiere Erkennungshypothesen (Schwellenwertregeln, Korrelationssuchen, Invariantenprüfungen).
4. Wiederhole den Test, bis die mittlere Erkennungszeit (MTTD) und die mittlere Eindämmungszeit (MTTC) den geschäftlichen Toleranzen entsprechen und Runbooks den Wertverlust zuverlässig stoppen.

Verfolge den Programmreifegrad anhand von drei Aspekten:<sup>[[2]](#references)</sup>
- **Sichtbarkeit**: Jeder kritische Wertpfad verfügt in jeder Ebene über Telemetrie.
- **Abdeckung**: Anteil der priorisierten AADAPT-Techniken, die durchgängig getestet wurden.
- **Reaktion**: Fähigkeit, Contracts zu pausieren, Keys zu widerrufen oder Flows vor einem unwiederbringlichen Verlust einzufrieren.

Typische Meilensteine: (1) vollständige Werterfassung und AADAPT-Zuordnung, (2) erstes durchgängiges Szenario mit implementierten Erkennungen, (3) vierteljährliche Purple-Team-Zyklen zur Erweiterung der Abdeckung und Verkürzung von MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Szenario-Vorlagen
Nutze diese wiederholbaren Vorlagen, um Simulationen zu entwerfen, die sich direkt AADAPT-Verhaltensweisen zuordnen lassen.<sup>[[2]](#references)</sup>

### Szenario A – Wirtschaftliche Manipulation durch Flash Loans
- **Ziel**: Innerhalb einer Transaktion vorübergehend Kapital leihen, um AMM-Preise/Liquidität zu verzerren und falsch bewertete Kredite, Liquidationen oder Mint-Vorgänge auszulösen, bevor die Rückzahlung erfolgt.
- **Ausführung**:
  1. Forke die Ziel-Chain und statte Pools mit produktionsnaher Liquidität aus.
  2. Leihe einen hohen Nominalbetrag per Flash Loan.
  3. Führe abgestimmte Swaps durch, um Preis-/Schwellenwertgrenzen zu überschreiten, auf die Lending-, Vault- oder Derivate-Logik angewiesen ist.
  4. Rufe unmittelbar nach der Verzerrung den betroffenen Contract auf (Kredit aufnehmen, liquidieren, minten) und zahle den Flash Loan zurück.
- **Messung**: Wurde die Invariantenverletzung erfolgreich ausgenutzt? Wurden Slippage-/Preisabweichungs-Monitore, Circuit Breakers oder Governance-Pause-Hooks ausgelöst? Wie lange dauerte es, bis die Analyse das anomale Gas-/Call-Graph-Muster erkannte?

### Szenario B – Vergiftung von Oracles/Datenfeeds
- **Ziel**: Feststellen, ob manipulierte Feeds destruktive automatisierte Aktionen auslösen können (Massenliquidationen, fehlerhafte Settlements).
- **Ausführung**:
  1. Stelle im Fork/Testnet einen bösartigen Feed bereit oder verändere Aggregator-Gewichtungen, Quorum oder Aktualisierungstaktung so, dass die tolerierte Abweichung überschritten wird.
  2. Lass abhängige Contracts die vergifteten Werte abrufen und ihre Standardlogik ausführen.
- **Messung**: Out-of-Band-Alarme auf Feed-Ebene, Aktivierung eines Fallback-Oracles, Durchsetzung von Minimal-/Maximalgrenzen und Zeitspanne zwischen Beginn der Anomalie und Reaktion des Betreibers.

### Szenario C – Missbrauch von Zugangsdaten/Signaturen
- **Ziel**: Testen, ob die Kompromittierung eines einzelnen Signers oder einer Automatisierungsidentität nicht autorisierte Upgrades, Parameteränderungen oder das Leeren der Treasury ermöglicht.
- **Ausführung**:
  1. Ermittle Identitäten mit sensiblen Signaturrechten (Betreiber, CI-Tokens, Service Accounts, die KMS/HSM aufrufen, Multisig-Teilnehmer).
  2. Simuliere eine Kompromittierung (verwende ihre Zugangsdaten/Keys innerhalb des Laborumfangs erneut).
  3. Versuche privilegierte Aktionen: Proxies upgraden, Risikoparameter ändern, Assets minten/pausieren oder Governance-Proposals auslösen.
- **Messung**: Lösen KMS/HSM-Logs Anomaliealarme aus (Tageszeit, Abweichung beim Ziel, Häufung risikoreicher Vorgänge)? Können Richtlinien oder Multisig-Schwellenwerte Missbrauch durch Einzelpersonen verhindern? Werden Drosselungen/Ratenbegrenzungen oder zusätzliche Genehmigungen durchgesetzt?

### Szenario D – Umgehung über Cross-Chain und Lücken bei der Nachverfolgbarkeit
- **Ziel**: Bewerten, wie gut Verteidiger Assets nachverfolgen und abfangen können, die schnell über Bridges, DEX-Router und Privacy-Hops gewaschen werden.
- **Ausführung**:
  1. Verknüpfe Lock-/Mint-Vorgänge über gängige Bridges, streue Swaps/Mixer auf jedem Hop ein und verwende durchgängige Correlation IDs pro Hop.
  2. Beschleunige Transfers, um die Monitoring-Latenz zu belasten (mehrere Hops innerhalb von Minuten/Blöcken).
- **Messung**: Zeit für die Korrelation von Ereignissen über Telemetrie und kommerzielle Chain-Analytics hinweg, Vollständigkeit des rekonstruierten Pfads, Fähigkeit, in einem realen Vorfall Ansatzpunkte zum Einfrieren zu identifizieren, sowie Genauigkeit der Alarme bei ungewöhnlicher Cross-Chain-Geschwindigkeit und ungewöhnlichem Wert.

## References

- [1] [AADAPT(TM): Cyber-Threat-Framework für digitale Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Das MITRE-AADAPT-Framework als Roadmap für Red Teams (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
