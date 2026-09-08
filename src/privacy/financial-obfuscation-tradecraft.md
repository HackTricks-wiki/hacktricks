# Tradecraft zur finanziellen Verschleierung

{{#include ../banners/hacktricks-training.md}}

Zahlungsdatenschutz ist ein Attributionsproblem, kein Problem der Zahlungsmarke. Ein Vorgang hinterlässt Beweise, wenn Werte erworben, transferiert, umgewandelt, ausgegeben und zugestellt werden. Eine Adresse auf einer öffentlichen Blockchain kann pseudonym sein, während eine Börse, ein Kartenaussteller, ein Händler, ein Mobilgerät oder eine Versandkamera die dahinterstehende Person identifiziert.

Diese Seite erläutert Muster zur finanziellen Verschleierung, die bei Cyberkriminalität und staatlich verbundenen Operationen eingesetzt werden, damit Verteidiger sie erkennen können. Sie bietet **keine** Anleitung zur Geldwäsche, zur Umgehung von Sanktionen, zur Verwendung falscher Identitäten oder zur Umgehung von KYC.

## Der durchgängige Wertgraph
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Ein Akteur versucht zu verhindern, dass ein Beobachter beide Enden sehen kann. Ermittler gehen umgekehrt vor: Sie bewahren Aufzeichnungen an jeder Grenze auf, normalisieren Zeit, Wert und Gebühren und identifizieren den **Wiederzusammenführungspunkt**, an dem separate Personas denselben Vermittler, dasselbe Gerät, Konto, denselben Händler oder dasselbe Ziel wiederverwenden.

## Instrumente und ihre tatsächlichen Beobachter

| Instrument | Vor Händler/Öffentlichkeit verborgen | Weiterhin sichtbar für |
|---|---|---|
| Virtuelle Karte/Token des Herausgebers | zugrunde liegende Kartennummer | Herausgeber, Netzwerk-/Token-Anbieter, Wallet, Händlerkonto und Zustellsysteme |
| Prepaid-/Geschenkguthaben | bei gewöhnlichem Kauf manchmal der gesetzliche Name | Einzelhändler/Zahlungsnetz, Aktivierungs-/Einlösedienst, Kameras, Gerät und Zustellung |
| Bargeld | öffentliches Hauptbuch und entfernter Herausgeber | Gegenparteien, Kameras, Abhebungs-/Seriennummernkontrollen, sofern anwendbar, physische Durchsuchung |
| Bitcoin/neue Adresse | direkte Zuordnung zu einem gesetzlichen Namen | jeder Blockchain-Beobachter; Wallet-/Netzwerk-Peers; Erwerbs-/Off-ramp-Dienste |
| CoinJoin/PayJoin | einfache Heuristiken zu gemeinsamen Inputs/Zahlungen | öffentliche Transaktion, Metadaten von Koordinator/Peer/Netzwerk und späteres Ausgabeverhalten |
| Privacy Coin | öffentlicher Sender/Empfänger/Betrag, abhängig vom Protokoll | Erwerbs-/Off-ramp-Dienst, Wallet-Endpunkt, Netzwerkbeobachter und Gegenpartei |
| Zentralisierter Mixer | direkte Verbindung zwischen Einzahlung und Auszahlung | Betreiber/Logs des Mixers, Blockchain-Eingangs-/Ausgangsmengen und Gegenparteien |
| Cross-Chain Bridge/Swap | Kontinuität auf einer Chain | beide Chains, Bridge-/Swap-Dienst, zeitliche/Wert- und Liquiditätsbeschränkungen |
| OTC-/P2P-Broker | direktes Börsenkonto in manchen Fällen | Broker, Kommunikation, Bank-/Bargeldbewegungen, Gegenparteien und Geräte |

## Karten, Prepaid-Guthaben, Strohmänner und Mules

### Virtuelle und maskierte Karten

Ein Herausgeber kann eine händlergebundene oder einmalig verwendbare Kartennummer erstellen. Dies verringert die Sichtbarkeit des Händlers und die Wiederverwendung der Nummer bei mehreren Händlern. Der Herausgeber ordnet sie weiterhin dem Kunden, dem Finanzierungskonto, dem Gerät, der IP und der Transaktion zu. Abrechnungsbezeichnungen, Händlerkonto, Lieferadresse und Browserdaten bleiben verknüpfbar.

Werbung für Karten „ohne Namen“ bedeutet keine anonyme Abwicklung. Regulierte Herausgeber und Vertriebsstellen können Identitätsprüfungen durchführen, Aufzeichnungen aufbewahren, geografische und Betragsgrenzen festlegen und auf rechtliche Anordnungen reagieren. Eine über einen Identitätsdiebstahl beschaffte Karte fügt Identitätsdiebstahl hinzu; sie entfernt weder Telemetrie des Herausgebers und Geräts noch des Händlers.

### Prepaid- und Geschenkguthaben

Prepaid-Karten und Geschenkcodes trennen eine spätere Einlösung vom ursprünglichen Zahlungsinstrument, erzeugen jedoch ein nummeriertes Objekt mit Kauf-, Aktivierungs-, Kontostandsabfrage- und Einlöseereignissen. Relevante Muster umfassen Großeinkäufe, wiederholte Stückelungen knapp unterhalb von Kontrollen, schnelle Einlösung an weit entfernten Orten, ein Gerät, das die Guthaben vieler Karten abfragt, oder das Zusammenlaufen vieler Karten bei einem Händler/Konto.

### Strohmänner, Money Mules und Scheinhändler

Ein Strohmann oder Mule stellt ein Konto und eine rechtliche Identität bereit, die zwischen dem Betreiber und einem Dienst liegen. Netzwerke können Recruiter, Kontoinhaber, Zahlungsabwickler, Scheinhändler und Broker für die Auszahlung zwischenschalten. Dies schafft Distanz, doch jeder Teilnehmer fügt Kommunikation, Gebühren, Verhaltensinkonsistenzen und einen potenziellen kooperierenden Zeugen hinzu. Scheinfirmen erzeugen zusätzlich Gründungs-, Steuer-, Bank-, Geschäftsführer-, Rechnungs-, Hosting- und Versandaufzeichnungen.

Verteidiger sollten gemeinsam genutzte Geräte/IPs, die Wiederverwendung von Zahlungsempfängern, Widersprüche bei der Geolokalisierung, eine mit der Kontohistorie unvereinbare Transaktionsgeschwindigkeit, zirkuläre Transfers, das Zusammenlaufen mehrerer unabhängiger Sender und sofortige Weiterbewegungen untersuchen. Gehen Sie nicht davon aus, dass der genannte Kontoinhaber der kontrollierende Akteur ist; behandeln Sie ihn als Knoten, dessen Rolle bestimmt werden muss.

## Muster zur Transaktionsverschleierung auf öffentlichen Chains

### Adressrotation und Coin Control

Das Erstellen einer neuen Adresse für jeden Zahlungseingang verhindert eine triviale Wiederverwendung von Adressen, doch Transaktionen können weiterhin durch gemeinsame Inputs, Change-Erkennung, exakten Wert/Zeitpunkt und spätere Konsolidierung demselben Eigentümer zugeordnet werden. **Coin Control** ermöglicht es einem Wallet, auszuwählen, welche Outputs ausgegeben werden, und das Zusammenführen von Compartments zu vermeiden. Es verbessert die Hygiene; eine bereits öffentliche Verbindung kann dadurch nicht entfernt werden.

### Peel Chains

Eine Peel Chain gibt wiederholt einen großen Saldo aus, sendet einen kleineren Betrag nach außen und führt den Restbetrag an eine neue Adresse zurück:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Die Adresse ändert sich bei jedem Schritt, aber Wertkontinuität, zeitliche Taktung und Transaktionsstruktur bilden häufig eine erkennbare Kette. Legitimate Exchange-Hot-Wallets können sich ähnlich verhalten, daher erfordert die Zuordnung Belege zum Dienst bzw. Kontext. Das DOJ hat die Analyse von Peel-Chains in mit der DVRK verbundenen Verfallsfällen eingesetzt.<sup>[[1]](#references)</sup>

### Structuring und Fan-out/Fan-in

- **Fan-out:** Eine Quelle teilt sich auf viele Adressen auf, um den Ermittlungsaufwand zu erhöhen oder eine parallele Umwandlung vorzubereiten.
- **Fan-in:** Viele Quellen werden in einem Collector konsolidiert, wodurch eine gemeinsame Kontrolle oder ein Dienst sichtbar wird.
- **Structuring:** Wiederholte kleinere Transfers sollen Prüfschwellen vermeiden oder sich in gewöhnliches Volumen einfügen.
- **Commingling:** Illegale und unabhängige Gelder teilen sich Wallets, Pools oder Dienste, wodurch vereinfachte proportionale Zuordnungen unsicher werden.

Die Graphstruktur ist ein Hinweis, kein Beweis. Analysten sollten Gebühren, das UTXO-/Account-Modell, das Verhalten von Diensten und Change-Konventionen berücksichtigen.

### CoinJoin und PayJoin

Bei einem typischen CoinJoin steuern mehrere Teilnehmer Inputs bei und erhalten Outputs in einer gemeinsamen Transaktion, häufig mit gleich großen Output-Stückelungen. Dadurch wird die Annahme widerlegt, dass jeder Input und Output einer Transaktion einen einzigen Eigentümer hat. Das Anonymity Set ist durch die Teilnehmerzahl und das spätere Verhalten begrenzt: Ungleiches Change, toxisches Change, Konsolidierung oder das Überschreiten eines bekannten Dienstes können Verknüpfungen wiederherstellen.

PayJoin verändert eine gewöhnliche Zahlung so, dass sowohl Zahler als auch Zahlungsempfänger Inputs beisteuern, wodurch die gängige Heuristik des gemeinsamen Input-Eigentums für diese Transaktion direkt ungültig wird. Es handelt sich hauptsächlich um ein Payment-Privacy-Protokoll, nicht um einen Bulk-Laundering-Dienst. Bei der Erkennung sollte vermieden werden, alle Inputs als gemeinsam kontrolliert zu deklarieren; stattdessen sollte Unsicherheit ausgedrückt werden, anstatt einen falschen Cluster zu erzwingen.

### Zentralisierte Mixer und Tumbler

Ein zentralisierter Mixer akzeptiert Einzahlungen und zahlt später andere Coins aus einer gemeinsamen Reserve aus, häufig nach Gebühren und Verzögerungen. Seine Privatsphäre hängt von der Poolgröße, der Auszahlungspolitik, Logs, der Ehrlichkeit des Betreibers und der Widerstandsfähigkeit gegen Beschlagnahmung ab. Die Analyse von Ein- und Auszahlungszeitpunkten und -werten, Einzahlungsadressen, der Clusterbildung von Service-Wallets und Aufzeichnungen kann die Menge möglicher Zuordnungen eingrenzen. Betreiber können Gelder stehlen oder eine vollständige Zuordnung aufbewahren.

Die rechtliche Gefährdung ist erheblich und hängt von der jeweiligen Jurisdiktion ab. DOJ-Verfahren gegen ChipMixer, Samourai Wallet sowie Entwickler und Betreiber von Tornado Cash und die sich verändernde Sanktionsrechtsprechung zeigen, dass Tatsachen zu Protokoll, Verwahrung, Kontrolle und Geldübermittlung entscheidend sind; eine Bezeichnung wie „dezentralisiert“ ist keine rechtliche Schlussfolgerung.<sup>[[2]](#references)</sup>

### Cross-chain hopping, Swaps und Bridges

Cross-chain hopping konvertiert einen Vermögenswert oder bewegt ihn über eine Bridge und unterbricht damit eine Abfrage über ein einzelnes Ledger, nicht jedoch die wirtschaftliche Kontinuität:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Analysten korrelieren Bridge-Contracts/Service-Einzahlungsadressen, Transaktionsreihenfolge, Zeitfenster, Wechselkurs, Gebühren, Liquidität und einzigartige Beträge. Wiederholte Swaps können die Mehrdeutigkeit erhöhen und zugleich Telemetriedaten von Providern/APIs/Wallets hinzufügen. FATF identifiziert Chain Hopping, Mixer, Peer-to-Peer-Dienste und anonymitätssteigernde Währungen ausdrücklich als Risikoindikatoren, wenn sie mit einem verdächtigen Kontext kombiniert werden.<sup>[[3]](#references)</sup>

### NFTs, Glücksspiel und Händlerkäufe

Selbstgeschäfte oder kollusive NFT-Trades können Geldern eine scheinbare Verkaufserzählung geben; Glücksspiel kann Einzahlungen in Auszahlungen umwandeln; Waren können digitalen Wert in wiederverkaufbare Bestände umwandeln. Diese Wege hinterlassen Marketplace-Konten, Creator-/Royalty-Verknüpfungen, Wash-Trading-Graphen, Quoten-/Spielhistorien, Geräteprotokolle sowie Nachweise zu Lieferung und Wiederverkauf. Ein Verlust oder eine Gebühr ist kein Beweis dafür, dass die Herkunft verschwunden ist.

## Datenschutzorientierte Kryptowährungen

Privacy-Protokolle unterscheiden sich technisch:

- **Monero** verwendet Einmaladressen, Ring Signatures und vertrauliche Beträge und reduziert dadurch die öffentliche Sichtbarkeit von Sender, Empfänger und Betrag. Netzwerkbeobachtung, Wallet-Kompromittierung, Beschaffung/Off-Ramp und Aufzeichnungen von Gegenparteien bleiben außerhalb dieses On-Chain-Schutzes.
- **Zcash Shielded Pools** können Sender, Empfänger und Betrag verbergen, wenn Shielded Transactions verwendet werden; transparente Adressen und Übergänge zwischen Pools bleiben öffentlich, und Nutzungsmuster beeinflussen die effektive Anonymitätsmenge.
- **Bitcoin** ist standardmäßig transparent. Neue Adressen, CoinJoin, PayJoin und Lightning verändern bestimmte Verknüpfungsannahmen, machen jedoch nicht alle Ebenen privat.

Privacy-Technologie hat legitime Sicherheits- und kommerzielle Anwendungsfälle. Aus Ermittlungsperspektive werden Endpoint-, Service-, Netzwerk- und menschliche Beweise wichtiger, wenn das Ledger weniger Informationen liefert. Schließe niemals allein aus der Wahl eines Privacy-Protokolls auf Kriminalität.

## DPRK-Mehrschichten-Fallmodell

Öffentliche Anschuldigungen des DOJ und Einziehungsverfahren beschreiben einen zusammengesetzten Prozess, nicht einen einzelnen Trick:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. Beschäftigte verwendeten fiktives/gestohlenes Identitätsmaterial und VPNs, um Remote-Arbeitsstellen zu erhalten;
2. Arbeitgeber zahlten Kryptowährung, einschließlich Stablecoins;
3. Gelder wurden in kleineren Beträgen bewegt, wechselten Chains oder Tokens, kauften NFTs oder wurden vermischt;
4. Weitere gestohlene Gelder gelangten in Mixer;
5. OTC-Trader und Briefkastenfirmen wandelten den Wert in Fiat-Zahlungen oder Waren um;
6. Wiederholt auftretende Facilitators, Konten und Blockchain-Pfade ermöglichten es Ermittlern, die Ebenen wieder miteinander zu verknüpfen.

Das Finanzministerium erklärte, dass Lazarus Blender.io zur Verarbeitung eines Teils des Axie-Infinity-/Ronin-Diebstahls verwendete, während das FBI Adressen veröffentlichte und Bridges, Exchanges, RPC-Betreiber und Analytics-Firmen aufforderte, mit späteren TraderTraitor-Diebstählen verknüpfte Gelder zu blockieren.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Die Lehre ist bidirektional: Staatliche Akteure nutzen gewöhnliche kommerzielle/kriminelle Dienste, und öffentliche Blockchains ermöglichen es Verteidigern, dem Wert zu folgen, selbst wenn Namen zunächst unbekannt sind.

## Erkennungs-Workflow

1. **Bewahre die ursprünglichen Transaktionskennungen und Aufzeichnungen auf.** Screenshots und gerundete Fiat-Werte sind unzureichend.
2. **Normalisiere Assets und Zeit.** Erfasse Chain, Token-Contract, Einheiten, Blockzeit, Zeitzone des Dienstes, Gebühren und Quelle des Wechselkurses.
3. **Kennzeichne die Beweissicherheit.** Unterscheide eine von einem Dienst veröffentlichte Adresse, ein deterministisches Contract-Event, eine Clustering-Heuristik und externe Informationen.
4. **Verfolge beide Richtungen.** Ermittle den Finanzierungsursprung, die unmittelbare Verteilung, die erneute Zusammenführung, Bridge-Exits, Service-Einzahlungen sowie Ausgaben/Lieferungen.
5. **Verknüpfe Off-Chain-Beweise.** Account-KYC, Geräte-, IP-, Support-Ticket-, API-Key-, Bank-/Zahlungs-, Versand- und Kommunikationsaufzeichnungen klären Mehrdeutigkeiten oft auf.
6. **Prüfe alternative Erklärungen.** Exchanges, Custodians, Payroll und Privacy-Protokolle können Fan-in/-out oder Co-Spends erzeugen, ohne dass ein gemeinsames wirtschaftliches Eigentum vorliegt.
7. **Überwache weiter, statt den Fall vorzeitig abzuschließen.** Ein ruhender Output kann später zugeordnet werden, wenn er einen Dienst erreicht.
8. **Wende aktuelle Sanktions-/AML-Pflichten mit rechtlicher Beratung an.** Regeln und Designations ändern sich; eine historische Verbindung ersetzt keine aktuelle rechtliche Analyse.

## Sicheres Red-Team-Beschaffungsmodell

Ein autorisiertes Team muss möglicherweise verhindern, dass das Ziel-SOC seine Hosting-Zahlung erkennt, während der Engagement-Controller die Verantwortung behält:

- Verwende eine engagement-spezifische Organisationskarte oder eine dokumentierte Unternehmens-Wallet;
- halte Abrechnungs-, Steuer- und Provider-Aufzeichnungen korrekt;
- trenne den Operator von Beschaffungsaufgaben und beschränke den Zugriff auf die Zuordnungskarte;
- verwende niemals einen Mule, eine falsche Identität, eine gestohlene Karte, eine Sanktionsumgehung oder einen nicht lizenzierten Exchanger;
- dokumentiere Asset, Betrag, Eigentümer, Service, Datum, Erstattungspfad und Nachweise zum Rückbau;
- teile dem Controller nach der Übung relevante Zahlungs-/Provider-Indikatoren mit.

Dadurch entsteht **Blindheit gegenüber dem Übungsteilnehmer**, nicht Blindheit gegenüber Gesetz, Provider oder Governance.

## References

- [1] [US DOJ — Rahmenwerk zur Durchsetzung von Kryptowährungsvorschriften (Peel-Chain-Beispiel und DPRK-Ermittlungen)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Zerschlagung von ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Warnsignale bei virtuellen Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Vertreter der nordkoreanischen Foreign Trade Bank wegen Verschwörungen zur Geldwäsche mit Kryptowährungen angeklagt](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Einziehungsbeschwerde bezüglich angeblich für die DPRK gewaschener 7,74 Millionen US-Dollar](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sanktionen gegen Blender.io und Lazarus-Gelder](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Nordkorea ist für den Bybit-Diebstahl von 2025 verantwortlich](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Anwendung der Vorschriften auf Nutzer, Administratoren und Exchanger virtueller Währungen](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
