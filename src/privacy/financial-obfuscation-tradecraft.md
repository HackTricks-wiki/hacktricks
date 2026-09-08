# Tradecraft zur finanziellen Verschleierung

Zahlungsprivatsphäre ist ein Zuordnungsproblem, kein Problem der Zahlungsmarke. Eine Operation hinterlässt Beweise, wenn Wert beschafft, bewegt, umgewandelt, ausgegeben und zugestellt wird. Eine Adresse auf einer öffentlichen Blockchain kann pseudonym sein, während eine Börse, ein Kartenanbieter, ein Händler, ein Mobilgerät oder eine Versandkamera die dahinterstehende Person identifiziert.

Diese Seite erläutert Muster der finanziellen Verschleierung, die in Cybercrime- und staatlich verbundenen Operationen verwendet werden, damit Verteidiger sie erkennen können. Sie bietet **keine** Anleitung zur Geldwäsche, zur Umgehung von Sanktionen, zur Verwendung falscher Identitäten oder zur KYC-Umgehung.

## Der durchgängige Wertgraph
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Ein Akteur versucht zu verhindern, dass ein Beobachter beide Enden sieht. Ermittler gehen umgekehrt vor: Sie bewahren Aufzeichnungen an jeder Grenze auf, normalisieren Zeit/Wert/Gebühren und identifizieren den **reconvergence point**, an dem getrennte Personas denselben Vermittler, dasselbe Gerät, Konto, denselben Händler oder dasselbe Ziel wiederverwenden.

## Instrumente und ihre tatsächlichen Beobachter

| Instrument | Vor Händler/Öffentlichkeit verborgen | Weiterhin sichtbar für |
|---|---|---|
| Virtuelle Karte/Token des Issuers | zugrunde liegende Kartennummer | Issuer, Netzwerk-/Token-Anbieter, Wallet, Händlerkonto und Zustellsysteme |
| Prepaid-/Geschenkwert | manchmal der rechtliche Name bei einem gewöhnlichen Kauf | Einzelhändler/Payment-Rail, Aktivierungs-/Einlösedienst, Kameras, Gerät und Zustellung |
| Bargeld | öffentliches Ledger und entfernter Issuer | Gegenparteien, Kameras, Abhebungs-/Seriennummernkontrollen, sofern zutreffend, physische Durchsuchung |
| Bitcoin/neue Adresse | direkte rechtliche Identität | jeder Blockchain-Beobachter; Wallet-/Netzwerk-Peers; Acquisition-/Off-Ramp-Dienste |
| CoinJoin/PayJoin | einfache Heuristiken zu gemeinsamen Inputs/Zahlungen | öffentliche Transaktion, Coordinator-/Peer-/Netzwerk-Metadaten und späteres Ausgabeverhalten |
| Privacy Coin | öffentlicher Sender/Empfänger/Betrag, abhängig vom Protokoll | Acquisition-/Off-Ramp, Wallet-Endpunkt, Netzwerkbeobachter und Gegenpartei |
| Zentralisierter Mixer | direkte Einzahlungs-/Auszahlungsverknüpfung | Mixer-Betreiber/Logs, Blockchain-Ein-/Ausstiegsgruppen und Gegenparteien |
| Cross-Chain Bridge/Swap | Kontinuität auf einer Chain | beide Chains, Bridge-/Swap-Dienst, Zeit-/Wert- und Liquiditätsbeschränkungen |
| OTC/P2P-Broker | direktes Exchange-Konto in manchen Fällen | Broker, Kommunikation, Bank-/Bargeldbewegungen, Gegenparteien und Geräte |

## Karten, Prepaid-Wert, Strohmänner und Mules

### Virtuelle und maskierte Karten

Ein Issuer kann eine an einen Händler gebundene oder einmalig verwendbare Kartennummer erstellen. Dies reduziert die Sichtbarkeit für den Händler und die Wiederverwendung der Nummer bei mehreren Händlern. Der Issuer ordnet sie weiterhin dem Kunden, dem Funding-Konto, dem Gerät, der IP-Adresse und der Transaktion zu. Abrechnungsbezeichnungen, Händlerkonto, Lieferadresse und Browserdaten bleiben verknüpfbar.

Marketing für Karten „ohne Namen“ bedeutet keine anonyme Abwicklung. Regulierte Issuer und Distributoren können Identitätsprüfungen durchführen, Aufzeichnungen aufbewahren, geografische und Betragsgrenzen festlegen und auf rechtliche Anordnungen reagieren. Eine mit einer gestohlenen Identität erworbene Karte stellt Identitätsdiebstahl dar; sie beseitigt weder die Telemetrie des Issuers, des Geräts noch des Händlers.

### Prepaid- und Geschenkwert

Prepaid-Karten und Geschenkcodes trennen eine spätere Einlösung vom ursprünglichen Zahlungsinstrument, erzeugen jedoch ein nummeriertes Objekt mit Ereignissen beim Kauf, bei der Aktivierung, bei der Saldoabfrage und bei der Einlösung. Relevante Muster sind unter anderem Großeinkäufe, wiederholte Nennwerte knapp unterhalb von Kontrollen, schnelle Einlösungen an weit entfernten Orten, ein Gerät, das viele Salden abfragt, oder viele Karten, die bei demselben Händler/Konto zusammenlaufen.

### Strohmänner, Money Mules und Händlerfronten

Ein Strohmann oder Mule stellt ein Konto und eine rechtliche Identität bereit, die zwischen dem Betreiber und einem Dienst liegen. Netzwerke können Recruiter, Kontoinhaber, Payment-Processor, Scheinhändler und Cash-out-Broker als Schichten einsetzen. Dies schafft Distanz, aber jeder Beteiligte fügt Kommunikation, Gebühren, Verhaltensinkonsistenzen und einen potenziellen kooperierenden Zeugen hinzu. Frontunternehmen erzeugen Aufzeichnungen zu Gründung, Steuern, Bankverbindungen, Geschäftsführern, Rechnungen, Hosting und Lieferungen.

Verteidiger sollten gemeinsam genutzte Geräte/IPs, die Wiederverwendung von Zahlungsempfängern, Widersprüche bei der Geolokalisierung, eine mit der Kontohistorie unvereinbare Geschwindigkeit, zirkuläre Transfers, das Zusammenlaufen mehrerer unabhängiger Sender sowie unmittelbare Weiterbewegungen untersuchen. Gehen Sie nicht davon aus, dass der genannte Kontoinhaber der steuernde Akteur ist; behandeln Sie ihn als Knoten, dessen Rolle bestimmt werden muss.

## Muster zur Transaktionsverschleierung auf öffentlichen Chains

### Adressrotation und Coin Control

Für jeden Zahlungseingang eine neue Adresse zu erstellen, verhindert eine triviale Wiederverwendung von Adressen. Transaktionen können jedoch weiterhin durch gemeinsame Inputs, Change-Erkennung, exakten Wert/Zeitpunkt und spätere Konsolidierung demselben Eigentümer zugeordnet werden. **Coin control** ermöglicht es einer Wallet, auszuwählen, welche Outputs ausgegeben werden, und die Verbindung von Kompartimenten zu vermeiden. Dies verbessert die Hygiene; eine bereits öffentliche Verbindung kann dadurch nicht entfernt werden.

### Peel Chains

Eine Peel Chain gibt wiederholt einen großen Saldo aus, sendet einen kleineren Betrag nach außen und führt den Rest an eine neue Adresse zurück:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Die Adresse ändert sich bei jedem Schritt, aber Wertkontinuität, Taktung und Transaktionsstruktur bilden oft eine erkennbare Kette. Legitimate Exchange-Hot-Wallets können sich ähnlich verhalten, daher erfordert die Attribution Belege zum Service und Kontext. DOJ hat die Analyse von Peel-Chains in mit der DPRK verbundenen Einziehungsverfahren eingesetzt.<sup>[[1]](#references)</sup>

### Structuring und Fan-out/Fan-in

- **Fan-out:** Eine Quelle teilt sich auf viele Adressen auf, um den Ermittlungsaufwand zu erhöhen oder eine parallele Konvertierung vorzubereiten.
- **Fan-in:** Viele Quellen werden in einem Collector zusammengeführt, was auf eine gemeinsame Kontrolle oder einen Service hinweist.
- **Structuring:** Wiederholte kleinere Transfers versuchen, Prüfschwellen zu vermeiden oder sich in gewöhnliches Volumen einzufügen.
- **Commingling:** Illicit Funds und nicht zusammenhängende Funds teilen sich Wallets, Pools oder Services, wodurch vereinfachte proportionale Zuordnungen unsicher werden.

Die Graphform ist ein Hinweis, kein Beweis. Analysten sollten Gebühren, UTXO/account model, das Verhalten des Services und Change-Konventionen berücksichtigen.

### CoinJoin und PayJoin

Bei einem typischen CoinJoin steuern mehrere Teilnehmer Inputs bei und erhalten Outputs in einer gemeinsamen Transaktion, häufig mit gleichen Output-Stückelungen. Dadurch wird die Annahme widerlegt, dass jeder Input und Output einer Transaktion einen einzigen Eigentümer hat. Das Anonymity Set ist durch die Teilnehmerzahl und das spätere Verhalten begrenzt: ungleiche Change-Beträge, toxic change, Konsolidierung oder das Überqueren eines bekannten Services können Verbindungen wiederherstellen.

PayJoin verändert eine gewöhnliche Zahlung so, dass sowohl Zahler als auch Zahlungsempfänger Inputs beisteuern, wodurch die Common-Input-Ownership-Heuristik für diese Transaktion direkt ungültig wird. Es handelt sich in erster Linie um ein Payment-Privacy-Protokoll, nicht um einen Bulk-Laundering-Service. Bei der Erkennung sollte vermieden werden, alle Inputs als gemeinsames Eigentum zu deklarieren; stattdessen sollte Unsicherheit ausgedrückt werden, anstatt einen falschen Cluster zu erzwingen.

### Zentralisierte Mixer und Tumbler

Ein zentralisierter Mixer akzeptiert Einzahlungen und zahlt später andere Coins aus einer gemeinsamen Reserve aus, häufig nach Gebühren und Verzögerungen. Seine Privacy hängt von der Poolgröße, der Auszahlungsrichtlinie, Logs, der Ehrlichkeit des Operators und der Widerstandsfähigkeit gegen Beschlagnahmung ab. Die Analyse von Ein- und Auszahlungszeitpunkten und -werten, Deposit-Adressen, dem Clustering von Service-Wallets und Aufzeichnungen kann die Menge möglicher Zuordnungen einschränken. Betreiber können Funds stehlen oder eine vollständige Zuordnung speichern.

Die rechtliche Exposition ist erheblich und von der jeweiligen Jurisdiktion abhängig. DOJ-Verfahren gegen ChipMixer, Samourai Wallet sowie Entwickler und Betreiber von Tornado Cash und die sich ändernde Sanktionsrechtsprechung zeigen, dass Fakten zu Protokoll, Verwahrung, Kontrolle und Geldübermittlung maßgeblich sind; eine Bezeichnung wie „dezentralisiert“ ist keine rechtliche Schlussfolgerung.<sup>[[2]](#references)</sup>

### Chain Hopping, Swaps und Bridges

Chain Hopping konvertiert einen Asset oder bewegt ihn über eine Bridge und unterbricht damit eine Abfrage über ein einzelnes Ledger, nicht jedoch die wirtschaftliche Kontinuität:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Analysten korrelieren Bridge-Contracts/Service-Einzahlungsadressen, Transaktionsreihenfolge, Zeitfenster, Wechselkurs, Gebühren, Liquidität und eindeutige Beträge. Wiederholte Swaps können die Mehrdeutigkeit erhöhen und gleichzeitig Provider-/API-/Wallet-Telemetrie hinzufügen. FATF identifiziert Chain Hopping, Mixer, Peer-to-Peer-Dienste und anonymitätsverstärkte Währungen ausdrücklich als Risikoindikatoren, wenn sie mit einem verdächtigen Kontext kombiniert werden.<sup>[[3]](#references)</sup>

### NFTs, Glücksspiel und Händlerkäufe

Eigengeschäfte oder kollusive NFT-Trades können den Geldern eine scheinbare Verkaufsgeschichte geben; Glücksspiel kann Einzahlungen in Auszahlungen umwandeln; Waren können digitalen Wert in wiederverkaufbare Bestände umwandeln. Diese Wege hinterlassen Marketplace-Konten, Creator-/Royalty-Verknüpfungen, Wash-Trading-Graphen, Quoten-/Spielhistorien, Geräteprotokolle sowie Nachweise zu Lieferung und Wiederverkauf. Ein Verlust oder eine Gebühr beweist nicht, dass die Herkunft verschwunden ist.

## Datenschutzorientierte Kryptowährungen

Privacy-Protokolle unterscheiden sich technisch:

- **Monero** verwendet Einmaladressen, Ring-Signaturen und vertrauliche Beträge und reduziert dadurch die öffentliche Sichtbarkeit von Sender, Empfänger und Betrag. Netzwerkbeobachtung, Wallet-Kompromittierung, Erwerbs-/Off-Ramp- und Gegenparteiaufzeichnungen bleiben außerhalb dieses On-Chain-Schutzes.
- **Zcash Shielded Pools** können Sender, Empfänger und Betrag verbergen, wenn Shielded-Transaktionen verwendet werden; transparente Adressen und Übergänge zwischen Pools bleiben öffentlich, und Nutzungsmuster beeinflussen die effektive Anonymitätsmenge.
- **Bitcoin** ist standardmäßig transparent. Neue Adressen, CoinJoin, PayJoin und Lightning verändern bestimmte Verknüpfungsannahmen, machen jedoch nicht alle Ebenen privat.

Privacy-Technologie hat legitime Sicherheits- und kommerzielle Anwendungsbereiche. Aus Ermittlungsperspektive werden Endpoint-, Service-, Netzwerk- und menschliche Beweise wichtiger, wenn das Ledger weniger Informationen liefert. Leite niemals allein aus der Wahl eines Privacy-Protokolls Kriminalität ab.

## DPRK-Mehrschichten-Fallmodell

Öffentliche Vorwürfe und Einziehungsmaßnahmen des DOJ beschreiben einen zusammengesetzten Prozess, nicht einen einzelnen Trick:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. Beschäftigte verwendeten fingiertes/gestohlenes Identitätsmaterial und VPNs, um eine Remote-Beschäftigung zu erhalten;
2. Arbeitgeber zahlten Kryptowährung, einschließlich Stablecoins;
3. Gelder wurden in kleineren Beträgen bewegt, überquerten Chains oder Token, kauften NFTs oder wurden vermischt;
4. andere gestohlene Gelder gelangten in Mixer;
5. OTC-Trader und Briefkastenfirmen wandelten den Wert in Fiat-Zahlungen oder Waren um;
6. wiederholt verwendete Facilitators, Konten und Blockchain-Pfade ermöglichten es Ermittlern, die Ebenen wieder miteinander zu verknüpfen.

Das Finanzministerium erklärte, dass Lazarus Blender.io nutzte, um einen Teil des Axie-Infinity-/Ronin-Diebstahls zu verarbeiten, während das FBI Adressen veröffentlichte und Bridges, Exchanges, RPC-Betreiber und Analytics-Firmen aufforderte, mit späteren TraderTraitor-Diebstählen verknüpfte Gelder zu blockieren.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Die Lehre ist bidirektional: Staatliche Akteure nutzen gewöhnliche kommerzielle/kriminelle Dienste, und öffentliche Blockchains ermöglichen es Verteidigern, den Wert zu verfolgen, selbst wenn Namen zunächst unbekannt sind.

## Erkennungs-Workflow

1. **Bewahre die rohen Transaktionskennungen und Aufzeichnungen auf.** Screenshots und gerundete Fiat-Werte sind unzureichend.
2. **Normalisiere Assets und Zeit.** Erfasse Chain, Token-Contract, Einheiten, Blockzeit, Service-Zeitzone, Gebühren und Quelle des Wechselkurses.
3. **Kennzeichne die Beweissicherheit.** Unterscheide zwischen einer vom Service veröffentlichten Adresse, einem deterministischen Contract-Event, einer Clustering-Heuristik und externen Informationen.
4. **Verfolge beide Richtungen.** Ermittle den Ursprung der Finanzierung, die unmittelbare Verteilung, die Wiederzusammenführung, Bridge-Exits, Service-Einzahlungen und Ausgaben/Lieferungen.
5. **Verknüpfe Off-Chain-Beweise.** Account-KYC-, Geräte-, IP-, Support-Ticket-, API-Key-, Bank-/Zahlungs-, Versand- und Kommunikationsaufzeichnungen klären häufig Mehrdeutigkeiten.
6. **Prüfe alternative Erklärungen.** Exchanges, Custodians, Payroll und Privacy-Protokolle können Fan-in/-out oder Co-Spends erzeugen, ohne gemeinsames wirtschaftliches Eigentum zu bedeuten.
7. **Überwache, statt vorschnell abzuschließen.** Ein ruhender Output kann später zuordenbar werden, wenn er anschließend einen Service erreicht.
8. **Wende aktuelle Sanktions-/AML-Pflichten mit juristischer Beratung an.** Regeln und Designations ändern sich; eine historische Verbindung ersetzt keine aktuelle rechtliche Analyse.

## Sicheres Red-Team-Beschaffungsmodell

Ein autorisiertes Team muss möglicherweise verhindern, dass der Ziel-SOC seine Hosting-Zahlung erkennt, während der Engagement-Controller die Verantwortlichkeit behält:

- verwende eine engagement-spezifische Organisationskarte oder eine dokumentierte Unternehmens-Wallet;
- halte Abrechnungs-, Steuer- und Provider-Aufzeichnungen korrekt;
- trenne den Operator von Beschaffungsaufgaben und beschränke den Zugriff auf die Zuordnungskarte;
- verwende niemals einen Mule, eine falsche Identität, eine gestohlene Karte, eine Sanktionsumgehung oder einen nicht lizenzierten Exchanger;
- dokumentiere Asset, Betrag, Eigentümer, Service, Datum, Rückerstattungspfad und Nachweise zum Abbau;
- lege dem Controller nach der Übung relevante Zahlungs-/Provider-Indikatoren offen.

Dies erzeugt **Blindheit gegenüber dem Übungsteilnehmer**, nicht Blindheit gegenüber Gesetzen, Providern oder Governance.

## References

- [1] [US DOJ — Rahmenwerk zur Durchsetzung von Kryptowährungsrecht (Peel-Chain-Beispiel und DPRK-Ermittlungen)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Stilllegung von ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Warnindikatoren für Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Vertreter der nordkoreanischen Foreign Trade Bank wegen Verschwörungen zur Geldwäsche mit Kryptowährungen angeklagt](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Einziehungsbeschwerde bezüglich angeblich für die DPRK gewaschener 7,74 Millionen US-Dollar](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sanktionen gegen Blender.io und Lazarus-Gelder](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Nordkorea ist für den Diebstahl bei Bybit im Jahr 2025 verantwortlich](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Anwendung der Vorschriften auf Nutzer, Administratoren und Exchanger virtueller Währungen](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
