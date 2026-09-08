# Katalog anonymer Zahlungstechniken

Dieser Katalog umfasst **Familien** von Zahlungen – von gewöhnlichem Bargeld über E-Cash mit blind signatures bis hin zur Verschleierung in öffentlichen Chains. „Anonym“ bedeutet immer anonym gegenüber einem benannten Beobachter. Ein Händler, Issuer, eine Mint, eine Exchange, ein Blockchain-Analyst, Network-Provider, Arbeitgeber und physischer Beobachter sehen jeweils unterschiedliche Fakten.

Die folgenden Verfahren gelten für rechtmäßige Gelder, wahrheitsgemäße Konten und autorisierte Beschaffung. Techniken, deren Zweck in den zitierten Fällen Geldwäsche, Sanktionsumgehung oder Identitätsbetrug war, werden erklärt und erkannt; ihr Verfahren ist jedoch eine synthetische forensische Übung – keine Anleitung zur Begehung der Straftat.

## Abdeckungsmatrix

| Familie | Wichtigste Privacy-Eigenschaft | Wichtigster Beobachter/Trust | Behandlung |
|---|---|---|---|
| Bargeld und bargeldähnliche Werte | kein Remote-Zahlungsnetzwerkdatensatz | Empfänger und physische Umgebung | rechtmäßiger Workflow |
| Prepaid-/Geschenk-/Gutscheinwert | trennt Einlösung von primärer Karte | Verkäufer, Issuer und Einlösedienst | rechtmäßiger Workflow, je nach Jurisdiktion unterschiedlich |
| Virtuelle/tokenisierte Karte | verbirgt wiederverwendbare PAN oder trennt Händler | Issuer/Network/Wallet identifizieren den Zahler weiterhin | rechtmäßiger Workflow |
| Payment-App/Intermediary | Händler sieht möglicherweise Alias/Intermediary | App sammelt Identität/Gerät/Transaktion | Vergleichsbasis |
| Bitcoin-Hygiene/Silent Payments | Pseudonyme und Unlinkability des Empfängers | öffentliche Graph und Wallet-/Netzwerkgrenze | einsetzbar |
| PayJoin/CoinJoin | schwächt Heuristiken für gemeinsame Eigentümerschaft/Verknüpfung | Teilnehmer/Coordinator/Network/public graph | einsetzbar, sofern unterstützt; rechtliche Prüfung |
| Lightning/BOLT 12 | Off-Chain-Routing und verringerte Sichtbarkeit des Empfängerpfads | Endpunkte, Hops, Services und Channel-Graph | einsetzbar, sofern unterstützt |
| Monero/Zcash/MWEB | Confidentiality auf Protokollebene | Beschaffung, Endpunkt, Netzwerk und Grenzen bleiben sichtbar | einsetzbar, sofern rechtmäßig/unterstützt |
| Ethereum-ZK-Anwendung | verbirgt eine bestimmte Aussage-/Aktionsverknüpfung | öffentliche Inputs, RPC, Relayer und App | anwendungsspezifisch |
| Cashu/Fedimint/Taler | Privacy des Zahlers durch blind signatures | Mint/Federation/Exchange-Custody und Grenzen | aufkommend/deployment-spezifisch |
| Stablecoins | bequeme digitale Abwicklung | transparente Chain plus Issuer-Freeze/Control | keine anonyme Baseline |
| Swaps/Bridges/DEX | bewegt Wert über Asset-/Chain-Grenzen | beide Graphen, Contracts und Provider | forensische Mechanik; nur gewöhnliche rechtmäßige Swaps |
| Mixer/Peel/Structuring | erhöht Graph-Ambiguität/Arbeitsaufwand | Entry-/Exit-Graph und Serviceaufzeichnungen | ausschließlich synthetische Erkennungsübung |
| Nominees/Mules/OTC/Fronts | fügt menschliche/geschäftliche Intermediaries ein | Facilitators, Banken, Kommunikation | ausschließlich Analyse kriminellen Missbrauchs |
| Wiederverwendbare/Stealth-Payment-Adressen | neue Empfängeradresse pro Zahlung | öffentliche Bekanntgabe/Benachrichtigung und Wallet-Grenzen | einsetzbar, sofern unterstützt |
| Confidential Sidechain/State Channel | verbirgt Betrag/Asset oder Zwischenaktualisierungen | Peers, Bridge/Federation und Lifecycle-Settlement | protokollspezifisch |
| Carrier/Open Banking/Platform Billing | verbirgt primäre Karte vor dem Händler | Carrier, Bank/PISP oder Platform identifizieren den Kunden | gewöhnliche identifizierte Zahlung |
| Mutual Credit/Net Settlement | weniger externe Settlement-Datensätze | privater Ledger-Betreiber besitzt vollständige Zuordnung | nur identifizierte Teilnehmer |

## Bargeld

**Mechanik:** Physischer Bearer Value wechselt den Besitzer, ohne Online-Autorisierung durch einen Issuer oder ein öffentliches Ledger.

**Vorteile:** Der Händler muss die Bank-/Kartenidentität nicht erfahren; kein Remote-Transaktionsgraph; allgemein verständlich und endgültig.

**Nachteile:** Nur face-to-face; Diebstahl/Verlust; Wechselgeld/Quittungen/Seriennummern oder Meldekontrollen; Abhebungen, Kameras, Zeugen und Standort können den Zahler weiterhin verknüpfen.

**Verfahren:** (1) Bestätigen, dass Bargeld rechtmäßig akzeptiert wird und welche Betrags-/Melderegel gilt; (2) es rechtmäßig abheben oder erhalten und private Buchhaltungsunterlagen führen; (3) einen gewöhnlichen Händler ohne unnötige Loyalty-/Kontokennungen bezahlen; (4) nur die erforderliche Quittung anfordern; (5) keine Versand-/Kontodaten angeben, wenn der Kauf sie nicht benötigt; (6) den legitimen Geschäftszweck intern dokumentieren.

**Erkennung:** Kasse/Quittung/Inventar sowie Kameras und Zugriffprotokolle gemäß geltender Richtlinie abgleichen; ungewöhnliche Bargeldrückerstattungen oder wiederholte Beträge knapp unter Kontrollgrenzen untersuchen, ohne gewöhnliche Bargeldnutzung allein als verdächtig zu behandeln.

## Zahlungsanweisung, Postanweisung, Bankscheck und Nachnahme

**Mechanik:** Ein regulierter Issuer wandelt Bargeld/Kontoguthaben in ein nummeriertes Instrument um, das an einen benannten Empfänger zahlbar ist; bei Nachnahme wird die Einziehung bis zur Lieferung aufgeschoben.

**Vorteile:** Der Empfänger erhält möglicherweise nicht die primäre Bank-/Kartennummer des Zahlers; nutzbar, wenn Bargeld nicht remote versendet werden kann; klare Quittung.

**Nachteile:** Issuer/Händler speichern Kauf-/Identitätsdaten wie vorgeschrieben; Seriennummern-Tracking; Empfänger-/Lieferadresse; Verlust/Betrug und regionale Beschränkungen; im Allgemeinen nicht anonym.

**Verfahren:** (1) Regeln, Limits, Identifikationsanforderungen und Akzeptanz des Empfängers prüfen; (2) mit wahrheitsgemäßen Angaben und rechtmäßigen Geldern kaufen; (3) Zahlungsempfänger/Betrag sofort eintragen; (4) Seriennummer/Quittung aufbewahren; (5) eine dem Wert angemessene Sendungsverfolgung verwenden; (6) Einlösung/Rückerstattung abgleichen.

**Erkennung:** Kauf-/Einlösedatensatz des Issuers, Instrumentenseriennummer, Händler/Kamera, Versand und Empfängerkonto; Änderungen, doppelte Seriennummern und eine schnelle, geografisch unplausible Einlösung markieren.

## Open-Loop-Prepaid-Karte

**Mechanik:** Ein netzwerkgebundenes Stored-Value-Instrument autorisiert gegen ein Prepaid-Guthaben statt gegen ein primäres Kreditkonto.

**Vorteile:** Begrenzt Händlerexposition und Verlust; trennt den Händler von der Haupt-PAN; online nutzbar, sofern akzeptiert.

**Nachteile:** Kauf-/Aktivierungs-/Auflade-/Registrierungs- und Gerätedaten; KYC und Limits variieren; Fehler bei Rechnungsadressen; Einschränkungen bei Auszahlung/Rückerstattung; „kein Name“ bedeutet nicht „kein Datensatz beim Issuer“.

**Verfahren:** (1) aktuelle Issuer-Identität, Gebühren, KYC, Geografie sowie Online-/Recurring-Unterstützung prüfen; (2) über einen autorisierten Verkäufer mit rechtmäßigen Geldern beschaffen; (3) erforderliche Daten wahrheitsgemäß registrieren; (4) für einen einzigen Bereich/Zweck verwenden; (5) keine Loads strukturieren und keinen Wohnsitz erfinden; (6) Kauf-/Ausgabennachweise aufbewahren und nach Issuer-Bedingungen schließen/entsorgen.

**Erkennung:** Verkäufer-/Aktivierungsdaten, Funding, Gerät/IP, Händlerautorisierung, Saldoabfragen und Einlösung/Rückerstattung verknüpfen. Das Prepaid-Label allein ist weniger wichtig als die Muster.

## Closed-Loop-Geschenkkarte, Gutschein und übertragbares Serviceguthaben

**Mechanik:** Ein nummerierter Wert kann nur bei einem Händler/Service oder innerhalb eines Ökosystems eingelöst werden. Airtime-, Game- und Store-Credits sind Varianten.

**Vorteile:** Der empfangende Händler sieht möglicherweise nur Code/Guthaben; begrenzter Schadensradius; einfaches Schenken und Budgettrennung.

**Nachteile:** Verkäufer und Service protokollieren Kauf/Aktivierung/Einlösung; Konto/Gerät/Zustellung stellen weiterhin Verbindungen her; Betrug, Wiederverkaufsrabatte und Ablauf-/Regionslimits; schwache Rückerstattungsrechte.

**Verfahren:** (1) ausschließlich über autorisierte Kanäle kaufen; (2) Codewert dokumentieren, ohne das Secret preiszugeben; (3) kein identifizierendes Loyalty-Konto verknüpfen, wenn unnötig; (4) über ein separates legitimes Händlerkonto/einen separaten Kontext einlösen; (5) Quittung bis zur Akzeptanz aufbewahren; (6) niemals Codes für eine unaufgeforderte „Steuer-/Support-/Lösegeld“-Forderung kaufen.

**Erkennung:** Zeitpunkt der Codeausgabe/-einlösung, Geräte-/Kontozusammenführung, Käufe in großen Mengen oder mit Schwellenmustern, ein Gerät mit vielen Saldoabfragen und schnelle Einlösung an weit entfernten Orten.

## Cryptocurrency-finanzierte Karte oder Gift-Code-Broker

**Mechanik:** Ein Intermediary akzeptiert Cryptocurrency und gibt eine Karte, einen Gutschein oder einen Händlercode aus. Dies ist eine Cross-Rail-Konvertierung: Der Händler sieht gewöhnlichen Karten-/Geschenkwert, während der Broker die On-Chain-Einzahlung mit Ausgabe und Zustellung verknüpft.

**Vorteile:** Der Händler erhält nicht die Funding-Wallet; nützlich für legitime Händler ohne Crypto-Akzeptanz; begrenzter Stored Value.

**Nachteile:** Nicht anonym gegenüber Broker/Issuer; KYC-, Sanktions-, Exchange- und Card-Program-Regeln; öffentlicher Deposit-Graph; Konto/Gerät/E-Mail und Code-Einlösung verbinden beide Seiten wieder; Betrugs-/Insolvenzrisiko.

**Verfahren:** (1) juristische Person, Kartenissuer, unterstützte Jurisdiktion, KYC, Gebühren und Rückerstattungsrichtlinie prüfen; (2) nur rechtmäßige, dokumentierte Gelder verwenden; (3) kleinste Stückelung testen; (4) Netzwerk-/Händlerbeschränkungen vor dem Kauf prüfen; (5) sowohl Blockchain-Transaktion als auch Brokerquittung für die Buchhaltung aufbewahren; (6) niemals einen Broker verwenden, der Identitätsbetrug, Sanktionsumgehung oder „untraceable“ Cash-out verspricht.

**Erkennung:** Broker-Deposit-Adressen, eindeutiger Betrag/Zeitpunkt, Konto/Gerät sowie Kartenautorisierung oder Gift-Code-Einlösung korrelieren; Issuer- und Brokeraufzeichnungen verbinden die öffentliche Chain mit dem Händler.

## Virtuelle oder händlergebundene Karte

**Mechanik:** Der Issuer ordnet eine generierte PAN/einen Token dem echten Konto zu und beschränkt häufig Händler, Betrag oder Ablaufdatum.

**Vorteile:** Verhindert die Offenlegung einer wiederverwendbaren PAN; Händlerkompartimentierung; Ausgabenlimits und einfache Sperrung; ausgereifte Fraud Controls.

**Nachteile:** Der Issuer kennt weiterhin Zahler, Funding, Händler, Gerät/IP und Zeitpunkt; der Händler sieht Konto/Zustellung; einige Rückerstattungen/Recurring Charges schlagen fehl; nicht anonym.

**Verfahren:** (1) die offizielle Funktion des regulierten Issuers verwenden; (2) eine Karte für einen Händler/ein Engagement erstellen; (3) kleinstmögliches sinnvolles Limit und Ablaufdatum setzen; (4) erforderliche Rechnungsdaten korrekt angeben; (5) Statement Descriptor und Rückerstattungsverhalten prüfen; (6) nach dem finalen Settlement einfrieren/löschen und Auditnachweise aufbewahren.

**Erkennung:** Issuer-Zuordnung von Token zu Konto, Händlerautorisierung, Gerät und Zustellung. Defenders nutzen händlerspezifische Wiederverwendung, Velocity und Account-Takeover-Signale.

## Mobile-Wallet-Network-Token

**Mechanik:** EMV-Payment-Tokenization ersetzt die PAN durch ein eingeschränktes Credential, das häufig an Gerät, Händler oder Zahlungsszenario gebunden ist.<sup>[[1]](#references)</sup>

**Vorteile:** Der Händler erhält nicht die wiederverwendbare PAN; Geräte-Kryptografie und dynamische Daten reduzieren Cloning; Widerruf ohne Kartentausch.

**Nachteile:** Issuer, Token-Service, Wallet-Plattform und Network speichern Zuordnungen/Transaktionen; Geräte-/Plattformkonto und Standort können den Zahler identifizieren.

**Verfahren:** (1) eine legitime Karte in der offiziellen Wallet registrieren; (2) Plattformkonto/Gerät mit starker Authentifizierung schützen; (3) Geräte-Token/letzte Ziffern beim Kauf prüfen; (4) unnötigen Standortzugriff/Analytics deaktivieren, sofern unterstützt; (5) verlorene Geräte/Tokens sofort deaktivieren; (6) Issuer- und Wallet-Datensätze prüfen.

**Erkennung:** Token-Requestor, Geräte-Cryptogram und Issuer-Zuordnung, Wallet-/Kontotelemetrie, Händlerterminal und physische Beweise.

## Payment-App, Marketplace-Wallet und zentralisierter Intermediary

**Mechanik:** Der Service verwaltet Konten und transferiert intern oder über Bank-/Kartenrails; der Händler sieht möglicherweise einen Alias, während der Service beide Parteien kennt.

**Vorteile:** Komfort, Streit-/Rückerstattungsmechanismen; der Empfänger muss Bank-/Kartendaten nicht unbedingt sehen.

**Nachteile:** Zentralisierter Identitäts-/Social-/Transaktions-/Gerätegraph; Sperren und rechtliche Verfahren; Gegenparteien können Profile offenlegen; Datennutzung kann über den Zahlungszweck hinausgehen.<sup>[[2]](#references)</sup>

**Verfahren:** (1) Identitäts-, Privacy-, Aufbewahrungs- und Käuferschutzbedingungen lesen; (2) optionale Profil-/Kontaktsynchronisierung minimieren; (3) separates wahrheitsgemäßes Konto nur verwenden, wenn die Bedingungen dies erlauben; (4) MFA/Alerts aktivieren; (5) Empfänger und Privacy von Memo/Profil prüfen; (6) Datensätze exportieren und ungenutzte Verknüpfungen schließen.

**Erkennung:** Providerkonto, Gerät/IP, Kontaktgraph, Funding/Withdrawal, Memo und Händlerdatensätze. Ein Alias bedeutet Pseudonymität gegenüber einer Gegenpartei, nicht Anonymität gegenüber der Plattform.

## Banküberweisung, ACH, Wire und Instant-Account-Payment

**Mechanik:** Regulierte Institute bewegen Werte zwischen identifizierten Konten und tauschen erforderliche Zahlungsdaten aus.

**Vorteile:** Schnell, nachvollziehbar, in begrenztem Umfang rückgängig machbar, starke Datensätze; virtuelle Kontonummern können die Händleroffenlegung reduzieren.

**Nachteile:** Banken/Processor kennen beide Seiten; Kontoauszüge und Referenzen; nicht anonym; grenzüberschreitende Daten sowie Travel-Rule-/AML-Daten.

**Verfahren:** Nur verwenden, wenn Verantwortlichkeit akzeptabel ist: Begünstigten unabhängig prüfen, optionale Memodaten minimieren, ein von der Bank bereitgestelltes virtuelles Konto/eine Referenz verwenden, sofern verfügbar, Alerts aktivieren, Rechnung aufbewahren und abgleichen.

**Erkennung:** Deterministische Bank-/Payment-Datensätze, Eigentümerschaft von Begünstigtem/Konto, Gerät/Session und Fraud Controls. Dies ist eine Baseline, keine Anonymitätstechnik.

## Konto- und Händlerkompartimentierung

**Mechanik:** Getrennte rechtmäßige Identitäten/Konten, E-Mail-Aliase, Karten und Lieferkontexte verhindern, dass unabhängige Händler Aktivitäten trivial zusammenführen, während ein Issuer/Controller die Zuordnung behält.

**Vorteile:** Reduziert Breach- und händlerübergreifende Verknüpfung; einfach auditierbar; kompatibel mit regulierten Zahlungen.

**Nachteile:** Der Provider ordnet Kompartimente weiterhin zu; Recovery-Telefon, Gerät/IP und Versand können sie wieder verbinden; Richtlinien können mehrere Konten verbieten.

**Verfahren:** (1) einen Zweck festlegen; (2) nur bedingungskonforme Aliase/Subkonten erstellen; (3) händlerspezifischen Token/Karte verwenden; (4) kontoübergreifende Kontakte-/Werbepersonalisierung deaktivieren; (5) einen verschlüsselten Controller-Ledger führen; (6) Identifikatoren nach Ende von Rückerstattungs-/Aufbewahrungsbedarf ausmustern.

**Erkennung:** Provider verbinden Recovery, Gerät, Funding und IP; Händler verbinden Zustellung, Browser und Kontoverhalten. Defenders sollten legitime Kompartimentierung von Synthetic-Identity-Fraud unterscheiden.

## Kontrollierte Red-Team-Beschaffung

**Mechanik:** Das SOC kennt einen Kauf nicht, während ein Exercise-Controller die Zuordnung von juristischer Person, Operator und Infrastruktur aufbewahrt.

**Vorteile:** Realistische Detection-Übung; kein persönliches Exposure; sofortige Deconfliction und Audit.

**Nachteile:** Nicht anonym gegenüber Organisation/Provider; Governance-Aufwand; Leaks, wenn der Controller-Ledger falsch behandelt wird.

**Verfahren:** (1) engagementbezogene Organisationskarte/-Wallet/-Budget zuweisen; (2) Käufer- und Operatorrollen trennen; (3) Asset, Betrag, Service, Zweck und Kill Date dokumentieren; (4) Zuordnung mit begrenztem Controller-Zugriff speichern; (5) niemals falsche Identität/Mule/gestohlene Gelder verwenden; (6) Indicators und Rückerstattungen beim Abschluss offenlegen/abgleichen.

**Erkennung:** Der Controller ordnet Providerrechnung und Asset zu; das SOC testet unabhängige Discovery über Domain, Certificate, Hosting und Traffic statt über Karteninhaberdaten.

## Bitcoin-Address-Hygiene und Coin Control

**Mechanik:** Neue Empfangsadressen, lokale Labels und selektives UTXO-Spending reduzieren Address Reuse und versehentliche Zusammenführung von Kompartimenten auf einem öffentlichen Ledger.

**Vorteile:** Breit unterstützt; Self-Custody; vermeidet die einfachste öffentliche Verknüpfung.

**Nachteile:** Alle Transaktionen/Beträge bleiben öffentlich; Common-Input-/Change-/Timing- und spätere Consolidation-Analysen verbinden Aktivitäten; Acquisition-/RPC-/Netzwerkdaten bleiben bestehen.

**Verfahren:** (1) eine gepflegte Wallet installieren/verifizieren; (2) Seed-Back-up und Wiederherstellung testen; (3) pro Rechnung eine neue Adresse verwenden; (4) Quelle/Zweck lokal labeln; (5) Coin Control verwenden, um Kontexte nicht zu vermischen; (6) einen lokalen Node oder eine Privacy-bewusste Verbindung bevorzugen; (7) Change/Gebühren prüfen und rechtmäßige Buchhaltung führen.<sup>[[3]](#references)</sup>

**Erkennung:** Address-Graph, Common-Input-/Change-Heuristiken mit Unsicherheit, exakter Betrag/Zeitpunkt, Consolidation, Service-Deposits, Node-/RPC-Broadcast-Timing und Off-Chain-Datensätze.

## Bitcoin Silent Payments

**Mechanik:** BIP 352 erlaubt dem Empfänger, einen statischen Code zu veröffentlichen, während Sender eindeutige Taproot-Outputs über ECDH ableiten; externe Beobachter können Outputs nicht direkt mit dem Code verknüpfen.<sup>[[4]](#references)</sup>

**Vorteile:** Wiederverwendbare öffentliche Kennung ohne Address Reuse; keine interaktive Adressanforderung oder Notification-Output; fügt sich in Taproot-Outputs ein.

**Nachteile:** Scanaufwand beim Empfänger; Wallet-Unterstützung variiert; Betrags-/Sendergraph und Spending bleiben öffentlich; Index-Server kann Scans beobachten.

**Verfahren:** (1) aktuelle BIP-352-Wallet auswählen; (2) Descriptor und Scan-Recovery sichern/testen; (3) unterstützten Code mit Label erzeugen; (4) veröffentlichten Code authentifizieren; (5) Sender prüft Inputs und sendet einen kleinen Test; (6) Empfänger scannt möglichst über eigenen Node; (7) empfangene UTXOs getrennt halten.

**Erkennung:** Aus dem Output allein absichtlich nicht zuverlässig erkennbar; Analysten verwenden Senderinputs, Betrag/Zeit, späteres Spending sowie Wallet-/Netzwerk-/Index- und Gegenparteidaten.

## PayJoin

**Mechanik:** Zahler und Zahlungsempfänger steuern Inputs zu einer Zahlungstransaktion bei und brechen damit die Annahme, dass alle Inputs demselben Eigentümer gehören.<sup>[[5]](#references)</sup>

**Vorteile:** Gewöhnliche Zahlung mit verbesserter Privacy; stärkt den breiteren Graphen durch Schwächung einer Common-Input-Heuristik; kein Pool gleich großer Outputs erforderlich.

**Nachteile:** Interaktivitäts-/Supportanforderung; Verfügbarkeit des Empfängerendpunkts; Betrag und finale Transaktion öffentlich; Implementierungs- und Fallback-Metadaten.

**Verfahren:** (1) bestätigen, dass beide gepflegten Wallets dieselbe PayJoin-Version unterstützen; (2) Rechnung/Endpoint authentifizieren; (3) über die PayJoin-fähige Payment-URI der Wallet starten; (4) finalen Betrag/Gebühr prüfen und nur erwartete Inputs signieren; (5) keine manuelle Transaktionsbearbeitung; (6) Broadcast und Empfang verifizieren; (7) Fallback dokumentieren, falls die Aushandlung scheitert.

**Erkennung:** Blockchain-Analysten dürfen Common-Input-Clustering nicht erzwingen; Endpoint/Provider kann Aushandlung protokollieren; Wallet-/Netzwerk- und späteres Spending-Evidence statt alleiniger Transaktionsform verwenden.

## CoinJoin

**Mechanik:** Mehrere Teilnehmer erstellen gemeinsam eine Transaktion mit vielen Inputs/Outputs, häufig gleichen Stückelungen, und erhöhen so die Unklarheit über Input-Output-Zuordnungen.

**Vorteile:** Größere On-Chain-Ambiguitätsmenge; Self-Custodial-Designs existieren; messbare Round-Struktur.

**Nachteile:** Coordinator-/Peer-/Netzwerkmetadaten; Gebühren/Liquidität; erkennbare Transaktionsform; toxisches Change und spätere Consolidation zerstören Vorteile; rechtliche/providerbezogene Verfügbarkeit variiert.

**Verfahren:** (1) aktuelle Wallet-/Coordinator-Verfügbarkeit und Rechtmäßigkeit prüfen; (2) offizielle Wallet installieren und sichern; (3) nur rechtmäßige UTXOs verwenden; (4) Stückelung, Gebühren und Coordinatormodell verstehen; (5) Change und gemischte Outputs labeln/getrennt halten; (6) niemals gemeinsam consolidieren; (7) Netzwerktraffic nur nach offizieller Unterstützung routen und Buchhaltung aufbewahren.

**Erkennung:** Kollaborative Struktur erkennen, ohne automatisch ein Verbrechen anzunehmen; mögliche Zuordnungen/Anonymity Set berechnen und anschließend Change/Consolidation, Service-Grenzen sowie Netzwerk-/Coordinator-Datensätze beobachten.

## Lightning Network

**Mechanik:** HTLC-Zahlungen durchlaufen onion-geroutete Channels; die meisten Zahlungsdetails werden nicht auf der Chain veröffentlicht, während Funding/Closing und öffentliche Channel-Informationen sichtbar sind.

**Vorteile:** Schnell, geringe Gebühren; Intermediaries sehen normalerweise nur benachbarte Hops; gewöhnliche Zahlungsdetails bleiben Off-Chain.

**Nachteile:** Sender/Empfänger und erster/letzter Hop wissen mehr; Probing, Timing, Channel-Graph, Liquidity-/Wallet-/LSP-Datensätze; Custodial Wallets identifizieren Nutzer.

**Verfahren:** (1) Self-Custodial oder Custodial bewusst auswählen; (2) Wallet/Seed/Channel-Recovery prüfen; (3) Invoice für die exakte Zahlung verwenden; (4) Private Channels/LSP-Funktionen erst nach Prüfung der Trade-offs bevorzugen; (5) Node-IP bei Bedarf mit unterstütztem Tor schützen; (6) identifizierende Invoices nicht wiederverwenden; (7) Channel- und Zahlungsbuchhaltung führen.<sup>[[6]](#references)</sup>

**Erkennung:** Node-/LSP-/Custodian-Logs, Channel-Graph/Probes, Payment Failure/Timing sowie On-Chain-Funding/Closure; keine öffentliche Transaktion bedeutet nicht, dass keine Datensätze existieren.

## BOLT-12-Offers und Route Blinding

**Mechanik:** Ein wiederverwendbares Offer erzeugt frische Invoices und kann blinded paths bekanntgeben, sodass der Zahler den eindeutigen Node/Pfad des Empfängers nicht erfahren muss.

**Vorteile:** Privacy des Empfängers; wiederverwendbarer Donation-/Payment-Endpoint ohne statische Invoice; Integration in Lightning-Onion-Routing.

**Nachteile:** Wallet-Unterstützung variiert; Endpunkte, ausgewählte Hops und Funding bleiben; öffentliche Kontakt- oder Netzwerkendpunkte können den Empfänger reidentifizieren.

**Verfahren:** (1) passende BOLT-12-Unterstützung bestätigen; (2) Offer authentifizieren; (3) frische Invoice anfordern; (4) Betrag/Issuer/Recurring-Daten prüfen; (5) über die Wallet bezahlen; (6) Empfang/Rückerstattungsverhalten verifizieren; (7) Node-Alias/Kontakt minimieren und Buchhaltung aufbewahren.<sup>[[7]](#references)</sup>

**Erkennung:** Wallet-/LSP- und First-/Last-Hop-Telemetrie, Offer-Verteilungskonto, Timing/Wert und Funding-Graph; Route Blinding begrenzt absichtlich die Sichtbarkeit des Zahlers.

## Monero

**Mechanik:** Einmalige Stealth Addresses verbergen die Empfängerverknüpfung, RingCT verbirgt Beträge und Ring Signatures erzeugen Sender-Ambiguität.

**Vorteile:** Privacy standardmäßig On-Chain; Vertraulichkeit von Sender/Empfänger/Betrag; ausgereiftes Wallet-/Node-Ökosystem.

**Nachteile:** Acquisition/Off-Ramp sowie Endpoint-/Netzwerk-/Gegenparteidaten; Remote Node sieht Abfragen/IP; Exchange-Support und rechtliche Behandlung variieren; kleine operative Fehler verbinden weiterhin Kontexte.

**Verfahren:** (1) rechtmäßig beschaffen und Grundlage/Quelle aufbewahren; (2) offizielle gepflegte Wallet installieren/verifizieren; (3) Seed sichern/testen; (4) lokalen Node oder dokumentierten Tor-/I2P-Remote-Node-Pfad verwenden; (5) pro Zahler/Invoice neue Subaddress verwenden; (6) Kontexte lokal labeln; (7) Transaction Proof/View Access nur bewusst offenlegen.<sup>[[8]](#references)</sup>

**Erkennung:** Auf Exchange-/Händler-/Geräte-/Netzwerk- und beschlagnahmte-Wallet-Evidence konzentrieren; Protokollnutzung allein ist nicht verdächtig, und die öffentliche Chain legt absichtlich weniger offen.

## Zcash Fully Shielded Orchard

**Mechanik:** Zero-Knowledge-Proofs validieren Shielded Transfers, während Sender, Empfänger und Betrag verschlüsselt sind; Transparent Pools und Pool-Übergänge bleiben öffentlich.

**Vorteile:** Starke Shielded-On-Chain-Vertraulichkeit; Viewing Keys können begrenzte Audits unterstützen; protokollvalidierte Korrektheit.

**Nachteile:** Wallet-/Exchange-Support und tatsächliche Poolauswahl variieren; Korrelation von Boundary-Timing/Wert bei transparenten Übergängen; Netzwerk/RPC und Endpoint bleiben sichtbar.

**Verfahren:** (1) gepflegte Orchard-Shielded-by-Default-Wallet auswählen; (2) verifizieren/sichern; (3) ZEC rechtmäßig beschaffen; (4) an unterstützte Unified Address empfangen und Pool bestätigen; (5) Shielded-to-Shielded bevorzugen; (6) unterstützte Network Privacy verwenden; (7) Offenlegung eines Viewing Keys vor einem Audit mit einer kleinen Wallet testen.<sup>[[9]](#references)</sup>

**Erkennung:** Transparente Grenzen und Service-Datensätze, Wallet-/Netzwerkmetadaten und rechtmäßig bereitgestellte Viewing Keys; nicht annehmen, dass alle Unified-Address-Zahlungen Shielded waren.

## Mimblewimble und Litecoin MWEB

**Mechanik:** Confidential Transactions verbergen Beträge, und Mimblewimble-artige Aggregation entfernt konventionelle adressreiche Historie; Litecoin implementiert einen optionalen Extension Block neben seiner transparenten Chain.

**Vorteile:** Vertrauliche Beträge und verbesserte Fungibility im privaten Bereich; effizientes Pruning/Aggregation.

**Nachteile:** Opt-in-Grenze durch Peg-in/out ist öffentlich und korrelierbar; Wallet-/Exchange-Support; interaktive/Adressmodellunterschiede; Netzwerk- und Acquisition-Daten.

**Verfahren:** (1) gepflegte Wallet mit expliziter MWEB-Unterstützung wählen; (2) verifizieren/sichern und kleinen Betrag testen; (3) rechtmäßig beschaffen; (4) in MWEB pegen und den Balance-Bereich prüfen; (5) nur mit kompatiblem Empfänger handeln; (6) sofortiges charakteristisches Peg-out vermeiden; (7) private Auditunterlagen aufbewahren.<sup>[[10]](#references)</sup>

**Erkennung:** Öffentliche Peg-in/out-Zeitpunkte/-Werte, Exchange-/Wallet-/Node-Daten und spätere transparente Spends; interne Confidential-Transferdetails sind absichtlich reduziert.

## Ethereum-Zero-Knowledge-Privacy-Anwendungen

**Mechanik:** Eine Circuit beweist eine Aussage – Membership, gültiges Note Ownership oder Authorization – ohne das Secret offenzulegen; ein Verifier Contract prüft sie. Deposits, Withdrawals, öffentliche Inputs, Events und Gas können weiterhin Verknüpfungen offenlegen.

**Vorteile:** Programmierbare selektive Offenlegung; Anwendungen mit Anonymity Set; überprüfbare Regeln ohne Offenlegung sämtlicher Daten.

**Nachteile:** Contract-/Circuit-Bugs; kleines Anonymity Set; öffentliche Grenzen; RPC/IP/Session/Analytics/Gas Funding; Anwendungs-, Sanktions- und Rechtsrisiko.

**Verfahren:** (1) genau definieren, was der Proof verbirgt; (2) rechtmäßig eine auditierte, gepflegte Anwendung verwenden; (3) öffentliche Inputs/Events und Deposit-/Withdraw-Regeln prüfen; (4) Action Wallet und Gas Sponsorship nach Protokollabsicht trennen; (5) Privacy-bewussten RPC-/Netzwerkpfad nutzen; (6) mit geringem Wert testen; (7) Compliance-Datensätze aufbewahren.<sup>[[11]](#references)</sup>

**Erkennung:** Contract Events, Deposit-/Withdraw-Timing/-Wert, Relayer/Paymaster, RPC/Session, Frontend Storage/Analytics und spätere Exchange-/Händlergrenzen. Der ZK-Proof verbirgt keine als öffentlich deklarierten Felder.

## Stablecoins

**Mechanik:** Tokens werden auf einer öffentlichen Chain transferiert; zentralisierte Issuer können Tokens einfrieren/blacklisten oder gegen identifizierte Konten einlösen.

**Vorteile:** Preisstabilität, Liquidität und Händlerunterstützung; schnelles Settlement; einfache Buchhaltung.

**Nachteile:** Transparenter Address-/Betrags-/Contract-Graph; Gas Funding; Identität/Control durch Issuer und Exchange; Sanktionsprüfung; generell schlechte Anonymität.

**Verfahren:** Als identifizierte Zahlung behandeln: frische Geschäftsadresse nur zur Kompartimentierung verwenden, Token Contract/Netzwerk verifizieren, kleinen Betrag testen, Wallet schützen, vertrauenswürdigen RPC/lokalen Node nutzen, Grundlage/Quelle dokumentieren und erforderliche Parteien prüfen.

**Erkennung:** Vollständiger Token-Event-Graph, Issuer-Freeze-Liste/-Aktionen sowie Exchange-/RPC-/Geräte- und Gas-Funding-Beziehungen.

## Cashu-Chaumian-E-Cash

**Mechanik:** Eine Mint signiert blind vom Client erzeugte Bearer Secrets, die durch Bitcoin-/Lightning-Reserven gedeckt sind; sie kann Double Spending verhindern, ohne Ausgabe direkt mit späterer Einlösung zu verknüpfen.

**Vorteile:** Accountlose Bearer Tokens; sofortiger Peer-Transfer; Mint kann blinded Withdrawal nicht direkt mit Spending verknüpfen; Tokens können als Daten/QR übertragen werden.

**Nachteile:** Mint-Custody/Solvency/Censorship; Verlust/Diebstahl von Bearer-Daten; Denomination/Timing und Lightning-Grenzen; Netzwerkmetadaten; frühes Software-Ökosystem.<sup>[[12]](#references)</sup>

**Verfahren:** (1) zuerst eine offizielle Test-Mint oder einen sehr kleinen, entbehrlichen Wert verwenden; (2) gepflegte Wallet installieren und Backup-/Restore-Limits testen; (3) Mint authentifizieren und Custody/Gebühren prüfen; (4) kleinen Betrag minen; (5) Token über einen authentifizierten privaten Channel/QR senden; (6) Empfänger tauscht den Token, bevor er ihn als final betrachtet; (7) einlösen und abgleichen. Niemals einen bedeutenden Wert in einer nicht vertrauenswürdigen Mint aufbewahren.

**Erkennung:** Die Mint sieht Netzwerk-, Issue-/Redeem-/Lightning-Grenzen und die Menge ausgegebener Tokens, aber Blinding entfernt die direkte Tokenverknüpfung; Endpunkte/Nachrichten und charakteristische Beträge/Zeitpunkte können Verbindungen wiederherstellen.

## Fedimint Federated E-Cash

**Mechanik:** Ein Threshold von Guardians hält Reserven und signiert E-Cash blind; interne Bearer Transfers sind für Guardians privat, während Lightning Gateways externe Zahlungen überbrücken.

**Vorteile:** Verteilte Custody; private interne Transfers; Community Governance; kein einzelner Guardian kontrolliert die Reserve unterhalb des Thresholds.

**Nachteile:** Guardian-Quorum/Custody/Software-Risiko; Gateway sieht Invoices/Timing; Deposit-/Withdraw-Grenzen; komplexe Recovery des Client-Zustands.

**Verfahren:** (1) Federation Invite/Guardians/Quorum/Jurisdiktion prüfen; (2) gepflegten Client installieren und Recovery testen; (3) kleinen rechtmäßigen Betrag einzahlen; (4) frische interne Payment Requests verwenden; (5) Gateway als Beobachter für Lightning behandeln; (6) Einlösung testen; (7) Quellen-/Steuerunterlagen außerhalb der öffentlichen Zahlungsdaten aufbewahren.<sup>[[13]](#references)</sup>

**Erkennung:** Federation sieht aggregierte Ausgabe/Einlösung, Gateways sehen externe Invoices, Bitcoin/Lightning zeigen Grenzen, und Endpoint-/Kommunikationsevidence kann interne Transfers verknüpfen.

## GNU Taler

**Mechanik:** Bankintegriertes E-Cash mit blind signatures soll den Zahler gegenüber Händlern anonym halten, während Händler und Einnahmen rechenschaftspflichtig bleiben.

**Vorteile:** Privacy des Zahlers by design; gewöhnliche Währung; Händlerverantwortlichkeit/Rückerstattungen; kein spekulativer Token erforderlich.

**Nachteile:** Begrenzte Deployments; Exchange/Bank sehen Funding; Händler sieht Bestellung/Zustellung; Risiko durch Bearer Wallet/Recovery; regulierte Betreiber.

**Verfahren:** (1) aktuelle Exchange/Händler für Jurisdiktion/Währung finden; (2) KYC/Gebühren/Privacy lesen; (3) offizielle Wallet installieren; (4) rechtmäßig von unterstützter Bank/Exchange abheben; (5) Händlervertrag prüfen; (6) bezahlen und Quittungs-/Rückerstattungsdaten aufbewahren; (7) unnötige Händler-Session-Identifier vermeiden.<sup>[[14]](#references)</sup>

**Erkennung:** Bank-/Exchange-Withdrawal und Händlerdeposit sind rechenschaftspflichtige Grenzen; Händlerbestellung/Gerät/Zustellung und Timing können auch bei blind signierten Coins korrelieren.

## Cross-Chain-Bridge, Atomic Swap und Decentralized Exchange

**Mechanik:** Ein Contract/Service sperrt/burnt ein Asset und gibt/mintet ein anderes frei, oder Gegenparteien tauschen atomar. Dies durchbricht die Sicht einer einzelnen Ledger, nicht die wirtschaftliche Kontinuität.

**Vorteile:** Asset-/Netzwerkinteroperabilität; kann einen zentralen Custodian vermeiden; gewöhnliche Portfolio-/Liquiditätsnutzung.

**Nachteile:** Beide Chains sind öffentlich; Zeit/Wert/Gebühren/Liquidität und Contracts korrelieren; Bridge-/Relayer-/Frontend-/RPC-Daten; Smart-Contract-/Gegenparteien- und Regulierungsrisiko.

**Verfahren für rechtmäßige Swaps:** (1) offiziellen Contract/Service und rechtliche Verfügbarkeit prüfen; (2) Custody/Audit/Gebühren/Slippage prüfen; (3) kleinen Test durchführen; (4) beide Transaction IDs und Kurs dokumentieren; (5) Approvals schützen; (6) Zielasset abgleichen und unnötige Approvals widerrufen. Swaps nicht verwenden, um die Mittelherkunft zu verschleiern.

**Erkennung:** Bridge-Deposit-/Withdraw-Events, eindeutiger Betrag abzüglich Gebühren, Zeitreihenfolge, Liquidität, Relayer/RPC/Frontend und spätere Service-Deposits.

## Zentralisierter Mixer oder Tumbler

**Mechanik:** Ein Service nimmt Deposits in einen Pool auf und gibt später andere Einheiten zurück, um die direkte Input-Output-Zuordnung zu verschleiern.

**Vorteile:** Kann theoretisch die Transaktionsambiguität vergrößern.

**Nachteile:** Betreiber kann stehlen/protokollieren; Analyse von Entry-/Exit-Timing und -Wert; Sanktions-/Geldübermittlungs- und kriminelles Risiko; Beschlagnahmen können Zuordnungen offenlegen; Taint-/Ablehnungsrisiko.

**Verfahren:** Es wird keine operative Mixing-Anleitung bereitgestellt. Den Graphen sicher reproduzieren, indem [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) erweitert wird: synthetische Deposits, Pool-Outputs, Gebühren und Verzögerungen erzeugen; Analysten unvollständige Zuordnungen geben; wirksame Heuristiken messen; anschließend Ground Truth offenlegen.

**Erkennung:** Service-Wallet/Contract identifizieren, Entry-/Exit-Kandidatenmengen, Betrag/Gebühr/Timing, Wiederverwendung von Deposit-Adressen, beschlagnahmte Provider-Logs und nachgelagerte Consolidation. Probabilistische Attribution kennzeichnen.

## Peel Chains, Fan-Out/Fan-In und Structuring

**Mechanik:** Wiederholte Transaktionen „peelen“ kleine Zahlungen aus Change, teilen Werte auf viele Adressen auf, führen sie bei Collectors wieder zusammen oder teilen Beträge zur Vermeidung einer Prüfung.

**Vorteile:** Erhöht den Arbeitsaufwand und die Adressanzahl für naive Analysten.

**Nachteile:** Erkennbare Wert-/Takt-/Transaktionskontinuität; Consolidation und Serviceendpunkte; Structuring kann selbst illegal sein; Gebühren und operative Fehler.

**Verfahren:** Nur synthetische CSV-/Testnet-Daten verwenden: eine große Quelle, wiederholte Payment-/Change-Kanten, parallele Zweige und einen Collector erzeugen; gutartige Exchange-ähnliche Beispiele hinzufügen; Detection abstimmen und False Positives dokumentieren.

**Erkennung:** Graphkontinuität, wiederholtes Change-Muster, Taktung, Beträge knapp unter Kontrollgrenzen, gemeinsamer Serviceendpunkt und Off-Chain-Daten. Exchange-Hot-Wallets können ähnlich aussehen, daher ist Kontext erforderlich.<sup>[[15]](#references)</sup>

## Nominee, Money Mule, OTC-Broker und Briefkastenfirma

**Mechanik:** Eine andere Person/ein anderes Konto/eine andere Firma empfängt, konvertiert oder verwendet Gelder und fügt rechtliche/operative Ebenen zwischen Controller und Transaktion ein.

**Vorteile für einen Angreifer:** Das benannte Konto identifiziert den Controller nicht sofort; kann Bargeld, Crypto, Waren und Jurisdiktionen verbinden.

**Nachteile:** Risiko durch Identitätsbetrug/Geldwäsche; jeder Teilnehmer fügt Kommunikations-, Bank-/Firmen-/Steuer-/Versanddatensätze, Gebühren, Widersprüche und Zeugen hinzu; wiederverwendete Facilitators erzeugen Hubs.

**Verfahren:** Nicht mit echten Personen/Konten nachbilden. Einen synthetischen Graphen mit Controller, Recruiter, Mule, OTC, Shell Merchant und Beneficiary aufbauen; Geräte-/IP-/Nachrichten-/Bankkanten einfügen; Ermittler zwischen Kontoinhaber und Controller unterscheiden und Evidenzkonfidenz dokumentieren lassen.

**Erkennung:** Gemeinsames Gerät/IP/Recovery, ungewöhnlicher Begünstigter/Velocity, viele unabhängige Sender, sofortige Weiterbewegung, Widersprüche bei Firma/Direktor/Rechnung, Kommunikation und Lieferung von Bargeld/Commodities.

## NFTs, Gambling, Händlerwaren und Refund Loops

**Mechanik:** Wert wird in ein selbstbewertetes Asset, Wettguthaben, weiterverkaufbare Waren oder Rückerstattungen umgewandelt, um eine andere Transaktionsgeschichte zu erzeugen.

**Vorteile für einen Angreifer:** Ändert die Assetform und fügt Marketplace-/Händlerintermediaries ein.

**Nachteile:** Marketplace-/Konto-/Geräte- und Wash-Trade-Graph; Odds-/Play- und Refund-Datensätze; Liefer-/Wiederverkaufsevidence; Gebühren/Verluste; Betrugs-/Geldwäschehaftung.

**Verfahren:** Kein Verschleierungsworkflow. Synthetische Marketplace-Daten mit Self-Trades verbundener Wallets, unplausibler Preisgestaltung, minimalem Spiel, nicht übereinstimmendem Refund-Instrument und gemeinsamer Lieferung verwenden; Detection gegen legitime Collector/Kunden validieren.

**Erkennung:** Zirkuläre/Self-Funded Trades, gemeinsame Eigentümerschaft/Funding, Preis-Ausreißer, sofortiger Wiederverkauf/Refund, minimale wirtschaftliche Aktivität, gemeinsames Gerät/Delivery und erneute Zusammenführung der Erlöse.

## Physische Bearer-Wallet oder Offline-Token-Transfer

**Mechanik:** Ein Gerät, Papier/QR, Hardware-Bearer-Instrument oder E-Cash-Token überträgt die Kontrolle über ein Secret, statt bei der Übergabe eine Zahlung zu broadcasten.

**Vorteile:** Kein Live-Network-Event während des Austauschs; offline nutzbar; physische, bargeldähnliche Custody.

**Nachteile:** Kopie/Diebstahl/Verlust und unklare Exklusivität; spätere Einlösung/Broadcast kann verknüpfen; physisches Treffen/Versand; Counterfeit-/Tamper-Risiko.

**Verfahren:** (1) nur geprüftes Instrument/Protokoll verwenden; (2) Authentizität privat initialisieren/verifizieren; (3) nur kleinen rechtmäßigen Wert laden; (4) in einem dokumentierten autorisierten Kontext übertragen; (5) Empfänger verifiziert oder sweeped zeitnah nach Protokoll; (6) niemals annehmen, dass der Sender keine Kopie behalten hat; (7) Eigentums-/Steuerevidence privat dokumentieren.

**Erkennung:** Kauf/Funding und späteres Sweep/Redemption, Geräte-Seriennummer/Tamper-Evidence, Delivery/Meeting und Endpoint-Datensätze.

## Händlergebundene Invoice oder einmalige Payment Request

**Mechanik:** Der Händler erstellt eine einmalige Request mit Betrag, Ablauf und Order Reference. Der Zahler begleicht sie über einen unterstützten Rail, ohne dem Händler direkt ein wiederverwendbares Credential offenzulegen; Issuer oder Payment Processor können weiterhin beide Parteien identifizieren.

**Vorteile:** Begrenzung der Credential-Wiederverwendung und versehentlicher händlerübergreifender Identifier; exakter Betrag/Ablauf reduzieren Fehler; kompatibel mit gewöhnlicher Buchhaltung und Rückerstattungen.

**Nachteile:** Invoice, Delivery, Browser, Processor und Issuer verknüpfen weiterhin die Bestellung; eindeutiger Betrag/Zeitpunkt kann Korrelation verstärken; bösartige Payment Links sind häufig.

**Verfahren:** (1) Händler unabhängig authentifizieren; (2) frische Invoice mit exaktem Betrag, Asset/Netzwerk und Ablauf anfordern; (3) Ziel und Rückerstattungsregeln prüfen; (4) aus dem genehmigten Engagement-Kompartiment bezahlen; (5) bestätigen, dass der Händler dieselbe Invoice anerkennt; (6) Quittung und Transaktionsreferenz aufbewahren; (7) Request ablaufen lassen statt wiederverwenden.

**Erkennung:** Händler und Processor verbinden Invoice, Session und Settlement; eindeutige Beträge/Zeitpunkte und Zustellung identifizieren den Zahler. **Erfasstes Wallet/Gerät:** Die Invoice-Historie offenbart Gegenparteien und Zweck; unnötige Memodaten minimieren, Gerät verschlüsseln und verbindliche Buchhaltung im kontrollierten Finanzsystem führen.

## Prepaid-Serviceguthaben und Capability Token

**Mechanik:** Ein Service wandelt eine konventionelle Zahlung in begrenzte interne Credits oder eine Bearer Capability um. Nachfolgende API-/Ressourcennutzung kann die ursprüngliche Karte bei jeder Anfrage vermeiden, aber der Service kann Ausgabe und Einlösung häufig zuordnen.

**Vorteile:** Begrenzt Ausgaben und Kompromittierungsverlust; trennt tägliche Worker vom Funding-Credential; unterstützt Projektbudgets und Widerruf.

**Nachteile:** Meist pseudonym, nicht anonym; Servicedatenbank, Redemption-IP und eindeutiges Nutzungsmuster verknüpfen Aktivität; Bearer Tokens können gestohlen werden; Rückerstattungen erfordern möglicherweise den ursprünglichen Zahler.

**Verfahren:** (1) Credits über ein Organisationskonto kaufen; (2) ein Projekt und Budget erstellen; (3) ein eng begrenztes Token mit Service-, Betrags- und Ablaufbeschränkungen ausgeben; (4) nur im genehmigten Secret Manager oder Workload-Identity-Pfad speichern; (5) Ablehnung außerhalb des Scopes und nach Ablauf testen; (6) Verbrauch überwachen; (7) ungenutzten Wert widerrufen und abgleichen.

**Erkennung:** Provider verbindet Fundingkonto, Projekt, Tokenausgabe und Nutzung; Defenders alarmieren bei geografischen/Prozessänderungen und anomalem Verbrauch. **Erfasster Node:** Annehmen, dass sein verbleibendes Capability ausgegeben werden kann; kurze Ablaufzeit, niedrigen Saldo, Audience Binding und sofortigen serverseitigen Widerruf verwenden.

## Privacy Pass oder Blinded Authorization Token

**Mechanik:** Ein Issuer erzeugt ein Privacy-preserving Authorization Token, das eine Origin validieren kann, ohne Redemption mit Issuance zu verknüpfen. Es kann ein bezahltes Recht oder einen rate-limitierten Zugriff darstellen, ist jedoch keine allgemeine Währung. Die Architektur trennt Client-, Attester-, Issuer- und Origin-Rollen und warnt, dass IP/Timing oder Collusion die Unlinkability aufheben können.<sup>[[18]](#references)</sup>

**Vorteile:** Unlinkable Redemption bei unterstützten Services; kein wiederverwendbarer Account-Cookie bei der Origin; gecachte Tokens können Issuance und Nutzung zeitlich trennen.

**Nachteile:** Anwendungsspezifisch; Trust in Issuer/Attester und Partitionierung des Anonymity Set; IP- und Browsermetadaten bleiben; Token-Diebstahl oder charakteristisches Issuance-Timing kann Nutzung korrelieren.

**Verfahren:** (1) eine Implementierung entsprechend dem relevanten Privacy-Pass-Token-Typ verwenden; (2) exakt definieren, welches Recht das Token beweist; (3) Issuer- und Origin-Administration trennen, wenn das Threat Model dies verlangt; (4) Challenge-Metadaten minimieren; (5) mehrere Testtokens ausstellen und jedes einmal an eigenen Origins einlösen; (6) Logs auf verbotene stabile Identifier vergleichen; (7) Replay-, Ablauf- und Revocation-/Abuse-Kontrollen testen.

**Erkennung:** Origins sehen Redemption-IP/-Zeit und Tokenvalidität; Issuer/Attester sehen Issuance-Kontext; Analysten prüfen Timing und Metadatenpartitionen, ohne einen kryptografischen Bruch anzunehmen. **Erfasster Client:** Ungenutzte Bearer Tokens können verwendbar sein; Wert, Lebensdauer und Audience begrenzen und niemals das Funding-Credential gemeinsam mit ihnen cachen.

## Delegierte Organisationsbeschaffung oder Fiscal Sponsor

**Mechanik:** Ein autorisiertes Procurement-Team, ein Reseller oder Fiscal Sponsor schließt Verträge und bezahlt, während das operative Team einen begrenzten Service erhält. Dies ist Rollentrennung mit wahrheitsgemäßen Datensätzen, kein Nominee oder falsche Identität.

**Vorteile:** Anbieter müssen nicht die Identität jedes Operators oder persönliche Zahlungsdaten erhalten; zentrale Compliance-, Steuer- und Rückerstattungsabwicklung; klares Budget und Offboarding.

**Nachteile:** Sponsor kennt Begünstigten und Zweck; Verträge, Freigaben, Zustellung und Konten bleiben bestehen; zusätzlicher Zeit-/Kostenaufwand; schwache Trennung, wenn dieselbe Person jede Ebene verwaltet.

**Verfahren:** (1) Geschäftszweck, Begünstigten und genehmigende Stelle dokumentieren; (2) organisationsgenehmigten Intermediary auswählen; (3) unter wahrheitsgemäßen Angaben kontrahieren; (4) projektspezifisches Subkonto ohne persönliche Billing-Credential bereitstellen; (5) Finance-Administratoren von Operatoren trennen; (6) Rechnungen und Zugriff abgleichen; (7) Service und delegierten Zugriff beim Abschluss beenden.

**Erkennung:** Procurement-, Identity-Provider-, Händler- und Lieferdatensätze verbinden die Kette. **Erfasstes operatives Gerät:** Es sollte das Serviceprojekt, nicht aber Finanz-Credentials offenlegen; Rechnungen und Zahleridentitäten im Finanzsystem, nicht auf Field Nodes, aufbewahren.

## Escrow oder bedingtes Settlement

**Mechanik:** Ein vertrauenswürdiger Escrow Agent oder Smart Contract hält Wert, bis dokumentierte Bedingungen erfüllt sind. Dies kann die direkte Offenlegung zwischen Zahler und Zahlungsempfänger reduzieren, während Escrow und zugrunde liegende Payment Rails die Beziehung behalten.

**Vorteile:** Streit- und Lieferschutz; Zahler und Händler können einander weniger wiederverwendbare Credentials offenlegen; auditierbare Release-Bedingungen.

**Nachteile:** Escrow-Custody-/Contract-Risiko, Gebühren und Identitätspflichten; On-Chain Contracts sind öffentlich; Bestell-, Versand- und Streitdaten bleiben; nicht anonym gegenüber dem Intermediary.

**Verfahren:** (1) juristische Person, Custody, Gebühren, Streitforum und unterstützte Assets prüfen; (2) exakten schriftlichen Meilenstein und Refund-Pfad erstellen; (3) von genehmigtem Organisationskonto finanzieren; (4) Empfang und Release Authorization unabhängig prüfen; (5) erst nach Evidence freigeben; (6) vollständigen Auditdatensatz aufbewahren; (7) ungenutzte Berechtigungen/Contract Approvals schließen.

**Erkennung:** Escrow-Konto-/Contract-Events, Funding-/Release-Zeitpunkt, Begünstigter und Streitdatensätze offenbaren die Transaktion. **Erfasstes Gerät:** Session Tokens oder Contract Approvals können Release erlauben; separaten Approver/MFA verlangen und bei Verlust aktive Sessions widerrufen.

## Gebündeltes oder gepooltes Organisations-Settlement

**Mechanik:** Viele genehmigte Verpflichtungen werden aggregiert und in weniger Bank- oder Blockchaintransaktionen abgewickelt, wobei ein privater interner Ledger jedem Anteil zuordnet. Batching kann öffentliche Details pro Kauf reduzieren, aber der Coordinator behält die vollständige Attribution.

**Vorteile:** Niedrigere Gebühren; weniger öffentliche Graphkanten; einzelne Positionen werden einem öffentlichen Beobachter bei aggregierten Beträgen verborgen; einfache interne Buchhaltung.

**Nachteile:** Coordinator ist vollständiger Beobachter und hochwertiges Ziel; charakteristische Summen/Zeiten können korrelieren; Custody-/Reconciliation-Risiko; Missbrauch kann wie Structuring aussehen.

**Verfahren:** (1) Teilnehmer und rechtmäßige Verpflichtungen im Buchhaltungssystem definieren; (2) ein regelmäßiges, geschäftlich begründetes Batch-Fenster statt schwellenwertbasierter Umgehung von Kontrollen festlegen; (3) Dual Approval für das Aggregat verlangen; (4) an authentifizierte Empfänger auszahlen; (5) jede interne Position dem Batch zuordnen; (6) Rückerstattungen als verknüpfte Korrekturen behandeln; (7) Ledgerzugriff schützen und nach Richtlinie aufbewahren.

**Erkennung:** Coordinator-Ledger sowie Freigabe- und Begünstigtendaten liefern Ground Truth; öffentliche Analysten nutzen Input-/Output-/Wert-/Zeit-Clustering vorsichtig. **Erfasstes Zahlergerät:** Es sollte nur seine Requisition, nicht den Signing Key des Pools oder den Teilnehmerledger enthalten.

## Account-Abstraction-Paymaster oder gesponsertes Gas

**Mechanik:** Ein Relayer/Bundler übermittelt eine Smart-Account-Operation und ein Paymaster bezahlt Transaktionsgebühren, wodurch eine direkte Native-Gas-Funding-Kante aus der User-Wallet entfällt. Eine Graph-Eigenschaft verbessert sich; Operation, Contract und Servicetelemetrie bleiben öffentlich oder beobachtbar.<sup>[[19]](#references)</sup>

**Vorteile:** Entfernt eine häufige Gas-Funding-Verknüpfung; unterstützt begrenztes Sponsoring und Rate Limits; besseres Onboarding für legitime Privacy-Anwendungen.

**Nachteile:** Paymaster/Bundler/RPC/Frontend können Requests korrelieren; Contract Events und öffentliche Inputs bleiben; Sponsoring Policy fingerprintet eine Gruppe; bösartige Contracts oder Approvals können Assets stehlen.

**Verfahren:** (1) auditierte gepflegte Smart Account und passenden Paymaster im korrekten Netzwerk verwenden; (2) prüfen, welche Felder öffentlich sind und was der Sponsor protokolliert; (3) Sponsoring nach Contract, Function, Betrag, Nonce und Ablauf begrenzen; (4) mit geringem Wert testen; (5) über den vorgesehenen Privacy-bewussten Anwendungspfad senden; (6) Operation und Fee Payer On-Chain verifizieren; (7) Allowances/Session Keys widerrufen und Compliance-Datensätze aufbewahren.

**Erkennung:** UserOperation-, EntryPoint-, Paymaster-, Bundler/RPC- und Application-Logs zusammenführen; identische Sponsoring Policies vorsichtig clustern. **Erfasste Wallet:** Session Keys und ausstehende Approvals können auch ohne Gas nutzbar sein; eng begrenzen und nach Recovery Policy des Accounts widerrufen.

## Threshold- oder Multisignature-Payment-Authorization

**Mechanik:** Ausgaben erfordern einen Threshold unabhängiger Signer. Dies verbirgt die Transaktion nicht, trennt aber Payment Authority von einem beschlagnahmten Laptop, Field Node oder einzelnen Operator.

**Vorteile:** Starker Schutz gegen Kompromittierung und Insider; nachvollziehbare Freigabe; kein einzelnes Field Device besitzt vollständige Signing Authority; unterstützt Recovery.

**Nachteile:** Koordination und Verfügbarkeit; Signer-/Geräte-/Kontometadaten können Teilnehmer korrelieren; schlechte Backup-Architektur führt zu Verlust; öffentliche Multisig-Muster können erkennbar sein.

**Verfahren:** (1) Signer, Threshold, Limits und Recovery vor Funding definieren; (2) auf separater unterstützter Hardware/in separaten Konten initialisieren; (3) Adressen und Backups unabhängig verifizieren; (4) Field Workloads nur unsigned Requisition Capability geben; (5) Out-of-Band-Prüfung von Empfänger, Betrag und Zweck verlangen; (6) Recovery und Verlust eines Signers mit geringem Wert testen; (7) kompromittierten Signer rotieren.

**Erkennung:** Approval-System, Signer-Gerät und öffentliches Script/Contract liefern Evidence; Defenders alarmieren bei Policy- oder Signer-Set-Änderungen. **Erfasster Node:** Er sollte höchstens einen Session Key mit niedriger Autorität oder eine unsigned Request offenlegen; Quorum-Material niemals gemeinsam cachen.

## Closed-Loop-Community- oder Event-Währung

**Mechanik:** Eine Cooperative, Conference oder private Testumgebung gibt Credits aus, die nur unter eingeschriebenen Teilnehmern eingelöst werden können. Interne Transfers können globale Payment Networks weniger belasten, während der Operator Issuance und Redemption kontrolliert.

**Vorteile:** Begrenzter Wirtschaftsbereich; testbare Offline- oder Privacy-preserving-Payment-UX; begrenztes externes Karten-Exposure; klare experimentelle Kontrollen.

**Nachteile:** Kleines Anonymity Set; Operator und Händler beobachten Aktivität; begrenzte Akzeptanz/Einlösung; Lizenz-, Verbraucherschutz- und Steuerregeln können auch für lokalen Wert gelten.

**Verfahren:** (1) rechtliche/Compliance-Prüfung einholen und Issuer Terms veröffentlichen; (2) zustimmende Testteilnehmer einschreiben; (3) Issuance begrenzen und bargeldähnlichen Missbrauch verbieten; (4) frische Payment Requests verwenden und öffentliche Teilnehmer-Identifier minimieren; (5) aggregierte Reserven und private Einzelquittungen dokumentieren; (6) Verlust/Refund/Redemption testen; (7) Ledger schließen und Restwert wie versprochen zurückgeben.

**Erkennung:** Issuer-Ledger, Enrollment, Händler- und Redemption-Datensätze rekonstruieren Flows; ungewöhnliche Circular Transfers oder schnelle Cash-outs prüfen. **Erfasste Wallet:** Lokaler Saldo und Gegenparteien können offengelegt werden; Wert begrenzen, Zustand verschlüsseln und Issuer-seitiges Freeze/Reissue mit auditierbarem Datensatz unterstützen.

## Wiederverwendbare Bitcoin-Payment-Codes und private Payment Instructions

**Mechanik:** BIP 47 Payment Codes verwenden eine wiederverwendbare öffentliche Kennung plus ECDH-abgeleitete einmalige Deposit-Adressen; BIP 351 spezifiziert ein neueres Design für private Payments. Sie reduzieren öffentliche Address Reuse, während ein Empfänger stabile Payment Instructions veröffentlichen kann. Notification, Wallet-Support, Funding und spätere Coin Selection beeinflussen die Privacy weiterhin.<sup>[[20]](#references)</sup>

**Vorteile:** Eine öffentliche Instruction kann unterschiedliche Adressen erzeugen; Empfänger muss nicht jede Invoice-Adresse veröffentlichen; kompatible Wallets können abgeleitete Zahlungen überwachen; nützlich für wiederkehrende rechtmäßige Spender/Kunden.

**Nachteile:** Wallet-Interoperabilität variiert; Notification-Transaktionen oder veröffentlichte Payment Codes verknüpfen einen Beziehungskontext; Sender, Empfänger und öffentlicher Graph sehen weiterhin Transaktionen; unvorsichtige Consolidation oder Change-Behandlung hebt den Vorteil auf.

**Verfahren:** (1) bestätigen, dass beide gepflegten Wallets exakt dieselbe Spezifikation/Version unterstützen; (2) Recovery auf einer Wallet mit geringem Wert sichern und testen; (3) Payment Code des Empfängers Out-of-Band authentifizieren; (4) kleinen rechtmäßigen Test senden; (5) verifizieren, dass eine frische abgeleitete Adresse verwendet wurde; (6) Beziehung lokal labeln und Coin Control anwenden; (7) Recovery und Refund-Verhalten testen, bevor man sich darauf verlässt.

**Erkennung:** Analysten untersuchen Notification-Muster, Funding/Change, spätere Consolidation und Servicegrenzen; die Veröffentlichung des Public Codes identifiziert den Empfängerkontext, auch wenn Deposit-Adressen variieren. **Capture-resiliente OPSEC:** Spend Keys von Field Devices fernhalten und höchstens eine Watch-only-Beziehungsansicht bereitstellen. **Monitoring:** Bei unerwarteten Notification-Transaktionen, wiederverwendeten abgeleiteten Adressen, Wallet-Gap-Limit-/Recovery-Fehlern und ungeplanter Consolidation alarmieren.

## EVM-Stealth-Adressen (ERC-5564)

**Mechanik:** Ein Sender leitet aus der Stealth Meta-Address eines Empfängers ein einmaliges Stealth-Konto ab und veröffentlicht eine Announcement mit ephemeral public key und view tag. Der Empfänger scannt Announcements mit einem Viewing Key und leitet den zugehörigen Spend Key ab. Die Empfängerverknüpfung verbessert sich, aber Sender, Betrag/Token, Gas, Announcement und späteres Spending bleiben sichtbar.<sup>[[21]](#references)</sup>

**Vorteile:** Nicht-interaktive frische Empfängeradresse; wiederverwendbare Meta-Address; getrennte Viewing-/Spending-Rollen; funktioniert über unterstützte EVM-Assets/Anwendungen hinweg.

**Nachteile:** Announcement-Scanning und Spam; Gas Funding für die neue Adresse kann sie wieder verknüpfen; Sender kennt den Empfänger; öffentlicher Token/Betrag und spätere Consolidation bleiben; Implementierungs- und Wallet-Support variieren.

**Verfahren:** (1) auditierte gepflegte Implementierung zunächst auf einem Testnetz verwenden; (2) getrennte Viewing-/Spending-Materialien erzeugen und sichern; (3) Meta-Address authentifizieren; (4) Transfer mit kleinem Wert und Announcement senden; (5) scannen und Stealth-Konto ableiten; (6) unterstütztes Gas Sponsoring ohne persönliche Funding-Kante testen; (7) öffentliche Felder dokumentieren und rechtmäßige Buchhaltung aufbewahren.

**Erkennung:** Announcement Caller, Token/Betrag, Timing, Gas Sponsor, Spending und Consolidation verfolgen; ein View Key kann den Empfang beweisen, ohne Spending zu erlauben. **Capture-resiliente OPSEC:** Ein vernetzter Scanner sollte, sofern unterstützt, nur die Viewing-Rolle besitzen; Spend- und Recovery Keys an anderer Stelle aufbewahren. **Monitoring:** Bei fehlerhaften/Spam-Announcements, View-Key-Zugriff, unerwarteter Spend-Derivation und nicht genehmigten Bewegungen von Stealth Outputs alarmieren.

## Liquid Confidential Transactions

**Mechanik:** Liquid blendet Output-Beträge und Assettypen standardmäßig mithilfe von Commitments und Proofs, während Transaktionsgraph, Input-/Output-Anzahl, Gebühr und Blockzeit sichtbar bleiben. Peg-in/peg-out und Servicegrenzen bleiben verknüpfbar, und Nutzer können Blinding-Daten selektiv offenlegen.<sup>[[22]](#references)</sup>

**Vorteile:** Vertraulicher Betrag und Assettyp standardmäßig; schnelles Sidechain-Settlement; selektives Audit über Blinding Keys/Descriptors; verbirgt kommerziell sensible Werte vor öffentlichen Beobachtern.

**Nachteile:** Graphstruktur und Timing bleiben; Federation-/Bridge- und Exchange-Trust; Peg-Grenzen und unconfidential Outputs; Wallet-/Node-/Netzwerkdatensätze; Sender und Empfänger kennen ihre Transaktion.

**Verfahren:** (1) gepflegte Liquid-Wallet wählen und Backup-Modell prüfen; (2) Testnet oder kleinen rechtmäßigen Betrag verwenden; (3) an Confidential Address empfangen und prüfen, dass die Wallet den Output als blinded markiert; (4) vertrauliche Testtransaktion senden; (5) prüfen, welche Explorer-Felder öffentlich bleiben; (6) nur den für das Audit erforderlichen begrenzten Blinding Proof exportieren; (7) Peg-/Exchange-Grenzen dokumentieren und Gelder abgleichen.

**Erkennung:** Sichtbaren Graphen/Gebühr/Zeit, Peg- und Exchange-Daten, Netzwerkmetadaten und spätere Unblinding-Evidence analysieren; keinen verborgenen Betrag oder Assettyp ableiten. **Capture-resiliente OPSEC:** Spend Seed, Blinding/View-Daten und Watch-only-Operationen trennen. **Monitoring:** Bei versehentlich unconfidential Adressen, unbekannten Peg Requests, Descriptor-Änderungen und nicht genehmiertem Export von Unblinding Keys alarmieren.

## Allgemeiner Payment- oder State Channel

**Mechanik:** Teilnehmer sperren Funds, tauschen signierte Off-Chain-State-Updates aus und veröffentlichen nur Opening, Closing oder strittigen State auf der Chain. Zwischenzahlungen werden nicht global broadcastet, aber Peers und Routing-/Intermediary-Services sehen ihren Anteil, und Endpunkte müssen den zuletzt durchsetzbaren State aufbewahren.<sup>[[23]](#references)</sup>

**Vorteile:** Viele schnelle Interaktionen mit niedrigen Gebühren und begrenzter Sichtbarkeit auf dem öffentlichen Ledger; weniger globale Transaktionsdetails; begrenzter Channel-Saldo; nützlich für gemessene Services und wiederkehrende Gegenparteien.

**Nachteile:** Channel-Peers kennen einander und können Updates speichern; Opening/Closing/Wert/Timing korrelieren; während Challenge Windows kann Online-Monitoring erforderlich sein; Implementierungs- und Liquiditätsrisiko; allein kein großes Anonymity Set.

**Verfahren:** (1) gepflegte auditierte Implementierung auswählen und Dispute Window verstehen; (2) Low-Value-Testchannel zwischen eigenen Parteien öffnen; (3) signierte State Updates mit eindeutigen Nonces austauschen; (4) neuesten durchsetzbaren State sichern; (5) kooperativ schließen; (6) Ablehnung eines veralteten States im Testnet üben; (7) Buchhaltung und Channel-Peer-Datensätze aufbewahren.

**Erkennung:** Öffentliche Chain zeigt Lifecycle/Disputes; Peers, Watch Services und Application Transport zeigen Off-Chain-Timing und Parteien. **Capture-resiliente OPSEC:** Hot Balance begrenzen und den letzten signierten State in einem verschlüsselten wiederherstellbaren Store getrennt von Field Nodes halten. **Monitoring:** Kontinuierlich auf Veröffentlichung eines veralteten States, fehlendes Backup, Peer-Key-Änderung und bevorstehende Challenge Deadline achten.

## Mobile-Carrier-Billing

**Mechanik:** Ein Online-Service belastet einen Kauf über das Carrier-Billing-System einer Mobile Subscription oder eines Prepaid-Guthabens. Der Händler erhält möglicherweise eine Carrier Authorization statt Karten-/Bankdaten, während der Carrier Subscriber/Line, Geräte-/Netzwerkkontext, Händler, Betrag und Zeitpunkt kennt.<sup>[[24]](#references)</sup>

**Vorteile:** Keine Kartennummer beim Händler; breite Telefonverfügbarkeit; für digitale Güter mit geringem Wert nutzbar; Carrier kann Gebühren begrenzen und rückgängig machen.

**Nachteile:** Durch SIM/Konto und häufig Gerät stark identifiziert; kleine Limits und hohe Gebühren; Händlerkategoriebeschränkungen; Account-Takeover-/SIM-Swap-Risiko; Carrier und Aggregator erzeugen vollständigen Transaktionsdatensatz.

**Verfahren:** (1) Serviceverfügbarkeit, Limit, Gebühr und Refund Terms beim Organisations-Carrier-Konto bestätigen; (2) nur bei gerechtfertigtem Bedarf auf einer dedizierten Organisationsleitung aktivieren; (3) niedrigstes sinnvolles Ausgabenlimit setzen; (4) gutartiges Testprodukt kaufen; (5) Händler- und Carrierquittungen prüfen; (6) wiederkehrende Authorization deaktivieren; (7) abgleichen und Funktion nach dem Assessment abschalten.

**Erkennung:** Carrier-, Aggregator- und Händlerdaten verbinden Leitung, Subscriber, IP/Gerät und Charge; Enterprise-Telecom-Rechnungen legen dies offen. **Capture-resiliente OPSEC:** Keine private Telefonnummer verwenden und Carrier-Account-MFA außerhalb des Field Devices verlangen. **Monitoring:** Sofortige Charge-/SIM-Change-Alerts aktivieren und bei unerwarteter Premium-Service-Registrierung, Weiterleitung oder Account-Recovery stoppen.

## Open-Banking-Payment-Initiation

**Mechanik:** Mit ausdrücklicher Zustimmung bittet ein regulierter Payment-Initiation-Service-Provider (PISP) die kontoführende Bank, eine Überweisung einzuleiten. Der Händler erhält möglicherweise keine Karten-Credentials, aber PISP und Banken behalten regulierte Zahler-, Empfänger-, Consent-, Geräte- und Transaktionsdaten.<sup>[[25]](#references)</sup>

**Vorteile:** Keine wiederverwendbare Kartennummer beim Checkout; starke Bankauthentifizierung; exaktes Account-to-Account-Settlement; Consent- und Status-APIs; klare Abgleichbarkeit.

**Nachteile:** Nicht anonym gegenüber Banken/PISP; Zahlungsempfänger sieht häufig rechtliche Kontodaten oder Referenz; Phishing-/Redirect-Risiko; Jurisdiktion und Refund-Schutz variieren; Consent-Metadaten fügen einen weiteren Beobachter hinzu.

**Verfahren:** (1) prüfen, dass der PISP aktuell reguliert und die Merchant-Callback-Domain authentisch ist; (2) über die Merchant Request starten; (3) Empfänger, Betrag, Referenz und verlangte Zustimmung bei der Bank prüfen; (4) nur die einzelne Zahlung autorisieren; (5) finalen Status unabhängig verifizieren; (6) verbleibende Zustimmung widerrufen; (7) Quittung aufbewahren und abgleichen.

**Erkennung:** Bank-/PISP-/Händlerlogs und Transferreferenzen liefern starke Attribution. **Capture-resiliente OPSEC:** Bankauthentifizierung und Recovery außerhalb operativer/Field Devices halten; das Gerät sollte nur ein Paid-Service-Entitlement enthalten. **Monitoring:** Banktransaktions-/Consent-Alerts verwenden und neue PISP Grants, geänderte Zahlungsempfänger oder Status-Callbacks außerhalb der erwarteten Session untersuchen.

## Platform Wallet, App-Store-Guthaben oder In-App-Credit

**Mechanik:** Eine Plattform belastet den Nutzer oder löst Kontoguthaben ein und stellt anschließend einer Anwendung eine signierte Quittung oder ein Entitlement aus. Der App-Entwickler erhält möglicherweise nicht das ursprüngliche Funding-Instrument, während die Plattform Konto, Gerät, Funding, Produkt und Redemption verbindet.<sup>[[26]](#references)</sup>

**Vorteile:** Händler/Entwickler erhält keine primäre PAN; Fraud-/Refund- und Familien-/Unternehmenskontrollen; kleines Prepaid-Guthaben begrenzt Exposure; signierte Quittungen vereinfachen Entitlement Verification.

**Nachteile:** Plattformkonto ist ein starkes Identitäts- und Verhaltenszentrum; Geräte- und Storefront-Geografie; Kauf-/Einlösespur des Guthabens; begrenzter Cash-out; Fraud Controls können Funds einfrieren; kein plattformübergreifendes Geld.

**Verfahren:** (1) organisationsverwaltetes Plattformkonto verwenden, sofern Richtlinie dies erlaubt; (2) Funding-, Regions-, Refund- und Transferability-Regeln prüfen; (3) nur das genehmigte Budget hinzufügen; (4) gutartiges Produkt über den offiziellen Store kaufen; (5) prüfen, dass die Anwendung nur erwartete Receipt-Felder erhält; (6) wiederkehrende Käufe deaktivieren; (7) abgleichen und Konto von operativer Hardware entfernen.

**Erkennung:** Platform Receipts/Server Notifications, Konto-/Geräte-Login und Funding-Daten rekonstruieren den Kauf. **Capture-resiliente OPSEC:** Niemals ein persönliches Store-Konto auf einem Field Node anmelden; nach Möglichkeit nur ein begrenztes App-Entitlement bereitstellen. **Monitoring:** New-Device-/Purchase-Alerts aktivieren und Receipt Replay, Familien-/Kontoänderungen oder unerwartete Restore Events untersuchen.

## Mutual Credit, Clearing oder periodisches Net Settlement

**Mechanik:** Teilnehmer erfassen Verpflichtungen in einem privaten Ledger und begleichen periodisch nur ihre Nettoposition. Einzelne Serviceereignisse müssen keine separaten öffentlichen Zahlungen erzeugen, aber Ledger-Betreiber und Gegenparteien behalten detaillierte Attribution.

**Vorteile:** Weniger externe Transaktionen und Gebühren; öffentliche Beobachter sehen nur das Net Settlement; geeignet für wiederkehrende Organisationen; explizite Kreditlimits begrenzen Exposure.

**Nachteile:** Zentralisierter Ledger ist vollständiges Evidence und ein Fraud-Ziel; Gegenparteien-/Default-Risiko; rechtliche/buchhalterische/steuerliche Pflichten; kleine Mitgliedermenge; ungewöhnliche Net Transfers können Beziehungen offenlegen.

**Verfahren:** (1) nur identifizierte zustimmende Organisationen mit rechtlicher/buchhalterischer Genehmigung verwenden; (2) Einheit, Kreditlimit, Settlement-Intervall und Streitregeln definieren; (3) jede Verpflichtung mit unveränderlicher Genehmigung erfassen; (4) getrennte Finance-Rollen Nettopositionen berechnen und genehmigen lassen; (5) über einen gewöhnlichen rechtmäßigen Rail begleichen; (6) Einzelpositionen mit dem Settlement abgleichen; (7) Zugriff schließen und Datensätze nach Richtlinie aufbewahren.

**Erkennung:** Ledger, Rechnungen, Freigaben und finales Bank-/Chain-Settlement liefern Ground Truth; Analysten sollten fehlende Bruttoaktivität nicht allein aus dem Net Transfer ableiten. **Capture-resiliente OPSEC:** Operative Geräte können begrenzte Requisitions einreichen, aber Salden nicht ändern oder Settlement autorisieren. **Monitoring:** Bei Kreditlimitüberschreitung, rückdatierten Einträgen, Administratoränderungen, Reconciliation Mismatch und Settlement an einen neuen Begünstigten alarmieren.

## Exposure-Matrix für Capture/Kompromittierung

Dies wendet auf jede Familie einen Beschlagnahme-/Verlusttest an. Ziel ist, Ausgabenbefugnis und Offenlegung unabhängiger Identitäten zu begrenzen und gleichzeitig rechtmäßige Buchhaltung zu erhalten – nicht Transaktionen zu löschen oder Ermittlungen zu vereiteln.

| Technikfamilie | Ein erfasstes Wallet/Gerät/Konto kann offenlegen | Minimale autorisierte Kontrolle |
|---|---|---|
| Bargeld, Zahlungsanweisung/COD, Prepaid/Geschenkguthaben, physischer Bearer Value | Quittungen, Seriennummern, Notizen, verbleibenden Bearer Value und physische Kontakte | nur genehmigten Betrag mitführen; private Buchhaltung trennen; Verlust sofort melden; keine falschen Datensätze |
| Prepaid, Gift, Voucher, Service Credits | Saldo, Issuer, Aktivierung, Einlösung und Konto-/Session-Tokens | niedriger Saldo; ein Zweck; wahrheitsgemäße Registrierung; Issuer-Freeze/Revocation, sofern verfügbar |
| Virtuelle/tokenisierte Karte, Wallet Token, Payment App | Issuerkonto, Gerätetoken, Transaktionen, Recovery und Händlerhistorie | Gerätesperre; Transaktionsalerts; Händler-Scope; Remote-Issuer-Suspension; kein gemeinsames Recovery-Konto |
| Bank-Kompartiment, delegiertes Procurement, Red-Team-Procurement | Organisation, Approver, Händler, Rechnungen und Projekt | Rollentrennung; Least-Privilege-Subkonto; Finanz-Credentials niemals auf operativen/Field Nodes |
| Invoice, Escrow, Batch Settlement | Gegenpartei, Zweck, ausstehende Genehmigung, Coordinator oder Streitspur | einmalige Request; separater Approver; begrenzte Session; zentraler verbindlicher Ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | Seed/Keys, Labels, Adressen, Transaktionsgraph und Netzwerkkonfiguration | Hardware-/Offline-Signing; verschlüsselte Wallet; Passphrase-Limits; Watch-only-Field-View; dokumentierte Recovery |
| Lightning/BOLT 12 | Seed, Channels, Invoices, Peers/LSP und Payment Database | kleiner Hot Balance; verschlüsseltes Backup; separate Node Identity; Closing/Recovery nach dokumentiertem Plan |
| Monero, Zcash, MWEB, ZK-Anwendungen | Spend-/View-Keys, lokale Wallet-Historie, RPC und Boundary Transactions | Spend-/View-Rollen trennen; Hardware-Support nutzen, sofern verfügbar; keine Exchange-Session auf Field Node |
| Stablecoins, Swaps, Bridges und DEX | transparenten Graph, Approvals, RPC-/Frontend-Zustand und Zielassets | Allowances widerrufen; Contracts verifizieren; Low-Value-Test; vollständiger Abgleich |
| Cashu, Fedimint, Taler, Privacy Pass | Bearer Tokens, Mint/Federation/Exchange, Issuance-/Redemption-Cache | kleiner Saldo; verschlüsseltes Backup nach Protokoll; redeem/reissue; Funding Credential niemals gemeinsam ablegen |
| Paymaster, Multisig/Threshold | Session Key, einen Signer, ausstehende Operations und Sponsor Policy | enger Session Key; unabhängiges Quorum; Signer Rotation; Field Device darf Threshold nicht erreichen |
| Mixer/Peel/Structuring, Nominees/Fronts, Refund/Gambling Abuse | belastende Provider-, Kommunikations-, Graph- und Teilnehmerdaten | keine operative Nutzung; nur mit synthetischen/Testnet-Evidence emulieren |
| Community-/Event-Währung | Enrollment, lokalen Saldo, Gegenparteien und Redemption | begrenzter Wert; Issuer Freeze/Reissue; Zustimmung und private auditierbare Buchhaltung |
| Wiederverwendbare Bitcoin-/EVM-Stealth-Adresse | Payment-/View-/Spend-Keys, Beziehungsmetadaten, Announcements und abgeleitete Outputs | Watch-/View-only-Netzwerkrolle; Offline-/Hardware-Spend-Rolle; keine persönliche Funding-Session |
| Liquid Confidential/State Channels | Seed, Blinding-Daten/aktuellen State, Peers, Grenzen und Disputes | Spend/View/State-Backup trennen; geringer Hot Balance; unabhängiger Dispute Monitor |
| Carrier/Open-Banking/Platform Billing | Telefon-/Bank-/Store-Konto, Consent, Receipt, Gerät und Fundingquelle | Organisationskonto; externe MFA; niedriges Limit; kein persönliches Konto auf Field Hardware |
| Mutual-Credit-Clearing | Mitglieder, Verpflichtungen, Limits, Freigaben und Settlement-Ledger | nur operative Requisition; separater unveränderlicher Ledger und Dual Finance Approval |

## Überwachung möglicher Discovery oder Payment-Kompromittierung

Eine Zahlungsablehnung, Compliance-Prüfung oder Offline-Wallet beweist nicht, dass eine Untersuchung stattfindet. Nur Konten, Ledger und Infrastruktur überwachen, deren Beobachtung die Organisation autorisiert ist; Provider oder Gegenparteien niemals sondieren, um festzustellen, ob sie mit Ermittlern kooperieren.

| Abgedeckte Techniken | Sichere Monitoring-Signale | Freeze-/Stop-Bedingung |
|---|---|---|
| Bargeld, Zahlungsanweisung/COD, Prepaid/Gift/Voucher, physischer Bearer Value | Inventar-/Quittungsabweichung, doppelte Seriennummer, unerwartete Einlösung/Rückerstattung oder Verlustmeldung | fehlendes Instrument, Einlösung außerhalb genehmigter Order, geänderte Quittung oder Custody Break |
| Virtuelle/tokenisierte Karte, Payment App, Bank/ACH/Wire, Open Banking, Carrier/Platform Billing | Issuer-/Bank-/Plattformalerts, neues Gerät/Consent/Payee, Token-Wiederverwendung, SIM-/Account-Recovery | unbekannte Autorisierung, Payee-Änderung, neuer Recovery-Faktor, SIM-Swap oder Recurring Charge |
| Konto-/Händlerkompartiment, kontrolliertes/delegiertes Procurement, Service Credits | IdP-/Vendor-Projekt-, Rollen-/Token-/Budgetänderung, Rechnung und Verbrauch | Cross-Project-Token, unbekannter Admin, Limitüberschreitung, Rechnungsabweichung oder nicht unterstütztes Ziel |
| Invoice, Escrow, Pooled Settlement, Mutual Credit | Request-Ablauf, Approval/Release, Ledgerintegrität, Reconciliation und Begünstigtenänderung | geänderter Betrag/Payee, rückdatierter Ledger, einseitige Freigabe oder nicht abgeglichener Batch |
| Bitcoin-Adresse/Coin Control, Silent Payments, BIP47/BIP351 | Watch-only-Transaktionen, Notification-/Scan-State, Address Reuse, UTXO-Labels und Consolidation | unbekannter Spend, wiederverwendeter Empfänger-Output, Wallet-Gap-/Recovery-Fehler oder nicht genehmigte Zusammenführung |
| PayJoin/CoinJoin | Proposal-Inputs/Outputs/Gebühren, Coordinator-Verfügbarkeit, finale Transaktion | ersetzter Output, überhöhte Gebühr, unerwartete Input-Offenlegung oder Coordinator-Policy-Änderung |
| Lightning/BOLT12/allgemeine Channels | Channel-Backup, Invoice-/Offer-Nutzung, Liquidität, Peer/LSP und Chain-Dispute | unbekannte Invoice-Zahlung, Peer-Key-Änderung, veraltetes Close oder bevorstehende Dispute Deadline |
| Monero/Zcash/MWEB/Liquid CT | View-/Watch-Events, Pool-/Domain-/Adresstyp, Descriptor und Boundary Transaction | Spend ohne Genehmigung, transparenter/unconfidential Downgrade, Key-Export oder unbekannte Boundary |
| Ethereum ZK, Stealth Addresses, Paymaster, Stablecoin | Contract/Announcement, RPC/Bundler, Gas Sponsor, Allowance/Session Key und Issuer-Aktion | falscher Contract/öffentlicher Wert, unbekannte Approval/Spend, Paymaster-Änderung oder Issuer Freeze |
| Cashu/Fedimint/Taler/Privacy Pass | Mint-/Federation-/Exchange-Zustand, Token Double-Spend/Replay, Gateway und Bearer-Saldo | unbekannte Redemption, Mint-Key-/Terms-Änderung, Restore-Fehler oder Saldoinkonsistenz |
| Swaps/Bridges/DEX | verifizierter Contract, Allowance, Bestätigungen beider Chains, Kurs und Ziel | Contract-/Route-Abweichung, unbegrenzte Approval, fehlendes Ziel oder Bridge Incident |
| Multisig/Threshold | Signer-Set-/Policy-Änderung, ausstehende Proposal, Quorum und Recovery-Audit | unbekannte Proposal/Signer, Threshold-Reduktion, Recovery-Aktivierung oder Policy Bypass |
| Mixer/Peel/Structuring, Nominees/Fronts, NFT/Gambling/Refund Abuse | ausschließlich synthetische Ground Truth des Labs und Detection Output | jedes echte Konto, jede Person oder jeder Wert in der Emulation: sofort stoppen |

## Auswahl- und Verifizierungsworkflow

1. Benennen, welche Partei welches Feld nicht erfahren darf.
2. Issuer/Mint/Custodian, Public Ledger, Network/RPC, Händler und physische Beobachter identifizieren.
3. Aktuelle Unterstützung, Rechtmäßigkeit, Limits, Custody, Recovery und Refund-Verhalten verifizieren.
4. Einen kleinen rechtmäßigen End-to-End-Test durchführen.
5. Händlerquittung, Provider-Auszug, Public Chain und Wallet-/Node-Logs prüfen.
6. Backup/Recovery und bewusste Audit-Offenlegung testen.
7. Erforderliche Source-, Ownership-, Steuer-, Sanktions- und Engagement-Datensätze korrekt, aber zugriffskontrolliert halten.

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Beobachtungen zur Datenerhebung durch große Payment-Plattformen](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Schütze deine Privatsphäre](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Ein einfacher Payjoin-Vorschlag](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion-Routing-Protokoll](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Technische Spezifikationen und Netzwerk-Privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Aufbau von Privacy-Anwendungen mit Zero-Knowledge-Proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protokoll und Privacy-Einschränkungen](https://docs.cashu.space/faq)
- [13] [Fedimint — Funktionsweise](https://fedimint.org/users/how-it-works)
- [14] [GNU-Taler-Dokumentation](https://docs.taler.net/)
- [15] [FATF — Red-Flag-Indikatoren für Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administratoren, Exchanger und Nutzer virtueller Währungen](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU-Verordnung 2023/1113 — Transferinformationen und Crypto-Assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Die Privacy-Pass-Architektur](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Wiederverwendbare Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State- und Payment-Channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier-Billing-API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment-Initiation-Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
