# Katalog anonymer Zahlungstechniken

{{#include ../banners/hacktricks-training.md}}

Dieser Katalog behandelt **Familien** von gewöhnlichem Bargeld bis zu Blind-Signature-E-Cash und Public-Chain-Obfuscation. „Anonym“ bedeutet immer anonym gegenüber einem benannten Beobachter. Händler, Issuer, Mint, Exchange, Blockchain-Analyst, Netzwerkprovider, Arbeitgeber und physische Beobachter sehen unterschiedliche Fakten.

Die folgenden Verfahren gelten für rechtmäßige Gelder, wahrheitsgemäße Konten und autorisierte Beschaffung. Techniken, deren Zweck in den zitierten Fällen Geldwäsche, Sanktionsumgehung oder Identitätsbetrug war, werden erklärt und erkannt; ihr Ablauf ist jedoch eine synthetische forensische Übung und keine Anleitung zur Begehung der Straftat.

## Coverage matrix

| Familie | Wichtigste Privacy-Eigenschaft | Wichtigster Beobachter/Vertrauenspunkt | Behandlung |
|---|---|---|---|
| Bargeld und bargeldähnliche Werte | kein Remote-Zahlungsnetzwerkdatensatz | Empfänger und physische Umgebung | rechtmäßiger Ablauf |
| Prepaid-/Geschenk-/Gutscheinwert | trennt Einlösung von primärer Karte | Händler, Issuer und Einlösedienst | rechtmäßiger Ablauf, je nach Rechtsordnung |
| Virtuelle/tokenisierte Karte | verbirgt wiederverwendbare PAN oder trennt Händler | Issuer/Netzwerk/Wallet identifizieren den Zahler weiterhin | rechtmäßiger Ablauf |
| Payment-App/Intermediär | Händler sieht möglicherweise Alias/Intermediär | App sammelt Identitäts-, Geräte- und Transaktionsdaten | Vergleichsbasis |
| Bitcoin-Hygiene/Silent Payments | Pseudonyme und fehlende Empfänger-Verknüpfbarkeit | Public Graph und Wallet-/Netzwerkgrenze | einsetzbar |
| PayJoin/CoinJoin | schwächt Common-Ownership-/Linkage-Heuristiken | Teilnehmer/Coordinator/Netzwerk/Public Graph | einsetzbar, sofern unterstützt; rechtliche Prüfung |
| Lightning/BOLT 12 | Off-Chain-Routing und reduzierte Empfängerpfade | Endpunkte, Hops, Dienste und Channel-Graph | einsetzbar, sofern unterstützt |
| Monero/Zcash/MWEB | On-Chain-Vertraulichkeit auf Protokollebene | Beschaffung, Endpunkt, Netzwerk und Grenzen bleiben | einsetzbar, sofern rechtmäßig/unterstützt |
| Ethereum-ZK-Anwendung | verbirgt eine bestimmte Aussage-/Aktionsverknüpfung | öffentliche Inputs, RPC, Relayer und App | anwendungsspezifisch |
| Cashu/Fedimint/Taler | Payer-Privacy durch Blind Signatures | Mint/Federation/Exchange-Custody und Grenzen | aufkommend/einsatzspezifisch |
| Stablecoins | bequeme digitale Abwicklung | transparente Chain sowie Issuer-Freeze/Control | keine anonyme Grundlage |
| Swaps/Bridges/DEX | bewegt Wert zwischen Assets/Chains | beide Graphen, Contracts und Provider | forensische Mechanik; nur gewöhnliche rechtmäßige Swaps |
| Mixer/Peel/Structuring | erhöht Graph-Mehrdeutigkeit und Analyseaufwand | Entry-/Exit-Graph und Servicedaten | nur synthetische Erkennungsübung |
| Nominees/Mules/OTCs/Fronts | fügt menschliche/geschäftliche Intermediäre ein | Helfer, Banken, Kommunikation | ausschließlich Analyse kriminellen Missbrauchs |
| Wiederverwendbare/Stealth-Payment-Adressen | neue Empfängeradresse pro Zahlung | öffentliche Bekanntgabe/Benachrichtigung und Wallet-Grenzen | einsetzbar, sofern unterstützt |
| Confidential Sidechain/State Channel | verbirgt Betrag/Asset oder Zwischenupdates | Peers, Bridge/Federation und Lifecycle-Settlement | protokollspezifisch |
| Carrier/Open Banking/Platform Billing | verbirgt primäre Karte vor dem Händler | Carrier, Bank/PISP oder Plattform identifizieren Kunden | gewöhnliche identifizierte Zahlung |
| Mutual Credit/Net Settlement | weniger externe Settlement-Datensätze | privater Ledger-Betreiber besitzt vollständige Zuordnung | nur identifizierte Teilnehmer |

## Cash

**Mechanik:** Physischer Bearer-Wert wechselt ohne Online-Autorisierung eines Issuers oder öffentlichen Ledger den Besitzer.

**Vorteile:** Der Händler muss Bank-/Kartenidentität nicht erfahren; kein Remote-Transaktionsgraph; allgemein verständlich und grundsätzlich final.

**Nachteile:** Nur persönliche Übergabe; Diebstahl/Verlust; Wechselgeld/Belege/Seriennummern oder Meldekontrollen; Abhebung, Kameras, Zeugen und Ort können den Zahler weiterhin verknüpfen.

**Ablauf:** (1) bestätigen, dass Bargeld legal/akzeptiert ist und Betrags-/Meldepflichten prüfen; (2) rechtmäßig abheben oder erhalten und private Buchhaltungsunterlagen führen; (3) bei einem gewöhnlichen Händler ohne unnötige Loyalty-/Kontokennungen bezahlen; (4) nur den erforderlichen Beleg anfordern; (5) keine Versand-/Kontodaten angeben, wenn der Kauf sie nicht benötigt; (6) legitimen Geschäftszweck intern dokumentieren.

**Erkennung:** Kasse/Belege/Inventar sowie Kameras und Zutrittslogs gemäß geltender Richtlinie abgleichen; ungewöhnliche Bargeldrückerstattungen oder wiederholte Beträge knapp unter Kontrollgrenzen untersuchen, ohne gewöhnliche Bargeldnutzung allein als verdächtig zu behandeln.

## Money Order, Postal Order, Cashier Instrument und Cash on Delivery

**Mechanik:** Ein regulierter Issuer wandelt Bargeld/Kontoguthaben in ein nummeriertes Instrument zugunsten eines benannten Empfängers um; COD verschiebt die Einziehung bis zur Lieferung.

**Vorteile:** Der Empfänger erhält möglicherweise nicht die primäre Bank-/Kartennummer des Zahlers; nutzbar, wenn Bargeld nicht remote versendet werden kann; klare Belege.

**Nachteile:** Issuer/Händler speichern erforderliche Kauf-/Identitätsdaten; Seriennummernverfolgung; Empfänger-/Lieferadresse; Verlust/Betrug und regionale Einschränkungen; im Allgemeinen nicht anonym.

**Ablauf:** (1) Regeln, Limits, Identifikation und Empfängerakzeptanz prüfen; (2) mit wahrheitsgemäßen Angaben und rechtmäßigen Mitteln kaufen; (3) Zahlungsempfänger/Betrag sofort eintragen; (4) Seriennummer/Beleg aufbewahren; (5) dem Wert angemessenen Tracking-Versand verwenden; (6) Einlösung/Rückerstattung abgleichen.

**Erkennung:** Kauf-/Einlösedatensatz des Issuers, Seriennummer, Händler/Kamera, Versand und Empfängerkonto; Änderungen, doppelte Seriennummern und schnelle geografisch unplausible Einlösungen markieren.

## Open-loop Prepaid Card

**Mechanik:** Ein netzwerkgebundenes Stored-Value-Instrument autorisiert gegen ein Prepaid-Guthaben statt gegen ein primäres Kreditkonto.

**Vorteile:** Begrenzt Händlerexposure und Verlust; trennt Händler von der Haupt-PAN; online nutzbar, sofern akzeptiert.

**Nachteile:** Kauf-/Aktivierungs-/Auflade-/Registrierungs- und Gerätedaten; KYC und Limits variieren; Probleme mit Rechnungsadresse; Einschränkungen bei Auszahlung/Rückerstattung; „kein Name“ bedeutet keinen fehlenden Issuer-Datensatz.

**Ablauf:** (1) aktuelle Issuer-Identität, Gebühren, KYC, Region sowie Online-/Recurring-Unterstützung prüfen; (2) über autorisierten Händler mit rechtmäßigen Mitteln beschaffen; (3) erforderliche Daten wahrheitsgemäß registrieren; (4) für einen einzelnen Zweck verwenden; (5) Loads nicht strukturieren und Wohnsitz nicht fälschen; (6) Kauf-/Ausgabennachweise aufbewahren und nach Issuer-Bedingungen schließen/entsorgen.

**Erkennung:** Händler-/Aktivierung, Funding, Gerät/IP, Merchant Authorization, Saldoabfragen und Einlösung/Rückerstattung verbinden. Muster sind wichtiger als das Prepaid-Label.

## Closed-loop Gift Card, Voucher und übertragbares Serviceguthaben

**Mechanik:** Nummerierter Wert kann nur bei einem Händler, Service oder Ökosystem eingelöst werden. Airtime-, Game- und Store-Credits sind Varianten.

**Vorteile:** Der Empfängerhändler sieht möglicherweise nur Code/Saldo; begrenzter Schadensradius; einfaches Schenken und Budgettrennung.

**Nachteile:** Verkäufer und Service protokollieren Kauf/Aktivierung/Einlösung; Konto/Gerät/Zustellung verknüpfen weiterhin; Betrug, Wiederverkaufsrabatte und Ablauf-/Regionslimits; schwacher Rückerstattungsschutz.

**Ablauf:** (1) nur autorisierte Kanäle verwenden; (2) Codewert dokumentieren, ohne das Geheimnis offenzulegen; (3) unnötiges Loyalty-Konto nicht verbinden; (4) über ein separates legitimes Händlerkonto/einen separaten Kontext einlösen; (5) Beleg bis zur Annahme behalten; (6) niemals Codes für unaufgeforderte Steuer-/Support-/Ransom-Forderungen kaufen.

**Erkennung:** Ausgabe-/Einlösungszeit, Geräte-/Kontenkonvergenz, Bulk-/Schwellenmuster, ein Gerät mit vielen Saldoabfragen und schnelle entfernte Einlösung.

## Cryptocurrency-funded Card oder Gift-code Broker

**Mechanik:** Ein Intermediär akzeptiert Cryptocurrency und stellt Karte, Gutschein oder Händlercode aus. Dies ist eine Cross-Rail-Konvertierung: Der Händler sieht gewöhnlichen Karten-/Gutscheinwert, während der Broker On-Chain-Einzahlung, Ausstellung und Zustellung verbindet.

**Vorteile:** Der Händler erhält die Funding-Wallet nicht; nützlich für legitime Händler ohne Crypto-Akzeptanz; begrenzter Stored Value.

**Nachteile:** Nicht anonym gegenüber Broker/Issuer; KYC-, Sanktions-, Exchange- und Card-Program-Regeln; öffentlicher Deposit-Graph; Konto/Gerät/E-Mail und Code-Einlösung verbinden beide Seiten erneut; Betrugs-/Insolvenzrisiko.

**Ablauf:** (1) Rechtsträger, Card Issuer, unterstützte Region, KYC, Gebühren und Rückerstattungsregeln prüfen; (2) nur rechtmäßige dokumentierte Mittel verwenden; (3) kleinste Stückelung testen; (4) Netzwerk-/Händlerbeschränkungen prüfen; (5) Blockchain-Transaktion und Brokerbeleg für die Buchhaltung aufbewahren; (6) niemals einen Broker verwenden, der Identitätsbetrug, Sanktionsumgehung oder „untraceable“ Cash-out verspricht.

**Erkennung:** Broker-Deposit-Adressen, eindeutiger Betrag/Zeit, Konto/Gerät sowie Kartenautorisierung oder Gutscheineinlösung korrelieren; Issuer- und Brokerdaten verbinden Public Chain und Händler.

## Virtual oder merchant-locked card

**Mechanik:** Der Issuer ordnet eine generierte PAN/einen Token dem echten Konto zu und beschränkt häufig Händler, Betrag oder Ablauf.

**Vorteile:** Verhindert Offenlegung einer wiederverwendbaren PAN; Händlersegmentierung; Ausgabenlimits und einfache Sperrung; ausgereifte Fraud Controls.

**Nachteile:** Issuer kennt weiterhin Zahler, Funding, Händler, Gerät/IP und Zeit; Händler sieht Konto/Zustellung; manche Rückerstattungen/Recurring Charges scheitern; nicht anonym.

**Ablauf:** (1) offizielle Funktion des regulierten Issuers nutzen; (2) Karte für einen Händler/ein Engagement erstellen; (3) kleinstes sinnvolles Limit und Ablauf setzen; (4) erforderliche Rechnungsdaten korrekt angeben; (5) Statement Descriptor/Rückerstattungsverhalten prüfen; (6) nach finalem Settlement einfrieren/löschen und Auditnachweise behalten.

**Erkennung:** Issuer-Token-zu-Konto-Mapping, Händlerautorisierung, Gerät und Zustellung. Verteidiger nutzen händlerspezifische Wiederverwendung, Velocity und Account-Takeover-Signale.

## Mobile-wallet network token

**Mechanik:** EMV-Payment-Tokenization ersetzt die PAN durch ein beschränktes Credential, das oft an Gerät, Händler oder Zahlungsszenario gebunden ist.<sup>[[1]](#references)</sup>

**Vorteile:** Händler erhält keine wiederverwendbare PAN; Geräte-Kryptografie und dynamische Daten reduzieren Cloning; widerrufbar ohne Kartentausch.

**Nachteile:** Issuer, Token Service, Wallet-Plattform und Netzwerk behalten Mappings/Transaktionen; Geräte-/Plattformkonto und Standort können den Zahler identifizieren.

**Ablauf:** (1) legitime Karte in der offiziellen Wallet registrieren; (2) Plattformkonto/Gerät mit starker Authentisierung schützen; (3) Gerätetoken/letzte Ziffern beim Kauf prüfen; (4) unnötige Standort-/Analytics-Funktionen deaktivieren, sofern möglich; (5) verlorene Geräte/Tokens sofort entfernen; (6) Issuer- und Wallet-Daten prüfen.

**Erkennung:** Token Requestor/Geräte-Cryptogramm und Issuer-Mapping, Wallet-/Kontotelemetrie, Händlerterminal und physische Beweise.

## Payment App, Marketplace Wallet und zentraler Intermediär

**Mechanik:** Der Dienst verwaltet Konten und Transfers intern oder über Bank-/Kartenrails; der Händler sieht möglicherweise einen Alias, der Dienst jedoch beide Parteien.

**Vorteile:** Komfort, Streit-/Rückerstattungsmechanismen; Empfänger sieht nicht zwingend Bank-/Kartendaten.

**Nachteile:** Zentraler Identitäts-/Sozial-/Transaktions-/Gerätegraph; Sperren und rechtliche Verfahren; Gegenparteien können das Profil offenlegen; Datennutzung kann über den Zahlungszweck hinausgehen.<sup>[[2]](#references)</sup>

**Ablauf:** (1) Identitäts-, Privacy-, Aufbewahrungs- und Käuferschutzbedingungen lesen; (2) optionale Profil-/Kontakt-Synchronisierung minimieren; (3) separates wahrheitsgemäßes Konto nur bei erlaubter Nutzung verwenden; (4) MFA/Alerts aktivieren; (5) Empfänger sowie Privacy von Memo/Profil prüfen; (6) Datensätze exportieren und ungenutzte Verknüpfungen schließen.

**Erkennung:** Providerkonto, Gerät/IP, Kontaktgraph, Funding/Withdrawal, Memo und Händlerdaten. Ein Alias ist Pseudonymität gegenüber einer Gegenpartei, nicht Anonymität gegenüber der Plattform.

## Bank Transfer, ACH, Wire und Instant-account Payment

**Mechanik:** Regulierte Institute bewegen Wert zwischen identifizierten Konten und tauschen vorgeschriebene Zahlungsdaten aus.

**Vorteile:** Schnell, nachvollziehbar, begrenzt rückholbar, starke Datensätze; virtuelle Kontonummern können Händleroffenlegung reduzieren.

**Nachteile:** Banken/Processor kennen beide Seiten; Kontoauszüge und Referenzen; nicht anonym; grenzüberschreitende Daten sowie Travel-Rule-/AML-Daten.

**Ablauf:** Nur verwenden, wenn Nachvollziehbarkeit akzeptabel ist: Begünstigten unabhängig prüfen, optionale Memo-Daten minimieren, verfügbares bankseitiges virtuelles Konto/Referenz verwenden, Alerts aktivieren, Rechnung aufbewahren und abgleichen.

**Erkennung:** Deterministische Bank-/Payment-Datensätze, Begünstigten-/Kontoinhaber, Gerät/Session und Fraud Controls. Dies ist eine Basis, keine Anonymitätstechnik.

## Account- und Händlersegmentierung

**Mechanik:** Getrennte rechtmäßige Identitäten/Konten, E-Mail-Aliase, Karten und Lieferkontexte verhindern, dass unabhängige Händler Aktivitäten trivial zusammenführen, während ein Issuer/Controller die Zuordnung behält.

**Vorteile:** Reduziert Breach- und Cross-Merchant-Linkage; leicht auditierbar; kompatibel mit regulierten Zahlungen.

**Nachteile:** Provider verbindet Segmente weiterhin; Recovery-Telefon, Gerät/IP und Versand können sie wieder verbinden; Richtlinien können mehrere Konten untersagen.

**Ablauf:** (1) einen Zweck definieren; (2) nur richtlinienkonforme Aliase/Subkonten erstellen; (3) händlerspezifischen Token/eine händlerspezifische Karte nutzen; (4) kontoübergreifende Kontakt-/Werbepersonalisierung deaktivieren; (5) verschlüsseltes Controller-Ledger führen; (6) Kennungen nach Ende von Rückerstattungs-/Aufbewahrungspflichten stilllegen.

**Erkennung:** Provider verbinden Recovery, Gerät, Funding und IP; Händler verbinden Lieferung, Browser und Kontoverhalten. Legitimes Compartmentation von Synthetic-Identity-Fraud unterscheiden.

## Controlled red-team procurement

**Mechanik:** Das SOC kennt einen Kauf nicht, während ein Exercise Controller rechtliche Einheit, Operator und Infrastruktur zuordnet.

**Vorteile:** Realistische Detection-Übung; keine persönliche Offenlegung; sofortige Deconfliction und Audit.

**Nachteile:** Nicht anonym gegenüber Organisation/Provider; Governance-Aufwand; Leaks bei fehlerhafter Behandlung des Controller-Ledgers.

**Ablauf:** (1) engagement-spezifische Organisationskarte/-Wallet/-Budget zuweisen; (2) Käufer-/Operatorrollen trennen; (3) Asset, Betrag, Service, Zweck und Kill Date dokumentieren; (4) Zuordnung mit beschränktem Controllerzugriff speichern; (5) niemals falsche Identität/Mule/gestohlene Mittel verwenden; (6) Indikatoren und Rückerstattungen beim Abschluss offenlegen/abgleichen.

**Erkennung:** Controller verbindet Providerrechnung und Asset; SOC testet unabhängige Erkennung über Domain, Zertifikat, Hosting und Traffic statt über Karteninhaberdaten.

## Bitcoin address hygiene and coin control

**Mechanik:** Neue Empfangsadressen, lokale Labels und selektives UTXO-Spending reduzieren Address Reuse und versehentliches Zusammenführen von Compartments auf einem öffentlichen Ledger.

**Vorteile:** Breit unterstützt; Self-custodial; vermeidet einfachste öffentliche Verknüpfungen.

**Nachteile:** Alle Transaktionen/Beträge bleiben öffentlich; Common-Input-/Change-/Timing- und spätere Consolidation-Analysen verbinden Aktivitäten; Acquisition-/RPC-/Netzwerkdaten bleiben.

**Ablauf:** (1) gepflegte Wallet installieren/verifizieren; (2) Seed- Wiederherstellung sichern und testen; (3) neue Adresse je Rechnung verwenden; (4) Quelle/Zweck lokal labeln; (5) Coin Control verwenden, um Kontexte nicht zu verbinden; (6) Local Node oder Privacy-aware Connection bevorzugen; (7) Change/Gebühren prüfen und rechtmäßige Buchhaltung führen.<sup>[[3]](#references)</sup>

**Erkennung:** Adressgraph, Common-Input-/Change-Heuristiken mit Unsicherheit, exakter Betrag/Zeit, Consolidation, Service Deposits, Node/RPC-Broadcast-Zeit und Off-Chain-Daten.

## Bitcoin Silent Payments

**Mechanik:** BIP 352 erlaubt dem Empfänger, einen statischen Code zu veröffentlichen, während Sender über ECDH eindeutige Taproot-Outputs ableiten; Außenstehende können Outputs nicht direkt mit dem Code verbinden.<sup>[[4]](#references)</sup>

**Vorteile:** Wiederverwendbare öffentliche Kennung ohne Address Reuse; keine interaktive Adressanforderung oder Notification-Output; fügt sich in Taproot-Outputs ein.

**Nachteile:** Scanaufwand beim Empfänger; Wallet-Support variiert; Betrag/Sendergraph und Spending bleiben öffentlich; Indexserver kann Scans beobachten.

**Ablauf:** (1) aktuelle BIP-352-Wallet auswählen; (2) Descriptor und Scan-Recovery sichern/testen; (3) unterstützten Code labeln; (4) veröffentlichten Code authentisieren; (5) Sender prüft Inputs und sendet kleinen Test; (6) Empfänger scannt möglichst über eigenen Node; (7) empfangene UTXOs getrennt halten.

**Erkennung:** Aus dem Output allein absichtlich nicht zuverlässig erkennbar; Analysten nutzen Senderinputs, Betrag/Zeit, spätere Ausgaben, Wallet/Netzwerk/Index und Gegenparteidaten.

## PayJoin

**Mechanik:** Zahler und Zahlungsempfänger steuern Inputs zu einer Zahlungstransaktion bei und brechen dadurch die Annahme, dass alle Inputs einem Besitzer gehören.<sup>[[5]](#references)</sup>

**Vorteile:** Gewöhnliche Zahlung mit besserer Privacy; schwächt eine verbreitete Heuristik im gesamten Graph; kein Equal-Output-Crowd erforderlich.

**Nachteile:** Interaktion/Support nötig; Verfügbarkeit des Empfängerendpunkts; Betrag und finale Transaktion öffentlich; Implementierungs- und Fallback-Metadaten.

**Ablauf:** (1) bestätigen, dass beide gepflegten Wallets dieselbe PayJoin-Version unterstützen; (2) Rechnung/Endpunkt authentisieren; (3) über die PayJoin-fähige Payment URI der Wallet starten; (4) finalen Betrag/Gebühr prüfen und nur erwartete Inputs signieren; (5) keine manuelle Transaction Surgery; (6) Broadcast und Empfang prüfen; (7) Fallback dokumentieren, falls Negotiation scheitert.

**Erkennung:** Blockchain-Analysten dürfen Common-Input-Clustering nicht erzwingen; Endpunkt/Provider kann Negotiation protokollieren; Wallet-/Netzwerk- und spätere Spending-Beweise statt alleiniger Transaktionsform nutzen.

## CoinJoin

**Mechanik:** Mehrere Teilnehmer erzeugen kollaborativ eine Transaktion mit vielen Inputs/Outputs, häufig gleichen Stückelungen, wodurch die Zuordnung von Inputs zu Outputs unklarer wird.

**Vorteile:** Größere On-Chain-Mehrdeutigkeit; Self-custodial Designs vorhanden; messbare Round-Struktur.

**Nachteile:** Coordinator-/Peer-/Netzwerkmetadaten; Gebühren/Liquidität; erkennbare Transaktionsform; Toxic Change und spätere Consolidation zerstören Gewinne; rechtliche/providerseitige Verfügbarkeit variiert.

**Ablauf:** (1) aktuelle Wallet-/Coordinator-Verfügbarkeit und Rechtmäßigkeit prüfen; (2) offizielle Wallet installieren und sichern; (3) nur rechtmäßige UTXOs verwenden; (4) Stückelung, Gebühren und Coordinatormodell verstehen; (5) Change und gemischte Outputs labeln/trennen; (6) nie zusammenführen; (7) Netzwerktraffic gemäß offizieller Unterstützung routen und Buchhaltung bewahren.

**Erkennung:** Kollaborative Struktur erkennen, ohne Kriminalität anzunehmen; mögliche Mappings/Anonymity Set berechnen und anschließend Change/Consolidation, Servicegrenzen sowie Netzwerk-/Coordinator-Daten überwachen.

## Lightning Network

**Mechanik:** HTLC-Zahlungen laufen durch onion-geroutete Channels; die meisten Zahlungsdetails werden nicht on-chain veröffentlicht, während Funding/Closing und öffentliche Channelinformationen sichtbar sind.

**Vorteile:** Schnell, geringe Gebühren; Intermediäre sehen normalerweise benachbarte Hops; normale Zahlungsdetails bleiben Off-Chain.

**Nachteile:** Sender/Empfänger und erster/letzter Hop wissen mehr; Probing, Timing, Channelgraph, Liquidität sowie Wallet-/LSP-Daten; Custodial Wallets identifizieren Nutzer.

**Ablauf:** (1) Self-custodial oder Custodial bewusst wählen; (2) Wallet/Seed/Channel-Recovery prüfen; (3) Invoice für exakte Zahlung verwenden; (4) Private Channels/LSP-Funktionen erst nach Prüfung der Trade-offs bevorzugen; (5) Node-IP bei Bedarf mit unterstütztem Tor schützen; (6) identifizierende Invoices nicht wiederverwenden; (7) Channel- und Payment-Buchhaltung führen.<sup>[[6]](#references)</sup>

**Erkennung:** Node-/LSP-/Custodian-Logs, Channelgraph/Probes, Payment Failure/Timing und On-Chain-Funding/Closing; keine öffentliche Transaktion bedeutet nicht keine Datensätze.

## BOLT 12 Offers und Route Blinding

**Mechanik:** Ein wiederverwendbares Offer erzeugt frische Invoices und kann Blinded Paths bekanntgeben, sodass der Zahler den eindeutigen Node/Pfad des Empfängers nicht erfahren muss.

**Vorteile:** Empfänger-Privacy; wiederverwendbarer Zahlungs-/Spendenendpunkt ohne statische Invoice; Integration in Lightning Onion Routing.

**Nachteile:** Wallet-Support variiert; Endpunkte, ausgewählte Hops und Funding bleiben; öffentliche Kontaktdaten oder Netzwerkendpunkt können den Empfänger reidentifizieren.

**Ablauf:** (1) kompatiblen BOLT-12-Support bestätigen; (2) Offer authentisieren; (3) frische Invoice anfordern; (4) Betrag/Issuer/Recurring prüfen; (5) über Wallet bezahlen; (6) Empfang/Rückerstattung prüfen; (7) Node-Alias/Kontakt minimieren und Buchhaltung führen.<sup>[[7]](#references)</sup>

**Erkennung:** Wallet-/LSP- und erster/letzter-Hop-Telemetrie, Offer-Verteilkonto, Timing/Wert und Fundinggraph; Route Blinding begrenzt absichtlich die Sicht des Zahlers.

## Monero

**Mechanik:** One-time Stealth Addresses verbergen Empfängerverknüpfungen, RingCT verbirgt Beträge und Ring Signatures erzeugen Sendermehrdeutigkeit.

**Vorteile:** Privacy ist on-chain standardmäßig aktiviert; Vertraulichkeit von Sender/Empfänger/Betrag; ausgereiftes Wallet-/Node-Ökosystem.

**Nachteile:** Acquisition/Off-ramp sowie Endpoint-/Netzwerk-/Gegenparteidaten; Remote Node sieht Abfragen/IP; Exchange-Support und rechtliche Behandlung variieren; kleine Bedienfehler verbinden Kontexte dennoch.

**Ablauf:** (1) rechtmäßig beschaffen und Grundlage/Quelle dokumentieren; (2) offizielle gepflegte Wallet installieren/verifizieren; (3) Seed sichern/testen; (4) Local Node oder dokumentierten Tor-/I2P-Remote-Node-Pfad verwenden; (5) neue Subadresse je Zahler/Invoice verwenden; (6) Kontexte lokal labeln; (7) Transaction Proof/View Access nur bewusst offenlegen.<sup>[[8]](#references)</sup>

**Erkennung:** Auf Exchange-/Händler-/Geräte-/Netzwerk- und beschlagnahmte Wallet-Daten konzentrieren; Protokollnutzung allein ist nicht verdächtig und die Public Chain offenbart absichtlich weniger.

## Zcash vollständig shielded Orchard

**Mechanik:** Zero-Knowledge-Proofs validieren Shielded Transfers, während Sender, Empfänger und Betrag verschlüsselt sind; transparente Pools und Poolübergänge bleiben öffentlich.

**Vorteile:** Starke Shielded-On-Chain-Vertraulichkeit; Viewing Keys können begrenztes Audit ermöglichen; protokollerzwungene Gültigkeit.

**Nachteile:** Wallet-/Exchange-Support und tatsächliche Poolwahl variieren; Timing-/Wertkorrelation transparenter Grenzen; Netzwerk/RPC und Endpunkt bleiben.

**Ablauf:** (1) gepflegte Orchard-Shielded-by-Default-Wallet auswählen; (2) verifizieren/sichern; (3) ZEC rechtmäßig beschaffen; (4) an unterstützte Unified Address empfangen und Pool bestätigen; (5) Shielded-to-Shielded bevorzugen; (6) unterstützte Netzwerk-Privacy verwenden; (7) Offenlegung eines Viewing Keys vor Audit mit kleiner Wallet testen.<sup>[[9]](#references)</sup>

**Erkennung:** Transparente Grenzen und Servicedaten, Wallet-/Netzwerkmetadaten sowie rechtmäßig bereitgestellte Viewing Keys; nicht annehmen, dass alle Unified-Address-Zahlungen shielded waren.

## Mimblewimble und Litecoin MWEB

**Mechanik:** Confidential Transactions verbergen Beträge, und Mimblewimble-artige Aggregation entfernt konventionelle adressenreiche Historie; Litecoin implementiert einen optionalen Extension Block neben seiner transparenten Chain.

**Vorteile:** Vertrauliche Beträge und bessere Fungibilität im privaten Bereich; effizientes Pruning/Aggregation.

**Nachteile:** Opt-in-Grenze Peg-in/Peg-out ist öffentlich und korrelierbar; Wallet-/Exchange-Support; Unterschiede bei Interaktion/Adressmodell; Netzwerk- und Acquisition-Daten.

**Ablauf:** (1) gepflegte Wallet mit explizitem MWEB-Support wählen; (2) verifizieren/sichern und kleinen Betrag testen; (3) rechtmäßig beschaffen; (4) in MWEB pegen und Balance-Domain prüfen; (5) nur mit kompatiblem Empfänger handeln; (6) unmittelbaren markanten Peg-out vermeiden; (7) private Auditdaten behalten.<sup>[[10]](#references)</sup>

**Erkennung:** Öffentliches Peg-in/out-Timing/-Wert, Exchange-/Wallet-/Node-Daten und spätere transparente Ausgaben; interne Confidential Transfers reduzieren Details absichtlich.

## Ethereum Zero-Knowledge Privacy Applications

**Mechanik:** Ein Circuit beweist eine Aussage – etwa Membership, gültiges Note Ownership oder Autorisierung – ohne das Geheimnis offenzulegen; ein Verifier Contract prüft sie. Deposits, Withdrawals, Public Inputs, Events und Gas können weiterhin Verknüpfungen offenlegen.

**Vorteile:** Programmierbare selektive Offenlegung; anonyme Sets; überprüfbare Regeln ohne vollständige Datenoffenlegung.

**Nachteile:** Contract-/Circuit-Bugs; kleines Anonymity Set; öffentliche Grenzen; RPC/IP/Session/Analytics/Gas-Funding; anwendungs- und sanktionsrechtliche Risiken.

**Ablauf:** (1) genau definieren, was der Proof verbirgt; (2) rechtmäßig eine auditierte gepflegte Anwendung verwenden; (3) Public Inputs/Events und Deposit-/Withdrawal-Regeln prüfen; (4) Action Wallet und Gas Sponsorship nach Protokollabsicht trennen; (5) Privacy-aware RPC/Netzwerkpfad verwenden; (6) kleinen Wert testen; (7) Compliance-Daten aufbewahren.<sup>[[11]](#references)</sup>

**Erkennung:** Contract Events, Deposit-/Withdrawal-Timing/-Wert, Relayer/Paymaster, RPC/Session, Frontend Storage/Analytics und spätere Exchange-/Händlergrenze. Der ZK-Proof verbirgt keine als öffentlich deklarierten Felder.

## Stablecoins

**Mechanik:** Tokens werden auf einer Public Chain übertragen; zentralisierte Issuer können einfrieren/blacklisten oder gegen identifizierte Konten einlösen.

**Vorteile:** Preisstabilität, Liquidität und Händlerunterstützung; schnelles Settlement; einfache Buchhaltung.

**Nachteile:** Transparenter Address-/Betrags-/Contractgraph; Gas Funding; Issuer- und Exchange-Identität/Control; Sanktionsprüfung; im Allgemeinen schlechte Anonymität.

**Ablauf:** Als identifizierte Zahlung behandeln: frische Geschäftsadresse nur zur Segmentierung verwenden, Token Contract/Netzwerk prüfen, kleinen Betrag testen, Wallet schützen, vertrauenswürdigen RPC/Local Node verwenden, Basis/Quelle dokumentieren und erforderliche Parteien prüfen.

**Erkennung:** Vollständiger Token-Eventgraph, Issuer-Freeze-Listen/-Aktionen, Exchange/RPC/Gerät und Gas-Funding-Beziehungen.

## Cashu Chaumian E-Cash

**Mechanik:** Eine Mint signiert vom Client erzeugte Bearer Secrets blind, die durch Bitcoin-/Lightning-Reserven gedeckt sind; Double Spend kann verhindert werden, ohne Ausstellung direkt mit späterer Einlösung zu verbinden.

**Vorteile:** Kontolose Bearer Tokens; sofortiger Peer-Transfer; Mint kann blinded Withdrawal nicht direkt mit Spend verbinden; Tokens können als Daten/QR übertragen werden.

**Nachteile:** Mint-Custody/Solvency/Censorship; Verlust/Diebstahl von Bearer-Daten; Stückelung/Timing und Lightning-Grenzen; Netzwerkmetadaten; frühes Softwareökosystem.<sup>[[12]](#references)</sup>

**Ablauf:** (1) zuerst offizielle Test-Mint oder sehr kleinen Wegwerfwert verwenden; (2) gepflegte Wallet installieren und Backup-/Restore-Limits testen; (3) Mint authentisieren und Custody/Gebühren prüfen; (4) kleine Menge minten; (5) Token über authentisierten privaten Kanal/QR senden; (6) Empfänger Token vor Finalität swappen; (7) einlösen und abgleichen. Niemals bedeutenden Wert in einer nicht vertrauenswürdigen Mint halten.

**Erkennung:** Mint sieht Netzwerk sowie Issue-/Redeem-/Lightning-Grenzen und ausgegebene Tokens, aber Blinding entfernt direkte Tokenverknüpfung; Endpunkte/Nachrichten und markanter Betrag/Zeit können Links wiederherstellen.

## Fedimint Federated E-Cash

**Mechanik:** Ein Threshold von Guardians hält Reserven und signiert E-Cash blind; interne Bearer Transfers bleiben vor Guardians verborgen, während Lightning Gateways externe Zahlungen verbinden.

**Vorteile:** Verteilte Custody; private interne Transfers; Community Governance; kein einzelner Guardian kontrolliert unterhalb des Thresholds die Reserve.

**Nachteile:** Guardian-Quorum/Custody/Software-Risiko; Gateway sieht Invoices/Timing; Deposit-/Withdrawal-Grenzen; komplexe Wiederherstellung des Clientzustands.

**Ablauf:** (1) Federation Invite, Guardians, Quorum und Rechtsordnung prüfen; (2) gepflegten Client installieren und Recovery testen; (3) kleinen rechtmäßigen Betrag einzahlen; (4) frische interne Payment Requests nutzen; (5) Gateway als Lightning-Beobachter behandeln; (6) Einlösung testen; (7) Quellen-/Steuerdaten außerhalb öffentlicher Zahlungsdaten behalten.<sup>[[13]](#references)</sup>

**Erkennung:** Federation sieht aggregierte Ausgabe/Einlösung, Gateways sehen externe Invoices, Bitcoin/Lightning zeigen Grenzen; Endpunkt-/Kommunikationsdaten können interne Transfers verbinden.

## GNU Taler

**Mechanik:** Bankintegriertes Blind-Signature-E-Cash soll den Zahler gegenüber Händlern anonym halten, während Händler und Einnahmen rechenschaftspflichtig bleiben.

**Vorteile:** Payer Privacy by Design; gewöhnliche Währung; Händlerverantwortung/Rückerstattungen; kein spekulativer Token erforderlich.

**Nachteile:** Begrenzte Deployments; Exchange/Bank sehen Funding; Händler sieht Bestellung/Zustellung; Bearer-/Recovery-Risiko der Wallet; regulierte Betreiber.

**Ablauf:** (1) aktuelle Exchange-/Händlerunterstützung für Region/Währung finden; (2) KYC/Gebühren/Privacy lesen; (3) offizielle Wallet installieren; (4) rechtmäßig über unterstützte Bank/Exchange abheben; (5) Händlervertrag prüfen; (6) bezahlen und Beleg-/Rückerstattungsdaten aufbewahren; (7) unnötige Händler-Session-Kennungen vermeiden.<sup>[[14]](#references)</sup>

**Erkennung:** Bank-/Exchange-Withdrawal und Händlerdeposit sind nachvollziehbare Grenzen; Händlerbestellung/Gerät/Zustellung und Timing können trotz Blinding korrelieren.

## Cross-chain Bridge, Atomic Swap und Decentralized Exchange

**Mechanik:** Ein Contract/Service sperrt/burnt ein Asset und gibt/mintet ein anderes aus, oder Gegenparteien tauschen atomar. Die wirtschaftliche Kontinuität wird nicht aufgehoben.

**Vorteile:** Asset-/Netzwerkinteroperabilität; kann einen zentralen Custodian vermeiden; gewöhnliche Portfolio-/Liquiditätsnutzung.

**Nachteile:** Beide Chains sind öffentlich; Zeit/Wert/Gebühren/Liquidität und Contracts korrelieren; Bridge-/Relayer-/Frontend-/RPC-Daten; Smart-Contract-/Gegenparteien- und regulatorisches Risiko.

**Ablauf für rechtmäßige Swaps:** (1) offiziellen Contract/Service und rechtliche Verfügbarkeit prüfen; (2) Custody/Audit/Gebühren/Slippage prüfen; (3) kleinen Test durchführen; (4) beide Transaction IDs und Rate dokumentieren; (5) Approvals schützen; (6) Zielasset abgleichen und unnötige Approvals widerrufen. Swaps nicht zum Verschleiern der Mittelherkunft verwenden.

**Erkennung:** Bridge-Deposit-/Withdrawal-Events, eindeutiger Betrag abzüglich Gebühren, zeitliche Reihenfolge, Liquidität, Relayer/RPC/Frontend und spätere Service Deposits.

## Centralized Mixer oder Tumbler

**Mechanik:** Ein Service empfängt Deposits in einem Pool und gibt später andere Einheiten zurück, um direkte Input-Output-Zuordnung zu verschleiern.

**Vorteile:** Kann theoretisch Transaktionsmehrdeutigkeit erhöhen.

**Nachteile:** Betreiber kann stehlen/protokollieren; Entry-/Exit-Timing-/Wertanalyse; Sanktions-/Geldtransfer- und Strafrisiko; Beschlagnahmung kann Mappings offenlegen; Taint-/Ablehnungsrisiko.

**Ablauf:** Es wird keine operative Mixing-Anleitung bereitgestellt. Den Graphen sicher reproduzieren, indem [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) erweitert wird: synthetische Deposits, Pool-Outputs, Gebühren und Verzögerungen erzeugen; Analysten unvollständige Mappings geben; funktionierende Heuristiken messen; danach Ground Truth offenlegen.

**Erkennung:** Service-Wallet-/Contract-Identifikation, Entry-/Exit-Kandidaten, Betrag/Gebühr/Timing, Deposit-Address-Reuse, beschlagnahmte/providerseitige Logs und nachgelagerte Consolidation. Probabilistische Attribution kennzeichnen.

## Peel Chains, Fan-out/Fan-in und Structuring

**Mechanik:** Wiederholte Transaktionen ziehen kleine Zahlungen aus Change ab, teilen Wert auf viele Adressen auf, führen Sammler wieder zusammen oder teilen Beträge zur Vermeidung von Prüfungen.

**Vorteile:** Erhöht den Aufwand naiver Analysten und die Adressanzahl.

**Nachteile:** Erkennbare Wert-/Takt-/Transaktionskontinuität; Consolidation und Serviceendpunkte; Structuring kann selbst illegal sein; Gebühren und Bedienfehler.

**Ablauf:** Nur synthetische CSV-/Testnet-Daten verwenden: große Quelle, wiederholte Payment-/Change-Kanten, parallele Zweige und einen Collector erzeugen; harmlose exchangeartige Beispiele hinzufügen; Detection abstimmen und False Positives dokumentieren.

**Erkennung:** Graphkontinuität, wiederholtes Change-Muster, Taktung, Beträge knapp unter Kontrollen, gemeinsamer Serviceendpunkt und Off-Chain-Daten. Exchange-Hot-Wallets können ähnlich aussehen; Kontext ist zwingend.<sup>[[15]](#references)</sup>

## Nominee, Money Mule, OTC Broker und Front Company

**Mechanik:** Eine andere Person/ein anderes Konto/eine andere Gesellschaft empfängt, konvertiert oder verwendet Gelder und fügt rechtliche/operative Ebenen zwischen Controller und Transaktion ein.

**Vorteile für einen Angreifer:** Benanntes Konto identifiziert den Controller nicht sofort; kann Bargeld, Crypto, Waren und Rechtsordnungen verbinden.

**Nachteile:** Risiko von Identitätsbetrug/Geldwäsche; jeder Beteiligte erzeugt Kommunikations-, Bank-, Firmen-, Steuer- und Versanddaten, Gebühren, Widersprüche und Zeugen; wiederverwendete Helfer schaffen Hubs.

**Ablauf:** Nicht mit realen Personen/Konten nachbilden. Synthetischen Graphen mit Controller, Recruiter, Mule, OTC, Shell Merchant und Beneficiary erstellen; Geräte-/IP-/Nachrichten-/Bankkanten einfügen; Ermittler den Kontoinhaber vom Controller unterscheiden und Beweissicherheit dokumentieren lassen.

**Erkennung:** Gemeinsames Gerät/IP/Recovery, ungewöhnlicher Begünstigter/Velocity, viele unabhängige Sender, sofortige Weiterbewegung, Firmen-/Direktoren-/Rechnungswidersprüche, Kommunikation und Bargeld-/Warenlieferung.

## NFTs, Gambling, Händlerwaren und Refund Loops

**Mechanik:** Wert wird in ein selbstbewertetes Asset, Wettguthaben, weiterverkaufbare Waren oder Rückerstattungen konvertiert, um eine andere Transaktionsdarstellung zu schaffen.

**Vorteile für einen Angreifer:** Ändert die Assetform und fügt Marketplace-/Händlerintermediäre ein.

**Nachteile:** Marketplace-/Konto-/Geräte- und Wash-Trade-Graph; Odds-/Play- und Rückerstattungsdaten; Liefer-/Wiederverkaufsbeweise; Gebühren/Verluste; Fraud-/Laundering-Haftung.

**Ablauf:** Kein Concealment-Workflow. Synthetische Marktplatzdaten mit Self-Trades verwandter Wallets, unrealistischen Preisen, minimalem Spiel, unpassendem Rückerstattungsinstrument und gemeinsamer Lieferung verwenden; Detection gegen legitime Sammler/Kunden validieren.

**Erkennung:** Zirkuläre/Self-funded Trades, gemeinsame Ownership/Funding, Preis-Ausreißer, sofortiger Wiederverkauf/Rückerstattung, minimale wirtschaftliche Aktivität, gemeinsames Gerät/Lieferung und erneute Konvergenz der Erlöse.

## Physical Bearer Wallet oder Offline Token Transfer

**Mechanik:** Ein Gerät, Papier/QR, Hardware-Bearer-Instrument oder E-Cash-Token überträgt die Kontrolle über ein Secret, statt bei der Übergabe eine Zahlung zu broadcasten.

**Vorteile:** Kein Live-Netzwerkereignis während des Austauschs; offline nutzbar; physische cashartige Custody.

**Nachteile:** Kopie/Diebstahl/Verlust und unsichere Exklusivität; spätere Einlösung/Broadcast verknüpft; persönliches Treffen/Versand; Fälschungs-/Manipulationsrisiko.

**Ablauf:** (1) nur geprüftes Instrument/Protokoll verwenden; (2) Authentizität privat initialisieren/verifizieren; (3) nur kleinen rechtmäßigen Wert laden; (4) in dokumentiertem autorisiertem Kontext übertragen; (5) Empfänger verifiziert oder sweeped zeitnah gemäß Protokoll; (6) nie annehmen, dass Sender keine Kopie behalten hat; (7) Eigentums-/Steuernachweise privat dokumentieren.

**Erkennung:** Kauf/Funding und spätere Sweep-/Redemption-Daten, Geräteseriennummer/Manipulationsbeweise, Liefer-/Treff- und Endpunktdaten.

## Merchant-scoped Invoice oder einmalige Payment Request

**Mechanik:** Der Händler erzeugt eine einmalige Request mit Betrag, Ablauf und Order Reference. Der Zahler begleicht sie über ein unterstütztes Rail, ohne dem Händler direkt ein wiederverwendbares Credential zu geben; Issuer/Processor können weiterhin beide Parteien identifizieren.

**Vorteile:** Begrenzt Credential-Reuse und versehentliche Cross-Merchant-Kennungen; exakter Betrag/Ablauf reduzieren Fehler; kompatibel mit normaler Buchhaltung und Rückerstattungen.

**Nachteile:** Invoice, Lieferung, Browser, Processor und Issuer verbinden die Bestellung weiterhin; eindeutiger Betrag/Zeit kann Korrelation verstärken; bösartige Payment Links sind häufig.

**Ablauf:** (1) Händler unabhängig authentisieren; (2) frische Invoice mit exaktem Betrag, Asset/Netzwerk und Ablauf anfordern; (3) Ziel und Rückerstattungsregeln prüfen; (4) aus dem genehmigten Engagement-Compartment zahlen; (5) bestätigen, dass Händler dieselbe Invoice akzeptiert; (6) Beleg und Transaction Reference aufbewahren; (7) Request ablaufen lassen statt wiederzuverwenden.

**Erkennung:** Händler/Processor verbinden Invoice, Session und Settlement; eindeutige Beträge/Zeiten und Lieferung identifizieren den Zahler. **Captured Wallet/Device:** Invoice-Historie offenbart Gegenparteien und Zweck; unnötige Memo-Daten minimieren, Gerät verschlüsseln und maßgebliche Buchhaltung im kontrollierten Finanzsystem führen.

## Prepaid Service Credit und Capability Token

**Mechanik:** Ein Service wandelt eine konventionelle Zahlung in begrenzte interne Credits oder eine Bearer Capability um. Nachfolgende API-/Ressourcennutzung kann die ursprüngliche Karte nicht bei jeder Anfrage präsentieren; der Service kann Ausstellung und Einlösung jedoch häufig verbinden.

**Vorteile:** Begrenzt Ausgaben und Kompromittierungsverlust; trennt tägliche Operatoren vom Funding-Credential; unterstützt Projektbudgets und Revocation.

**Nachteile:** Meist pseudonym, nicht anonym; Service-Datenbank, Redemption-IP und eindeutige Nutzungsmuster verbinden Aktivitäten; Bearer Tokens können gestohlen werden; Rückerstattungen können den ursprünglichen Zahler erfordern.

**Ablauf:** (1) Credits über Organisationskonto kaufen; (2) ein Projekt und Budget erstellen; (3) eng begrenzten Token mit Service-, Betrags- und Ablaufrestriktionen ausstellen; (4) nur im genehmigten Secret Manager oder Workload-Identity-Pfad speichern; (5) Ablehnung außerhalb des Scopes/nach Ablauf testen; (6) Verbrauch überwachen; (7) widerrufen und ungenutzten Wert abgleichen.

**Erkennung:** Provider verbindet Fundingkonto, Projekt, Tokenausgabe und Nutzung; bei geografischen/Prozessänderungen und anomalem Verbrauch alarmieren. **Captured Node:** verbleibende Capability als nutzbar annehmen; kurze Laufzeit, niedriges Guthaben, Audience Binding und sofortige serverseitige Revocation verwenden.

## Privacy Pass oder Blinded Authorization Token

**Mechanik:** Ein Issuer erzeugt ein Privacy-preserving Authorization Token, das ein Origin ohne Verknüpfung der Einlösung mit der Ausstellung validieren kann. Es kann bezahlte Berechtigung oder rate-limited access darstellen, ist aber keine allgemeine Währung. Die Architektur trennt Client-, Attester-, Issuer- und Origin-Rollen und warnt, dass IP/Timing oder Kollusion Unlinkability aufheben können.<sup>[[18]](#references)</sup>

**Vorteile:** Unlinkable Redemption für unterstützte Services; kein wiederverwendbares Account-Cookie beim Origin; gecachte Tokens können Ausstellung und Nutzung zeitlich trennen.

**Nachteile:** Anwendungsspezifisch; Vertrauen in Issuer/Attester und Aufteilung des Anonymity Set; IP- und Browsermetadaten bleiben; Token-Diebstahl oder markantes Ausstellungs-Timing kann Nutzung korrelieren.

**Ablauf:** (1) Implementierung gemäß relevanter Privacy-Pass-Tokenart verwenden; (2) genau definieren, welche Berechtigung der Token beweist; (3) Issuer- und Origin-Administration trennen, wenn das Threat Model dies erfordert; (4) Challenge-Metadaten minimieren; (5) mehrere Testtokens ausstellen und jeweils einmal bei eigenen Origins einlösen; (6) Logs auf verbotene stabile Kennungen vergleichen; (7) Replay-, Ablauf- und Revocation-/Abuse-Kontrollen testen.

**Erkennung:** Origins sehen Redemption-IP/Zeit und Tokenvalidität; Issuer/Attester sehen Ausstellungskontext; Analysten testen Timing und Metadatenpartitionen, ohne einen kryptografischen Bruch anzunehmen. **Captured Client:** ungenutzte Bearer Tokens können nutzbar sein; Wert, Lebensdauer und Audience begrenzen und Funding-Credential niemals mit ihnen cachen.

## Delegated Organization Procurement oder Fiscal Sponsor

**Mechanik:** Ein autorisiertes Beschaffungsteam, Reseller oder Fiscal Sponsor kontrahiert und bezahlt, während das operative Team einen begrenzten Service erhält. Dies ist Rollentrennung mit wahrheitsgemäßen Daten, kein Nominee oder falsche Identität.

**Vorteile:** Vendor muss nicht die Identität jedes Operators oder persönliche Zahlungsdaten erhalten; zentrale Compliance-, Steuer- und Rückerstattungsabwicklung; klares Budget und Offboarding.

**Nachteile:** Sponsor kennt Begünstigten und Zweck; Verträge, Freigaben, Lieferung und Konten bleiben; zusätzlicher Aufwand/Gebühren; schwache Trennung, wenn dieselbe Person jede Ebene verwaltet.

**Ablauf:** (1) Geschäftszweck, Begünstigten und Genehmigungsbefugnis dokumentieren; (2) organisationsgenehmigten Intermediär wählen; (3) unter wahrheitsgemäßen Daten kontrahieren; (4) projektspezifisches Subkonto ohne persönliche Billing-Credentials bereitstellen; (5) Finanzadministratoren und Operatoren trennen; (6) Rechnungen und Zugriff abgleichen; (7) Service und delegierten Zugriff beim Abschluss beenden.

**Erkennung:** Beschaffungs-, Identity-Provider-, Vendor- und Lieferdaten verbinden die Kette. **Captured Operational Device:** sollte das Serviceprojekt, aber keine Finance-Credentials offenlegen; Rechnungen und Zahleridentitäten im Finanzsystem, nicht auf Field Nodes speichern.

## Escrow oder Conditional Settlement

**Mechanik:** Ein vertrauenswürdiger Escrow Agent oder Smart Contract hält Wert, bis dokumentierte Bedingungen erfüllt sind. Direkte Offenlegung zwischen Zahler und Zahlungsempfänger kann sinken, Escrow und zugrunde liegende Rails behalten die Beziehung jedoch.

**Vorteile:** Streit- und Lieferschutz; Zahler und Händler müssen einander weniger wiederverwendbare Credentials geben; auditierbare Freigabebedingungen.

**Nachteile:** Escrow-Custody-/Contract-Risiko, Gebühren und Identitätspflichten; On-Chain-Contracts sind öffentlich; Bestell-, Versand- und Streitdaten bleiben; nicht anonym gegenüber dem Intermediär.

**Ablauf:** (1) Rechtsträger, Custody, Gebühren, Streitforum und unterstützte Assets prüfen; (2) exakten schriftlichen Meilenstein und Refund-Pfad erstellen; (3) aus genehmigtem Organisationskonto finanzieren; (4) Empfang und Freigabe unabhängig prüfen; (5) nur nach Beweis freigeben; (6) vollständigen Auditdatensatz aufbewahren; (7) ungenutzte Berechtigungen/Contract Approvals schließen.

**Erkennung:** Escrowkonto-/Contract-Events, Funding-/Freigabezeit, Begünstigten- und Streitdaten offenbaren Transaktion. **Captured Device:** Session Tokens oder Contract Approvals können Freigabe erlauben; separaten Approver/MFA verlangen und aktive Sessions bei Verlust widerrufen.

## Batched oder Pooled Organization Settlement

**Mechanik:** Viele genehmigte Verpflichtungen werden aggregiert und in weniger Bank-/Blockchain-Transaktionen beglichen; ein privater interner Ledger ordnet Anteile zu. Batching kann öffentliche Details je Kauf reduzieren, der Coordinator behält jedoch vollständige Attribution.

**Vorteile:** Geringere Gebühren; weniger öffentliche Graphkanten; einzelne Positionen für öffentliche Beobachter verborgen, wenn Beträge aggregiert werden; einfache interne Buchhaltung.

**Nachteile:** Coordinator ist vollständiger Beobachter und wertvolles Ziel; markante Summen/Zeiten können korrelieren; Custody-/Abgleichrisiko; Missbrauch kann wie Structuring wirken.

**Ablauf:** (1) Teilnehmer und rechtmäßige Verpflichtungen im Buchhaltungssystem definieren; (2) regelmäßiges geschäftlich begründetes Batch-Fenster statt kontrollvermeidender Schwellen setzen; (3) doppelte Genehmigung der Gesamtsumme verlangen; (4) an authentisierte Empfänger auszahlen; (5) jede interne Position dem Batch zuordnen; (6) Rückerstattungen als verknüpfte Korrekturen behandeln; (7) Ledgerzugriff schützen und richtliniengemäß aufbewahren.

**Erkennung:** Coordinator-Ledger sowie Freigabe- und Begünstigtendaten liefern Ground Truth; öffentliche Analysten nutzen Input-/Output-/Wert-/Zeit-Clustering vorsichtig. **Captured Payer Device:** sollte nur seine Requisition, nicht Pool-Signing-Key oder Teilnehmerledger enthalten.

## Account-abstraction Paymaster oder Sponsored Gas

**Mechanik:** Ein Relayer/Bundler übermittelt eine Smart-Account-Operation und ein Paymaster bezahlt Transaktionsgebühren, wodurch eine direkte Native-Gas-Funding-Kante von der User-Wallet entfällt. Eine Graph-Eigenschaft verbessert sich; Operation, Contract und Servicetelemetrie bleiben öffentlich/beobachtbar.<sup>[[19]](#references)</sup>

**Vorteile:** Entfernt häufige Gas-Funding-Verknüpfung; unterstützt begrenztes Sponsoring und Rate Limits; erleichtert legitime Privacy-Anwendungen.

**Nachteile:** Paymaster/Bundler/RPC/Frontend können Requests korrelieren; Contract Events und Public Inputs bleiben; Sponsoring Policy kann eine Gruppe fingerprinten; bösartige Contracts/Approvals können Assets stehlen.

**Ablauf:** (1) auditierte gepflegte Smart Account-/Paymaster-Lösung im korrekten Netzwerk verwenden; (2) öffentliche Felder und Sponsor-Logging prüfen; (3) Sponsoring nach Contract, Function, Betrag, Nonce und Ablauf begrenzen; (4) kleinen Wert testen; (5) über den vorgesehenen Privacy-aware Application Path senden; (6) Operation und Fee Payer on-chain prüfen; (7) Allowances/Session Keys widerrufen und Compliance-Daten behalten.

**Erkennung:** UserOperation, EntryPoint, Paymaster, Bundler/RPC und Application Logs verbinden; gleiche Sponsoring Policy vorsichtig clustern. **Captured Wallet:** Session Keys und ausstehende Approvals können auch ohne Gas nutzbar sein; eng begrenzen und gemäß Recovery Policy widerrufen.

## Threshold- oder Multisignature Payment Authorization

**Mechanik:** Spending erfordert einen Threshold unabhängiger Signer. Die Transaktion wird nicht verborgen, aber Payment Authority von kompromittiertem Laptop, Field Node oder einzelnem Operator getrennt.

**Vorteile:** Starker Schutz gegen Kompromittierung und Insider; nachvollziehbare Genehmigung; kein Field Device besitzt vollständige Signing Authority; Recovery-Unterstützung.

**Nachteile:** Koordination/Verfügbarkeit; Signer-/Geräte-/Kontometadaten können Teilnehmer korrelieren; schlechte Backups verursachen Verlust; öffentliche Multisig-Muster können erkennbar sein.

**Ablauf:** (1) Signer, Threshold, Limits und Recovery vor Funding definieren; (2) auf getrennten unterstützten Geräten/Konten initialisieren; (3) Adressen und Backups unabhängig prüfen; (4) Field Workloads nur unsignierte Requisitionen erlauben; (5) Empfänger, Betrag und Zweck Out-of-Band prüfen; (6) Recovery und Verlust eines Signers mit kleinem Wert testen; (7) kompromittierten Signer rotieren.

**Erkennung:** Approval-System, Signergerät und öffentliches Script/Contract liefern Beweise; bei Policy-/Signer-Set-Änderungen alarmieren. **Captured Node:** sollte höchstens einen Session Key mit niedriger Berechtigung oder unsignierte Request offenlegen; Quorum-Material nie gemeinsam cachen.

## Closed-loop Community- oder Event Currency

**Mechanik:** Eine Cooperative, Konferenz oder private Testumgebung gibt Credits aus, die nur unter eingeschriebenen Teilnehmern einlösbar sind. Interne Transfers können globale Zahlungsnetze weniger belasten, während der Operator Ausstellung und Einlösung kontrolliert.

**Vorteile:** Begrenzter Wirtschaftsraum; testbar für Offline- oder Privacy-preserving Payment UX; geringere externe Kartenoffenlegung; klare experimentelle Kontrollen.

**Nachteile:** Kleines Anonymity Set; Operator und Händler sehen Aktivitäten; begrenzte Akzeptanz/Einlösung; Lizenz-, Verbraucherschutz- und Steuerregeln können auch für lokale Werte gelten.

**Ablauf:** (1) rechtliche/compliance Prüfung durchführen und Issuer-Bedingungen veröffentlichen; (2) zustimmende Testteilnehmer aufnehmen; (3) Ausgabe begrenzen und Bargeldmissbrauch untersagen; (4) frische Payment Requests verwenden und öffentliche Teilnehmerkennungen minimieren; (5) aggregierte Reserven und private Einzelbelege dokumentieren; (6) Verlust/Rückerstattung/Einlösung testen; (7) Ledger schließen und Restwert wie versprochen zurückgeben.

**Erkennung:** Issuer-Ledger, Enrollment, Händler- und Einlösedaten rekonstruieren Flüsse; ungewöhnliche zirkuläre Transfers oder schnelle Auszahlungen prüfen. **Captured Wallet:** Lokalsaldo und Gegenparteien können offengelegt werden; Wert begrenzen, State verschlüsseln und Issuer-seitiges Freeze/Reissue mit Auditdatensatz unterstützen.

## Bitcoin Reusable Payment Codes und Private Payment Instructions

**Mechanik:** BIP 47 nutzt eine wiederverwendbare öffentliche Kennung plus ECDH-abgeleitete einmalige Deposit-Adressen; BIP 351 spezifiziert ein neueres Private-Payment-Instruction-Design. Beide reduzieren öffentliche Address Reuse und erlauben stabile veröffentlichte Zahlungsanweisungen. Notification, Wallet-Support, Funding und spätere Coin Selection beeinflussen Privacy weiterhin.<sup>[[20]](#references)</sup>

**Vorteile:** Eine öffentliche Instruction kann unterschiedliche Adressen erzeugen; Empfänger muss nicht jede Invoice-Adresse veröffentlichen; kompatible Wallets können abgeleitete Zahlungen überwachen; nützlich für wiederkehrende rechtmäßige Spender/Kunden.

**Nachteile:** Wallet-Interoperabilität variiert; Notification Transactions oder veröffentlichter Payment Code verbinden Beziehungskontext; Sender, Empfänger und Public Graph sehen Transaktionen weiterhin; unvorsichtige Consolidation/Change-Behandlung beseitigt den Vorteil.

**Ablauf:** (1) sicherstellen, dass beide gepflegten Wallets exakt dieselbe Spezifikation/Version unterstützen; (2) Recovery mit kleiner Wallet sichern/testen; (3) Empfänger-Payment-Code Out-of-Band authentisieren; (4) kleinen rechtmäßigen Test senden; (5) frische abgeleitete Adresse prüfen; (6) Beziehung lokal labeln und Coin Control einsetzen; (7) Recovery und Refund-Verhalten testen.

**Erkennung:** Analysten untersuchen Notification-Muster, Funding/Change, spätere Consolidation und Servicegrenzen; Veröffentlichung des Public Codes identifiziert den Empfängerkontext, auch wenn Deposit-Adressen variieren. **Capture-resilient OPSEC:** Spend Keys von Field Devices fernhalten und höchstens eine Watch-only-Beziehungsansicht bereitstellen. **Monitoring:** Bei unerwarteten Notification Transactions, wiederverwendeten Derived Addresses, Wallet-Gap-Limit-/Recovery-Fehlern und ungeplanter Consolidation alarmieren.

## EVM Stealth Addresses (ERC-5564)

**Mechanik:** Ein Sender leitet aus der Stealth Meta-address des Empfängers ein einmaliges Stealth Account ab und veröffentlicht eine Announcement mit ephemeral Public Key und View Tag. Der Empfänger scannt Announcements mit Viewing Key und leitet den zugehörigen Spend Key ab. Empfänger-Linkage verbessert sich, aber Sender, Betrag/Token, Gas, Announcement und spätere Ausgaben bleiben sichtbar.<sup>[[21]](#references)</sup>

**Vorteile:** Nicht-interaktive frische Empfängeradresse; wiederverwendbare Meta-address; getrennte Viewing-/Spending-Rollen; funktioniert für unterstützte EVM-Assets/Anwendungen.

**Nachteile:** Announcement-Scanning und Spam; Gas Funding der neuen Adresse kann sie relinken; Sender kennt Empfänger; öffentlicher Token/Betrag und spätere Consolidation bleiben; Implementierungs-/Wallet-Support variiert.

**Ablauf:** (1) auditierte gepflegte Implementierung zuerst in Testnet verwenden; (2) getrenntes Viewing-/Spending-Material erzeugen und sichern; (3) Meta-address authentisieren; (4) Low-value-Test und Announcement senden; (5) scannen und Stealth Account ableiten; (6) unterstütztes Gas Sponsorship ohne persönliche Funding-Kante testen; (7) öffentliche Felder und rechtmäßige Buchhaltung dokumentieren.

**Erkennung:** Announcement Caller, Token/Betrag, Timing, Gas Sponsor, Spending und Consolidation verfolgen; View Key kann Empfang beweisen, ohne Spending zu gewähren. **Capture-resilient OPSEC:** Ein vernetzter Scanner sollte, sofern unterstützt, nur die Viewing-Rolle besitzen; Spend- und Recovery Keys anderswo halten. **Monitoring:** Bei fehlerhaften/spamartigen Announcements, View-Key-Zugriff, unerwarteter Spend-Derivation und nicht genehmigt bewegten Stealth Outputs alarmieren.

## Liquid Confidential Transactions

**Mechanik:** Liquid verbirgt Output-Beträge und Assettypen standardmäßig mittels Commitments und Proofs, während Transaktionsgraph, Input-/Output-Anzahl, Gebühr und Blockzeit sichtbar bleiben. Peg-in/Peg-out und Servicegrenzen bleiben verknüpfbar; Nutzer können Blinding-Daten selektiv offenlegen.<sup>[[22]](#references)</sup>

**Vorteile:** Vertraulicher Betrag und Assettyp standardmäßig; schnelles Sidechain-Settlement; selektives Audit über Blinding Keys/Descriptors; schützt kommerziell sensible Werte vor öffentlichen Beobachtern.

**Nachteile:** Graphstruktur und Timing bleiben; Federation-/Bridge- und Exchange-Vertrauen; Peg-Grenzen und unconfidential Outputs; Wallet-/Node-/Netzwerkdaten; Sender und Empfänger kennen ihre Transaktion.

**Ablauf:** (1) gepflegte Liquid Wallet wählen und Backup-Modell prüfen; (2) Testnet oder kleinen rechtmäßigen Betrag verwenden; (3) an Confidential Address empfangen und prüfen, dass Wallet Output als blinded markiert; (4) Confidential Transaction testen; (5) prüfen, welche Explorer-Felder öffentlich bleiben; (6) nur benötigten Blinding Proof für Audit exportieren; (7) Peg-/Exchange-Grenzen dokumentieren und Gelder abgleichen.

**Erkennung:** Sichtbaren Graph, Gebühr/Zeit, Peg- und Exchange-Daten, Netzwerkmetadaten sowie spätere Unblinding-Beweise analysieren; verborgenen Betrag oder Assettyp nicht ableiten. **Capture-resilient OPSEC:** Spend Seed, Blinding/View-Daten und Watch-only-Operationen trennen. **Monitoring:** Bei versehentlich unconfidential Adressen, unbekannten Peg-Requests, Descriptoränderungen und nicht genehmigtem Blinding-Key-Export alarmieren.

## General Payment oder State Channel

**Mechanik:** Teilnehmer sperren Gelder, tauschen signierte Off-Chain-State-Updates und veröffentlichen nur Opening, Closing oder Disputed State on-chain. Zwischenzahlungen werden nicht global broadcastet, aber Peers und Routing-/Intermediärdienste sehen ihren Anteil; Endpunkte müssen den zuletzt durchsetzbaren State behalten.<sup>[[23]](#references)</sup>

**Vorteile:** Viele schnelle Interaktionen mit niedrigen Gebühren und geringerer globaler Ledger-Detailtiefe; begrenztes Channel-Guthaben; nützlich für gemessene Services und wiederkehrende Gegenparteien.

**Nachteile:** Channel-Peers kennen einander und können Updates speichern; Opening/Closing/Wert/Timing korrelieren; während Challenge Windows kann Online-Monitoring nötig sein; Implementierungs-/Liquiditätsrisiko; allein kein großes Anonymity Set.

**Ablauf:** (1) gepflegte auditierte Implementierung und Dispute Window verstehen; (2) Low-value-Testchannel zwischen eigenen Parteien öffnen; (3) signierte State Updates mit eindeutigen Nonces austauschen; (4) letzten durchsetzbaren State sichern; (5) kooperativ schließen; (6) Ablehnung veralteter States im Testnet üben; (7) Buchhaltung und Channel-Peer-Daten aufbewahren.

**Erkennung:** Public Chain zeigt Lifecycle/Disputes; Peers, Watch Services und Application Transport zeigen Off-Chain-Timing und Parteien. **Capture-resilient OPSEC:** Hot Balance begrenzen und letzten signierten State verschlüsselt/wiederherstellbar getrennt von Field Nodes speichern. **Monitoring:** kontinuierlich auf Stale-State-Publikation, fehlendes Backup, Peer-Key-Änderung und nahende Challenge Deadline achten.

## Mobile Carrier Billing

**Mechanik:** Ein Online-Service belastet einen Kauf über Carrier Billing dem Mobilfunkvertrag oder Prepaid-Guthaben. Der Händler erhält möglicherweise eine Carrier-Autorisierung statt Karten-/Bankdaten, während der Carrier Subscriber/Line, Geräte-/Netzwerkkontext, Händler, Betrag und Zeit kennt.<sup>[[24]](#references)</sup>

**Vorteile:** Keine Kartennummer beim Händler; breite Telefonverfügbarkeit; geeignet für günstige digitale Güter; Carrier kann Belastungen begrenzen/zurücknehmen.

**Nachteile:** Stark über SIM/Konto und oft Gerät identifiziert; geringe Limits und hohe Gebühren; Händlerkategoriebeschränkungen; Account-Takeover/SIM-Swap-Risiko; Carrier und Aggregator erzeugen vollständige Spur.

**Ablauf:** (1) Verfügbarkeit, Limit, Gebühren und Rückerstattungen mit Organisations-Carrier-Konto prüfen; (2) nur bei Begründung auf dedizierter Organisationsleitung aktivieren; (3) kleinstes sinnvolles Limit setzen; (4) harmlosen Testkauf durchführen; (5) Händler- und Carrierbelege prüfen; (6) Recurring Authorization deaktivieren; (7) abgleichen und Funktion nach Assessment abschalten.

**Erkennung:** Carrier-, Aggregator- und Händlerdaten verbinden Leitung, Subscriber, IP/Gerät und Charge; Enterprise-Telekomrechnungen offenbaren dies. **Capture-resilient OPSEC:** Keine private Nummer verwenden und Carrier-Account-MFA außerhalb des Field Devices verlangen. **Monitoring:** Sofortige Charge-/SIM-Change-Alerts aktivieren und bei unerwarteter Premium-Service-Registrierung, Weiterleitung oder Account-Recovery stoppen.

## Open-banking Payment Initiation

**Mechanik:** Mit ausdrücklicher Zustimmung bittet ein regulierter Payment Initiation Service Provider (PISP) die kontoführende Bank, einen Transfer zu initiieren. Der Händler erhält möglicherweise keine Karten-Credentials, aber PISP und Banken behalten regulierte Zahler-, Empfänger-, Consent-, Geräte- und Transaktionsdaten.<sup>[[25]](#references)</sup>

**Vorteile:** Keine wiederverwendbare Kartennummer beim Checkout; starke Bankauthentisierung; exaktes Account-to-Account-Settlement; Consent-/Status-APIs; klare Abstimmung.

**Nachteile:** Nicht anonym gegenüber Banken/PISP; Zahlungsempfänger sieht oft rechtliche Kontodaten/Referenz; Phishing-/Redirect-Risiko; Rechtsordnung und Rückerstattungsschutz variieren; Consent-Metadaten schaffen weiteren Beobachter.

**Ablauf:** (1) aktuelle Regulierung des PISP und Authentizität der Merchant-Callback-Domain prüfen; (2) von der Merchant Request starten; (3) Empfänger, Betrag, Referenz und verlangtes Consent bei der Bank prüfen; (4) nur die einzelne Zahlung autorisieren; (5) finalen Status unabhängig prüfen; (6) verbleibendes Consent widerrufen; (7) Beleg aufbewahren und abgleichen.

**Erkennung:** Bank-/PISP-/Händlerlogs und Transferreferenzen liefern starke Attribution. **Capture-resilient OPSEC:** Banking-Authentisierung und Recovery von operativen/Field Devices fernhalten; Gerät sollte nur eine Paid-Service-Entitlement enthalten. **Monitoring:** Bank-Transaktions-/Consent-Alerts nutzen und neue PISP Grants, geänderte Zahlungsempfänger oder Status-Callbacks außerhalb der erwarteten Session untersuchen.

## Platform Wallet, App-Store-Balance oder In-app Credit

**Mechanik:** Eine Plattform belastet den Nutzer oder löst Account Credit ein und stellt der Anwendung anschließend eine signierte Receipt oder Entitlement aus. Der App-Entwickler erhält möglicherweise nicht das ursprüngliche Funding Instrument, während die Plattform Konto, Gerät, Funding, Produkt und Einlösung verbindet.<sup>[[26]](#references)</sup>

**Vorteile:** Händler/Entwickler erhält keine primäre PAN; Fraud-/Refund- und Familien-/Geschäftskontrollen; kleines Prepaid-Guthaben begrenzt Exposure; signierte Receipts vereinfachen Entitlement Verification.

**Nachteile:** Plattformkonto ist starker Identitäts- und Verhaltenshub; Gerät und Storefront-Geografie; Gift-Balance-Kauf-/Einlösungsspur; begrenzter Cash-out; Fraud Controls können Guthaben einfrieren; kein plattformübergreifendes Geld.

**Ablauf:** (1) von der Organisation verwaltetes Plattformkonto verwenden, sofern erlaubt; (2) Funding-, Regions-, Refund- und Transferregeln prüfen; (3) nur genehmigtes Budget hinzufügen; (4) harmloses Produkt über offiziellen Store kaufen; (5) prüfen, dass Anwendung nur erwartete Receipt-Felder erhält; (6) Recurring Purchase deaktivieren; (7) abgleichen und Konto von operativer Hardware entfernen.

**Erkennung:** Plattform-Receipts/Server Notifications, Konto-/Geräte-Logins und Funding-Daten rekonstruieren den Kauf. **Capture-resilient OPSEC:** Field Node nie bei persönlichem Storekonto anmelden; möglichst nur begrenzte App-Entitlement bereitstellen. **Monitoring:** Alerts für neue Geräte/Käufe aktivieren und Receipt Replay, Familien-/Kontenänderungen oder unerwartete Restore Events untersuchen.

## Mutual Credit, Clearing oder periodisches Net Settlement

**Mechanik:** Teilnehmer erfassen Verpflichtungen in einem privaten Ledger und begleichen regelmäßig nur ihre Nettoposition. Einzelne Serviceereignisse müssen keine separaten öffentlichen Zahlungen erzeugen, aber Ledgerbetreiber und Gegenparteien behalten detaillierte Attribution.

**Vorteile:** Weniger externe Transaktionen und Gebühren; öffentliche Beobachter sehen nur Net Settlement; geeignet für wiederkehrende Organisationen; explizite Credit Limits begrenzen Exposure.

**Nachteile:** Zentraler Ledger ist vollständiger Beweis und Angriffsziel; Gegenparteien-/Ausfallrisiko; rechtliche/Buchhaltungs-/Steuerpflichten; kleine Mitgliederzahl; ungewöhnliche Net Transfers können Beziehungen offenbaren.

**Ablauf:** (1) nur identifizierte zustimmende Organisationen mit rechtlicher/buchhalterischer Freigabe verwenden; (2) Einheit, Credit Limit, Settlement-Intervall und Streitregeln definieren; (3) jede Verpflichtung mit unveränderlicher Genehmigung erfassen; (4) getrennte Finanzrollen berechnen und Nettopositionen genehmigen lassen; (5) über gewöhnliches rechtmäßiges Rail begleichen; (6) Einzelpositionen dem Settlement zuordnen; (7) Zugriff schließen und richtliniengemäß aufbewahren.

**Erkennung:** Ledger, Rechnungen, Genehmigungen und finales Bank-/Chain-Settlement liefern Ground Truth; Analysten dürfen fehlende Bruttoaktivität nicht allein aus dem Net Transfer ableiten. **Capture-resilient OPSEC:** Operative Geräte dürfen begrenzte Requisitionen senden, aber weder Salden ändern noch Settlement autorisieren. **Monitoring:** Bei Credit-Limit-Überschreitung, rückdatierten Einträgen, Adminänderungen, Abweichungen und Settlement an neuen Begünstigten alarmieren.

## Capture/Compromise Exposure Matrix

Dies wird auf jede Familie angewendet. Ziel ist, Ausgabeberechtigung und Offenlegung unabhängiger Identitäten zu begrenzen und dabei rechtmäßige Buchhaltung zu behalten – nicht Transaktionen zu löschen oder Ermittlungen zu vereiteln.

| Technikfamilie | Ein erfasstes Wallet/Gerät/Konto kann offenlegen | Minimale autorisierte Kontrolle |
|---|---|---|
| Bargeld, Money Order, COD, physischer Bearer-Wert | Belege, Seriennummern, Notizen, verbleibenden Bearer-Wert und physische Kontakte | nur genehmigten Betrag mitführen; private Buchhaltung trennen; Verlust melden; keine falschen Datensätze |
| Prepaid, Geschenk, Gutschein, Service Credits | Saldo, Issuer, Aktivierung, Einlösung und Konto-/Session-Tokens | niedriger Saldo; ein Zweck; wahrheitsgemäße Registrierung; Issuer-Freeze/Revocation |
| Virtuelle/tokenisierte Karte, Wallet Token, Payment App | Issuerkonto, Gerätetoken, Transaktionen, Recovery und Händlerhistorie | Gerätesperre; Transaktionsalerts; Händlerscope; Remote-Issuer-Sperre; kein gemeinsames Recoverykonto |
| Bank-Compartment, delegierte Beschaffung, Red-Team Procurement | Organisation, Genehmiger, Vendor, Rechnungen und Projekt | Rollentrennung; Least-Privilege-Subkonto; Finance-Credentials nie auf operativen/Field Nodes |
| Invoice, Escrow, Batch Settlement | Gegenpartei, Zweck, ausstehende Genehmigung, Coordinator- oder Streitspur | einmalige Request; separater Genehmiger; begrenzte Session; zentrales maßgebliches Ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | Seeds/Keys, Labels, Adressen, Transaktionsgraph und Netzwerkkonfiguration | Hardware/Offline Signing; verschlüsselte Wallet; Passphrase-Limits; Watch-only Field View; dokumentierte Recovery |
| Lightning/BOLT 12 | Seed, Channels, Invoices, Peers/LSP und Payment-Datenbank | minimales Hot Balance; verschlüsseltes Backup; getrennte Node-Identität; dokumentierte Recovery |
| Monero, Zcash, MWEB, ZK-Anwendungen | Spend/View Keys, lokale Wallet-Historie, RPC und Boundary Transactions | Spend/View-Rollen trennen; Hardwareunterstützung; keine Exchange-Session auf Field Node |
| Stablecoins, Swaps, Bridges und DEX | transparenter Graph, Approvals, RPC-/Frontend-State und Zielassets | Allowances widerrufen; geprüfte Contracts; Low-value-Test; vollständiger Abgleich |
| Cashu, Fedimint, Taler, Privacy Pass | Bearer Tokens, Mint/Federation/Exchange, Ausgabe-/Einlösungscache | kleiner Saldo; verschlüsseltes Backup; einlösen/neu ausgeben; Funding-Credential nicht zusammen speichern |
| Paymaster, Multisig/Threshold | Session Key, einzelner Signer, ausstehende Operations und Sponsor Policy | enger Session Key; unabhängiges Quorum; Signerrotation; Field Device erreicht Threshold nicht |
| Mixer/Peel/Structuring, Nominees/Fronts, Refund-/Gambling-Missbrauch | belastende Provider-, Kommunikations-, Graph- und Teilnehmerdaten | keine operative Nutzung; nur synthetische/Testnet-Evidenz |
| Community-/Event-Währung | Enrollment, lokaler Saldo, Gegenparteien und Einlösung | begrenzter Wert; Issuer Freeze/Reissue; Zustimmung und privates auditierbares Ledger |
| Wiederverwendbare Bitcoin-/EVM-Stealth-Adresse | Payment-/View-/Spend Keys, Beziehungsmetadaten, Announcements und abgeleitete Outputs | Watch/View-only-Netzwerkrolle; Offline-/Hardware-Spend-Rolle; keine persönliche Funding-Session |
| Liquid Confidential/State Channels | Seed, Blinding-Daten/letzter State, Peers, Grenzen und Disputes | Spend/View/State-Backups trennen; niedriges Hot Balance; unabhängiger Dispute Monitor |
| Carrier/Open Banking/Platform Billing | Telefon-/Bank-/Storekonto, Consent, Receipt, Gerät und Fundingquelle | Organisationskonto; externe MFA; niedriges Limit; kein persönliches Konto auf Field Hardware |
| Mutual-credit Clearing | Mitglieder, Verpflichtungen, Limits, Genehmigungen und Settlement-Ledger | nur operative Requisition; separates unveränderliches Ledger und doppelte Finanzgenehmigung |

## Monitoring möglicher Entdeckung oder Payment Compromise

Zahlungsverweigerung, Compliance Review oder Offlinegehen einer Wallet beweist keine Untersuchung. Nur Konten, Ledger und Infrastruktur überwachen, für die die Organisation berechtigt ist; Provider oder Gegenparteien niemals testen, um Kooperation mit Ermittlern festzustellen.

| Abgedeckte Techniken | Sichere Monitoring-Signale | Freeze-/Stop-Bedingung |
|---|---|---|
| Bargeld, Money Order/COD, Prepaid/Geschenk/Gutschein, physischer Bearer-Wert | Inventar-/Belegabweichung, doppelte Seriennummer, unerwartete Einlösung/Rückerstattung oder Verlustmeldung | fehlendes Instrument, Einlösung außerhalb genehmigter Bestellung, veränderter Beleg oder Custody-Bruch |
| Virtuelle/tokenisierte Karte, Payment App, Bank/ACH/Wire, Open Banking, Carrier/Platform Billing | Issuer-/Bank-/Plattformalerts, neues Gerät/Consent/Begünstigter, Token-Reuse, SIM-/Account-Recovery | unbekannte Autorisierung, Begünstigtenänderung, neuer Recovery-Faktor, SIM-Swap oder Recurring Charge |
| Account-/Merchant-Compartment, kontrollierte/delegierte Beschaffung, Service Credits | IdP-/Vendor-Projekt-, Rollen-/Token-/Budgetänderung, Rechnung und Verbrauch | Cross-project Token, unbekannter Admin, Limitüberschreitung, Rechnungsabweichung oder nicht unterstütztes Ziel |
| Invoice, Escrow, Pooled Settlement, Mutual Credit | Ablauf von Requests, Approval/Release, Ledgerintegrität, Abgleich und Begünstigtenänderung | geänderter Betrag/Zahlungsempfänger, rückdatiertes Ledger, einseitige Freigabe oder nicht abgeglichener Batch |
| Bitcoin Address/Coin Control, Silent Payments, BIP47/BIP351 | Watch-only-Transaktionen, Notification-/Scan-State, Address Reuse, UTXO-Labels und Consolidation | unbekannter Spend, wiederverwendeter Empfängeroutput, Wallet-Gap-/Recovery-Fehler oder nicht genehmigtes Merge |
| PayJoin/CoinJoin | Proposal-Inputs/Outputs/Gebühren, Coordinatorverfügbarkeit, finale Transaktion | ersetzter Output, übermäßige Gebühr, unerwartete Input-Offenlegung oder Coordinator-Policy-Änderung |
| Lightning/BOLT12/allgemeine Channels | Channel-Backup, Invoice-/Offer-Nutzung, Liquidität, Peer/LSP und Chain Dispute | unbekannte Invoice-Zahlung, Peer-Key-Änderung, veraltetes Closing oder bevorstehender Dispute Deadline |
| Monero/Zcash/MWEB/Liquid CT | View-/Watch-Events, Pool/Domain/Adresstyp, Descriptor und Boundary Transaction | nicht genehmigter Spend, transparente/unconfidential Rückstufung, Key Export oder unbekannte Boundary |
| Ethereum ZK, Stealth Addresses, Paymaster, Stablecoin | Contract/Announcement, RPC/Bundler, Gas Sponsor, Allowance/Session Key und Issuer-Aktion | falscher Contract/Public Field, unbekannte Approval/Spend, Paymasteränderung oder Issuer-Freeze |
| Cashu/Fedimint/Taler/Privacy Pass | Mint-/Federation-/Exchange-Zustand, Token Double Spend/Replay, Gateway und Bearer-Saldo | unbekannte Einlösung, Mint-Key-/Terms-Änderung, Restore-Fehler oder Saldoinkonsistenz |
| Swaps/Bridges/DEX | geprüfter Contract, Allowance, Bestätigungen beider Chains, Rate und Ziel | Contract-/Route-Abweichung, Unlimited Approval, fehlendes Ziel oder Bridge Incident |
| Multisig/Threshold | Signer-Set-/Policy-Änderung, ausstehendes Proposal, Quorum und Recovery Audit | unbekannter Proposal/Signer, Threshold-Reduktion, Recovery-Aktivierung oder Policy Bypass |
| Mixer/Peel/Structuring, Nominees/Fronts, NFT/Gambling/Refund Abuse | nur synthetische Lab-Ground-Truth und Detection Output | jedes reale Konto, jede Person oder jeder Wert in der Emulation: sofort stoppen |

## Selection and Verification Workflow

1. Benennen, welche Partei welches Feld nicht erfahren darf.
2. Issuer/Mint/Custodian, Public Ledger, Netzwerk/RPC, Händler und physische Beobachter identifizieren.
3. Aktuellen Support, Rechtmäßigkeit, Limits, Custody, Recovery und Refund-Verhalten prüfen.
4. Einen kleinen rechtmäßigen End-to-End-Test durchführen.
5. Händlerbeleg, Provider-Statement, Public Chain und Wallet-/Node-Logs prüfen.
6. Backup/Recovery und absichtliche Audit-Offenlegung testen.
7. Erforderliche Quellen-, Eigentums-, Steuer-, Sanktions- und Engagement-Daten korrekt, aber zugriffsgeschützt führen.

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Beobachtungen zur Datenerfassung durch große Payment-Plattformen](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Schutz Ihrer Privatsphäre](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Ein einfacher Payjoin-Vorschlag](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion-Routing-Protokoll](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero-Dokumentation — Technische Spezifikationen und Netzwerk-Privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Entwicklung von Privacy-Anwendungen mit Zero-Knowledge-Proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protokoll und Privacy-Einschränkungen](https://docs.cashu.space/faq)
- [13] [Fedimint — Funktionsweise](https://fedimint.org/users/how-it-works)
- [14] [GNU-Taler-Dokumentation](https://docs.taler.net/)
- [15] [FATF — Red-Flag-Indikatoren für virtuelle Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administratoren, Exchanges und Nutzer virtueller Währungen](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU-Verordnung 2023/1113 — Übertragungsinformationen und Crypto-Assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Die Privacy-Pass-Architektur](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State- und Payment Channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier-Billing-API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
{{#include ../banners/hacktricks-training.md}}
