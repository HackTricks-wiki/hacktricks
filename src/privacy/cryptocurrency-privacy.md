# Cryptocurrency Privacy

Cryptocurrency Privacy ist eine Frage von Protokoll und Betrieb, kein Synonym für Geheimhaltung oder Immunität. Öffentliche Ledger, Exchanges, Wallet-Server, Netzwerk-Peers, Händler und spätere Transaktionen legen unterschiedliche Teile des Graphen offen.

Beginne mit dem [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) für das Format mit Vor-/Nachteilen, Verfahren und Erkennung pro Technik. Diese Seite erweitert die kryptowährungsspezifischen Mechanismen und betrieblichen Grenzen.

{% hint style="danger" %}
Dieses Kapitel ist für rechtmäßige Self-Custody und Datenminimierung gedacht. Verwende es nicht, um Erlöse zu waschen, Sanktionen/Steuern/Meldepflichten zu umgehen, mit verbotenen Parteien zu handeln, einen regulierten Anbieter zu täuschen oder einen nicht lizenzierten Übertragungsdienst zu betreiben. Privacy-Technologie ändert weder die rechtmäßige Herkunft noch das Eigentum an den Geldern.
{% endhint %}

## Threat model nach Schicht

| Schicht | Beobachter | Häufige Offenlegung |
|---|---|---|
| Erwerb/Off-ramp | Exchange, Bank, Broker, P2P-Gegenpartei | Identität, Finanzierungskonto, Ziel, Gerät, IP, Zeitpunkt |
| Ledger | Jeder, der Analytics betreibt | Adressen/Outputs, Beträge und Zeitpunkte auf transparenten Chains; protokollspezifische Metadaten andernorts |
| Wallet-Backend | RPC-Provider, Explorer, Remote-Node | Adressabfragen, Guthaben, IP, Transaktionsübertragung |
| Netzwerk | ISP, Peers, Anonymitätsnetzwerk-Einstiegspunkt | IP, Timing, Volumen und Protokollnutzung |
| Gegenpartei | Zahler/Zahlungsempfänger | Rechnung/Adresse, Lieferung, Kommunikation, Konto und Timing |
| Endpunkt | Malware, Cloud-Backup, physische Beschlagnahmung | Seed, Keys, Labels, Verlauf, Screenshots und Clipboard |

Self-Custody kann einen Verwahrer aus dem Kontrollpfad entfernen, löscht jedoch weder das Ledger noch den Erwerbsdatensatz, Netzwerkmetadaten oder Beweise auf dem Endpunkt.

## Protokollvergleich

| Methode | Nützliche Privacy-Eigenschaft | Wichtige Grenzen |
|---|---|---|
| Bitcoin on-chain | Self-Custody; neue Adressen vermeiden einfache Adresswiederverwendung | Öffentlicher, dauerhafter Transaktionsgraph; Betrags-/Timing- und Spending-Heuristiken |
| Bitcoin PayJoin | Der Input des Empfängers kann die Heuristik zum gemeinsamen Input-Eigentum brechen | Beide Wallets benötigen Support; Transaktion bleibt öffentlich; Support ist uneinheitlich |
| Bitcoin CoinJoin | Erzeugt Mehrdeutigkeit unter koordinierten Teilnehmern | Erkennbare Muster, Verknüpfungen davor/danach, Konsolidierung, Policy-/Legal-/Provider-Risiko |
| Lightning | Onion-geroutete Zahlungen werden nicht global als gewöhnliche Transfers veröffentlicht | Channels werden on-chain geöffnet/geschlossen; Endpunkte, Peers, Probes oder Verwahrer können Daten ableiten |
| Monero | Stärkere standardmäßige On-Chain-Vertraulichkeit für Empfänger, Betrag und Sendergruppe | Verknüpfungen durch Exchange, Node, Timing, Endpunkt und Gegenpartei bleiben bestehen |
| Ethereum/Stablecoins | Breite Verfügbarkeit und Smart-Contract-Interoperabilität | Öffentlicher State/Aktionen; RPC-Metadaten; zentrale Emittenten können blockieren/einfrieren/melden |

## Bitcoin: Privacy-erhaltende Grundlage

Bitcoin ist pseudonym, nicht anonym. Bestätigte Transaktionen sind öffentlich und dauerhaft; Adresswiederverwendung, gemeinsames Input-Eigentum, Change-Erkennung und öffentlich identifizierte Adressen können Cluster bilden.<sup>[[1]](#references)</sup>

### Workflow

1. **Wähle ein gepflegtes Self-Custody-Wallet.** Lade es vom offiziellen Projekt herunter, verifiziere angebotene Signaturen/Hashes und installiere Sicherheitsupdates.
2. **Erstelle das Wallet auf einem vertrauenswürdigen Endpunkt.** Notiere den Recovery-Seed offline; speichere ihn niemals in E-Mail, Chat, Screenshots oder gewöhnlichen Cloud-Notizen. Teste die Wiederherstellung vor der Aufbewahrung größerer Werte.
3. **Halte nur den operativen Wert hot.** Verwende für langfristige Werte eine geeignete Offline-/Hardware-Verwahrung mit einem Recovery-Plan, der den Seed nicht einem einzigen fragilen Ort aussetzt.
4. **Erzeuge für jede Transaktion eine neue Empfangsadresse/Rechnung.** Veröffentliche keine statische Adresse, wenn ein Invoice-Server oder eine authentifizierte private Zustellung möglich ist.
5. **Verwende nach Möglichkeit deinen eigenen Full Node.** Ein Drittanbieter-Explorer/Electrum-Server kann abgefragte Adressen und IP-Metadaten erfahren. Konfiguriere nur vom Wallet unterstütztes Tor-/Proxy-Verhalten; Tor verbirgt einen Netzwerk-Rand, nicht den Blockchain-Graphen.
6. **Beschrifte jeden UTXO privat** mit Quelle, Eigentümer, Zweck und Compliance-Status. Aktiviere Coin Control, damit nicht zusammengehörige Identitätskontexte nicht gemeinsam ausgegeben werden.
7. **Prüfe die Transaktion vorab:** ausgewählte Inputs, Change-Ziel, Betrag, Gebühr, Gegenpartei und ob der Spend Compartments zusammenführt. Vermeide unnötige Konsolidierung.
8. **Bewahre rechtmäßige Unterlagen getrennt und verschlüsselt auf.** Bewahre Anschaffungskosten, Rechnungen, Autorisierung und Steuer-/Meldeinformationen auf, ohne die Zuordnung zu veröffentlichen.
9. **Behandle spätere Ausgaben als Teil derselben Privacy-Entscheidung.** Ein gut getrennter Empfang kann erneut verknüpft werden, wenn sein Output gemeinsam mit identifizierten Geldern ausgegeben wird.

Die Privacy-Dokumentation von Bitcoin Core erklärt, dass ein Full Node verhindert, dass Wallet-Abfragen an Drittanbieter-Server offengelegt werden, dass Transaktionsübertragung und öffentliche Historie jedoch weiterhin analysiert werden müssen.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin ist eine kollaborative Zahlung, bei der der Empfänger einen Input hinzufügt. Dadurch wird die vereinfachte Annahme widerlegt, dass alle Inputs dem Sender gehören. BIP 78 beschreibt das ursprüngliche interaktive Protokoll; Draft BIP 77 definiert ein asynchrones v2-Design mit einer verschlüsselten Mailbox/OHTTP.<sup>[[3]](#references)</sup>

Sichere Verwendung:

1. Bestätige, dass beide gepflegten Wallets dieselbe PayJoin-Version unterstützen.
2. Beziehe die PayJoin-fähige Rechnung über einen authentifizierten Kanal; schütze sie wie jede Zahlungsanforderung.
3. Prüfe den ursprünglichen Betrag und das Ziel und lasse das Wallet den Vorschlag/die PSBT, den Gebührenanteil und unzulässige Ersetzungen validieren.
4. Bestätige die abschließende Wallet-Zusammenfassung. Genehmige niemals manuell einen unerwarteten Output, Betrag oder eine überhöhte Gebühr.
5. Wenn die Verhandlung fehlschlägt, kläre, ob das Wallet sicher auf eine gewöhnliche Zahlung zurückfällt oder eine neue Rechnung erfordert.
6. Bewahre die privaten Belege/Unterlagen auf, die für Eigentum, Buchhaltung und Streitfälle erforderlich sind.

PayJoin verbessert eine Heuristik der Chain-Analyse; es verbirgt die Zahlung jedoch nicht vor den Parteien, der Erwerbsplattform, den Endpunkten oder dem öffentlichen Ledger.

## CoinJoin: Vorteile und Grenzen

CoinJoin koordiniert mehrere Nutzer in einer Transaktion, um die Zuordnung zwischen Inputs und Outputs unsicherer zu machen. Untersuchungen zu bestimmten historischen Designs von Wasabi und Samourai fanden sehr erkennbare Transaktionen und zeigten, dass das Verhalten vor/nach dem Mix die Anonymität erheblich einschränken kann.<sup>[[4]](#references)</sup> Dieses Ergebnis sollte nicht auf jede Implementierung oder künftige Version verallgemeinert werden, zeigt aber, warum eine Zahl zum „Anonymity Set“ keine Garantie ist.

Vor jeder rechtmäßigen Nutzung:

- prüfe das aktuell geltende lokale Recht, den Sanktionsstatus, die Richtlinien von Exchange/Verwahrer sowie Steuer-/Meldepflichten;
- verwende gepflegte, nicht verwahrende Software aus dem offiziellen Projekt;
- verstehe das Coordinator-Modell, Gebühren, Denial-of-Service-Kontrollen und ob der aktuelle Dienst noch betrieben wird – zkSNACKs beendete seinen Coordinator 2024, obwohl andere Wasabi-Coordinators existieren können;
- bewahre Herkunfts- und Transaktionsdaten privat auf;
- akzeptiere niemals unbekannte Gelder im Namen einer anderen Person und verwende keinen verwahrenden „Mixer“, der nicht nachverfolgbare Auszahlungen verspricht;
- halte Outputs nach Quelle/Kontext getrennt und vermeide spätere Konsolidierung, die die beabsichtigte Mehrdeutigkeit zerstört.

Rechtliche Folgen sind sachverhalts- und jurisdiktionsabhängig. Die Schuldbekenntnisse von Samourai aus dem Jahr 2025 betrafen den wissentlich betriebenen, nicht lizenzierten Money-Transmitter, der kriminelle Erlöse bewegte; sie stellen nicht fest, dass jede kollaborative Transaktion oder jeder Privacy-suchende Nutzer kriminell ist.<sup>[[5]](#references)</sup>

## Lightning Network

Lightnings Sphinx Onion Routing ist so ausgelegt, dass ein Zwischen-Hop seinen Vorgänger und Nachfolger erfährt, nicht jedoch die gesamte Route.<sup>[[6]](#references)</sup> Es bietet keine vollständige Anonymität: Channel-Finanzierung/-Schließung ist öffentlich, Nodes veröffentlichen ihre Topologie, Gegenparteien kennen die Endpunkte, Routing/Probing kann Guthaben oder Parteien ableiten, und ein verwahrendes Wallet sieht die Kontoaktivität seines Nutzers.

Für bessere Privacy:

1. Bevorzuge ein gepflegtes nicht verwahrendes Wallet, wenn die Privacy gegenüber Intermediären wichtig ist; plane zuerst Channel-Backup und Recovery.
2. Verwende für jede Zahlung eine neue Rechnung oder ein neues Offer. Prüfe, ob das konkrete Wallet BOLT 12/Route Blinding tatsächlich unterstützt, statt dies anzunehmen.
3. Veröffentliche keine unnötigen Node-Aliase, Kontaktdaten oder stabilen Netzwerkendpunkte.
4. Verbinde dich gegebenenfalls über ein unterstütztes Privacy-Netzwerk und beachte, dass Uptime-/Timing-Muster weiterhin korrelierbar sein können.
5. Schließe nicht daraus, dass eine Off-Chain-Zahlung keine Datensätze hinterlässt: Sender, Empfänger, Peers, Watchtowers, Liquiditätsanbieter und Wallet-Dienste können Beobachtungen speichern.

Veröffentlichte Forschung hat gezeigt, dass sich Sender/Empfänger und Channel-Guthaben anhand öffentlicher Daten und aktiver Probes ableiten lassen, wobei sich Angriffe und Gegenmaßnahmen weiterentwickeln.<sup>[[7]](#references)</sup>

## Monero

Monero verwendet einmalige Stealth-Adressen für Outputs, RingCT zur Verschleierung von Beträgen und Ring-Signaturen für probabilistische Sender-Mehrdeutigkeit; die aktuellen technischen Spezifikationen dokumentieren eine Ringgröße von 16 (15 Decoys).<sup>[[8]](#references)</sup> Dies sind stärkere Standardvorgaben für On-Chain-Vertraulichkeit als bei transparenten Ledgers, aber kein magischer Schutz vor Fehlern an Endpunkten oder im Betrieb.

### Rechtmäßiger Workflow

1. **Rechtmäßig erwerben.** Eine regulierte Exchange kann den Kauf und die Auszahlung kennen, selbst wenn spätere On-Chain-Details vertraulich sind. Bewahre Herkunfts-, Anschaffungs- und Meldeunterlagen auf.
2. **Installiere das offizielle gepflegte Wallet** und verifiziere den Download gemäß den Projektanweisungen. Sichere den Seed offline und teste die Wiederherstellung mit einem kleinen Betrag.
3. **Bevorzuge einen lokalen Node** für maximale Privacy bei Wallet-Abfragen. Wenn dies unpraktisch ist, wähle einen vertrauenswürdigen Remote-Node, der über eine offiziell unterstützte Onion-/I2P-Konfiguration erreichbar ist. Ein Remote-Node kann IP, Anfragen, Timing und Transaktions-IDs protokollieren; manche Lightweight-Designs geben einen View Key preis.
4. **Verwende pro Zahler, Kampagne oder Rechnung eine neue Subadresse.** Ein Zahler kann die wiederholte Verwendung derselben Subadresse korrelieren.<sup>[[9]](#references)</sup>
5. **Beschrifte eingehende Kontexte lokal.** Vermeide es, getrennte Zahlungseingänge betrieblich zusammenzuführen, wenn ein sachkundiger Zahler das spätere Verhalten erkennen könnte.
6. **Schütze Netzwerkmetadaten.** Befolge die offizielle Konfiguration des Anonymitätsnetzwerks und beachte dokumentierte Leaks durch Zeitstempel, intermittierende Synchronisierung, Bandbreitenmuster und Stream-Wiederverwendung.<sup>[[10]](#references)</sup>
7. **Halte Compliance-/Audit-Daten privat.** Gib einen View Key oder Transaktionsnachweis nur bewusst an den vorgesehenen Auditor/die vorgesehene Partei weiter und verstehe genau, was dadurch offengelegt wird.

Historische Rückverfolgbarkeitsstudien umfassen Bugs und Epochen der Decoy-Auswahl, die sich inzwischen geändert haben; wende alte Erfolgsprozentsätze nicht auf aktuelle Transaktionen an. Ebenso bleibt FCMP++ zum Forschungsstichtag dieses Kapitels im September 2026 Roadmap-Arbeit und ist kein eingesetzter Schutz.<sup>[[11]](#references)</sup>

## Ethereum und Stablecoins

Das eigene Privacy-Material von Ethereum weist darauf hin, dass On-Chain-Aktionen sichtbar sind und Wallet-/RPC-Infrastruktur zusätzliche IP- und Metadaten preisgibt.<sup>[[12]](#references)</sup> Token-Transfers, Approvals, Smart-Contract-Interaktionen, Name Services und Gas-Finanzierung können Identitäten miteinander verbinden.

Zentrale Stablecoins bringen Kontrolle durch den Emittenten hinzu. Die aktuellen Bedingungen von USDC und Tether behalten sich Befugnisse vor, Adressen oder Assets zu blockieren/einzufrieren sowie gesetzlichen und verfahrensbezogenen Pflichten nachzukommen.<sup>[[13]](#references)</sup> Sie können nützliche Zahlungsinstrumente sein, sind aber eine schlechte Wahl, wenn Zensurresistenz oder On-Chain-Anonymität erforderlich ist.

## Compliance-Grenzen

- FATF-Empfehlungen werden durch nationales Recht umgesetzt und ändern sich im Laufe der Zeit; das Update von 2026 betont die Lizenzierung/Registrierung von VASPs und die Umsetzung der Travel Rule.<sup>[[14]](#references)</sup>
- In den USA unterscheidet FinCEN zwischen einer Person, die Convertible Virtual Currency für eigene Waren/Dienstleistungen verwendet, und einem Unternehmen, das sie akzeptiert, überträgt oder tauscht; die konkreten Umstände und spätere Regeln sind maßgeblich.<sup>[[15]](#references)</sup>
- Die EU Transfer of Funds Regulation verlangt Informationen zu Auftraggeber/Begünstigtem, wenn ein Crypto-Asset-Service-Provider beteiligt ist, und ergänzt Verifizierungsregeln für bestimmte Transfers zu/von Self-Hosted-Adressen.<sup>[[16]](#references)</sup>
- Sanktionen und Steuerpflichten gelten weiterhin. Führe erforderliche Prüfungen durch, lehne verbotene Parteien ab und bewahre Unterlagen auf; Listen und Rechtsstatus können sich schnell ändern.<sup>[[17]](#references)</sup>

Hole vor erheblichen Werten, grenzüberschreitenden Aktivitäten, Privacy-erhöhender Koordination oder einem geschäftsähnlichen Exchange-/Übertragungsbetrieb aktuelle professionelle Beratung für die relevanten Jurisdiktionen ein.

Für Bitcoin Silent Payments, vollständig abgeschirmtes Zcash, GNU Taler, föderiertes Chaumian E-Cash und BOLT 12 siehe weiterhin [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Schütze deine Privacy](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy-Funktionen](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Ein einfacher PayJoin-Vorschlag](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Akzeptanz und tatsächliche Privacy dezentralisierter CoinJoin-Implementierungen in Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Gründer von Samourai Wallet bekennen sich schuldig (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion-Routing-Protokoll](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Eine empirische Analyse der Privacy im Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth-Adressen](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring-Signaturen](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) und [Technische Spezifikationen](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subadresse](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Netzwerke](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad und Victor — Untersuchung der Entwicklung von Moneros Privacy (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privacy auf Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC-Bedingungen](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Gezieltes Update 2026 zu Virtual Assets und VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Anwendung der FinCEN-Vorschriften auf Personen, die Virtual Currencies verwalten, tauschen oder verwenden](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Verordnung (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Leitfaden zur Sanktions-Compliance für die Virtual-Currency-Branche](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
