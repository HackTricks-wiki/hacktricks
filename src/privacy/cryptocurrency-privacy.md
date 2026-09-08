# Cryptocurrency Privacy

{{#include ../banners/hacktricks-training.md}}

Die Privatsphäre bei Kryptowährungen ist eine Frage des Protokolls und der operativen Abläufe, kein Synonym für Geheimhaltung oder Immunität. Öffentliche Ledger, Exchanges, Wallet-Server, Netzwerk-Peers, Händler und spätere Transaktionen legen unterschiedliche Teile des Graphen offen.

Beginne mit dem [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) für das Format mit Vor-/Nachteilen, Verfahren und Erkennung pro Technik. Diese Seite erweitert die kryptowährungsspezifischen Mechanismen und operativen Grenzen.

{% hint style="danger" %}
Dieses Kapitel dient der rechtmäßigen Self-Custody und der Datenminimierung. Verwende es nicht, um Erträge zu waschen, Sanktionen/Steuern/Meldepflichten zu umgehen, mit verbotenen Parteien zu handeln, einen regulierten Anbieter zu täuschen oder einen nicht lizenzierten Übertragungsdienst zu betreiben. Privacy-Technologie ändert weder die rechtliche Herkunft noch das Eigentum an Geldern.
{% endhint %}

## Threat model by layer

| Ebene | Beobachter | Übliche Offenlegung |
|---|---|---|
| Erwerb/Off-Ramp | Exchange, Bank, Broker, P2P-Gegenpartei | Identität, Finanzierungskonto, Ziel, Gerät, IP, Zeitpunkt |
| Ledger | Jeder, der Analytics betreibt | Adressen/Outputs, Beträge und Zeitpunkte auf transparenten Chains; protokollspezifische Metadaten andernorts |
| Wallet-Backend | RPC-Anbieter, Explorer, Remote-Node | Adressabfragen, Salden, IP, Transaktions-Broadcast |
| Netzwerk | ISP, Peers, Zugangspunkt eines Anonymitätsnetzwerks | IP, Timing, Volumen und Protokollnutzung |
| Gegenpartei | Zahler/Zahlungsempfänger | Rechnung/Adresse, Lieferung, Kommunikation, Konto und Timing |
| Endpoint | Malware, Cloud-Backup, physische Beschlagnahmung | Seed, Keys, Labels, Verlauf, Screenshots und Zwischenablage |

Self-Custody kann einen Custodian aus dem Kontrollpfad entfernen, löscht jedoch weder das Ledger, den Erwerbsdatensatz, Netzwerkmetadaten noch Beweise auf dem Endpoint.

## Protocol comparison

| Methode | Nützliche Privacy-Eigenschaft | Wichtige Grenzen |
|---|---|---|
| Bitcoin on-chain | Self-Custody; frische Adressen vermeiden einfache Adresswiederverwendung | Öffentlicher, dauerhafter Transaktionsgraph; Betrags-/Timing- und Spending-Heuristiken |
| Bitcoin PayJoin | Der Input des Empfängers kann die Heuristik des gemeinsamen Input-Eigentums durchbrechen | Beide Wallets benötigen Support; die Transaktion bleibt öffentlich; Support ist uneinheitlich |
| Bitcoin CoinJoin | Erzeugt Mehrdeutigkeit zwischen koordinierten Teilnehmern | Erkennbare Muster, Pre-/Post-Links, Konsolidierung, Policy-/Legal-/Provider-Risiko |
| Lightning | Onion-geroutete Zahlungen werden nicht als gewöhnliche Transfers global veröffentlicht | Channels werden on-chain geöffnet/geschlossen; Endpoints, Peers, Probes oder Custodians können Daten ableiten |
| Monero | Stärkere standardmäßige On-Chain-Vertraulichkeit für Empfänger, Betrag und Sender-Menge | Exchange-, Node-, Timing-, Endpoint- und Gegenparteiverknüpfungen bleiben bestehen |
| Ethereum/Stablecoins | Breite Verfügbarkeit und Smart-Contract-Interoperabilität | Öffentlicher State/Aktionen; RPC-Metadaten; zentralisierte Issuer können blockieren/einfrieren/melden |

## Bitcoin: privacy-preserving baseline

Bitcoin ist pseudonym, nicht anonym. Bestätigte Transaktionen sind öffentlich und dauerhaft; Adresswiederverwendung, gemeinsames Input-Eigentum, Change-Erkennung und öffentlich identifizierte Adressen können Cluster bilden.<sup>[[1]](#references)</sup>

### Workflow

1. **Wähle eine gepflegte Self-Custody-Wallet.** Lade sie vom offiziellen Projekt herunter, verifiziere angebotene Signaturen/Hashes und installiere Sicherheitsupdates.
2. **Erstelle die Wallet auf einem vertrauenswürdigen Endpoint.** Notiere den Recovery-Seed offline; speichere ihn niemals in E-Mail, Chat, Screenshots oder gewöhnlichen Cloud-Notizen. Teste die Wiederherstellung vor der Aufbewahrung erheblicher Werte.
3. **Halte nur den operativen Wert hot.** Verwende für langfristige Werte geeignete Offline-/Hardware-Custody mit einem Recovery-Plan, der den Seed nicht einem einzigen fragilen Ort aussetzt.
4. **Generiere für jede Transaktion eine neue Empfangsadresse/Rechnung.** Veröffentliche keine statische Adresse, wenn ein Invoice-Server oder eine authentifizierte private Zustellung möglich ist.
5. **Verwende nach Möglichkeit deinen eigenen Full Node.** Ein Drittanbieter-Explorer/Electrum-Server kann abgefragte Adressen und IP-Metadaten erfahren. Konfiguriere nur von der Wallet unterstütztes Tor-/Proxy-Verhalten; Tor verbirgt einen Netzwerkzugang, nicht den Blockchain-Graphen.
6. **Vergebe für jedes UTXO private Labels** mit Quelle, Eigentümer, Zweck und Compliance-Status. Aktiviere Coin Control, damit nicht zusammengehörige Identitätskontexte nicht gemeinsam ausgegeben werden.
7. **Prüfe die Transaktion:** ausgewählte Inputs, Change-Ziel, Betrag, Gebühr, Gegenpartei und ob der Spend Compartments zusammenführt. Vermeide unnötige Konsolidierung.
8. **Bewahre rechtmäßige Aufzeichnungen getrennt und verschlüsselt auf.** Bewahre Anschaffungskosten, Rechnungen, Genehmigungen und Steuer-/Meldeinformationen auf, ohne die Zuordnung zu veröffentlichen.
9. **Betrachte spätere Ausgaben als Teil derselben Privacy-Entscheidung.** Ein gut getrennter Empfang kann erneut verknüpft werden, wenn sein Output gemeinsam mit identifizierten Geldern ausgegeben wird.

Die Privacy-Dokumentation von Bitcoin Core erklärt, dass ein Full Node verhindert, dass Wallet-Abfragen an Drittanbieter-Server offengelegt werden, dass Transaktions-Broadcasts und die öffentliche Historie jedoch weiterhin analysiert werden müssen.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin ist eine kollaborative Zahlung, bei der der Empfänger einen Input hinzufügt. Dadurch wird die vereinfachte Annahme widerlegt, dass alle Inputs dem Sender gehören. BIP 78 beschreibt das ursprüngliche interaktive Protokoll; der Entwurf BIP 77 definiert ein asynchrones v2-Design mit einer verschlüsselten Mailbox/OHTTP.<sup>[[3]](#references)</sup>

Sichere Verwendung:

1. Bestätige, dass beide gepflegten Wallets dieselbe PayJoin-Version unterstützen.
2. Beziehe die PayJoin-fähige Rechnung über einen authentifizierten Kanal und schütze sie wie jede Zahlungsanforderung.
3. Prüfe den ursprünglichen Betrag und das Ziel und lasse die Wallet anschließend Proposal/PSBT, Gebührenbeitrag und unzulässige Ersetzungen validieren.
4. Bestätige die abschließende Wallet-Zusammenfassung. Genehmige niemals manuell einen unerwarteten Output, Betrag oder eine überhöhte Gebühr.
5. Wenn die Verhandlung fehlschlägt, prüfe, ob die Wallet sicher auf eine gewöhnliche Zahlung zurückfällt oder eine neue Rechnung benötigt.
6. Bewahre die für Eigentum, Buchhaltung und Streitfälle erforderlichen privaten Belege/Aufzeichnungen auf.

PayJoin verbessert eine Heuristik der Chain-Analyse; es verbirgt die Zahlung jedoch nicht vor den Parteien, der Erwerbsplattform, den Endpoints oder dem öffentlichen Ledger.

## CoinJoin: benefits and limits

CoinJoin koordiniert mehrere Nutzer in einer Transaktion, um die Zuordnung von Inputs und Outputs unsicherer zu machen. Untersuchungen zu bestimmten historischen Wasabi- und Samourai-Designs fanden stark erkennbare Transaktionen und zeigten, dass das Verhalten vor/nach dem Mix die Anonymität erheblich einschränken kann.<sup>[[4]](#references)</sup> Dieses Ergebnis sollte nicht auf jede Implementierung oder künftige Version verallgemeinert werden, zeigt aber, warum eine Zahl zur „Anonymitätsmenge“ keine Garantie ist.

Vor jeder rechtmäßigen Nutzung:

- Prüfe die aktuelle lokale Rechtslage, den Sanktionsstatus, die Richtlinien von Exchange/Custodian sowie Steuer-/Meldepflichten.
- Verwende gepflegte, nicht-custodiale Software, die vom offiziellen Projekt bezogen wurde.
- Verstehe das Coordinator-Modell, Gebühren, Denial-of-Service-Kontrollen und ob der aktuelle Dienst noch betrieben wird – zkSNACKs beendete seinen Coordinator 2024, obwohl andere Wasabi-Coordinatoren existieren können.
- Bewahre Herkunftsnachweise und Transaktionsaufzeichnungen privat auf.
- Akzeptiere niemals unbekannte Gelder im Namen einer anderen Person und verwende keinen custodial „Mixer“, der nicht nachverfolgbare Auszahlungen verspricht.
- Halte Outputs nach Quelle/Kontext getrennt und vermeide spätere Konsolidierung, die die beabsichtigte Mehrdeutigkeit zerstört.

Rechtliche Folgen sind fall- und jurisdiktionsabhängig. Die Schuldbekenntnisse von Samourai im Jahr 2025 betrafen den wissentlichen Betrieb eines nicht lizenzierten Geldübermittlers, der kriminelle Erträge bewegte; sie begründen nicht, dass jede kollaborative Transaktion oder jeder Nutzer mit Privacy-Interesse kriminell ist.<sup>[[5]](#references)</sup>

## Lightning Network

Lightnings Sphinx Onion Routing ist so konzipiert, dass ein zwischengeschalteter Hop seinen Vorgänger und Nachfolger erfährt, nicht jedoch die gesamte Route.<sup>[[6]](#references)</sup> Es handelt sich nicht um pauschale Anonymität: Channel-Finanzierung/-Schließung ist öffentlich, Nodes veröffentlichen Topologie, Gegenparteien kennen die Endpoints, Routing/Probing kann Salden oder Parteien ableiten, und eine custodiale Wallet sieht die Kontoaktivität ihres Nutzers.

Für bessere Privacy:

1. Bevorzuge eine gepflegte nicht-custodiale Wallet, wenn die Privacy gegenüber Intermediären wichtig ist; plane zuerst Channel-Backup und -Wiederherstellung.
2. Verwende für jede Zahlung eine neue Rechnung oder ein neues Offer. Prüfe, ob die konkrete Wallet BOLT 12/Route Blinding unterstützt, statt dies anzunehmen.
3. Veröffentliche keine unnötigen Node-Aliase, Kontaktdaten oder stabilen Netzwerkendpoints.
4. Verbinde dich gegebenenfalls über ein unterstütztes Privacy-Netzwerk und beachte, dass Verfügbarkeits-/Timing-Muster weiterhin korrelieren können.
5. Leite nicht daraus ab, dass eine Off-Chain-Zahlung keine Aufzeichnungen hinterlässt: Sender, Empfänger, Peers, Watchtowers, Liquiditätsanbieter und Wallet-Dienste können Beobachtungen speichern.

Veröffentlichte Forschung hat gezeigt, dass sich Sender/Empfänger und Channel-Salden aus öffentlichen Daten und aktivem Probing ableiten lassen, wobei sich Angriffe und Gegenmaßnahmen weiterentwickeln.<sup>[[7]](#references)</sup>

## Monero

Monero verwendet einmalige Stealth-Adressen für Outputs, RingCT zum Verbergen von Beträgen und Ringsignaturen für probabilistische Sender-Mehrdeutigkeit; die aktuellen technischen Spezifikationen dokumentieren eine Ringgröße von 16 (15 Decoys).<sup>[[8]](#references)</sup> Dies sind stärkere Standardeinstellungen für On-Chain-Vertraulichkeit als bei transparenten Ledgers, kein magischer Schutz vor Fehlern am Endpoint oder in den operativen Abläufen.

### Lawful workflow

1. **Rechtmäßig erwerben.** Eine regulierte Exchange kann den Kauf und die Auszahlung kennen, selbst wenn spätere On-Chain-Details vertraulich sind. Bewahre Herkunft, Anschaffungskosten und Meldeaufzeichnungen auf.
2. **Installiere die offizielle gepflegte Wallet** und verifiziere den Download gemäß den Projektanweisungen. Sichere den Seed offline und teste die Wiederherstellung mit einem kleinen Betrag.
3. **Bevorzuge einen lokalen Node** für maximale Privacy bei Wallet-Abfragen. Wenn dies unpraktisch ist, wähle einen vertrauenswürdigen Remote Node, der über eine offiziell unterstützte Onion-/I2P-Konfiguration erreichbar ist. Ein Remote Node kann IP, Anfragen, Timing und Transaktions-IDs protokollieren; manche Lightweight-Designs legen einen View Key offen.
4. **Verwende pro Zahler, Kampagne oder Rechnung eine neue Subadresse.** Ein Zahler kann die wiederholte Nutzung derselben Subadresse korrelieren.<sup>[[9]](#references)</sup>
5. **Vergebe eingehenden Kontexten lokale Labels.** Vermeide es, getrennte Zahlungseingänge operativ zusammenzuführen, wenn ein sachkundiger Zahler das anschließende Verhalten erkennen könnte.
6. **Schütze Netzwerkmetadaten.** Befolge die offizielle Konfiguration des Anonymitätsnetzwerks und beachte dokumentierte Leaks durch Zeitstempel, intermittierende Synchronisierung, Bandbreitenmuster und Stream-Wiederverwendung.<sup>[[10]](#references)</sup>
7. **Halte Compliance-/Audit-Daten privat.** Lege einen View Key oder Transaktionsnachweis nur bewusst gegenüber dem vorgesehenen Auditor/der vorgesehenen Partei offen und verstehe genau, was dadurch sichtbar wird.

Historische Studien zur Rückverfolgbarkeit umfassen Bugs und Epochen der Decoy-Auswahl, die sich inzwischen geändert haben; wende alte Erfolgsprozentsätze nicht auf aktuelle Transaktionen an. Ebenso bleibt FCMP++ zum Forschungsstichtag dieses Kapitels im September 2026 Roadmap-Arbeit und ist kein eingesetzter Schutz.<sup>[[11]](#references)</sup>

## Ethereum and stablecoins

Ethereums eigene Privacy-Materialien weisen darauf hin, dass On-Chain-Aktionen sichtbar sind und Wallet-/RPC-Infrastruktur zusätzliche IP- und Metadaten preisgibt.<sup>[[12]](#references)</sup> Token-Transfers, Approvals, Smart-Contract-Interaktionen, Name Services und Gas-Finanzierung können Identitäten miteinander verbinden.

Zentralisierte Stablecoins erweitern die Kontrolle des Issuers. Die aktuellen Bedingungen von USDC und Tether behalten sich Befugnisse vor, Adressen oder Assets zu blockieren/einzufrieren und gesetzlichen/prozessualen Verpflichtungen nachzukommen.<sup>[[13]](#references)</sup> Sie können nützliche Zahlungsinstrumente sein, sind jedoch eine schlechte Wahl, wenn Zensurresistenz oder On-Chain-Anonymität erforderlich ist.

## Compliance boundaries

- FATF-Empfehlungen werden durch nationales Recht umgesetzt und ändern sich im Laufe der Zeit; das Update von 2026 betont die Lizenzierung/Registrierung von VASPs und die Umsetzung der Travel Rule.<sup>[[14]](#references)</sup>
- In den USA unterscheidet FinCEN zwischen einer Person, die Convertible Virtual Currency für eigene Waren/Dienstleistungen verwendet, und einem Unternehmen, das sie akzeptiert und überträgt oder umtauscht; die Fakten und spätere Regelungen sind maßgeblich.<sup>[[15]](#references)</sup>
- Die EU Transfer of Funds Regulation verlangt Angaben zu Auftraggeber und Begünstigtem, wenn ein Crypto-Asset-Service-Provider beteiligt ist, und ergänzt Verifizierungsregeln für bestimmte Transfers zu/von Self-Hosted-Adressen.<sup>[[16]](#references)</sup>
- Sanktionen und Steuerpflichten gelten weiterhin. Führe erforderliche Prüfungen durch, lehne verbotene Parteien ab und bewahre Aufzeichnungen auf; Listen und Rechtsstatus können sich schnell ändern.<sup>[[17]](#references)</sup>

Vor der Verwendung erheblicher Werte, grenzüberschreitender Aktivitäten, Privacy-erhöhender Koordination oder eines geschäftsähnlichen Exchange-/Übertragungsbetriebs solltest du aktuelle professionelle Beratung für die relevanten Jurisdiktionen einholen.

Für Bitcoin Silent Payments, vollständig abgeschirmtes Zcash, GNU Taler, föderiertes Chaumian E-Cash und BOLT 12 siehe weiterhin [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Schütze deine Privatsphäre](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy-Funktionen](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Ein einfacher PayJoin-Vorschlag](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Akzeptanz und tatsächliche Privacy dezentraler CoinJoin-Implementierungen in Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Gründer von Samourai Wallet bekennen sich schuldig (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion-Routing-Protokoll](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Eine empirische Analyse der Privacy im Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth-Adressen](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ringsignaturen](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) und [Technische Spezifikationen](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subadresse](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Netzwerke](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad und Victor — Untersuchung der Entwicklung der Monero-Privacy (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privacy auf Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC-Bedingungen](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Gezieltes Update 2026 zu virtuellen Assets und VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Anwendung der FinCEN-Regelungen auf Personen, die virtuelle Währungen verwalten, umtauschen oder verwenden](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Verordnung (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Leitfaden zur Sanktions-Compliance für die Virtual-Currency-Branche](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
