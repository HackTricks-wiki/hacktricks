# Datenschutzfreundliche Zahlungsprotokolle

Fortgeschrittene Zahlungssysteme können einen Zahler vor dem Händler verbergen, einen Empfänger oder Betrag vor einem öffentlichen Ledger verbergen oder verhindern, dass eine Mint die Auszahlung mit der Einlösung verknüpft. Dies sind unterschiedliche Eigenschaften. Keines davon löscht Beschaffungs-, Geräte-, Netzwerk-, Liefer-, Buchhaltungs-, Sanktions- oder Endpoint-Datensätze.

Der [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) stellt für jede Zahlungsfamilie standardisierte Einträge für `Pros`, `Cons`, eine schrittweise `Procedure` und `Detection` bereit. Diese Seite behandelt die fortgeschrittenen Protokolle ausführlicher.

{% hint style="danger" %}
Verwende nur rechtmäßige Geldmittel und Gegenparteien. Verwende keine Privacy-Protokolle, um vorgeschriebene Identifizierung, Sanktionen, Steuern, Prüfungen der Mittelherkunft oder Transaktionsmeldungen zu umgehen. Betreibe keine Exchange-, Mint- oder Übertragungsdienste, ohne die Anforderungen an Lizenzen, Verwahrung, AML und Verbraucherschutz zu verstehen.
{% endhint %}

## Die fortgeschrittenen Optionen vergleichen

| Protokoll | Vor Öffentlichkeit/Händler verborgen | Vertrauenswürdige oder beobachtende Partei | Reifegrad/Verfügbarkeit |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Außenstehende können einen wiederverwendbaren Zahlungscode nicht mit dessen einmaligen Outputs verknüpfen | Der öffentliche Bitcoin-Graph bleibt bestehen; Wallet-/Index-Server können Scans sehen | Spezifikation abgeschlossen; Wallet-Unterstützung variiert |
| Zcash vollständig abgeschirmtes Orchard | Sender, Empfänger und Betrag sind On-Chain verschlüsselt | Wallet-Backend/Netzwerk sowie Beschaffung/Off-Ramp bleiben sichtbar | Eingeführt; Unterstützung für Shielding variiert je nach Wallet/Exchange |
| GNU Taler | Händler müssen die Identität des Zahlers nicht erfahren; Händlerumsätze bleiben nachvollziehbar | Taler-Exchange/Bank sieht die Finanzierung; Händler sieht die Bestellung | Deployments sind geografisch begrenzt |
| Federated Chaumian e-cash | Die Federation sollte ausgegebene Notes nicht mit internen Transfers/Einlösungen verknüpfen können | Guardian-Quorum verwahrt Reserven; Gateways sehen Aktivitäten an den Grenzen | Aufkommende Community-Deployments |
| Lightning BOLT 12/route blinding | Reduziert die Offenlegung von Empfänger/Node und Route | Endpoints, ausgewählte Hops, Funding-Chain und Wallet-Dienste | Unterstützung ist Wallet-abhängig |
| Virtuelle Karte/Token | Händler erhält ein eingeschränktes Credential, keine wiederverwendbare PAN | Issuer/Netzwerk behalten Zahler- und Transaktionsdaten | Ausgereift und weit verbreitet |

## Bitcoin Silent Payments (BIP 352)

Silent Payments ermöglichen es einem Empfänger, einen einzigen statischen Zahlungscode zu veröffentlichen, während jeder Sender einen eindeutigen Taproot-Output ableitet. Ein externer Chain-Beobachter kann diese Outputs nicht direkt mit dem veröffentlichten Code verknüpfen, und es ist weder eine interaktive Adressanfrage noch ein On-Chain-Benachrichtigungs-Output erforderlich. BIP 352 ist als **Complete** gekennzeichnet, führt jedoch Scan-Kosten ein und ist mit Wallets inkompatibel, die es nicht implementiert haben.<sup>[[1]](#references)</sup>

### Workflow des Empfängers

1. Wähle ein gepflegtes Wallet, das den Empfang über BIP 352 ausdrücklich unterstützt. Überprüfe das Feature anhand der aktuellen Wallet-Dokumentation und nicht anhand einer Behauptung in sozialen Medien.
2. Sichere den Wallet-Seed sowie das Material für Silent-Payment-Descriptor/Key mit der dokumentierten Wiederherstellungsmethode des Wallets. Teste die Erkennung mit einem kleinen Testnet-/Mainnet-Betrag, bevor du den Code veröffentlichst.
3. Erzeuge separate **Labels** für Kampagnen, Rechnungen oder Gegenparteien, sofern das Wallet BIP-352-Labels unterstützt. Labels unterstützen die lokale Buchhaltung, ohne verknüpfbare Adressen zu veröffentlichen.
4. Veröffentliche den statischen Silent-Payment-Code über einen authentifizierten Kanal. Er ist wiederverwendbar, aber ein Angreifer kann seinen eigenen Code einschleusen.
5. Scanne nach Möglichkeit über einen lokalen Full Node. Ein Drittanbieter-Index-/Scanning-Server kann Anfragezeitpunkte oder Filterdaten erfahren, selbst wenn er keine Ausgaben tätigen kann.
6. Behalte erkannte UTXOs mit Labels und wende dieselben Coin-Control-Regeln wie bei gewöhnlichem Bitcoin an. Das Ausgeben oder Konsolidieren dieser UTXOs kann Eigentumsbeziehungen offenlegen.
7. Bestätige, dass die Wiederherstellung Zahlungen erkennt, ohne auf einen nicht gesicherten externen Index angewiesen zu sein.

### Workflow des Senders

1. Bestätige, dass das Wallet das Senden an die Adressversion unterstützt, und authentifiziere den statischen Code des Empfängers.
2. Lass das Wallet den Output erstellen; konvertiere oder kürze den Code niemals manuell.
3. Überprüfe die ausgewählten Inputs sorgfältig. Silent Payments verbessern die Privatsphäre der Empfängeradresse, aber Sender-Inputs bleiben im öffentlichen Graph sichtbar.
4. Verwende vom Wallet unterstütztes Fee-Bumping-/PSBT-Verhalten. BIP 352 erfordert eine erneute Ableitung des Outputs, wenn sich Inputs ändern, und einige Signiermodi sind unsicher.
5. Bewahre einen verschlüsselten Beleg oder Nachweis auf, der für Streitfälle oder die Buchhaltung erforderlich ist.

Silent Payments lösen die wiederholte Veröffentlichung von Empfängeradressen. Sie verbergen jedoch weder Betrag, Transaktionszeitpunkt, Sender-Cluster, Beschaffungshistorie noch späteres gemeinsames Ausgeben.

## Zcash vollständig abgeschirmte Zahlungen

Zcash unterstützt transparente und abgeschirmte Value Pools. Abgeschirmte Orchard-Transaktionen verwenden Zero-Knowledge-Proofs, sodass Nodes die Gültigkeit überprüfen können, während Transaktionsdetails verschlüsselt sind; Unified Addresses können mehrere Empfängertypen enthalten.<sup>[[2]](#references)</sup> Die Privacy hängt vom tatsächlich vom Wallet ausgewählten Pfad ab, nicht vom ersten Zeichen einer angezeigten Adresse.

### Shielded-Workflow

1. Wähle ein gepflegtes Wallet, das das Verhalten **shielded-by-default** und die aktuelle Orchard-Unterstützung eindeutig angibt. Überprüfe den Download und sichere/teste den Seed.
2. Beschaffe ZEC rechtmäßig und dokumentiere Grundlage/Herkunft. Eine Exchange kennt weiterhin die Beschaffung und Auszahlung.
3. Empfange an eine vom Wallet unterstützte Unified Address und prüfe anschließend, ob die Transaktion in einem Shielded Pool gelandet ist. Gehe nicht ohne Bestätigung des Wallet-Verhaltens von automatischem Shielding aus.
4. Bevorzuge **shielded-to-shielded**-Transfers. Bewegungen von transparent zu shielded und von shielded zu transparent legen öffentliche Werte/Zeitpunkte offen und können eine Betragskorrelation ermöglichen; die Orchard-Spezifikation weist darauf hin, dass das Ausgeben an eine Nicht-Orchard-Adresse den Transaktionswert offenlegt.<sup>[[3]](#references)</sup>
5. Vermeide auffällige Transfers mit exakten Beträgen und unmittelbare Grenzüberschreitungen. Dies ist Privacy-Hygiene und keine Erlaubnis, Eigentum oder Meldepflichten zu verschleiern.
6. Verwende den vom Wallet unterstützten Network-Privacy-Pfad. Shielded-Kryptografie verbirgt IP-Adresse/Zeitpunkt nicht vor Wallet-Servern oder Peers.
7. Bewahre interne Compliance-Aufzeichnungen auf und verwende Viewing Keys nur für eine bewusst vorgenommene Prüfung/Offenlegung, nachdem du deren Umfang verstanden hast.
8. Bestätige vor dem Senden die Unterstützung des Empfänger-Wallets bzw. der Exchange. Ein erzwungener transparenter Empfänger verändert die Privacy-Eigenschaft.

## GNU Taler: anonymer Zahler, rechenschaftspflichtiger Händler

GNU Taler ist ein offenes elektronisches Zahlungsprotokoll, das traditionelle Währungen, Blind Signatures und die Integration mit regulierten Exchanges/Banken verwendet. Sein Design soll Kunden gegenüber Händlern anonym halten, während Händler identifizierbar und steuerpflichtig bleiben.<sup>[[4]](#references)</sup> Es ist keine Kryptowährung, und die Verfügbarkeit hängt von einer kompatiblen regionalen Exchange, Bank, Wallet und Händlerseite ab.

### Benutzer-Workflow, sofern verfügbar

1. Ermittle eine aktive Taler-Exchange und einen Händler in der relevanten Währung/Jurisdiktion. Lies deren aktuelle Bedingungen, Gebühren, KYC- und Datenschutzhinweise.
2. Installiere das offizielle Wallet und überprüfe seine Herkunft. Schütze Wallet-Backup-/Wiederherstellungsdaten wie Bargeld, da Wallet-Guthaben ein Inhaberwert sein kann.
3. Zahle den Wert über den unterstützten Bank-/Exchange-Ablauf mit wahrheitsgemäßen Angaben ein. Das Finanzinstitut bzw. die Exchange kann die Auszahlung kennen, auch wenn Blind Signatures die direkte Verknüpfung von Coin und Auszahlung aufheben.
4. Prüfe den Händlervertrag im Wallet: Händleridentität, Artikel/Zusammenfassung, Betrag, Gebühren, Erstattungs- und Lieferbedingungen.
5. Bezahle und bewahre die für Erstattung, Garantie, Buchhaltung oder Steuern erforderlichen Belegdaten auf.
6. Verwende optionale Händler-Session-/Account-Identifier nicht erneut, wenn die Unverknüpfbarkeit gegenüber dem Händler erforderlich ist.
7. Berücksichtige Wallet-, Netzwerk- und Liefermetadaten im Threat Model. Die Zahlungskryptografie von Taler verbirgt weder eine Lieferadresse noch ein kompromittiertes Endpoint.

Händler und Exchange bleiben rechenschaftspflichtig, und der Betrieb einer dieser Komponenten kann eine regulierte Zahlungsdienstaktivität darstellen.

## Federated Chaumian e-cash

Chaumian e-cash verwendet Blind Signatures, sodass eine Mint ein Token signiert, ohne das später ausgegebene unblinded Token zu sehen. Fedimint verteilt die Verwahrung von Reserven und das Signieren auf eine Guardian-Federation. Laut Dokumentation sehen Guardians aggregierte Reserven/ausstehende Notes, sollten jedoch weder individuelle Guthaben noch sehen, wer innerhalb der Federation wen bezahlt hat.<sup>[[5]](#references)</sup>

Dies ist **verwahrter Inhaberwert**. Ein ausreichendes Guardian-Quorum kontrolliert die Reserven; Ausfall der Federation, unehrliche Guardians, Softwarefehler oder verlorener Client-Zustand können zu Verlusten führen. Einzahlungen, Auszahlungen und Lightning-Gateways sind sichtbare Grenzereignisse und können Zeitpunkt/Betrag korrelieren.

### Workflow mit begrenztem Risiko

1. Verwende nur einen kleinen Betrag, dessen Verlust du verkraften kannst. Betrachte öffentliche/unbekannte Federations als risikoreicher als Guardians mit realer Verantwortlichkeit.
2. Überprüfe die Federation-Einladung über einen authentifizierten Kanal und dokumentiere Guardian-Identitäten, Quorum, Jurisdiktion, Gebühren, Wiederherstellung und Abschaltregeln.
3. Installiere ein gepflegtes, kompatibles Wallet, überprüfe es und verstehe dessen Backup-Schema, bevor du einzahlst.
4. Zahle rechtmäßig erworbenes Bitcoin über den dokumentierten Pfad ein. Dokumentiere den Peg-in für die Buchhaltung und gehe davon aus, dass Zeitpunkt/Betrag an der Grenze öffentlich oder bekannt sind.
5. Verwende innerhalb der Federation neue Zahlungsanfragen und vermeide Account-/Chat-/Liefer-Identifier, die die durch die Blind Signature entfernte Verknüpfung wiederherstellen.
6. Behandle das Gateway bei Lightning-Zahlungen als zusätzlichen Beobachter von Invoices und dem Zeitpunkt der Grenzereignisse.
7. Löse gemäß den Regeln ein bzw. zahle aus und rechne damit, dass ein auffälliger Betrag und ein unmittelbarer Zeitpunkt mit einer Einzahlung oder externen Zahlung korrelieren können.
8. Bewahre Steuer-/Herkunfts-/Autorisierungsaufzeichnungen privat auf. Bitte Guardians oder Gateways nicht, Aktivitäten falsch darzustellen.

Beschreibe Federated e-cash nicht als trustless, self-custodial oder garantiert anonym.

## BOLT 12 Offers und route blinding

BOLT 12 Offers können wiederverwendbar sein, ohne eine stabile On-Chain-Adresse zu veröffentlichen, und können Blinded Paths verwenden, sodass ein Zahler die eindeutige Node-Identität bzw. den Pfad des Empfängers nicht erfahren muss. Dies ergänzt das bestehende Onion Routing von Lightning, ersetzt es jedoch nicht.

Vor der Verwendung:

1. Bestätige, dass Sender- und Empfänger-Wallet dieselben aktuellen BOLT-12-Features unterstützen. Leite Unterstützung nicht aus einem allgemeinen „Lightning“-Branding ab.
2. Authentifiziere das Offer out of band und überprüfe Betrag, Aussteller/Beschreibung und Wiederholungsregeln.
3. Verwende einen neuen Invoice-/Zahlungskontext, der aus dem Offer erzeugt wurde.
4. Halte Node-Aliase, öffentliche Kontaktinformationen und stabile Netzwerk-Endpoints auf ein Minimum beschränkt.
5. Gehe davon aus, dass Sender/Empfänger, erster/letzter Hop, Wallet-Dienst, Channel-Graph und On-Chain-Funding/-Schließung weiterhin Teile der Beziehung offenlegen.

## Auditierbarkeit ohne öffentliche Offenlegung

Privacy und Audit können nebeneinander bestehen:

- Bewahre Labels, Rechnungen, Autorisierung, Anschaffungskosten und Eigentumszuordnung verschlüsselt außerhalb des öffentlichen Protokolls auf.
- Trenne einen **View-/Audit-Key** von einem Spending Key, wenn das Protokoll einen solchen bereitstellt; teste zunächst an einem Beispiel-Wallet die genaue Offenlegung.
- Gib einem Auditor nur den minimal erforderlichen, begrenzten Nachweis und niemals einen Seed oder ein uneingeschränktes Spending Credential.
- Dokumentiere zum Transaktionszeitpunkt Softwareversion, Protokoll/Pool, Transaktions-ID oder Proof, Zweck der Gegenpartei und Quelle des Wechselkurses.
- Definiere Aufbewahrung und Löschung, anstatt einen permanenten unverschlüsselten Identitätsgraphen aufzubauen.

## Auswahl-Checkliste

- [ ] Das verborgene Feld und der Beobachter sind präzise benannt.
- [ ] Die Unterstützung durch Wallet/Protokoll wurde zum Transaktionsdatum überprüft.
- [ ] Verknüpfungen zu Beschaffung, Netzwerk, Node/RPC, Gegenpartei, Lieferung und späterem Ausgeben sind dokumentiert.
- [ ] Risiken in Bezug auf Verwahrung, Wiederherstellung, Liquidität, Solvenz von Issuer/Federation und Erstattungen werden akzeptiert.
- [ ] Erforderliche Identitäts-, Steuer-, Sanktions-, Herkunfts- und Organisationsaufzeichnungen bleiben korrekt.
- [ ] Ein kleiner End-to-End-Test einschließlich Wiederherstellung und Audit-Nachweis war erfolgreich.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Einheitliche Adressen](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Abgeschirmtes Orchard-Protokoll](https://zips.z.cash/zip-0224)
- [4] [GNU-Taler-Dokumentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Funktionsweise](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
