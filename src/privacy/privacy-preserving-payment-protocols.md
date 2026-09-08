# Datenschutzfreundliche Zahlungsprotokolle

{{#include ../banners/hacktricks-training.md}}

Fortgeschrittene Zahlungssysteme können den Zahler vor dem Händler verbergen, einen Empfänger oder Betrag aus einem öffentlichen Ledger verbergen oder verhindern, dass eine Mint die Auszahlung mit der Einlösung verknüpft. Dies sind unterschiedliche Eigenschaften. Keine davon löscht Aufzeichnungen über Beschaffung, Gerät, Netzwerk, Lieferung, Buchhaltung, Sanktionen oder Endgeräte.

Der [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) stellt für jede Zahlungsfamilie standardisierte Einträge für `Pros`, `Cons`, eine schrittweise `Procedure` und `Detection` bereit. Diese Seite behandelt die fortgeschrittenen Protokolle ausführlicher.

{% hint style="danger" %}
Verwende ausschließlich rechtmäßige Gelder und Vertragspartner. Verwende Privacy-Protokolle nicht, um erforderliche Identifizierung, Sanktionen, Steuern, Prüfungen der Mittelherkunft oder Transaktionsmeldungen zu umgehen. Betreibe keine Börse, Mint oder Übertragungsdienst, ohne die Pflichten in Bezug auf Lizenzen, Verwahrung, AML und Verbraucherschutz zu verstehen.
{% endhint %}

## Vergleich der fortgeschrittenen Optionen

| Protokoll | Was vor Öffentlichkeit/Händler verborgen wird | Vertrauenswürdige oder beobachtende Partei | Reifegrad/Verfügbarkeit |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Außenstehende können einen wiederverwendbaren Zahlungscode nicht mit seinen einmaligen Outputs verknüpfen | Der öffentliche Bitcoin-Graph bleibt bestehen; Wallet-/Index-Server können Scans sehen | Spezifikation vollständig; Wallet-Unterstützung unterschiedlich |
| Zcash vollständig abgeschirmtes Orchard | Sender, Empfänger und Betrag sind on-chain verschlüsselt | Wallet-Backend/Netzwerk sowie Beschaffung und Off-Ramp bleiben sichtbar | Eingesetzt; Unterstützung für Shielding variiert je nach Wallet/Exchange |
| GNU Taler | Der Händler muss die Identität des Zahlers nicht erfahren; Händlereinnahmen bleiben nachvollziehbar | Taler-Exchange/Bank sieht die Finanzierung; Händler sieht die Bestellung | Deployments sind geografisch begrenzt |
| Föderiertes Chaumian e-cash | Die Föderation sollte ausgestellte Notes nicht mit internen Transfers/Einlösungen verknüpfen | Guardian-Quorum verwahrt Reserven; Gateways sehen Aktivitäten an den Grenzen | Aufkommende Community-Deployments |
| Lightning BOLT 12/route blinding | Reduziert die Offenlegung von Empfänger/Node und Route | Endpunkte, ausgewählte Hops, Funding-Chain und Wallet-Dienste | Unterstützung ist Wallet-abhängig |
| Virtuelle Karte/Token | Der Händler erhält ein eingeschränktes Credential statt einer wiederverwendbaren PAN | Herausgeber/Netzwerk behalten Zahler und Transaktion | Ausgereift und weit verbreitet |

## Bitcoin Silent Payments (BIP 352)

Silent Payments ermöglichen es einem Empfänger, einen statischen Zahlungscode zu veröffentlichen, während jeder Sender einen eindeutigen Taproot-Output ableitet. Ein externer Chain-Beobachter kann diese Outputs nicht direkt mit dem veröffentlichten Code verknüpfen, und es ist weder eine interaktive Adressanfrage noch ein on-chain-Benachrichtigungs-Output erforderlich. BIP 352 ist als **Complete** gekennzeichnet, führt jedoch Scan-Kosten ein und ist mit Wallets inkompatibel, die es nicht implementiert haben.<sup>[[1]](#references)</sup>

### Workflow des Empfängers

1. Wähle ein gepflegtes Wallet, das den Empfang mit BIP 352 ausdrücklich unterstützt; überprüfe die Funktion anhand der aktuellen Wallet-Dokumentation und nicht anhand einer Behauptung in sozialen Medien.
2. Sichere den Wallet-Seed sowie das Material für Silent-Payment-Deskriptoren/Schlüssel mit der dokumentierten Wiederherstellungsmethode des Wallets. Teste die Erkennung mit einem kleinen Testnet-/Mainnet-Betrag, bevor du den Code veröffentlichst.
3. Erzeuge separate **Labels** für Kampagnen, Rechnungen oder Vertragspartner, sofern das Wallet BIP-352-Labels unterstützt. Labels erleichtern die lokale Buchhaltung, ohne verknüpfbare Adressen zu veröffentlichen.
4. Veröffentliche den statischen Silent-Payment-Code über einen authentifizierten Kanal. Er ist wiederverwendbar, aber ein Angreifer kann seinen eigenen Code einschleusen.
5. Führe Scans nach Möglichkeit über einen lokalen Full Node durch. Ein Drittanbieter-Index-/Scanning-Server kann Anfragezeitpunkte oder Filterdaten erfahren, selbst wenn er nicht ausgeben kann.
6. Behalte entdeckte UTXOs mit Labels versehen und wende dieselben Coin-Control-Regeln wie bei gewöhnlichem Bitcoin an. Ihr Ausgeben oder Konsolidieren kann Besitzbeziehungen offenlegen.
7. Bestätige, dass die Wiederherstellung Zahlungen erkennt, ohne auf einen nicht gesicherten externen Index angewiesen zu sein.

### Workflow des Senders

1. Bestätige, dass das Wallet das Senden an die Adressversion unterstützt, und authentifiziere den langen statischen Code des Empfängers.
2. Lass das Wallet den Output erstellen; konvertiere oder kürze den Code niemals manuell.
3. Überprüfe die ausgewählten Inputs sorgfältig. Silent Payments verbessern die Privatsphäre der Empfängeradresse, aber Sender-Inputs bleiben im öffentlichen Graphen sichtbar.
4. Verwende die vom Wallet unterstützten Verfahren für Fee Bumping/PSBT. BIP 352 erfordert eine erneute Ableitung der Outputs, wenn sich Inputs ändern, und manche Signing-Modi sind unsicher.
5. Bewahre einen verschlüsselten Beleg oder Nachweis auf, der für Streitfälle oder die Buchhaltung erforderlich ist.

Silent Payments lösen das Problem der wiederholten Veröffentlichung von Empfängeradressen. Sie verbergen weder Betrag, Transaktionszeitpunkt, Sender-Cluster, Beschaffungshistorie noch späteres gemeinsames Ausgeben.

## Zcash vollständig abgeschirmte Zahlungen

Zcash unterstützt transparente und abgeschirmte Value Pools. Abgeschirmte Orchard-Transaktionen verwenden Zero-Knowledge-Proofs, sodass Nodes die Gültigkeit prüfen können, während Transaktionsdetails verschlüsselt sind; Unified Addresses können mehrere Empfängertypen enthalten.<sup>[[2]](#references)</sup> Die Privatsphäre hängt vom tatsächlich vom Wallet gewählten Pfad ab, nicht vom ersten Zeichen einer angezeigten Adresse.

### Abgeschirmter Workflow

1. Wähle ein gepflegtes Wallet, das sein Verhalten **shielded-by-default** und die aktuelle Orchard-Unterstützung eindeutig ausweist. Überprüfe den Download und sichere/teste den Seed.
2. Beschaffe ZEC rechtmäßig und dokumentiere Grundlage/Herkunft. Eine Exchange kennt die Beschaffung und Auszahlung weiterhin.
3. Empfange an eine vom Wallet unterstützte Unified Address und prüfe anschließend, ob die Transaktion in einem abgeschirmten Pool gelandet ist. Gehe nicht ohne Bestätigung des Wallet-Verhaltens von automatischem Shielding aus.
4. Bevorzuge **shielded-to-shielded**-Transfers. Bewegungen von transparent zu abgeschirmt und von abgeschirmt zu transparent legen öffentliche Werte/Zeitpunkte offen und können eine Betragskorrelation ermöglichen; die Orchard-Spezifikation weist darauf hin, dass das Ausgeben an eine Nicht-Orchard-Adresse den Transaktionswert offenlegt.<sup>[[3]](#references)</sup>
5. Vermeide charakteristische Transaktionen mit exakten Beträgen und unmittelbare Grenzüberschreitungen. Dies ist Privacy-Hygiene und keine Erlaubnis, Besitz oder Meldepflichten zu verschleiern.
6. Verwende den vom Wallet unterstützten Network-Privacy-Pfad. Abgeschirmte Kryptografie verbirgt IP-Adresse/Zeitpunkte nicht vor Wallet-Servern oder Peers.
7. Bewahre interne Compliance-Aufzeichnungen auf und verwende Viewing Keys nur für bewusst geplante Prüfungen/Offenlegungen, nachdem du deren Umfang verstanden hast.
8. Bestätige vor dem Senden die Unterstützung des Empfänger-Wallets bzw. der Exchange; ein erzwungener transparenter Empfänger verändert die Privacy-Eigenschaft.

## GNU Taler: anonymer Zahler, verantwortlicher Händler

GNU Taler ist ein offenes elektronisches Zahlungsprotokoll, das traditionelle Währungen, Blind Signatures und die Integration regulierter Exchanges/Banken verwendet. Das Design zielt darauf ab, Kunden gegenüber Händlern anonym zu halten, während Händler identifizierbar und steuerpflichtig bleiben.<sup>[[4]](#references)</sup> Es ist keine Kryptowährung, und die Verfügbarkeit hängt von einer kompatiblen regionalen Exchange, Bank, Wallet und Händlerumgebung ab.

### Benutzer-Workflow, sofern verfügbar

1. Identifiziere eine aktive Taler-Exchange und einen Händler in der relevanten Währung/Jurisdiktion; lies deren aktuelle Bedingungen, Gebühren, KYC- und Datenschutzhinweise.
2. Installiere das offizielle Wallet und überprüfe dessen Quelle. Schütze Wallet-Backup-/Wiederherstellungsdaten wie Bargeld, da der Wallet-Wert ein Bearer Asset sein kann.
3. Hebe den Wert über den unterstützten Bank-/Exchange-Ablauf mit wahrheitsgemäßen Angaben ab. Das finanzierende Institut bzw. die Exchange kann die Auszahlung kennen, obwohl Blind Signatures die direkte Verbindung zwischen Coin und Auszahlung aufbrechen.
4. Prüfe den Händlervertrag im Wallet: Händleridentität, Artikel/Zusammenfassung, Betrag, Gebühren, Erstattung und Lieferbedingungen.
5. Bezahle und bewahre die für Erstattung, Garantie, Buchhaltung oder Steuern erforderlichen Belegdaten auf.
6. Verwende optionale Händler-Session-/Kontokennungen nicht erneut, wenn die Unverknüpfbarkeit gegenüber dem Händler erforderlich ist.
7. Berücksichtige Wallet-, Netzwerk- und Liefermetadaten im Threat Model; die Zahlungs-Kryptografie von Taler verbirgt weder eine Lieferadresse noch ein kompromittiertes Endgerät.

Händler und Exchange bleiben rechenschaftspflichtig, und der Betrieb einer dieser Komponenten kann eine regulierte Zahlungsdienstaktivität darstellen.

## Föderiertes Chaumian e-cash

Chaumian e-cash verwendet Blind Signatures, sodass eine Mint einen Token signiert, ohne den später ausgegebenen unblinded Token zu sehen. Fedimint verteilt die Verwahrung der Reserven und das Signing über eine Guardian-Föderation; laut Dokumentation sehen Guardians aggregierte Reserven/ausstehende Notes, sollten aber weder einzelne Salden noch sehen, wer innerhalb der Föderation an wen bezahlt hat.<sup>[[5]](#references)</sup>

Dies ist **verwahrtes Bearer Value**. Ein ausreichendes Guardian-Quorum kontrolliert die Reserven; Ausfall der Föderation, unehrliche Guardians, Softwarefehler oder verlorener Client-State können zu Verlusten führen. Einzahlungen, Auszahlungen und Lightning-Gateways sind sichtbare Ereignisse an den Grenzen und können Zeitpunkte/Beträge korrelieren.

### Workflow mit begrenztem Risiko

1. Verwende nur einen kleinen Betrag, dessen Verlust du verkraften kannst. Behandle öffentliche/unbekannte Föderationen als riskanter als Guardians mit realer Verantwortlichkeit.
2. Überprüfe die Föderationseinladung über einen authentifizierten Kanal und dokumentiere Guardian-Identitäten, Quorum, Jurisdiktion, Gebühren, Wiederherstellung und Abschaltregeln.
3. Installiere ein gepflegtes, kompatibles Wallet, überprüfe es und verstehe dessen Backup-Verfahren, bevor du einzahlst.
4. Zahle rechtmäßig beschafftes Bitcoin über den dokumentierten Pfad ein. Dokumentiere den Peg-in für die Buchhaltung und gehe davon aus, dass dessen Zeitpunkt/Betrag an der Grenze öffentlich oder bekannt ist.
5. Verwende innerhalb der Föderation frische Zahlungsanfragen und vermeide Konto-/Chat-/Lieferkennungen, die die durch die Blind Signature entfernte Verbindung wiederherstellen.
6. Behandle das Gateway bei Lightning-Zahlungen als zusätzlichen Beobachter von Rechnungen und Zeitpunkten an der Grenze.
7. Löse gemäß den Regeln ein bzw. zahle aus und rechne damit, dass ein charakteristischer Betrag und ein unmittelbarer Zeitpunkt mit einer Einzahlung oder externen Zahlung korrelieren können.
8. Bewahre Steuer-/Herkunfts-/Autorisierungsaufzeichnungen privat auf; bitte Guardians oder Gateways nicht darum, Aktivitäten falsch darzustellen.

Bezeichne föderiertes e-cash nicht als trustless, self-custodial oder garantiert anonym.

## BOLT 12 Offers und route blinding

BOLT 12 Offers können wiederverwendbar sein, ohne eine stabile on-chain-Adresse zu veröffentlichen, und können blinded paths verwenden, sodass ein Zahler die eindeutige Node-Identität bzw. den Pfad des Empfängers nicht erfahren muss. Dies ergänzt das bestehende Onion Routing von Lightning, ersetzt es jedoch nicht.

Vor der Verwendung:

1. Bestätige, dass die Wallets von Sender und Empfänger dieselben aktuellen BOLT-12-Funktionen unterstützen; leite die Unterstützung nicht aus einem allgemeinen „Lightning“-Branding ab.
2. Authentifiziere das Offer out of band und prüfe Betrag, Herausgeber/Beschreibung und Wiederholungsregeln.
3. Verwende einen frischen, aus dem Offer erzeugten Invoice-/Zahlungskontext.
4. Halte Node-Aliase, öffentliche Kontaktinformationen und stabile Netzwerkendpunkte auf ein Minimum beschränkt.
5. Gehe davon aus, dass Sender/Empfänger, erster/letzter Hop, Wallet-Dienst, Channel-Graph sowie on-chain Funding/Closure weiterhin Teile der Beziehung offenlegen.

## Auditierbarkeit ohne öffentliche Offenlegung

Privacy und Audit können koexistieren:

- Bewahre Labels, Rechnungen, Autorisierung, Anschaffungskosten und Besitzzuordnung verschlüsselt außerhalb des öffentlichen Protokolls auf.
- Trenne einen **View-/Audit-Key** von einem Spending Key, wenn das Protokoll dies ermöglicht; teste dessen genaue Offenlegung zuerst an einem Beispiel-Wallet.
- Gib einem Auditor nur den minimal erforderlichen, begrenzten Nachweis und keinen Seed oder uneingeschränkten Spending Credential.
- Dokumentiere zum Transaktionszeitpunkt Softwareversion, Protokoll/Pool, Transaktions-ID oder Proof, Zweck des Vertragspartners und Quelle des Wechselkurses.
- Definiere Aufbewahrung und Löschung, statt einen dauerhaft unverschlüsselten Identitätsgraphen anzusammeln.

## Auswahl-Checkliste

- [ ] Das verborgene Feld und der Beobachter sind präzise benannt.
- [ ] Die Wallet-/Protokollunterstützung wurde zum Transaktionsdatum überprüft.
- [ ] Verbindungen zu Beschaffung, Netzwerk, Node/RPC, Vertragspartner, Lieferung und späterem Ausgeben sind dokumentiert.
- [ ] Risiken durch Verwahrung, Wiederherstellung, Liquidität, Solvenz von Herausgeber/Föderation und Erstattungen werden akzeptiert.
- [ ] Erforderliche Identitäts-, Steuer-, Sanktions-, Herkunfts- und Organisationsaufzeichnungen bleiben korrekt.
- [ ] Ein kleiner End-to-End-Test einschließlich Wiederherstellung und Audit-Nachweis war erfolgreich.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Abgeschirmtes Orchard-Protokoll](https://zips.z.cash/zip-0224)
- [4] [GNU-Taler-Dokumentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Funktionsweise](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
