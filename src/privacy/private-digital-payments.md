# Private digitale Zahlungen

Zahlungsdatenschutz ist die kontrollierte Offenlegung von Transaktionsdaten. Er ist kein Mittel, um illegale Gelder zu legitimieren, Steuern oder Sanktionen zu umgehen, KYC zu umgehen, falsche Identitäten zu verwenden oder eine nicht autorisierte Beauftragung zu verbergen. Eine Zahlung kann gegenüber einem Händler privat bleiben, während sie für einen Herausgeber, ein Netzwerk, einen Arbeitgeber, eine Steuerbehörde oder einen Ermittler vollständig sichtbar ist.

Der [Katalog für anonyme Zahlungstechniken](anonymous-payment-techniques.md) ist das standardisierte Verzeichnis mit `Pros`, `Cons`, einer rechtmäßigen schrittweisen `Procedure` und `Detection` für jede Kategorie. Diese Seite erweitert die Beschreibung herkömmlicher Zahlungsmethoden.

{% hint style="danger" %}
Verwende niemals gestohlene Konten, synthetische Identitäten, Finanzagenten, fiktive Angaben zum Wohnsitz oder zur Mittelherkunft, Transaktionsaufteilung („structuring“) oder undurchsichtige Vermittler für „No-KYC-Karten“. Prüfe das geltende Recht und die Anbieterbedingungen in jeder relevanten Rechtsordnung.
{% endhint %}

## Die Datenschutzeigenschaft definieren

Bestimme den Beobachter, bevor du einen Zahlungsweg auswählst:

| Beobachter | Typische Daten | Nützliche Kontrolle | Was weiterhin bestehen bleibt |
|---|---|---|---|
| Händler | Name, E-Mail-Adresse, Adresse, Kartentoken, IP/Gerät, Warenkorb | Gastzahlung, möglichst wenige optionale Daten, händlerspezifische virtuelle Karte | Lieferung, Konto- und Betrugs-Telemetrie |
| Herausgeber/Zahlungsabwickler | Rechtliche Identität, Finanzierungsquelle, Händler, Betrag, Zeitpunkt, Gerät | Auswahl eines regulierten Anbieters mit guten Datenschutz-/Sicherheitsbedingungen | Der Anbieter verarbeitet die Daten weiterhin und kann Aufzeichnungen speichern oder offenlegen |
| Arbeitgeber/Auftraggeber | Ausgabe, Betreiber und Zweck | Separates Auftragsbudget und zugriffskontrolliertes Ledger | Eine rechtmäßige Governance erfordert interne Zuordnung |
| Beobachter einer öffentlichen Blockchain | Adressen, Zahlungsflüsse, Beträge und Zeit, abhängig von der Chain | Geeignetes Protokoll und angemessene Wallet-Disziplin | Erwerb, Endpunkte und spätere Ausgaben können Aktivitäten erneut verknüpfen |
| Netzwerk-/RPC-/Node-Betreiber | IP, Wallet-Abfragen, Transaktionsübertragungen | Lokaler Node oder geeignetes Privacy-Netzwerk | Zeitverhalten und Endpunktverhalten können weiterhin korrelieren |
| Physischer Beobachter | Gesicht, Standort, Fahrzeug, CCTV, Quittung | Gewöhnlicher situativer Datenschutz | Bargeld macht eine Person physisch nicht unsichtbar |

Die CFPB beschreibt Payment-Apps als in der Lage, Identitäts-, Geräte-, Standort-, Kontakt-, Transaktions- und Verhaltensdaten zu erfassen; Datenschutzregeln der Bundesstaaten verhindern nicht zwangsläufig die Monetarisierung oder jede sekundäre Nutzung.<sup>[[1]](#references)</sup> Lies den tatsächlichen Datenschutzhinweis des Anbieters, statt aus einem Produktnamen auf Datenschutz zu schließen.

## Zahlungsmethoden vergleichen

| Methode | Datenschutzvorteil | Wichtigste Beobachter/Verknüpfungen | Geeignete Verwendung |
|---|---|---|---|
| Bargeld | Kein Ledger des Zahlungsnetzwerks | Empfänger, Kameras, Zeugen, Vorschriften zur Bargeldmeldung | Rechtmäßige lokale Einkäufe, sofern akzeptiert |
| Open-Loop-Prepaid-/Geschenkkarte | Trennt die Kartennummer von einer Hauptkarte | Verkäufer, Aktivierungs-/Registrierungsanbieter, Finanzierungsquelle, Händler | Budgetierung oder begrenzte Abschottung gegenüber Händlern |
| Virtuelle/Einmal-Kartennummer | Verbirgt die wiederverwendbare PAN vor dem Händler; einfache Sperrung | Der Herausgeber kennt Identität und Transaktion weiterhin | Abschottung von Online-Händlern |
| Mobile-Wallet-Token | Gerät/Händler erhält einen Token statt der zugrunde liegenden PAN | Wallet-Anbieter, Herausgeber, Zahlungsnetzwerk und Händler | Schutz von Zugangsdaten, nicht Anonymität |
| Banküberweisung/App | Bequemer Prüfpfad | Bank/App, Gegenpartei und verknüpfte Identität | Verantwortbare organisatorische Zahlungen |
| Kryptowährung | Variiert je nach Protokoll; Self-Custody kann die Abhängigkeit vom Verwahrer reduzieren | Öffentliches Ledger oder Privacy-Protokoll, Exchange, Endpunkt, Gegenpartei | Rechtmäßige Übertragungen nach einer protokollspezifischen Analyse |

## Bargeld

Bargeld wird weiterhin als wichtig für Datenschutz und Teilhabe angesehen und vermeidet einen Datensatz im Zahlungsnetzwerk.<sup>[[2]](#references)</sup> Es verhindert weder CCTV, Zeugen, Gerätestandort, Quittungen, die Nachverfolgung von Seriennummern in besonderen Fällen noch gesetzliche Meldepflichten.

### Rechtmäßiger Ablauf

1. Prüfe vor der Transaktion die Akzeptanz und die örtlichen Bargeldgrenzen. Die Grenzen unterscheiden sich nach Land und Art der Partei und ändern sich im Laufe der Zeit.
2. Führe den gewöhnlichen Kauf in einer einzigen ehrlichen Transaktion durch. **Teile ihn niemals auf**, um einen Schwellenwert oder eine Meldung zu vermeiden.
3. Lehne optionale Kundenbindungs- oder Marketingerfassung ab. Gib für Garantie, Sicherheit, Lieferung, Steuern oder gesetzliche Vorgaben erforderliche Daten wahrheitsgemäß an.
4. Bewahre notwendige Kaufnachweise und vorgeschriebene Buchhaltungsunterlagen in verschlüsseltem Speicher mit einem Löschdatum auf.
5. Erstatte Ausgaben für eine Organisation über den genehmigten Prozess und erfasse Betreiber, Genehmigung, Zweck, Betrag, Datum und Quittung.

In den Vereinigten Staaten reichen bestimmte Gewerbetreibende oder Unternehmen das Formular 8300 für Bareinnahmen über 10.000 US-Dollar ein, einschließlich zusammenhängender Transaktionen; das absichtliche Aufteilen von Transaktionen kann selbst ein rechtswidriges Structuring darstellen.<sup>[[3]](#references)</sup> Andere Rechtsordnungen unterscheiden sich—Spanien veröffentlicht beispielsweise seine eigene gesetzliche Beschränkung von Barzahlungen.<sup>[[4]](#references)</sup>

## Prepaid- und Geschenkkarten

„Prepaid“ bedeutet nicht anonym. Ein Geschäft, Herausgeber, Programmbetreiber, eine finanzierende Bank und ein Händler können Kauf, Aktivierung, Gerät, IP, Standort und Ausgaben korrelieren. Aufladungen, ATM-Zugriff, internationale Nutzung, höhere Limits oder Schutz bei Verlust erfordern üblicherweise eine Registrierung.

US-Verbraucherinformationen erklären, dass Herausgeber Identitätsdaten zur rechtlichen Überprüfung anfordern und eine registrierte Karte ablehnen können, wenn die Überprüfung fehlschlägt.<sup>[[5]](#references)</sup> Die FinCEN-Regeln legen fest, welche Prepaid-Programme und Beteiligten AML-Pflichten haben.<sup>[[6]](#references)</sup> In der EU wurden die engen Ausnahmen für anonymes E-Geld durch die Richtlinie (EU) 2018/843 eingeschränkt; die Verordnung (EU) 2024/1624 ändert den Rahmen erneut, gilt aber allgemein erst ab dem **10. Juli 2027**. Beschreibe sie daher 2026 nicht als bereits geltend.<sup>[[7]](#references)</sup>

Verwende Prepaid-Guthaben nur, wenn es rechtmäßig von einem identifizierbaren Herausgeber erworben wurde, dessen Bedingungen die beabsichtigte Nutzung erlauben und der Zweck in der Budgetierung oder der Trennung von einer primären Zahlungszugangsdaten besteht. Vermeide Wiederverkaufsmärkte und Vermittler, die nicht überprüfbare „No-Name“-Karten anbieten: Das Guthaben kann gestohlen, bereits eingelöst, geografisch beschränkt oder beschlagnahmbar sein.

## Virtuelle Karten und Wallet-Tokens

Eine virtuelle Kartennummer (VCN) wird normalerweise hinter einem echten, verifizierten Konto ausgegeben. Händlerspezifische oder einmalige Nummern reduzieren das Risiko von Datenlecks und die händlerübergreifende PAN-Korrelation; sie verbergen die Transaktion jedoch **nicht** vor dem Herausgeber. Die Tokenisierung des Netzwerks ersetzt eine Kartenzugangsdaten ebenfalls durch einen eingeschränkten Token.<sup>[[8]](#references)</sup>

### Händlerspezifischer Ablauf

1. Eröffne ein Konto bei einem regulierten Herausgeber und verwende genaue Identitäts-, Wohnsitz- und Finanzierungsdaten.
2. Sichere es mit einem einzigartigen Passwort, phishing-resistenter MFA, sofern verfügbar, Anmeldebenachrichtigungen und offline gespeicherten Wiederherstellungscodes.
3. Erzeuge eine händlergebundene oder einmalige VCN. Lege, sofern unterstützt, ein angemessenes Betrags-/Zeitlimit fest.
4. Verwende die Gastzahlung und lasse nur **optionale** Profil-, Kundenbindungs- und Marketingfelder aus. Gib erforderliche Rechnungs-, Liefer- und Steuerdaten korrekt an.
5. Vermeide die Anmeldung bei nicht verwandten Identitätsanbietern; verwende eine Browser-Abschottung für Auftrag/Konto und den genehmigten Netzwerkpfad.
6. Speichere die Quittung und die Zuordnung von VCN zu Zweck in einem verschlüsselten internen Ledger.
7. Sperre oder widerrufe die Nummer nach Ablauf des Erstattungs-/Chargeback-Zeitraums und überwache das übergeordnete Konto auf unerwartete Autorisierungen.

Capital One und Google dokumentieren, dass virtuelle Nummern weiterhin mit dem zugrunde liegenden Konto verbunden sind, während EMVCo/Visa Tokenisierung als Ersetzung von Zugangsdaten und Domänenbeschränkung und nicht als Anonymität des Zahlers beschreiben.<sup>[[8]](#references)</sup>

## Lieferung, Konten und Erstattungen

Die Zahlung ist nur eine Kante im Verknüpfungsgraphen:

- Eine einzigartige Karte wird durch die Wiederverwendung einer persönlichen E-Mail-Adresse, Telefonnummer, eines Browserprofils, einer IP-Adresse oder eines Kundenkontos entwertet.
- Für eine physische Lieferung werden normalerweise ein rechtmäßiger Empfänger und ein Standort benötigt. Verwende nicht die Adresse einer unbeteiligten Person und gib dich nicht als Bewohner aus. Genehmigte geschäftliche Empfangsdienste sind sicherer als erfundene Angaben.
- Digitale Güter können Kontenidentität, IP, Geräte-Fingerprint, Lizenzaktivierung und Downloads protokollieren.
- Erstattungen werden üblicherweise über den ursprünglichen Zahlungsweg zurückgeführt. Aufforderungen, Gelder zu empfangen und sie anderweitig weiterzuleiten oder zu erstatten, sind ein Warnsignal für Betrug und Finanzagenten.
- Händlerbezeichnungen, Rechnungstexte und Versandbenachrichtigungen können einen sensiblen Kauf gegenüber Kontodelegierten offenlegen; lege Zugriff und Benachrichtigungen bewusst fest.

## Autorisierte Red-Team-Käufe

Ein Auftrag sollte nach außen diskret und intern rechenschaftspflichtig sein:

1. Hole einen schriftlich festgelegten Umfang, Zweck, Ausgabenhöchstbetrag, Genehmiger, zulässige Händler/Assets und Erstattungsregel ein.
2. Verwende ein von der Organisation kontrolliertes Zahlungskonto und eine separate VCN oder ein Unterkonto pro Auftrag oder Händler.
3. Halte korrekte Rechnungs- und Registrantendaten bei Anbietern vor. Der Datenschutz bei öffentlicher Registrierung kann die Offenlegung minimieren, ist aber keine Erlaubnis zu lügen.
4. Führe ein verschlüsseltes Ledger mit Betreiber, Genehmigung, Zweck, Datum, Betrag, Gegenpartei, Asset-Kennung und Quittung.
5. Überprüfe Gegenparteien wie erforderlich und befolge Anbieter-, Sanktions-, Steuer- und Meldepflichten.
6. Gib der Finanzabteilung nur den benötigten Zugriff und den Betreibern nur die benötigte begrenzte Ausgabenbefugnis.
7. Schließe oder sperre Zahlungszugangsdaten während der Stilllegung, gleiche ausstehende Belastungen/Erstattungen ab und bewahre Aufzeichnungen gemäß den Richtlinien auf.

Für kryptospezifische Entscheidungen fahre mit [Cryptocurrency Privacy](cryptocurrency-privacy.md) fort. Für die Infrastruktur, die diese Käufe unterstützt, siehe [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Verifizierungscheckliste

- [ ] Die gewünschte Datenschutzeigenschaft und die Beobachter sind schriftlich festgehalten.
- [ ] Anbieter-, Händler- und Rechtsordnungsregeln wurden kürzlich geprüft.
- [ ] Angaben zu Identität und Mittelherkunft sind wahrheitsgemäß.
- [ ] Optionale Händlerdaten werden minimiert, ohne die erforderliche Überprüfung zu umgehen.
- [ ] Verknüpfungen von Finanzierung, Gerät, Netzwerk, Konto, Lieferung und Erstattung sind verstanden.
- [ ] Es sind keine Schwellenwertumgehung, verbotene Gegenpartei, Finanzagenten, gestohlenen Zugangsdaten oder Identität einer dritten Person beteiligt.
- [ ] Erforderliche Quittungen, Genehmigungen, Steuerunterlagen und Wiederherstellungsinformationen sind verschlüsselt und zugriffskontrolliert.

## References

- [1] [US CFPB — Informationsanfrage zur Erfassung, Nutzung und Monetarisierung von Verbraucherzahlungs- und anderen persönlichen Finanzdaten](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [Europäische Zentralbank — Studie zu den Zahlungsverhalten von Verbrauchern im Euroraum (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Anleitung zum Formular 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanische Steuerbehörde — Meldung von Barzahlungen](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Warum werde ich zur Aktivierung oder Registrierung einer Prepaid-Karte nach persönlichen Daten gefragt?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) und [Kann eine Prepaid-Karte abgelehnt werden?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Endgültige Regelung zum Prepaid-Zugriff](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Richtlinie (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Verwendung virtueller Kreditkarten](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
