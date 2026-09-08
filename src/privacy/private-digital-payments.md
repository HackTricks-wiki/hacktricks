# Private digitale Zahlungen

{{#include ../banners/hacktricks-training.md}}

Zahlungsprivatsphäre ist die kontrollierte Offenlegung von Transaktionsdaten. Sie ist keine Möglichkeit, illegale Gelder zu legitimieren, Steuern oder Sanktionen zu umgehen, KYC zu umgehen, falsche Identitäten zu verwenden oder eine nicht autorisierte Tätigkeit zu verbergen. Eine Zahlung kann für einen Händler privat sein und gleichzeitig für einen Kartenherausgeber, ein Netzwerk, einen Arbeitgeber, eine Steuerbehörde oder einen Ermittler vollständig sichtbar bleiben.

Der [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) ist das normalisierte Verzeichnis mit `Pros`, `Cons`, einer rechtmäßigen schrittweisen `Procedure` und `Detection` für jede Familie. Diese Seite erweitert konventionelle Zahlungsmethoden.

{% hint style="danger" %}
Verwende niemals gestohlene Konten, synthetische Identitäten, Geldkuriere, fingierte Angaben zum Wohnsitz oder zur Herkunft von Geldern, Transaktionsaufteilung („structuring“) oder undurchsichtige Vermittler für „No-KYC-Karten“. Prüfe das geltende Recht und die Anbieterbedingungen in jeder relevanten Rechtsordnung.
{% endhint %}

## Die Privatsphäreeigenschaft definieren

Bestimme den Beobachter, bevor du einen Zahlungsweg auswählst:

| Beobachter | Typische Daten | Sinnvolle Kontrolle | Was bleibt |
|---|---|---|---|
| Händler | Name, E-Mail-Adresse, Anschrift, Kartentoken, IP/Gerät, Warenkorb | Gast-Checkout, minimale optionale Daten, händlerspezifische virtuelle Karte | Lieferung, Konto- und Betrugs-Telemetrie |
| Kartenherausgeber/Zahlungsabwickler | Rechtliche Identität, Finanzierungsquelle, Händler, Betrag, Zeitpunkt, Gerät | Auswahl eines regulierten Anbieters mit guten Datenschutz-/Sicherheitsbedingungen | Der Anbieter verarbeitet die Daten weiterhin und kann Aufzeichnungen speichern oder offenlegen |
| Arbeitgeber/Auftraggeber | Ausgabe, Bearbeiter und Zweck | Getrenntes Auftragsbudget und zugriffsgesteuertes Hauptbuch | Eine rechtmäßige Governance erfordert interne Zuordnung |
| Öffentlicher Blockchain-Beobachter | Adressen, Zahlungsströme, Beträge und Zeitpunkte, abhängig von der Chain | Geeignetes Protokoll und sorgfältiger Umgang mit Wallets | Erwerb, Endpunkte und spätere Ausgaben können Aktivitäten wieder verknüpfen |
| Netzwerk-/RPC-/Node-Betreiber | IP, Wallet-Abfragen, Transaktionsübertragungen | Lokaler Node oder geeignetes Datenschutznetzwerk | Zeitliche Abläufe und Endpunktverhalten können weiterhin korrelieren |
| Physischer Beobachter | Gesicht, Standort, Fahrzeug, CCTV, Quittung | Gewöhnliche situative Privatsphäre | Bargeld macht eine Person physisch nicht unsichtbar |

Die CFPB beschreibt Payment-Apps als fähig, Identitäts-, Geräte-, Standort-, Kontakt-, Transaktions- und Verhaltensdaten zu erheben; Datenschutzvorschriften der Bundesstaaten verhindern nicht unbedingt die Monetarisierung oder jede sekundäre Nutzung.<sup>[[1]](#references)</sup> Lies den tatsächlichen Datenschutzhinweis des Anbieters, statt aus einem Produktnamen auf Datenschutz zu schließen.

## Zahlungsmethoden vergleichen

| Methode | Vorteil für die Privatsphäre | Hauptbeobachter/Verknüpfungen | Geeignete Verwendung |
|---|---|---|---|
| Bargeld | Kein Hauptbuch des Zahlungsnetzwerks | Empfänger, Kameras, Zeugen, Vorschriften zur Bargeldmeldung | Rechtmäßige lokale Käufe, sofern akzeptiert |
| Prepaid-/Geschenkkarte mit offenem Zahlungsnetzwerk | Trennt die Kartennummer von einer Hauptkarte | Verkäufer, Aktivierungs-/Registrierungsanbieter, Finanzierungsquelle, Händler | Budgetierung oder begrenzte Trennung nach Händlern |
| Virtuelle/Einmal-Kartennummer | Verbirgt die wiederverwendbare PAN vor dem Händler; einfache Sperrung | Der Kartenherausgeber kennt Identität und Transaktion weiterhin | Trennung von Online-Händlern |
| Mobile-Wallet-Token | Gerät/Händler erhält statt der zugrunde liegenden PAN ein Token | Wallet-Anbieter, Kartenherausgeber, Zahlungsnetzwerk und Händler | Schutz von Zugangsdaten, nicht Anonymität |
| Banküberweisung/App | Bequeme Prüfspur | Bank/App, Gegenpartei und verknüpfte Identität | Rechenschaftspflichtige organisatorische Zahlungen |
| Kryptowährung | Variiert je nach Protokoll; Self-Custody kann die Abhängigkeit von Verwahrern reduzieren | Öffentliches Hauptbuch oder Datenschutzprotokoll, Börse, Endpunkt, Gegenpartei | Rechtmäßige Übertragungen nach protokollspezifischer Analyse |

## Bargeld

Bargeld wird weiterhin als wichtig für Privatsphäre und Teilhabe angesehen und vermeidet einen Datensatz im Zahlungsnetzwerk.<sup>[[2]](#references)</sup> Es verhindert weder CCTV, Zeugen, Gerätestandort, Quittungen, die Nachverfolgung von Seriennummern in besonderen Fällen noch gesetzliche Meldepflichten.

### Rechtmäßiger Ablauf

1. Prüfe vor der Transaktion die Akzeptanz und die örtlichen Bargeldgrenzen. Die Grenzen unterscheiden sich je nach Land und Art der Partei und ändern sich im Laufe der Zeit.
2. Führe den gewöhnlichen Kauf in einer einzigen ehrlichen Transaktion durch. **Teile ihn niemals auf**, um einen Schwellenwert oder eine Meldung zu vermeiden.
3. Lehne optionale Kundenbindungs- oder Marketingerfassung ab. Stelle für Garantie, Sicherheit, Lieferung, Steuern oder gesetzliche Vorgaben erforderliche Daten wahrheitsgemäß bereit.
4. Bewahre notwendige Kaufnachweise und vorgeschriebene Buchhaltungsunterlagen verschlüsselt und mit einem Löschdatum auf.
5. Erstatte Auslagen in einer Organisation über den genehmigten Prozess und erfasse Bearbeiter, Genehmigung, Zweck, Betrag, Datum und Quittung.

In den Vereinigten Staaten reichen bestimmte Gewerbe oder Unternehmen das Formular 8300 für Bareinnahmen von über 10.000 US-Dollar ein, einschließlich verbundener Transaktionen; das absichtliche Aufteilen von Transaktionen kann selbst als rechtswidriges structuring gelten.<sup>[[3]](#references)</sup> Andere Rechtsordnungen unterscheiden sich – beispielsweise veröffentlicht Spanien eigene gesetzliche Beschränkungen für Barzahlungen.<sup>[[4]](#references)</sup>

## Prepaid- und Geschenkkarten

„Prepaid“ bedeutet nicht anonym. Ein Geschäft, Kartenherausgeber, Programmbetreiber, finanzierende Bank und Händler können Kauf, Aktivierung, Gerät, IP, Standort und Ausgaben korrelieren. Aufladungen, ATM-Zugriff, internationale Nutzung, höhere Limits oder Schutz bei Verlust erfordern üblicherweise eine Registrierung.

US-Verbraucherinformationen erklären, dass Kartenherausgeber Identitätsdaten zur gesetzlich vorgeschriebenen Verifizierung anfordern und eine registrierte Karte ablehnen können, wenn die Verifizierung fehlschlägt.<sup>[[5]](#references)</sup> Die FinCEN-Regeln legen fest, welche Prepaid-Programme und Teilnehmer AML-Pflichten haben.<sup>[[6]](#references)</sup> In der EU wurden die engen Ausnahmen für anonymes E-Geld durch die Richtlinie (EU) 2018/843 eingeschränkt; die Verordnung (EU) 2024/1624 ändert den Rahmen erneut, gilt jedoch grundsätzlich erst ab dem **10. Juli 2027**. Beschreibe sie daher 2026 nicht als bereits anwendbar.<sup>[[7]](#references)</sup>

Verwende Prepaid-Guthaben nur, wenn es rechtmäßig von einem identifizierbaren Herausgeber erworben wurde, dessen Bedingungen die beabsichtigte Nutzung erlauben und der Nutzen in Budgetierung oder der Trennung von einem primären Zahlungszugang liegt. Vermeide Wiederverkaufsmärkte und Vermittler, die nicht überprüfbare „No-Name“-Karten anbieten: Das Guthaben kann gestohlen, bereits eingelöst, geografisch beschränkt oder beschlagnahmungsgefährdet sein.

## Virtuelle Karten und Wallet-Tokens

Eine virtuelle Kartennummer (VCN) wird normalerweise hinter einem echten, verifizierten Konto ausgegeben. Händlerspezifische oder einmalig verwendbare Nummern verringern das Risiko von Datenleaks und die händlerübergreifende PAN-Korrelation; sie verbergen die Transaktion jedoch **nicht** vor dem Kartenherausgeber. Die Tokenisierung des Netzwerks ersetzt eine Karten-Zugangsinformation auf ähnliche Weise durch ein eingeschränktes Token.<sup>[[8]](#references)</sup>

### Händlerspezifischer Ablauf

1. Eröffne ein Konto bei einem regulierten Kartenherausgeber und verwende korrekte Identitäts-, Wohnsitz- und Finanzierungsdaten.
2. Sichere es mit einem einzigartigen Passwort, phishing-resistenter MFA, sofern verfügbar, Login-Warnungen und offline gespeicherten Wiederherstellungscodes.
3. Erzeuge eine händlergebundene oder einmalig verwendbare VCN. Lege, sofern unterstützt, ein angemessenes Betrags- oder Zeitlimit fest.
4. Verwende den Gast-Checkout und lasse nur **optionale** Profil-, Kundenbindungs- und Marketingfelder aus. Stelle erforderliche Rechnungs-, Liefer- und Steuerdaten korrekt bereit.
5. Vermeide die Anmeldung bei nicht verbundenen Identity Providern; verwende eine Browser-Trennung für Auftrag/Konto und den genehmigten Netzwerkpfad.
6. Speichere die Quittung und die Zuordnung von VCN zu Zweck in einem verschlüsselten internen Hauptbuch.
7. Friere die Nummer nach Ablauf des Erstattungs-/Chargeback-Zeitraums ein oder widerrufe sie; überwache das übergeordnete Konto auf unerwartete Autorisierungen.

Capital One und Google dokumentieren, dass virtuelle Nummern weiterhin an das zugrunde liegende Konto gebunden sind, während EMVCo/Visa Tokenisierung als Ersetzung von Zugangsdaten und Domänenbeschränkung und nicht als Anonymität des Zahlers beschreiben.<sup>[[8]](#references)</sup>

## Lieferungen, Konten und Erstattungen

Die Zahlung ist nur eine Kante im Verknüpfungsgraphen:

- Eine einzigartige Karte wird durch die Wiederverwendung einer persönlichen E-Mail-Adresse, Telefonnummer, eines Browserprofils, einer IP-Adresse oder eines Kundenkontos entwertet.
- Eine physische Lieferung erfordert normalerweise einen rechtmäßigen Empfänger und Standort. Verwende nicht die Adresse einer unbeteiligten Person und gib dich nicht als Bewohner aus. Genehmigte geschäftliche Empfangsdienste sind sicherer als erfundene Angaben.
- Digitale Waren können Kontoidentität, IP, Geräte-Fingerprint, Lizenzaktivierung und Downloads protokollieren.
- Erstattungen erfolgen gewöhnlich über den ursprünglichen Zahlungsweg. Aufforderungen, Geld zu empfangen und es anderweitig weiterzuleiten oder zu erstatten, sind ein Warnsignal für Betrug und Geldkuriertätigkeit.
- Händlerbezeichnungen, Rechnungstexte und Versandbenachrichtigungen können einen sensiblen Kauf gegenüber Kontodelegierten offenlegen; lege Zugriffe und Warnungen bewusst fest.

## Autorisierte Red-Team-Käufe

Ein Auftrag sollte nach außen diskret und intern rechenschaftspflichtig sein:

1. Hole den schriftlichen Umfang, Zweck, Ausgabenhöchstbetrag, Genehmiger, zulässige Händler/Assets und die Erstattungsregel ein.
2. Verwende ein von der Organisation kontrolliertes Zahlungskonto und eine separate VCN oder ein Unterkonto pro Auftrag oder Händler.
3. Halte korrekte Rechnungs- und Registrierungsdaten bei Anbietern aufrecht. Öffentlicher Registrierungsschutz kann die Offenlegung minimieren, ist aber keine Erlaubnis zu lügen.
4. Führe ein verschlüsseltes Hauptbuch mit Bearbeiter, Genehmigung, Zweck, Datum, Betrag, Gegenpartei, Asset-Identifier und Quittung.
5. Prüfe Gegenparteien wie vorgeschrieben und befolge Anbieter-, Sanktions-, Steuer- und Meldepflichten.
6. Gib der Finanzabteilung nur den erforderlichen Zugriff und Bearbeitern nur die erforderliche begrenzte Ausgabefähigkeit.
7. Schließe Zahlungsschlüssel während des Teardowns oder friere sie ein, gleiche ausstehende Belastungen/Erstattungen ab und bewahre Aufzeichnungen gemäß Richtlinie auf.

Für kryptospezifische Entscheidungen fahre mit [Cryptocurrency Privacy](cryptocurrency-privacy.md) fort. Für die Infrastruktur, die diese Käufe unterstützt, siehe [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Verifizierungs-Checkliste

- [ ] Die gewünschte Privatsphäreeigenschaft und die Beobachter sind schriftlich festgehalten.
- [ ] Anbieter-, Händler- und Rechtsordnungsvorschriften wurden kürzlich geprüft.
- [ ] Angaben zu Identität und Herkunft der Gelder sind wahrheitsgemäß.
- [ ] Optionale Händlerinformationen werden minimiert, ohne die erforderliche Verifizierung zu umgehen.
- [ ] Verknüpfungen durch Finanzierung, Gerät, Netzwerk, Konto, Lieferung und Erstattung sind verstanden.
- [ ] Es sind keine Schwellenwertvermeidung, verbotenen Gegenparteien, Geldkuriere, gestohlenen Zugangsdaten oder Identitäten Dritter beteiligt.
- [ ] Erforderliche Quittungen, Genehmigungen, Steuerunterlagen und Wiederherstellungsinformationen sind verschlüsselt und zugriffsgesteuert.

## References

- [1] [US CFPB — Informationsersuchen zur Erhebung, Nutzung und Monetarisierung von Zahlungs- und anderen persönlichen Finanzdaten von Verbrauchern](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [Europäische Zentralbank — Studie zu den Zahlungsverhalten von Verbrauchern im Euroraum (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Anleitung zum Formular 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanische Steuerbehörde — Meldung von Barzahlungen](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Warum werde ich bei der Aktivierung oder Registrierung einer Prepaid-Karte nach persönlichen Daten gefragt?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) und [Kann eine Prepaid-Karte abgelehnt werden?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Endgültige Regelung zu Prepaid Access](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Richtlinie (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Verwendung virtueller Kreditkarten](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
