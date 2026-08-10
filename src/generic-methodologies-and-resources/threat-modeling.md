# Bedrohungsmodellierung

Willkommen zu HackTricks' umfassendem Leitfaden zur Bedrohungsmodellierung! Erkunde diesen kritischen Aspekt der Cybersicherheit, bei dem wir potenzielle Schwachstellen in einem System identifizieren, verstehen und Strategien gegen sie entwickeln. Dieser Leitfaden dient als Schritt-für-Schritt-Anleitung mit Beispielen aus der Praxis, hilfreicher Software und leicht verständlichen Erklärungen. Ideal sowohl für Einsteiger als auch für erfahrene Praktiker, die ihre Cybersicherheitsmaßnahmen stärken möchten.

### Häufig verwendete Szenarien

1. **Softwareentwicklung**: Als Bestandteil des Secure Software Development Life Cycle (SSDLC) hilft die Bedrohungsmodellierung dabei, **potenzielle Quellen von Schwachstellen** bereits in frühen Entwicklungsphasen zu **identifizieren**.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Der Penetration Testing Execution Standard (PTES) betrachtet die Bedrohungsmodellierung als erforderlich für eine korrekte Durchführung und fordert die Dokumentation von Geschäftsressourcen, Geschäftsprozessen, Bedrohungsgemeinschaften und deren Fähigkeiten.<sup>[[2]](#references)</sup>

### Bedrohungsmodell kurz erklärt

Ein Bedrohungsmodell wird typischerweise als Diagramm, Bild oder eine andere visuelle Darstellung einer geplanten Architektur oder einer bestehenden Anwendung dargestellt. Datenflussdiagramme (DFDs) sind eine gängige Methode zur Modellierung eines Systems und seiner Interaktionen, während die Bedrohungsmodellierung eine sicherheitsorientierte Analyse ergänzt.<sup>[[1]](#references)</sup>

Im Microsoft Threat Modeling Tool zeigen rote gestrichelte Linien Vertrauensgrenzen an; andere Tools können andere visuelle Konventionen verwenden.<sup>[[4]](#references)</sup> Um die Identifizierung von Risiken zu vereinfachen, können Teams die CIA-Triade (Confidentiality, Integrity, Availability) oder die STRIDE-Bedrohungskategorien verwenden. Die geeignete Methodik hängt jedoch vom Kontext und den Anforderungen des Projekts ab.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### Die CIA-Triade

Die CIA-Triade ist ein weithin anerkanntes Modell der Informationssicherheit und steht für Confidentiality, Integrity und Availability. Diese Eigenschaften werden häufig verwendet, um Sicherheitsziele für Daten und Systeme zu beschreiben.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Sicherstellen, dass nicht autorisierte Personen nicht auf die Daten oder das System zugreifen. Dies ist ein zentraler Sicherheitsaspekt und erfordert geeignete Zugriffskontrollen, Verschlüsselung und weitere Maßnahmen, um Datenverletzungen zu verhindern.
2. **Integrity**: Die Genauigkeit, Konsistenz und Vertrauenswürdigkeit der Daten während ihres gesamten Lebenszyklus. Dieses Prinzip stellt sicher, dass die Daten nicht von unbefugten Parteien verändert oder manipuliert werden. Häufig kommen dabei Prüfsummen, Hashing und andere Methoden zur Datenüberprüfung zum Einsatz.
3. **Availability**: Dies stellt sicher, dass Daten und Dienste autorisierten Benutzern bei Bedarf zur Verfügung stehen. Dazu gehören häufig Redundanz, Fehlertoleranz und Hochverfügbarkeitskonfigurationen, damit Systeme auch bei Störungen weiter funktionieren.

### Methodiken der Bedrohungsmodellierung

1. **STRIDE**: Der STRIDE-Ansatz von Microsoft kategorisiert Bedrohungen für Software als **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service und Elevation of Privilege**. Diese Kategorien helfen Analysten, mögliche Bedrohungen an jedem gefährdeten Punkt eines Designs zu identifizieren.<sup>[[5]](#references)</sup>
2. **DREAD**: Dieser Bewertungsansatz von Microsoft bewertet Bedrohungen anhand von **Damage, Reproducibility, Exploitability, Affected users und Discoverability**. Die daraus resultierende Punktzahl kann dabei helfen, Bedrohungen für die Abwehr zu priorisieren.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Dies ist eine siebenteilige, **risikozentrierte** Methodik, die Ziele, den technischen Umfang, die Anwendungszerlegung, die Bedrohungsanalyse, die Analyse von Schwachstellen und Sicherheitslücken, die Angriffsmodellierung sowie die Risiko-/Auswirkungsanalyse umfasst.<sup>[[8]](#references)</sup>
4. **Trike**: Dieses Framework für Sicherheitsaudits nähert sich der Bedrohungsmodellierung aus einer **Risikomanagement-** und defensiven Perspektive.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Diese Methode legt Wert auf skalierbare und nutzbare Bedrohungsmodelle für Anwendungs- und Betriebsperspektiven und kann in Entwicklungs- und DevOps-Lebenszyklen integriert werden.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): OCTAVE wurde von der CERT Division des Software Engineering Institute der Carnegie Mellon University entwickelt und ist eine risikobasierte strategische Bewertungs- und Planungsmethode, die sich auf organisatorische Risiken und nicht ausschließlich auf Technologie konzentriert.<sup>[[10]](#references)</sup>

## Tools

Es gibt verschiedene Tools und Softwarelösungen, die bei der Erstellung und Verwaltung von Bedrohungsmodellen **helfen** können. Hier sind einige, die du in Betracht ziehen könntest.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite ist ein plattformübergreifender Webcrawler für Sicherheitsexperten, der die Kartierung der Angriffsfläche, die Erkennung von Endpunkten und die Analyse von Webanwendungen unterstützt.<sup>[[6]](#references)</sup>

**Verwendung**

1. Wähle eine URL aus und starte den Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph anzeigen

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon ist eine kostenlose, quelloffene und plattformübergreifende Anwendung zur Bedrohungsmodellierung, mit der Diagramme gezeichnet, Bedrohungen vorgeschlagen und Gegenmaßnahmen dokumentiert werden können. Sie ist als Web- und Desktopanwendung verfügbar.<sup>[[7]](#references)</sup>

**Verwendung**

1. Neues Projekt erstellen

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Manchmal könnte es so aussehen:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Neues Projekt starten

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Neues Projekt speichern

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Erstelle dein Modell

Du kannst Tools wie SpiderSuite Crawler verwenden, um Inspiration zu erhalten. Ein einfaches Modell könnte ungefähr so aussehen:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Hier eine kurze Erklärung der Entitäten:

- Process (Die Entität selbst, z. B. Webserver oder Webfunktionalität)
- Actor (Eine Person, z. B. ein Websitebesucher, Benutzer oder Administrator)
- Data Flow Line (Indikator für eine Interaktion)
- Trust Boundary (Verschiedene Netzwerksegmente oder Bereiche)
- Store (Orte, an denen Daten gespeichert werden, z. B. Datenbanken)

5. Eine Bedrohung erstellen (Schritt 1)

Zuerst musst du die Ebene auswählen, der du eine Bedrohung hinzufügen möchtest.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Nun kannst du die Bedrohung erstellen.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Beachte, dass es einen Unterschied zwischen Actor Threats und Process Threats gibt. Wenn du einem Actor eine Bedrohung hinzufügen würdest, könntest du nur "Spoofing" und "Repudiation" auswählen. In unserem Beispiel fügen wir jedoch einer Process-Entität eine Bedrohung hinzu, sodass wir im Fenster zur Bedrohungserstellung Folgendes sehen:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Fertig

Dein fertiges Modell sollte nun ungefähr so aussehen. So erstellst du ein einfaches Bedrohungsmodell mit OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft's Threat Modeling Tool ist ein kostenlos herunterladbares Tool zur Analyse von Softwaredesigns. Der Workflow erstellt ein Diagramm, identifiziert Bedrohungen und unterstützt die Gegenmaßnahmenplanung und Validierung mithilfe des STRIDE-Ansatzes.<sup>[[4]](#references)</sup>

## References

- [1] [Cheat Sheet zur Bedrohungsmodellierung](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Bedrohungsmodellierung - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Grundlagen der Sicherheit - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Erste Schritte mit dem Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Bedrohungsmodellierung für Treiber - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA-Bedrohungsmodellierung: Die 7 Phasen erklärt](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 Methodikdokument](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Bedrohungsmodellierung: Eine Zusammenfassung verfügbarer Methoden](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
