# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

Willkommen zum umfassenden HackTricks-Leitfaden zu Threat Modeling! Begib dich auf eine Erkundung dieses kritischen Aspekts der Cybersecurity, bei dem wir potenzielle Schwachstellen in einem System identifizieren, verstehen und Strategien gegen sie entwickeln. Dieser Abschnitt dient als Schritt-für-Schritt-Anleitung mit praxisnahen Beispielen, hilfreicher Software und leicht verständlichen Erklärungen. Ideal sowohl für Anfänger als auch für erfahrene Praktiker, die ihre Cybersecurity-Abwehr stärken möchten.

### Häufig verwendete Szenarien

1. **Softwareentwicklung**: Als Bestandteil des Secure Software Development Life Cycle (SSDLC) hilft Threat Modeling dabei, **potenzielle Quellen von Schwachstellen** bereits in frühen Entwicklungsphasen zu identifizieren.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Der Penetration Testing Execution Standard (PTES) betrachtet Threat Modeling als Voraussetzung für eine korrekte Durchführung und fordert die Dokumentation von Geschäftsressourcen, Geschäftsprozessen, Bedrohungsgemeinschaften und deren Fähigkeiten.<sup>[[2]](#references)</sup>

### Threat Model im Überblick

Ein Threat Model wird typischerweise als Diagramm, Bild oder andere visuelle Darstellung einer geplanten Architektur oder einer bestehenden Anwendung dargestellt. Data-flow diagrams (DFDs) sind eine gängige Möglichkeit, ein System und seine Interaktionen zu modellieren, während Threat Modeling eine auf Security fokussierte Analyse ergänzt.<sup>[[1]](#references)</sup>

Im Threat Modeling Tool von Microsoft zeigen rote gestrichelte Linien Trust Boundaries an; andere Tools können andere visuelle Konventionen verwenden.<sup>[[4]](#references)</sup> Zur Vereinfachung der Risikoidentifizierung können Teams die CIA-Triade (Confidentiality, Integrity, Availability) oder die STRIDE-Bedrohungskategorien verwenden. Die geeignete Methodik hängt jedoch vom Kontext und den Anforderungen des Projekts ab.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### Die CIA-Triade

Die CIA-Triade ist ein weithin anerkanntes Modell der Informationssicherheit und steht für Confidentiality, Integrity und Availability. Diese Eigenschaften werden häufig verwendet, um Security-Ziele für Daten und Systeme zu beschreiben.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Sicherstellen, dass nicht autorisierte Personen nicht auf die Daten oder das System zugreifen können. Dies ist ein zentraler Aspekt der Security und erfordert geeignete Zugriffskontrollen, Verschlüsselung und weitere Maßnahmen, um Data Breaches zu verhindern.
2. **Integrity**: Die Genauigkeit, Konsistenz und Vertrauenswürdigkeit der Daten während ihres gesamten Lebenszyklus. Dieses Prinzip stellt sicher, dass die Daten nicht von nicht autorisierten Parteien verändert oder manipuliert werden. Dazu gehören häufig Checksums, Hashing und weitere Methoden zur Datenüberprüfung.
3. **Availability**: Sicherstellen, dass Daten und Services autorisierten Benutzern bei Bedarf zur Verfügung stehen. Dies umfasst häufig Redundanz, Fehlertoleranz und High-Availability-Konfigurationen, damit Systeme auch bei Störungen betriebsbereit bleiben.

### Threat-Modeling-Methodologien

1. **STRIDE**: Der STRIDE-Ansatz von Microsoft kategorisiert Software-Bedrohungen als **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service und Elevation of Privilege**. Diese Kategorien helfen Analysten dabei, mögliche Bedrohungen an jedem verwundbaren Punkt eines Designs zu identifizieren.<sup>[[5]](#references)</sup>
2. **DREAD**: Dieser Bewertungsansatz von Microsoft bewertet Bedrohungen anhand von **Damage, Reproducibility, Exploitability, Affected users und Discoverability**. Die daraus resultierende Punktzahl kann helfen, Bedrohungen für die Mitigation zu priorisieren.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Dies ist eine siebenteilige, **risikozentrierte** Methodik, die Ziele, den technischen Umfang, die Dekomposition der Anwendung, die Bedrohungsanalyse, die Analyse von Schwachstellen und Schwächen, das Attack Modeling sowie die Risiko-/Auswirkungsanalyse umfasst.<sup>[[8]](#references)</sup>
4. **Trike**: Dieses Framework für Security Audits nähert sich Threat Modeling aus einer **Risikomanagement-** und defensiven Perspektive.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Diese Methode legt den Schwerpunkt auf skalierbare und praktikable Threat Models für Anwendungs- und Betriebsperspektiven und kann in Entwicklungs- und DevOps-Lifecycles integriert werden.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): OCTAVE wurde von der CERT Division des Software Engineering Institute der Carnegie Mellon University entwickelt und ist eine risikobasierte strategische Bewertungs- und Planungsmethode, die sich auf organisatorische Risiken und nicht ausschließlich auf Technologie konzentriert.<sup>[[10]](#references)</sup>

## Tools

Es stehen verschiedene Tools und Softwarelösungen zur Verfügung, die bei der Erstellung und Verwaltung von Threat Models **unterstützen** können. Hier sind einige, die du in Betracht ziehen kannst.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite ist ein plattformübergreifender Web Crawler für Security-Professionals, der Attack-Surface-Mapping, Endpoint Discovery und Web-Application-Analyse unterstützt.<sup>[[6]](#references)</sup>

**Verwendung**

1. Eine URL auswählen und crawlen

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph anzeigen

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon ist eine kostenlose, quelloffene und plattformübergreifende Threat-Modeling-Anwendung zum Zeichnen von Diagrammen, Vorschlagen von Bedrohungen und Dokumentieren von Mitigations. Sie ist als Web- und Desktop-Anwendung verfügbar.<sup>[[7]](#references)</sup>

**Verwendung**

1. Neues Projekt erstellen

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Manchmal kann es so aussehen:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Neues Projekt starten

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Neues Projekt speichern

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Dein Model erstellen

Du kannst Tools wie den SpiderSuite Crawler verwenden, um Inspiration zu erhalten. Ein grundlegendes Model könnte etwa so aussehen:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Eine kurze Erklärung zu den Entitäten:

- Process (Die Entität selbst, beispielsweise ein Webserver oder eine Web-Funktionalität)
- Actor (Eine Person, beispielsweise ein Website-Besucher, Benutzer oder Administrator)
- Data Flow Line (Indikator einer Interaktion)
- Trust Boundary (Unterschiedliche Netzwerksegmente oder Geltungsbereiche)
- Store (Orte, an denen Daten gespeichert werden, beispielsweise Datenbanken)

5. Eine Bedrohung erstellen (Schritt 1)

Zuerst musst du die Ebene auswählen, der du eine Bedrohung hinzufügen möchtest.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Jetzt kannst du die Bedrohung erstellen.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Beachte, dass es einen Unterschied zwischen Actor Threats und Process Threats gibt. Wenn du eine Bedrohung zu einem Actor hinzufügen würdest, könntest du nur „Spoofing“ und „Repudiation“ auswählen. Da wir in unserem Beispiel jedoch eine Bedrohung zu einer Process-Entität hinzufügen, sehen wir im Fenster zur Bedrohungserstellung Folgendes:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Fertig

Dein fertiges Model sollte nun ungefähr so aussehen. So erstellst du ein einfaches Threat Model mit OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Das Threat Modeling Tool von Microsoft ist ein kostenlos herunterladbares Tool zur Analyse von Softwaredesigns. Sein Workflow erstellt ein Diagramm, identifiziert Bedrohungen und unterstützt Mitigation und Validierung mithilfe des STRIDE-Ansatzes.<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - Der Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Security-Grundlagen - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Erste Schritte mit dem Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Threat Modeling für Treiber - Windows-Treiber](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA Threat Modeling: Die 7 Phasen erklärt](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 Methodologiedokument](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling: Eine Zusammenfassung verfügbarer Methoden](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
