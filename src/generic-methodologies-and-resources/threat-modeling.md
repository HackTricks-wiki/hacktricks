# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

## Threat Modeling

Willkommen bei HackTricks' umfassendem Leitfaden zu Threat Modeling! Erkunde diesen kritischen Aspekt der Cybersicherheit, bei dem wir potenzielle Schwachstellen in einem System identifizieren, verstehen und Strategien gegen sie entwickeln. Dieser Thread dient als schrittweise Anleitung mit realen Beispielen, hilfreicher Software und leicht verständlichen Erklärungen. Ideal sowohl für Anfänger als auch für erfahrene Praktiker, die ihre Cybersicherheitsmaßnahmen stärken möchten.

### Häufig verwendete Szenarien

1. **Softwareentwicklung**: Als Teil des Secure Software Development Life Cycle (SSDLC) hilft Threat Modeling dabei, **potenzielle Quellen von Schwachstellen** bereits in den frühen Entwicklungsphasen zu identifizieren.
2. **Penetration Testing**: Das Penetration Testing Execution Standard (PTES)-Framework erfordert **Threat Modeling, um die Schwachstellen des Systems zu verstehen**, bevor der Test durchgeführt wird.

### Threat Model in aller Kürze

Ein Threat Model wird typischerweise als Diagramm, Bild oder eine andere Form visueller Darstellung präsentiert, die die geplante Architektur oder den bestehenden Aufbau einer Anwendung abbildet. Es ähnelt einem **Data-Flow-Diagramm**, der entscheidende Unterschied liegt jedoch in der sicherheitsorientierten Gestaltung.

Threat Models enthalten häufig rot markierte Elemente, die potenzielle Schwachstellen, Risiken oder Barrieren symbolisieren. Um den Prozess der Risikoidentifizierung zu vereinfachen, wird die CIA-Triade (Confidentiality, Integrity, Availability) eingesetzt. Sie bildet die Grundlage vieler Threat-Modeling-Methoden, wobei STRIDE eine der häufigsten ist. Die gewählte Methode kann jedoch je nach spezifischem Kontext und Anforderungen variieren.

### Die CIA-Triade

Die CIA-Triade ist ein weithin anerkanntes Modell im Bereich der Informationssicherheit und steht für Confidentiality, Integrity und Availability. Diese drei Säulen bilden die Grundlage, auf der viele Sicherheitsmaßnahmen und Richtlinien aufbauen, darunter auch Threat-Modeling-Methoden.

1. **Confidentiality**: Sicherstellen, dass nicht autorisierte Personen auf die Daten oder das System zugreifen. Dies ist ein zentraler Sicherheitsaspekt und erfordert geeignete Zugriffskontrollen, Verschlüsselung und weitere Maßnahmen, um Datenleaks zu verhindern.
2. **Integrity**: Die Genauigkeit, Konsistenz und Vertrauenswürdigkeit der Daten während ihres gesamten Lebenszyklus. Dieses Prinzip stellt sicher, dass die Daten nicht von nicht autorisierten Parteien verändert oder manipuliert werden. Häufig kommen dabei Prüfsummen, Hashing und andere Methoden zur Datenüberprüfung zum Einsatz.
3. **Availability**: Sicherstellen, dass Daten und Services autorisierten Benutzern bei Bedarf zur Verfügung stehen. Dies umfasst häufig Redundanz, Fehlertoleranz und Hochverfügbarkeitskonfigurationen, damit Systeme auch bei Störungen weiterlaufen.

### Threat-Modeling-Methoden

1. **STRIDE**: STRIDE wurde von Microsoft entwickelt und ist ein Akronym für **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service und Elevation of Privilege**. Jede Kategorie stellt eine Art von Bedrohung dar. Diese Methode wird häufig in der Designphase eines Programms oder Systems eingesetzt, um potenzielle Bedrohungen zu identifizieren.
2. **DREAD**: Dies ist eine weitere von Microsoft stammende Methode zur Risikobewertung identifizierter Bedrohungen. DREAD steht für **Damage potential, Reproducibility, Exploitability, Affected users und Discoverability**. Jeder dieser Faktoren wird bewertet, und das Ergebnis wird verwendet, um identifizierte Bedrohungen zu priorisieren.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Dies ist eine siebenstufige, **risikozentrierte** Methode. Sie umfasst die Definition und Identifizierung von Sicherheitszielen, die Erstellung eines technischen Umfangs, die Zerlegung der Anwendung, die Bedrohungsanalyse, die Schwachstellenanalyse sowie die Risiko- und Triage-Bewertung.
4. **Trike**: Dies ist eine risikobasierte Methode, die sich auf den Schutz von Assets konzentriert. Sie beginnt aus der Perspektive des **Risikomanagements** und betrachtet Bedrohungen und Schwachstellen in diesem Kontext.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Dieser Ansatz soll leichter zugänglich sein und sich in Agile-Entwicklungsumgebungen integrieren lassen. Er kombiniert Elemente der anderen Methoden und konzentriert sich auf **visuelle Darstellungen von Bedrohungen**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Dieses vom CERT Coordination Center entwickelte Framework ist auf die **Bewertung organisatorischer Risiken statt spezifischer Systeme oder Software** ausgerichtet.

## Tools

Es gibt verschiedene Tools und Softwarelösungen, die bei der **Erstellung** und Verwaltung von Threat Models **unterstützen** können. Hier sind einige, die du in Betracht ziehen könntest.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Ein fortschrittlicher, plattformübergreifender GUI-Web-Spider/Crawler mit zahlreichen Funktionen für Cybersicherheitsprofis. Spider Suite kann zum Mapping und zur Analyse der Angriffsfläche verwendet werden.

**Verwendung**

1. Wähle eine URL aus und starte den Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Zeige den Graphen an

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon ist ein Open-Source-Projekt von OWASP. Es handelt sich sowohl um eine Web- als auch um eine Desktop-Anwendung, die Systemdiagramme sowie eine Rule Engine zur automatischen Generierung von Bedrohungen/Mitigations umfasst.

**Verwendung**

1. Erstelle ein neues Projekt

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Manchmal kann es so aussehen:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Starte ein neues Projekt

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Speichere das neue Projekt

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Erstelle dein Model

Du kannst Tools wie SpiderSuite Crawler verwenden, um Inspiration zu erhalten. Ein grundlegendes Model könnte etwa so aussehen:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Hier eine kurze Erklärung der Entitäten:

- Process (Die Entität selbst, z. B. Webserver oder Webfunktionalität)
- Actor (Eine Person, z. B. ein Website-Besucher, Benutzer oder Administrator)
- Data Flow Line (Indikator einer Interaktion)
- Trust Boundary (Unterschiedliche Netzwerksegmente oder Bereiche.)
- Store (Orte, an denen Daten gespeichert werden, z. B. Datenbanken)

5. Erstelle eine Threat (Schritt 1)

Zuerst musst du die Ebene auswählen, der du eine Threat hinzufügen möchtest.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Nun kannst du die Threat erstellen.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Beachte, dass es einen Unterschied zwischen Actor Threats und Process Threats gibt. Wenn du einem Actor eine Threat hinzufügen würdest, könntest du nur „Spoofing“ und „Repudiation“ auswählen. Da wir in unserem Beispiel jedoch einem Process eine Threat hinzufügen, sehen wir dies im Fenster zur Erstellung der Threat:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Fertig

Dein fertiges Model sollte nun ungefähr so aussehen. So erstellst du ein einfaches Threat Model mit OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Dies ist ein kostenloses Tool von Microsoft, das dabei hilft, Bedrohungen in der Designphase von Softwareprojekten zu finden. Es verwendet die STRIDE-Methode und eignet sich besonders für Entwickler, die auf Microsofts Stack entwickeln.

{{#include ../banners/hacktricks-training.md}}
