# Bedrohungsmodellierung

## Bedrohungsmodellierung

Willkommen zu HackTricks' umfassendem Leitfaden zur Bedrohungsmodellierung! Beginnen Sie eine Erkundung dieses kritischen Aspekts der Cybersicherheit, bei dem wir potenzielle Schwachstellen in einem System identifizieren, verstehen und Strategien dagegen entwickeln. Dieser Thread dient als Schritt-für-Schritt-Anleitung, die mit realen Beispielen, hilfreicher Software und leicht verständlichen Erklärungen gefüllt ist. Ideal für sowohl Anfänger als auch erfahrene Praktiker, die ihre Cybersicherheitsverteidigung stärken möchten.

### Häufig Verwendete Szenarien

1. **Softwareentwicklung**: Im Rahmen des Secure Software Development Life Cycle (SSDLC) hilft die Bedrohungsmodellierung bei der **Identifizierung potenzieller Quellen von Schwachstellen** in den frühen Phasen der Entwicklung.
2. **Penetration Testing**: Der Penetration Testing Execution Standard (PTES) erfordert **Bedrohungsmodellierung, um die Schwachstellen des Systems zu verstehen**, bevor der Test durchgeführt wird.

### Bedrohungsmodell in Kürze

Ein Bedrohungsmodell wird typischerweise als Diagramm, Bild oder in einer anderen Form der visuellen Darstellung dargestellt, die die geplante Architektur oder den bestehenden Aufbau einer Anwendung zeigt. Es ähnelt einem **Datenflussdiagramm**, aber der entscheidende Unterschied liegt im sicherheitsorientierten Design.

Bedrohungsmodelle enthalten oft Elemente, die in Rot markiert sind und potenzielle Schwachstellen, Risiken oder Barrieren symbolisieren. Um den Prozess der Risikoidentifizierung zu vereinfachen, wird das CIA (Vertraulichkeit, Integrität, Verfügbarkeit) Triad verwendet, das die Grundlage vieler Bedrohungsmodellierungsmethodologien bildet, wobei STRIDE eine der häufigsten ist. Die gewählte Methodologie kann jedoch je nach spezifischem Kontext und Anforderungen variieren.

### Das CIA-Triad

Das CIA-Triad ist ein weithin anerkanntes Modell im Bereich der Informationssicherheit, das für Vertraulichkeit, Integrität und Verfügbarkeit steht. Diese drei Säulen bilden die Grundlage, auf der viele Sicherheitsmaßnahmen und -richtlinien basieren, einschließlich der Bedrohungsmodellierungsmethodologien.

1. **Vertraulichkeit**: Sicherstellen, dass die Daten oder das System nicht von unbefugten Personen zugegriffen werden. Dies ist ein zentraler Aspekt der Sicherheit, der angemessene Zugriffskontrollen, Verschlüsselung und andere Maßnahmen erfordert, um Datenverletzungen zu verhindern.
2. **Integrität**: Die Genauigkeit, Konsistenz und Vertrauenswürdigkeit der Daten über ihren Lebenszyklus. Dieses Prinzip stellt sicher, dass die Daten nicht von unbefugten Parteien verändert oder manipuliert werden. Es umfasst oft Prüfziffern, Hashing und andere Datenverifizierungsmethoden.
3. **Verfügbarkeit**: Dies stellt sicher, dass Daten und Dienste für autorisierte Benutzer bei Bedarf zugänglich sind. Dies umfasst oft Redundanz, Fehlertoleranz und Hochverfügbarkeitskonfigurationen, um Systeme auch bei Störungen am Laufen zu halten.

### Bedrohungsmodellierungsmethodologien

1. **STRIDE**: Entwickelt von Microsoft, ist STRIDE ein Akronym für **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service und Elevation of Privilege**. Jede Kategorie stellt eine Art von Bedrohung dar, und diese Methodologie wird häufig in der Entwurfsphase eines Programms oder Systems verwendet, um potenzielle Bedrohungen zu identifizieren.
2. **DREAD**: Dies ist eine weitere Methodologie von Microsoft, die zur Risikobewertung identifizierter Bedrohungen verwendet wird. DREAD steht für **Damage potential, Reproducibility, Exploitability, Affected users und Discoverability**. Jeder dieser Faktoren wird bewertet, und das Ergebnis wird verwendet, um identifizierte Bedrohungen zu priorisieren.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Dies ist eine siebenstufige, **risikozentrierte** Methodologie. Sie umfasst die Definition und Identifizierung von Sicherheitszielen, die Erstellung eines technischen Rahmens, die Anwendungszerlegung, die Bedrohungsanalyse, die Schwachstellenanalyse und die Risiko-/Triagebewertung.
4. **Trike**: Dies ist eine risikobasierte Methodologie, die sich auf den Schutz von Vermögenswerten konzentriert. Sie beginnt aus einer **Risikomanagement**-Perspektive und betrachtet Bedrohungen und Schwachstellen in diesem Kontext.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Dieser Ansatz zielt darauf ab, zugänglicher zu sein und in agile Entwicklungsumgebungen integriert zu werden. Er kombiniert Elemente aus den anderen Methodologien und konzentriert sich auf **visuelle Darstellungen von Bedrohungen**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Entwickelt vom CERT Coordination Center, ist dieses Framework auf **organisatorische Risikobewertung anstelle spezifischer Systeme oder Software** ausgerichtet.

## Werkzeuge

Es gibt mehrere Werkzeuge und Softwarelösungen, die bei der **Erstellung** und Verwaltung von Bedrohungsmodellen helfen können. Hier sind einige, die Sie in Betracht ziehen könnten.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Ein fortschrittlicher plattformübergreifender und multifunktionaler GUI-Webspider/Crawler für Cybersicherheitsprofis. Spider Suite kann zur Kartierung und Analyse der Angriffsfläche verwendet werden.

**Verwendung**

1. Wählen Sie eine URL und crawlen

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph anzeigen

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Ein Open-Source-Projekt von OWASP, Threat Dragon ist sowohl eine Web- als auch eine Desktop-Anwendung, die Systemdiagrammierung sowie eine Regel-Engine zur automatischen Generierung von Bedrohungen/Minderungen umfasst.

**Verwendung**

1. Neues Projekt erstellen

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Manchmal könnte es so aussehen:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Neues Projekt starten

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Das neue Projekt speichern

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Erstellen Sie Ihr Modell

Sie können Tools wie SpiderSuite Crawler verwenden, um Inspiration zu erhalten, ein einfaches Modell könnte so aussehen

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Nur eine kleine Erklärung zu den Entitäten:

- Prozess (Die Entität selbst, wie Webserver oder Webfunktionalität)
- Akteur (Eine Person wie ein Website-Besucher, Benutzer oder Administrator)
- Datenflusslinie (Indikator für Interaktion)
- Vertrauensgrenze (Verschiedene Netzwerksegmente oder -bereiche.)
- Speicher (Dinge, in denen Daten gespeichert werden, wie Datenbanken)

5. Eine Bedrohung erstellen (Schritt 1)

Zuerst müssen Sie die Ebene auswählen, zu der Sie eine Bedrohung hinzufügen möchten

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Jetzt können Sie die Bedrohung erstellen

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Beachten Sie, dass es einen Unterschied zwischen Akteur-Bedrohungen und Prozess-Bedrohungen gibt. Wenn Sie eine Bedrohung zu einem Akteur hinzufügen, können Sie nur "Spoofing" und "Repudiation" auswählen. In unserem Beispiel fügen wir jedoch eine Bedrohung zu einer Prozesseinheit hinzu, sodass wir dies im Bedrohungserstellungsfeld sehen werden:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Fertig

Jetzt sollte Ihr fertiges Modell so aussehen. Und so erstellen Sie ein einfaches Bedrohungsmodell mit OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Dies ist ein kostenloses Tool von Microsoft, das hilft, Bedrohungen in der Entwurfsphase von Softwareprojekten zu finden. Es verwendet die STRIDE-Methodologie und ist besonders geeignet für diejenigen, die auf Microsofts Stack entwickeln.
