# AI-Risiken

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine-Learning-Schwachstellen

Owasp hat die zehn wichtigsten Machine-Learning-Schwachstellen identifiziert, die AI-Systeme betreffen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, darunter Data Poisoning, Model Inversion und Adversarial Attacks. Das Verständnis dieser Schwachstellen ist entscheidend für den Aufbau sicherer AI-Systeme.

Eine aktualisierte und detaillierte Liste der zehn wichtigsten Machine-Learning-Schwachstellen findet sich im Projekt [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[10]](#references)</sup>

- **Input Manipulation Attack**: Ein Angreifer fügt **eingehenden Daten** winzige, oft unsichtbare Änderungen hinzu, sodass das Modell die falsche Entscheidung trifft.\
*Beispiel*: Einige Farbspritzer auf einem Stoppschild bringen ein selbstfahrendes Auto dazu, ein Geschwindigkeitsbegrenzungsschild zu "sehen".

- **Data Poisoning Attack**: Der **Trainingsdatensatz** wird absichtlich mit schlechten Beispielen verunreinigt und bringt dem Modell schädliche Regeln bei.\
*Beispiel*: Malware-Binärdateien werden in einem Antivirus-Trainingskorpus fälschlicherweise als "harmlos" gekennzeichnet, sodass ähnliche Malware später unentdeckt bleibt.

- **Model Inversion Attack**: Durch das Abfragen von Ausgaben erstellt ein Angreifer ein **Umkehrmodell**, das sensible Merkmale der ursprünglichen Eingaben rekonstruiert.\
*Beispiel*: Rekonstruktion des MRT-Bildes eines Patienten aus den Vorhersagen eines Krebsdiagnosemodells.

- **Membership Inference Attack**: Der Angreifer testet anhand von Konfidenzunterschieden, ob ein **bestimmter Datensatz** während des Trainings verwendet wurde.\
*Beispiel*: Bestätigen, dass die Banktransaktion einer Person in den Trainingsdaten eines Betrugserkennungsmodells enthalten ist.

- **Model Theft**: Wiederholte Abfragen ermöglichen es einem Angreifer, Entscheidungsgrenzen zu erlernen und das **Verhalten des Modells zu klonen** (einschließlich des geistigen Eigentums).\
*Beispiel*: Ausreichend viele Frage-und-Antwort-Paare von einer ML-as-a-Service-API sammeln, um ein nahezu gleichwertiges lokales Modell zu erstellen.

- **AI Supply-Chain Attack**: Eine beliebige Komponente (Daten, Bibliotheken, vortrainierte Gewichte, CI/CD) in der **ML-Pipeline** wird kompromittiert, um nachgelagerte Modelle zu korrumpieren.\
*Beispiel*: Eine vergiftete Dependency in einem Model-Hub installiert in zahlreichen Apps ein mit einer Backdoor versehenes Sentiment-Analysis-Modell.

- **Transfer Learning Attack**: Schädliche Logik wird in einem **vortrainierten Modell** platziert und überlebt das Fine-Tuning auf die Aufgabe des Opfers.\
*Beispiel*: Ein Vision-Backbone mit einem verborgenen Trigger vertauscht weiterhin Labels, nachdem es für medizinische Bildgebung angepasst wurde.

- **Model Skewing**: Subtil verzerrte oder falsch gekennzeichnete Daten **verschieben die Ausgaben des Modells**, um die Ziele des Angreifers zu begünstigen.\
*Beispiel*: "Saubere" Spam-E-Mails werden als Ham gekennzeichnet und eingefügt, sodass ein Spamfilter ähnliche zukünftige E-Mails durchlässt.

- **Output Integrity Attack**: Der Angreifer **verändert die Modellvorhersagen während der Übertragung**, nicht das Modell selbst, und täuscht dadurch nachgelagerte Systeme.\
*Beispiel*: Das Urteil "bösartig" eines Malware-Klassifikators wird in "harmlos" geändert, bevor die Datei-Quarantänestufe es erhält.

- **Model Poisoning** --- Direkte, gezielte Änderungen an den **Modellparametern** selbst, häufig nachdem Schreibzugriff erlangt wurde, um das Verhalten zu verändern.\
*Beispiel*: Gewichte eines Betrugserkennungsmodells in der Produktion werden so angepasst, dass Transaktionen bestimmter Karten immer genehmigt werden.


## Google-SAIF-Risiken

Googles [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beschreibt verschiedene mit AI-Systemen verbundene Risiken:<sup>[[11]](#references)</sup>

- **Data Poisoning**: Böswillige Akteure verändern Trainings-/Tuning-Daten oder schleusen solche Daten ein, um die Genauigkeit zu verschlechtern, Backdoors zu implantieren oder Ergebnisse zu verzerren. Dadurch wird die Modellintegrität über den gesamten Datenlebenszyklus hinweg untergraben.

- **Unauthorized Training Data**: Das Einlesen urheberrechtlich geschützter, sensibler oder nicht genehmigter Datensätze erzeugt rechtliche, ethische und leistungsbezogene Haftungsrisiken, da das Modell aus Daten lernt, deren Verwendung nie erlaubt war.

- **Model Source Tampering**: Manipulationen der Modell-Quelle, der Dependencies oder der Gewichte innerhalb der Supply Chain oder durch Insider vor oder während des Trainings können verborgene Logik einbetten, die auch nach einem erneuten Training bestehen bleibt.

- **Excessive Data Handling**: Schwache Kontrollen für Datenaufbewahrung und Governance führen dazu, dass Systeme mehr personenbezogene Daten speichern oder verarbeiten als notwendig, wodurch das Risiko von Datenpreisgabe und Compliance-Verstößen steigt.

- **Model Exfiltration**: Angreifer stehlen Modelldateien oder -gewichte, wodurch geistiges Eigentum verloren geht und Nachahmerdienste oder Folgeangriffe ermöglicht werden.

- **Model Deployment Tampering**: Angreifer verändern Modellartefakte oder die Serving-Infrastruktur, sodass sich das laufende Modell von der geprüften Version unterscheidet und sich möglicherweise sein Verhalten ändert.

- **Denial of ML Service**: Das Überfluten von APIs oder das Senden von "Sponge"-Eingaben kann Rechenleistung und Energie erschöpfen und das Modell offline bringen, ähnlich wie bei klassischen DoS-Angriffen.

- **Model Reverse Engineering**: Durch das Sammeln großer Mengen von Eingabe-Ausgabe-Paaren können Angreifer das Modell klonen oder destillieren, wodurch Nachahmerprodukte und individuell angepasste Adversarial Attacks entstehen.

- **Insecure Integrated Component**: Verwundbare Plugins, Agents oder vorgelagerte Services ermöglichen es Angreifern, Code in die AI-Pipeline einzuschleusen oder Berechtigungen zu erweitern.

- **Prompt Injection**: Durch das direkte oder indirekte Erstellen von Prompts werden Anweisungen eingeschleust, die die Systemabsicht überschreiben und das Modell dazu bringen, unbeabsichtigte Befehle auszuführen.

- **Model Evasion**: Sorgfältig erstellte Eingaben bringen das Modell dazu, falsch zu klassifizieren, zu halluzinieren oder nicht erlaubte Inhalte auszugeben, wodurch Sicherheit und Vertrauen beeinträchtigt werden.

- **Sensitive Data Disclosure**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem Benutzerkontext preis und verletzt dadurch Datenschutzbestimmungen und Vorschriften.

- **Inferred Sensitive Data**: Das Modell leitet persönliche Eigenschaften ab, die nie angegeben wurden, und verursacht durch diese Schlussfolgerung neue Datenschutzverletzungen.

- **Insecure Model Output**: Nicht bereinigte Antworten übertragen schädlichen Code, Fehlinformationen oder unangemessene Inhalte an Benutzer oder nachgelagerte Systeme.

- **Rogue Actions**: Autonom integrierte Agents führen unbeabsichtigte Vorgänge in der realen Welt aus (Dateischreibvorgänge, API-Aufrufe, Käufe usw.), ohne ausreichende Überwachung durch Benutzer.

## Mitre-AI-ATLAS-Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet ein umfassendes Framework zum Verständnis und zur Minderung von Risiken im Zusammenhang mit AI-Systemen. Sie kategorisiert verschiedene Angriffstechniken und Taktiken, die Angreifer gegen AI-Modelle einsetzen können, sowie die Verwendung von AI-Systemen zur Durchführung verschiedener Angriffe.<sup>[[12]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Angreifer stehlen aktive Session-Tokens oder Cloud-API-Credentials und rufen kostenpflichtige, Cloud-hosted LLMs ohne Berechtigung auf. Der Zugriff wird häufig über Reverse Proxies weiterverkauft, die dem Account des Opfers vorgeschaltet sind, z. B. über "oai-reverse-proxy"-Deployments. Zu den Folgen gehören finanzielle Verluste, eine nicht richtlinienkonforme Nutzung des Modells und die Zuordnung der Aktivitäten zum Tenant des Opfers.<sup>[[2]](#references)[[3]](#references)</sup>

TTPs:
- Tokens von infizierten Entwicklergeräten oder Browsern sammeln; CI/CD-Secrets stehlen; geleakte Cookies kaufen.
- Einen Reverse Proxy einrichten, der Anfragen an den echten Anbieter weiterleitet, den Upstream-Key verbirgt und viele Kunden multiplexed.
- Direkte Base-Model-Endpunkte missbrauchen, um Enterprise-Schutzmechanismen und Rate Limits zu umgehen.

Abwehrmaßnahmen:
- Tokens an Geräte-Fingerprints, IP-Bereiche und Client Attestation binden; kurze Ablaufzeiten erzwingen und die Erneuerung mit MFA durchführen.
- Keys auf das notwendige Minimum beschränken (kein Tool-Zugriff, sofern möglich nur Lesezugriff); bei Anomalien rotieren.
- Den gesamten Datenverkehr serverseitig hinter einem Policy Gateway beenden, das Safety-Filter, Quotas pro Route und Tenant-Isolation erzwingt.
- Auf ungewöhnliche Nutzungsmuster achten (plötzliche Ausgabenspitzen, atypische Regionen, UA-Strings) und verdächtige Sessions automatisch widerrufen.
- mTLS oder signierte JWTs, die von eurem IdP ausgestellt wurden, gegenüber langlebigen statischen API-Keys bevorzugen.

## Absicherung von Self-hosted LLM Inference

Das Ausführen eines lokalen LLM-Servers für vertrauliche Daten erzeugt eine andere Angriffsfläche als Cloud-hosted APIs: Inference-/Debug-Endpunkte können Prompts leaken, der Serving-Stack stellt üblicherweise einen Reverse Proxy bereit, und GPU-Device-Nodes gewähren Zugriff auf große `ioctl()`-Oberflächen. Wenn du einen On-Prem-Inference-Service bewertest oder bereitstellst, solltest du mindestens die folgenden Punkte prüfen.<sup>[[4]](#references)</sup>

### Prompt-Leaks über Debug- und Monitoring-Endpunkte

Behandle die Inference-API als **sensiblen Multi-User-Service**. Debug- oder Monitoring-Routen können Prompt-Inhalte, Slot-Zustand, Metadaten des Modells oder Informationen über interne Queues offenlegen. In `llama.cpp` ist der `/slots`-Endpunkt besonders sensibel, da er den Zustand der einzelnen Slots offenlegt und nur für die Inspektion bzw. Verwaltung von Slots vorgesehen ist.<sup>[[4]](#references)[[5]](#references)</sup>

- Einen Reverse Proxy vor den Inference-Server schalten und **standardmäßig alles ablehnen**.
- Nur die exakt benötigten Kombinationen aus HTTP-Methode und Pfad für den Client bzw. die UI allowlisten.
- Introspection-Endpunkte nach Möglichkeit direkt im Backend deaktivieren, zum Beispiel `llama-server --no-slots`.
- Den Reverse Proxy an `127.0.0.1` binden und ihn über einen authentifizierten Transport wie SSH Local Port Forwarding zugänglich machen, statt ihn im LAN zu veröffentlichen.

Beispiel für eine Allowlist mit nginx:
```nginx
map "$request_method:$uri" $llm_whitelist {
default 0;

"GET:/health"              1;
"GET:/v1/models"           1;
"POST:/v1/completions"     1;
"POST:/v1/chat/completions" 1;
}

server {
listen 127.0.0.1:80;

location / {
if ($llm_whitelist = 0) { return 403; }
proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
}
}
```
### Rootless-Container ohne Netzwerk und UNIX-Sockets

Wenn der Inference-Daemon das Lauschen an einem UNIX-Socket unterstützt, sollte dies gegenüber TCP bevorzugt und der Container mit **keinem Netzwerk-Stack** ausgeführt werden:
```bash
podman run --rm -d \
--network none \
--user 1000:1000 \
--userns=keep-id \
--umask=007 \
--volume /var/lib/models:/models:ro \
--volume /srv/llm/socks:/run/llama-cpp \
ghcr.io/ggml-org/llama.cpp:server-cuda13 \
--host /run/llama-cpp/llama-cpp.sock \
--model /models/model.gguf \
--parallel 4 \
--no-slots
```
Vorteile:
- `--network none` entfernt die eingehende/ausgehende TCP/IP-Exposition und vermeidet User-Mode-Hilfsprogramme, die rootless Container andernfalls benötigen würden.
- Ein UNIX-Socket ermöglicht die Verwendung von POSIX-Berechtigungen/ACLs auf dem Socket-Pfad als erste Zugriffskontrollschicht.
- `--userns=keep-id` und rootless Podman verringern die Auswirkungen eines container breakout, da Container-root nicht Host-root ist.
- Read-only-Model-Mounts verringern die Wahrscheinlichkeit einer Manipulation des Modells aus dem Container heraus.

### Minimierung von GPU-Device-Nodes

Für GPU-gestützte Inference sind `/dev/nvidia*`-Dateien besonders wertvolle lokale Angriffsflächen, da sie umfangreiche Treiber-`ioctl()`-Handler und potenziell gemeinsam genutzte GPU-Speicherverwaltungspfade offenlegen.<sup>[[4]](#references)</sup>

- `/dev/nvidia*` darf nicht für alle Benutzer schreibbar sein.
- Beschränke `nvidia`, `nvidiactl` und `nvidia-uvm` mit `NVreg_DeviceFileUID/GID/Mode`, udev-Regeln und ACLs, sodass nur die zugeordnete Container-UID sie öffnen kann.
- Deaktiviere unnötige Module wie `nvidia_drm`, `nvidia_modeset` und `nvidia_peermem` auf Headless-Inference-Hosts.
- Lade beim Booten nur die erforderlichen Module vor, anstatt der Runtime zu erlauben, sie beim Start der Inference opportunistisch per `modprobe` zu laden.

Beispiel:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Ein wichtiger Prüfpunkt ist **`/dev/nvidia-uvm`**. Selbst wenn die Workload nicht ausdrücklich `cudaMallocManaged()` verwendet, können aktuelle CUDA-Runtimes `nvidia-uvm` dennoch benötigen. Da dieses Gerät gemeinsam genutzt wird und die Verwaltung des virtuellen GPU-Speichers übernimmt, sollte es als Angriffsfläche für tenantübergreifende Datenlecks behandelt werden. Wenn das Inference-Backend dies unterstützt, kann ein Vulkan-Backend einen interessanten Kompromiss darstellen, da dadurch möglicherweise vollständig darauf verzichtet werden kann, `nvidia-uvm` für den Container freizugeben.

### LSM-Isolierung für Inference-Worker

AppArmor/SELinux/seccomp sollten als Defense in Depth rund um den Inference-Prozess eingesetzt werden:<sup>[[4]](#references)</sup>

- Nur die tatsächlich benötigten Shared Libraries, Model-Pfade, Socket-Verzeichnisse und GPU-Device-Nodes zulassen.
- Hochriskante Capabilities wie `sys_admin`, `sys_module`, `sys_rawio` und `sys_ptrace` ausdrücklich verweigern.
- Das Model-Verzeichnis schreibgeschützt halten und beschreibbare Pfade ausschließlich auf die Runtime-Socket-/Cache-Verzeichnisse begrenzen.
- Denial-Logs überwachen, da sie nützliche Detection-Telemetrie liefern, wenn der Model-Server oder ein Post-Exploitation-Payload versucht, aus seinem erwarteten Verhalten auszubrechen.

Beispielregeln für AppArmor für einen GPU-gestützten Worker:
```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```
## Phantom Squatting: Von LLM halluzinierte Domains als Vektor für die AI Supply-Chain

Phantom Squatting ist das **Domain-/URL-Äquivalent von Slopsquatting**. Anstatt einen nicht existierenden Paketnamen zu halluzinieren, halluziniert das LLM eine plausible **Portal-, API-, Webhook-, Billing-, SSO-, Download- oder Support-Domain** für eine reale Marke, und ein Angreifer registriert diesen Namespace, bevor ein Mensch oder Agent ihn verwendet.<sup>[[8]](#references)[[9]](#references)</sup>

Dies ist relevant, weil die Modellausgabe in vielen AI-unterstützten Workflows als **vertrauenswürdige Dependency** behandelt wird:
- Entwickler fügen den vorgeschlagenen Endpoint in Code oder CI/CD-Integrationen ein.
- AI agents rufen automatisch Dokumentation, Schemas, APKs, ZIPs oder Webhook-Ziele ab.
- Generierte Runbooks oder Dokumentationen können die gefälschte URL so einbetten, als wäre sie autoritativ.

### Offensiver Workflow

1. **Die Halluzinationsfläche untersuchen**: markenspezifische Fragen zu realistischen Workflows stellen, etwa zu `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` oder `mobile app`-Portalen.
2. **Kandidaten normalisieren**: generierte URLs auflösen, NXDOMAIN-Antworten auf die übergeordnete registrierbare Domain reduzieren und Prompt-Familien deduplizieren. Prompt-Korpora sollten vielfältig bleiben, beispielsweise indem nahezu identische Einträge anhand der **Jaccard-Ähnlichkeit** entfernt werden.
3. **Vorhersehbare Halluzinationen priorisieren**:
- **Thermal Hallucination Persistence (THP)**: Dieselbe gefälschte Domain erscheint bei verschiedenen Temperaturen, einschließlich niedriger Temperaturen wie `T=0.1`.
- **Modellübergreifender Konsens**: Mehrere LLM-Familien generieren dieselbe gefälschte Domain.
4. Die übergeordnete Domain **registrieren und weaponizen**, anschließend Phishing, gefälschte APK-/ZIP-Downloads, Credential Harvester, schädliche Dokumente oder API-Endpoints hosten, die Secrets/Webhook-Payloads sammeln. **Reine Halluzinationen auf Domain-Ebene** lassen sich am einfachsten monetarisieren, weil der Angreifer den gesamten Namespace kontrolliert; Halluzinationen von Subdomains/Pfaden können weiterhin missbraucht werden, wenn die normalisierte übergeordnete Domain nicht registriert ist.
5. Das **Zero-Reputation-Fenster ausnutzen**: Neu registrierten Domains fehlen häufig Blocklist-Historie, URL-Reputation und ausgereifte Telemetrie, sodass sie Kontrollen umgehen können, bis die Erkennungen nachziehen. Angreifer können dieses Fenster mit nur für Crawler bestimmten harmlosen Antworten, Redirect-Cloaking, CAPTCHA-Gates oder verzögertem Payload-Staging verlängern.

### Warum dies für Agents gefährlich ist

Für ein menschliches Opfer benötigt die gefälschte Domain normalerweise weiterhin einen Klick und eine weitere Aktion. In einem **agentischen Workflow** kann das LLM sowohl der **Köder** als auch der **Executor** sein: Der Agent erhält die halluzinierte URL, ruft sie ab, analysiert die Antwort und kann anschließend Tokens leaken, Anweisungen ausführen, eine Dependency herunterladen oder vergiftete Daten ohne menschliche Prüfung in CI/CD einschleusen.<sup>[[8]](#references)</sup>

### Praktische Angreifer-Prompts

Ertragreiche Prompts sehen normalerweise wie gewöhnliche Enterprise-Aufgaben aus und nicht wie explizite Phishing-Köder:
- „Wie lautet die Payment-Sandbox-URL für `<brand>`-Integrationen?“
- „Welchen Webhook-Endpoint sollte ich für `<brand>`-Build-Benachrichtigungen verwenden?“
- „Wo befindet sich das Employee-Benefits-/Billing-/SSO-Portal für `<brand>`?“
- „Gib mir den direkten Android-APK- oder Desktop-Client-Download für `<brand>`.“

### Defensive Umkehrung

Behandle dies als proaktives Domain-Monitoring-Problem und nicht nur als Prompt-Injection-Problem:
- Einen **Marken-Prompt-Korpus** aufbauen und die von deinen Benutzern/Agents verwendeten LLMs regelmäßig untersuchen.
- Halluzinierte URLs speichern und verfolgen, welche davon über Temperaturen/Modelle hinweg stabil sind.
- Das **Adversarial Exploitation Window (AEW)** verfolgen: die Zeit zwischen der ersten Halluzination und der Registrierung durch einen Angreifer. Ein positives AEW bedeutet, dass Verteidiger die Domain vor der Weaponization vorab registrieren, sinkholen oder blockieren können.
- **NXDOMAIN-zu-registriert**-Übergänge für die übergeordneten Domains überwachen.
- Bei der Registrierung Registrar, Erstellungsdatum, Nameserver, Privacy Shielding, Seiteninhalt, Screenshots, Status der geparkten Seite und Ähnlichkeit von Marken-Assets prüfen.
- Policy-Gates hinzufügen, damit Agents/Entwickler **LLM-generierten Domains standardmäßig nicht vertrauen**: Allowlists, Ownership-Validierung, CT-/RDAP-Prüfungen oder menschliche Freigabe vor der ersten Nutzung verlangen.

Dies fällt gleichzeitig in mehrere AI-Risikokategorien: **AI-Supply-Chain-Angriff**, **unsichere Modellausgabe** und **Rogue Actions**, wenn Agents die halluzinierte URL autonom verwenden.

## Referenzen
- [1] [Unit 42 – Die Risiken von Code-Assistant-LLMs: Schädliche Inhalte, Missbrauch und Täuschung](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [Übersicht zum LLMJacking-Schema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy (Weiterverkauf gestohlener LLM-Zugänge)](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv – Deep-Dive in die Bereitstellung eines On-Premise-LLM-Servers mit geringen Berechtigungen](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [README des llama.cpp-Servers](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Podman-Quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [CNCF Container Device Interface (CDI)-Spezifikation](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting: Von AI halluzinierte Domains als Vektor für die Software-Supply-Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting: Wie AI-Halluzinationen eine neue Klasse von Supply-Chain-Angriffen vorantreiben](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Google SAIF (Security AI Framework) Risks](https://saif.google/secure-ai-framework/risks)
- [12] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
