# AI-Risiken

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp hat die 10 wichtigsten Machine-Learning-Schwachstellen identifiziert, die AI-Systeme betreffen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, darunter Data Poisoning, Model Inversion und adversarial attacks. Das Verständnis dieser Schwachstellen ist entscheidend für den Aufbau sicherer AI-Systeme.

Eine aktualisierte und detaillierte Liste der 10 wichtigsten Machine-Learning-Schwachstellen findest du im Projekt [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Ein Angreifer fügt **eingehenden Daten** winzige, oft unsichtbare Änderungen hinzu, sodass das Modell die falsche Entscheidung trifft.\
*Beispiel*: Einige Farbspritzer auf einem Stoppschild bringen ein selbstfahrendes Auto dazu, ein Geschwindigkeitsbegrenzungsschild zu "sehen".

- **Data Poisoning Attack**: Der **Trainingsdatensatz** wird absichtlich mit fehlerhaften Beispielen verunreinigt, wodurch das Modell schädliche Regeln erlernt.\
*Beispiel*: Malware-Binärdateien werden in einem Trainingskorpus für Antivirussoftware fälschlicherweise als "harmlos" gekennzeichnet, sodass ähnliche Malware später unentdeckt bleibt.

- **Model Inversion Attack**: Durch das Abfragen von Ausgaben erstellt ein Angreifer ein **umgekehrtes Modell**, das sensible Merkmale der ursprünglichen Eingaben rekonstruiert.\
*Beispiel*: Rekonstruktion des MRT-Bildes eines Patienten aus den Vorhersagen eines Modells zur Krebserkennung.

- **Membership Inference Attack**: Der Angreifer testet anhand von Unterschieden bei den Konfidenzwerten, ob ein **bestimmter Datensatz** während des Trainings verwendet wurde.\
*Beispiel*: Bestätigen, dass die Banktransaktion einer Person in den Trainingsdaten eines Modells zur Betrugserkennung enthalten ist.

- **Model Theft**: Wiederholte Abfragen ermöglichen es einem Angreifer, Entscheidungsgrenzen zu erlernen und das **Verhalten des Modells zu klonen** (einschließlich des geistigen Eigentums).\
*Beispiel*: Das Sammeln ausreichender Frage-und-Antwort-Paare aus einer ML-as-a-Service-API, um ein nahezu gleichwertiges lokales Modell zu erstellen.

- **AI Supply-Chain Attack**: Kompromittierung beliebiger Komponenten (Daten, Bibliotheken, vortrainierte Gewichte, CI/CD) in der **ML-Pipeline**, um nachgelagerte Modelle zu manipulieren.\
*Beispiel*: Eine vergiftete Abhängigkeit aus einem Model-Hub installiert in zahlreichen Apps ein mit einer Backdoor versehenes Modell zur Sentimentanalyse.

- **Transfer Learning Attack**: Schädliche Logik wird in einem **vortrainierten Modell** platziert und überlebt das Fine-Tuning für die Aufgabe des Opfers.\
*Beispiel*: Ein Vision-Backbone mit einem versteckten Trigger vertauscht weiterhin Labels, nachdem es für medizinische Bildgebung angepasst wurde.

- **Model Skewing**: Subtil voreingenommene oder falsch beschriftete Daten **verschieben die Ausgaben des Modells**, um die Ziele des Angreifers zu unterstützen.\
*Beispiel*: Einspeisen von "sauberen" Spam-E-Mails, die als Ham gekennzeichnet sind, sodass ein Spamfilter ähnliche zukünftige E-Mails durchlässt.

- **Output Integrity Attack**: Der Angreifer **verändert die Modellvorhersagen während der Übertragung**, nicht das Modell selbst, und täuscht dadurch nachgelagerte Systeme.\
*Beispiel*: Ändern des Ergebnisses "schädlich" eines Malware-Klassifikators in "harmlos", bevor die Dateiquarantäne es erhält.

- **Model Poisoning** --- Direkte, gezielte Änderungen an den **Modellparametern** selbst, oft nach dem Erlangen von Schreibzugriff, um das Verhalten zu verändern.\
*Beispiel*: Ändern der Gewichte eines Modells zur Betrugserkennung in der Produktion, sodass Transaktionen bestimmter Karten immer genehmigt werden.


## Google SAIF Risks

Googles [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beschreibt verschiedene Risiken im Zusammenhang mit AI-Systemen:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Böswillige Akteure verändern Trainings- oder Tuning-Daten oder schleusen solche Daten ein, um die Genauigkeit zu verschlechtern, Backdoors einzubauen oder Ergebnisse zu verzerren, wodurch die Modellintegrität über den gesamten Datenlebenszyklus hinweg beeinträchtigt wird.

- **Unauthorized Training Data**: Die Verwendung urheberrechtlich geschützter, sensibler oder nicht genehmigter Datensätze schafft rechtliche, ethische und leistungsbezogene Haftungsrisiken, da das Modell aus Daten lernt, deren Nutzung nie erlaubt war.

- **Model Source Tampering**: Manipulation von Modellcode, Abhängigkeiten oder Gewichten in der Supply Chain oder durch Insider vor oder während des Trainings kann versteckte Logik einbetten, die auch nach erneutem Training bestehen bleibt.

- **Excessive Data Handling**: Schwache Kontrollen für Datenaufbewahrung und Governance führen dazu, dass Systeme mehr personenbezogene Daten als erforderlich speichern oder verarbeiten, wodurch das Risiko von Datenleaks und Compliance-Verstößen steigt.

- **Model Exfiltration**: Angreifer stehlen Modelldateien oder Gewichte, wodurch geistiges Eigentum verloren geht und Nachahmerdienste oder Folgeangriffe ermöglicht werden.

- **Model Deployment Tampering**: Angreifer verändern Modellartefakte oder die Serving-Infrastruktur, sodass sich das laufende Modell von der geprüften Version unterscheidet und sich dadurch möglicherweise sein Verhalten ändert.

- **Denial of ML Service**: Das Überfluten von APIs oder das Senden von „Sponge“-Eingaben kann Rechenleistung und Energie erschöpfen und das Modell offline nehmen, ähnlich wie bei klassischen DoS-Angriffen.

- **Model Reverse Engineering**: Durch das Sammeln großer Mengen von Eingabe-Ausgabe-Paaren können Angreifer das Modell klonen oder destillieren, wodurch Nachahmerprodukte und angepasste adversarial attacks ermöglicht werden.

- **Insecure Integrated Component**: Verwundbare Plugins, Agents oder vorgelagerte Services ermöglichen es Angreifern, Code einzuschleusen oder innerhalb der AI-Pipeline Privilegien zu erweitern.

- **Prompt Injection**: Durch direktes oder indirektes Erstellen von Prompts werden Anweisungen eingeschleust, die die Systemabsicht überschreiben und das Modell dazu bringen, unbeabsichtigte Befehle auszuführen.

- **Model Evasion**: Sorgfältig entworfene Eingaben veranlassen das Modell zu Fehlklassifizierungen, Halluzinationen oder der Ausgabe nicht erlaubter Inhalte, wodurch Sicherheit und Vertrauen beeinträchtigt werden.

- **Sensitive Data Disclosure**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem Benutzerkontext preis und verletzt dadurch Datenschutz und Vorschriften.

- **Inferred Sensitive Data**: Das Modell leitet persönliche Merkmale ab, die nie bereitgestellt wurden, und erzeugt dadurch durch Inferenz neue Datenschutzverletzungen.

- **Insecure Model Output**: Nicht bereinigte Antworten übermitteln schädlichen Code, Desinformation oder unangemessene Inhalte an Benutzer oder nachgelagerte Systeme.

- **Rogue Actions**: Autonom integrierte Agents führen unbeabsichtigte Vorgänge in der realen Welt aus (Dateischreibvorgänge, API-Aufrufe, Käufe usw.), ohne ausreichende Benutzerüberwachung.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet ein umfassendes Framework zum Verständnis und zur Minderung von Risiken im Zusammenhang mit AI-Systemen. Sie kategorisiert verschiedene Angriffstechniken und Taktiken, die Angreifer gegen AI-Modelle einsetzen können, und beschreibt außerdem, wie AI-Systeme für die Durchführung verschiedener Angriffe verwendet werden können.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Angreifer stehlen aktive Session-Tokens oder Cloud-API-Credentials und nutzen kostenpflichtige, in der Cloud gehostete LLMs ohne Autorisierung. Der Zugriff wird häufig über Reverse Proxies weiterverkauft, die dem Account des Opfers vorgeschaltet sind, beispielsweise durch "oai-reverse-proxy"-Deployments. Zu den Folgen gehören finanzielle Verluste, eine nicht richtlinienkonforme Nutzung des Modells und die Zuordnung der Aktivitäten zum Tenant des Opfers.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Tokens von infizierten Entwicklergeräten oder Browsern erbeuten; CI/CD-Secrets stehlen; geleakte Cookies kaufen.<sup>[[5]](#references)</sup>
- Einen Reverse Proxy einrichten, der Anfragen an den echten Provider weiterleitet, den Upstream-Key verbirgt und viele Kunden über eine gemeinsame Verbindung multiplexed.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Direkte Base-Model-Endpunkte missbrauchen, um Enterprise-Guardrails und Rate Limits zu umgehen.<sup>[[4]](#references)</sup>

Mitigations:
- Tokens an Geräte-Fingerprints, IP-Bereiche und Client-Attestation binden; kurze Ablaufzeiten erzwingen und die Erneuerung mit MFA durchführen.
- Keys so minimal wie möglich berechtigen (kein Tool-Zugriff, sofern möglich schreibgeschützt); bei Anomalien rotieren.
- Den gesamten Traffic serverseitig hinter einem Policy-Gateway beenden, das Safety-Filter, Quotas pro Route und Tenant-Isolation erzwingt.
- Auf ungewöhnliche Nutzungsmuster achten (plötzliche Ausgabenspitzen, atypische Regionen, UA-Strings) und verdächtige Sessions automatisch widerrufen.
- mTLS oder signierte JWTs bevorzugen, die vom eigenen IdP ausgestellt werden, statt langlebiger statischer API-Keys.

## Absicherung von Self-hosted LLM-Inferenz

Das Betreiben eines lokalen LLM-Servers für vertrauliche Daten erzeugt eine andere Angriffsfläche als Cloud-hosted APIs: Inferenz- und Debug-Endpunkte können Prompts leaken, der Serving-Stack stellt üblicherweise einen Reverse Proxy bereit, und GPU-Device-Nodes ermöglichen den Zugriff auf umfangreiche `ioctl()`-Angriffsflächen. Wenn du einen On-Prem-Inferenzservice bewertest oder bereitstellst, solltest du mindestens die folgenden Punkte prüfen.<sup>[[8]](#references)</sup>

### Prompt-Leaks über Debug- und Monitoring-Endpunkte

Behandle die Inferenz-API als **sensiblen Multi-User-Service**. Debug- oder Monitoring-Routen können Prompt-Inhalte, Slot-Zustände, Metadaten des Modells oder Informationen über interne Warteschlangen offenlegen. In `llama.cpp` ist der `/slots`-Endpunkt besonders sensibel, da er den Zustand der einzelnen Slots offenlegt und nur zur Inspektion oder Verwaltung von Slots vorgesehen ist.<sup>[[8]](#references)</sup>

- Einen Reverse Proxy vor den Inferenzserver setzen und **standardmäßig alles ablehnen**.
- Nur die für den Client bzw. die UI benötigten exakten Kombinationen aus HTTP-Methode und Pfad allowlisten.
- Introspection-Endpunkte nach Möglichkeit direkt im Backend deaktivieren, beispielsweise mit `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Den Reverse Proxy an `127.0.0.1` binden und ihn über einen authentifizierten Transport wie SSH Local Port Forwarding erreichbar machen, statt ihn im LAN zu veröffentlichen.

Beispiel einer Allowlist mit nginx:
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

Wenn der Inferenz-Daemon das Lauschen an einem UNIX-Socket unterstützt, sollte dieser gegenüber TCP bevorzugt und der Container mit **keinem Netzwerk-Stack** ausgeführt werden:<sup>[[8]](#references)</sup>
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
- `--network none` entfernt die eingehende/ausgehende TCP/IP-Exposition und vermeidet User-Mode-Hilfsprogramme, die Rootless-Container andernfalls benötigen würden.
- Ein UNIX-Socket ermöglicht die Verwendung von POSIX-Berechtigungen/ACLs auf dem Socket-Pfad als erste Zugriffskontrollschicht.
- `--userns=keep-id` und rootless Podman reduzieren die Auswirkungen eines Container-Ausbruchs, da Container-root nicht dem Host-root entspricht.
- Read-only Model-Mounts verringern die Wahrscheinlichkeit einer Manipulation des Modells aus dem Container heraus.

Für persistente Deployments können dieselben Einschränkungen als Podman-Quadlet-Units ausgedrückt werden. Wenn der GPU-Zugriff über die Container Device Interface delegiert wird, sollte die CDI-Gerätespezifikation so eng wie möglich gehalten werden, anstatt jeden Accelerator-Node freizugeben.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimierung von GPU-Device-Nodes

Bei GPU-gestützter Inference sind `/dev/nvidia*`-Dateien besonders wertvolle lokale Angriffsflächen, da sie umfangreiche Treiber-`ioctl()`-Handler und potenziell gemeinsam genutzte GPU-Speicherverwaltungspfade offenlegen.<sup>[[8]](#references)</sup>

- `/dev/nvidia*` darf nicht für alle Benutzer schreibbar sein.
- `nvidia`, `nvidiactl` und `nvidia-uvm` mit `NVreg_DeviceFileUID/GID/Mode`, udev-Regeln und ACLs so beschränken, dass nur die zugeordnete Container-UID sie öffnen kann.
- Nicht erforderliche Module wie `nvidia_drm`, `nvidia_modeset` und `nvidia_peermem` auf Headless-Inference-Hosts blacklisten.
- Beim Booten nur die erforderlichen Module vorab laden, anstatt dem Runtime während des Starts der Inference opportunistisches `modprobe` zu erlauben.

Beispiel:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Ein wichtiger Prüfpunkt ist **`/dev/nvidia-uvm`**. Auch wenn die Workload nicht ausdrücklich `cudaMallocManaged()` verwendet, können aktuelle CUDA-Runtimes `nvidia-uvm` dennoch benötigen. Da dieses Gerät gemeinsam genutzt wird und das Management des virtuellen GPU-Speichers übernimmt, sollte es als Angriffsfläche für Datenlecks zwischen Tenants betrachtet werden. Falls das Inference-Backend dies unterstützt, kann ein Vulkan-Backend einen interessanten Kompromiss darstellen, da dadurch möglicherweise vollständig vermieden wird, `nvidia-uvm` für den Container freizugeben.<sup>[[8]](#references)</sup>

### LSM-Isolierung für Inference-Worker

AppArmor/SELinux/seccomp sollten als Defense-in-Depth-Maßnahmen rund um den Inference-Prozess eingesetzt werden:<sup>[[8]](#references)</sup>

- Nur die tatsächlich benötigten Shared Libraries, Model-Pfade, Socket-Verzeichnisse und GPU-Geräteknoten erlauben.
- Hochriskante Capabilities wie `sys_admin`, `sys_module`, `sys_rawio` und `sys_ptrace` ausdrücklich verweigern.
- Das Model-Verzeichnis schreibgeschützt halten und schreibbare Pfade ausschließlich auf die Runtime-Socket-/Cache-Verzeichnisse beschränken.
- Denial-Logs überwachen, da sie nützliche Detection-Telemetrie liefern, wenn der Model-Server oder ein Post-Exploitation-Payload versucht, aus seinem erwarteten Verhaltensbereich auszubrechen.

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
## Phantom Squatting: Von LLMs halluzinierte Domains als AI-Supply-Chain-Vektor

Phantom squatting ist das **Domain-/URL-Äquivalent von slopsquatting**. Statt eines nicht existierenden Paketnamens halluziniert das LLM eine plausible **Portal-, API-, Webhook-, Billing-, SSO-, Download- oder Support-Domain** für eine reale Marke, und ein Angreifer registriert diesen Namespace, bevor ein Mensch oder Agent ihn verwendet.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Das ist relevant, weil die Modellausgabe in vielen AI-gestützten Workflows als **vertrauenswürdige Dependency** behandelt wird:
- Entwickler fügen den vorgeschlagenen Endpoint in Code oder CI/CD-Integrationen ein.
- AI-Agents rufen automatisch Dokumentation, Schemas, APKs, ZIPs oder Webhook-Ziele ab.
- Generierte Runbooks oder Dokumente können die gefälschte URL so einbetten, als wäre sie autoritativ.

### Offensive Vorgehensweise

1. **Die Halluzinationsfläche sondieren**: Stelle markenspezifische Fragen zu realistischen Workflows wie `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` oder `mobile app`-Portalen.<sup>[[12]](#references)</sup>
2. **Kandidaten normalisieren**: Löse generierte URLs auf, fasse NXDOMAIN-Antworten auf die übergeordnete registrierbare Domain zusammen und entferne Duplikate aus Prompt-Familien. Prompt-Korpora sollten vielfältig bleiben, beispielsweise indem nahezu identische Einträge mit **Jaccard similarity** entfernt werden.
3. **Vorhersehbare Halluzinationen priorisieren**:
- **Thermal Hallucination Persistence (THP)**: Dieselbe gefälschte Domain erscheint über verschiedene Temperaturen hinweg, einschließlich niedriger Temperaturen wie `T=0.1`.
- **Cross-model consensus**: Mehrere LLM-Familien generieren dieselbe gefälschte Domain.
4. **Die übergeordnete Domain registrieren und weaponizen**, anschließend Phishing, gefälschte APK-/ZIP-Downloads, Credential-Harvester, schädliche Dokumente oder API-Endpoints hosten, die Secrets/Webhook-Payloads sammeln. **Reine Halluzinationen auf Domain-Ebene** lassen sich am einfachsten monetarisieren, da der Angreifer den gesamten Namespace kontrolliert; Halluzinationen von Subdomains/Pfaden können weiterhin missbraucht werden, wenn die normalisierte übergeordnete Domain nicht registriert ist.
5. **Das Zero-Reputation-Fenster ausnutzen**: Neu registrierten Domains fehlen häufig Blocklist-Historie, URL-Reputation und ausgereifte Telemetrie. Dadurch können sie Kontrollen umgehen, bis die Erkennungen nachziehen. Angreifer können dieses Fenster mit nur für Crawler bestimmten harmlosen Antworten, Redirect-Cloaking, CAPTCHA-Gates oder verzögertem Payload-Staging verlängern.

### Warum dies für Agents gefährlich ist

Für ein menschliches Opfer benötigt die gefälschte Domain normalerweise noch einen Klick und eine weitere Aktion. In einem **agentischen Workflow** kann das LLM sowohl der **Köder** als auch der **Ausführer** sein: Der Agent erhält die halluzinierte URL, ruft sie ab, verarbeitet die Antwort und kann anschließend Tokens leaken, Anweisungen ausführen, eine Dependency herunterladen oder vergiftete Daten ohne menschliche Prüfung in CI/CD einspielen.<sup>[[12]](#references)</sup>

### Praktische Angreifer-Prompts

Ertragreiche Prompts sehen meist wie normale Enterprise-Aufgaben aus und nicht wie explizite Phishing-Köder:<sup>[[12]](#references)</sup>
- „Wie lautet die Payment-Sandbox-URL für `<brand>`-Integrationen?“
- „Welchen Webhook-Endpoint soll ich für `<brand>`-Build-Benachrichtigungen verwenden?“
- „Wo befindet sich das Employee-Benefits-/Billing-/SSO-Portal für `<brand>`?“
- „Gib mir den direkten Android-APK- oder Desktop-Client-Download für `<brand>`.“

### Defensive Umkehrung

Behandle dies als proaktives Domain-Monitoring-Problem und nicht nur als Prompt-Injection-Problem:<sup>[[12]](#references)</sup>
- Erstelle ein **Brand-Prompt-Korpus** und sondiere regelmäßig die LLMs, auf die sich deine Benutzer/Agents verlassen.
- Speichere halluzinierte URLs und verfolge, welche über Temperaturen/Modelle hinweg stabil bleiben.
- Verfolge das **Adversarial Exploitation Window (AEW)**: die Zeit zwischen der ersten Halluzination und der Registrierung durch den Angreifer. Ein positives AEW bedeutet, dass Verteidiger vor der Weaponisierung vorregistrieren, sinkholen oder blockieren können.
- Überwache Übergänge von **NXDOMAIN → registriert** für die übergeordneten Domains.
- Prüfe bei einer Registrierung Registrar, Erstellungsdatum, Nameserver, Privacy Shielding, Seiteninhalte, Screenshots, den Status geparkter Seiten und die Ähnlichkeit von Brand-Assets.
- Füge Policy-Gates hinzu, damit Agents/Entwickler **LLM-generierten Domains standardmäßig nicht vertrauen**: Verlange Allowlists, eine Validierung der Inhaberschaft, CT-/RDAP-Prüfungen oder eine menschliche Freigabe vor der ersten Nutzung.

Dies fällt gleichzeitig in mehrere AI-Risikokategorien: **AI-Supply-Chain-Angriff**, **unsichere Modellausgabe** und **Rogue Actions**, wenn Agents die halluzinierte URL autonom verwenden.

## References

- [1] [OWASP Top 10 Machine-Learning-Schwachstellen](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risiken](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Die Risiken von Code-Assistant-LLMs: Schädliche Inhalte, Missbrauch und Täuschung](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Gestohlene Cloud-Credentials bei einem neuen AI-Angriff verwendet](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Überblick über das LLMJacking-Schema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (Weiterverkauf gestohlener LLM-Zugänge)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv – Tiefenanalyse der Bereitstellung eines On-Premise-LLM-Servers mit geringen Berechtigungen](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp-Server-README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman-Quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI)-Spezifikation](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Von AI halluzinierte Domains als Vektor für Software-Supply-Chain-Angriffe](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Wie AI-Halluzinationen eine neue Klasse von Supply-Chain-Angriffen fördern](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
