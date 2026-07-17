# AI-Risiken

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp hat die 10 wichtigsten Machine-Learning-Schwachstellen identifiziert, die AI-Systeme beeinträchtigen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, darunter Data Poisoning, Model Inversion und Adversarial Attacks. Das Verständnis dieser Schwachstellen ist entscheidend für den Aufbau sicherer AI-Systeme.

Eine aktualisierte und detaillierte Liste der 10 wichtigsten Machine-Learning-Schwachstellen findest du im Projekt [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Ein Angreifer fügt den **eingehenden Daten** winzige, oft unsichtbare Änderungen hinzu, damit das Modell eine falsche Entscheidung trifft.\
*Beispiel*: Einige Farbspritzer auf einem Stoppschild bringen ein selbstfahrendes Auto dazu, ein Tempolimit-Schild zu "sehen".

- **Data Poisoning Attack**: Das **Training Set** wird absichtlich mit fehlerhaften Samples verunreinigt, wodurch dem Modell schädliche Regeln beigebracht werden.\
*Beispiel*: Malware-Binaries werden in einem Antivirus-Trainingskorpus fälschlicherweise als "harmlos" gekennzeichnet, sodass ähnliche Malware später unentdeckt bleibt.

- **Model Inversion Attack**: Durch das Abfragen von Outputs erstellt ein Angreifer ein **Reverse Model**, das sensible Merkmale der ursprünglichen Inputs rekonstruiert.\
*Beispiel*: Rekonstruktion des MRT-Bildes eines Patienten anhand der Vorhersagen eines Krebsdetektionsmodells.

- **Membership Inference Attack**: Der Angreifer testet anhand von Unterschieden bei den Konfidenzwerten, ob ein **bestimmter Datensatz** beim Training verwendet wurde.\
*Beispiel*: Bestätigung, dass die Banktransaktion einer Person in den Trainingsdaten eines Betrugserkennungsmodells enthalten ist.

- **Model Theft**: Durch wiederholte Abfragen kann ein Angreifer Entscheidungsgrenzen erlernen und das **Verhalten des Modells klonen** (einschließlich des geistigen Eigentums).\
*Beispiel*: Das Sammeln ausreichender Frage-und-Antwort-Paare von einer ML-as-a-Service-API, um ein nahezu gleichwertiges lokales Modell zu erstellen.

- **AI Supply-Chain Attack**: Eine beliebige Komponente (Daten, Libraries, vortrainierte Weights, CI/CD) in der **ML-Pipeline** wird kompromittiert, um nachgelagerte Modelle zu manipulieren.\
*Beispiel*: Eine vergiftete Dependency auf einem Model Hub installiert ein mit einer Backdoor versehenes Sentiment-Analysis-Modell in zahlreichen Apps.

- **Transfer Learning Attack**: Schädliche Logik wird in einem **vortrainierten Modell** platziert und übersteht das Fine-Tuning für die Aufgabe des Opfers.\
*Beispiel*: Ein Vision-Backbone mit einem versteckten Trigger vertauscht weiterhin Labels, nachdem es für Medical Imaging angepasst wurde.

- **Model Skewing**: Subtil verzerrte oder falsch gelabelte Daten **verschieben die Outputs des Modells**, um die Ziele des Angreifers zu begünstigen.\
*Beispiel*: Das Einschleusen "sauberer" Spam-E-Mails mit dem Label Ham, sodass ein Spamfilter ähnliche zukünftige E-Mails durchlässt.

- **Output Integrity Attack**: Der Angreifer **verändert die Vorhersagen des Modells während der Übertragung**, nicht das Modell selbst, und täuscht dadurch nachgelagerte Systeme.\
*Beispiel*: Das Ändern des Ergebnisses eines Malware-Klassifikators von "schädlich" zu "harmlos", bevor die Datei-Quarantäne es verarbeitet.

- **Model Poisoning** --- Direkte, gezielte Änderungen an den **Modellparametern** selbst, oft nachdem Schreibzugriff erlangt wurde, um das Verhalten zu verändern.\
*Beispiel*: Das Anpassen der Weights eines Betrugserkennungsmodells in der Production, sodass Transaktionen bestimmter Karten immer genehmigt werden.


## Google SAIF Risks

Googles [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beschreibt verschiedene Risiken im Zusammenhang mit AI-Systemen:

- **Data Poisoning**: Böswillige Akteure verändern Trainings-/Tuning-Daten oder schleusen solche Daten ein, um die Genauigkeit zu verschlechtern, Backdoors einzubauen oder Ergebnisse zu verzerren. Dadurch wird die Integrität des Modells über den gesamten Data-Lifecycle hinweg beeinträchtigt.

- **Unauthorized Training Data**: Das Einbinden urheberrechtlich geschützter, sensibler oder nicht genehmigter Datensätze führt zu rechtlichen, ethischen und leistungsbezogenen Risiken, da das Modell aus Daten lernt, die es nie verwenden durfte.

- **Model Source Tampering**: Manipulationen durch die Supply Chain oder Insider an Model-Code, Dependencies oder Weights vor oder während des Trainings können versteckte Logik einbetten, die selbst nach einem erneuten Training bestehen bleibt.

- **Excessive Data Handling**: Schwache Data-Retention- und Governance-Kontrollen führen dazu, dass Systeme mehr personenbezogene Daten als nötig speichern oder verarbeiten, wodurch Exposure- und Compliance-Risiken steigen.

- **Model Exfiltration**: Angreifer stehlen Model-Dateien/Weights, was zum Verlust geistigen Eigentums führt und Copycat-Services oder Folgeangriffe ermöglicht.

- **Model Deployment Tampering**: Angreifer verändern Model-Artefakte oder die Serving-Infrastruktur, sodass sich das laufende Modell von der geprüften Version unterscheidet und sich dadurch möglicherweise sein Verhalten ändert.

- **Denial of ML Service**: Das Überfluten von APIs oder das Senden von "Sponge"-Inputs kann Rechenleistung und Energie aufbrauchen und das Modell offline nehmen, ähnlich wie klassische DoS-Angriffe.

- **Model Reverse Engineering**: Durch das Sammeln großer Mengen von Input-Output-Paaren können Angreifer das Modell klonen oder destillieren, wodurch Nachahmerprodukte und individuell angepasste Adversarial Attacks ermöglicht werden.

- **Insecure Integrated Component**: Verwundbare Plugins, Agents oder vorgelagerte Services ermöglichen es Angreifern, Code in die AI-Pipeline einzuschleusen oder Privilegien zu erweitern.

- **Prompt Injection**: Durch direkt oder indirekt formulierte Prompts werden Anweisungen eingeschleust, die die Systemabsicht überschreiben und das Modell dazu bringen, unbeabsichtigte Befehle auszuführen.

- **Model Evasion**: Sorgfältig gestaltete Inputs bringen das Modell dazu, falsch zu klassifizieren, zu halluzinieren oder nicht erlaubte Inhalte auszugeben, wodurch Sicherheit und Vertrauen beeinträchtigt werden.

- **Sensitive Data Disclosure**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem User-Kontext preis und verletzt dadurch Datenschutzanforderungen und gesetzliche Vorgaben.

- **Inferred Sensitive Data**: Das Modell leitet persönliche Merkmale ab, die nie bereitgestellt wurden, und verursacht dadurch neue Datenschutzverletzungen durch Inferenz.

- **Insecure Model Output**: Nicht bereinigte Antworten geben schädlichen Code, Fehlinformationen oder unangemessene Inhalte an User oder nachgelagerte Systeme weiter.

- **Rogue Actions**: Autonom integrierte Agents führen unbeabsichtigte Vorgänge in der realen Welt aus (Dateischreibvorgänge, API-Aufrufe, Käufe usw.), ohne ausreichende Kontrolle durch den User.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet ein umfassendes Framework zum Verständnis und zur Reduzierung von Risiken im Zusammenhang mit AI-Systemen. Sie kategorisiert verschiedene Attack Techniques und Tactics, die Angreifer gegen AI-Modelle einsetzen können, sowie Möglichkeiten, AI-Systeme für die Durchführung verschiedener Angriffe zu verwenden.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Angreifer stehlen aktive Session-Tokens oder Cloud-API-Credentials und rufen kostenpflichtige, in der Cloud gehostete LLMs unbefugt auf. Der Zugriff wird häufig über Reverse Proxies weiterverkauft, die das Konto des Opfers als Frontend verwenden, beispielsweise bei "oai-reverse-proxy"-Deployments. Zu den Folgen gehören finanzielle Verluste, eine nicht richtlinienkonforme Nutzung des Modells und eine Zuordnung zum Tenant des Opfers.

TTPs:
- Tokens von infizierten Developer-Maschinen oder Browsern abgreifen; CI/CD-Secrets stehlen; geleakte Cookies kaufen.
- Einen Reverse Proxy einrichten, der Requests an den echten Provider weiterleitet, den Upstream-Key verbirgt und viele Kunden über eine gemeinsame Verbindung bedient.
- Direkte Base-Model-Endpoints missbrauchen, um Enterprise-Guardrails und Rate Limits zu umgehen.

Mitigations:
- Tokens an Device-Fingerprint, IP-Ranges und Client-Attestation binden; kurze Ablaufzeiten erzwingen und die Erneuerung mit MFA absichern.
- Keys so wenig wie möglich berechtigen (kein Tool-Zugriff, sofern möglich nur Lesezugriff); bei Anomalien rotieren.
- Den gesamten Traffic serverseitig hinter einem Policy Gateway terminieren, das Safety Filters, Quotas pro Route und Tenant-Isolation erzwingt.
- Auf ungewöhnliche Nutzungsmuster achten (plötzliche Ausgabenspitzen, atypische Regionen, UA-Strings) und verdächtige Sessions automatisch widerrufen.
- mTLS oder signierte JWTs bevorzugen, die vom eigenen IdP ausgestellt werden, statt langlebiger statischer API-Keys.

## Self-hosted LLM inference hardening

Das Betreiben eines lokalen LLM-Servers für vertrauliche Daten erzeugt eine andere Angriffsfläche als Cloud-hosted APIs: Inference-/Debug-Endpoints können Prompts leaken, der Serving-Stack stellt üblicherweise einen Reverse Proxy bereit, und GPU-Device-Nodes gewähren Zugriff auf umfangreiche `ioctl()`-Oberflächen. Wenn du einen On-Prem-Inference-Service analysierst oder bereitstellst, solltest du mindestens die folgenden Punkte prüfen.

### Prompt leakage via debug and monitoring endpoints

Behandle die Inference-API als **sensiblen Multi-User-Service**. Debug- oder Monitoring-Routen können Prompt-Inhalte, Slot-Zustände, Model-Metadaten oder Informationen über interne Queues offenlegen. In `llama.cpp` ist der `/slots`-Endpoint besonders sensibel, da er den Zustand einzelner Slots offenlegt und nur für die Inspektion/Verwaltung von Slots vorgesehen ist.

- Einen Reverse Proxy vor den Inference-Server setzen und **standardmäßig alles verweigern**.
- Nur die exakten Kombinationen aus HTTP-Methode und Pfad allowlisten, die der Client/die UI benötigt.
- Introspection-Endpoints nach Möglichkeit direkt im Backend deaktivieren, beispielsweise mit `llama-server --no-slots`.
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
### Rootless-Container ohne Netzwerk und mit UNIX-Sockets

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
- `--network none` entfernt die eingehende/ausgehende TCP/IP-Exposition und vermeidet User-Mode-Helfer, die rootless Container andernfalls benötigen würden.
- Ein UNIX-Socket ermöglicht die Verwendung von POSIX-Berechtigungen/ACLs auf dem Socket-Pfad als erste Zugriffskontrollschicht.
- `--userns=keep-id` und rootless Podman reduzieren die Auswirkungen eines Container-Breakouts, da Container-root nicht Host-root ist.
- Read-only-Modell-Mounts verringern die Wahrscheinlichkeit einer Modell-Manipulation aus dem Container heraus.

### Minimierung von GPU-Device-Nodes

Bei GPU-gestützter Inferenz sind `/dev/nvidia*`-Dateien hochwertige lokale Angriffsflächen, da sie umfangreiche Treiber-`ioctl()`-Handler und potenziell gemeinsam genutzte GPU-Speicherverwaltungspfade offenlegen.

- `/dev/nvidia*` darf nicht global beschreibbar sein.
- Beschränke `nvidia`, `nvidiactl` und `nvidia-uvm` mit `NVreg_DeviceFileUID/GID/Mode`, udev-Regeln und ACLs so, dass nur die gemappte Container-UID sie öffnen kann.
- Deaktiviere unnötige Module wie `nvidia_drm`, `nvidia_modeset` und `nvidia_peermem` auf Headless-Inferenzhosts.
- Lade beim Booten nur die erforderlichen Module vor, anstatt dem Runtime während des Inferenzstarts opportunistisches `modprobe` zu erlauben.

Beispiel:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Ein wichtiger Prüfpunkt ist **`/dev/nvidia-uvm`**. Selbst wenn der Workload nicht ausdrücklich `cudaMallocManaged()` verwendet, können aktuelle CUDA-Runtimes `nvidia-uvm` dennoch benötigen. Da dieses Device gemeinsam genutzt wird und die Verwaltung des virtuellen GPU-Speichers übernimmt, sollte es als Angriffsfläche für Datenleaks zwischen Tenants behandelt werden. Wenn das Inference-Backend dies unterstützt, kann ein Vulkan-Backend ein interessanter Kompromiss sein, da dadurch möglicherweise vollständig vermieden wird, `nvidia-uvm` gegenüber dem Container freizugeben.

### LSM-Isolierung für Inference-Worker

AppArmor/SELinux/seccomp sollten als Defense in Depth rund um den Inference-Prozess eingesetzt werden:

- Nur die tatsächlich benötigten Shared Libraries, Model-Pfade, Socket-Verzeichnisse und GPU-Device-Nodes erlauben.
- Hochriskante Capabilities wie `sys_admin`, `sys_module`, `sys_rawio` und `sys_ptrace` ausdrücklich verweigern.
- Das Model-Verzeichnis schreibgeschützt halten und schreibbare Pfade ausschließlich auf die Runtime-Socket-/Cache-Verzeichnisse begrenzen.
- Denial-Logs überwachen, da sie nützliche Detection-Telemetrie liefern, wenn der Model-Server oder ein Post-Exploitation-Payload versucht, aus seinem erwarteten Verhalten auszubrechen.

Beispielhafte AppArmor-Regeln für einen GPU-gestützten Worker:
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
## Phantom Squatting: Von LLM halluzinierte Domains als AI-Supply-Chain-Vektor

Phantom Squatting ist das **Domain-/URL-Äquivalent von slopsquatting**. Statt eines nicht existierenden Paketnamens halluziniert das LLM eine plausible **Portal-, API-, Webhook-, Billing-, SSO-, Download- oder Support-Domain** für eine reale Marke, und ein Angreifer registriert diesen Namespace, bevor ein Mensch oder Agent ihn verwendet.

Dies ist relevant, weil die Modellausgabe in vielen AI-gestützten Workflows als **vertrauenswürdige Dependency** behandelt wird:
- Entwickler fügen den vorgeschlagenen Endpoint in Code oder CI/CD-Integrationen ein.
- AI agents rufen Dokumentation, Schemas, APKs, ZIPs oder Webhook-Ziele automatisch ab.
- Generierte Runbooks oder Dokumente können die gefälschte URL so einbetten, als wäre sie autoritativ.

### Offensive Vorgehensweise

1. **Die Halluzinationsfläche untersuchen**: markenspezifische Fragen zu realistischen Workflows stellen, etwa zu Portalen für `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` oder `mobile app`.
2. **Kandidaten normalisieren**: generierte URLs auflösen, NXDOMAIN-Antworten auf die übergeordnete registrierbare Domain reduzieren und Prompt-Familien deduplizieren. Prompt-Korpora sollten vielfältig bleiben, beispielsweise durch das Entfernen nahezu identischer Prompts anhand der **Jaccard-Ähnlichkeit**.
3. **Vorhersehbare Halluzinationen priorisieren**:
- **Thermal Hallucination Persistence (THP)**: Dieselbe gefälschte Domain erscheint über verschiedene Temperaturen hinweg, einschließlich niedriger Temperaturen wie `T=0.1`.
- **Cross-Model-Konsens**: Mehrere LLM-Familien generieren dieselbe gefälschte Domain.
4. Die übergeordnete Domain **registrieren und weaponizen**, anschließend Phishing, gefälschte APK-/ZIP-Downloads, Credential-Harvester, schädliche Dokumente oder API-Endpoints hosten, die Secrets/Webhook-Payloads sammeln. **Reine Halluzinationen auf Domain-Ebene** lassen sich am einfachsten monetarisieren, da der Angreifer den gesamten Namespace kontrolliert; Halluzinationen von Subdomains/Pfaden können dennoch missbraucht werden, wenn die normalisierte übergeordnete Domain nicht registriert ist.
5. Das **Zero-Reputation-Fenster ausnutzen**: Neu registrierte Domains verfügen häufig noch nicht über Blocklist-Historie, URL-Reputation oder ausgereifte Telemetrie und können daher Kontrollen umgehen, bis die Erkennungsmechanismen nachziehen. Angreifer können dieses Fenster mit crawler-only benign responses, Redirect-Cloaking, CAPTCHA-Gates oder verzögertem Payload-Staging verlängern.

### Warum dies für Agents gefährlich ist

Für ein menschliches Opfer benötigt die gefälschte Domain normalerweise noch einen Klick und eine weitere Aktion. In einem **agentischen Workflow** kann das LLM sowohl der **Köder** als auch der **Executor** sein: Der Agent erhält die halluzinierte URL, ruft sie ab, verarbeitet die Antwort und kann anschließend Tokens leaken, Anweisungen ausführen, eine Dependency herunterladen oder vergiftete Daten ohne menschliche Prüfung in CI/CD einschleusen.

### Praktische Angreifer-Prompts

Ertragreiche Prompts sehen meist wie normale Enterprise-Aufgaben aus und nicht wie explizite Phishing-Köder:
- „Wie lautet die Payment-Sandbox-URL für `<brand>`-Integrationen?“
- „Welchen Webhook-Endpoint sollte ich für `<brand>`-Build-Benachrichtigungen verwenden?“
- „Wo befindet sich das Employee-Benefits-/Billing-/SSO-Portal für `<brand>`?“
- „Gib mir den direkten Android-APK- oder Desktop-Client-Download für `<brand>`.“

### Defensive Umkehrung

Behandle dies als proaktives Domain-Monitoring-Problem und nicht nur als Prompt-Injection-Problem:
- Einen **Marken-Prompt-Korpus** aufbauen und die von deinen Benutzern/Agents verwendeten LLMs regelmäßig testen.
- Halluzinierte URLs speichern und verfolgen, welche über verschiedene Temperaturen/Modelle hinweg stabil bleiben.
- Das **Adversarial Exploitation Window (AEW)** verfolgen: die Zeit zwischen der ersten Halluzination und der Registrierung durch den Angreifer. Ein positives AEW bedeutet, dass Verteidiger die Domain vor der Weaponisierung vorab registrieren, in einen Sinkhole umleiten oder blockieren können.
- **NXDOMAIN → registriert**-Übergänge für die übergeordneten Domains überwachen.
- Bei einer Registrierung Registrar, Erstellungsdatum, Nameserver, Privacy-Shielding, Seiteninhalt, Screenshots, Status geparkter Seiten und Ähnlichkeit von Marken-Assets prüfen.
- Policy-Gates hinzufügen, damit Agents/Entwickler **LLM-generierten Domains standardmäßig nicht vertrauen**: Allowlists, Eigentumsvalidierung, CT-/RDAP-Prüfungen oder menschliche Genehmigung vor der ersten Verwendung verlangen.

Dies fällt gleichzeitig in mehrere AI-Risikokategorien: **AI-Supply-Chain-Angriff**, **unsichere Modellausgabe** und **Rogue Actions**, wenn Agents die halluzinierte URL autonom verwenden.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
