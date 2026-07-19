# AI-Risiken

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine-Learning-Schwachstellen

OWASP hat die zehn wichtigsten Machine-Learning-Schwachstellen identifiziert, die AI-Systeme betreffen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, darunter Data Poisoning, Model Inversion und Adversarial Attacks. Das Verständnis dieser Schwachstellen ist entscheidend für den Aufbau sicherer AI-Systeme.

Eine aktualisierte und detaillierte Liste der zehn wichtigsten Machine-Learning-Schwachstellen finden Sie im Projekt [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Ein Angreifer fügt **eingehenden Daten** winzige, oft unsichtbare Änderungen hinzu, damit das Modell die falsche Entscheidung trifft.\
*Beispiel*: Einige Farbspritzer auf einem Stoppschild bringen ein selbstfahrendes Auto dazu, ein Geschwindigkeitsbegrenzungsschild zu "sehen".

- **Data Poisoning Attack**: Der **Trainingsdatensatz** wird absichtlich mit fehlerhaften Samples verunreinigt, wodurch dem Modell schädliche Regeln beigebracht werden.\
*Beispiel*: Malware-Binärdateien werden in einem Antivirus-Trainingskorpus fälschlich als "harmlos" markiert, sodass ähnliche Malware später durchgelassen wird.

- **Model Inversion Attack**: Durch das Abfragen von Outputs erstellt ein Angreifer ein **umgekehrtes Modell**, das sensible Merkmale der ursprünglichen Inputs rekonstruiert.\
*Beispiel*: Rekonstruktion des MRT-Bildes eines Patienten aus den Vorhersagen eines Krebs-Erkennungsmodells.

- **Membership Inference Attack**: Der Angreifer testet anhand von Konfidenzunterschieden, ob ein **bestimmter Datensatz** beim Training verwendet wurde.\
*Beispiel*: Bestätigung, dass die Banktransaktion einer Person in den Trainingsdaten eines Betrugserkennungsmodells enthalten ist.

- **Model Theft**: Wiederholte Abfragen ermöglichen es einem Angreifer, Entscheidungsgrenzen zu erlernen und das **Verhalten des Modells** (sowie dessen IP) zu **klonen**.\
*Beispiel*: Das Sammeln ausreichender Frage-und-Antwort-Paare von einer ML-as-a-Service-API, um ein nahezu gleichwertiges lokales Modell zu erstellen.

- **AI Supply-Chain Attack**: Jede Komponente (Daten, Bibliotheken, vortrainierte Weights, CI/CD) in der **ML-Pipeline** wird kompromittiert, um nachgelagerte Modelle zu manipulieren.\
*Beispiel*: Eine vergiftete Dependency aus einem Model-Hub installiert in zahlreichen Apps ein mit einer Backdoor versehenes Sentiment-Analysis-Modell.

- **Transfer Learning Attack**: Schadlogik wird in einem **vortrainierten Modell** platziert und überlebt das Fine-Tuning für die Aufgabe des Opfers.\
*Beispiel*: Ein Vision-Backbone mit einem versteckten Trigger vertauscht weiterhin Labels, nachdem es für Medical Imaging angepasst wurde.

- **Model Skewing**: Subtil verzerrte oder falsch markierte Daten **verschieben die Outputs des Modells**, um die Ziele des Angreifers zu begünstigen.\
*Beispiel*: Einspeisen "sauberer" Spam-E-Mails, die als Ham markiert sind, sodass ein Spamfilter ähnliche zukünftige E-Mails durchlässt.

- **Output Integrity Attack**: Der Angreifer **verändert die Vorhersagen des Modells während der Übertragung**, nicht das Modell selbst, und täuscht dadurch nachgelagerte Systeme.\
*Beispiel*: Das Urteil "bösartig" eines Malware-Classifiers wird in "harmlos" geändert, bevor die Datei-Quarantäne es verarbeitet.

- **Model Poisoning** --- Direkte, gezielte Änderungen an den **Modellparametern** selbst, häufig nachdem Schreibzugriff erlangt wurde, um das Verhalten zu verändern.\
*Beispiel*: Anpassen der Weights eines Betrugserkennungsmodells in der Produktion, sodass Transaktionen bestimmter Karten immer genehmigt werden.


## Google SAIF-Risiken

Googles [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beschreibt verschiedene Risiken im Zusammenhang mit AI-Systemen:

- **Data Poisoning**: Böswillige Akteure verändern Trainings- oder Tuning-Daten oder fügen solche Daten ein, um die Genauigkeit zu verschlechtern, Backdoors einzubauen oder Ergebnisse zu verzerren. Dadurch wird die Integrität des Modells über den gesamten Data-Lifecycle hinweg beeinträchtigt.

- **Unauthorized Training Data**: Die Verwendung urheberrechtlich geschützter, sensibler oder nicht genehmigter Datensätze erzeugt rechtliche, ethische und leistungsbezogene Risiken, da das Modell aus Daten lernt, die es nie verwenden durfte.

- **Model Source Tampering**: Supply-Chain- oder Insider-Manipulationen an Modellcode, Dependencies oder Weights vor oder während des Trainings können versteckte Logik einbetten, die auch nach einem erneuten Training bestehen bleibt.

- **Excessive Data Handling**: Schwache Kontrollen für Datenaufbewahrung und Governance führen dazu, dass Systeme mehr personenbezogene Daten als nötig speichern oder verarbeiten, wodurch das Risiko von Datenleaks und Compliance-Verstößen steigt.

- **Model Exfiltration**: Angreifer stehlen Modelldateien oder Weights, was zum Verlust geistigen Eigentums führt und Copycat-Services oder Folgeangriffe ermöglicht.

- **Model Deployment Tampering**: Angreifer verändern Modellartefakte oder die Serving-Infrastruktur, sodass sich das laufende Modell von der geprüften Version unterscheidet und sich möglicherweise sein Verhalten ändert.

- **Denial of ML Service**: Das Überfluten von APIs oder das Senden von "Sponge"-Inputs kann Rechenleistung und Energie erschöpfen und das Modell offline nehmen, ähnlich wie bei klassischen DoS-Angriffen.

- **Model Reverse Engineering**: Durch das Sammeln großer Mengen von Input-Output-Paaren können Angreifer das Modell klonen oder destillieren, wodurch Imitationsprodukte und angepasste Adversarial Attacks ermöglicht werden.

- **Insecure Integrated Component**: Verwundbare Plugins, Agents oder vorgelagerte Services ermöglichen es Angreifern, Code in die AI-Pipeline einzuschleusen oder ihre Rechte zu erweitern.

- **Prompt Injection**: Durch direktes oder indirektes Erstellen von Prompts werden Anweisungen eingeschleust, die die Systemabsicht überschreiben und das Modell dazu bringen, unbeabsichtigte Befehle auszuführen.

- **Model Evasion**: Sorgfältig entworfene Inputs veranlassen das Modell, falsch zu klassifizieren, zu halluzinieren oder nicht erlaubte Inhalte auszugeben, wodurch Sicherheit und Vertrauen beeinträchtigt werden.

- **Sensitive Data Disclosure**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem Benutzerkontext preis und verletzt dadurch Datenschutzvorgaben und gesetzliche Bestimmungen.

- **Inferred Sensitive Data**: Das Modell leitet persönliche Merkmale ab, die nie bereitgestellt wurden, und erzeugt dadurch durch Inferenz neue Datenschutzrisiken.

- **Insecure Model Output**: Nicht bereinigte Antworten übermitteln schädlichen Code, Fehlinformationen oder unangemessene Inhalte an Benutzer oder nachgelagerte Systeme.

- **Rogue Actions**: Autonom integrierte Agents führen unbeabsichtigte Vorgänge in der realen Welt aus (Dateischreibvorgänge, API-Aufrufe, Käufe usw.), ohne ausreichende Benutzerkontrolle.

## MITRE AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet ein umfassendes Framework zum Verständnis und zur Eindämmung von Risiken im Zusammenhang mit AI-Systemen. Sie kategorisiert verschiedene Angriffstechniken und Taktiken, die Angreifer gegen AI-Modelle einsetzen können, sowie Möglichkeiten, AI-Systeme für die Durchführung verschiedener Angriffe zu verwenden.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Angreifer stehlen aktive Session-Tokens oder Cloud-API-Credentials und rufen kostenpflichtige, in der Cloud gehostete LLMs unbefugt auf. Der Zugriff wird häufig über Reverse Proxies weiterverkauft, die vor dem Account des Opfers betrieben werden, beispielsweise durch "oai-reverse-proxy"-Deployments. Zu den Folgen gehören finanzielle Verluste, eine nicht richtlinienkonforme Nutzung des Modells und eine Zuordnung zum Tenant des Opfers.

TTPs:
- Tokens von infizierten Entwicklerrechnern oder Browsern abgreifen, CI/CD-Secrets stehlen und geleakte Cookies kaufen.
- Einen Reverse Proxy aufsetzen, der Requests an den echten Provider weiterleitet, den Upstream-Key verbirgt und viele Kunden multiplexed.
- Direkte Base-Model-Endpoints missbrauchen, um Enterprise-Guardrails und Rate Limits zu umgehen.

Maßnahmen:
- Tokens an Geräte-Fingerprint, IP-Bereiche und Client-Attestation binden, kurze Ablaufzeiten erzwingen und die Erneuerung mit MFA schützen.
- Keys minimal berechtigen (kein Tool-Zugriff, sofern zutreffend nur Lesezugriff) und sie bei Anomalien rotieren.
- Den gesamten Traffic serverseitig hinter einem Policy Gateway beenden, das Safety Filters, Quotas pro Route und Tenant-Isolation erzwingt.
- Auf ungewöhnliche Nutzungsmuster achten (plötzliche Ausgabenspitzen, ungewöhnliche Regionen, UA-Strings) und verdächtige Sessions automatisch widerrufen.
- mTLS oder signierte JWTs verwenden, die vom eigenen IdP ausgestellt wurden, statt langlebiger statischer API-Keys.

## Härtung von Self-hosted LLM Inference

Der Betrieb eines lokalen LLM-Servers für vertrauliche Daten erzeugt eine andere Angriffsfläche als Cloud-gehostete APIs: Inference-/Debug-Endpoints können Prompts leaken, der Serving-Stack stellt normalerweise einen Reverse Proxy bereit, und GPU-Device-Nodes ermöglichen Zugriff auf umfangreiche `ioctl()`-Oberflächen. Wenn Sie einen On-Prem-Inference-Service prüfen oder bereitstellen, sollten Sie mindestens die folgenden Punkte berücksichtigen.

### Prompt-Leaks über Debug- und Monitoring-Endpoints

Behandeln Sie die Inference-API als **sensiblen Multi-User-Service**. Debug- oder Monitoring-Routen können Prompt-Inhalte, Slot-Status, Modellmetadaten oder Informationen über interne Queues offenlegen. In `llama.cpp` ist der `/slots`-Endpoint besonders sensibel, da er den Status einzelner Slots offenlegt und nur zur Inspektion oder Verwaltung von Slots vorgesehen ist.

- Einen Reverse Proxy vor den Inference-Server setzen und standardmäßig **alles verweigern**.
- Nur die exakt benötigten Kombinationen aus HTTP-Methode und Pfad für Client/UI allowlisten.
- Introspection-Endpoints möglichst direkt im Backend deaktivieren, beispielsweise mit `llama-server --no-slots`.
- Den Reverse Proxy an `127.0.0.1` binden und ihn über einen authentifizierten Transport wie SSH Local Port Forwarding bereitstellen, statt ihn im LAN zu veröffentlichen.

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

Wenn der Inference-Daemon das Lauschen an einem UNIX-Socket unterstützt, sollte dieser gegenüber TCP bevorzugt und der Container mit **keinem Netzwerk-Stack** ausgeführt werden:
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
- `--userns=keep-id` und Rootless Podman reduzieren die Auswirkungen eines Container-Breakouts, da Container-root nicht Host-root ist.
- Read-only-Modell-Mounts verringern die Wahrscheinlichkeit einer Modellmanipulation aus dem Container heraus.

### Minimierung von GPU-Geräteknoten

Für GPU-gestützte Inferenz sind `/dev/nvidia*`-Dateien hochwertige lokale Angriffsflächen, da sie umfangreiche Treiber-`ioctl()`-Handler und möglicherweise gemeinsam genutzte GPU-Speicherverwaltungspfade offenlegen.

- `/dev/nvidia*` darf nicht für alle Benutzer beschreibbar sein.
- Beschränke `nvidia`, `nvidiactl` und `nvidia-uvm` mit `NVreg_DeviceFileUID/GID/Mode`, udev-Regeln und ACLs, sodass nur die zugeordnete Container-UID sie öffnen kann.
- Deaktiviere unnötige Module wie `nvidia_drm`, `nvidia_modeset` und `nvidia_peermem` auf headless Inferenz-Hosts.
- Lade beim Booten nur die erforderlichen Module vor, anstatt dem Runtime-System zu erlauben, sie während des Starts der Inferenz opportunistisch per `modprobe` zu laden.

Beispiel:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Ein wichtiger Prüfpunkt ist **`/dev/nvidia-uvm`**. Selbst wenn die Workload `cudaMallocManaged()` nicht ausdrücklich verwendet, können aktuelle CUDA-Runtimes `nvidia-uvm` dennoch benötigen. Da dieses Gerät gemeinsam genutzt wird und die Verwaltung des virtuellen GPU-Speichers übernimmt, sollte es als Angriffsfläche für die Offenlegung tenantübergreifender Daten behandelt werden. Wenn das Inference-Backend dies unterstützt, kann ein Vulkan-Backend einen interessanten Kompromiss darstellen, da dadurch möglicherweise vollständig darauf verzichtet werden kann, `nvidia-uvm` dem Container zugänglich zu machen.

### LSM-Isolierung für Inference-Worker

AppArmor/SELinux/seccomp sollten als Defense in Depth rund um den Inference-Prozess eingesetzt werden:

- Nur die tatsächlich benötigten Shared Libraries, Model-Pfade, Socket-Verzeichnisse und GPU-Device-Nodes erlauben.
- Hochriskante Capabilities wie `sys_admin`, `sys_module`, `sys_rawio` und `sys_ptrace` ausdrücklich verweigern.
- Das Model-Verzeichnis schreibgeschützt halten und beschreibbare Pfade ausschließlich auf die Runtime-Socket-/Cache-Verzeichnisse beschränken.
- Denial-Logs überwachen, da sie nützliche Detection-Telemetrie liefern, wenn der Model-Server oder ein Post-Exploitation-Payload versucht, aus seinem erwarteten Verhalten auszubrechen.

Beispiel-AppArmor-Regeln für einen GPU-gestützten Worker:
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

Phantom Squatting ist das **Domain-/URL-Äquivalent von slopsquatting**. Statt eines nicht existierenden Paketnamens halluziniert das LLM eine plausible **Portal-, API-, Webhook-, Billing-, SSO-, Download- oder Support-Domain** für eine reale Marke, und ein Angreifer registriert diesen Namespace, bevor ein Mensch oder Agent ihn verwendet.

Das ist relevant, weil die Modellausgabe in vielen AI-gestützten Workflows als **vertrauenswürdige Dependency** behandelt wird:
- Entwickler fügen den vorgeschlagenen Endpoint in Code oder CI/CD-Integrationen ein.
- AI-Agents rufen automatisch Dokumentation, Schemas, APKs, ZIPs oder Webhook-Ziele ab.
- Generierte Runbooks oder Dokumente können die gefälschte URL so einbetten, als wäre sie autoritativ.

### Offensive workflow

1. **Die Halluzinationsfläche untersuchen**: markenspezifische Fragen zu realistischen Workflows stellen, etwa zu `admin`-, `billing`-, `sandbox`-, `benefits`-, `api`-, `download`-, `support`-, `webhook`- oder `mobile app`-Portalen.
2. **Kandidaten normalisieren**: generierte URLs auflösen, NXDOMAIN-Antworten auf die übergeordnete registrierbare Domain reduzieren und Prompt-Familien deduplizieren. Prompt-Korpora sollten vielfältig bleiben, beispielsweise indem nahezu identische Prompts anhand der **Jaccard similarity** entfernt werden.
3. **Vorhersehbare Halluzinationen priorisieren**:
- **Thermal Hallucination Persistence (THP)**: Dieselbe gefälschte Domain erscheint über verschiedene Temperaturen hinweg, einschließlich niedriger Temperaturen wie `T=0.1`.
- **Cross-model consensus**: Mehrere LLM-Familien generieren dieselbe gefälschte Domain.
4. Die übergeordnete Domain **registrieren und weaponizen**, anschließend Phishing, gefälschte APK-/ZIP-Downloads, Credential-Harvester, schädliche Dokumente oder API-Endpoints hosten, die Secrets/Webhook-Payloads sammeln. **Reine Halluzinationen auf Domain-Ebene** lassen sich am einfachsten monetarisieren, weil der Angreifer den gesamten Namespace kontrolliert; Halluzinationen von Subdomains/Pfaden können weiterhin missbraucht werden, wenn die normalisierte übergeordnete Domain nicht registriert ist.
5. Das **Zero-Reputation-Fenster ausnutzen**: Neu registrierte Domains verfügen häufig noch nicht über Blocklist-Historie, URL-Reputation oder ausgereifte Telemetrie und können daher Kontrollen umgehen, bis die Erkennungen nachgezogen haben. Angreifer können dieses Fenster durch crawler-only-Benign-Responses, Redirect-Cloaking, CAPTCHA-Gates oder verzögertes Payload-Staging verlängern.

### Warum es für Agents gefährlich ist

Für ein menschliches Opfer benötigt die gefälschte Domain normalerweise noch einen Klick und eine weitere Aktion. In einem **agentic workflow** kann das LLM sowohl der **Lure** als auch der **Executor** sein: Der Agent erhält die halluzinierte URL, ruft sie ab, parst die Antwort und kann anschließend Tokens leaken, Anweisungen ausführen, eine Dependency herunterladen oder vergiftete Daten ohne menschliche Prüfung in CI/CD einschleusen.

### Praktische Angreifer-Prompts

Ertragreiche Prompts sehen normalerweise wie gewöhnliche Enterprise-Aufgaben aus und nicht wie explizite Phishing-Lures:
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive Inversion

Behandle dies als proaktives Domain-Monitoring-Problem und nicht nur als Prompt-Injection-Problem:
- Erstelle ein **Brand-Prompt-Korpus** und untersuche regelmäßig die LLMs, auf die sich deine Benutzer/Agents verlassen.
- Speichere halluzinierte URLs und verfolge, welche über verschiedene Temperaturen/Modelle hinweg stabil bleiben.
- Verfolge das **Adversarial Exploitation Window (AEW)**: die Zeit zwischen der ersten Halluzination und der Registrierung durch einen Angreifer. Ein positives AEW bedeutet, dass Defender vor der Weaponization vorregistrieren, sinkholen oder vorab blockieren können.
- Überwache **NXDOMAIN → registered**-Übergänge für die übergeordneten Domains.
- Bei einer Registrierung Registrar, Erstellungsdatum, Nameserver, Privacy Shielding, Seiteninhalte, Screenshots, Parked-Page-Status und Ähnlichkeit der Brand-Assets prüfen.
- Füge Policy-Gates hinzu, damit Agents/Entwickler **LLM-generierten Domains standardmäßig nicht vertrauen**: Allowlists, Ownership-Validierung, CT/RDAP-Checks oder menschliche Freigabe vor der ersten Verwendung verlangen.

Dies fällt gleichzeitig in mehrere AI-Risikokategorien: **AI supply-chain attack**, **insecure model output** und **rogue actions**, wenn Agents die halluzinierte URL autonom verwenden.

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
