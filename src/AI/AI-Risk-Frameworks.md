# KI-Risiken

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP hat die Top‑10‑Schwachstellen im Bereich Machine Learning identifiziert, die AI‑Systeme beeinträchtigen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, einschließlich Data Poisoning, Model Inversion und adversarial attacks. Das Verständnis dieser Schwachstellen ist entscheidend für den Aufbau sicherer AI‑Systeme.

Für eine aktuelle und ausführliche Liste der Top‑10‑Machine‑Learning‑Schwachstellen siehe das Projekt [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Ein Angreifer fügt winzige, oft unsichtbare Änderungen an den **eingehenden Daten** hinzu, sodass das Modell die falsche Entscheidung trifft.\
*Example*: Ein paar Farbspritzer auf einem Stoppschild täuschen ein selbstfahrendes Auto, sodass es ein Tempolimitschild "sieht".

- **Data Poisoning Attack**: Der **Trainingssatz** wird absichtlich mit schädlichen Samples verunreinigt, wodurch das Modell schädliche Regeln erlernt.\
*Example*: Malware‑Binärdateien werden in einem Antivirus‑Trainingskorpus fälschlicherweise als "benign" gekennzeichnet, sodass ähnliche Malware später durchrutscht.

- **Model Inversion Attack**: Durch Ausfragen der Outputs erstellt ein Angreifer ein **reverse model**, das sensible Merkmale der ursprünglichen Eingaben rekonstruiert.\
*Example*: Ein MRT‑Bild eines Patienten aus den Vorhersagen eines Krebs‑Erkennungsmodells rekonstruieren.

- **Membership Inference Attack**: Der Angreifer prüft, ob ein **konkreter Datensatz** während des Trainings verwendet wurde, indem er Unterschiede in den Confidence‑Werten erkennt.\
*Example*: Bestätigen, dass eine bestimmte Banktransaktion in den Trainingsdaten eines Fraud‑Detection‑Modells vorkommt.

- **Model Theft**: Wiederholte Abfragen erlauben es einem Angreifer, Entscheidungsgrenzen zu lernen und das **Verhalten des Modells zu klonen** (und geistiges Eigentum zu entwenden).\
*Example*: Ausreichend viele Q&A‑Paare aus einer ML‑as‑a‑Service‑API ernten, um ein nahezu gleichwertiges lokales Modell zu erstellen.

- **AI Supply‑Chain Attack**: Kompromittieren Sie eine Komponente (Daten, Libraries, vortrainierte Weights, CI/CD) in der **ML‑Pipeline**, um nachgelagerte Modelle zu korrumpieren.\
*Example*: Eine vergiftete Dependency in einem Model‑Hub installiert ein backdoored Sentiment‑Analysis‑Modell über viele Apps hinweg.

- **Transfer Learning Attack**: Bösartige Logik wird in ein **pre‑trained model** eingeschleust und übersteht das Fine‑Tuning für die Aufgabe des Opfers.\
*Example*: Ein Vision‑Backbone mit einem versteckten Trigger verändert weiterhin Labels, nachdem es für die medizinische Bildgebung adaptiert wurde.

- **Model Skewing**: Subtil voreingenommene oder falsch gelabelte Daten **verschieben die Modell‑Outputs**, um die Agenda des Angreifers zu begünstigen.\
*Example*: "Saubere" Spam‑E‑Mails werden als ham gelabelt, damit ein Spam‑Filter ähnliche zukünftige E‑Mails durchlässt.

- **Output Integrity Attack**: Der Angreifer **ändert Modellvorhersagen während der Übertragung**, nicht das Modell selbst, und täuscht damit nachgelagerte Systeme.\
*Example*: Ein Malware‑Classifier‑Verdikt wird von "malicious" zu "benign" umgeschaltet, bevor die File‑Quarantine‑Stufe interveniert.

- **Model Poisoning** --- Direkte, gezielte Änderungen an den **Modellparametern** selbst, oft nachdem Schreibzugriff erlangt wurde, um das Verhalten zu verändern.\
*Example*: Gewichte eines Fraud‑Detection‑Modells in Produktion so anpassen, dass Transaktionen bestimmter Karten immer genehmigt werden.


## Google SAIF Risiken

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) skizziert verschiedene Risiken, die mit AI‑Systemen verbunden sind:

- **Data Poisoning**: Böswillige Akteure verändern oder injizieren Trainings-/Tuning‑Daten, um Genauigkeit zu verschlechtern, Backdoors zu implantieren oder Ergebnisse zu verzerren und damit die Integrität des Modells über den gesamten Daten‑Lifecycle zu untergraben.

- **Unauthorized Training Data**: Das Einlesen von urheberrechtlich geschützten, sensiblen oder nicht genehmigten Datensätzen schafft rechtliche, ethische und Performance‑Risiken, weil das Modell aus Daten lernt, die nicht verwendet werden durften.

- **Model Source Tampering**: Supply‑Chain‑ oder Insider‑Manipulation von Modellcode, Abhängigkeiten oder Weights vor oder während des Trainings kann versteckte Logik einbetten, die selbst nach Retraining bestehen bleibt.

- **Excessive Data Handling**: Schwache Daten‑Retention‑ und Governance‑Kontrollen führen dazu, dass Systeme mehr personenbezogene Daten speichern oder verarbeiten als nötig, was die Exponierung und Compliance‑Risiken erhöht.

- **Model Exfiltration**: Angreifer stehlen Modellfiles/Weights, was zu Verlust von geistigem Eigentum führt und Copy‑Cat‑Dienste oder Folgeangriffe ermöglicht.

- **Model Deployment Tampering**: Adversaries verändern Modellartefakte oder Serving‑Infrastruktur, sodass das laufende Modell von der geprüften Version abweicht und sich potenziell anders verhält.

- **Denial of ML Service**: APIs fluten oder "sponge" Inputs senden kann Compute/Energie erschöpfen und das Modell offline nehmen — analog klassische DoS‑Angriffe.

- **Model Reverse Engineering**: Durch das Sammeln großer Mengen von Input‑Output‑Paaren können Angreifer das Modell klonen oder distillieren, was Imitationsprodukte und maßgeschneiderte adversariale Angriffe begünstigt.

- **Insecure Integrated Component**: Verletzliche Plugins, Agents oder Upstream‑Services erlauben Angreifern, Code zu injizieren oder Privilegien innerhalb der AI‑Pipeline zu eskalieren.

- **Prompt Injection**: Das Konstruieren von Prompts (direkt oder indirekt), um Anweisungen einzuschmuggeln, die die System‑Intentionslage überschreiben und das Modell zu unbeabsichtigten Befehlen bringen.

- **Model Evasion**: Sorgfältig gestaltete Inputs bringen das Modell dazu, falsch zu klassifizieren, zu halluzinieren oder unerlaubte Inhalte auszugeben, was Sicherheit und Vertrauen untergräbt.

- **Sensitive Data Disclosure**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem Benutzerkontext preis und verletzt so Datenschutzbestimmungen.

- **Inferred Sensitive Data**: Das Modell leitet persönliche Attribute ab, die nie direkt bereitgestellt wurden, und schafft dadurch neue Datenschutzschäden durch Inferenz.

- **Insecure Model Output**: Unsanitized Responses liefern schädlichen Code, Desinformation oder unangemessene Inhalte an Benutzer oder nachgelagerte Systeme.

- **Rogue Actions**: Autonom integrierte Agents führen unbeabsichtigte Real‑World‑Operationen aus (File‑Writes, API‑Calls, Käufe usw.) ohne angemessene Benutzeraufsicht.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet einen umfassenden Rahmen zum Verständnis und zur Minderung von Risiken, die mit AI‑Systemen verbunden sind. Sie kategorisiert verschiedene Angriffstechniken und Taktiken, die Angreifer gegen AI‑Modelle einsetzen können, und zeigt auch, wie AI‑Systeme genutzt werden können, um unterschiedliche Angriffe durchzuführen.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Angreifer stehlen aktive Session‑Tokens oder Cloud‑API‑Credentials und rufen bezahlte, cloud‑gehostete LLMs ohne Autorisierung auf. Zugriff wird oft über wiederverkaufte Reverse‑Proxies realisiert, die das Konto des Opfers vor dem Upstream‑Provider repräsentieren, z. B. "oai-reverse-proxy"‑Deployments. Konsequenzen umfassen finanzielle Verluste, Modellmissbrauch außerhalb der Richtlinien und Attribution auf den victim tenant.

TTPs:
- Tokens von infizierten Entwickler‑Maschinen oder Browsern harvesten; CI/CD‑Secrets stehlen; geleakte Cookies kaufen.
- Einen reverse proxy aufsetzen, der Requests an den echten Provider weiterleitet, den Upstream‑Key versteckt und viele Kunden multiplexed.
- Direkte base‑model Endpoints missbrauchen, um Enterprise‑Guardrails und Rate‑Limits zu umgehen.

Mitigations:
- Tokens an Device‑Fingerprint, IP‑Ranges und Client‑Attestation binden; kurze Expirations erzwingen und Refresh mit MFA.
- Keys minimal scopeen (kein Tool‑Zugriff, read‑only wo möglich); bei Anomalien rotieren.
- Serverseitig sämtlichen Traffic hinter einem Policy‑Gateway terminieren, das Safety‑Filter, per‑Route Quotas und Tenant‑Isolation durchsetzt.
- Auf ungewöhnliche Usage‑Muster (plötzliche Kosten‑Spikes, atypische Regionen, UA‑Strings) überwachen und verdächtige Sessions automatisch widerrufen.
- mTLS oder signed JWTs vom IdP bevorzugen gegenüber langlaufenden statischen API‑Keys.

## Härtung selbst gehosteter LLM‑Inference

Der Betrieb eines lokalen LLM‑Servers für vertrauliche Daten schafft eine andere Angriffsfläche als cloud‑gehostete APIs: inference/debug Endpoints können Prompts leak, der Serving‑Stack exponiert üblicherweise einen reverse proxy, und GPU‑Device‑Nodes geben Zugriff auf große `ioctl()`‑Flächen. Wenn Sie einen On‑Prem‑Inference‑Service bewerten oder ausrollen, prüfen Sie mindestens die folgenden Punkte.

### Prompt leakage via debug and monitoring endpoints

Behandeln Sie die Inferenz‑API als einen **sensiblen Mehrbenutzer‑Dienst**. Debug‑ oder Monitoring‑Routen können Prompt‑Inhalte, Slot‑Zustände, Modell‑Metadaten oder interne Queue‑Informationen preisgeben. In `llama.cpp` ist der `/slots`‑Endpoint besonders sensibel, da er pro Slot Zustand offenlegt und nur zur Slot‑Inspektion/-Verwaltung gedacht ist.

- Setzen Sie einen reverse proxy vor den Inference‑Server und **deny by default**.
- Allowlisten Sie nur die exakt benötigten HTTP‑Methoden + Pfad‑Kombinationen, die vom Client/UI gebraucht werden.
- Deaktivieren Sie Introspektion‑Endpoints im Backend selbst, wann immer möglich, z. B. `llama-server --no-slots`.
- Binden Sie den reverse proxy an `127.0.0.1` und exponieren Sie ihn über einen authentifizierten Transport wie SSH local port forwarding, anstatt ihn im LAN zu veröffentlichen.

Beispiel‑Allowlist mit nginx:
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
### Rootless containers with no network and UNIX sockets

Wenn der inference daemon das Zuhören auf einem UNIX socket unterstützt, bevorzugen Sie das gegenüber TCP und starten Sie den container mit **no network stack**:
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
- `--network none` entfernt die Ein- und Ausgangs-TCP/IP-Exposition und vermeidet user-mode helpers, die rootless containers sonst benötigen.
- Ein UNIX socket erlaubt es, POSIX permissions/ACLs auf dem Socket-Pfad als erste Zugriffskontroll-Schicht zu verwenden.
- `--userns=keep-id` und rootless Podman reduzieren die Auswirkungen eines Container-Breakouts, weil der Container-root nicht der Host-root ist.
- Read-only model mounts verringern die Wahrscheinlichkeit einer Manipulation des Modells von innerhalb des Containers.

### Minimierung von GPU-Geräte-Knoten

Für GPU-gestützte Inferenz sind `/dev/nvidia*`-Dateien hochwertige lokale Angriffsflächen, da sie große Treiber-`ioctl()`-Handler und potenziell gemeinsame GPU-Speicherverwaltungs-Pfade exponieren.

- Lassen Sie `/dev/nvidia*` nicht world-writable.
- Beschränken Sie `nvidia`, `nvidiactl` und `nvidia-uvm` mit `NVreg_DeviceFileUID/GID/Mode`, udev rules und ACLs, sodass nur die gemappte Container-UID sie öffnen kann.
- Sperren Sie unnötige Module wie `nvidia_drm`, `nvidia_modeset` und `nvidia_peermem` auf headless inference hosts.
- Preloaden Sie nur benötigte Module beim Boot, anstatt der runtime zu erlauben, sie opportunistisch mit `modprobe` während des Inference-Starts zu laden.

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
One important review point is **`/dev/nvidia-uvm`**. Selbst wenn der Workload nicht explizit `cudaMallocManaged()` verwendet, können neuere CUDA-Runtimes dennoch `nvidia-uvm` benötigen. Da dieses Device geteilt wird und die GPU-VM-Verwaltung übernimmt, sollten Sie es als mandantenübergreifende Angriffsfläche für Datenexposition behandeln. Wenn das Inference-Backend dies unterstützt, kann ein Vulkan-Backend ein interessanter Kompromiss sein, da es eventuell vermeidet, `nvidia-uvm` überhaupt dem Container auszusetzen.

### LSM-Einschränkung für Inference-Worker

AppArmor/SELinux/seccomp sollten als Defense-in-Depth rund um den Inference-Prozess eingesetzt werden:

- Erlauben Sie nur die tatsächlich benötigten geteilten Bibliotheken, Modellpfade, Socket-Verzeichnisse und GPU-Device-Knoten.
- Verweigern Sie ausdrücklich hochriskante Capabilities wie `sys_admin`, `sys_module`, `sys_rawio` und `sys_ptrace`.
- Halten Sie das Modellverzeichnis schreibgeschützt und beschränken Sie beschreibbare Pfade nur auf die Runtime-Socket-/Cache-Verzeichnisse.
- Überwachen Sie denial logs, da diese nützliche Erkennungs-Telemetrie liefern, wenn der Modellserver oder ein post-exploitation payload versucht, sein erwartetes Verhalten zu verlassen.

Example AppArmor rules for a GPU-backed worker:
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
## Referenzen
- [Unit 42 – Die Risiken von Code Assistant LLMs: Schädliche Inhalte, Missbrauch und Täuschung](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Übersicht zum LLMJacking-Schema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (Weiterverkauf von gestohlenem LLM-Zugriff)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Tiefenanalyse zur Bereitstellung eines lokal betriebenen, niedrig-privilegierten LLM-Servers](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) Spezifikation](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
