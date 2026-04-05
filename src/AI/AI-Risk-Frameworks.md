# AI Risiken

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP hat die Top‑10‑Schwachstellen im Machine Learning identifiziert, die AI‑Systeme beeinträchtigen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, darunter data poisoning, model inversion und adversarial attacks. Das Verständnis dieser Schwachstellen ist entscheidend für den Aufbau sicherer AI‑Systeme.

Für eine aktualisierte und detaillierte Liste der Top‑10 Machine‑Learning‑Schwachstellen siehe das [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) Projekt.

- **Input Manipulation Attack**: Ein Angreifer fügt winzige, oft unsichtbare Änderungen an den **eingehenden Daten** hinzu, sodass das Modell eine falsche Entscheidung trifft.\
*Beispiel*: Ein paar Farbspritzer auf einem Stoppschild bringen ein selbstfahrendes Auto dazu, ein Geschwindigkeitsbegrenzungszeichen zu "sehen".

- **Data Poisoning Attack**: Der **Training‑Datensatz** wird absichtlich mit schlechten Samples verschmutzt, wodurch das Modell schädliche Regeln lernt.\
*Beispiel*: Malware‑Binaries werden in einem Antivirus‑Trainingkorpus fälschlich als "benign" gelabelt, sodass ähnliche Malware später unerkannt bleibt.

- **Model Inversion Attack**: Durch Abfragen der Ausgaben baut ein Angreifer ein **Reverse‑Modell**, das sensible Merkmale der ursprünglichen Eingaben rekonstruiert.\
*Beispiel*: Wiederherstellung eines MRT‑Bildes eines Patienten aus den Vorhersagen eines Krebs‑Erkennungsmodells.

- **Membership Inference Attack**: Der Angreifer prüft, ob ein **konkreter Datensatz** beim Training verwendet wurde, indem er Konfidenz‑Unterschiede erkennt.\
*Beispiel*: Bestätigung, dass eine Person mit ihren Banktransaktionen in den Trainingsdaten eines Fraud‑Detection‑Modells vorkommt.

- **Model Theft**: Wiederholte Abfragen erlauben einem Angreifer, Entscheidungsgrenzen zu lernen und das **Verhalten des Modells zu klonen** (und geistiges Eigentum).\
*Beispiel*: Genügend Q&A‑Paare von einer ML‑as‑a‑Service‑API sammeln, um ein nahezu gleichwertiges lokales Modell zu erstellen.

- **AI Supply‑Chain Attack**: Kompromittierung einer Komponente (Daten, Bibliotheken, pre‑trained weights, CI/CD) in der **ML‑Pipeline**, um nachgelagerte Modelle zu korrumpieren.\
*Beispiel*: Eine vergiftete Abhängigkeit in einem model‑hub installiert ein backdoored Sentiment‑Analyse‑Modell in vielen Apps.

- **Transfer Learning Attack**: Bösartige Logik wird in ein **pre‑trained model** eingebettet und überlebt das Fine‑Tuning für die Aufgabe des Opfers.\
*Beispiel*: Ein Vision‑Backbone mit einem versteckten Trigger verändert weiterhin Labels, nachdem es für die medizinische Bildgebung adaptiert wurde.

- **Model Skewing**: Subtil voreingenommene oder falsch gelabelte Daten **verschieben die Modell‑Ausgaben**, um der Agenda des Angreifers zu dienen.\
*Beispiel*: "Saubere" Spam‑E‑Mails als ham labeln, sodass ein Spamfilter ähnliche zukünftige E‑Mails durchlässt.

- **Output Integrity Attack**: Der Angreifer **ändert Modell‑Vorhersagen während der Übertragung**, nicht das Modell selbst, und täuscht damit nachgelagerte Systeme.\
*Beispiel*: Ein Malware‑Klassifizierer wird so manipuliert, dass das "malicious"‑Verdikt vor der Quarantänephase in "benign" geändert wird.

- **Model Poisoning** --- Direkte, zielgerichtete Änderungen an den **Model‑Parametern** selbst, oft nach Erlangung von Schreibzugriff, um das Verhalten zu verändern.\
*Beispiel*: Gewichte eines Fraud‑Detection‑Modells in Produktion anpassen, sodass Transaktionen bestimmter Karten immer genehmigt werden.


## Google SAIF Risiken

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beschreibt verschiedene Risiken, die mit AI‑Systemen verbunden sind:

- **Data Poisoning**: Böswillige Akteure verändern oder injizieren Trainings-/Tuning‑Daten, um die Genauigkeit zu verschlechtern, Backdoors zu platzieren oder Ergebnisse zu verzerren und so die Integrität des Modells über den gesamten Datenlebenszyklus zu untergraben.

- **Unauthorized Training Data**: Das Einbringen von urheberrechtlich geschützten, sensiblen oder nicht freigegebenen Datensätzen schafft rechtliche, ethische und Performance‑Risiken, weil das Modell aus Daten lernt, die nicht verwendet werden durften.

- **Model Source Tampering**: Supply‑chain‑ oder Insider‑Manipulation des Model‑Codes, von Abhängigkeiten oder Weights vor oder während des Trainings kann versteckte Logik einbetten, die selbst nach Retraining bestehen bleibt.

- **Excessive Data Handling**: Schwache Datenaufbewahrungs‑ und Governance‑Kontrollen führen dazu, dass Systeme mehr personenbezogene Daten speichern oder verarbeiten als nötig, was die Angriffsfläche und Compliance‑Risiken erhöht.

- **Model Exfiltration**: Angreifer stehlen Modell‑Dateien/Weights, was zu geistigem Eigentumsverlust führt und Copy‑Cat‑Services oder Folgeangriffe ermöglicht.

- **Model Deployment Tampering**: Gegner verändern Modell‑Artefakte oder Serving‑Infrastruktur, sodass das laufende Modell von der geprüften Version abweicht und sich potenziell anders verhält.

- **Denial of ML Service**: APIs fluten oder "sponge" Inputs senden kann Rechen-/Energie‑Ressourcen erschöpfen und das Modell außer Betrieb setzen – analog zu klassischen DoS‑Angriffen.

- **Model Reverse Engineering**: Durch das Ernten großer Mengen von Input‑Output‑Paaren können Angreifer das Modell klonen oder distillieren, was Nachahmerprodukte und angepasste adversarial attacks ermöglicht.

- **Insecure Integrated Component**: Verwundbare Plugins, Agents oder Upstream‑Services erlauben Angreifern, Code zu injizieren oder Privilegien im AI‑Pipeline‑Kontext zu eskalieren.

- **Prompt Injection**: Spezielle Prompts (direkt oder indirekt) werden genutzt, um Anweisungen einzuschmuggeln, die die Systemintention überschreiben und das Modell zu unbeabsichtigten Aktionen bringen.

- **Model Evasion**: Sorgfältig gestaltete Eingaben führen dazu, dass das Modell falsch klassifiziert, halluziniert oder unerlaubte Inhalte ausgibt und damit Sicherheit und Vertrauen untergräbt.

- **Sensitive Data Disclosure**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem Nutzerkontext preis und verletzt so Datenschutz und Regulationen.

- **Inferred Sensitive Data**: Das Modell schließt persönliche Attribute, die nie direkt bereitgestellt wurden, und schafft so neue Datenschutzschäden durch Inferenz.

- **Insecure Model Output**: Ungefilterte Antworten liefern schädlichen Code, Fehlinformationen oder unangemessene Inhalte an Nutzer oder nachgelagerte Systeme.

- **Rogue Actions**: Autonom integrierte Agents führen unbeabsichtigte reale Operationen aus (Dateischreibvorgänge, API‑Aufrufe, Käufe etc.) ohne ausreichende Nutzeraufsicht.


## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet einen umfassenden Rahmen, um Risiken im Zusammenhang mit AI‑Systemen zu verstehen und zu mindern. Sie kategorisiert verschiedene Angriffstechniken und Taktiken, die Gegner gegen AI‑Modelle einsetzen können, sowie wie AI‑Systeme genutzt werden können, um unterschiedliche Angriffe durchzuführen.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Angreifer stehlen aktive Session‑Tokens oder Cloud‑API‑Credentials und rufen bezahlte, in der Cloud gehostete LLMs ohne Autorisierung auf. Der Zugang wird häufig über Reverse‑Proxies weiterverkauft, die das Konto des Opfers vor dem Upstream‑Provider verbergen, z. B. "oai-reverse-proxy" Deployments. Folgen sind finanzielle Verluste, Missbrauch des Modells außerhalb der Richtlinien und Zuordnungsprobleme für den betroffenen Tenant.

TTPs:
- Harvest Tokens von infizierten Entwickler‑Maschinen oder Browsern; stehle CI/CD‑Secrets; kaufe geleakte Cookies.
- Stelle einen Reverse Proxy bereit, der Anfragen an den echten Provider weiterleitet, den Upstream‑Key verbirgt und viele Kunden multiplexed.
- Missbrauche direkte base‑model Endpoints, um Enterprise‑Guardrails und Rate‑Limits zu umgehen.

Gegenmaßnahmen:
- Binde Tokens an Device‑Fingerprints, IP‑Bereiche und Client‑Attestation; erzwinge kurze Gültigkeiten und Refresh mit MFA.
- Scope Keys minimal (kein Tool‑Zugriff, read‑only wo möglich); rotiere bei Anomalien.
- Beende serverseitig sämtlichen Traffic hinter einem Policy‑Gateway, das Safety‑Filter, Per‑Route‑Quotas und Tenant‑Isolation durchsetzt.
- Überwache ungewöhnliche Nutzungsmuster (plötzliche Ausgaben‑Spikes, atypische Regionen, UA‑Strings) und widerrufe verdächtige Sessions automatisch.
- Bevorzuge mTLS oder signierte JWTs, ausgestellt von deinem IdP, gegenüber langlebigen statischen API‑Keys.


## Self-hosted LLM inference hardening

Den Betrieb eines lokal gehosteten LLM‑Servers für vertrauliche Daten birgt eine andere Angriffsfläche als cloud‑gehostete APIs: inference/debug Endpoints können prompts leak, der Serving‑Stack stellt meist einen reverse proxy bereit, und GPU‑Device‑Nodes bieten Zugriff auf große `ioctl()`‑Flächen. Wenn du einen On‑Prem Inference‑Service bewertest oder bereitstellst, prüfe mindestens die folgenden Punkte.

### Prompt leakage via debug and monitoring endpoints

Behandle die Inferenz‑API als einen **sensitiven Mehrbenutzer‑Dienst**. Debug‑ oder Monitoring‑Routen können Prompt‑Inhalte, Slot‑Zustände, Modell‑Metadaten oder interne Warteschlangeninformationen offenlegen. In `llama.cpp` ist der `/slots`‑Endpoint besonders sensibel, da er pro‑Slot‑Zustand offenlegt und nur zur Slot‑Inspektion/-Verwaltung gedacht ist.

- Setze einen reverse proxy vor den Inference‑Server und **deny by default**.
- Allowliste nur die exakt benötigten HTTP‑Methode + Pfad‑Kombinationen, die vom Client/UI gebraucht werden.
- Deaktiviere Introspektion‑Endpoints im Backend selbst, wann immer möglich, z. B. `llama-server --no-slots`.
- Binde den Reverse‑Proxy an `127.0.0.1` und exponiere ihn über einen authentifizierten Transport wie SSH‑Local‑Port‑Forwarding, anstatt ihn im LAN zu publizieren.

Beispiel-Allowlist für nginx:
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

Wenn der Inference-Daemon das Zuhören auf einem UNIX-Socket unterstützt, bevorzugen Sie dieses gegenüber TCP und führen Sie den Container mit **keinem Netzwerk-Stack** aus:
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
- `--network none` entfernt die Angriffsfläche für eingehenden/ausgehenden TCP/IP-Verkehr und vermeidet user-mode helpers, die rootless containers sonst benötigen würden.
- Ein UNIX-Socket erlaubt die Nutzung von POSIX-Berechtigungen/ACLs auf dem Socket-Pfad als erste Zugriffskontrollschicht.
- `--userns=keep-id` und rootless Podman verringern die Auswirkungen eines Container-Breakouts, da der Container-root nicht der Host-root ist.
- Schreibgeschützte Modell-Mounts reduzieren die Wahrscheinlichkeit einer Modellmanipulation von innerhalb des Containers.

### Minimierung von GPU-Gerätedateien

Für GPU-basierte Inferenz sind `/dev/nvidia*`-Dateien wertvolle lokale Angriffsflächen, da sie große Treiber-`ioctl()`-Handler und möglicherweise gemeinsame GPU-Speicherverwaltungswege offenlegen.

- Lassen Sie `/dev/nvidia*` nicht für alle Benutzer schreibbar.
- Beschränken Sie `nvidia`, `nvidiactl` und `nvidia-uvm` mittels `NVreg_DeviceFileUID/GID/Mode`, udev-Regeln und ACLs, sodass nur die auf den Container abgebildete UID sie öffnen kann.
- Sperren Sie unnötige Module wie `nvidia_drm`, `nvidia_modeset` und `nvidia_peermem` auf headless Inferenz-Hosts.
- Laden Sie nur die benötigten Module beim Boot vor, anstatt der runtime zu erlauben, sie opportunistisch mit `modprobe` beim Start der Inferenz nachzuladen.

Beispiel:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
One important review point is **`/dev/nvidia-uvm`**. Selbst wenn die Workload nicht explizit `cudaMallocManaged()` verwendet, können aktuelle CUDA-Runtimes weiterhin `nvidia-uvm` benötigen. Da dieses Gerät geteilt wird und die virtuelle GPU-Speicherverwaltung übernimmt, sollte es als eine mandantenübergreifende Datenexpositionsfläche betrachtet werden. Wenn das Inference-Backend dies unterstützt, kann ein Vulkan-Backend ein interessanter Kompromiss sein, da es möglicherweise verhindert, dass `nvidia-uvm` überhaupt an den Container exponiert wird.

### LSM-Einschränkung für Inference-Worker

AppArmor/SELinux/seccomp sollten als mehrschichtiger Schutz rund um den Inference-Prozess eingesetzt werden:

- Erlaube nur die tatsächlich benötigten Shared Libraries, Model-Pfade, Socket-Verzeichnis und GPU-Gerätenodes.
- Sperre ausdrücklich risikoreiche Capabilities wie `sys_admin`, `sys_module`, `sys_rawio` und `sys_ptrace`.
- Halte das Model-Verzeichnis schreibgeschützt und beschränke beschreibbare Pfade ausschließlich auf die Runtime-Socket-/Cache-Verzeichnisse.
- Überwache Denial-Logs, da sie nützliche Erkennungs-Telemetrie liefern, wenn der Model-Server oder eine post-exploitation payload versucht, sein erwartetes Verhalten zu verlassen.

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
## Quellen
- [Unit 42 – Die Risiken von Code Assistant LLMs: schädliche Inhalte, Missbrauch und Täuschung](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking-Schema-Übersicht – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (Wiederverkauf gestohlener LLM-Zugänge)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Detaillierte Analyse zur Bereitstellung eines on-premise LLM-Servers mit eingeschränkten Rechten](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) Spezifikation](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
