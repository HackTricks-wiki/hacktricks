# KI-Risiken

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP hat die zehn wichtigsten Machine-Learning-Schwachstellen identifiziert, die KI-Systeme betreffen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, darunter Data Poisoning, Model Inversion und Adversarial Attacks. Das Verständnis dieser Schwachstellen ist entscheidend für den Aufbau sicherer KI-Systeme.

Eine aktualisierte und detaillierte Liste der zehn wichtigsten Machine-Learning-Schwachstellen findest du im Projekt [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Ein Angreifer fügt **eingehenden Daten** winzige, oft unsichtbare Änderungen hinzu, sodass das Modell die falsche Entscheidung trifft.\
*Beispiel*: Einige Farbspritzer auf einem Stoppschild bringen ein selbstfahrendes Auto dazu, es als Geschwindigkeitsbegrenzungsschild zu "erkennen".

- **Data Poisoning Attack**: Der **Trainingsdatensatz** wird absichtlich mit fehlerhaften Beispielen verunreinigt, wodurch das Modell schädliche Regeln lernt.\
*Beispiel*: Malware-Binärdateien werden in einem Antivirus-Trainingskorpus fälschlicherweise als "harmlos" gekennzeichnet, sodass ähnliche Malware später durchgelassen wird.

- **Model Inversion Attack**: Durch das Abfragen von Ausgaben erstellt ein Angreifer ein **Umkehrmodell**, das vertrauliche Merkmale der ursprünglichen Eingaben rekonstruiert.\
*Beispiel*: Das Rekonstruieren des MRT-Bildes eines Patienten anhand der Vorhersagen eines Krebs­erkennungsmodells.

- **Membership Inference Attack**: Der Angreifer testet anhand von Unterschieden bei den Konfidenzwerten, ob ein **bestimmter Datensatz** während des Trainings verwendet wurde.\
*Beispiel*: Bestätigen, dass die Banktransaktion einer Person in den Trainingsdaten eines Betrugserkennungsmodells enthalten ist.

- **Model Theft**: Wiederholte Abfragen ermöglichen es einem Angreifer, Entscheidungsgrenzen zu erlernen und das **Verhalten des Modells zu klonen** (einschließlich des geistigen Eigentums).\
*Beispiel*: Das Sammeln einer ausreichenden Anzahl von Frage-Antwort-Paaren über eine ML-as-a-Service-API, um ein nahezu gleichwertiges lokales Modell zu erstellen.

- **AI Supply-Chain Attack**: Eine beliebige Komponente (Daten, Bibliotheken, vortrainierte Gewichte, CI/CD) in der **ML-Pipeline** wird kompromittiert, um nachgelagerte Modelle zu manipulieren.\
*Beispiel*: Eine vergiftete Abhängigkeit von einem Model Hub installiert in zahlreichen Apps ein mit einer Backdoor versehenes Sentiment-Analysis-Modell.

- **Transfer Learning Attack**: Schädliche Logik wird in einem **vortrainierten Modell** platziert und überlebt das Fine-Tuning für die Aufgabe des Opfers.\
*Beispiel*: Ein Vision-Backbone mit einem versteckten Trigger vertauscht weiterhin Labels, nachdem es für medizinische Bildgebung angepasst wurde.

- **Model Skewing**: Subtil verzerrte oder falsch gelabelte Daten **verschieben die Ausgaben des Modells**, um die Ziele des Angreifers zu unterstützen.\
*Beispiel*: Das Einschleusen "sauberer" Spam-E-Mails, die als Ham gekennzeichnet sind, sodass ein Spamfilter ähnliche zukünftige E-Mails durchlässt.

- **Output Integrity Attack**: Der Angreifer **verändert Modellvorhersagen während der Übertragung**, nicht das Modell selbst, und täuscht dadurch nachgelagerte Systeme.\
*Beispiel*: Das Ändern des Ergebnisses "bösartig" eines Malware-Klassifikators in "harmlos", bevor die Datei-Quarantänestufe es sieht.

- **Model Poisoning** --- Direkte, gezielte Änderungen an den **Modellparametern** selbst, oft nachdem Schreibzugriff erlangt wurde, um das Verhalten zu verändern.\
*Beispiel*: Das Anpassen der Gewichte eines Betrugserkennungsmodells in der Produktion, sodass Transaktionen bestimmter Karten immer genehmigt werden.


## Google SAIF Risks

Googles [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beschreibt verschiedene Risiken im Zusammenhang mit KI-Systemen:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Böswillige Akteure verändern Trainings- oder Tuning-Daten oder schleusen solche Daten ein, um die Genauigkeit zu verringern, Backdoors zu implantieren oder Ergebnisse zu verzerren. Dadurch wird die Integrität des Modells über den gesamten Datenlebenszyklus hinweg beeinträchtigt.

- **Unauthorized Training Data**: Das Einlesen urheberrechtlich geschützter, vertraulicher oder nicht genehmigter Datensätze führt zu rechtlichen, ethischen und leistungsbezogenen Risiken, da das Modell aus Daten lernt, deren Nutzung nie gestattet wurde.

- **Model Source Tampering**: Manipulationen durch die Supply Chain oder Insider an Modellcode, Abhängigkeiten oder Gewichten vor oder während des Trainings können versteckte Logik einbetten, die auch nach einem erneuten Training bestehen bleibt.

- **Excessive Data Handling**: Schwache Richtlinien für Datenaufbewahrung und Governance führen dazu, dass Systeme mehr personenbezogene Daten als nötig speichern oder verarbeiten, wodurch das Risiko von Datenleaks und Compliance-Verstößen steigt.

- **Model Exfiltration**: Angreifer stehlen Modelldateien oder Gewichte, was zum Verlust geistigen Eigentums führt und Copycat-Services oder nachfolgende Angriffe ermöglicht.

- **Model Deployment Tampering**: Angreifer verändern Modellartefakte oder die Serving-Infrastruktur, sodass sich das laufende Modell von der geprüften Version unterscheidet und möglicherweise ein anderes Verhalten zeigt.

- **Denial of ML Service**: Das Überfluten von APIs oder das Senden von "Sponge"-Inputs kann Rechenleistung und Energie erschöpfen und das Modell offline schalten, ähnlich wie bei klassischen DoS-Angriffen.

- **Model Reverse Engineering**: Durch das Sammeln großer Mengen von Input-Output-Paaren können Angreifer das Modell klonen oder destillieren, wodurch Nachahmerprodukte und angepasste Adversarial Attacks ermöglicht werden.

- **Insecure Integrated Component**: Verwundbare Plugins, Agents oder vorgelagerte Services ermöglichen es Angreifern, Code in die KI-Pipeline einzuschleusen oder Privilegien zu erweitern.

- **Prompt Injection**: Durch direkt oder indirekt erstellte Prompts werden Anweisungen eingeschleust, die die Systemabsicht überschreiben und das Modell dazu bringen, unbeabsichtigte Befehle auszuführen.

- **Model Evasion**: Sorgfältig gestaltete Inputs veranlassen das Modell zu Fehlklassifizierungen, Halluzinationen oder zur Ausgabe nicht erlaubter Inhalte, wodurch Sicherheit und Vertrauen geschwächt werden.

- **Sensitive Data Disclosure**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem Benutzerkontext preis und verletzt dadurch Datenschutz und Vorschriften.

- **Inferred Sensitive Data**: Das Modell leitet persönliche Merkmale ab, die nie bereitgestellt wurden, und erzeugt dadurch neue Datenschutzprobleme durch Inferenz.

- **Insecure Model Output**: Nicht bereinigte Antworten geben schädlichen Code, Fehlinformationen oder unangemessene Inhalte an Benutzer oder nachgelagerte Systeme weiter.

- **Rogue Actions**: Autonom integrierte Agents führen ohne ausreichende Benutzerkontrolle unbeabsichtigte Aktionen in der realen Welt aus, etwa Dateischreibvorgänge, API-Aufrufe oder Käufe.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet ein umfassendes Framework zum Verständnis und zur Eindämmung von Risiken im Zusammenhang mit KI-Systemen. Sie kategorisiert verschiedene Angriffstechniken und Taktiken, die Angreifer gegen KI-Modelle einsetzen können, sowie Möglichkeiten, KI-Systeme für die Durchführung verschiedener Angriffe zu verwenden.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Angreifer stehlen aktive Session-Tokens oder Cloud-API-Credentials und rufen kostenpflichtige, in der Cloud gehostete LLMs ohne Autorisierung auf. Der Zugriff wird häufig über Reverse Proxies weiterverkauft, die das Konto des Opfers als Frontend verwenden, beispielsweise bei Deployments von "oai-reverse-proxy". Zu den Folgen gehören finanzielle Verluste, eine nicht richtlinienkonforme Nutzung des Modells und die Zuordnung der Aktivitäten zum Tenant des Opfers.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- Tokens von infizierten Entwicklergeräten oder Browsern sammeln, CI/CD-Secrets stehlen und geleakte Cookies kaufen.<sup>[[5]](#references)</sup>
- Einen Reverse Proxy einrichten, der Anfragen an den echten Anbieter weiterleitet, den Upstream-Key verbirgt und viele Kunden multiplexed.<sup>[[5]](#references)[[7]](#references)</sup>
- Direkte Base-Model-Endpoints missbrauchen, um Enterprise-Guardrails und Rate Limits zu umgehen.<sup>[[4]](#references)</sup>

Mitigations:
- Tokens an Geräte-Fingerprints, IP-Bereiche und Client Attestation binden, kurze Ablaufzeiten erzwingen und die Erneuerung mit MFA durchführen.
- Schlüssel möglichst stark beschränken (kein Toolzugriff, sofern möglich nur Lesezugriff) und bei Anomalien rotieren.
- Den gesamten Datenverkehr serverseitig hinter einem Policy Gateway terminieren, das Safety-Filter, Quotas pro Route und Tenant-Isolation erzwingt.
- Auf ungewöhnliche Nutzungsmuster achten (plötzliche Ausgabenspitzen, atypische Regionen, UA-Strings) und verdächtige Sessions automatisch widerrufen.
- mTLS oder signierte JWTs bevorzugen, die vom eigenen IdP ausgestellt werden, statt langlebiger statischer API-Keys.

## Härtung der Self-hosted LLM-Inferenz

Der Betrieb eines lokalen LLM-Servers für vertrauliche Daten erzeugt eine andere Angriffsfläche als Cloud-gehostete APIs: Inferenz- und Debug-Endpoints können Prompts leaken, der Serving-Stack stellt üblicherweise einen Reverse Proxy bereit, und GPU-Device-Nodes ermöglichen den Zugriff auf umfangreiche `ioctl()`-Angriffsflächen. Wenn du einen On-Prem-Inferenzdienst bewertest oder bereitstellst, solltest du mindestens die folgenden Punkte prüfen.<sup>[[8]](#references)</sup>

### Prompt-Leaks über Debug- und Monitoring-Endpoints

Behandle die Inference API als **sensitiven Multi-User-Service**. Debug- oder Monitoring-Routen können Prompt-Inhalte, Slot-Zustand, Metadaten des Modells oder Informationen über interne Queues offenlegen. In `llama.cpp` ist der `/slots`-Endpoint besonders sensibel, da er den Zustand der einzelnen Slots offenlegt und nur zur Inspektion oder Verwaltung von Slots vorgesehen ist.<sup>[[8]](#references)</sup>

- Einen Reverse Proxy vor den Inference-Server setzen und **standardmäßig alles verweigern**.
- Nur die exakten Kombinationen aus HTTP-Methode und Pfad allowlisten, die vom Client oder der UI benötigt werden.
- Introspection-Endpoints nach Möglichkeit direkt im Backend deaktivieren, beispielsweise mit `llama-server --no-slots`.<sup>[[9]](#references)</sup>
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

Wenn der Inference-Daemon das Lauschen auf einem UNIX-Socket unterstützt, sollte dieser gegenüber TCP bevorzugt und der Container mit **keinem Netzwerk-Stack** ausgeführt werden:<sup>[[8]](#references)</sup>
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
- `--userns=keep-id` und Rootless Podman verringern die Auswirkungen eines Container-Breakouts, da Container-root nicht Host-root ist.
- Schreibgeschützte Model-Mounts verringern die Wahrscheinlichkeit einer Manipulation des Models aus dem Container heraus.

### Minimierung von GPU-Device-Nodes

Für GPU-gestützte Inference sind `/dev/nvidia*`-Dateien hochwertige lokale Angriffsflächen, da sie umfangreiche Driver-`ioctl()`-Handler und potenziell gemeinsam genutzte GPU-Speicherverwaltungs-Pfade offenlegen.<sup>[[8]](#references)</sup>

- `/dev/nvidia*` darf nicht für alle Benutzer schreibbar sein.
- Beschränke `nvidia`, `nvidiactl` und `nvidia-uvm` mit `NVreg_DeviceFileUID/GID/Mode`, udev-Regeln und ACLs, sodass nur die gemappte Container-UID sie öffnen kann.
- Setze unnötige Module wie `nvidia_drm`, `nvidia_modeset` und `nvidia_peermem` auf Headless-Inference-Hosts auf die Blacklist.
- Lade beim Booten nur erforderliche Module vor, anstatt dem Runtime zu erlauben, sie während des Starts der Inference opportunistisch per `modprobe` zu laden.

Beispiel:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Ein wichtiger Prüfpunkt ist **`/dev/nvidia-uvm`**. Auch wenn die Workload nicht ausdrücklich `cudaMallocManaged()` verwendet, können aktuelle CUDA-Runtimes weiterhin `nvidia-uvm` benötigen. Da dieses Device gemeinsam genutzt wird und das Management des virtuellen GPU-Speichers übernimmt, sollte es als Cross-Tenant-Datenexposure-Surface behandelt werden. Wenn das Inference-Backend dies unterstützt, kann ein Vulkan-Backend einen interessanten Trade-off darstellen, da dadurch möglicherweise ganz darauf verzichtet werden kann, `nvidia-uvm` gegenüber dem Container bereitzustellen.<sup>[[8]](#references)</sup>

### LSM-Isolierung für Inference-Worker

AppArmor/SELinux/seccomp sollte als Tiefenverteidigung rund um den Inference-Prozess eingesetzt werden:<sup>[[8]](#references)</sup>

- Nur die tatsächlich benötigten Shared Libraries, Model-Pfade, Socket-Verzeichnisse und GPU-Device-Nodes erlauben.
- Hochriskante Capabilities wie `sys_admin`, `sys_module`, `sys_rawio` und `sys_ptrace` explizit verweigern.
- Das Model-Verzeichnis schreibgeschützt halten und schreibbare Pfade ausschließlich auf die Laufzeit-Socket-/Cache-Verzeichnisse beschränken.
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
## Phantom Squatting: Von LLM halluzinierte Domains als Vektor für die AI-Supply-Chain

Phantom Squatting ist das **Domain-/URL-Äquivalent von Slopsquatting**. Statt einen nicht existierenden Paketnamen zu halluzinieren, halluziniert das LLM eine plausible **Portal-, API-, Webhook-, Billing-, SSO-, Download- oder Support-Domain** für eine reale Marke, und ein Angreifer registriert diesen Namespace, bevor ein Mensch oder Agent ihn verwendet.<sup>[[12]](#references)[[13]](#references)</sup>

Dies ist relevant, weil die Modellausgabe in vielen AI-gestützten Workflows als **vertrauenswürdige Abhängigkeit** behandelt wird:
- Entwickler fügen den vorgeschlagenen Endpoint in Code oder CI/CD-Integrationen ein.
- AI-Agenten rufen Dokumentation, Schemas, APKs, ZIPs oder Webhook-Ziele automatisch ab.
- Generierte Runbooks oder Dokumente können die gefälschte URL so einbetten, als wäre sie autoritativ.

### Offensiver Workflow

1. **Die Halluzinationsfläche untersuchen**: markenspezifische Fragen zu realistischen Workflows stellen, etwa zu `admin`-, `billing`-, `sandbox`-, `benefits`-, `api`-, `download`-, `support`-, `webhook`- oder `mobile app`-Portalen.<sup>[[12]](#references)</sup>
2. **Kandidaten normalisieren**: generierte URLs auflösen, NXDOMAIN-Antworten auf die übergeordnete registrierbare Domain reduzieren und Prompt-Familien deduplizieren. Prompt-Korpora sollten vielfältig bleiben, beispielsweise indem nahezu identische Prompts anhand der **Jaccard-Ähnlichkeit** entfernt werden.
3. **Vorhersagbare Halluzinationen priorisieren**:
- **Thermal Hallucination Persistence (THP)**: Dieselbe gefälschte Domain erscheint bei verschiedenen Temperaturen, einschließlich niedriger Temperaturen wie `T=0.1`.
- **Modellübergreifender Konsens**: Mehrere LLM-Familien generieren dieselbe gefälschte Domain.
4. Die übergeordnete Domain **registrieren und weaponisieren**, anschließend Phishing, gefälschte APK-/ZIP-Downloads, Credential-Harvester, schädliche Dokumente oder API-Endpoints hosten, die Secrets/Webhook-Payloads sammeln. **Reine Halluzinationen auf Domain-Ebene** lassen sich am einfachsten monetarisieren, weil der Angreifer den gesamten Namespace kontrolliert; Halluzinationen von Subdomains/Pfaden können weiterhin missbraucht werden, wenn die normalisierte übergeordnete Domain nicht registriert ist.
5. **Das Zero-Reputation-Fenster ausnutzen**: Neu registrierten Domains fehlen häufig Blocklist-Historie, URL-Reputation und ausgereifte Telemetrie. Dadurch können sie Kontrollen umgehen, bis die Erkennungsmechanismen nachziehen. Angreifer können dieses Fenster mit ausschließlich für Crawler bestimmten harmlosen Antworten, Redirect-Cloaking, CAPTCHA-Gates oder verzögertem Payload-Staging verlängern.

### Warum dies für Agenten gefährlich ist

Für ein menschliches Opfer benötigt die gefälschte Domain normalerweise weiterhin einen Klick und eine zusätzliche Aktion. In einem **agentischen Workflow** kann das LLM sowohl der **Köder** als auch der **Ausführer** sein: Der Agent erhält die halluzinierte URL, ruft sie ab, analysiert die Antwort und kann anschließend Tokens leaken, Anweisungen ausführen, eine Abhängigkeit herunterladen oder vergiftete Daten ohne menschliche Prüfung in CI/CD einschleusen.<sup>[[12]](#references)</sup>

### Praktische Angreifer-Prompts

Ertragreiche Prompts wirken normalerweise wie gewöhnliche Enterprise-Aufgaben und nicht wie explizite Phishing-Köder:<sup>[[12]](#references)</sup>
- „Wie lautet die Payment-Sandbox-URL für `<brand>`-Integrationen?“
- „Welchen Webhook-Endpoint sollte ich für `<brand>`-Build-Benachrichtigungen verwenden?“
- „Wo befindet sich das Mitarbeiter-Benefits-, Billing- oder SSO-Portal für `<brand>`?“
- „Gib mir den direkten Android-APK- oder Desktop-Client-Download für `<brand>`.“

### Defensive Umkehrung

Behandle dies als proaktives Domain-Monitoring-Problem und nicht nur als Prompt-Injection-Problem:<sup>[[12]](#references)</sup>
- Einen **Marken-Prompt-Korpus** aufbauen und die von deinen Benutzern/Agenten verwendeten LLMs regelmäßig untersuchen.
- Halluzinierte URLs speichern und verfolgen, welche über Temperaturen/Modelle hinweg stabil bleiben.
- Das **Adversarial Exploitation Window (AEW)** verfolgen: die Zeit zwischen der ersten Halluzination und der Registrierung durch den Angreifer. Ein positives AEW bedeutet, dass Verteidiger vor der Weaponisierung präventiv registrieren, sinkholen oder blockieren können.
- **NXDOMAIN-zu-registriert**-Übergänge für die übergeordneten Domains überwachen.
- Bei der Registrierung Registrar, Erstellungsdatum, Nameserver, Privacy-Shielding, Seiteninhalt, Screenshots, den Status geparkter Seiten und die Ähnlichkeit von Marken-Assets prüfen.
- Policy-Gates hinzufügen, damit Agenten/Entwickler **standardmäßig keinen LLM-generierten Domains vertrauen**: Allowlists, Eigentumsvalidierung, CT-/RDAP-Prüfungen oder menschliche Genehmigung vor der ersten Verwendung verlangen.

Dies fällt gleichzeitig in mehrere AI-Risikokategorien: **AI-Supply-Chain-Angriff**, **unsichere Modellausgabe** und **Rogue Actions**, wenn Agenten die halluzinierte URL autonom verwenden.

## Referenzen

- [1] [OWASP Top 10 für Machine-Learning-Schwachstellen](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risiken](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – Die Risiken von Code-Assistant-LLMs: schädliche Inhalte, Missbrauch und Täuschung](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Gestohlene Cloud-Credentials bei einem neuen AI-Angriff verwendet](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Übersicht zum LLMJacking-Schema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (Weiterverkauf gestohlener LLM-Zugänge)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv – Tiefenanalyse der Bereitstellung eines On-Premise-LLM-Servers mit geringeren Berechtigungen](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp-Server-README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman-Quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI)-Spezifikation](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Von AI halluzinierte Domains als Vektor für die Software-Supply-Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Wie AI-Halluzinationen eine neue Klasse von Supply-Chain-Angriffen ermöglichen](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
