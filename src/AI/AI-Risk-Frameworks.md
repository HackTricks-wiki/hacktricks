# Risiken durch KI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP hat die 10 wichtigsten Machine-Learning-Schwachstellen identifiziert, die KI-Systeme betreffen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, darunter Data Poisoning, Model Inversion und adversarial attacks. Das Verständnis dieser Schwachstellen ist entscheidend für die Entwicklung sicherer KI-Systeme.

Eine aktuelle und ausführliche Liste der 10 wichtigsten Machine-Learning-Schwachstellen finden Sie im Projekt [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Ein Angreifer fügt **eingehenden Daten** winzige, oft unsichtbare Änderungen hinzu, damit das Modell eine falsche Entscheidung trifft.\
    *Beispiel*: Einige Farbspritzer auf einem Stoppschild bringen ein selbstfahrendes Auto dazu, es als Tempolimitschild zu „sehen“.

- **Data Poisoning Attack**: Der **Trainingsdatensatz** wird gezielt mit fehlerhaften Beispielen verunreinigt, wodurch das Modell schädliche Regeln lernt.\
*Beispiel*: Malware-Dateien werden in einem Antivirus-Trainingskorpus fälschlich als „harmlos“ gekennzeichnet, sodass ähnliche Malware später unentdeckt bleibt.

- **Model Inversion Attack**: Durch das Abfragen von Ausgaben erstellt ein Angreifer ein **inverses Modell**, das sensible Merkmale der ursprünglichen Eingaben rekonstruiert.\
*Beispiel*: Rekonstruktion des MRT-Bildes eines Patienten anhand der Vorhersagen eines Krebserkennungsmodells.

- **Membership Inference Attack**: Der Angreifer prüft anhand von Unterschieden bei den Konfidenzwerten, ob ein **bestimmter Datensatz** beim Training verwendet wurde.\
*Beispiel*: Bestätigung, dass die Banktransaktion einer Person in den Trainingsdaten eines Betrugserkennungsmodells enthalten ist.

- **Model Theft**: Durch wiederholte Abfragen kann ein Angreifer Entscheidungsgrenzen ermitteln und das **Verhalten des Modells nachbilden** (sowie dessen geistiges Eigentum stehlen).\
*Beispiel*: Erfassung ausreichender Frage-Antwort-Paare über eine ML-as-a-Service-API, um ein nahezu gleichwertiges lokales Modell zu erstellen.

- **AI Supply-Chain Attack**: Kompromittierung beliebiger Komponenten (Daten, Bibliotheken, vortrainierte Gewichte, CI/CD) in der **ML-Pipeline**, um nachgelagerte Modelle zu verfälschen.\
*Beispiel*: Eine vergiftete Abhängigkeit von einem Model-Hub installiert in zahlreichen Apps ein mit einer Backdoor versehenes Sentiment-Analysemodell.

- **Transfer Learning Attack**: Schädliche Logik wird in einem **vortrainierten Modell** platziert und übersteht das Fine-Tuning für die Aufgabe des Opfers.\
*Beispiel*: Ein Vision-Backbone mit einem verborgenen Trigger verändert weiterhin Labels, nachdem es für medizinische Bildgebung angepasst wurde.

- **Model Skewing**: Unauffällig verzerrte oder falsch gekennzeichnete Daten **verschieben die Modellausgaben** zugunsten der Ziele des Angreifers.\
*Beispiel*: Einschleusen von „sauberen“ Spam-E-Mails, die als Ham gekennzeichnet sind, damit ein Spamfilter ähnliche zukünftige E-Mails durchlässt.

- **Output Integrity Attack**: Der Angreifer **verändert Modellvorhersagen während der Übertragung**, nicht das Modell selbst, und täuscht so nachgelagerte Systeme.\
*Beispiel*: Ändern des Urteils eines Malware-Klassifizierers von „bösartig“ zu „harmlos“, bevor es die Dateiquarantäne erreicht.

- **Model Poisoning** --- Direkte, gezielte Änderungen an den **Modellparametern**, oft nach Erlangen von Schreibzugriff, um das Verhalten zu verändern.\
*Beispiel*: Verändern der Gewichte eines Betrugserkennungsmodells in der Produktionsumgebung, sodass Transaktionen bestimmter Karten immer genehmigt werden.


## Google SAIF: Risiken

Googles [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beschreibt verschiedene Risiken im Zusammenhang mit KI-Systemen:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Böswillige Akteure verändern Trainings- oder Tuning-Daten oder schleusen Daten ein, um die Genauigkeit zu verringern, Backdoors einzubauen oder Ergebnisse zu verzerren. Dadurch wird die Modellintegrität über den gesamten Datenlebenszyklus hinweg beeinträchtigt.

- **Nicht autorisierte Trainingsdaten**: Die Verwendung urheberrechtlich geschützter, sensibler oder nicht freigegebener Datensätze führt zu rechtlichen, ethischen und leistungsbezogenen Risiken, weil das Modell aus Daten lernt, die es nicht verwenden durfte.

- **Manipulation des Modellquellcodes**: Manipulation von Modellcode, Abhängigkeiten oder Gewichten durch Angriffe auf die Lieferkette oder durch Insider vor oder während des Trainings kann verborgene Logik einbetten, die auch nach erneutem Training bestehen bleibt.

- **Übermäßige Datenverarbeitung**: Schwache Kontrollen für Datenaufbewahrung und Data Governance führen dazu, dass Systeme mehr personenbezogene Daten speichern oder verarbeiten als nötig, wodurch das Risiko von Offenlegung und Compliance-Verstößen steigt.

- **Model Exfiltration**: Angreifer stehlen Modelldateien oder -gewichte. Dies führt zum Verlust geistigen Eigentums und ermöglicht Nachahmerdienste oder Folgeangriffe.

- **Manipulation der Modellbereitstellung**: Angreifer verändern Modellartefakte oder die Serving-Infrastruktur, sodass sich das laufende Modell von der geprüften Version unterscheidet und sein Verhalten möglicherweise verändert wird.

- **Denial of ML Service**: Das Überfluten von APIs oder das Senden von „Sponge“-Eingaben kann Rechenleistung und Energie aufbrauchen und das Modell außer Betrieb setzen – ähnlich wie bei klassischen DoS-Angriffen.

- **Reverse Engineering von Modellen**: Durch das Sammeln großer Mengen von Eingabe-Ausgabe-Paaren können Angreifer das Modell klonen oder destillieren. Das begünstigt Nachahmerprodukte und maßgeschneiderte adversarial attacks.

- **Unsichere integrierte Komponente**: Verwundbare Plugins, Agents oder vorgelagerte Dienste ermöglichen es Angreifern, Code einzuschleusen oder ihre Berechtigungen innerhalb der KI-Pipeline auszuweiten.

- **Prompt Injection**: Prompts werden direkt oder indirekt so gestaltet, dass sie Anweisungen einschleusen, die die Systemvorgaben außer Kraft setzen und das Modell zu unbeabsichtigten Aktionen veranlassen.

- **Model Evasion**: Sorgfältig gestaltete Eingaben veranlassen das Modell zu Fehlklassifizierungen, Halluzinationen oder unzulässigen Ausgaben und untergraben dadurch Sicherheit und Vertrauen.

- **Offenlegung sensibler Daten**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem Benutzerkontext preis und verletzt dadurch Datenschutz und Vorschriften.

- **Abgeleitete sensible Daten**: Das Modell leitet persönliche Merkmale ab, die nie angegeben wurden, und verursacht dadurch neue Datenschutzrisiken.

- **Unsichere Modellausgabe**: Nicht bereinigte Antworten geben schädlichen Code, Fehlinformationen oder unangemessene Inhalte an Benutzer oder nachgelagerte Systeme weiter.

- **Unbefugte Aktionen**: Autonom integrierte Agents führen ohne ausreichende Benutzeraufsicht unbeabsichtigte Aktionen in der realen Welt aus (Dateien schreiben, API-Aufrufe tätigen, Käufe durchführen usw.).

## MITRE AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet einen umfassenden Rahmen, um Risiken im Zusammenhang mit KI-Systemen zu verstehen und zu mindern. Sie kategorisiert verschiedene Angriffstechniken und Taktiken, die Angreifer gegen KI-Modelle einsetzen können, sowie Möglichkeiten, KI-Systeme für verschiedene Angriffe zu nutzen.<sup>[[3]](#references)</sup>

## LLMJacking (Token-Diebstahl und Weiterverkauf des Zugriffs auf cloud-gehostete LLMs)

Angreifer stehlen aktive Sitzungstokens oder Cloud-API-Zugangsdaten und rufen kostenpflichtige, cloud-gehostete LLMs unbefugt auf. Der Zugriff wird häufig über Reverse Proxies weiterverkauft, die Anfragen über das Konto des Opfers leiten, zum Beispiel über Bereitstellungen von „oai-reverse-proxy“. Zu den Folgen zählen finanzielle Verluste, eine nicht richtlinienkonforme Nutzung des Modells und die Zuordnung der Aktivitäten zum Mandanten des Opfers.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Tokens von infizierten Entwicklergeräten oder Browsern sammeln, CI/CD-Secrets stehlen und geleakte Cookies kaufen.<sup>[[5]](#references)</sup>
- Einen Reverse Proxy einrichten, der Anfragen an den echten Anbieter weiterleitet, den Upstream-Schlüssel verbirgt und viele Kunden über denselben Zugang bedient.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Direkte Endpunkte für Basismodelle missbrauchen, um Enterprise-Sicherheitsvorkehrungen und Rate Limits zu umgehen.<sup>[[4]](#references)</sup>

Gegenmaßnahmen:
- Tokens an Geräte-Fingerprints, IP-Bereiche und Client-Attestierung binden; kurze Ablaufzeiten erzwingen und die Erneuerung durch MFA absichern.
- Schlüssel auf die nötigsten Berechtigungen beschränken (kein Tool-Zugriff, falls möglich nur Lesezugriff); bei Auffälligkeiten rotieren.
- Den gesamten Datenverkehr serverseitig über ein Policy Gateway leiten, das Sicherheitsfilter, Kontingente pro Route und Mandantentrennung erzwingt.
- Ungewöhnliche Nutzungsmuster überwachen (plötzliche Ausgabenspitzen, unübliche Regionen, UA-Strings) und verdächtige Sitzungen automatisch widerrufen.
- mTLS oder signierte JWTs Ihres IdP gegenüber langlebigen statischen API-Schlüsseln bevorzugen.

## Absicherung der Inferenz mit selbst gehosteten LLMs

Der Betrieb eines lokalen LLM-Servers für vertrauliche Daten schafft eine andere Angriffsfläche als cloud-gehostete APIs: Inferenz- und Debug-Endpunkte können Prompts leaken, der Serving-Stack stellt üblicherweise einen Reverse Proxy bereit, und GPU-Geräteknoten ermöglichen den Zugriff auf umfangreiche `ioctl()`-Angriffsflächen. Wenn Sie einen lokalen Inferenzdienst prüfen oder bereitstellen, sollten Sie mindestens die folgenden Punkte berücksichtigen.<sup>[[8]](#references)</sup>

### Prompt-Leakage über Debug- und Monitoring-Endpunkte

Behandeln Sie die Inferenz-API als **sensiblen Mehrbenutzerdienst**. Debug- oder Monitoring-Routen können Prompt-Inhalte, Slot-Zustände, Modellmetadaten oder interne Informationen zu Warteschlangen offenlegen. In `llama.cpp` ist der `/slots`-Endpunkt besonders sensibel, da er den Zustand einzelner Slots offenlegt und nur für deren Prüfung und Verwaltung vorgesehen ist.<sup>[[8]](#references)</sup>

Für Black-Box-Fingerprinting und Tests offengelegter Model Runner und verwandter KI-Dienste siehe [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Einen Reverse Proxy vor den Inferenzserver schalten und **standardmäßig alles verweigern**.
- Nur die exakt benötigten HTTP-Methode- und Pfadkombinationen für den Client bzw. die UI zulassen.
- Introspektionsendpunkte nach Möglichkeit auch im Backend deaktivieren, zum Beispiel mit `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Den Reverse Proxy an `127.0.0.1` binden und über einen authentifizierten Transport wie SSH Local Port Forwarding zugänglich machen, statt ihn im LAN bereitzustellen.

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

Wenn der Inferenz-Daemon Verbindungen über einen UNIX-Socket entgegennehmen kann, bevorzuge das gegenüber TCP und führe den Container **ohne Netzwerk-Stack** aus:<sup>[[8]](#references)</sup>

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
- `--network none` entfernt die eingehende und ausgehende TCP/IP-Angriffsfläche und vermeidet User-Mode-Helfer, die rootless Container andernfalls benötigen würden.
- Ein UNIX-Socket ermöglicht die Verwendung von POSIX-Berechtigungen/ACLs auf dem Socket-Pfad als erste Zugriffskontrollschicht.
- `--userns=keep-id` und rootless Podman verringern die Auswirkungen eines Container-Breakouts, da Container-root nicht Host-root ist.
- Schreibgeschützte Model-Mounts verringern das Risiko, dass Modelle aus dem Container heraus manipuliert werden.

Für dauerhafte Deployments lassen sich dieselben Einschränkungen als Podman-Quadlet-Units ausdrücken. Wenn der GPU-Zugriff über die Container Device Interface delegiert wird, sollte die CDI-Gerätespezifikation so eng wie möglich gefasst werden, anstatt jeden Accelerator-Node freizugeben.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimierung von GPU-Geräteknoten

Bei GPU-gestützter Inferenz sind `/dev/nvidia*`-Dateien besonders sensible lokale Angriffsflächen, da sie umfangreiche Treiber-`ioctl()`-Handler und potenziell gemeinsam genutzte GPU-Speicherverwaltungspfade zugänglich machen.<sup>[[8]](#references)</sup>

- `/dev/nvidia*` darf nicht für alle Benutzer schreibbar sein.
- Beschränken Sie `nvidia`, `nvidiactl` und `nvidia-uvm` mithilfe von `NVreg_DeviceFileUID/GID/Mode`, udev-Regeln und ACLs, sodass nur die zugeordnete Container-UID sie öffnen kann.
- Sperren Sie auf Headless-Inferenz-Hosts unnötige Module wie `nvidia_drm`, `nvidia_modeset` und `nvidia_peermem`.
- Laden Sie beim Booten nur erforderliche Module vor, anstatt der Laufzeit zu erlauben, sie beim Start der Inferenz opportunistisch mit `modprobe` zu laden.

Beispiel:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Ein wichtiger Prüfpunkt ist **`/dev/nvidia-uvm`**. Auch wenn die Workload `cudaMallocManaged()` nicht ausdrücklich verwendet, benötigen aktuelle CUDA-Runtimes möglicherweise trotzdem `nvidia-uvm`. Da dieses Gerät gemeinsam genutzt wird und die Verwaltung des virtuellen GPU-Speichers übernimmt, sollte es als Angriffsfläche für die Offenlegung von Daten zwischen Mandanten behandelt werden. Wenn das Inference-Backend es unterstützt, kann ein Vulkan-Backend ein interessanter Kompromiss sein, da es möglicherweise ganz darauf verzichten kann, `nvidia-uvm` im Container bereitzustellen.<sup>[[8]](#references)</sup>

### LSM-Einschränkung für Inference-Worker

AppArmor/SELinux/seccomp sollten als Defense in Depth für den Inference-Prozess eingesetzt werden:<sup>[[8]](#references)</sup>

- Nur die tatsächlich benötigten Shared Libraries, Modellpfade, Socket-Verzeichnisse und GPU-Geräteknoten zulassen.
- Hochriskante Capabilities wie `sys_admin`, `sys_module`, `sys_rawio` und `sys_ptrace` ausdrücklich verweigern.
- Das Modellverzeichnis schreibgeschützt halten und beschreibbare Pfade ausschließlich auf die Runtime-Socket- und Cache-Verzeichnisse beschränken.
- Verweigerungsprotokolle überwachen, da sie nützliche Telemetriedaten für die Erkennung liefern, wenn der Model Server oder ein Post-Exploitation-Payload versucht, aus seinem vorgesehenen Verhalten auszubrechen.

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

## Phantom Squatting: Von LLMs halluzinierte Domains als Vektor für Angriffe auf die AI-Supply-Chain

Phantom Squatting ist das **Domain-/URL-Äquivalent von Slopsquatting**. Statt einen nicht existierenden Paketnamen zu halluzinieren, halluziniert das LLM eine plausible **Portal-, API-, Webhook-, Billing-, SSO-, Download- oder Support-Domain** einer echten Marke, und ein Angreifer registriert diesen Namensraum, bevor ein Mensch oder Agent ihn verwendet.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Das ist relevant, weil die Modellausgabe in vielen KI-gestützten Workflows als **vertrauenswürdige Abhängigkeit** behandelt wird:
- Entwickler fügen den vorgeschlagenen Endpunkt in Code oder CI/CD-Integrationen ein.
- AI-Agenten rufen automatisch Dokumentation, Schemas, APKs, ZIPs oder Webhook-Ziele ab.
- Generierte Runbooks oder Dokumente können die gefälschte URL einbetten, als wäre sie maßgeblich.

### Angriffsablauf

1. **Die Halluzinationsfläche sondieren**: Stelle markenspezifische Fragen zu realistischen Workflows, etwa zu Portalen für `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` oder `mobile app`.<sup>[[12]](#references)</sup>
2. **Kandidaten normalisieren**: Löse generierte URLs auf, fasse NXDOMAIN-Antworten zur übergeordneten registrierbaren Domain zusammen und entferne doppelte Prompt-Familien. Prompt-Korpora sollten vielfältig bleiben, zum Beispiel indem nahezu identische Prompts anhand der **Jaccard-Ähnlichkeit** entfernt werden.
3. **Vorhersehbare Halluzinationen priorisieren**:
   - **Thermal Hallucination Persistence (THP)**: Dieselbe gefälschte Domain erscheint bei verschiedenen Temperaturen, auch bei niedrigen Temperaturen wie `T=0.1`.
   - **Konsens über mehrere Modelle hinweg**: Mehrere LLM-Familien generieren dieselbe gefälschte Domain.
4. Die übergeordnete Domain **registrieren und für Angriffe nutzen**. Anschließend Phishing-Seiten, gefälschte APK-/ZIP-Downloads, Credential-Harvester, schädliche Dokumente oder API-Endpunkte hosten, die Secrets/Webhook-Payloads erfassen. **Halluzinationen auf reiner Domain-Ebene** lassen sich am einfachsten monetarisieren, da der Angreifer den gesamten Namensraum kontrolliert. Halluzinationen von Subdomains/Pfaden können weiterhin missbraucht werden, wenn die normalisierte übergeordnete Domain noch nicht registriert ist.
5. Das **Reputationsfenster ohne Vorgeschichte ausnutzen**: Neu registrierten Domains fehlen oft Blocklist-Einträge, URL-Reputation und ausgereifte Telemetrie. Daher können sie Kontrollen umgehen, bis die Erkennungsmechanismen aufholen. Angreifer können dieses Zeitfenster durch harmlose Antworten nur für Crawler, Redirect-Cloaking, CAPTCHA-Schranken oder verzögertes Staging von Payloads verlängern.

### Warum dies für Agenten gefährlich ist

Bei einem menschlichen Opfer braucht die gefälschte Domain normalerweise noch einen Klick und eine weitere Aktion. In einem **agentischen Workflow** kann das LLM sowohl **Köder** als auch **Ausführender** sein: Der Agent erhält die halluzinierte URL, ruft sie ab, verarbeitet die Antwort und kann anschließend Tokens leaken, Anweisungen ausführen, eine Abhängigkeit herunterladen oder vergiftete Daten ohne menschliche Prüfung in CI/CD einspeisen.<sup>[[12]](#references)</sup>

### Praktische Angreifer-Prompts

Ertragreiche Prompts wirken meist wie normale Unternehmensaufgaben und nicht wie explizite Phishing-Köder:<sup>[[12]](#references)</sup>
- „Wie lautet die Payment-Sandbox-URL für `<brand>`-Integrationen?“
- „Welchen Webhook-Endpunkt soll ich für Build-Benachrichtigungen von `<brand>` verwenden?“
- „Wo finde ich das Portal für Mitarbeiterleistungen, Billing oder SSO von `<brand>`?“
- „Gib mir den direkten Download für die Android-APK oder den Desktop-Client von `<brand>`.“

### Defensive Umkehrung

Behandle dies als proaktives Domain-Monitoring-Problem und nicht nur als Prompt-Injection-Problem:<sup>[[12]](#references)</sup>
- Erstelle ein **Brand-Prompt-Korpus** und sondiere regelmäßig die LLMs, auf die sich deine Benutzer/Agenten verlassen.
- Speichere halluzinierte URLs und verfolge, welche davon über verschiedene Temperaturen/Modelle hinweg stabil bleiben.
- Verfolge das **Adversarial Exploitation Window (AEW)**: die Zeit zwischen der ersten Halluzination und der Registrierung durch einen Angreifer. Ein positives AEW bedeutet, dass Verteidiger die Domain vor der missbräuchlichen Nutzung vorab registrieren, in ein Sinkhole leiten oder blockieren können.
- Überwache Übergänge von **NXDOMAIN → registriert** für die übergeordneten Domains.
- Prüfe bei einer Registrierung Registrar, Erstellungsdatum, Nameserver, Privacy Shielding, Seiteninhalt, Screenshots, Status als Parking-Seite und Ähnlichkeit zu Marken-Assets.
- Füge Richtlinienprüfungen hinzu, damit Agenten/Entwickler **LLM-generierten Domains nicht standardmäßig vertrauen**: Verlange Allowlists, Eigentumsvalidierung, CT-/RDAP-Prüfungen oder menschliche Freigabe vor der ersten Verwendung.

Dies fällt gleichzeitig in mehrere AI-Risikokategorien: **AI-Supply-Chain-Angriff**, **unsichere Modellausgabe** und **eigenmächtige Aktionen**, wenn Agenten die halluzinierte URL autonom verwenden.

## References

- [1] [OWASP Top 10 für Machine-Learning-Schwachstellen](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risiken](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE-ATLAS-Bedrohungsmatrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Die Risiken von Code-Assistant-LLMs: Schädliche Inhalte, Missbrauch und Täuschung](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Gestohlene Cloud-Zugangsdaten bei einem neuen AI-Angriff verwendet](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Übersicht über das LLMJacking-Schema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (Weiterverkauf gestohlener LLM-Zugänge)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv – Tiefgehende Analyse der Bereitstellung eines On-Premise-LLM-Servers mit geringen Berechtigungen](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README des llama.cpp-Servers](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman Quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF-Spezifikation für die Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Von KI halluzinierte Domains als Vektor für Angriffe auf die Software-Supply-Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Wie KI-Halluzinationen eine neue Klasse von Supply-Chain-Angriffen befeuern](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
