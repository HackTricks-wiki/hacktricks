# KI-Risiken

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP hat die 10 wichtigsten Machine-Learning-Schwachstellen identifiziert, die KI-Systeme betreffen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, darunter Data Poisoning, Model Inversion und Adversarial Attacks. Für die Entwicklung sicherer KI-Systeme ist es entscheidend, diese Schwachstellen zu verstehen.

Eine aktuelle und ausführliche Liste der 10 wichtigsten Machine-Learning-Schwachstellen finden Sie im Projekt [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Ein Angreifer fügt **eingehenden Daten** winzige, oft unsichtbare Veränderungen hinzu, damit das Modell eine falsche Entscheidung trifft.\
    *Beispiel*: Ein paar Farbspritzer auf einem Stoppschild bringen ein selbstfahrendes Auto dazu, ein Tempolimit-Schild zu „sehen“.

- **Data Poisoning Attack**: Der **Trainingsdatensatz** wird absichtlich mit fehlerhaften Beispielen verunreinigt, sodass das Modell schädliche Regeln lernt.\
*Beispiel*: Malware-Binärdateien werden in einem Trainingskorpus für Antivirensoftware fälschlich als „harmlos“ gekennzeichnet, sodass ähnliche Malware später unerkannt bleibt.

- **Model Inversion Attack**: Durch das Abfragen von Ausgaben erstellt ein Angreifer ein **Umkehrmodell**, das sensible Merkmale der ursprünglichen Eingaben rekonstruiert.\
*Beispiel*: Rekonstruktion des MRT-Bilds eines Patienten anhand der Vorhersagen eines Krebsdiagnosemodells.

- **Membership Inference Attack**: Der Angreifer prüft anhand von Unterschieden bei den Konfidenzwerten, ob ein **bestimmter Datensatz** beim Training verwendet wurde.\
*Beispiel*: Bestätigung, dass die Banktransaktion einer Person in den Trainingsdaten eines Betrugserkennungsmodells enthalten ist.

- **Model Theft**: Durch wiederholte Abfragen kann ein Angreifer Entscheidungsgrenzen ermitteln und das **Verhalten des Modells klonen** (sowie dessen geistiges Eigentum).\
*Beispiel*: Erfassung genügend vieler Frage-Antwort-Paare über eine ML-as-a-Service-API, um ein nahezu gleichwertiges lokales Modell zu erstellen.

- **AI Supply‑Chain Attack**: Kompromittierung beliebiger Komponenten (Daten, Bibliotheken, vortrainierte Gewichte, CI/CD) der **ML-Pipeline**, um nachgelagerte Modelle zu manipulieren.\
*Beispiel*: Eine vergiftete Abhängigkeit von einem Model-Hub installiert in zahlreichen Apps ein manipuliertes Sentiment-Analysemodell.

- **Transfer Learning Attack**: Schädliche Logik wird in ein **vortrainiertes Modell** eingebaut und bleibt auch nach dem Fine-Tuning für die Aufgabe des Opfers erhalten.\
*Beispiel*: Ein Vision-Backbone mit einem verborgenen Trigger kehrt weiterhin Labels um, nachdem es für medizinische Bildgebung angepasst wurde.

- **Model Skewing**: Subtil verzerrte oder falsch gekennzeichnete Daten **verschieben die Modellausgaben** zugunsten der Ziele des Angreifers.\
*Beispiel*: Einspeisung „sauberer“ Spam-E-Mails, die als Ham gekennzeichnet sind, damit ein Spamfilter ähnliche zukünftige E-Mails durchlässt.

- **Output Integrity Attack**: Der Angreifer **verändert Modellvorhersagen während der Übertragung**, nicht das Modell selbst, und täuscht dadurch nachgelagerte Systeme.\
*Beispiel*: Umkehrung des Urteils „bösartig“ eines Malware-Klassifikators zu „harmlos“, bevor die Datei-Quarantäne dieses erhält.

- **Model Poisoning** --- Direkte, gezielte Änderungen an den **Modellparametern** selbst, oft nach Erlangung von Schreibzugriff, um das Verhalten zu verändern.\
*Beispiel*: Anpassung der Gewichte eines Betrugserkennungsmodells in der Produktionsumgebung, sodass Transaktionen bestimmter Karten stets genehmigt werden.


## Google SAIF Risks

Das [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) von Google beschreibt verschiedene Risiken im Zusammenhang mit KI-Systemen:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Böswillige Akteure verändern Trainings- oder Tuningdaten oder schleusen solche Daten ein, um die Genauigkeit zu verringern, Backdoors einzubauen oder Ergebnisse zu verzerren. Dadurch wird die Modellintegrität während des gesamten Datenlebenszyklus beeinträchtigt.

- **Unauthorized Training Data**: Die Verwendung urheberrechtlich geschützter, sensibler oder nicht freigegebener Datensätze schafft rechtliche, ethische und leistungsbezogene Risiken, da das Modell aus Daten lernt, die es nicht verwenden durfte.

- **Model Source Tampering**: Manipulation von Modellcode, Abhängigkeiten oder Gewichten durch Angriffe auf die Lieferkette oder durch Insider vor oder während des Trainings kann verborgene Logik einbetten, die auch nach erneutem Training bestehen bleibt.

- **Excessive Data Handling**: Schwache Kontrollen für Datenaufbewahrung und Governance führen dazu, dass Systeme mehr personenbezogene Daten als nötig speichern oder verarbeiten, was das Risiko für Datenlecks und Compliance-Verstöße erhöht.

- **Model Exfiltration**: Angreifer stehlen Modelldateien oder -gewichte. Dadurch geht geistiges Eigentum verloren und Nachahmerdienste oder Folgeangriffe werden ermöglicht.

- **Model Deployment Tampering**: Angreifer verändern Modellartefakte oder die Serving-Infrastruktur, sodass sich das laufende Modell von der geprüften Version unterscheidet und sein Verhalten dadurch möglicherweise verändert wird.

- **Denial of ML Service**: Das Überfluten von APIs oder das Senden von „Sponge“-Eingaben kann Rechenkapazität und Energie aufbrauchen und das Modell außer Betrieb setzen – ähnlich wie bei klassischen DoS-Angriffen.

- **Model Reverse Engineering**: Durch das Sammeln großer Mengen von Ein- und Ausgabepaaren können Angreifer das Modell klonen oder destillieren. Dies begünstigt Nachahmerprodukte und maßgeschneiderte Adversarial Attacks.

- **Insecure Integrated Component**: Verwundbare Plugins, Agents oder vorgelagerte Dienste ermöglichen es Angreifern, Code einzuschleusen oder ihre Berechtigungen innerhalb der KI-Pipeline auszuweiten.

- **Prompt Injection**: Erstellen von Prompts, die direkt oder indirekt Anweisungen einschleusen, welche die Systemabsicht überschreiben und das Modell dazu bringen, unbeabsichtigte Befehle auszuführen.

- **Model Evasion**: Sorgfältig gestaltete Eingaben bringen das Modell dazu, falsch zu klassifizieren, zu halluzinieren oder unzulässige Inhalte auszugeben, wodurch Sicherheit und Vertrauen untergraben werden.

- **Sensitive Data Disclosure**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem Benutzerkontext preis und verletzt dadurch Datenschutz und Vorschriften.

- **Inferred Sensitive Data**: Das Modell leitet personenbezogene Merkmale ab, die nie angegeben wurden, und verursacht dadurch neue Datenschutzrisiken.

- **Insecure Model Output**: Nicht bereinigte Antworten geben schädlichen Code, Fehlinformationen oder unangemessene Inhalte an Benutzer oder nachgelagerte Systeme weiter.

- **Rogue Actions**: Integrierte autonome Agents führen ohne angemessene Aufsicht durch Benutzer unbeabsichtigte Aktionen in der realen Welt aus (Dateischreibvorgänge, API-Aufrufe, Käufe usw.).

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet einen umfassenden Rahmen, um Risiken im Zusammenhang mit KI-Systemen zu verstehen und zu mindern. Sie kategorisiert verschiedene Angriffstechniken und Taktiken, die Angreifer gegen KI-Modelle einsetzen können, sowie Möglichkeiten, KI-Systeme für verschiedene Angriffe zu nutzen.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Angreifer stehlen aktive Sitzungstoken oder Cloud-API-Zugangsdaten und nutzen kostenpflichtige, in der Cloud gehostete LLMs ohne Autorisierung. Der Zugriff wird häufig über Reverse-Proxys weiterverkauft, die Anfragen über das Konto des Opfers leiten, z. B. über Deployments von „oai-reverse-proxy“. Zu den Folgen zählen finanzielle Verluste, eine richtlinienwidrige Nutzung des Modells und die Zuordnung der Aktivitäten zum Mandanten des Opfers.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Tokens von infizierten Entwicklerrechnern oder Browsern abgreifen, CI/CD-Secrets stehlen und geleakte Cookies kaufen.<sup>[[5]](#references)</sup>
- Einen Reverse-Proxy einrichten, der Anfragen an den echten Anbieter weiterleitet, den Upstream-Key verbirgt und Anfragen vieler Kunden bündelt.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Direkte Endpunkte des Basismodells missbrauchen, um Enterprise-Sicherheitsvorkehrungen und Rate Limits zu umgehen.<sup>[[4]](#references)</sup>

Gegenmaßnahmen:
- Tokens an Geräte-Fingerprints, IP-Bereiche und Client-Attestation binden; kurze Ablaufzeiten durchsetzen und die Erneuerung mit MFA absichern.
- Schlüssel so weit wie möglich einschränken (kein Tool-Zugriff, sofern möglich schreibgeschützt); bei Auffälligkeiten rotieren.
- Den gesamten Datenverkehr serverseitig über ein Policy-Gateway leiten, das Sicherheitsfilter, Quoten pro Route und Mandantenisolierung durchsetzt.
- Auf ungewöhnliche Nutzungsmuster achten (plötzliche Ausgabenspitzen, untypische Regionen, UA-Strings) und verdächtige Sitzungen automatisch widerrufen.
- mTLS oder signierte JWTs verwenden, die vom eigenen IdP ausgestellt wurden, statt langlebiger statischer API-Schlüssel.

## Absicherung der Inferenz mit selbst gehosteten LLMs

Ein lokaler LLM-Server für vertrauliche Daten schafft eine andere Angriffsfläche als Cloud-gehostete APIs: Inferenz- und Debug-Endpunkte können Prompts leaken, der Serving-Stack stellt üblicherweise einen Reverse-Proxy bereit, und GPU-Geräteknoten bieten Zugriff auf umfangreiche `ioctl()`-Angriffsflächen. Wenn Sie einen lokalen Inferenzdienst bewerten oder bereitstellen, prüfen Sie mindestens die folgenden Punkte.<sup>[[8]](#references)</sup>

### Prompt leakage über Debug- und Monitoring-Endpunkte

Betrachten Sie die Inferenz-API als **sensiblen Dienst für mehrere Benutzer**. Debug- oder Monitoring-Routen können Prompt-Inhalte, den Slot-Status, Modellmetadaten oder interne Informationen zur Warteschlange offenlegen. In `llama.cpp` ist der Endpunkt `/slots` besonders sensibel, da er den Status der einzelnen Slots offenlegt und ausschließlich zur Prüfung und Verwaltung von Slots vorgesehen ist.<sup>[[8]](#references)</sup>

- Einen Reverse-Proxy vor den Inferenzserver schalten und standardmäßig **alles ablehnen**.
- Nur die genau benötigten Kombinationen aus HTTP-Methode und Pfad für den Client bzw. die UI zulassen.
- Introspektionsendpunkte nach Möglichkeit direkt im Backend deaktivieren, zum Beispiel mit `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Den Reverse-Proxy an `127.0.0.1` binden und über einen authentifizierten Transport wie SSH Local Port Forwarding erreichbar machen, statt ihn im LAN bereitzustellen.

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

Wenn der Inferenz-Daemon das Lauschen an einem UNIX-Socket unterstützt, verwende diesen statt TCP und führe den Container **ohne Netzwerkstack** aus:<sup>[[8]](#references)</sup>

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
- `--network none` entfernt die eingehende/ausgehende TCP/IP-Angriffsfläche und vermeidet User-Mode-Helpers, die rootless containers andernfalls benötigen würden.
- Ein UNIX-Socket ermöglicht die Verwendung von POSIX-Berechtigungen/ACLs auf dem Socket-Pfad als erste Zugriffskontrollschicht.
- `--userns=keep-id` und rootless Podman verringern die Auswirkungen eines Container-Breakouts, da Container-root nicht Host-root ist.
- Schreibgeschützte Model-Mounts verringern die Wahrscheinlichkeit, dass Modelle innerhalb des Containers manipuliert werden.

Bei persistenten Deployments lassen sich dieselben Einschränkungen als Podman-Quadlet-Units ausdrücken. Wenn der GPU-Zugriff über das Container Device Interface delegiert wird, sollte die CDI-Gerätespezifikation so eng wie möglich gefasst werden, statt alle Accelerator-Geräteknoten offenzulegen.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimierung von GPU-Geräteknoten

Bei GPU-gestützter Inferenz sind `/dev/nvidia*`-Dateien besonders wertvolle lokale Angriffsflächen, da sie umfangreiche Treiber-`ioctl()`-Handler und potenziell gemeinsam genutzte GPU-Speicherverwaltungspfade zugänglich machen.<sup>[[8]](#references)</sup>

- `/dev/nvidia*` darf nicht für alle Benutzer beschreibbar sein.
- Beschränken Sie `nvidia`, `nvidiactl` und `nvidia-uvm` mithilfe von `NVreg_DeviceFileUID/GID/Mode`, udev-Regeln und ACLs so, dass nur die zugeordnete Container-UID sie öffnen kann.
- Sperren Sie auf Inferenz-Hosts ohne grafische Oberfläche unnötige Module wie `nvidia_drm`, `nvidia_modeset` und `nvidia_peermem` per Blacklist.
- Laden Sie beim Systemstart nur erforderliche Module vor, statt dem Runtime-System zu erlauben, sie beim Start der Inferenz bei Bedarf mit `modprobe` zu laden.

Beispiel:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Ein wichtiger Prüfpunkt ist **`/dev/nvidia-uvm`**. Auch wenn die Workload `cudaMallocManaged()` nicht explizit verwendet, können neuere CUDA-Runtimes `nvidia-uvm` dennoch benötigen. Da dieses Gerät gemeinsam genutzt wird und die Verwaltung des virtuellen GPU-Speichers übernimmt, sollte es als Angriffsfläche für Datenlecks zwischen Mandanten betrachtet werden. Falls das Inference-Backend es unterstützt, kann ein Vulkan-Backend ein interessanter Kompromiss sein, da dadurch `nvidia-uvm` möglicherweise gar nicht erst im Container freigegeben werden muss.<sup>[[8]](#references)</sup>

### LSM-Einschränkung für Inference-Worker

AppArmor/SELinux/seccomp sollten als Defense-in-Depth-Maßnahmen rund um den Inference-Prozess eingesetzt werden:<sup>[[8]](#references)</sup>

- Nur die tatsächlich benötigten Shared Libraries, Modellpfade, Socket-Verzeichnisse und GPU-Geräteknoten zulassen.
- Hochriskante Capabilities wie `sys_admin`, `sys_module`, `sys_rawio` und `sys_ptrace` ausdrücklich verweigern.
- Das Modellverzeichnis schreibgeschützt halten und schreibbare Pfade ausschließlich auf die Socket- und Cache-Verzeichnisse der Laufzeitumgebung beschränken.
- Verweigerungsprotokolle überwachen, da sie nützliche Erkennungstelemetrie liefern, wenn der Modellserver oder eine Post-Exploitation-Payload versucht, aus seinem erwarteten Verhalten auszubrechen.

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

Phantom Squatting ist das **Domain-/URL-Äquivalent von Slopsquatting**. Statt einen nicht existierenden Paketnamen zu halluzinieren, halluziniert das LLM eine plausible **Portal-, API-, Webhook-, Abrechnungs-, SSO-, Download- oder Support-Domain** für eine reale Marke. Ein Angreifer registriert diesen Namensraum, bevor ihn ein Mensch oder Agent verwendet.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Das ist relevant, weil die Modellausgabe in vielen KI-gestützten Workflows als **vertrauenswürdige Abhängigkeit** behandelt wird:
- Entwickler fügen den vorgeschlagenen Endpunkt in Code oder CI/CD-Integrationen ein.
- AI-Agenten rufen automatisch Dokumentation, Schemas, APKs, ZIP-Dateien oder Webhook-Ziele ab.
- Generierte Runbooks oder Dokumentationen können die gefälschte URL so einbetten, als wäre sie maßgeblich.

### Angriffsablauf

1. **Die Halluzinationsfläche untersuchen**: Fragen zu markenspezifischen, realistischen Workflows stellen, etwa zu `admin`-, `billing`-, `sandbox`-, `benefits`-, `api`-, `download`-, `support`-, `webhook`- oder `mobile app`-Portalen.<sup>[[12]](#references)</sup>
2. **Kandidaten normalisieren**: Generierte URLs auflösen, NXDOMAIN-Antworten auf die übergeordnete registrierbare Domain zurückführen und Prompt-Familien deduplizieren. Prompt-Korpora sollten vielfältig bleiben, etwa indem nahezu identische Prompts anhand der **Jaccard-Ähnlichkeit** entfernt werden.
3. **Vorhersehbare Halluzinationen priorisieren**:
   - **Thermal Hallucination Persistence (THP)**: Dieselbe gefälschte Domain erscheint bei verschiedenen Temperaturen, auch bei niedrigen Werten wie `T=0.1`.
   - **Konsens über mehrere Modelle hinweg**: Mehrere LLM-Familien generieren dieselbe gefälschte Domain.
4. Die übergeordnete Domain **registrieren und als Waffe einsetzen**. Anschließend dort Phishing, gefälschte APK-/ZIP-Downloads, Zugangsdaten-Diebe, bösartige Dokumente oder API-Endpunkte hosten, die Geheimnisse oder Webhook-Payloads abgreifen. **Reine Domain-Halluzinationen** lassen sich am einfachsten monetarisieren, da der Angreifer den gesamten Namensraum kontrolliert. Halluzinationen von Subdomains oder Pfaden können ebenfalls missbraucht werden, wenn die normalisierte übergeordnete Domain noch nicht registriert ist.
5. Das **Zeitfenster ohne Reputation** ausnutzen: Neu registrierten Domains fehlen oft Blocklist-Historie, URL-Reputation und ausgereifte Telemetriedaten. Daher können sie Schutzmaßnahmen umgehen, bis Erkennungen nachziehen. Angreifer können dieses Zeitfenster durch harmlose Antworten nur für Crawler, Redirect-Cloaking, CAPTCHA-Schranken oder verzögertes Bereitstellen von Payloads verlängern.

### Warum Agenten dadurch gefährdet sind

Bei einem menschlichen Opfer benötigt die gefälschte Domain normalerweise noch einen Klick und eine weitere Aktion. In einem **agentenbasierten Workflow** kann das LLM sowohl der **Köder** als auch der **Ausführer** sein: Der Agent erhält die halluzinierte URL, ruft sie ab, verarbeitet die Antwort und kann anschließend Tokens leaken, Anweisungen ausführen, eine Abhängigkeit herunterladen oder vergiftete Daten in CI/CD einspeisen – ganz ohne menschliche Prüfung.<sup>[[12]](#references)</sup>

### Praktische Prompts für Angreifer

Prompts mit hoher Erfolgsquote ähneln meist normalen Unternehmensaufgaben und keinen expliziten Phishing-Ködern:<sup>[[12]](#references)</sup>
- „Wie lautet die URL der Payment-Sandbox für `<brand>`-Integrationen?“
- „Welchen Webhook-Endpunkt sollte ich für Build-Benachrichtigungen von `<brand>` verwenden?“
- „Wo befindet sich das Mitarbeiter-Benefits-, Abrechnungs- oder SSO-Portal von `<brand>`?“
- „Gib mir den direkten Download der Android-APK oder des Desktop-Clients von `<brand>`.“

### Defensive Umkehrung

Behandle dies als proaktives Domain-Monitoring und nicht nur als Prompt-Injection-Problem:<sup>[[12]](#references)</sup>
- Erstelle ein **Marken-Prompt-Korpus** und teste regelmäßig die LLMs, auf die sich deine Nutzer oder Agenten verlassen.
- Speichere halluzinierte URLs und erfasse, welche davon über verschiedene Temperaturen und Modelle hinweg stabil bleiben.
- Überwache das **Adversarial Exploitation Window (AEW)**: die Zeit zwischen der ersten Halluzination und der Registrierung durch einen Angreifer. Ein positives AEW bedeutet, dass Verteidiger Domains vor dem Einsatz durch Angreifer registrieren, in ein Sinkhole umleiten oder vorab blockieren können.
- Überwache Übergänge von **NXDOMAIN → registriert** für die übergeordneten Domains.
- Prüfe bei einer Registrierung den Registrar, das Erstellungsdatum, die Nameserver, den Datenschutz, den Seiteninhalt, Screenshots, den Status als geparkte Seite und die Ähnlichkeit zu Marken-Assets.
- Füge Richtlinienprüfungen hinzu, damit Agenten und Entwickler **LLM-generierten Domains nicht standardmäßig vertrauen**: Verlange Allowlists, eine Prüfung der Eigentümerschaft, CT-/RDAP-Prüfungen oder eine menschliche Freigabe, bevor eine Domain erstmals verwendet wird.

Dies fällt gleichzeitig in mehrere AI-Risikobereiche: **Angriffe auf die AI-Supply-Chain**, **unsichere Modellausgaben** und **unerwünschte Aktionen**, wenn Agenten die halluzinierte URL autonom verwenden.

## References

- [1] [OWASP Top 10 für Machine-Learning-Schwachstellen](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risiken](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE-ATLAS-Bedrohungsmatrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Die Risiken von Code-Assistant-LLMs: schädliche Inhalte, Missbrauch und Täuschung](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Gestohlene Cloud-Zugangsdaten bei einem neuen AI-Angriff verwendet](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Überblick über das LLMJacking-Schema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (Weiterverkauf gestohlener LLM-Zugänge)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv – Ein tiefer Einblick in die Bereitstellung eines On-Premise-LLM-Servers mit geringen Berechtigungen](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README des llama.cpp-Servers](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman-Quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF-Spezifikation der Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Von KI halluzinierte Domains als Vektor für Angriffe auf die Software-Supply-Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Wie KI-Halluzinationen eine neue Klasse von Supply-Chain-Angriffen befeuern](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
