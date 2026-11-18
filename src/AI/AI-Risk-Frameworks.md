# KI-Risiken

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP hat die zehn wichtigsten Machine-Learning-Schwachstellen identifiziert, die KI-Systeme betreffen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, darunter Data Poisoning, Model Inversion und adversarial attacks. Das Verständnis dieser Schwachstellen ist entscheidend für die Entwicklung sicherer KI-Systeme.

Eine aktuelle und detaillierte Liste der zehn wichtigsten Machine-Learning-Schwachstellen finden Sie im Projekt [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Ein Angreifer fügt **eingehenden Daten** winzige, oft unsichtbare Änderungen hinzu, damit das Modell eine falsche Entscheidung trifft.\
    *Beispiel*: Ein paar Farbspritzer auf einem Stoppschild verleiten ein selbstfahrendes Auto dazu, ein Tempolimitschild zu „sehen“.

- **Data Poisoning Attack**: Der **Trainingsdatensatz** wird absichtlich mit fehlerhaften Beispielen verunreinigt, wodurch das Modell schädliche Regeln lernt.\
*Beispiel*: Malware-Binärdateien werden in einem Trainingskorpus für Antivirensoftware fälschlich als „harmlos“ gekennzeichnet, sodass ähnliche Malware später unentdeckt bleibt.

- **Model Inversion Attack**: Indem ein Angreifer die Ausgaben abfragt, erstellt er ein **umgekehrtes Modell**, das sensible Merkmale der ursprünglichen Eingaben rekonstruiert.\
*Beispiel*: Rekonstruktion eines MRT-Bildes eines Patienten anhand der Vorhersagen eines Krebsdiagnosemodells.

- **Membership Inference Attack**: Der Angreifer prüft anhand von Konfidenzunterschieden, ob ein **bestimmter Datensatz** beim Training verwendet wurde.\
*Beispiel*: Feststellen, ob die Banktransaktion einer Person in den Trainingsdaten eines Betrugserkennungsmodells enthalten ist.

- **Model Theft**: Durch wiederholte Abfragen kann ein Angreifer Entscheidungsgrenzen ermitteln und das **Verhalten des Modells klonen** (sowie geistiges Eigentum stehlen).\
*Beispiel*: Ausreichend viele Frage-Antwort-Paare aus einer ML-as-a-Service-API sammeln, um ein nahezu gleichwertiges lokales Modell zu erstellen.

- **AI Supply-Chain Attack**: Eine beliebige Komponente (Daten, Bibliotheken, vortrainierte Gewichte, CI/CD) in der **ML-Pipeline** kompromittieren, um nachgelagerte Modelle zu verfälschen.\
*Beispiel*: Eine vergiftete Abhängigkeit aus einem Model Hub installiert in vielen Apps ein manipuliertes Sentiment-Analyse-Modell.

- **Transfer Learning Attack**: Schädliche Logik wird in einem **vortrainierten Modell** platziert und übersteht das Fine-Tuning für die Aufgabe des Opfers.\
*Beispiel*: Ein Vision-Backbone mit einem versteckten Trigger vertauscht weiterhin Labels, nachdem es für die medizinische Bildgebung angepasst wurde.

- **Model Skewing**: Subtil verzerrte oder falsch gekennzeichnete Daten **verschieben die Modellausgaben** zugunsten der Ziele des Angreifers.\
*Beispiel*: „Saubere“ Spam-E-Mails werden als Ham gekennzeichnet, sodass ein Spamfilter ähnliche zukünftige E-Mails durchlässt.

- **Output Integrity Attack**: Der Angreifer **verändert Modellvorhersagen während der Übertragung**, nicht das Modell selbst, und täuscht so nachgelagerte Systeme.\
*Beispiel*: Das Urteil „schädlich“ eines Malware-Klassifikators wird in „harmlos“ geändert, bevor die Datei die Quarantänestufe erreicht.

- **Model Poisoning** --- Gezielte direkte Änderungen an den **Modellparametern**, oft nachdem Schreibzugriff erlangt wurde, um das Verhalten zu verändern.\
*Beispiel*: Gewichte eines Betrugserkennungsmodells in der Produktion werden so angepasst, dass Transaktionen bestimmter Karten immer genehmigt werden.


## Google SAIF-Risiken

Googles [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beschreibt verschiedene Risiken im Zusammenhang mit KI-Systemen:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Böswillige Akteure verändern oder injizieren Trainings- bzw. Tuning-Daten, um die Genauigkeit zu verringern, Backdoors einzubauen oder Ergebnisse zu verzerren. Dadurch wird die Integrität des Modells über den gesamten Datenlebenszyklus hinweg beeinträchtigt.

- **Unauthorized Training Data**: Das Einlesen urheberrechtlich geschützter, sensibler oder nicht freigegebener Datensätze birgt rechtliche, ethische und leistungsbezogene Risiken, da das Modell mit Daten trainiert wird, die es nicht verwenden durfte.

- **Model Source Tampering**: Manipulation von Modellcode, Abhängigkeiten oder Gewichten durch Angriffe auf die Lieferkette oder durch Insider vor oder während des Trainings kann verborgene Logik einbetten, die auch nach erneutem Training erhalten bleibt.

- **Excessive Data Handling**: Schwache Kontrollen zur Datenaufbewahrung und Governance führen dazu, dass Systeme mehr personenbezogene Daten als nötig speichern oder verarbeiten, wodurch Risiken für Datenschutz und Compliance steigen.

- **Model Exfiltration**: Angreifer stehlen Modelldateien oder Gewichte. Das führt zum Verlust geistigen Eigentums und ermöglicht Nachahmerdienste oder Folgeangriffe.

- **Model Deployment Tampering**: Angreifer verändern Modellartefakte oder die Bereitstellungsinfrastruktur, sodass sich das laufende Modell von der geprüften Version unterscheidet und sein Verhalten möglicherweise verändert wird.

- **Denial of ML Service**: Das Überfluten von APIs oder das Senden von „Sponge“-Eingaben kann Rechenleistung und Energie erschöpfen und das Modell außer Betrieb setzen – ähnlich wie bei klassischen DoS-Angriffen.

- **Model Reverse Engineering**: Durch das Sammeln großer Mengen von Ein- und Ausgabepaaren können Angreifer das Modell klonen oder destillieren und so Nachahmerprodukte sowie gezielte adversarial attacks ermöglichen.

- **Insecure Integrated Component**: Schwachstellen in Plugins, Agents oder vorgelagerten Diensten ermöglichen es Angreifern, Code in die KI-Pipeline einzuschleusen oder ihre Berechtigungen auszuweiten.

- **Prompt Injection**: Prompts werden direkt oder indirekt so gestaltet, dass sie Anweisungen einschleusen, die die Systemabsicht überschreiben und das Modell zu unbeabsichtigten Befehlen veranlassen.

- **Model Evasion**: Sorgfältig gestaltete Eingaben veranlassen das Modell zu Fehlklassifizierungen, Halluzinationen oder zur Ausgabe unzulässiger Inhalte und untergraben so Sicherheit und Vertrauen.

- **Sensitive Data Disclosure**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem Benutzerkontext preis und verletzt damit Datenschutzvorgaben und Vorschriften.

- **Inferred Sensitive Data**: Das Modell leitet persönliche Merkmale ab, die nie angegeben wurden, und verursacht dadurch neue Datenschutzrisiken.

- **Insecure Model Output**: Nicht bereinigte Antworten geben schädlichen Code, Falschinformationen oder unangemessene Inhalte an Benutzer oder nachgelagerte Systeme weiter.

- **Rogue Actions**: Integrierte autonome Agents führen ohne ausreichende Aufsicht durch Benutzer unbeabsichtigte Aktionen in der realen Welt aus (Dateien schreiben, API-Aufrufe tätigen, Käufe abschließen usw.).

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet einen umfassenden Rahmen, um Risiken im Zusammenhang mit KI-Systemen zu verstehen und zu mindern. Sie kategorisiert verschiedene Angriffstechniken und Taktiken, die Angreifer gegen KI-Modelle einsetzen können, sowie Möglichkeiten, KI-Systeme für unterschiedliche Angriffe zu nutzen.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Angreifer stehlen aktive Sitzungstoken oder Cloud-API-Anmeldedaten und greifen ohne Autorisierung auf kostenpflichtige, in der Cloud gehostete LLMs zu. Der Zugriff wird oft über Reverse Proxies weiterverkauft, die Anfragen über das Konto des Opfers leiten, z. B. über „oai-reverse-proxy“-Deployments. Mögliche Folgen sind finanzielle Verluste, eine richtlinienwidrige Nutzung des Modells und die Zuordnung der Aktivitäten zum Tenant des Opfers.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Token von infizierten Entwicklergeräten oder Browsern abgreifen, CI/CD-Secrets stehlen und geleakte Cookies kaufen.<sup>[[5]](#references)</sup>
- Einen Reverse Proxy einrichten, der Anfragen an den echten Anbieter weiterleitet, den Upstream-Schlüssel verbirgt und mehrere Kunden bedient.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Direkte Endpunkte des Basismodells missbrauchen, um Enterprise-Schutzmaßnahmen und Rate Limits zu umgehen.<sup>[[4]](#references)</sup>

**Wiederverwendung von API-Schlüsseln auf dem Host:** Nach einer Kompromittierung des Hosts kann ein Implantat Modell-API-Anfragen direkt vom Host des Opfers senden und die Antworten über C2 weiterleiten, ohne einen Cloud-API-Schlüssel zu exportieren oder eine lokale AI-CLI zu starten. Im beobachteten Handler hat ein von C2 bereitgestellter Schlüssel Vorrang. Nur wenn dieser fehlt, liest das Implantat `OPENAI_API_KEY` aus der Prozessumgebung. Die Nutzung des Kontos des Opfers erfordert daher einen gültigen Schlüssel, der für diesen Prozess sichtbar ist, sowie Zugriff auf die Modell-API. Der Prompt des Operators geht an die Chat Completions API; die Modellausgabe und der Tokenverbrauch werden über C2 zurückgesendet. So kann der kostenpflichtige Modellzugriff des Opfers genutzt werden, ohne die AI-Tools des Entwicklers auszuführen – anders als beim Missbrauch der Konfiguration von [lokalen AI-CLIs oder MCP](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md).<sup>[[14]](#references)</sup>

Gegenmaßnahmen:
- Token an Geräte-Fingerprints, IP-Bereiche und Client-Attestierung binden; kurze Ablaufzeiten festlegen und die Aktualisierung mit MFA absichern.
- Schlüssel auf das nötige Minimum beschränken (kein Toolzugriff, sofern anwendbar schreibgeschützt) und bei Auffälligkeiten rotieren.
- Den gesamten Datenverkehr serverseitig über ein Policy Gateway leiten, das Sicherheitsfilter, Kontingente pro Route und Tenant-Isolierung durchsetzt.
- Ungewöhnliche Nutzungsmuster überwachen (plötzliche Ausgabenanstiege, ungewöhnliche Regionen, UA-Strings) und verdächtige Sitzungen automatisch widerrufen.
- mTLS oder signierte JWTs, die von Ihrem IdP ausgestellt werden, gegenüber langlebigen statischen API-Schlüsseln bevorzugen.

## Absicherung selbst gehosteter LLM-Inferenz

Ein lokaler LLM-Server für vertrauliche Daten weist eine andere Angriffsfläche auf als cloudgehostete APIs: Inferenz- und Debug-Endpunkte können Prompts offenlegen, der Serving-Stack stellt üblicherweise einen Reverse Proxy bereit, und GPU-Geräteknoten bieten Zugriff auf umfangreiche `ioctl()`-Angriffsflächen. Wenn Sie einen On-Prem-Inferenzdienst prüfen oder bereitstellen, berücksichtigen Sie mindestens die folgenden Punkte.<sup>[[8]](#references)</sup>

### Prompt-Leaks über Debug- und Monitoring-Endpunkte

Behandeln Sie die Inferenz-API als **sensiblen Mehrbenutzerdienst**. Debug- oder Monitoring-Routen können Prompt-Inhalte, den Status von Slots, Modellmetadaten oder interne Warteschlangeninformationen offenlegen. In `llama.cpp` ist der `/slots`-Endpunkt besonders sensibel, da er den Status einzelner Slots offenlegt und nur zur Inspektion bzw. Verwaltung von Slots vorgesehen ist.<sup>[[8]](#references)</sup>

Für Black-Box-Fingerprinting und Tests offengelegter Model Runner und zugehöriger KI-Dienste siehe [Offengelegte selbst gehostete KI-Dienste](AI-Exposed-Self-Hosted-AI-Services.md).

- Einen Reverse Proxy vor den Inferenzserver setzen und **standardmäßig alles blockieren**.
- Nur die exakten Kombinationen aus HTTP-Methode und Pfad freigeben, die der Client bzw. die UI benötigt.
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

### Rootless-Container ohne Netzwerk und mit UNIX-Sockets

Wenn der Inferenz-Daemon das Lauschen an einem UNIX-Socket unterstützt, ziehe dies TCP vor und führe den Container **ohne Netzwerk-Stack** aus:<sup>[[8]](#references)</sup>

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
- `--network none` entfernt die eingehende/ausgehende TCP/IP-Exposition und vermeidet User-Mode-Helfer, die rootless-Container andernfalls benötigen würden.
- Ein UNIX-Socket ermöglicht die Verwendung von POSIX-Berechtigungen/ACLs für den Socket-Pfad als erste Zugriffskontrollschicht.
- `--userns=keep-id` und rootless Podman verringern die Auswirkungen eines Container-Ausbruchs, da Container-root nicht Host-root ist.
- Read-only-Modell-Mounts verringern das Risiko einer Manipulation des Modells aus dem Container heraus.

Für persistente Deployments lassen sich dieselben Einschränkungen als Podman-Quadlet-Units ausdrücken. Wenn der GPU-Zugriff über die Container Device Interface delegiert wird, sollte die CDI-Gerätespezifikation so eng wie möglich gefasst werden, statt alle Accelerator-Geräteknoten offenzulegen.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimierung der GPU-Geräteknoten

Bei GPU-gestützter Inferenz sind `/dev/nvidia*`-Dateien besonders wertvolle lokale Angriffsflächen, da sie umfangreiche Treiber-`ioctl()`-Handler und möglicherweise gemeinsam genutzte GPU-Speicherverwaltungspfade offenlegen.<sup>[[8]](#references)</sup>

- `/dev/nvidia*` darf nicht für alle Benutzer beschreibbar sein.
- Beschränke `nvidia`, `nvidiactl` und `nvidia-uvm` mithilfe von `NVreg_DeviceFileUID/GID/Mode`, udev-Regeln und ACLs so, dass sie nur von der zugeordneten Container-UID geöffnet werden können.
- Sperre auf headless Inferenz-Hosts unnötige Module wie `nvidia_drm`, `nvidia_modeset` und `nvidia_peermem`.
- Lade beim Booten nur erforderliche Module vor, statt die Runtime während des Inferenzstarts opportunistisch `modprobe` ausführen zu lassen.

Beispiel:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Ein wichtiger Prüfpunkt ist **`/dev/nvidia-uvm`**. Auch wenn die Workload `cudaMallocManaged()` nicht explizit verwendet, können aktuelle CUDA-Runtimes `nvidia-uvm` dennoch benötigen. Da dieses Gerät gemeinsam genutzt wird und die Verwaltung des virtuellen GPU-Speichers übernimmt, sollte es als mandantenübergreifende Angriffsfläche für Datenoffenlegung behandelt werden. Wenn das Inferenz-Backend es unterstützt, kann ein Vulkan-Backend eine interessante Abwägung sein, da sich dadurch möglicherweise ganz vermeiden lässt, `nvidia-uvm` für den Container freizugeben.<sup>[[8]](#references)</sup>

### LSM-Einschränkung für Inferenz-Worker

AppArmor/SELinux/seccomp sollten als mehrschichtige Schutzmaßnahme für den Inferenzprozess eingesetzt werden:<sup>[[8]](#references)</sup>

- Nur die tatsächlich benötigten Shared Libraries, Modellpfade, Socket-Verzeichnisse und GPU-Geräteknoten zulassen.
- Hochriskante Capabilities wie `sys_admin`, `sys_module`, `sys_rawio` und `sys_ptrace` explizit verweigern.
- Das Modellverzeichnis schreibgeschützt halten und beschreibbare Pfade auf die Runtime-Socket- und Cache-Verzeichnisse beschränken.
- Verweigerungsprotokolle überwachen, da sie nützliche Telemetriedaten für die Erkennung liefern, wenn der Model-Server oder eine Post-Exploitation-Payload versucht, die erwarteten Grenzen zu umgehen.

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

## Phantom Squatting: Von LLMs halluzinierte Domains als Angriffsvektor auf die AI-Supply-Chain

Phantom Squatting ist das **Domain-/URL-Pendant zu Slopsquatting**. Statt einen nicht existierenden Paketnamen zu halluzinieren, halluziniert das LLM eine plausible **Portal-, API-, Webhook-, Abrechnungs-, SSO-, Download- oder Support-Domain** für eine reale Marke, und ein Angreifer registriert diesen Namensraum, bevor ein Mensch oder Agent ihn verwendet.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Das ist relevant, weil die Modellausgabe in vielen KI-gestützten Workflows als **vertrauenswürdige Abhängigkeit** behandelt wird:
- Entwickler fügen den vorgeschlagenen Endpunkt in Code oder CI/CD-Integrationen ein.
- AI-Agents rufen automatisch Dokumentation, Schemas, APKs, ZIP-Dateien oder Webhook-Ziele ab.
- Generierte Runbooks oder Dokumentationen können die gefälschte URL so einbetten, als wäre sie maßgeblich.

### Angriffsablauf

1. **Die Halluzinationsfläche sondieren**: Stelle markenspezifische Fragen zu realistischen Workflows wie Portalen für `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` oder `mobile app`.<sup>[[12]](#references)</sup>
2. **Kandidaten normalisieren**: Löse generierte URLs auf, fasse NXDOMAIN-Antworten zur übergeordneten registrierbaren Domain zusammen und dedupliziere Prompt-Familien. Prompt-Korpora sollten vielfältig bleiben, zum Beispiel durch Entfernen von Beinahe-Duplikaten anhand der **Jaccard-Ähnlichkeit**.
3. **Vorhersehbare Halluzinationen priorisieren**:
   - **Thermal Hallucination Persistence (THP)**: Dieselbe gefälschte Domain erscheint über verschiedene Temperaturen hinweg, auch bei niedrigen Temperaturen wie `T=0.1`.
   - **Modellübergreifender Konsens**: Mehrere LLM-Familien generieren dieselbe gefälschte Domain.
4. **Die übergeordnete Domain registrieren und für Angriffe nutzen**, dann Phishing-Seiten, gefälschte APK-/ZIP-Downloads, Credential-Harvester, bösartige Dokumente oder API-Endpunkte hosten, die Secrets/Webhook-Payloads sammeln. **Reine Domain-Halluzinationen** lassen sich am einfachsten monetarisieren, weil der Angreifer den gesamten Namensraum kontrolliert; Halluzinationen von Subdomains/Pfaden können weiterhin missbraucht werden, wenn die normalisierte übergeordnete Domain nicht registriert ist.
5. **Das Zeitfenster ohne Reputation ausnutzen**: Neu registrierte Domains haben oft keine Blocklist-Historie, URL-Reputation oder ausgereifte Telemetrie und können daher Kontrollen umgehen, bis die Erkennung aufholt. Angreifer können dieses Zeitfenster durch gutartige Antworten nur für Crawler, Redirect-Cloaking, CAPTCHA-Schranken oder verzögertes Bereitstellen der Payload verlängern.

### Warum dies für Agents gefährlich ist

Bei einem menschlichen Opfer benötigt die gefälschte Domain normalerweise noch einen Klick und eine weitere Aktion. Bei einem **agentischen Workflow** kann das LLM sowohl der **Köder** als auch der **Ausführer** sein: Der Agent erhält die halluzinierte URL, ruft sie ab, analysiert die Antwort und kann anschließend Tokens leaken, Anweisungen ausführen, eine Abhängigkeit herunterladen oder vergiftete Daten ohne menschliche Prüfung in CI/CD einspeisen.<sup>[[12]](#references)</sup>

### Praktische Angreifer-Prompts

Besonders ergiebige Prompts sehen meist wie normale Unternehmensaufgaben aus und nicht wie explizite Phishing-Köder:<sup>[[12]](#references)</sup>
- „Wie lautet die URL der Payment-Sandbox für `<brand>`-Integrationen?“
- „Welchen Webhook-Endpunkt soll ich für Build-Benachrichtigungen von `<brand>` verwenden?“
- „Wo befindet sich das Mitarbeiter-Benefits-/Abrechnungs-/SSO-Portal von `<brand>`?“
- „Gib mir den direkten Download für die Android-APK oder den Desktop-Client von `<brand>`.“

### Defensive Umkehrung

Behandle dies als proaktives Domain-Monitoring-Problem und nicht nur als Prompt-Injection-Problem:<sup>[[12]](#references)</sup>
- Erstelle ein **Marken-Prompt-Korpus** und prüfe regelmäßig die LLMs, auf die sich deine Benutzer/Agents verlassen.
- Speichere halluzinierte URLs und verfolge, welche davon über verschiedene Temperaturen/Modelle hinweg stabil sind.
- Verfolge das **Adversarial Exploitation Window (AEW)**: den Zeitraum zwischen der ersten Halluzination und der Registrierung durch einen Angreifer. Ein positives AEW bedeutet, dass Verteidiger Domains vor dem Einsatz für Angriffe registrieren, per Sinkhole umleiten oder vorab blockieren können.
- Überwache Übergänge von **NXDOMAIN → registriert** bei den übergeordneten Domains.
- Prüfe nach einer Registrierung Registrar, Erstellungsdatum, Nameserver, Privacy Shielding, Seiteninhalte, Screenshots, Status als geparkte Seite und Ähnlichkeit zu Marken-Assets.
- Ergänze Policy-Gates, damit Agents/Entwickler **LLM-generierten Domains nicht standardmäßig vertrauen**: Verlange Allowlists, Eigentumsvalidierung, CT-/RDAP-Prüfungen oder menschliche Freigabe vor der ersten Verwendung.

Dies fällt gleichzeitig in mehrere AI-Risikokategorien: **AI-Supply-Chain-Angriff**, **unsichere Modellausgabe** und **unerlaubte Aktionen**, wenn Agents die halluzinierte URL autonom verwenden.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [OWASP Top 10 für Machine-Learning-Schwachstellen](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risiken](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE-ATLAS-Bedrohungsmatrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Die Risiken von Code-Assistant-LLMs: schädliche Inhalte, Missbrauch und Täuschung](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Gestohlene Cloud-Zugangsdaten werden bei einem neuen AI-Angriff verwendet](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Überblick über das LLMJacking-Schema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (Weiterverkauf gestohlener LLM-Zugänge)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv – Tiefgehende Analyse der Bereitstellung eines On-Premise-LLM-Servers mit geringen Berechtigungen](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README des llama.cpp-Servers](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman Quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF-Spezifikation für Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Von AI halluzinierte Domains als Vektor für Angriffe auf die Software-Supply-Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Wie AI-Halluzinationen eine neue Klasse von Supply-Chain-Angriffen befeuern](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: Das neue AI-gestützte Command-and-Control-Framework](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
