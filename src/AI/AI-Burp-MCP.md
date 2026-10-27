# Burp MCP: pregled saobraćaja uz pomoć LLM-a

{{#include ../banners/hacktricks-training.md}}

## Pregled

Burp-ovo proširenje **MCP Server** može da izloži presretnuti HTTP(S) saobraćaj MCP-kompatibilnim LLM klijentima, kako bi mogli da **analiziraju stvarne zahteve i odgovore** radi otkrivanja ranjivosti i sastavljanja izveštaja. Burp neka ostane izvor istine: koristite pasivnu analizu ili namerna ponovljena slanja sa promenom samo jedne promenljive, a ne nasumično skeniranje.<sup>[[8]](#references)</sup>

## Arhitektura

- **Burp MCP Server (BApp)** podrazumevano osluškuje na adresi `127.0.0.1:9876` i izlaže presretnuti saobraćaj putem MCP-a.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** povezuje stdio (na strani klijenta) sa Burp-ovom MCP SSE krajnjom tačkom.
- **Opcioni lokalni reverse proxy** (Caddy) normalizuje zaglavlja radi provere strogog MCP rukovanja vezom.
- **Klijenti/pozadinske usluge**: Codex CLI (cloud), Gemini CLI (cloud) ili Ollama (lokalno).

## Podešavanje

### 1) Instalirajte Burp MCP Server

Instalirajte **MCP Server** iz Burp BApp Store-a i proverite da osluškuje na adresi `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Izdvojite proxy JAR

Na kartici MCP Server kliknite na **Extract server proxy jar** i sačuvajte `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Konfigurišite MCP klijenta (primer za Codex)

Usmerite klijenta na proxy JAR i Burp-ovu direktnu SSE krajnju tačku. Uključen proxy je most između stdio-a i SSE-a; ne zamenjuje Burp listener.<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

Ekvivalentna Codex komanda je:<sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

Zatim pokrenite Codex i izlistajte MCP alate:

```bash
codex
# inside Codex: /mcp
```

### 4) Popravite strogu validaciju Origin/zaglavlja pomoću Caddy-ja (ako je potrebno)

Ako MCP rukovanje ne uspe zbog strogih provera `Origin` zaglavlja ili dodatnih zaglavlja, upotrebite lokalni reverse proxy za normalizaciju zaglavlja (ovo odgovara zaobilaznom rešenju za problem stroge validacije Burp MCP-a).<sup>[[1]](#references)[[3]](#references)</sup>

```bash
brew install caddy
mkdir -p ~/burp-mcp
cat >~/burp-mcp/Caddyfile <<'EOF'
:19876

reverse_proxy 127.0.0.1:9876 {
  # lock Host/Origin to the Burp listener
  header_up Host "127.0.0.1:9876"
  header_up Origin "http://127.0.0.1:9876"

  # strip client headers that trigger Burp's 403 during SSE init
  header_up -User-Agent
  header_up -Accept
  header_up -Accept-Encoding
  header_up -Connection
}
EOF
```

Pokrenite proxy i klijent, a podešeni `--sse-url` promenite u `http://127.0.0.1:19876` samo dok koristite ovaj Caddy listener:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Uparite stanje pregledača sa dokazima iz proxy-ja (Playwright MCP)

Podesite Playwright MCP tako da njegov pregledač koristi Burp-ov proxy. To agentu omogućava da poveže prikazano stanje DOM-a/pristupačnosti sa tačnom HTTP istorijom koja ga je proizvela.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Prilagodite adresu listenera, ponovo pokrenite Codex i upotrebite `/mcp` da proverite obe integracije. Primer isključuje greške browser sertifikata kako Burp-ov lokalno generisani sertifikat ne bi blokirao HTTPS presretanje.<sup>[[6]](#references)[[8]](#references)</sup>

## Automatizacija pregledača uz podršku za proxy (OpenBurp)

Burp MCP veza i presretnuti put saobraćaja pregledača predstavljaju odvojene tokove podataka. MCP servis izlaže Burp alate na `127.0.0.1:9876`, dok namenski Chromium šalje HTTP(S) saobraćaj kroz Burp-ov proxy na `127.0.0.1:8080`. Zato zahtevi koje direktno generiše MCP alat možda neće biti prikazani u **Proxy > HTTP history**; koristite pregledač konfigurisan za proxy kada zahtev/odgovor treba da bude vidljiv, izmenjiv ili sačuvan kao dokaz.<sup>[[2]](#references)[[9]](#references)</sup>

Klijent koji podržava SSE može direktno da registruje Burp. Klijent koji podržava samo stdio može umesto toga da pokrene PortSwigger-ov proxy JAR. U oba slučaja registrujte drugi MCP za kontrolu pregledača i usmerite ga na Burp-ov ugrađeni Chromium (`BURP_CHROMIUM` je lokalna putanja do izvršne datoteke):<sup>[[9]](#references)</sup>

```bash
# Claude Code: direct SSE plus a proxied browser
claude mcp add -s project -t sse burpsuite http://127.0.0.1:9876/
claude mcp add -s project -t stdio chrome-devtools -- chrome-devtools-mcp \
  --executablePath "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
  --accept-insecure-certs --isolated

# Codex: SSE-to-stdio bridge plus a proxied browser
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
codex mcp add burp-browser -- npx -y @playwright/mcp@latest \
  --executable-path "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors --isolated
```

TLS-bypass zastavica prihvata sertifikate koje generiše interception proxy, dok `--isolated` sprečava procenu da ponovo koristi uobičajeni profil pregledača operatora. Izolacija štiti stanje profila, ali **nije bezbednosni sandbox**: kontroler i dalje može da pristupi autentifikovanim sesijama otvorenim u tom testnom pregledaču, a Burp MCP može da izloži osetljive zahteve, odgovore i konfiguraciju.<sup>[[9]](#references)</sup>

Nezavisno testirajte SSE listener pre nego što počnete da otklanjate probleme u client bridge-u:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Ispravan listener vraća `Content-Type: text/event-stream`. Timeout nakon zaglavlja je očekivan jer SSE stream ostaje otvoren za buduće događaje. Ako klijent i dalje ne radi, proverite konfigurisanu rutu ekstenzije: PortSwigger napominje da endpoint može biti root path ili `/sse`, u zavisnosti od klijenta i konfiguracije ekstenzije.<sup>[[9]](#references)[[7]](#references)</sup>

## Korišćenje različitih klijenata

### Codex CLI

- Podesite `~/.codex/config.toml` kao što je navedeno iznad.
- Pokrenite `codex`, zatim `/mcp` da biste proverili listu Burp alata.

### Gemini CLI

Repo **burp-mcp-agents** sadrži pomoćne launchere:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (lokalno)

Koristi obezbeđeni pomoćni alat za pokretanje i izaberi lokalni model:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Primeri lokalnih modela i približne potrebe za VRAM-om:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Reprodukcija i validacija zasnovane na dokazima

Ne dozvolite agentu da uverljivo objašnjenje ili međuporuku tretira kao dokaz. Koristite Burp zahteve/odgovore i nezavisno zabeleženo stanje u pregledaču kako bi svaki test mogao da se opovrgne.<sup>[[8]](#references)</sup>

1. Sačuvajte početni par zahteva/odgovora i utvrdite tačnu komponentu koju kontroliše napadač.
2. Pri poređenju autorizacije, nezavisno zabeležite isti tok rada na oba naloga pre menjanja identifikatora, kolačića ili tokena.
3. Pre reprodukcije izmene zabeležite hipotezu, lokaciju dokaza, očekivani signal i rezultat koji bi je opovrgao.
4. Menjajte jednu komponentu odjednom, sačuvajte dobijeni par i odvojeno označite neposredna zapažanja i zaključke.
5. Svaki kandidat označite kao `open`, `blocked`, `rejected` ili `confirmed`; vratite mu se samo ako novi dokazi promene mehanizam ili preduslov.
6. Potvrdite kontrolu napadača, dostupnost, ponovljivost, zaobilaženje ograničenja, uticaj i konačno stanje aplikacije. Preusmerenje ili uspešan poziv alata nisu dokaz ako se navodna promena stanja dešava nizvodno.

Detalje eksploatacije držite na odgovarajućoj stranici tehnike. Na primer, kandidati povezani sa porukama pregledača pripadaju stranici [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), dok ponašanje izbora ključa tokena pripada stranici [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Sažet zapis hipoteze sprečava paralelne agente da ponavljaju istu primamljivu granu:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Trijaža WebSocket frejmova pomoću Burp MCP

Zvanična ekstenzija omogućava `get_proxy_websocket_history_regex` za pretrage Burp WebSocket istorije samo za čitanje, uz paginaciju. Prima `regex`, `count` i `offset`; za razliku od `send_http1_request`, ne šalje WebSocket frejm. Burp beleži poruke u oba smera čak i kada je Intercept isključen, zato filtrirajte istoriju pre nego što modelu prosledite mali skup relevantnih frejmova.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Izvedite istu radnju koja koristi WebSocket kroz pregledač povezan preko Burp proxy-ja, koristeći dva nezavisno autentifikovana testna naloga. Sačuvajte zajedno svaki upgrade handshake i njegove cookies, ID veze, smer frejma i frejmove odgovora; događaj od servera ka klijentu na vezi prvog naloga nije dokaz da ga je primio drugi nalog.
2. Pretražite `get_proxy_websocket_history_regex` uskim izrazom kao što je `(?i)(subscribe|room|tenant|objectId)`, uz `count: 20` i `offset: 0`. Povećavajte `offset` da biste pregledali kasnija poklapanja. Uporedite identifikator objekta ili teme u odlaznom frejmu sa odgovorom na **istoj vezi**.
3. U **Proxy > WebSockets history** pošaljite mogući odlazni frejm u Repeater. Priložite ga odgovarajućoj otvorenoj vezi ili se ponovo povežite koristeći handshake drugog naloga. Promenite samo identifikator objekta/teme i uporedite dobijene serverske poruke i stanje aplikacije sa oba osnovna slučaja. MCP istorijski alat ne može da izvrši ovo ponovno slanje; WebSocket Repeater može da izmeni i ponovo pošalje frejmove, kao i da uspostavi novu vezu.

Za testove specifične za protokol, kao što su cross-site WebSocket hijacking i autorizacija broker tema, pogledajte [WebSocket Attacks](../pentesting-web/websocket-attacks.md). Nemojte smatrati da su prihvaćen upgrade ili echo na strani klijenta dokaz da je zaštićena pretplata uspešno uspostavljena.

## Ciljana out-of-band validacija pomoću Burp MCP

Burp Suite Professional omogućava korišćenje `generate_collaborator_payload` i `get_collaborator_interactions` kroz zvaničnu MCP ekstenziju. Kombinujte ih sa `get_proxy_http_history_regex` i jednim ponovnim slanjem pomoću `send_http1_request` da biste testirali sumnjivo serversko preuzimanje URL-a, bez skeniranja celog cilja. Burp može zahtevati zasebno odobrenje za čitanje istorije i slanje zahteva.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtrirajte istoriju da biste pronašli zahtev koji sadrži mogući URL, na primer zahtev sa `url=`, `webhook` ili `callback`. Sačuvajte originalni zahtev i odgovor. Alat za istoriju prima `regex`, `count` i `offset`; koristite paginaciju umesto da tražite od modela da pregleda svaki unos.<sup>[[10]](#references)</sup>
2. Generišite novi Collaborator payload i sačuvajte vraćeni **ID payload-a**. Ponovo pošaljite zabeleženi zahtev istom hostu i portu, menjajući samo mogući URL u HTTPS URL pod domenom tog payload-a. Za `send_http1_request` prosledite kompletan HTTP/1.1 zahtev kao `content`, uz `targetHostname`, `targetPort` i `usesHttps`; odredišna polja identifikuju **aplikaciju**, a ne Collaborator host.<sup>[[10]](#references)</sup>
3. Proveravajte `get_collaborator_interactions` koristeći taj ID payload-a i uporedite vreme interakcije sa vremenom ponovnog slanja. HTTP interakcija ukazuje na preuzimanje, dok samo DNS pokazuje razrešavanje imena, ali ne i dovršen HTTP zahtev. Proverite izvor interakcije i zaglavlja zahteva da biste razlikovali izlazni saobraćaj servera od učitavanja na strani pregledača, a zatim ponovite test sa novim payload-om da biste isključili nepovezan saobraćaj.<sup>[[10]](#references)[[11]](#references)</sup>

MCP alat za zahteve vraća odgovor direktno i ne mora da ga upiše u **Proxy > HTTP history**. Sačuvajte rezultat zahteva/odgovora ili koristite pregledač povezan preko proxy-ja ili Repeater da biste dobili artefakt iz istorije. Za izbor SSRF payload-a i naredne testove koristite [SSRF chapter](../pentesting-web/ssrf-server-side-request-forgery/), umesto da out-of-band callback smatrate dokazom uticaja na internu mrežu. Za testiranje samog MCP servera pogledajte [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Paket promptova za pasivni pregled

Repozitorijum **burp-mcp-agents** sadrži šablone promptova za analizu Burp saobraćaja zasnovanu na dokazima:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: široko otkrivanje ranjivosti pasivnom analizom.
- `idor_hunter.md`: IDOR/BOLA/odstupanja objekata i tenant-a, kao i neusaglašenosti autentifikacije.
- `auth_flow_mapper.md`: poređenje autentifikovanih i neautentifikovanih putanja.
- `ssrf_redirect_hunter.md`: kandidati za SSRF/open-redirect na osnovu parametara za preuzimanje URL-a i lanaca preusmeravanja.
- `logic_flaw_hunter.md`: logičke greške u više koraka.
- `session_scope_hunter.md`: zloupotreba audience/scope vrednosti tokena.
- `rate_limit_abuse_hunter.md`: propusti u ograničavanju učestalosti/zloupotreba.
- `report_writer.md`: izveštavanje usmereno na dokaze.

## Opcionalno označavanje saobraćaja

Da biste označili Burp/LLM saobraćaj u logovima, dodajte pravilo za prepisivanje zaglavlja (proxy ili Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Bezbednosne napomene

- Dajte prednost **lokalnim modelima** kada saobraćaj sadrži osetljive podatke.
- Za nalaz delite samo minimum potrebnih dokaza.
- Neka Burp bude izvor istine; koristite model za **analizu i izveštavanje**, ne za skeniranje.

## Burp AI Agent (trijaža uz pomoć AI-ja + MCP alati)

**Burp AI Agent** je Burp ekstenzija koja povezuje lokalne/cloud LLM-ove sa pasivnom/aktivnom analizom (62 klase ranjivosti) i izlaže više od 53 MCP alata, kako bi eksterni MCP klijenti mogli da upravljaju Burp-om.<sup>[[5]](#references)</sup> Izdvojene funkcije:

- **Trijaža iz kontekstnog menija**: zabeležite saobraćaj preko Proxy-ja, otvorite **Proxy > HTTP History**, kliknite desnim tasterom na zahtev → **Extensions > Burp AI Agent > Analyze this request** da biste pokrenuli AI čet vezan za taj zahtev/odgovor.
- **Pozadinski sistemi** (mogu da se izaberu za svaki profil):
  - Lokalni HTTP: **Ollama**, **LM Studio**.
  - Udaljeni HTTP: krajnja tačka kompatibilna sa **OpenAI**-jem (osnovni URL + naziv modela).
  - Cloud CLI-jevi: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ili `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (prijava specifična za provajdera).
- **Profili agenta**: šabloni promptova automatski se instaliraju u `~/.burp-ai-agent/AGENTS/`; dodajte dodatne `*.md` fajlove da biste uneli prilagođena ponašanja za analizu/skeniranje.
- **MCP server**: omogućite ga preko **Settings > MCP Server** da biste Burp operacije izložili bilo kom MCP klijentu (više od 53 alata). Claude Desktop može da se poveže sa serverom tako što ćete izmeniti `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ili `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kontrole privatnosti**: STRICT / BALANCED / OFF uklanjaju osetljive podatke iz zahteva pre slanja udaljenim modelima; dajte prednost lokalnim pozadinskim sistemima pri radu sa tajnama.
- **Evidentiranje revizije**: JSONL dnevnici sa SHA-256 heširanjem integriteta za svaki unos, radi praćenja AI/MCP radnji koje otkriva neovlašćene izmene.
- **Izgradnja/učitavanje**: preuzmite JAR izdanje ili ga izgradite pomoću Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Operativni oprez: cloud backend-ovi mogu da eksfiltriraju session cookies/PII ako privacy mode nije omogućen; izlaganje MCP-a omogućava daljinsko upravljanje Burp-om, zato ograničite pristup na pouzdane agente i nadgledajte integrity-hashed audit log.



## References

- [1] [Integracija Burp MCP + Codex CLI i ispravka Caddy handshake-a](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem sa strogom proverom Origin/header-a u PortSwigger MCP serveru](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Kako koristiti Codex za istraživanje Bug Bounty programa: široko istražujte, rigorozno proveravajte](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orkestracija Burp Suite-a za Claude Code i Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implementacije alata PortSwigger MCP Server-a i parametri](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind SSRF ranjivosti](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - Istorija WebSockets-a](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Rad sa WebSocket porukama u Burp Repeater-u](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
