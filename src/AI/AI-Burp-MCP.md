# Burp MCP: pregled saobraćaja uz pomoć LLM-a

{{#include ../banners/hacktricks-training.md}}

## Pregled

Burp-ovo proširenje **MCP Server** može da izloži presretnuti HTTP(S) saobraćaj MCP-kompatibilnim LLM klijentima kako bi mogli da **analiziraju stvarne zahteve/odgovore** radi otkrivanja ranjivosti i sastavljanja izveštaja.<sup>[[8]](#references)</sup> Burp neka ostane izvor istine: koristite pasivnu analizu ili namerna ponovna slanja zahteva uz promenu jedne promenljive, a ne skeniranje naslepo.

## Arhitektura

- **Burp MCP Server (BApp)** podrazumevano osluškuje na `127.0.0.1:9876` i izlaže presretnuti saobraćaj putem MCP-a.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** povezuje stdio (na strani klijenta) sa Burp-ovom MCP SSE krajnjom tačkom.
- **Opcioni lokalni reverse proxy** (Caddy) standardizuje zaglavlja radi provera MCP rukovanja vezom koje striktno proveravaju format.
- **Klijenti/backendi**: Codex CLI (cloud), Gemini CLI (cloud) ili Ollama (lokalno).

## Podešavanje

### 1) Instalirajte Burp MCP Server

Instalirajte **MCP Server** iz Burp BApp Store-a i proverite da osluškuje na `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Izdvojite proxy JAR

Na kartici MCP Server kliknite na **Extract server proxy jar** i sačuvajte `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Konfigurišite MCP klijent (primer za Codex)

Podesite klijenta da koristi proxy JAR i Burp-ovu direktnu SSE krajnju tačku. Upakovani proxy povezuje stdio sa SSE-om; ne zamenjuje Burp listener.<sup>[[7]](#references)</sup>

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

### 4) Popravite strogu validaciju Origin/header zaglavlja pomoću Caddy-ja (ako je potrebno)

Ako MCP handshake ne uspe zbog strogih provera `Origin` zaglavlja ili dodatnih zaglavlja, upotrebite lokalni reverse proxy za normalizaciju zaglavlja (ovo odgovara zaobilaznom rešenju za problem stroge validacije Burp MCP-a).<sup>[[1]](#references)[[3]](#references)</sup>

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

Pokrenite proxy i klijent i promenite podešeni `--sse-url` na `http://127.0.0.1:19876` samo dok koristite ovaj Caddy listener:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Uparite stanje pregledača sa dokazima iz proxy-ja (Playwright MCP)

Registrujte Playwright MCP tako da njegov pregledač koristi Burp-ov proxy. To omogućava agentu da poveže renderovano DOM/stanje pristupačnosti sa tačnom HTTP istorijom koja ga je proizvela.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Prilagodite adresu listener-a, ponovo pokrenite Codex i upotrebite `/mcp` da biste proverili obe integracije. Primer isključuje greške browser-a zbog sertifikata, kako Burp-ov lokalno generisani sertifikat ne bi blokirao HTTPS presretanje.<sup>[[6]](#references)[[8]](#references)</sup>

## Automatizacija browser-a s podrškom za proxy (OpenBurp)

Burp MCP veza i presretnuta putanja browser-a predstavljaju odvojene tokove podataka. MCP servis izlaže Burp alate na `127.0.0.1:9876`, dok namenski Chromium prosleđuje svoj HTTP(S) saobraćaj kroz Burp-ov proxy na `127.0.0.1:8080`. Zato zahtevi koje direktno generiše MCP alat možda neće biti prikazani u **Proxy > HTTP history**; koristite browser preko proxy-ja kada zahtev/odgovor treba da bude vidljiv, izmenljiv ili sačuvan kao dokaz.<sup>[[2]](#references)[[9]](#references)</sup>

Klijent sa podrškom za SSE može direktno da registruje Burp. Klijent koji podržava samo stdio može umesto toga da pokrene PortSwigger-ov proxy JAR. U oba slučaja registrujte drugi MCP za kontrolu browser-a i usmerite ga na Burp-ov ugrađeni Chromium (`BURP_CHROMIUM` je lokalna putanja do izvršne datoteke):<sup>[[9]](#references)</sup>

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

Zastavica TLS-bypass prihvata sertifikate koje je generisao proxy za presretanje, dok `--isolated` sprečava da procena ponovo koristi uobičajeni profil pregledača operatera. Izolacija štiti stanje profila, ali **nije bezbednosni sandbox**: kontroler i dalje može da pristupi autentifikovanim sesijama otvorenim u tom testnom pregledaču, a Burp MCP može da izloži osetljive zahteve, odgovore i konfiguraciju.<sup>[[9]](#references)</sup>

Nezavisno testirajte SSE listener pre otklanjanja problema sa client bridge-om:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Ispravan listener vraća `Content-Type: text/event-stream`. Vremensko ograničenje nakon zaglavlja je očekivano jer SSE stream ostaje otvoren za buduće događaje. Ako klijent i dalje ne radi, proverite konfiguriranu rutu ekstenzije: PortSwigger napominje da endpoint može biti root putanja ili `/sse`, u zavisnosti od klijenta i konfiguracije ekstenzije.<sup>[[9]](#references)[[7]](#references)</sup>

## Korišćenje različitih klijenata

### Codex CLI

- Podesite `~/.codex/config.toml` kao što je navedeno iznad.
- Pokrenite `codex`, a zatim `/mcp` da biste proverili listu Burp alata.

### Gemini CLI

Repo **burp-mcp-agents** pruža pomoćne launchere:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (lokalno)

Koristite priloženi pomoćni program za pokretanje i izaberite lokalni model:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Primeri lokalnih modela i približne potrebe za VRAM-om:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Replay i validacija zasnovani na dokazima

Ne dozvolite agentu da verovatno objašnjenje ili međuporuku tretira kao dokaz. Koristite Burp zahteve/odgovore i nezavisno posmatrano stanje pregledača kako bi svaki test mogao da se opovrgne.<sup>[[8]](#references)</sup>

1. Sačuvajte par osnovnog zahteva/odgovora i utvrdite tačnu komponentu kojom napadač može da upravlja.
2. Za poređenja autorizacije, nezavisno snimite isti tok rada na oba naloga pre menjanja identifikatora, cookies-a ili tokena.
3. Pre ponovnog slanja izmenjenog zahteva zabeležite hipotezu, lokaciju dokaza, očekivani signal i rezultat koji bi je opovrgao.
4. Menjajte jednu komponentu odjednom, sačuvajte nastali par i jasno razdvojite neposredna zapažanja od zaključaka.
5. Pratite svaki kandidat kao `open`, `blocked`, `rejected` ili `confirmed`; razmotrite ga ponovo samo kada novi dokaz promeni mehanizam ili preduslov.
6. Potvrdite kontrolu napadača, dostupnost, ponovljivost, zaobilaženje ograničenja, uticaj i konačno stanje aplikacije. Preusmeravanje ili uspešan poziv alata nije dokaz ako se navodna promena stanja dešava u narednom koraku.

Detalje eksploatacije zadržite na relevantnoj stranici tehnike. Na primer, kandidati vezani za poruke pregledača pripadaju stranici [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), dok ponašanje pri izboru ključa tokena pripada stranici [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Sažet zapis hipoteza sprečava paralelne agente da ponavljaju istu primamljivu granu:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Ciljana out-of-band validacija pomoću Burp MCP-a

Burp Suite Professional izlaže `generate_collaborator_payload` i `get_collaborator_interactions` putem zvaničnog MCP dodatka. Kombinujte ih sa `get_proxy_http_history_regex` i jednim ponovnim slanjem zahteva pomoću `send_http1_request` da biste testirali sumnju na serversko preuzimanje URL-a, bez skeniranja celog cilja. Burp može zahtevati odvojeno odobrenje za čitanje istorije i slanje zahteva.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtrirajte istoriju da biste pronašli zahtev koji sadrži kandidatni URL, na primer onaj koji sadrži `url=`, `webhook` ili `callback`. Sačuvajte originalni zahtev i odgovor. Alat za istoriju prihvata `regex`, `count` i `offset`; koristite paginaciju umesto da tražite od modela da pregleda svaki unos.<sup>[[10]](#references)</sup>
2. Generišite svež Collaborator payload i sačuvajte vraćeni **payload ID**. Ponovo pošaljite snimljeni zahtev istom hostu i portu, menjajući samo kandidatni URL u HTTPS URL pod domenom tog payload-a. Za `send_http1_request` prosledite ceo HTTP/1.1 zahtev kao `content`, uz `targetHostname`, `targetPort` i `usesHttps`; odredišna polja određuju **aplikaciju**, a ne Collaborator host.<sup>[[10]](#references)</sup>
3. Pozovite `get_collaborator_interactions` sa tim payload ID-jem i uporedite vreme interakcije sa ponovnim slanjem zahteva. HTTP interakcija potvrđuje preuzimanje, dok samo DNS pokazuje razrešavanje, ali ne i dovršen HTTP zahtev. Proverite izvor interakcije i zaglavlja zahteva da biste razlikovali serverski izlazni saobraćaj od učitavanja na strani pregledača, a zatim ponovite test sa svežim payload-om da biste isključili nepovezan saobraćaj.<sup>[[10]](#references)[[11]](#references)</sup>

MCP alat za slanje zahteva vraća odgovor direktno i ne mora da ga upiše u **Proxy > HTTP history**. Sačuvajte rezultat zahteva/odgovora koji je vratio arba koristite pregledač podešen preko proxy-ja ili Repeater da biste dobili artefakt sačuvan u istoriji. Za izbor SSRF payload-a i naknadne testove pogledajte [poglavlje o SSRF-u](../pentesting-web/ssrf-server-side-request-forgery/), umesto da out-of-band callback tretirate kao dokaz uticaja na internu mrežu. Za testiranje samog MCP servera pogledajte [testiranje MCP servera](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Paket promptova za pasivni pregled

Repozitorijum **burp-mcp-agents** sadrži predloške promptova za analizu Burp saobraćaja zasnovanu na dokazima:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: široko pasivno otkrivanje ranjivosti.
- `idor_hunter.md`: IDOR/BOLA/odstupanja objekata i tenant-a, kao i nepodudaranja autentifikacije.
- `auth_flow_mapper.md`: poređenje autentifikovanih i neautentifikovanih putanja.
- `ssrf_redirect_hunter.md`: kandidati za SSRF/open redirect na osnovu parametara za preuzimanje URL-a i lanaca preusmeravanja.
- `logic_flaw_hunter.md`: višekoračni logički propusti.
- `session_scope_hunter.md`: zloupotreba audience/scope vrednosti tokena.
- `rate_limit_abuse_hunter.md`: nedostaci u ograničavanju brzine/zloupotrebama.
- `report_writer.md`: izveštavanje usmereno na dokaze.

## Opcionalno označavanje porekla

Da biste označili Burp/LLM saobraćaj u logovima, dodajte pravilo za izmenu zaglavlja (proxy ili Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Bezbednosne napomene

- Dajte prednost **lokalnim modelima** kada saobraćaj sadrži osetljive podatke.
- Delite samo minimum dokaza potrebnih za nalaz.
- Neka Burp ostane izvor istine; koristite model za **analizu i izveštavanje**, a ne za skeniranje.

## Burp AI Agent (trijaža uz pomoć AI-ja + MCP alati)

**Burp AI Agent** je Burp ekstenzija koja povezuje lokalne/cloud LLM-ove sa pasivnom/aktivnom analizom (62 klase ranjivosti) i pruža više od 53 MCP alata kako bi eksterni MCP klijenti mogli da upravljaju Burp-om.<sup>[[5]](#references)</sup> Izdvajamo:

- **Trijaža iz kontekstnog menija**: zabeležite saobraćaj preko Proxy-ja, otvorite **Proxy > HTTP History**, kliknite desnim tasterom miša na zahtev → **Extensions > Burp AI Agent > Analyze this request** da biste pokrenuli AI čet povezan sa tim zahtevom/odgovorom.
- **Pozadinske usluge** (mogu se izabrati za svaki profil):
  - Lokalni HTTP: **Ollama**, **LM Studio**.
  - Udaljeni HTTP: krajnja tačka kompatibilna sa **OpenAI** (osnovni URL + naziv modela).
  - Cloud CLI-jevi: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ili `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (prijava specifična za provajdera).
- **Profili agenta**: šabloni promptova se automatski instaliraju u `~/.burp-ai-agent/AGENTS/`; dodajte dodatne `*.md` datoteke tamo da biste dodali prilagođena ponašanja za analizu/skeniranje.
- **MCP server**: omogućite ga preko **Settings > MCP Server** da biste Burp operacije učinili dostupnim bilo kom MCP klijentu (više od 53 alata). Claude Desktop možete povezati sa serverom uređivanjem datoteke `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ili `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kontrole privatnosti**: STRICT / BALANCED / OFF uklanjaju osetljive podatke iz zahteva pre slanja udaljenim modelima; koristite lokalne pozadinske usluge pri radu sa tajnama.
- **Evidentiranje revizije**: JSONL dnevnici sa SHA-256 heširanjem integriteta za svaki unos, radi praćenja koje omogućava otkrivanje neovlašćenih izmena AI/MCP radnji.
- **Izgradnja/učitavanje**: preuzmite JAR izdanje ili ga izgradite koristeći Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Operativna upozorenja: cloud backend-i mogu da eksfiltriraju session cookies/PII ako nije uključen privacy mode; izlaganje MCP-a omogućava daljinsku orkestraciju Burp-a, zato ograničite pristup na pouzdane agente i nadgledajte audit log sa hash-om integriteta.



## References

- [1] [Burp MCP + Codex CLI integracija i ispravka Caddy handshake-a](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem sa strogom validacijom Origin/header-a u PortSwigger MCP serveru](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (tokovi rada, pokretači, paket promptova)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Kako koristiti Codex za istraživanje Bug Bounty programa: istražujte široko, rigorozno proveravajte](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orkestracija Burp Suite-a za Claude Code i Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implementacije alata i parametri PortSwigger MCP Server-a](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind SSRF ranjivosti](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
