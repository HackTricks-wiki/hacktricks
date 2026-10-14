# Metodologija bezbednosti AI agenata

{{#include ../banners/hacktricks-training.md}}

Procena agenta treba da prati **put od ulaza pod kontrolom napadača do spolja vidljivog efekta**. Jailbreaking, promene karaktera i otkrivanje system prompta pokazuju da se na kanal rezonovanja može uticati, ali je nalaz velikog uticaja lanac koji vodi do pristupa podacima, neovlašćene radnje alata, nizvodnog injection sinka, postojanosti ili drugog agenta.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) je koristan za označavanje obuhvaćenih oblasti (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust i rogue agents). Koristite te oznake nakon što konstruišete napadni put od početka do kraja, umesto da neočekivani tekst modela tretirate kao kraj testa.<sup>[[1]](#references)[[2]](#references)</sup>

## Napravite mapu cilja

Pre pisanja payload-a zabeležite ovih pet dimenzija za svaki radni tok agenta:<sup>[[2]](#references)</sup>

| Dimenzija | Šta popisati | Bezbednosno pitanje |
|---|---|---|
| **Nepouzdan ulaz** | Chat/API parametre, URL-ove, dokumente, email, tikete, kalendarske unose, preuzete isečke, memoriju, rezultate alata i poruke agentskih kolega | Gde napadač može da postavi sadržaj koji će kasnije ući u kontekst modela? |
| **Alati** | Nazive i šeme alata, sporedne efekte, automatsko izvršavanje, ponašanje pri potvrđivanju i dinamički učitane alate | Koji pozivi čitaju tajne, menjaju stanje, šalju poruke, brišu podatke, izvršavaju kod ili prenose vrednost? |
| **Ovlašćenja** | Delegiranje korisnika, servisne naloge, API tokene, trajanje akreditiva, opseg tenanta/resursa i dostupnost mreže | Kao koji identitet se izvršava svaki poziv i da li se autorizacija ponavlja na granici alata? |
| **Obrada** | Graditelje upita, shell-ove, URL fetchere, template engine-e, interpretere, parser-e, operacije nad fajlovima i deserializatore | Gde podaci koje generiše model postaju sintaksa za drugi interpreter? |
| **Izlaz** | Odgovore, prikazani Markdown/HTML, linkove, preuzimanje slika, webhook-ove, email, fajlove, logove, izveštaje, metrike i saobraćaj agentskih kolega | Koji vidljivi kanal može da prenese tajnu ili pokrene sekundarni zahtev? |

Nemojte ovo svoditi na spisak reklamiranih integracija. Koristan artefakt mapira svaki izvor na tačnu poziciju konteksta do koje dolazi, alate dostupne na toj tački, akreditiv koji koristi svaki alat, nizvodni interpreter i sve izlazne puteve. Isti alat može imati mali uticaj uz token za čitanje po korisniku, a kritičan uticaj uz zajednički administratorski akreditiv.<sup>[[2]](#references)</sup>

## Izviđanje

### Mapirajte svaki put isporuke i unosa

Počnite od površine isporuke (web, mobilna aplikacija, API, email, platforma za chat, browser extension) i presretite saobraćaj između klijenta i backend-a. Pregledajte polja skrivena u UI-ju, parametre pretrage/autodovršavanja/filtriranja, objekte stanja razgovora, zadatke za otpremanje i indeksiranje, odgovore alata i saobraćaj podagenata. Za mobilne klijente može biti potreban emulator i instrumentacija za zaobilaženje certificate pinning-a pre nego što stvarna šema zahteva postane vidljiva.<sup>[[2]](#references)</sup>

Zatim mapirajte stek ispod modela: orchestration framework, sastavljanje prompta, skladišta za retrieval i memoriju, runtime (na primer Python, container ili WASM), montirane volumene, host servise, interne API-je, dostupnost cloud metadata-e i susedne mreže. Podrazumevane postavke framework-a su važne jer se neki „pozivi alata“ izvršavaju generisanjem ili evaluacijom koda; granica runtime-a/sandbox-a određuje da li rezultat ostaje izolovan.<sup>[[2]](#references)</sup>

### Otkrivajte rutiranje nedestruktivnim probama

Uporedite zahtev u opsegu sa nekoliko nepovezanih zahteva, uz očuvanje kompletnog odgovora, statusnog koda, latencije i ponašanja pri strimovanju. Stabilno odbijanje pre bilo kakvog rezonovanja specifičnog za zadatak može ukazivati na zaseban gateway/classifier; odbijanje zavisno od konteksta sugeriše da je zahtev stigao do modela; prazan ili isključivo ekstraktivan odgovor može ukazivati na pretragu po ključnim rečima ili usko ograničen retrieval. Tretirajte ovo kao hipoteze i potvrdite ih ponovnim slanjem iste probe kroz alternativna API polja i putanje unosa.<sup>[[2]](#references)</sup>

Izviđanje je završeno kada procena može da identifikuje najraniji izvor pod kontrolom napadača koji menja ponašanje agenta **i** alate, identitete, interpretere i izlaze dostupne preko tog izvora.<sup>[[2]](#references)</sup>

## Eksploatacija: pređite granicu poverenja

Testirajte kanale, a ne samo formulaciju prompta. Počnite direktnim injection-om da biste utvrdili šta blokira vidljiva ulazna tačka, a zatim ponovite ekvivalentnu nameru kroz manje vidljive puteve navedene u nastavku:<sup>[[2]](#references)</sup>

- **Indirektan sadržaj:** stranice, fajlovi, email, tiketi, metapodaci, alt tekst, HTML komentari, tekst van ekrana ili zero-width karakteri. Tehnike za isporuku payload-a pogledajte u [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection).
- **Retrieval i memorija:** kompromitujte sadržaj koji će kasnije biti preuzet ili stanje koje će se ponovo učitati u budućim sesijama. Zabeležite da li brisanje originalnog izvora uklanja ovo ponašanje.
- **Izlaz alata i agentski kolege:** postavite marker u odgovor alata ili poruku između agenata da biste testirali da li interni saobraćaj zaobilazi filtere primenjene samo na korisnički ulaz i konačni izlaz.
- **Supply chain:** pregledajte opise alata, plugine, povezane servere, veštine, modele i zavisnosti kao izvore pouzdanih instrukcija. Za testove specifične za MCP pogledajte [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Ljudsko odobrenje:** uporedite stvarni strukturirani poziv alata sa tekstom odobrenja koji je generisao model. Testirajte da li uticaj napadača može da izostavi odredište, opseg, pogođene objekte ili nepovratne sporedne efekte.

Prvo upotrebite bezazlen, jedinstven marker. Sačuvajte izvorni artefakt, sastavljeni kontekst ako je vidljiv, izabrani poziv alata, podatke o odobrenju, backend zahtev/odgovor i konačno stanje. Tako ćete razlikovati uticaj od halucinirane tvrdnje da je radnja izvršena.<sup>[[2]](#references)</sup>

### Izolacija konteksta podagenata

Subagent koji nije fork u Claude Agent SDK-u dobija sopstveni `AgentDefinition.prompt`, prompt za delegiranje i dostupne alate, ali ne i system prompt roditelja ili razgovor. Ako se `tools` izostavi iz njegove definicije, nasleđuje alate dostupne podagentima; projektni `CLAUDE.md` se i dalje može učitati. Zbog toga ograničenje prompta koje važi samo za roditelja nije pouzdana granica ako dete može da koristi iste alate za fajl-sistem ili izvršavanje.<sup>[[4]](#references)</sup>

Testirajte granicu poređenjem direktnog zahteva koji roditelj odbija sa istim zadatkom delegiranim imenovanom podagentu. NCC Group izveštava da je odbijeno nabrajanje fajlova operativnog sistema uspelo kada je detetu preformulisano kao bezazlena „mapa rasporeda“.<sup>[[3]](#references)</sup>

Pregledajte stvarne pozive alata deteta i efektivnu listu dozvoljenih alata, a ne samo konačni odgovor roditelja; potvrdite da li je dete pristupilo fajlovima kojima roditelj ne bi pristupio.<sup>[[4]](#references)</sup> Ovo je propust u nasleđivanju zaštitnih ograničenja, a ne dokaz [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ili bekstva iz container-a.<sup>[[3]](#references)[[4]](#references)</sup>

## Izvršavanje: dokažite stvarni uticaj

Postoje dva različita puta od uticaja do posledica:<sup>[[2]](#references)</sup>

1. **Zloupotreba mogućnosti:** ovlašćeni alat već može da izvrši ciljnu radnju. Primeri uključuju čitanje zapisa jednog tenanta i njegovo upisivanje u izveštaj vidljiv napadaču, slanje email-a, menjanje zapisa, brisanje fajla ili pokretanje uplate. Nije potrebna sekundarna softverska ranjivost.
2. **Eksploatacija nizvodnog sinka:** izlaz modela usmeren od strane napadača postaje sintaksa za drugu komponentu. Pregledajte upite baze podataka zbog [SQL injection](../pentesting-web/sql-injection/README.md) ili [NoSQL injection](../pentesting-web/nosql-injection.md), shell omotače zbog [command injection](../pentesting-web/command-injection.md), izabrane URL-ove zbog [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operacije nad fajlovima zbog path traversal-a, evaluatore template-a/koda zbog RCE-a i parser-e objekata zbog [unsafe deserialization](../pentesting-web/deserialization/README.md).

Za svakog kandidata dokažite sledeći lanac:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Integracija samo za čitanje i dalje može biti zloupotrebljena ako bilo koja naredna komponenta može da objavi ono što je pročitala. Testirajte uobičajene odgovore i manje očigledne kanale za iznošenje podataka, kao što su linkovi pod kontrolom napadača, automatsko preuzimanje slika, webhooks, logovi, izveštaji, brojači, obaveštenja i poruke drugim agentima.<sup>[[2]](#references)</sup>

## Radnje nad ciljevima

Nakon potvrde jedne radnje, procenite ceo opseg posledica, umesto da se zaustavite na prvom vidljivom efektu:<sup>[[2]](#references)</sup>

- **Eksfiltracija:** tajne, korisnički zapisi, interne datoteke, podaci iz razgovora ili sadržaj prompta/konteksta napuštaju sistem preko kanala koji se može nadzirati.
- **Neovlašćena radnja:** agent koristi legitimne mogućnosti za pisanje u cilju napadača.
- **Uskraćivanje usluge:** destruktivni alati ili ponovljene skupe operacije utiču na integritet ili dostupnost.
- **Postojanost:** zatrovana memorija, indeksirani sadržaj, pouzdano stanje ili izmene okruženja tokom izvršavanja opstaju nakon završetka sesije ili uklanjanja izvornog sadržaja.
- **Širenje:** pouzdani agent preuzima poruku ili deljeno stanje kompromitovanog agenta i ponavlja radnju koristeći sopstvene alate i akreditive.

Ozbiljnost treba da se procenjuje prema dostupnim podacima, efektivnim privilegijama, mogućnosti iskorišćavanja odredišta, kanalu za iznošenje podataka, postojanosti i širenju — a ne prema tome koliko iznenađujuće deluje tekst modela.<sup>[[2]](#references)</sup>

## Kontrole koje treba proveriti tokom procene

Filteri za promptove i bolji sistemski prompt mogu povećati trošak napadača, ali ne treba ih smatrati granicama za autorizaciju. Proverite kontrole u nastavku tako što ćete ponovo pokrenuti isti lanac preko direktnog unosa, indirektnog sadržaja, memorije, alata i agentskih kolega:<sup>[[2]](#references)</sup>

- Deterministički sloj pravila proverava autentifikovanog korisnika, zakupca, objekat, radnju i odredište pri **svakom pozivu alata**; model ne može da navede ili promeni identitet pozivaoca.
- Mogućnosti čitanja i pisanja koriste odvojene, privilegovane samo u najmanjoj meri, kratkotrajne akreditive; alati visokog uticaja dostupni su samo po potrebi i nikad se ne izvršavaju automatski na osnovu unetog sadržaja.
- Izlazni mrežni saobraćaj i interna odredišta stavljeni su na allowlist nezavisno od URL-ova koje izabere model; pristup metapodacima, montiranim tajnama i susednim servisima iz okruženja tokom izvršavanja je blokiran, osim ako je neophodan.
- Interfejs za odobravanje generiše se iz kanonskog strukturiranog zahteva i prikazuje tačne argumente, identitet, odredište, obuhvaćene objekte i sporedne efekte — ne slobodan sažetak koji je sastavio model.
- Uspeh se proverava u odredišnom sistemu ili sistemu evidencije. Opis agenta, zahtev za poziv alata ili HTTP preusmerenje ne dokazuju da je došlo do navedene promene stanja.
- Unosi u memoriju i sistem za pronalaženje informacija zadržavaju poreklo i oznake poverenja, mogu da se ponište, a njihovo korišćenje za kasniju radnju ponovo se autorizuje.
- Poruke između agenata autentifikuju se i autorizuju kao nepouzdani zahtevi; reputacija agentskog kolege ili agentska kartica ne delegiraju podrazumevano alate primaoca.

## References

- [1] [OWASP Top 10 za Agentic Applications za 2026.](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Hakerski vodič za napade na AI agente](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Koliko je zaista teško izvući AI agenta iz njegovog sandboxa?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Podagenti u SDK-u](https://code.claude.com/docs/en/agent-sdk/subagents)
{{#include ../banners/hacktricks-training.md}}
