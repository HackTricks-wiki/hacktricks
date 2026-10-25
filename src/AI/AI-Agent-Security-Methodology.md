# Metodologija bezbednosti AI agenata

{{#include ../banners/hacktricks-training.md}}

Procena agenta treba da prati **put od ulaza pod kontrolom napadača do spolja uočljivog efekta**. Jailbreaking, promene karaktera i otkrivanje sistemskog prompta dokazuju da se na kanal rezonovanja može uticati, ali nalaz visokog uticaja jeste lanac koji vodi do pristupa podacima, neovlašćene radnje pomoću alata, nizvodnog mesta za injekciju, perzistencije ili drugog agenta.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) koristan je za označavanje obuhvata (otmica cilja, zloupotreba alata, zloupotreba privilegija, lanac snabdevanja, izvršavanje koda, trovanje memorije, poverenje između agenata, kaskadni otkazi, ljudsko poverenje i rogue agenti). Koristite te oznake nakon što sastavite napadni put od početka do kraja, umesto da neočekivani tekst modela tretirate kao završetak testa.<sup>[[1]](#references)[[2]](#references)</sup>

## Napravite mapu cilja

Pre pisanja payload-a, za svaki tok rada agenta zabeležite ovih pet dimenzija:<sup>[[2]](#references)</sup>

| Dimenzija | Šta popisati | Bezbednosno pitanje |
|---|---|---|
| **Nepoverljiv ulaz** | Parametre za chat/API, URL-ove, dokumente, email, tikete, stavke kalendara, preuzete isečke, memoriju, rezultate alata i poruke agenata-saradnika | Gde napadač može da postavi sadržaj koji će kasnije ući u kontekst modela? |
| **Alati** | Nazive i šeme alata, sporedne efekte, automatsko izvršavanje, ponašanje pri potvrdi i dinamički učitane alate | Koji pozivi čitaju tajne, menjaju stanje, šalju poruke, brišu podatke, izvršavaju kod ili prenose vrednost? |
| **Ovlašćenja** | Delegiranje korisnika, servisne naloge, API tokene, vek trajanja akreditiva, opseg tenant-a/resursa i mrežni domet | U ime kog identiteta se izvršava svaki poziv i da li se autorizacija ponavlja na granici alata? |
| **Obrada** | Graditelje upita, shell-ove, preuzimače URL-ova, template engine-e, interpretere, parsere, operacije nad fajlovima i deserializatore | Gde podaci koje generiše model postaju sintaksa za drugi interpreter? |
| **Izlaz** | Odgovore, renderovani Markdown/HTML, linkove, preuzimanje slika, webhook-ove, email, fajlove, logove, izveštaje, metrike i saobraćaj agenata-saradnika | Koji uočljivi kanal može da prenese tajnu ili pokrene sekundarni zahtev? |

Nemojte ovo svesti na spisak reklamiranih integracija. Koristan artefakt mapira svaki izvor na tačno mesto u kontekstu do kog stiže, alate koji su tada dostupni, akreditive koje svaki alat koristi, nizvodni interpreter i sve izlazne puteve. Isti alat može imati mali uticaj uz token za čitanje po korisniku, a kritičan uz zajednički administratorski akreditiv.<sup>[[2]](#references)</sup>

## Izviđanje

### Mapirajte svaki put isporuke i unosa

Počnite od površine za isporuku (web, mobilna aplikacija, API, email, platforma za chat, ekstenzija pregledača) i presretnite saobraćaj između klijenta i backend-a. Pregledajte polja skrivena u UI-ju, parametre za pretragu/autodovršavanje/filtriranje, objekte stanja razgovora, poslove za otpremanje i indeksiranje, odgovore alata i saobraćaj podagenata. Za mobilne klijente možda će biti potreban emulator i instrumentacija za zaobilaženje certificate pinning-a pre nego što se otkrije stvarna šema zahteva.<sup>[[2]](#references)</sup>

Zatim mapirajte stek ispod modela: orchestration framework, sastavljanje prompta, skladišta za retrieval i memoriju, runtime (na primer Python, container ili WASM), montirane volumene, host servise, interne API-je, dostupnost cloud metadata i susedne mreže. Podrazumevane postavke framework-a su važne jer se neki „pozivi alata“ izvršavaju generisanjem ili evaluacijom koda; granica runtime/sandbox određuje da li rezultat ostaje ograničen.<sup>[[2]](#references)</sup>

### Utvrdite rutiranje nedestruktivnim probama

Uporedite zahtev u opsegu sa nekoliko nepovezanih zahteva, uz očuvanje celog odgovora, statusnog koda, kašnjenja i ponašanja pri stream-ovanju. Stabilno odbijanje pre rezonovanja specifičnog za zadatak može ukazivati na zaseban gateway/classifier; kontekstualno odbijanje sugeriše da je zahtev stigao do modela; prazan ili isključivo ekstraktivan odgovor može ukazivati na pretragu po ključnim rečima ili ograničen retrieval. Tretirajte ovo kao hipoteze i potvrdite ih ponovnim slanjem iste probe kroz alternativna API polja i puteve unosa.<sup>[[2]](#references)</sup>

Izviđanje je završeno kada procena može da navede najraniji izvor pod kontrolom napadača koji menja ponašanje agenta **i** alate, identitete, interpretere i izlaze dostupne iz tog izvora.<sup>[[2]](#references)</sup>

## Eksploatacija: pređite granicu poverenja

Testirajte kanale, ne samo formulacije prompta. Počnite direktnom injekcijom da biste utvrdili šta blokira vidljivi ulazni kanal, a zatim ponovite istu nameru kroz manje vidljive puteve ispod:<sup>[[2]](#references)</sup>

- **Indirektni sadržaj:** stranice, fajlovi, email, tiketi, metapodaci, alt tekst, HTML komentari, tekst van vidljivog dela ekrana ili zero-width karakteri. Pogledajte [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) za tehnike isporuke payload-a.
- **Retrieval i memorija:** zagadite sadržaj koji će kasnije biti preuzet ili stanje koje će se ponovo učitati u narednim sesijama. Zabeležite da li brisanje izvornog sadržaja uklanja ponašanje.
- **Izlaz alata i agenti-saradnici:** postavite marker u odgovor alata ili poruku između agenata da biste proverili da li interni saobraćaj zaobilazi filtere koji se primenjuju samo na korisnički ulaz i konačni izlaz.
- **Lanac snabdevanja:** pregledajte deskriptore alata, dodatke, povezane servere, veštine, modele i zavisnosti kao izvore pouzdanih instrukcija. Za testove specifične za MCP pogledajte [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Ljudsko odobrenje:** uporedite stvarni strukturirani poziv alata sa tekstom odobrenja koji je generisao model. Testirajte da li uticaj napadača može da izostavi odredište, opseg, pogođene objekte ili nepovratne sporedne efekte.

Najpre upotrebite bezopasan, jedinstven marker. Sačuvajte izvorni artefakt, sastavljeni kontekst ako je vidljiv, izabrani poziv alata, podatke o odobrenju, backend zahtev/odgovor i konačno stanje. Tako ćete razlikovati stvarni uticaj od halucinirane tvrdnje da je neka radnja izvršena.<sup>[[2]](#references)</sup>

### Tekst nalik politici u procenjivaču rizika alata

Model-based kapija za alate može da primi tekst pod kontrolom napadača unutar inače korisnog konteksta za klasifikaciju. LangChain-ov eksperimentalni `AutoModeMiddleware`, na primer, prosleđuje predloženi poziv alata, njegove argumente, opcioni opis alata i do 30 nedavnih poruka TypeSafe `is_risky` procenjivaču. Blokira podešene alate kada je vraćena Noul verovatnoća najmanje `0.5`; ovaj middleware ne klasifikuje alate koji nisu na spisku.<sup>[[5]](#references)</sup> TypeSafe takođe upozorava da adversarial tekst u stanju može da utiče na klasifikaciju čak i kada je predviđeno da stanje bude samo podatak.<sup>[[6]](#references)</sup>

**Lažna politika** razlikuje se od pukog predstavljanja kao sistemska poruka. Ona postavlja alternativne oznake ili definicije rizika unutar stanja sa nižim stepenom poverenja i podstiče procenjivač da koristi te definicije umesto kriterijuma koje je definisao developer. U Datadog-ovom testu, korisnik je mogao da menja `profile_description`, koji je prosleđen u argumentima alata zajedno sa `can_edit:false`. Tekst nalik politici tvrdio je da je pokušaj upisa niskorizičan jer bi ga zasebna provera dozvola odbila pre bilo kakve izmene. Tokom 40 pokretanja, prosečna ocena `is_risky` pala je sa `0.893` na `0.290`, dok je direktno poređenje sa lažnim predstavljanjem uloge imalo prosek `0.905`. Pad prosečne vrednosti ispod `0.5` ne dokazuje da je svaki pojedinačni poziv prošao kapiju, a eksperiment **nije** pokazao da je izvršen neovlašćeni upis.<sup>[[7]](#references)</sup>

Pri testiranju ove granice razlikujte odluku klasifikatora od stvarnog rezultata autorizacije alata. Proverite koja polja koja korisnik može da menja stižu do procenjivača, uporedite istu predloženu radnju sa tekstom nalik politici i bez njega i nezavisno proverite konačno stanje. Zasebna provera dozvola i dalje mora da koristi ovlašćenja autentifikovanog podnosioca zahteva, a ne prava servisnog naloga konektora.<sup>[[7]](#references)</sup> Pogledajte [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) za druge načine otkaza klasifikatora; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) odnose se na drugu granicu rutiranja i akreditiva.

### Izolacija konteksta podagenta

Podagent Claude Agent SDK-ja koji nije fork dobija sopstveni `AgentDefinition.prompt`, prompt za delegiranje i dostupne alate, ali ne i sistemski prompt ili razgovor roditeljskog agenta. Ako je `tools` izostavljen iz njegove definicije, nasleđuje alate dostupne podagentima; projektni `CLAUDE.md` se i dalje može učitati. Zbog toga ograničenje prompta postavljeno samo kod roditeljskog agenta nije pouzdana granica kada dete može da koristi iste alate za fajl-sistem ili izvršavanje.<sup>[[4]](#references)</sup>

Testirajte granicu tako što ćete uporediti direktan zahtev koji roditeljski agent odbija sa istim zadatkom delegiranim imenovanom podagentu. NCC Group navodi da je popis fajlova operativnog sistema, koji je bio odbijen, uspeo kada je preformulisan za dete kao bezopasna „mapa rasporeda“.<sup>[[3]](#references)</sup>

Pregledajte stvarne pozive alata deteta i efektivnu listu dozvoljenih alata, a ne samo konačni odgovor roditeljskog agenta; potvrdite da li je dete pristupilo fajlovima kojima roditeljski agent ne bi pristupio.<sup>[[4]](#references)</sup> Ovo je otkaz nasleđivanja zaštitnih ograda, a ne dokaz zaobilaska [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ili izlaska iz container-a.<sup>[[3]](#references)[[4]](#references)</sup>

## Izvršavanje: dokažite stvarni uticaj

Postoje dva različita puta od uticaja do posledica:<sup>[[2]](#references)</sup>

1. **Zloupotreba mogućnosti:** ovlašćeni alat već može da ostvari cilj. Primeri obuhvataju čitanje zapisa jednog tenant-a i upisivanje u izveštaj vidljiv napadaču, slanje email-a, menjanje zapisa, brisanje fajla ili pokretanje plaćanja. Nije potrebna sekundarna softverska ranjivost.
2. **Eksploatacija nizvodnog mesta:** izlazom modela, kojim upravlja napadač, postaje sintaksa za drugu komponentu. Pregledajte upite ka bazi podataka zbog [SQL injection](../pentesting-web/sql-injection/README.md) ili [NoSQL injection](../pentesting-web/nosql-injection.md), shell omotače zbog [command injection](../pentesting-web/command-injection.md), izabrane URL-ove zbog [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operacije nad fajlovima zbog path traversal-a, evaluatore template-a/koda zbog RCE-a i parsere objekata zbog [unsafe deserialization](../pentesting-web/deserialization/README.md).

Za svakog kandidata dokažite ovaj lanac:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Integracija samo za čitanje i dalje može biti iskorišćena ako bilo koja kasnija komponenta može da objavi ono što je pročitala. Testirajte uobičajene odgovore, kao i manje očigledne kanale za izlaz podataka, poput linkova koje kontroliše napadač, automatskog preuzimanja slika, webhookova, logova, izveštaja, brojača, obaveštenja i poruka drugim agentima.<sup>[[2]](#references)</sup>

## Radnje u vezi sa ciljevima

Nakon potvrde jedne radnje, procenite celokupan radijus uticaja umesto da se zaustavite na prvom vidljivom efektu:<sup>[[2]](#references)</sup>

- **Eksfiltracija:** tajne, korisnički zapisi, interne datoteke, podaci iz razgovora ili sadržaj prompta/konteksta izlaze kroz kanal koji se može nadzirati.
- **Neovlašćena radnja:** agent koristi legitimne mogućnosti upisa da bi ostvario cilj napadača.
- **Uskraćivanje usluge:** destruktivni alati ili ponovljene skupe operacije utiču na integritet ili dostupnost.
- **Postojanost:** zatrovana memorija, indeksirani sadržaj, pouzdano stanje ili izmene tokom izvršavanja opstaju nakon završetka sesije ili uklanjanja izvora.
- **Širenje:** pouzdani peer obrađuje poruku ili deljeno stanje kompromitovanog agenta i ponavlja radnju koristeći sopstvene alate i akreditive.

Ozbiljnost treba da zavisi od dostupnih podataka, efektivnih privilegija, mogućnosti iskorišćavanja odredišta, izlaza podataka, postojanosti i širenja — a ne od toga koliko neočekivano zvuči tekst modela.<sup>[[2]](#references)</sup>

## Kontrole koje treba proveriti tokom procene

Filteri za promptove i bolji sistemski prompt mogu povećati trošak napadača, ali ih ne treba smatrati granicama autorizacije. Proverite sledeće kontrole tako što ćete ponovo pokrenuti isti lanac kroz direktni unos, indirektni sadržaj, memoriju, alate i peer agente:<sup>[[2]](#references)</sup>

- Deterministički sloj pravila proverava autentifikovanog korisnika, zakupca, objekat, radnju i odredište pri **svakom pozivu alata**; model ne može da navede niti izmeni identitet pozivaoca.
- Mogućnosti čitanja i upisa koriste odvojene akreditive sa najmanjim potrebnim privilegijama i kratkim rokom važenja; alati visokog uticaja se aktiviraju neposredno pre upotrebe i nikada se ne izvršavaju automatski na osnovu unetog sadržaja.
- Izlazni mrežni saobraćaj i interna odredišta stavljeni su na liste dozvoljenih nezavisno od URL-ova koje odabere model; pristup okruženja za izvršavanje metapodacima, montiranim tajnama i susednim servisima je blokiran, osim ako je neophodan.
- Interfejs za odobravanje generiše se iz kanonskog strukturiranog zahteva i prikazuje tačne argumente, identitet, odredište, pogođene objekte i sporedne efekte — a ne slobodno formiran sažetak modela.
- Uspeh se proverava u odredišnom sistemu ili sistemu evidencije. Opis agenta, zahtev za poziv alata ili HTTP preusmeravanje nisu dokaz da je došlo do navedene promene stanja.
- Unosi u memoriju i sistem za preuzimanje sadržaja čuvaju poreklo i oznake pouzdanosti, mogu da se ponište i ponovo se proverava njihova autorizacija kada se koriste za kasniju radnju.
- Poruke između agenata se autentifikuju i autorizuju kao nepouzdani zahtevi; reputacija peer-a ili njegova agent kartica ne delegiraju implicitno alate primaoca.

Za agent kartice A2A, tokove zadataka i njihovu površinu napada, pogledajte [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 za agentne aplikacije za 2026. godinu](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Hakerski vodič za napad na AI agente](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Koliko je zaista teško izvući AI agenta iz njegovog sandboxa?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Podagenti u SDK-u](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Izvorni kod TypeSafe Auto Mode middleware-a za LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Neujednačenost modela TypeSafe AI Jev: adversarijalni sadržaj](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev kao sudija: kako lažirana pravila usmeravaju Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
