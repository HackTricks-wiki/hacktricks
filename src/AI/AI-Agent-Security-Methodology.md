# Metodologija bezbednosti AI agenata

{{#include ../banners/hacktricks-training.md}}

Procena agenta treba da prati **putanju od unosa pod kontrolom napadača do spolja vidljivog efekta**. Jailbreaking, izmene karaktera i otkrivanje system prompta dokazuju da se na kanal rezonovanja može uticati, ali nalaz visokog uticaja jeste lanac koji vodi do pristupa podacima, neovlašćene radnje alata, nizvodnog injection sinka, postojanosti ili drugog agenta.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) korisna je za označavanje pokrivenosti (otimanje cilja, zloupotreba alata, zloupotreba privilegija, lanac snabdevanja, izvršavanje koda, trovanje memorije, poverenje između agenata, kaskadni otkazi, ljudsko poverenje i odbegli agenti). Te oznake koristite nakon što sastavite napadnu putanju od početka do kraja, umesto da neočekivani tekst modela smatrate završetkom testa.<sup>[[1]](#references)[[2]](#references)</sup>

## Napravite mapu cilja

Pre pisanja payload-a, zabeležite ovih pet dimenzija za svaki tok rada agenta:<sup>[[2]](#references)</sup>

| Dimenzija | Šta popisati | Bezbednosno pitanje |
|---|---|---|
| **Nepouzdan unos** | Chat/API parametre, URL-ove, dokumente, e-poštu, tikete, unose kalendara, preuzete odlomke, memoriju, rezultate alata i poruke agenata | Gde napadač može da postavi sadržaj koji će kasnije dospeti u kontekst modela? |
| **Alati** | Nazive i šeme alata, sporedne efekte, automatsko izvršavanje, ponašanje pri potvrdi i dinamički učitane alate | Koji pozivi čitaju tajne, menjaju stanje, šalju poruke, brišu podatke, izvršavaju kod ili prenose vrednost? |
| **Ovlašćenja** | Delegiranje korisnika, servisne naloge, API tokene, trajanje kredencijala, opseg tenanta/resursa i dostupnost mreže | Pod kojim identitetom se izvršava svaki poziv i da li se autorizacija ponavlja na granici alata? |
| **Obrada** | Graditelje upita, shell-ove, URL fetchere, template engine-e, interpretere, parser-e, operacije nad fajlovima i deserijalizatore | Gde podaci koje generiše model postaju sintaksa za drugi interpreter? |
| **Izlaz** | Odgovore, renderovani Markdown/HTML, linkove, preuzimanja slika, webhook-ove, e-poštu, fajlove, logove, izveštaje, metrike i saobraćaj između agenata | Koji vidljiv kanal može da prenese tajnu ili pokrene sekundarni zahtev? |

Nemojte ovo svesti na spisak oglašenih integracija. Koristan dokument mapira svaki izvor na tačno mesto u kontekstu do kog stiže, alate dostupne u tom trenutku, kredencijal koji svaki alat koristi, nizvodni interpreter i svaku putanju za izlaz podataka. Isti alat može imati mali uticaj uz korisnički read token, a kritičan uticaj uz zajednički administratorski kredencijal.<sup>[[2]](#references)</sup>

## Izviđanje

### Mapirajte sve putanje za dostavu i unos podataka

Počnite od površine za dostavu (web, mobilna aplikacija, API, e-pošta, chat platforma, browser ekstenzija) i presretnite saobraćaj između klijenta i backend-a. Pregledajte polja koja UI skriva, parametre za pretragu/autocomplete/filter, objekte stanja razgovora, poslove za otpremanje i indeksiranje, odgovore alata i saobraćaj podagenata. Za klijente dostupne samo na mobilnom uređaju možda će biti potreban emulator i instrumentacija za zaobilaženje certificate pinning-a pre nego što šema stvarnog zahteva postane vidljiva.<sup>[[2]](#references)</sup>

Zatim mapirajte slojeve ispod modela: framework za orkestraciju, sastavljanje prompta, skladišta za retrieval i memoriju, runtime (na primer Python, container ili WASM), montirane volumene, host servise, interne API-je, dostupnost cloud metapodataka i susedne mreže. Podrazumevane postavke framework-a su važne jer se neki „pozivi alata“ izvršavaju generisanjem ili evaluacijom koda; granica runtime-a/sandbox-a određuje da li rezultat ostaje izolovan.<sup>[[2]](#references)</sup>

### Utvrdite rutiranje bezdestruktivnim probama

Uporedite zahtev u opsegu procene sa nekoliko nepovezanih zahteva, uz očuvanje celog odgovora, statusnog koda, kašnjenja i ponašanja streaming-a. Stabilno odbijanje pre bilo kakvog rezonovanja vezanog za konkretan zadatak može ukazivati na zaseban gateway/classifier; kontekstualno odbijanje sugeriše da je zahtev stigao do modela; prazan ili isključivo ekstraktivan odgovor može ukazivati na pretragu po ključnim rečima ili ograničen retrieval. Tretirajte ovo kao hipoteze i proverite ih ponovnim slanjem iste probe kroz alternativna API polja i putanje za unos podataka.<sup>[[2]](#references)</sup>

Izviđanje je završeno kada procena može da imenuje najraniji izvor pod kontrolom napadača koji menja ponašanje agenta **i** alate, identitete, interpretere i izlaze dostupne iz tog izvora.<sup>[[2]](#references)</sup>

## Eksploatacija: pređite granicu poverenja

Testirajte kanale, ne samo formulacije prompta. Počnite direktnim injection-om da biste utvrdili šta blokira vidljivi ulazni kanal, a zatim ponovite ekvivalentnu nameru kroz manje vidljive putanje u nastavku:<sup>[[2]](#references)</sup>

- **Indirektan sadržaj:** stranice, fajlovi, e-pošta, tiketi, metapodaci, alt tekst, HTML komentari, tekst van vidljivog dela ekrana ili zero-width karakteri. Tehnike za dostavljanje payload-a pogledajte u odeljku [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection).
- **Retrieval i memorija:** ubacite zlonameran sadržaj koji će kasnije biti preuzet ili stanje koje će se ponovo učitati u narednim sesijama. Zabeležite da li se ponašanje menja kada se obriše izvorni sadržaj.
- **Izlaz alata i drugi agenti:** postavite marker u odgovor alata ili poruku između agenata da biste proverili da li interni saobraćaj zaobilazi filtere koji se primenjuju samo na korisnički unos i konačni izlaz.
- **Lanac snabdevanja:** tretirajte opise alata, dodatke, povezane servere, veštine, modele i zavisnosti kao pouzdane izvore instrukcija. Za specifične MCP testove pogledajte [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Ljudsko odobrenje:** uporedite stvarni strukturirani poziv alata sa tekstom odobrenja koji je generisao model. Proverite da li uticaj napadača može da izostavi odredište, opseg, pogođene objekte ili nepovratne sporedne efekte.

Prvo koristite bezopasan, jedinstven marker. Sačuvajte izvorni artefakt, sastavljeni kontekst ako je vidljiv, izabrani poziv alata, podatke o odobrenju, backend zahtev/odgovor i konačno stanje. Tako ćete razlikovati stvarni uticaj od halucinirane tvrdnje da je radnja izvršena.<sup>[[2]](#references)</sup>

### Tekst koji liči na pravila u procenjivaču rizika alata

Kapija za alate zasnovana na modelu može da primi tekst pod kontrolom napadača unutar inače korisnog klasifikacionog konteksta. Na primer, LangChain-ov eksperimentalni `AutoModeMiddleware` šalje predloženi poziv alata, njegove argumente, opcioni opis alata i do 30 nedavnih poruka TypeSafe `is_risky` procenjivaču. Blokira podešene alate kada je vraćena Noul verovatnoća najmanje `0.5`; ovaj middleware ne klasifikuje alate koji nisu na listi.<sup>[[5]](#references)</sup> TypeSafe takođe upozorava da adversarial tekst u stanju može uticati na klasifikaciju čak i kada je predviđeno da stanje bude samo podatak.<sup>[[6]](#references)</sup>

**Lažna pravila** razlikuju se od pukog predstavljanja kao system poruke. Ona postavljaju alternativne oznake ili definicije rizika u stanje nižeg nivoa poverenja i navode procenjivača da koristi te definicije umesto kriterijuma koje je definisao developer. U Datadog-ovom testu, korisnički izmenljiv `profile_description` kopiran je u argumente alata zajedno sa `can_edit:false`. Tekst nalik pravilima tvrdio je da je pokušaj upisa niskog rizika jer bi zasebna provera dozvola trebalo da ga odbije pre bilo kakve izmene. Tokom 40 pokretanja, prosečna vrednost `is_risky` pala je sa `0.893` na `0.290`, dok je direktno poređenje sa lažiranjem uloge imalo prosek `0.905`. To što je prosek pao ispod `0.5` ne dokazuje da je svaki pojedinačni poziv prošao kapiju, a eksperiment **nije** pokazao da je izvršen neovlašćen upis.<sup>[[7]](#references)</sup>

Pri testiranju ove granice razlikujte odluku klasifikatora od stvarnog rezultata autorizacije alata. Proverite koja izmenljiva polja stižu do procenjivača, uporedite istu predloženu radnju sa tekstom nalik pravilima i bez njega, pa nezavisno proverite konačno stanje. Zasebna provera dozvola i dalje mora da koristi ovlašćenja autentifikovanog podnosioca zahteva, a ne prava servisnog naloga konektora.<sup>[[7]](#references)</sup> Druge načine otkaza klasifikatora pogledajte u odeljku [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass); [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) odnose se na drugu granicu rutiranja i kredencijala.

### Izolacija konteksta podagenata

Podagent koji nije fork u Claude Agent SDK-u dobija sopstveni `AgentDefinition.prompt`, prompt za delegiranje i dostupne alate, ali ne i system prompt ili razgovor roditeljskog agenta. Ako se `tools` izostavi iz njegove definicije, nasleđuje alate dostupne podagentima; projektni `CLAUDE.md` i dalje može da se učita. Zbog toga ograničenje prompta koje postoji samo kod roditelja nije pouzdana granica kada dete može da koristi iste alate za fajl sistem ili izvršavanje.<sup>[[4]](#references)</sup>

Testirajte granicu tako što ćete uporediti direktan zahtev koji roditelj odbija sa istim zadatkom delegiranim imenovanom podagentu. NCC Group izveštava da je enumeracija fajlova operativnog sistema, koju je roditelj odbio, uspela kada je za dete preformulisana kao bezopasna „mapa rasporeda“.<sup>[[3]](#references)</sup>

Pregledajte stvarne pozive alata deteta i efektivnu listu dozvoljenih alata, a ne samo konačan odgovor roditelja; potvrdite da li je dete pristupilo fajlovima kojima roditelj ne bi pristupio.<sup>[[4]](#references)</sup> Ovo je otkaz nasleđivanja zaštitnih mera, a ne dokaz za [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ili bekstvo iz containera.<sup>[[3]](#references)[[4]](#references)</sup>

### Mobilni GUI agenti: instrukcije na ekranu i ponovno vezivanje radnje

Mobilni GUI agent može da pošalje svaki snimak ekrana cloud modelu pre nego što izabere sledeću radnju u drugoj aplikaciji. Da biste testirali **indirektan visual injection**, postavite tekst pod kontrolom napadača u SMS, e-poštu ili stranicu koju će agent pregledati tokom ovlašćenog zadatka. Uporedite direktan prompt zadatka sa istom instrukcijom vidljivom samo na snimku ekrana, pa pregledajte sledeću radnju i odluku o operaciji visokog rizika. U procenjenom asistentu, klijentski `checkPrompt` proveravao je direktan tekst zadatka, ali nije primenjivao ekvivalentno filtriranje na sadržaj snimka ekrana. Ovo je mobilna, cross-app varijanta [agentic-browser screenshot injection](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md), a ne način za zaobilaženje Android autentifikacije komponenti.<sup>[[9]](#references)</sup>

Ilustrativni test sporednog efekta koristi formu pod kontrolom napadača koja traži od agenta da popuni osetljiva polja, a zatim traži od čoveka da klikne na „upload“, dok stranica šalje popunjena polja čim se promene. Predaja čoveku ne može da zaštiti podatke koje je JavaScript stranice već poslao; proverite stvarno slanje umesto da agentovo objašnjenje smatrate dokazom. Izvor ovo predstavlja kao mogući obrazac, a ne kao demonstriran kompromis svakog asistenta.<sup>[[9]](#references)</sup>

**GUI TOCTOU / ponovno vezivanje radnje** predstavlja zaseban način otkaza: agent planira unos na osnovu ekrana viđenog u trenutku `t0`, ali se UI u prvom planu promeni pre nego što se unos izvrši u trenutku `t1`.<sup>[[8]](#references)</sup> Kasniji snimak ekrana u trenutku `t2` ne može da poništi već izvršenu radnju.<sup>[[9]](#references)</sup> U ovlašćenom Android testu, ponovljiv tok rada je:<sup>[[8]](#references)</sup>

1. Profilirajte koordinate kontrole na ciljnom ekranu i prikažite bezopasnu kontrolu na istom mestu u kontrolisanoj aplikaciji.
2. Ostavite taj nosač vidljivim dok ga agent ne uoči, pa tokom razmaka između posmatranja i radnje pokrenite uobičajenu promenu aplikacije u prvom planu.
3. Proverite da li planirani dodir aktivira kontrolu u novoj aplikaciji i potvrdite nastalo stanje u ciljnoj aplikaciji, umesto da se oslanjate na agentovo objašnjenje.

Izvorna studija o ponovnom vezivanju radnji to demonstrira aplikacijom bez opasnih dozvola; opisuje i ponavljanje promene kroz petlju za oporavak zadatka agenta u višekoračnim tokovima.<sup>[[8]](#references)</sup>

**Nemojte** pretpostaviti da će primitiv raditi neizmenjen protiv svakog asistenta. U proceni Doubao-a, `OpClickUI` je preskakao klikove ako bi se promenila aplikacija Activity najvišeg nivoa i upoređivao je snimke ekrana kada se `OpOpenApp` pojavio među prethodna tri koraka. Zato su pojedinačni dodiri, dugi pritisci i dvostruki dodiri pružali malo pouzdanih mogućnosti za tajming pod kontrolom napadača. `OpTypeText`, `OpSwipeUI` i `OpScrollWheelAction` nisu imali ekvivalentne zaštite, ali je izveštaj ocenio da je njihov praktični uticaj ograničeniji.<sup>[[9]](#references)</sup>

## Izvršavanje: dokažite stvarni uticaj

Postoje dve različite putanje od uticaja do posledica:<sup>[[2]](#references)</sup>

1. **Zloupotreba sposobnosti:** ovlašćeni alat već izvršava željeni cilj. Primeri uključuju čitanje zapisa jednog tenanta i upisivanje u izveštaj vidljiv napadaču, slanje e-pošte, menjanje zapisa, brisanje fajla ili pokretanje plaćanja. Nije potrebna dodatna softverska ranjivost.
2. **Eksploatacija nizvodnog sinka:** izlaz modela usmeren od strane napadača postaje sintaksa za drugu komponentu. Pregledajte upite ka bazi podataka zbog [SQL injection](../pentesting-web/sql-injection/README.md) ili [NoSQL injection](../pentesting-web/nosql-injection.md), shell omotače zbog [command injection](../pentesting-web/command-injection.md), izabrane URL-ove zbog [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operacije nad fajlovima zbog path traversal-a, template/code evaluatore zbog RCE-a i parser-e objekata zbog [unsafe deserialization](../pentesting-web/deserialization/README.md).

Za svakog kandidata dokažite sledeći lanac:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Integracija samo za čitanje i dalje može da se iskoristi ako bilo koja kasnija komponenta može da objavi ono što je pročitala. Testirajte uobičajene odgovore i manje očigledne izlazne kanale, kao što su linkovi pod kontrolom napadača, automatsko preuzimanje slika, webhooks, logs, reports, counters, notifications i poruke drugim agentima.<sup>[[2]](#references)</sup>

## Akcije usmerene ka ciljevima

Nakon što potvrdite jednu akciju, procenite celokupan opseg posledica, umesto da stanete na prvom vidljivom efektu:<sup>[[2]](#references)</sup>

- **Eksfiltracija:** tajne, korisnički zapisi, interne datoteke, podaci iz razgovora ili sadržaj prompta/konteksta odlaze kroz kanal koji se može nadzirati.
- **Neovlašćena akcija:** agent koristi legitimne write capabilities u cilju napadača.
- **Uskraćivanje usluge:** destruktivni alati ili ponovljene skupe operacije utiču na integritet ili dostupnost.
- **Postojanost:** zatrovana memorija, indeksirani sadržaj, pouzdano stanje ili izmene u runtime okruženju opstaju nakon završetka sesije ili uklanjanja izvora.
- **Širenje:** pouzdan peer konzumira poruku ili deljeno stanje kompromitovanog agenta i ponavlja akciju koristeći sopstvene alate i akreditive.

Ozbiljnost treba da zavisi od dostupnih podataka, efektivnih privilegija, mogućnosti iskorišćavanja odredišta, izlaznih kanala, postojanosti i širenja — a ne od toga koliko tekst modela deluje iznenađujuće.<sup>[[2]](#references)</sup>

## Kontrole koje treba proveriti tokom procene

Prompt filteri i bolji system prompt mogu povećati trošak napadača, ali ne treba ih smatrati granicama autorizacije. Proverite kontrole u nastavku tako što ćete ponovo pokrenuti isti lanac kroz direktni unos, indirektni sadržaj, memoriju, alate i peer agente:<sup>[[2]](#references)</sup>

- Deterministički policy layer proverava autentifikovanog korisnika, tenant, objekat, akciju i odredište pri **svakom pozivu alata**; model ne može da navede niti izmeni identitet pozivaoca.
- Read i write capabilities koriste odvojene, minimalno privilegovane akreditive sa kratkim rokom važenja; alati visokog uticaja omogućavaju se just in time i nikada se ne izvršavaju automatski na osnovu unetog sadržaja.
- Izlazni mrežni saobraćaj i interna odredišta stavljaju se na allowlist nezavisno od URL-ova koje izabere model; pristup runtime okruženja endpointima metapodataka, montiranim tajnama i susednim servisima blokira se osim kada je neophodan.
- Approval UI se generiše iz kanoničkog strukturisanog zahteva i prikazuje tačne argumente, identitet, odredište, pogođene objekte i sporedne efekte — a ne slobodno formulisani sažetak modela.
- Uspeh se proverava u odredišnom sistemu ili sistemu evidencije. Naracija agenta, zahtev za poziv alata ili HTTP redirect nisu dokaz navodne promene stanja.
- Unosi u memoriji i sistemu za pronalaženje zadržavaju poreklo i oznake poverenja, mogu se poništiti, a njihova upotreba za kasniju akciju ponovo se autorizuje.
- Poruke između agenata autentifikuju se i autorizuju kao nepouzdani zahtevi; reputacija peer-a ili agent card ne delegira podrazumevano alate primaoca.

Za agent cards protokola A2A, tokove zadataka i njihovu površinu napada, pogledajte [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 za Agentic Applications za 2026.](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Hakerov vodič za napad na AI agente](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Koliko je zaista teško izvući AI agenta iz njegovog sandboxa?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagenti u SDK-u](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Izvorni kod TypeSafe Auto Mode middleware-a za LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Jev model jaggedness kompanije TypeSafe AI: adversarial sadržaj](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev kao sudija: kako lažna politika usmerava Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Manipulacija bez dozvola: možemo li verovati GUI agentima koje pokreću veliki multimodalni modeli?](https://arxiv.org/html/2601.12349v1)
- [9] [Kada AI asistent postane deo lanca napada hakera | Bezbednosna analiza Doubao Phone](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
