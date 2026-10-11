# Metodologija bezbednosti AI agenata

{{#include ../banners/hacktricks-training.md}}

Procena agenta treba da prati **put od ulaza pod kontrolom napadača do spolja vidljivog efekta**. Jailbreaking, promene karaktera i otkrivanje system prompt-a pokazuju da se na tok rezonovanja može uticati, ali najznačajniji nalaz je lanac koji vodi do pristupa podacima, neovlašćene radnje alata, nizvodnog injection sink-a, postojanosti ili drugog agenta.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) koristan je za označavanje pokrivenosti (preuzimanje kontrole nad ciljem, zloupotreba alata, zloupotreba privilegija, lanac snabdevanja, izvršavanje koda, trovanje memorije, poverenje među agentima, kaskadni kvarovi, poverenje ljudi i rogue agenti). Koristite te oznake tek nakon što utvrdite napadni put od početka do kraja, umesto da neočekivan tekst modela smatrate krajem testa.<sup>[[1]](#references)[[2]](#references)</sup>

## Napravite mapu cilja

Pre nego što napišete payload-e, zabeležite ovih pet dimenzija za svaki tok rada agenta:<sup>[[2]](#references)</sup>

| Dimenzija | Šta popisati | Bezbednosno pitanje |
|---|---|---|
| **Nepoverljivi ulaz** | Parametre za chat/API, URL-ove, dokumente, email, tikete, stavke kalendara, preuzete isečke, memoriju, rezultate alata i poruke agenata-partnera | Gde napadač može da postavi sadržaj koji će kasnije dospeti u kontekst modela? |
| **Alati** | Nazive i šeme alata, sporedne efekte, automatsko izvršavanje, ponašanje pri potvrđivanju i dinamički učitane alate | Koji pozivi čitaju tajne, upisuju stanje, šalju poruke, brišu podatke, izvršavaju kod ili prenose vrednost? |
| **Ovlašćenja** | Delegiranje korisnika, servisne naloge, API tokene, trajanje akreditiva, opseg zakupca/resursa i mrežni doseg | Pod kojim identitetom se izvršava svaki poziv i da li se autorizacija ponavlja na granici alata? |
| **Obrada** | Graditelje upita, shell-ove, URL fetcher-e, template engine-e, interpretere, parser-e, operacije nad datotekama i deserializer-e | Gde podaci koje generiše model postaju sintaksa za drugi interpreter? |
| **Izlaz** | Odgovore, prikazani Markdown/HTML, linkove, preuzimanja slika, webhooks, email, datoteke, logove, izveštaje, metrike i saobraćaj između agenata | Koji vidljivi kanal može da prenese tajnu ili pokrene sekundarni zahtev? |

Nemojte ovo svesti na spisak oglašenih integracija. Koristan artefakt povezuje svaki izvor sa tačnim mestom u kontekstu do kog stiže, alatima koji su tada dostupni, akreditivom koji svaki alat koristi, nizvodnim interpreterom i svim izlaznim rutama. Isti alat može imati mali uticaj uz token za čitanje po korisniku, a kritičan uticaj uz zajednički administratorski akreditiv.<sup>[[2]](#references)</sup>

## Izviđanje

### Mapirajte sve puteve isporuke i prijema podataka

Počnite od površine isporuke (web, mobilna aplikacija, API, email, chat platforma, browser extension) i presretnite saobraćaj klijent–backend. Pregledajte polja skrivena u UI-ju, parametre za pretragu/autodovršavanje/filtriranje, objekte stanja razgovora, poslove za otpremanje i indeksiranje, odgovore alata i saobraćaj podagenata. Za klijente dostupne samo na mobilnim uređajima možda će biti potreban emulator i instrumentacija za zaobilaženje certificate pinning-a pre nego što postane vidljiva stvarna šema zahteva.<sup>[[2]](#references)</sup>

Zatim mapirajte infrastrukturu ispod modela: orchestration framework, sastavljanje prompt-a, skladišta za retrieval i memoriju, runtime (na primer Python, kontejner ili WASM), montirane volumene, host servise, interne API-je, dostupnost cloud metapodataka i susedne mreže. Podrazumevane postavke framework-a su važne jer se neki „tool calls“ izvršavaju generisanjem ili evaluacijom koda; granica runtime-a/sandbox-a određuje da li taj rezultat ostaje izolovan.<sup>[[2]](#references)</sup>

### Utvrdite rutiranje pomoću bezopasnih proba

Uporedite zahtev u opsegu sa nekoliko nepovezanih zahteva, uz očuvanje celog odgovora, statusnog koda, latencije i ponašanja pri streamovanju. Stabilno odbijanje pre bilo kakvog rezonovanja specifičnog za zadatak može ukazivati na zaseban gateway/classifier; odbijanje koje zavisi od konteksta sugeriše da je zahtev stigao do modela; prazan ili isključivo ekstraktivan odgovor može ukazivati na pretragu po ključnim rečima ili usko ograničen retrieval. Tretirajte ovo kao hipoteze i potvrdite ih ponovnim slanjem iste probe kroz alternativna API polja i puteve za prijem podataka.<sup>[[2]](#references)</sup>

Izviđanje je završeno kada procena može da utvrdi najraniji izvor pod kontrolom napadača koji menja ponašanje agenta **i** alate, identitete, interpretere i izlaze dostupne iz tog izvora.<sup>[[2]](#references)</sup>

## Eksploatacija: pređite granicu poverenja

Testirajte kanale, ne samo formulacije prompt-a. Počnite direktnim injection-om da biste utvrdili šta blokira vidljivi ulazni kanal, a zatim ponovite ekvivalentnu nameru kroz manje vidljive puteve navedene u nastavku:<sup>[[2]](#references)</sup>

- **Indirektan sadržaj:** stranice, datoteke, email, tiketi, metapodaci, alt tekst, HTML komentari, tekst van vidljivog dela ekrana ili zero-width karakteri. Pogledajte [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) za tehnike isporuke payload-a.
- **Retrieval i memorija:** zatrovajte sadržaj koji će kasnije biti preuzet ili stanje koje će se ponovo učitati u narednim sesijama. Zabeležite da li brisanje izvornog sadržaja uklanja ponašanje.
- **Izlaz alata i agenti-partneri:** postavite marker u odgovor alata ili poruku između agenata da biste proverili da li interni saobraćaj zaobilazi filtere koji se primenjuju samo na korisnički ulaz i konačni izlaz.
- **Lanac snabdevanja:** pregledajte deskriptore alata, plugin-ove, povezane servere, veštine, modele i zavisnosti kao pouzdane izvore instrukcija. Za testove specifične za MCP pogledajte [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Ljudsko odobrenje:** uporedite stvarni strukturirani poziv alata sa tekstom odobrenja koji je generisao model. Proverite da li uticaj napadača može da izostavi odredište, opseg, obuhvaćene objekte ili nepovratne sporedne efekte.

Prvo upotrebite bezopasan, jedinstven marker. Sačuvajte izvorni artefakt, sastavljeni kontekst ako je vidljiv, izabrani poziv alata, podatke za odobrenje, backend zahtev/odgovor i konačno stanje. Tako ćete razlikovati stvarni uticaj od halucinirane tvrdnje da je neka radnja izvršena.<sup>[[2]](#references)</sup>

## Izvršavanje: dokažite stvarni uticaj

Postoje dva različita puta od uticaja do posledica:<sup>[[2]](#references)</sup>

1. **Zloupotreba mogućnosti:** ovlašćeni alat već obavlja željenu radnju. Primeri uključuju čitanje zapisa jednog zakupca i upisivanje u izveštaj vidljiv napadaču, slanje email-a, menjanje zapisa, brisanje datoteke ili pokretanje uplate. Nije potrebna sekundarna softverska ranjivost.
2. **Eksploatacija nizvodnog sink-a:** izlaz modela usmeren od strane napadača postaje sintaksa za drugu komponentu. Pregledajte upite ka bazama podataka zbog [SQL injection](../pentesting-web/sql-injection/README.md) ili [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrapper-e zbog [command injection](../pentesting-web/command-injection.md), izabrane URL-ove zbog [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operacije nad datotekama zbog traversal-a, evaluatore template-a/koda zbog RCE-a i parser-e objekata zbog [unsafe deserialization](../pentesting-web/deserialization/README.md).

Za svaki kandidat dokažite sledeći lanac:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Integracija samo za čitanje i dalje je podložna eksploataciji ako bilo koja kasnija komponenta može da objavi ono što je pročitala. Testirajte uobičajene odgovore, kao i manje očigledne kanale za izlaz podataka, kao što su veze pod kontrolom napadača, automatsko preuzimanje slika, vebhookovi, logovi, izveštaji, brojači, obaveštenja i poruke drugim agentima.<sup>[[2]](#references)</sup>

## Radnje usmerene na ciljeve

Nakon potvrde jedne radnje, procenite kompletan opseg uticaja umesto da se zaustavite na prvom vidljivom efektu:<sup>[[2]](#references)</sup>

- **Eksfiltracija:** tajne, korisnički zapisi, interne datoteke, podaci iz razgovora ili sadržaj prompta/konteksta izlaze kroz kanal koji se može nadgledati.
- **Neovlašćena radnja:** agent koristi legitimne mogućnosti pisanja u cilju napadača.
- **Uskraćivanje usluge:** destruktivni alati ili ponavljane skupe operacije utiču na integritet ili dostupnost.
- **Trajnost:** zatrovana memorija, indeksirani sadržaj, pouzdano stanje ili izmene tokom izvršavanja opstaju i nakon završetka sesije ili uklanjanja izvora.
- **Širenje:** pouzdani ravnopravni agent obrađuje poruku ili deljeno stanje kompromitovanog agenta i ponavlja radnju koristeći sopstvene alate i akreditive.

Ozbiljnost treba da zavisi od dostupnih podataka, efektivnih privilegija, mogućnosti eksploatacije odredišta, izlaznog saobraćaja, trajnosti i širenja — a ne od toga koliko tekst modela deluje iznenađujuće.<sup>[[2]](#references)</sup>

## Kontrole koje treba proveriti tokom procene

Filteri za promptove i bolji sistemski prompt mogu povećati trošak napada za napadača, ali ih ne treba smatrati granicama autorizacije. Proverite kontrole u nastavku ponovnim pokretanjem istog lanca kroz direktan unos, indirektan sadržaj, memoriju, alate i ravnopravne agente:<sup>[[2]](#references)</sup>

- Deterministički sloj politika proverava autentifikovanog korisnika, zakupca, objekat, radnju i odredište pri **svakom pozivu alata**; model ne može da navede niti izmeni identitet pozivaoca.
- Mogućnosti čitanja i pisanja koriste odvojene akreditive sa najmanjim potrebnim privilegijama i kratkim rokom važenja; alati visokog uticaja izlažu se samo po potrebi i nikada se ne izvršavaju automatski na osnovu učitanog sadržaja.
- Izlazni mrežni saobraćaj i interna odredišta stavljaju se na liste dozvoljenih nezavisno od URL-ova koje izabere model; pristup tokom izvršavanja metapodacima, montiranim tajnama i susednim servisima blokira se osim ako nije neophodan.
- Interfejs za odobravanje generiše se iz kanonskog strukturiranog zahteva i prikazuje tačne argumente, identitet, odredište, obuhvaćene objekte i sporedne efekte — a ne slobodno formulisani sažetak modela.
- Uspeh se potvrđuje u odredišnom sistemu ili sistemu evidencije. Opis agenta, zahtev za poziv alata ili HTTP preusmeravanje ne dokazuju da je navedena promena stanja zaista izvršena.
- Unosi u memoriju i sisteme za pronalaženje zadržavaju poreklo i oznake poverenja, mogu da se ponište, a pri kasnijoj upotrebi za neku radnju ponovo se proverava njihova autorizacija.
- Poruke između agenata autentifikuju se i autorizuju kao nepouzdani zahtevi; reputacija ravnopravnog agenta ili njegova kartica ne dodeljuju implicitno primaocu pravo da koristi svoje alate.

## References

- [1] [OWASP Top 10 za agentske aplikacije za 2026. godinu](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Hakerski vodič za napad na AI agente](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
