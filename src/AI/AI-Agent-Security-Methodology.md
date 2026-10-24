# Metodologija za bezbednost AI agenata

{{#include ../banners/hacktricks-training.md}}

Procena agenta treba da prati **put od ulaza pod kontrolom napadača do spolja uočljivog efekta**. Jailbreaking, izmene karaktera i otkrivanje sistemskog prompta dokazuju da je moguće uticati na kanal zaključivanja, ali je nalaz visokog uticaja lanac koji vodi do pristupa podacima, neovlašćene radnje alata, nizvodnog injection sinka, postojanosti ili drugog agenta.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) koristan je za označavanje obuhvata (preuzimanje kontrole nad ciljem, zloupotreba alata, zloupotreba privilegija, lanac snabdevanja, izvršavanje koda, trovanje memorije, poverenje među agentima, kaskadni kvarovi, poverenje ljudi i neovlašćeni agenti). Koristite te oznake nakon što sastavite napadni put od početka do kraja, umesto da neočekivani tekst modela tretirate kao završetak testa.<sup>[[1]](#references)[[2]](#references)</sup>

## Napravite mapu cilja

Pre pisanja payload-a zabeležite ovih pet dimenzija za svaki tok rada agenta:<sup>[[2]](#references)</sup>

| Dimenzija | Šta popisati | Bezbednosno pitanje |
|---|---|---|
| **Nepouzdani ulaz** | Parametri za chat/API, URL-ovi, dokumenti, email, tiketi, unosi u kalendar, preuzeti isečci, memorija, rezultati alata i poruke drugih agenata | Gde napadač može da postavi sadržaj koji će kasnije ući u kontekst modela? |
| **Alati** | Nazivi i šeme alata, sporedni efekti, automatsko izvršavanje, ponašanje pri potvrdi i dinamički učitani alati | Koji pozivi čitaju tajne, menjaju stanje, šalju poruke, brišu podatke, izvršavaju kod ili prenose vrednost? |
| **Ovlašćenja** | Delegiranje korisnika, servisni nalozi, API tokeni, trajanje akreditiva, opseg tenant-a/resursa i mrežni doseg | Kao koji identitet se izvršava svaki poziv i da li se autorizacija ponavlja na granici alata? |
| **Obrada** | Graditelji upita, shell-ovi, URL fetcher-i, template engine-i, interpreteri, parser-i, operacije nad datotekama i deserializer-i | Gde podaci koje generiše model postaju sintaksa za drugi interpreter? |
| **Izlaz** | Odgovori, renderovani Markdown/HTML, linkovi, preuzimanje slika, webhook-ovi, email, datoteke, logovi, izveštaji, metrike i saobraćaj između agenata | Koji vidljivi kanal može da prenese tajnu ili pokrene sekundarni zahtev? |

Nemojte ovo svoditi na listu reklamiranih integracija. Koristan artefakt mapira svaki izvor na tačnu poziciju u kontekstu do koje stiže, alate dostupne na toj tački, akreditive koje koristi svaki alat, nizvodni interpreter i sve izlazne kanale. Isti alat može imati mali uticaj uz token za čitanje po korisniku, a kritičan uticaj uz zajednički administratorski akreditiv.<sup>[[2]](#references)</sup>

## Izviđanje

### Mapirajte sve puteve isporuke i unosa

Počnite od površine za isporuku (web, mobilna aplikacija, API, email, chat platforma, browser ekstenzija) i presretnite saobraćaj između klijenta i backend-a. Pregledajte polja skrivena u UI-ju, parametre za pretragu/autocomplete/filter, objekte stanja razgovora, poslove za otpremanje i indeksiranje, odgovore alata i saobraćaj podagenata. Za mobilne klijente možda će biti potreban emulator i instrumentacija za zaobilaženje certificate pinning-a pre nego što postane vidljiva stvarna šema zahteva.<sup>[[2]](#references)</sup>

Zatim mapirajte slojeve ispod modela: framework za orkestraciju, sastavljanje prompta, skladišta za retrieval i memoriju, runtime (na primer Python, container ili WASM), montirane volumene, host servise, interne API-je, dostupnost cloud metadata-e i susedne mreže. Podrazumevane postavke framework-a su važne jer se neki „pozivi alata” ostvaruju generisanjem ili evaluacijom koda; granica runtime-a/sandbox-a određuje da li rezultat ostaje ograničen.<sup>[[2]](#references)</sup>

### Utvrdite rutiranje pomoću bezbednih proba

Uporedite zahtev unutar opsega sa nekoliko nepovezanih zahteva, uz očuvanje celog odgovora, statusnog koda, latencije i ponašanja pri streamingu. Stabilno odbijanje pre bilo kakvog rezonovanja specifičnog za zadatak može ukazivati na zaseban gateway/classifier; kontekstualno odbijanje sugeriše da je zahtev stigao do modela; prazan ili isključivo ekstraktivan odgovor može ukazivati na pretragu po ključnim rečima ili usko ograničen retrieval. Tretirajte ovo kao hipoteze i potvrdite ih ponovnim slanjem iste probe kroz alternativna API polja i putanje unosa.<sup>[[2]](#references)</sup>

Izviđanje je završeno kada procena može da navede najraniji izvor pod kontrolom napadača koji menja ponašanje agenta **i** alate, identitete, interpretere i izlaze do kojih taj izvor može da dođe.<sup>[[2]](#references)</sup>

## Eksploatacija: pređite granicu poverenja

Testirajte kanale, a ne samo formulacije prompta. Počnite direktnim injection-om da biste utvrdili šta blokira vidljivi ulazni kanal, a zatim ponovite ekvivalentnu nameru kroz manje vidljive puteve u nastavku:<sup>[[2]](#references)</sup>

- **Indirektan sadržaj:** stranice, datoteke, email, tiketi, metapodaci, alt tekst, HTML komentari, tekst van vidljivog dela ekrana ili znakovi nulte širine. Tehnike isporuke payload-a potražite u odeljku [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection).
- **Retrieval i memorija:** ubacite zlonameran sadržaj koji će kasnije biti preuzet ili stanje koje će se ponovo učitati u narednim sesijama. Zabeležite da li se ponašanje uklanja brisanjem izvornog sadržaja.
- **Izlaz alata i drugi agenti:** postavite marker u odgovor alata ili poruku između agenata da biste proverili da li interni saobraćaj zaobilazi filtere koji se primenjuju samo na korisnički ulaz i konačni izlaz.
- **Lanac snabdevanja:** pregledajte opise alata, dodatke, povezane servere, veštine, modele i zavisnosti kao pouzdane izvore instrukcija. Za specifične MCP testove pogledajte [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Ljudsko odobrenje:** uporedite stvarni strukturirani poziv alata sa tekstom odobrenja koji je generisao model. Testirajte da li uticaj napadača može da izostavi odredište, opseg, pogođene objekte ili nepovratne sporedne efekte.

Prvo upotrebite bezazlen, jedinstven marker. Sačuvajte izvorni artefakt, sastavljeni kontekst ako je vidljiv, izabrani poziv alata, podatke za odobrenje, backend zahtev/odgovor i konačno stanje. Tako ćete razlikovati uticaj od halucinirane tvrdnje da je neka radnja izvršena.<sup>[[2]](#references)</sup>

### Tekst nalik pravilima u procenjivaču rizika alata

Kapija za alate zasnovana na modelu može da primi tekst pod kontrolom napadača unutar inače korisnog konteksta za klasifikaciju. Na primer, LangChain-ov eksperimentalni `AutoModeMiddleware` prosleđuje predloženi poziv alata, njegove argumente, opcioni opis alata i do 30 nedavnih poruka TypeSafe `is_risky` judge-у. Он блокира конфигурисане алате када је враћена Noul вероватноћа најмање `0.5`; овај middleware не класификује алате који нису наведени.<sup>[[5]](#references)</sup> TypeSafe такође упозорава да противнички текст у стању може да утиче на класификацију, чак и када је стање намењено да представља податке.<sup>[[6]](#references)</sup>

**Лажна политика** се разликује од обичне тврдње да је порука системска. Она у стање нижег нивоа поверења уноси алтернативне ознаке или дефиниције ризика и наводи judge да примени те дефиниције уместо критеријума које је дефинисао developer. У Datadog-овом тесту, корисник је могао да мења `profile_description`, који је копиран у аргументе алата заједно са `can_edit:false`. Текст налик политици тврдио је да је покушај уписа ниског ризика јер би засебна провера дозвола требало да га одбије пре било какве измене. Током 40 покретања, средња вредност `is_risky` пала је са `0.893` на `0.290`, док је поређење са директним лажирањем улоге имало просек `0.905`. Пад средње вредности испод `0.5` не доказује да је сваки појединачни позив прошао капију, а експеримент **није** показао да је дошло до неовлашћеног уписа.<sup>[[7]](#references)</sup>

При тестирању ове границе разликујте пресуду класификатора од стварног резултата ауторизације алата. Проверите која изменљива поља стижу до judge-а, упоредите исту предложену радњу са текстом налик политици и без њега и независно проверите коначно стање. Засебна провера дозвола и даље мора да користи овлашћења аутентификованог подносиоца захтева, а не права сервисног налога конектора.<sup>[[7]](#references)</sup> За друге начине отказа класификатора погледајте [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass); [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) обрађују другу границу рутирања и акредитива.

### Изолација контекста подагента

Подагент Claude Agent SDK који није fork добија сопствени `AgentDefinition.prompt`, prompt за делегирање и доступне алате, али не и родитељски системски prompt или разговор. Ако је `tools` изостављен из његове дефиниције, наслеђује алате доступне подагентима; пројектни `CLAUDE.md` и даље може да се учита. Због тога ограничење prompt-а које важи само за родитеља није поуздана граница ако дете може да користи исте алате за датотечни систем или извршавање.<sup>[[4]](#references)</sup>

Тестирајте границу тако што ћете упоредити директан захтев који родитељ одбија са истим задатком делегираним именованом подагенту. NCC Group наводи да је попис датотека оперативног система, који је одбијен, успео када је детету представљен као безопасна „мапа распореда”.<sup>[[3]](#references)</sup>

Проверите стварне позиве алата детета и ефективну листу дозвољених алата, а не само коначни одговор родитеља; потврдите да ли је дете приступило датотекама којима родитељ не би приступио.<sup>[[4]](#references)</sup> Ово је пропуст у наслеђивању заштитних механизама, а не доказ [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) или бекства из container-а.<sup>[[3]](#references)[[4]](#references)</sup>

## Извршавање: докажите стварни утицај

Постоје два различита пута од утицаја до последица:<sup>[[2]](#references)</sup>

1. **Злоупотреба могућности:** овлашћени алат већ обавља жељену радњу. Примери укључују читање записа једног tenant-а и уписивање у извештај видљив нападачу, слање email-а, измену записа, брисање датотеке или покретање уплате. Није потребан додатни софтверски пропуст.
2. **Експлоатација низводног sink-а:** излаз модела којим управља нападач постаје синтакса за другу компоненту. Проверите упите ка бази података због [SQL injection](../pentesting-web/sql-injection/README.md) или [NoSQL injection](../pentesting-web/nosql-injection.md), shell обавијаче због [command injection](../pentesting-web/command-injection.md), изабране URL-ове због [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), операције над датотекама због traversal-а, template/code евалуаторе због RCE-а и парсере објеката због [unsafe deserialization](../pentesting-web/deserialization/README.md).

За сваки кандидат докажите овај ланац:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Integracija samo za čitanje i dalje je ranjiva ako bilo koja kasnija komponenta može da objavi ono što je pročitala. Testirajte uobičajene odgovore, ali i manje očigledne izlazne kanale, kao što su linkovi pod kontrolom napadača, automatsko preuzimanje slika, webhook-ovi, logovi, izveštaji, brojači, obaveštenja i poruke drugim agentima.<sup>[[2]](#references)</sup>

## Aktivnosti nad ciljevima

Nakon što potvrdite jednu radnju, procenite celokupan opseg posledica umesto da stanete na prvom vidljivom efektu:<sup>[[2]](#references)</sup>

- **Eksfiltracija:** tajne, zapisi o korisnicima, interne datoteke, podaci iz razgovora ili sadržaj prompta/konteksta izlaze kroz kanal koji se može nadzirati.
- **Neovlašćena radnja:** agent koristi legitimne mogućnosti pisanja u cilju napadača.
- **Uskraćivanje usluge:** destruktivni alati ili ponovljene skupe operacije utiču na integritet ili dostupnost.
- **Postojanost:** zatrovana memorija, indeksirani sadržaj, pouzdano stanje ili izmene tokom izvršavanja opstaju nakon završetka sesije koja ih je izazvala ili uklanjanja izvora.
- **Širenje:** pouzdani agent prima poruku ili deljeno stanje kompromitovanog agenta i ponavlja radnju pomoću sopstvenih alata i akreditiva.

Ozbiljnost treba da zavisi od dostupnih podataka, efektivnih privilegija, mogućnosti iskorišćavanja odredišta, izlaznih kanala, postojanosti i širenja — a ne od toga koliko tekst modela deluje iznenađujuće.<sup>[[2]](#references)</sup>

## Kontrole koje treba proveriti tokom procene

Filteri za promptove i bolji sistemski prompt mogu da povećaju trošak za napadača, ali ne treba ih smatrati granicama autorizacije. Proverite kontrole u nastavku tako što ćete ponovo pokrenuti isti lanac kroz direktan unos, indirektan sadržaj, memoriju, alate i agentske kolege:<sup>[[2]](#references)</sup>

- Deterministički sloj politike proverava autentifikovanog korisnika, zakupca, objekat, radnju i odredište pri **svakom pozivu alata**; model ne može da navede niti promeni identitet pozivaoca.
- Mogućnosti čitanja i pisanja koriste zasebne akreditive sa najmanjim potrebnim privilegijama i kratkim rokom važenja; alati visokog uticaja dostupni su samo po potrebi i nikada se ne izvršavaju automatski na osnovu unetog sadržaja.
- Izlazni mrežni saobraćaj i interna odredišta zasebno su na listi dozvoljenih, nezavisno od URL-ova koje odabere model; pristup tokom izvršavanja metapodacima, montiranim tajnama i susednim servisima blokiran je osim ako je neophodan.
- Interfejs za odobravanje generiše se iz kanonskog strukturiranog zahteva i prikazuje tačne argumente, identitet, odredište, pogođene objekte i sporedne efekte — a ne slobodno sastavljen sažetak modela.
- Uspeh se proverava u odredišnom sistemu ili sistemu evidencije. Agentovo objašnjenje, zahtev za poziv alata ili HTTP preusmeravanje nisu dokaz da je navedena promena stanja zaista izvršena.
- Unosi u memoriju i sistem za pronalaženje informacija zadržavaju poreklo i oznake pouzdanosti, mogu se poništiti i ponovo se proverava njihova autorizacija prilikom korišćenja za kasniju radnju.
- Poruke između agenata autentifikuju se i autorizuju kao nepouzdani zahtevi; reputacija drugog agenta ili njegova kartica ne prenosi implicitno alate primaoca.

## References

- [1] [OWASP Top 10 za agentičke aplikacije za 2026. godinu](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Hakerski vodič za napad na AI agente](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Koliko je zaista teško izvući AI agenta iz njegovog sandbox-a?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Podagenti u SDK-u](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Izvorni kod TypeSafe Auto Mode middleware-a za LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Neravnomernost Jev modela TypeSafe AI: adversarijalni sadržaj](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev kao sudija: kako lažna politika usmerava Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
