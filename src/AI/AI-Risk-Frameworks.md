# Rizici AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 ranjivosti mašinskog učenja

OWASP je identifikovao 10 glavnih ranjivosti mašinskog učenja koje mogu uticati na AI sisteme. Ove ranjivosti mogu dovesti do različitih bezbednosnih problema, uključujući trovanje podataka, inverziju modela i adversarial napade. Razumevanje ovih ranjivosti ključno je za izgradnju bezbednih AI sistema.

Ažuriran i detaljan spisak 10 glavnih ranjivosti mašinskog učenja potražite u projektu [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Napadač unosi sitne, često nevidljive izmene u **ulazne podatke** kako bi naveo model da donese pogrešnu odluku.\
    *Primer*: Nekoliko mrlja boje na znaku STOP navede samovozeći automobil da „vidi“ znak za ograničenje brzine.

- **Data Poisoning Attack**: **Skup za obuku** namerno se zagađuje neispravnim uzorcima, čime se model uči štetnim pravilima.\
*Primer*: Binarne datoteke malware-a pogrešno se označavaju kao „bezopasne“ u korpusu za obuku antivirusnog sistema, pa sličan malware kasnije prolazi neprimećeno.

- **Model Inversion Attack**: Ispitujući izlaze, napadač pravi **obrnuti model** koji rekonstruiše osetljiva svojstva originalnih ulaza.\
*Primer*: Rekonstrukcija pacijentovog MRI snimka na osnovu predviđanja modela za otkrivanje raka.

- **Membership Inference Attack**: Napadač proverava da li je **određeni zapis** korišćen tokom obuke, uočavajući razlike u nivou pouzdanosti.\
*Primer*: Potvrđivanje da se bankarska transakcija neke osobe nalazi u podacima za obuku modela za otkrivanje prevara.

- **Model Theft**: Ponavljano slanje upita omogućava napadaču da nauči granice odlučivanja i **klonira ponašanje modela** (i intelektualnu svojinu).\
*Primer*: Prikupljanje dovoljnog broja parova pitanja i odgovora iz ML-as-a-Service API-ja za izradu gotovo ekvivalentnog lokalnog modela.

- **AI Supply‑Chain Attack**: Kompromitovanje bilo koje komponente (**ML pipeline**) — podataka, biblioteka, prethodno obučenih težina ili CI/CD-a — radi kvarenja nizvodnih modela.\
*Primer*: Zavisnost sa trovanim kodom na model hub-u instalira model za analizu sentimenta sa backdoor-om u mnoge aplikacije.

- **Transfer Learning Attack**: Zlonamerna logika se ubacuje u **prethodno obučeni model** i opstaje nakon fine-tuning-a za zadatak žrtve.\
*Primer*: Skriveni okidač u osnovnom modelu za obradu slika i dalje menja oznake nakon prilagođavanja za medicinsko snimanje.

- **Model Skewing**: Suptilno pristrasni ili pogrešno označeni podaci **menjaju izlaze modela** u korist napadačevih ciljeva.\
*Primer*: Ubacivanje „čistih“ spam poruka označenih kao ham, zbog čega filter za spam propušta slične buduće poruke.

- **Output Integrity Attack**: Napadač **menja predviđanja modela tokom prenosa**, a ne sam model, i tako obmanjuje nizvodne sisteme.\
*Primer*: Promena ocene „zlonamerno“ klasifikatora malware-a u „bezopasno“ pre nego što je sistem za karantin datoteka primi.

- **Model Poisoning** --- Direktne, ciljane izmene samih **parametara modela**, često nakon sticanja pristupa za upis, radi promene njegovog ponašanja.\
*Primer*: Podešavanje težina produkcionog modela za otkrivanje prevara tako da se transakcije sa određenih kartica uvek odobravaju.


## Rizici Google SAIF-a

Googleov [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) opisuje različite rizike povezane sa AI sistemima:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Zlonamerni akteri menjaju ili ubacuju podatke za obuku/fino podešavanje kako bi smanjili tačnost, ugradili backdoor-e ili iskrivili rezultate, narušavajući integritet modela tokom čitavog životnog ciklusa podataka.

- **Unauthorized Training Data**: Korišćenje zaštićenih autorskim pravima, osetljivih ili neodobrenih skupova podataka stvara pravne, etičke i performansne rizike, jer se model uči na podacima za čiju upotrebu nije imao dozvolu.

- **Model Source Tampering**: Manipulacija kodom modela, zavisnostima ili težinama pre obuke ili tokom nje, bilo kroz lanac snabdevanja ili od strane insajdera, može ugraditi skrivenu logiku koja opstaje čak i nakon ponovne obuke.

- **Excessive Data Handling**: Slabe kontrole zadržavanja i upravljanja podacima dovode do toga da sistemi skladište ili obrađuju više ličnih podataka nego što je potrebno, čime se povećavaju izloženost i rizik od neusklađenosti.

- **Model Exfiltration**: Napadači kradu datoteke/težine modela, što dovodi do gubitka intelektualne svojine i omogućava pravljenje kopija usluga ili izvođenje naknadnih napada.

- **Model Deployment Tampering**: Napadači menjaju artefakte modela ili infrastrukturu za njegovo posluživanje, tako da pokrenuti model odstupa od proverene verzije, što može promeniti njegovo ponašanje.

- **Denial of ML Service**: Zatrpavanje API-ja zahtevima ili slanje „sponge“ ulaza može iscrpeti računarske resurse/energiju i oboriti model, slično klasičnim DoS napadima.

- **Model Reverse Engineering**: Prikupljanjem velikog broja parova ulaz-izlaz, napadači mogu klonirati ili destilovati model, čime podstiču proizvode koji ga imitiraju i prilagođene adversarial napade.

- **Insecure Integrated Component**: Ranjivi dodaci, agenti ili uzvodne usluge omogućavaju napadačima da ubace kod ili eskaliraju privilegije unutar AI pipeline-a.

- **Prompt Injection**: Kreiranje prompt-ova, direktno ili indirektno, radi podmetanja instrukcija koje nadjačavaju sistemsku nameru i navode model da izvršava nenameravane komande.

- **Model Evasion**: Pažljivo osmišljeni ulazi navode model da pogrešno klasifikuje, halucinira ili generiše nedozvoljen sadržaj, narušavajući bezbednost i poverenje.

- **Sensitive Data Disclosure**: Model otkriva privatne ili poverljive informacije iz podataka za obuku ili korisničkog konteksta, čime krši privatnost i propise.

- **Inferred Sensitive Data**: Model zaključuje lične osobine koje nikada nisu navedene, stvarajući nove povrede privatnosti zaključivanjem.

- **Insecure Model Output**: Nepročišćeni odgovori prosleđuju korisnicima ili nizvodnim sistemima štetan kod, dezinformacije ili neprimeren sadržaj.

- **Rogue Actions**: Integrisani autonomni agenti izvršavaju nenameravane operacije u stvarnom svetu (upisivanje datoteka, API pozivi, kupovine itd.) bez odgovarajućeg nadzora korisnika.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) pruža sveobuhvatan okvir za razumevanje i ublažavanje rizika povezanih sa AI sistemima. Klasifikuje različite tehnike napada i taktike koje napadači mogu koristiti protiv AI modela, kao i načine na koje se AI sistemi mogu koristiti za izvođenje različitih napada.<sup>[[3]](#references)</sup>

## LLMJacking (krađa tokena i preprodaja pristupa cloud-hosted LLM-ovima)

Napadači kradu aktivne tokene sesije ili cloud API akreditive i neovlašćeno pristupaju plaćenim LLM-ovima hostovanim u cloud-u. Pristup se često preprodaje preko reverse proxy-ja koji posreduju u pristupu nalogu žrtve, npr. kroz „oai-reverse-proxy“ implementacije. Posledice uključuju finansijske gubitke, zloupotrebu modela suprotno pravilima i pripisivanje aktivnosti tenant-u žrtve.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Prikupljanje tokena sa zaraženih računara programera ili iz pregledača; krađa CI/CD tajni; kupovina procurelih kolačića.<sup>[[5]](#references)</sup>
- Postavljanje reverse proxy-ja koji prosleđuje zahteve pravom pružaocu usluge, skriva upstream ključ i opslužuje više korisnika.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Zloupotreba direktnih endpoint-a osnovnog modela radi zaobilaženja enterprise zaštitnih mehanizama i ograničenja brzine.<sup>[[4]](#references)</sup>

Ublažavanje:
- Povežite tokene sa otiskom uređaja, IP opsezima i atestacijom klijenta; nametnite kratko vreme važenja i osvežavajte tokene uz MFA.
- Ograničite ključeve na najmanji potreban opseg (bez pristupa alatima, samo za čitanje gde je primenljivo); rotirajte ih ako se uoči anomalija.
- Usmerite sav saobraćaj na strani servera kroz policy gateway koji sprovodi bezbednosne filtere, kvote po ruti i izolaciju tenant-a.
- Pratite neuobičajene obrasce korišćenja (nagla povećanja troškova, neuobičajene regione, UA stringove) i automatski opozovite sumnjive sesije.
- Dajte prednost mTLS-u ili potpisanim JWT-ovima koje izdaje vaš IdP umesto dugotrajnih statičkih API ključeva.

## Ojačavanje self-hosted LLM inferencije

Pokretanje lokalnog LLM servera za poverljive podatke stvara drugačiju površinu napada od cloud-hosted API-ja: inference/debug endpoint-i mogu da leak-uju prompt-ove, stack za posluživanje obično izlaže reverse proxy, a GPU device node-ovi omogućavaju pristup velikoj površini `ioctl()`. Ako procenjujete ili uvodite on-prem inference uslugu, pregledajte bar sledeće stavke.<sup>[[8]](#references)</sup>

### Curenje prompt-ova preko debug i monitoring endpoint-a

Tretirajte inference API kao **osetljivu uslugu za više korisnika**. Debug ili monitoring rute mogu izložiti sadržaj prompt-ova, stanje slotova, metapodatke modela ili interne informacije o redovima čekanja. U `llama.cpp` endpoint `/slots` je naročito osetljiv jer izlaže stanje pojedinačnih slotova i namenjen je samo njihovom pregledu/upravljanju.<sup>[[8]](#references)</sup>

- Postavite reverse proxy ispred inference servera i **podrazumevano odbijajte pristup**.
- Dodajte na allowlist samo tačne kombinacije HTTP metode i putanje koje su potrebne klijentu/UI-ju.
- Kad god je moguće, onemogućite introspekcione endpoint-e u samom backend-u, na primer `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Vežite reverse proxy za `127.0.0.1` i izložite ga preko autentifikovanog transporta, kao što je SSH local port forwarding, umesto da ga objavite na LAN-u.

Primer allowlist-e uz nginx:

```nginx
map "$request_method:$uri" $llm_whitelist {
    default 0;

    "GET:/health"              1;
    "GET:/v1/models"           1;
    "POST:/v1/completions"     1;
    "POST:/v1/chat/completions" 1;
}

server {
    listen 127.0.0.1:80;

    location / {
        if ($llm_whitelist = 0) { return 403; }
        proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
    }
}
```

### Rootless kontejneri bez mreže i UNIX soketi

Ako inference daemon podržava osluškivanje na UNIX socket-u, dajte prednost tome u odnosu na TCP i pokrenite kontejner bez **mrežnog steka**:<sup>[[8]](#references)</sup>

```bash
podman run --rm -d \
  --network none \
  --user 1000:1000 \
  --userns=keep-id \
  --umask=007 \
  --volume /var/lib/models:/models:ro \
  --volume /srv/llm/socks:/run/llama-cpp \
  ghcr.io/ggml-org/llama.cpp:server-cuda13 \
    --host /run/llama-cpp/llama-cpp.sock \
    --model /models/model.gguf \
    --parallel 4 \
    --no-slots
```

Prednosti:
- `--network none` uklanja izloženost TCP/IP-u za dolazni i odlazni saobraćaj i izbegava pomoćne procese u korisničkom režimu koji bi rootless kontejneri inače morali da koriste.
- UNIX socket omogućava upotrebu POSIX dozvola/ACL-ova na putanji socket-a kao prvog sloja kontrole pristupa.
- `--userns=keep-id` i rootless Podman smanjuju posledice probijanja iz kontejnera jer root u kontejneru nije root na hostu.
- Montiranja modela samo za čitanje smanjuju mogućnost menjanja modela iz kontejnera.

Za trajne instalacije, ista ograničenja mogu se izraziti kao Podman Quadlet jedinice. Ako se pristup GPU-u delegira putem Container Device Interface-a, specifikaciju CDI uređaja svedite na najmanju moguću meru umesto da izložite svaki akceleratorski čvor.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Svođenje GPU čvorova uređaja na najmanju moguću meru

Za zaključivanje zasnovano na GPU-u, datoteke `/dev/nvidia*` predstavljaju visokovredne lokalne površine napada jer izlažu velike `ioctl()` obrađivače upravljačkih programa i potencijalno deljene putanje za upravljanje GPU memorijom.<sup>[[8]](#references)</sup>

- Ne ostavljajte `/dev/nvidia*` sa dozvolom za upis za sve korisnike.
- Ograničite pristup uređajima `nvidia`, `nvidiactl` i `nvidia-uvm` pomoću `NVreg_DeviceFileUID/GID/Mode`, udev pravila i ACL-ova tako da ih može otvoriti samo mapirani UID kontejnera.
- Onemogućite nepotrebne module kao što su `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem` na hostovima za zaključivanje bez grafičkog prikaza.
- Učitajte unapred samo potrebne module pri pokretanju sistema umesto da dozvolite okruženju za izvršavanje da ih po potrebi učitava pomoću `modprobe` tokom pokretanja zaključivanja.

Primer:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Jedna važna stavka za proveru je **`/dev/nvidia-uvm`**. Čak i ako workload ne koristi izričito `cudaMallocManaged()`, noviji CUDA runtime-i možda i dalje zahtevaju `nvidia-uvm`. Pošto se ovaj uređaj deli i upravlja virtuelnom memorijom GPU-a, tretirajte ga kao površinu za izlaganje podataka između zakupaca. Ako ga backend za inference podržava, Vulkan backend može biti zanimljiv kompromis jer može u potpunosti da izbegne izlaganje `nvidia-uvm` kontejneru.<sup>[[8]](#references)</sup>

### LSM ograničavanje inference radnika

AppArmor/SELinux/seccomp treba koristiti kao dodatni sloj zaštite oko inference procesa:<sup>[[8]](#references)</sup>

- Dozvolite samo deljene biblioteke, putanje modela, direktorijum soketa i čvorove GPU uređaja koji su zaista potrebni.
- Izričito zabranite visokorizične privilegije kao što su `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Direktorijum modela držite samo za čitanje, a putanje za upis ograničite samo na direktorijume runtime soketa/keša.
- Pratite logove odbijanja jer pružaju korisnu telemetriju za detekciju kada server modela ili post-exploitation payload pokuša da izađe iz očekivanog ponašanja.

Primer AppArmor pravila za radnika koji koristi GPU:

```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```

## Phantom Squatting: domeni koje halucinira LLM kao vektor napada na AI lanac snabdevanja

Phantom squatting je **ekvivalent slopsquattinga za domen/URL**. Umesto da halucinira nepostojeći naziv paketa, LLM halucinira uverljiv **portal, API, webhook, billing, SSO, download ili support domen** stvarnog brenda, a napadač registruje taj namespace pre nego što ga upotrebi čovek ili agent.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ovo je važno zato što se u mnogim tokovima rada potpomognutim veštačkom inteligencijom izlaz modela tretira kao **pouzdana zavisnost**:
- Programeri ubacuju predloženi endpoint u kod ili CI/CD integracije.
- AI agenti automatski preuzimaju dokumentaciju, šeme, APK-ove, ZIP-ove ili odredišta webhookova.
- Generisani runbookovi ili dokumenti mogu da sadrže lažni URL kao da je merodavan.

### Ofanzivni tok rada

1. **Ispitajte površinu za halucinacije**: postavljajte pitanja specifična za brend o realističnim tokovima rada kao što su portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ili `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizujte kandidate**: razrešite generisane URL-ove, svedite NXDOMAIN odgovore na nadređeni domen koji može da se registruje i uklonite duplikate iz porodica promptova. Korpus promptova treba da bude raznovrstan; na primer, izbacite skoro duplikate pomoću **Jaccard sličnosti**.
3. **Dajte prioritet predvidljivim halucinacijama**:
   - **Thermal Hallucination Persistence (THP)**: isti lažni domen pojavljuje se pri različitim temperaturama, uključujući nisku temperaturu kao što je `T=0.1`.
   - **Konsenzus između modela**: više porodica LLM-ova generiše isti lažni domen.
4. **Registrujte i naoružajte** nadređeni domen, a zatim hostujte phishing sadržaj, lažna preuzimanja APK/ZIP datoteka, alate za krađu kredencijala, zlonamerne dokumente ili API endpointove koji prikupljaju tajne/webhook sadržaje. **Halucinacije koje se odnose samo na nivo domena** najlakše je unovčiti jer napadač kontroliše ceo namespace; halucinacije poddomena/putanja i dalje se mogu zloupotrebiti ako normalizovani nadređeni domen nije registrovan.
5. **Iskoristite period bez reputacije**: novoregistrovanim domenima često nedostaju podaci u blocklistama, URL reputacija i zrela telemetrija, pa mogu da zaobiđu kontrole dok ih sistemi za detekciju ne sustignu. Napadači mogu da produže ovaj period tako što crawlerima prikazuju bezazlene odgovore, koriste prikrivanje redirekcijama, CAPTCHA provere ili odloženo postavljanje payload-a.

### Zašto je opasno za agente

Kod ljudske žrtve lažni domen obično i dalje zahteva klik i još jednu radnju. U **agentnom toku rada**, LLM može biti i **mamac** i **izvršilac**: agent dobija URL koji je halucinirao model, preuzima ga, parsira odgovor i zatim može da oda tokene, izvrši instrukcije, preuzme zavisnost ili unese zatrovane podatke u CI/CD bez ikakve ljudske provere.<sup>[[12]](#references)</sup>

### Praktični promptovi za napadače

Promptovi sa najvećim potencijalom obično liče na uobičajene poslovne zadatke, a ne na eksplicitne phishing mamce:<sup>[[12]](#references)</sup>
- „Koji je URL payment sandboxa za `<brand>` integracije?“
- „Koji webhook endpoint treba da koristim za obaveštenja o `<brand>` buildovima?“
- „Gde se nalazi portal za employee benefits / billing / SSO za `<brand>`?“
- „Daj mi direktan link za preuzimanje Android APK-a ili desktop klijenta za `<brand>`.“

### Odbrambeni pristup

Tretirajte ovo kao proaktivan problem praćenja domena, a ne samo kao problem prompt injectiona:<sup>[[12]](#references)</sup>
- Napravite **korpus promptova za brendove** i povremeno ispitujte LLM-ove na koje se oslanjaju vaši korisnici/agenti.
- Čuvajte URL-ove koje su modeli halucinirali i pratite koji ostaju stabilni pri različitim temperaturama/modelima.
- Pratite **Adversarial Exploitation Window (AEW)**: vreme između prve halucinacije i registracije domena od strane napadača. Pozitivan AEW znači da branioci mogu unapred da registruju domen, preusmere ga na sinkhole ili ga blokiraju pre nego što bude naoružan.
- Pratite promene **NXDOMAIN → registrovan** za nadređene domene.
- Nakon registracije proverite registrara, datum kreiranja, nameservere, zaštitu privatnosti, sadržaj stranice, snimke ekrana, status parkirane stranice i sličnost sa elementima brenda.
- Dodajte kontrolne mehanizme kako agenti/programeri **ne bi podrazumevano verovali domenima koje je generisao LLM**: zahtevajte allowliste, proveru vlasništva, CT/RDAP provere ili ljudsko odobrenje pre prve upotrebe.

Ovo se istovremeno uklapa u nekoliko kategorija AI rizika: **napad na AI lanac snabdevanja**, **nebezbedan izlaz modela** i **neovlašćene radnje** kada agenti samostalno koriste URL koji je model halucinirao.

## References

- [1] [OWASP Top 10 ranjivosti mašinskog učenja](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Rizici](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS matrica pretnji](https://atlas.mitre.org/)
- [4] [Unit 42 – Rizici LLM-ova za pomoć u pisanju koda: štetan sadržaj, zloupotreba i obmana](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: ukradeni kredencijali za cloud upotrebljeni u novom AI napadu](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Pregled šeme LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (preprodaja ukradenog pristupa LLM-ovima)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Detaljna analiza primene lokalnog LLM servera sa niskim privilegijama](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README za llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specifikacija CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domeni koje halucinira AI kao vektor napada na lanac snabdevanja softverom](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: kako halucinacije AI-ja podstiču novu klasu napada na lanac snabdevanja](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
