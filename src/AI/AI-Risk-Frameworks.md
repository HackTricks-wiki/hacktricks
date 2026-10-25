# Rizici AI-ja

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 ranjivosti mašinskog učenja

OWASP je utvrdio 10 najvažnijih ranjivosti mašinskog učenja koje mogu uticati na AI sisteme. Ove ranjivosti mogu dovesti do različitih bezbednosnih problema, uključujući trovanje podataka, inverziju modela i adversarijalne napade. Razumevanje ovih ranjivosti ključno je za izradu bezbednih AI sistema.

Ažuriran i detaljan spisak 10 najvažnijih ranjivosti mašinskog učenja potražite u projektu [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Napadač unosi sitne, često nevidljive izmene u **ulazne podatke**, zbog kojih model donosi pogrešnu odluku.\
    *Primer*: Nekoliko mrlja boje na znaku stop navede samovozeći automobil da ga „vidi” kao znak ograničenja brzine.

- **Data Poisoning Attack**: **Skup za obuku** namerno se zagađuje lošim uzorcima, čime se model uči štetnim pravilima.\
*Primer*: Binarne datoteke zlonamernog softvera pogrešno se označavaju kao „bezopasne” u skupu za obuku antivirusnog softvera, pa sličan zlonamerni softver kasnije prolazi neprimećeno.

- **Model Inversion Attack**: Ispitujući izlaze, napadač gradi **obrnuti model** koji rekonstruiše osetljive karakteristike originalnih ulaza.\
*Primer*: Rekonstrukcija pacijentovog MRI snimka na osnovu predviđanja modela za otkrivanje raka.

- **Membership Inference Attack**: Napadač proverava da li je **određeni zapis** korišćen tokom obuke tako što uočava razlike u pouzdanosti modela.\
*Primer*: Potvrđivanje da se transakcija neke osobe nalazi u podacima za obuku modela za otkrivanje prevara.

- **Model Theft**: Ponavljanim slanjem upita napadač može da nauči granice odlučivanja i **klonira ponašanje modela** (i intelektualnu svojinu).\
*Primer*: Prikupljanje dovoljnog broja parova pitanja i odgovora iz ML-as-a-Service API-ja radi izrade gotovo istovetnog lokalnog modela.

- **AI Supply‑Chain Attack**: Kompromitovanje bilo koje komponente (**ML pipeline-a**) — podataka, biblioteka, unapred obučenih težina ili CI/CD-a — radi oštećivanja nizvodnih modela.\
*Primer*: Zavisnost zatrovana na platformi za modele instalira model za analizu sentimenta sa backdoor-om u brojne aplikacije.

- **Transfer Learning Attack**: Zlonamerna logika ugrađuje se u **unapred obučeni model** i opstaje nakon njegovog finog podešavanja za zadatak žrtve.\
*Primer*: Skriveni okidač u vizuelnom backbone modelu i dalje menja oznake nakon prilagođavanja za medicinsko snimanje.

- **Model Skewing**: Suptilno pristrasni ili pogrešno označeni podaci **usmeravaju izlaze modela** u korist napadačevih ciljeva.\
*Primer*: Ubacivanje „čistih” neželjenih poruka označenih kao ham, tako da filter za spam propušta slične buduće poruke.

- **Output Integrity Attack**: Napadač **menja predviđanja modela tokom prenosa**, a ne sam model, obmanjujući nizvodne sisteme.\
*Primer*: Promena presude klasifikatora zlonamernog softvera iz „zlonameran” u „bezopasan” pre nego što je vidi sistem za stavljanje datoteka u karantin.

- **Model Poisoning** --- Direktne, ciljane izmene samih **parametara modela**, često nakon sticanja pristupa za upisivanje, kojima se menja njegovo ponašanje.\
*Primer*: Podešavanje težina produkcionog modela za otkrivanje prevara tako da se transakcije sa određenih kartica uvek odobravaju.


## Rizici u Google SAIF-u

Googleov [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) opisuje različite rizike povezane sa AI sistemima:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Zlonamerni akteri menjaju ili ubacuju podatke za obuku ili fino podešavanje da bi umanjili tačnost, ugradili backdoor-e ili iskrivili rezultate, narušavajući integritet modela tokom čitavog životnog ciklusa podataka. 

- **Unauthorized Training Data**: Korišćenje zaštićenih autorskim pravima, osetljivih ili neodobrenih skupova podataka stvara pravne, etičke i performansne rizike jer model uči iz podataka koje nije smeo da koristi. 

- **Model Source Tampering**: Manipulacija kôdom modela, zavisnostima ili težinama tokom lanca snabdevanja ili iznutra, pre ili tokom obuke, može da ugradi skrivenu logiku koja opstaje i nakon ponovne obuke. 

- **Excessive Data Handling**: Slabe kontrole zadržavanja podataka i upravljanja njima dovode do toga da sistemi čuvaju ili obrađuju više ličnih podataka nego što je potrebno, povećavajući rizik od izlaganja i neusklađenosti. 

- **Model Exfiltration**: Napadači kradu datoteke ili težine modela, što dovodi do gubitka intelektualne svojine i omogućava izradu kopija usluga ili naknadne napade. 

- **Model Deployment Tampering**: Napadači menjaju artefakte modela ili infrastrukturu za pružanje usluge tako da se model koji radi razlikuje od proverene verzije, što može da promeni njegovo ponašanje. 

- **Denial of ML Service**: Zatrpavanje API-ja zahtevima ili slanje „sunđerastih” ulaza može da iscrpi računarske resurse ili energiju i obori model, slično klasičnim DoS napadima. 

- **Model Reverse Engineering**: Prikupljanjem velikog broja parova ulaznih i izlaznih podataka, napadači mogu da kloniraju ili destiluju model, što podstiče izradu imitacija i prilagođenih adversarijalnih napada. 

- **Insecure Integrated Component**: Ranjivi dodaci, agenti ili uzvodne usluge omogućavaju napadačima da ubace kôd ili eskaliraju privilegije unutar AI pipeline-a. 

- **Prompt Injection**: Sastavljanje promptova (direktno ili indirektno) radi podmetanja instrukcija koje nadjačavaju nameru sistema i navode model da izvršava neželjene komande. 

- **Model Evasion**: Pažljivo osmišljeni ulazi navode model da pogrešno klasifikuje, halucinira ili izbacuje zabranjen sadržaj, narušavajući bezbednost i poverenje. 

- **Sensitive Data Disclosure**: Model otkriva privatne ili poverljive informacije iz podataka za obuku ili korisničkog konteksta, kršeći privatnost i propise. 

- **Inferred Sensitive Data**: Model zaključuje lične atribute koji nikada nisu navedeni, stvarajući nove rizike po privatnost kroz zaključivanje. 

- **Insecure Model Output**: Nepročišćeni odgovori prosleđuju štetan kôd, dezinformacije ili neprikladan sadržaj korisnicima ili nizvodnim sistemima. 

- **Rogue Actions**: Autonomno integrisani agenti izvršavaju neželjene operacije u stvarnom svetu (upisivanje datoteka, API pozivi, kupovine itd.) bez odgovarajućeg nadzora korisnika.

## Matrica Mitre AI ATLAS

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) pruža sveobuhvatan okvir za razumevanje i ublažavanje rizika povezanih sa AI sistemima. Klasifikuje različite tehnike napada i taktike koje protivnici mogu primeniti protiv AI modela, kao i načine korišćenja AI sistema za izvođenje različitih napada.<sup>[[3]](#references)</sup>

## LLMJacking (krađa tokena i preprodaja pristupa LLM-ovima hostovanim u cloudu)

Napadači kradu aktivne tokene sesija ili cloud API akreditive i neovlašćeno pozivaju plaćene LLM-ove hostovane u cloudu. Pristup se često preprodaje preko reverse proxy-ja koji posreduju u korišćenju naloga žrtve, npr. implementacija „oai-reverse-proxy”. Posledice obuhvataju finansijske gubitke, zloupotrebu modela protivno pravilima i pripisivanje aktivnosti nalogu žrtve.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP-ovi:
- Prikupljanje tokena sa zaraženih računara programera ili iz pregledača; krađa CI/CD tajni; kupovina procurelih kolačića.<sup>[[5]](#references)</sup>
- Postavljanje reverse proxy-ja koji prosleđuje zahteve stvarnom pružaocu usluge, skriva uzvodni ključ i opslužuje više korisnika.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Zloupotreba direktnih endpoint-a osnovnog modela radi zaobilaženja zaštitnih mehanizama preduzeća i ograničenja broja zahteva.<sup>[[4]](#references)</sup>

Ublažavanje rizika:
- Povezati tokene sa otiskom uređaja, IP opsezima i atestacijom klijenta; primeniti kratko vreme važenja i osvežavanje uz MFA.
- Ograničiti ključeve na najmanji potreban opseg (bez pristupa alatima, samo za čitanje gde je primenljivo); rotirati ih u slučaju anomalije.
- Sav saobraćaj usmeriti na serversku stranu kroz policy gateway koji primenjuje bezbednosne filtere, kvote po ruti i izolaciju zakupaca.
- Pratiti neuobičajene obrasce korišćenja (nagli skokovi troškova, neuobičajeni regioni, UA stringovi) i automatski opozivati sumnjive sesije.
- Prednost dati mTLS-u ili potpisanim JWT-ovima koje izdaje IdP umesto dugotrajnih statičkih API ključeva.

## Ojačavanje inference-a samostalno hostovanog LLM-a

Pokretanje lokalnog LLM servera za poverljive podatke stvara drugačiju površinu napada od API-ja hostovanih u cloudu: inference/debug endpoint-i mogu da otkriju promptove, sloj za pružanje usluge obično izlaže reverse proxy, a čvorovi GPU uređaja omogućavaju pristup velikom broju `ioctl()` interfejsa. Ako procenjujete ili postavljate lokalnu inference uslugu, pregledajte barem sledeće tačke.<sup>[[8]](#references)</sup>

### Curenje promptova preko debug i monitoring endpoint-a

Tretirajte inference API kao **osetljivu uslugu za više korisnika**. Debug ili monitoring rute mogu da otkriju sadržaj promptova, stanje slotova, metapodatke modela ili interne informacije o redovima čekanja. U `llama.cpp` je endpoint `/slots` posebno osetljiv jer otkriva stanje pojedinačnih slotova i namenjen je samo njihovom pregledu i upravljanju.<sup>[[8]](#references)</sup>

Za black-box otiskivanje i testiranje izloženih model runner-a i srodnih AI usluga pogledajte [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Postavite reverse proxy ispred inference servera i **podrazumevano zabranite pristup**.
- Dozvolite samo tačne kombinacije HTTP metoda i putanja koje su potrebne klijentu/UI-ju.
- Isključite endpoint-e za introspekciju u samom backend-u kad god je moguće, na primer `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Povežite reverse proxy sa `127.0.0.1` i izložite ga preko autentifikovanog transporta, kao što je prosleđivanje lokalnog porta preko SSH-a, umesto da ga objavite na LAN-u.

Primer allowlist-a sa nginx-om:

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

Ako inference daemon podržava osluškivanje na UNIX socket-u, dajte prednost tome u odnosu na TCP i pokrenite kontejner bez mrežnog steka:<sup>[[8]](#references)</sup>

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
- `--network none` uklanja izloženost dolaznom/odlaznom TCP/IP saobraćaju i izbegava pomoćne procese u korisničkom režimu koji bi inače bili potrebni rootless kontejnerima.
- UNIX socket omogućava korišćenje POSIX dozvola/ACL-ova na putanji socket-a kao prvog sloja kontrole pristupa.
- `--userns=keep-id` i rootless Podman smanjuju posledice proboja kontejnera jer root u kontejneru nije root na hostu.
- Mount-ovi modela samo za čitanje smanjuju mogućnost menjanja modela iz kontejnera.

Za trajne primene, ista ograničenja mogu se definisati kao Podman Quadlet jedinice. Ako se pristup GPU-u delegira preko Container Device Interface-a, specifikaciju CDI uređaja držite što užom umesto da izložite svaki čvor akceleratora.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Svođenje GPU čvorova uređaja na minimum

Za inferenciju koja koristi GPU, datoteke `/dev/nvidia*` predstavljaju vredne lokalne površine za napad jer izlažu velike `ioctl()` rukovaoce i potencijalno deljene putanje za upravljanje GPU memorijom.<sup>[[8]](#references)</sup>

- Ne ostavljajte `/dev/nvidia*` dostupnim za upis svima.
- Ograničite `nvidia`, `nvidiactl` i `nvidia-uvm` pomoću `NVreg_DeviceFileUID/GID/Mode`, udev pravila i ACL-ova tako da ih može otvoriti samo mapirani UID kontejnera.
- Na headless hostovima za inferenciju stavite na crnu listu nepotrebne module kao što su `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem`.
- Unapred učitajte samo neophodne module pri pokretanju sistema umesto da dozvolite runtime-u da ih po potrebi učita pomoću `modprobe` tokom pokretanja inferencije.

Primer:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Jedna važna stavka za proveru je **`/dev/nvidia-uvm`**. Čak i ako radno opterećenje izričito ne koristi `cudaMallocManaged()`, noviji CUDA runtime-i i dalje mogu zahtevati `nvidia-uvm`. Pošto je ovaj uređaj deljen i upravlja virtuelnom memorijom GPU-a, tretirajte ga kao površinu za izlaganje podataka između zakupaca. Ako ga podržava backend za inferenciju, Vulkan backend može biti zanimljiv kompromis jer može u potpunosti da izbegne izlaganje `nvidia-uvm` uređaja kontejneru.<sup>[[8]](#references)</sup>

### LSM ograničavanje radnika za inferenciju

AppArmor/SELinux/seccomp treba koristiti kao dodatni sloj odbrane oko procesa za inferenciju:<sup>[[8]](#references)</sup>

- Dozvolite samo deljene biblioteke, putanje do modela, direktorijum soketa i čvorove GPU uređaja koji su zaista potrebni.
- Izričito zabranite visokorizične mogućnosti kao što su `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Direktorijum modela držite samo za čitanje, a upisivanje ograničite samo na direktorijume za runtime sokete/keš.
- Pratite evidenciju odbijanja jer pruža korisne telemetrijske podatke za detekciju kada server modela ili post-exploitation payload pokuša da izađe iz očekivanog ponašanja.

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

Phantom squatting je **ekvivalent slopsquatting-a za domene/URL-ove**. Umesto da halucinira nepostojeći naziv paketa, LLM halucinira uverljiv **portal, API, webhook, billing, SSO, domen za preuzimanje ili podršku** za postojeći brend, a napadač registruje taj namespace pre nego što ga upotrebi čovek ili agent.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ovo je važno zato što se u mnogim AI-potpomognutim tokovima rada izlaz modela tretira kao **pouzdana zavisnost**:
- Programeri ubacuju predloženi endpoint u kod ili CI/CD integracije.
- AI agenti automatski preuzimaju dokumentaciju, šeme, APK-ove, ZIP-ove ili odredišta webhook-a.
- Generisani runbook-ovi ili dokumentacija mogu da sadrže lažni URL kao da je merodavan.

### Napadački tok rada

1. **Ispitajte površinu halucinacija**: postavljajte pitanja specifična za brend o realističnim tokovima rada kao što su portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ili `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizujte kandidate**: razrešite generisane URL-ove, svedite NXDOMAIN odgovore na roditeljski domen koji može da se registruje i uklonite duplikate iz porodica promptova. Korpusi promptova treba da ostanu raznovrsni; na primer, uklonite skoro identične promptove pomoću **Jaccard sličnosti**.
3. **Dajte prednost predvidljivim halucinacijama**:
   - **Thermal Hallucination Persistence (THP)**: isti lažni domen pojavljuje se pri različitim temperaturama, uključujući nisku temperaturu kao što je `T=0.1`.
   - **Konsenzus među modelima**: više LLM porodica generiše isti lažni domen.
4. **Registrujte i naoružajte** roditeljski domen, a zatim hostujte phishing, lažna preuzimanja APK/ZIP fajlova, alate za krađu kredencijala, zlonamernu dokumentaciju ili API endpoint-e koji prikupljaju tajne/webhook payload-e. **Halucinacije koje obuhvataju samo domen** najlakše je unovčiti jer napadač kontroliše ceo namespace; halucinacije poddomena/putanje i dalje mogu da se zloupotrebe ako normalizovani roditeljski domen nije registrovan.
5. **Iskoristite period bez reputacije**: novoregistrovanim domenima često nedostaju istorija na blocklist-ama, reputacija URL-a i zrela telemetrija, pa mogu da zaobiđu kontrole dok se detekcije ne ažuriraju. Napadači mogu da produže ovaj period benignim odgovorima namenjenim samo crawler-ima, prikrivanjem redirekcija, CAPTCHA proverama ili odloženim postavljanjem payloada.

### Zašto je opasno za agente

Kod ljudske žrtve, lažni domen obično i dalje zahteva klik i dodatnu radnju. U **agentskom toku rada**, LLM može istovremeno da bude i **mamac** i **izvršilac**: agent dobija URL koji je halucinirao model, preuzima ga, parsira odgovor, a zatim može da otkrije tokene, izvrši instrukcije, preuzme zavisnost ili ubaci zatrovane podatke u CI/CD bez ikakve ljudske provere.<sup>[[12]](#references)</sup>

### Praktični promptovi za napadače

Promptovi sa velikim učinkom obično liče na uobičajene zadatke u preduzeću, a ne na eksplicitne phishing mamce:<sup>[[12]](#references)</sup>
- „Koji je URL payment sandbox-a za integracije sa `<brand>`?“
- „Koji webhook endpoint treba da koristim za obaveštenja o build-u za `<brand>`?“
- „Gde je portal za employee benefits / billing / SSO za `<brand>`?“
- „Daj mi direktan link za preuzimanje Android APK-a ili desktop klijenta za `<brand>`.“

### Odbrambeni pristup

Tretirajte ovo kao proaktivan problem nadzora domena, a ne samo kao problem prompt injection-a:<sup>[[12]](#references)</sup>
- Napravite **korpus promptova za brendove** i periodično proveravajte LLM-ove na koje se oslanjaju korisnici/agenti.
- Čuvajte URL-ove koje su modeli halucinirali i pratite koji ostaju stabilni pri različitim temperaturama/modelima.
- Pratite **Adversarial Exploitation Window (AEW)**: vreme između prve halucinacije i registracije domena od strane napadača. Pozitivan AEW znači da branioci mogu unapred da registruju domen, usmere ga na sinkhole ili ga blokiraju pre nego što bude naoružan.
- Pratite prelaze **NXDOMAIN → registrovan** za roditeljske domene.
- Nakon registracije, proverite registrara, datum kreiranja, nameserver-e, zaštitu privatnosti, sadržaj stranice, snimke ekrana, status parkirane stranice i sličnost sa sredstvima brenda.
- Dodajte kontrolne politike kako agenti/programeri **ne bi podrazumevano verovali domenima koje generiše LLM**: zahtevajte allowlist-e, proveru vlasništva, CT/RDAP provere ili ljudsko odobrenje pre prve upotrebe.

Ovo istovremeno spada u nekoliko kategorija AI rizika: **napad na AI lanac snabdevanja**, **nebezbedan izlaz modela** i **neovlašćene radnje** kada agenti autonomno koriste URL koji je model halucinirao.

## References

- [1] [OWASP Top 10 ranjivosti mašinskog učenja](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – rizici](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS matrica pretnji](https://atlas.mitre.org/)
- [4] [Unit 42 – Rizici LLM-ova za asistenciju pri pisanju koda: štetan sadržaj, zloupotreba i obmana](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: ukradeni kredencijali za cloud upotrebljeni u novom AI napadu](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Pregled LLMJacking šeme – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (preprodaja ukradenog pristupa LLM-u)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Detaljna analiza postavljanja on-premise LLM servera sa niskim privilegijama](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README za llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specifikacija CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domeni koje halucinira AI kao vektor napada na lanac snabdevanja softverom](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: kako halucinacije AI-ja podstiču novu klasu napada na lanac snabdevanja](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
