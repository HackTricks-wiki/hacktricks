# AI ризици

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP је идентификовао 10 најчешћих рањивости машинског учења које могу да утичу на AI системе. Ове рањивости могу довести до различитих безбедносних проблема, укључујући тровање података, инверзију модела и adversarial нападе. Разумевање ових рањивости је кључно за изградњу безбедних AI система.

За ажуриран и детаљан списак 10 најчешћих рањивости машинског учења погледајте пројекат [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Нападач уноси ситне, често невидљиве измене у **улазне податке** да би навео модел на погрешну одлуку.\
    *Пример*: Неколико тачкица боје на знаку стоп наведе самовозећи аутомобил да га „види“ као знак ограничења брзине.

- **Data Poisoning Attack**: **Скуп за обучавање** намерно се затрује неисправним узорцима, чиме модел учи штетна правила.\
*Пример*: Бинарне датотеке малвера у корпусу за обучавање антивируса погрешно се означе као „безопасне“, па сличан малвер касније прође непримећено.

- **Model Inversion Attack**: Испитујући излазе, нападач прави **обрнути модел** који реконструише осетљиве карактеристике првобитних улаза.\
*Пример*: Реконструкција MRI снимка пацијента на основу предвиђања модела за откривање рака.

- **Membership Inference Attack**: Нападач проверава да ли је **одређени запис** коришћен током обучавања, уочавајући разлике у поузданости предвиђања.\
*Пример*: Потврђивање да се трансакција неке особе налази у подацима за обучавање модела за откривање превара.

- **Model Theft**: Понављаним слањем упита нападач може да открије границе одлучивања и **клонира понашање модела** (и IP).\
*Пример*: Прикупљање довољно парова питања и одговора из API-ја ML-as-a-Service ради изградње локалног модела сличних могућности.

- **AI Supply‑Chain Attack**: Компромитовање било које компоненте (**података, библиотека, претходно обучених тежина или CI/CD**) у **ML pipeline-у** може да поквари наредне моделе.\
*Пример*: Заражена зависност са model hub-а инсталира backdoored модел за анализу сентимента у многе апликације.

- **Transfer Learning Attack**: Злонамерна логика се поставља у **претходно обучен модел** и опстаје након дообучавања за задатак жртве.\
*Пример*: Скривени окидач у vision backbone-у и даље мења ознаке након прилагођавања модела за медицинско снимање.

- **Model Skewing**: Суптилно пристрасни или погрешно означени подаци **померају излазе модела** у корист нападачевог циља.\
*Пример*: Убацивање „чистих“ spam порука означених као ham како би spam филтер пропуштао сличне будуће поруке.

- **Output Integrity Attack**: Нападач **мења предвиђања модела током преноса**, а не сам модел, и тако обмањује наредне системе.\
*Пример*: Промена пресуде класификатора малвера са „злонамерно“ на „безопасно“ пре него што дође до фазе стављања датотеке у карантин.

- **Model Poisoning** --- Директне, циљане измене самих **параметара модела**, често након стицања приступа за писање, ради промене понашања.\
*Пример*: Подешавање тежина продукционог модела за откривање превара тако да увек одобрава трансакције са одређених картица.


## Google SAIF ризици

Google-ов [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) описује различите ризике повезане са AI системима:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Злонамерни актери мењају или убацују податке за обучавање/подешавање како би умањили тачност, уградили backdoor или искривили резултате, нарушавајући интегритет модела током целог животног циклуса података.

- **Unauthorized Training Data**: Коришћење ауторски заштићених, осетљивих или неовлашћених скупова података ствара правне, етичке и пословне ризике, јер модел учи на подацима које није смео да користи.

- **Model Source Tampering**: Манипулација кôдом модела, зависностима или тежинама током ланца снабдевања или од стране инсајдера, пре или током обучавања, може да угради скривену логику која опстаје и након поновног обучавања.

- **Excessive Data Handling**: Слабе контроле чувања података и управљања њима доводе до тога да системи складиште или обрађују више личних података него што је потребно, повећавајући изложеност и ризик од непоштовања прописа.

- **Model Exfiltration**: Нападачи краду датотеке/тежине модела, што доводи до губитка интелектуалне својине и омогућава прављење копија услуга или накнадне нападе.

- **Model Deployment Tampering**: Нападачи мењају артефакте модела или инфраструктуру за опслуживање, тако да се покренути модел разликује од проверене верзије и може да се понаша другачије.

- **Denial of ML Service**: Преплављивање API-ја захтевима или слање „sponge“ улаза може да исцрпи рачунарске ресурсе/енергију и обори модел, као код класичних DoS напада.

- **Model Reverse Engineering**: Прикупљањем великог броја парова улаз-излаз нападачи могу да клонирају или дестилују модел, што омогућава прављење имитација производа и прилагођених adversarial напада.

- **Insecure Integrated Component**: Рањиви додаци, агенти или узводне услуге омогућавају нападачима да убаце кôд или повећају привилегије у AI pipeline-у.

- **Prompt Injection**: Креирање prompt-ова, директно или индиректно, ради прокријумчарења упутстава која надјачавају системску намеру и наводе модел да изврши ненамераване команде.

- **Model Evasion**: Пажљиво осмишљени улази наводе модел да погрешно класификује, халуцинира или генерише забрањен садржај, урушавајући безбедност и поверење.

- **Sensitive Data Disclosure**: Модел открива приватне или поверљиве информације из података за обучавање или контекста корисника, кршећи приватност и прописе.

- **Inferred Sensitive Data**: Модел закључује личне особине које никада нису наведене, стварајући нову штету по приватност путем закључивања.

- **Insecure Model Output**: Несанирани одговори преносе штетан кôд, дезинформације или неприкладан садржај корисницима или наредним системима.

- **Rogue Actions**: Аутономно интегрисани агенти обављају ненамераване радње у стварном свету (уписивање датотека, API позиви, куповине итд.) без одговарајућег надзора корисника.

## MITRE AI ATLAS матрица

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) пружа свеобухватан оквир за разумевање и ублажавање ризика повезаних са AI системима. Она категоризује различите технике напада и тактике које нападачи могу да примене против AI модела, као и начине коришћења AI система за извођење различитих напада.<sup>[[3]](#references)</sup>

## LLMJacking (крађа token-а и препродаја приступа cloud-hosted LLM-у)

Нападачи краду активне token-е сесије или cloud API акредитиве и неовлашћено користе плаћене cloud-hosted LLM-ове. Приступ се често препродаје путем reverse proxy-ја који усмеравају захтеве преко налога жртве, нпр. примене „oai-reverse-proxy“. Последице укључују финансијски губитак, злоупотребу модела кршећи политику и приписивање активности tenant-у жртве.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Прикупљање token-а са заражених рачунарa програмера или из прегледача; крађа CI/CD тајни; куповина процурелих cookies.<sup>[[5]](#references)</sup>
- Постављање reverse proxy-ја који прослеђује захтеве стварном провајдеру, скрива upstream кључ и опслужује више клијената.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Злоупотреба директних endpoint-а основног модела ради заобилажења enterprise заштитних механизама и ограничења броја захтева.<sup>[[4]](#references)</sup>

**Поновна употреба API кључа на хосту:** Након компромитовања хоста, имплант може директно са хоста жртве да шаље захтеве моделу и прослеђује одговоре преко C2, без извоза cloud API кључа или покретања локалног AI CLI-ја. У посматраном handler-у, кључ достављен преко C2 има предност; само када га нема, имплант чита `OPENAI_API_KEY` из окружења сопственог процеса. Зато је за коришћење налога жртве потребан важећи кључ доступан том процесу и приступ API-ју модела. Prompt оператера шаље се Chat Completions API-ју, док се излаз модела и број потрошених token-а враћају преко C2. Ово може да потроши плаћени приступ моделу жртве без покретања AI алата програмера, за разлику од злоупотребе [локалног AI CLI-ја или MCP конфигурације](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md).<sup>[[14]](#references)</sup>

Мере ублажавања:
- Везивање token-а за отисак уређаја, IP опсеге и атестацију клијента; примена кратког рока важења и освежавање уз MFA.
- Ограничење кључева на најмањи потребан обим (без приступа алатима, само за читање где је применљиво); ротација при уочавању аномалија.
- Усмеравање целокупног саобраћаја са стране сервера кроз policy gateway који примењује безбедносне филтере, квоте по рути и изолацију tenant-а.
- Праћење необичних образаца употребе (нагли скокови трошкова, неуобичајени региони, UA стрингови) и аутоматско опозивање сумњивих сесија.
- Предност дати mTLS-у или потписаним JWT-овима које издаје ваш IdP уместо дуготрајних статичких API кључева.

## Ојачавање self-hosted LLM inference-а

Покретање локалног LLM сервера за поверљиве податке ствара другачију површину за напад од cloud-hosted API-ја: inference/debug endpoint-и могу да открију prompt-ове, serving stack обично излаже reverse proxy, а GPU device чворови омогућавају приступ великом броју `ioctl()` површина. Ако процењујете или постављате on-prem inference услугу, проверите бар следеће ставке.<sup>[[8]](#references)</sup>

### Цурење prompt-ова преко debug и monitoring endpoint-а

Третирајте inference API као **осетљиву услугу за више корисника**. Debug или monitoring руте могу да открију садржај prompt-ова, стање слотова, метаподатке модела или информације о интерном реду чекања. У `llama.cpp`, endpoint `/slots` је посебно осетљив јер открива стање појединачних слотова и намењен је само прегледу/управљању слотовима.<sup>[[8]](#references)</sup>

За black-box fingerprinting и тестирање изложених model runner-а и повезаних AI услуга погледајте [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Поставите reverse proxy испред inference сервера и **подразумевано одбијајте захтеве**.
- Дозволите само тачне комбинације HTTP метода и путања које су потребне клијенту/UI-ју.
- Искључите introspection endpoint-е у самом backend-у кад год је могуће, на пример `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Вежите reverse proxy за `127.0.0.1` и изложите га преко аутентификованог транспорта као што је SSH local port forwarding, уместо да га објавите на LAN-у.

Пример allowlist-а са nginx:

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

Ako inference daemon podržava osluškivanje na UNIX soketu, dajte prednost tome u odnosu na TCP i pokrenite kontejner **bez mrežnog steka**:<sup>[[8]](#references)</sup>

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
- `--network none` uklanja izloženost ulaznom/izlaznom TCP/IP saobraćaju i izbegava pomoćne programe u korisničkom režimu koji bi inače bili potrebni rootless kontejnerima.
- UNIX socket omogućava korišćenje POSIX dozvola/ACL-ova na putanji socket-a kao prvog sloja kontrole pristupa.
- `--userns=keep-id` i rootless Podman smanjuju posledice proboja iz kontejnera jer root u kontejneru nije root na hostu.
- Montiranja modela samo za čitanje smanjuju mogućnost menjanja modela iz kontejnera.

Za trajne implementacije, ista ograničenja mogu se izraziti kao Podman Quadlet jedinice. Ako se GPU pristup delegira kroz Container Device Interface, specifikaciju CDI uređaja suzite što je više moguće, umesto da izložite svaki akceleratorski čvor.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Svođenje GPU čvorova uređaja na minimum

Kod inference-a zasnovanog na GPU-u, datoteke `/dev/nvidia*` predstavljaju lokalne napadne površine visoke vrednosti jer izlažu velike `ioctl()` obrađivače i potencijalno deljene putanje za upravljanje GPU memorijom.<sup>[[8]](#references)</sup>

- Ne ostavljajte `/dev/nvidia*` sa dozvolama za pisanje svim korisnicima.
- Ograničite pristup uređajima `nvidia`, `nvidiactl` i `nvidia-uvm` pomoću `NVreg_DeviceFileUID/GID/Mode`, udev pravila i ACL-ova, tako da ih može otvoriti samo mapirani UID kontejnera.
- Blokirajte nepotrebne module kao što su `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem` na hostovima za inference bez grafičkog okruženja.
- Učitajte unapred samo neophodne module pri pokretanju sistema, umesto da dozvolite runtime-u da ih po potrebi učitava pomoću `modprobe` tokom pokretanja inference-a.

Primer:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Jedna važna stavka za proveru je **`/dev/nvidia-uvm`**. Čak i ako workload ne koristi eksplicitno `cudaMallocManaged()`, novija CUDA okruženja za izvršavanje i dalje mogu zahtevati `nvidia-uvm`. Pošto se ovaj uređaj deli i upravlja virtuelnom memorijom GPU-a, tretirajte ga kao površinu za izlaganje podataka između tenant-a. Ako ga inference backend podržava, Vulkan backend može biti zanimljiv kompromis jer možda uopšte ne izlaže `nvidia-uvm` kontejneru.<sup>[[8]](#references)</sup>

### LSM ograničavanje inference worker-a

AppArmor/SELinux/seccomp treba koristiti kao dodatni sloj odbrane oko inference procesa:<sup>[[8]](#references)</sup>

- Dozvolite samo deljene biblioteke, putanje do modela, direktorijum socket-a i čvorove GPU uređaja koji su zaista potrebni.
- Eksplicitno zabranite visokorizične mogućnosti kao što su `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Direktorijum modela zadržite samo za čitanje, a upis dozvolite samo u direktorijume socket-a/cache-a za runtime.
- Pratite logove odbijanja jer pružaju korisnu telemetriju za detekciju kada server modela ili payload nakon eksploatacije pokuša da izađe iz očekivanog ponašanja.

Primer AppArmor pravila za worker koji koristi GPU:

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

## Phantom Squatting: domeni koje halucinira LLM kao vektor napada na lanac snabdevanja AI-ja

Phantom squatting je **ekvivalent slopsquatting-a za domene/URL-ove**. Umesto da halucinira nepostojeći naziv paketa, LLM halucinira uverljiv **domen portala, API-ja, webhook-a, naplate, SSO-a, preuzimanja ili podrške** za stvarni brend, a napadač registruje taj namespace pre nego što ga upotrebi čovek ili agent.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ovo je važno zato što se u mnogim AI-potpomognutim tokovima rada izlaz modela smatra **pouzdanom zavisnošću**:
- Programeri kopiraju predloženi endpoint u kod ili CI/CD integracije.
- AI agenti automatski preuzimaju dokumentaciju, šeme, APK-ove, ZIP-ove ili webhook odredišta.
- Generisani runbook-ovi ili dokumentacija mogu da sadrže lažni URL kao da je autoritativan.

### Ofanzivni tok rada

1. **Ispitajte površinu halucinacija**: postavljajte pitanja specifična za brend o realističnim tokovima rada kao što su portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ili `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizujte kandidate**: razrešite generisane URL-ove, svedite NXDOMAIN odgovore na nadređeni domen koji može da se registruje i uklonite duplikate iz grupa promptova. Korpusi promptova treba da ostanu raznovrsni, na primer tako što se uklanjaju skoro identični primeri pomoću **Jaccard sličnosti**.
3. **Dajte prioritet predvidljivim halucinacijama**:
   - **Postojanost termičke halucinacije (THP)**: isti lažni domen pojavljuje se pri različitim temperaturama, uključujući nisku temperaturu poput `T=0.1`.
   - **Konsenzus između modela**: više porodica LLM-ova generiše isti lažni domen.
4. **Registrujte i naoružajte** nadređeni domen, pa na njemu hostujte phishing, lažna APK/ZIP preuzimanja, alate za prikupljanje akreditiva, zlonamerne dokumente ili API endpoint-e koji prikupljaju tajne/webhook sadržaj. **Halucinacije na nivou samog domena** najlakše je unovčiti jer napadač kontroliše ceo namespace; halucinacije poddomena/putanje i dalje mogu da se zloupotrebe ako normalizovani nadređeni domen nije registrovan.
5. **Iskoristite period bez reputacije**: novoregistrovani domeni često nemaju istoriju na blocklist-ama, reputaciju URL-a ni razvijenu telemetriju, pa mogu da zaobiđu kontrole dok ih sistemi za detekciju ne sustignu. Napadači mogu da produže ovaj period benignim odgovorima namenjenim samo crawler-ima, prikrivanjem redirect-a, CAPTCHA proverama ili odloženim postavljanjem payload-a.

### Zašto je opasno za agente

Kod ljudske žrtve, lažni domen obično i dalje zahteva klik i dodatnu radnju. U **agentskom toku rada**, LLM može biti i **mamac** i **izvršilac**: agent dobija URL koji je halucinirao model, preuzima ga, parsira odgovor i zatim može da oda tokene, izvrši instrukcije, preuzme zavisnost ili unese zatrovane podatke u CI/CD bez ikakve ljudske provere.<sup>[[12]](#references)</sup>

### Praktični promptovi napadača

Promptovi sa najvećim učinkom obično liče na uobičajene poslovne zadatke, a ne na eksplicitne phishing mamce:<sup>[[12]](#references)</sup>
- „Koji je URL payment sandbox-a za integracije `<brand>`?“
- „Koji webhook endpoint treba da koristim za obaveštenja o build-u za `<brand>`?“
- „Gde se nalazi portal za employee benefits / billing / SSO za `<brand>`?“
- „Daj mi direktno preuzimanje Android APK-a ili desktop klijenta za `<brand>`.“

### Odbrambeni pristup

Tretirajte ovo kao problem proaktivnog nadgledanja domena, a ne samo kao problem prompt injection-a:<sup>[[12]](#references)</sup>
- Napravite **korpus promptova za brendove** i periodično testirajte LLM-ove na koje se oslanjaju vaši korisnici/agenti.
- Čuvajte URL-ove koje je model halucinirao i pratite koji su stabilni pri različitim temperaturama/modelima.
- Pratite **prozor adversarne eksploatacije (AEW)**: vreme između prve halucinacije i registracije domena od strane napadača. Pozitivan AEW znači da branioci mogu unapred da registruju domen, preusmere ga na sinkhole ili ga blokiraju pre naoružavanja.
- Pratite prelaze **NXDOMAIN → registrovan** za nadređene domene.
- Pri registraciji proverite registrara, datum kreiranja, nameserver-e, zaštitu privatnosti, sadržaj stranice, snimke ekrana, status parkirane stranice i sličnost sa elementima brenda.
- Dodajte kontrolne mehanizme kako agenti/programeri **ne bi podrazumevano verovali domenima koje generiše LLM**: zahtevajte allowlist-e, proveru vlasništva, CT/RDAP provere ili ljudsko odobrenje pre prve upotrebe.

Ovo istovremeno spada u nekoliko kategorija rizika AI-ja: **napad na lanac snabdevanja AI-ja**, **nebezbedan izlaz modela** i **neovlašćene radnje** kada agenti samostalno koriste URL koji je model halucinirao.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [OWASP Top 10 ranjivosti mašinskog učenja](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Rizici](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS matrica pretnji](https://atlas.mitre.org/)
- [4] [Unit 42 – Rizici LLM-ova za pomoć pri programiranju: štetan sadržaj, zloupotreba i obmana](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: ukradeni Cloud akreditivi upotrebljeni u novom AI napadu](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Pregled šeme LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (preprodaja ukradenog pristupa LLM-u)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Detaljna analiza postavljanja on-premise LLM servera sa niskim privilegijama](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specifikacija](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domeni koje halucinira AI kao vektor napada na lanac snabdevanja softverom](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: kako halucinacije AI-ja podstiču novu vrstu napada na lanac snabdevanja](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: novi AI-om omogućeni framework za komandovanje i kontrolu](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
