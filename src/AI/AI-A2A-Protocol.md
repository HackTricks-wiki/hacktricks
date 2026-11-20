# Bezbednost A2A (Agent2Agent) protokola

{{#include ../banners/hacktricks-training.md}}

## Šta je A2A

A2A (Agent2Agent) je otvoreni protokol koji omogućava jednom AI agentu da pronađe drugog agenta i pošalje mu zadatke preko HTTP-a. MCP povezuje agenta sa **alatima i podacima**; A2A povezuje agenta sa **drugim agentima**, koji su obično udaljene usluge u vlasništvu drugog tima ili kompanije. A2A server je web API iza kog se nalazi LLM agent, pa objekti samog protokola (Agent Card-ovi, zadaci, webhook-ovi za push-notifikacije i proširene kartice) zahtevaju posebne provere autentifikacije, IDOR-a i SSRF-a tokom testiranja uobičajenog API-ja.<sup>[[1]](#references)[[2]](#references)</sup>

Glavne komponente su:

- **Agent Card:** JSON dokument koji opisuje agenta: ime, opis, veštine, URL-ove usluga, podržane transporte, mogućnosti (streaming, push-notifikacije, proširena kartica) i `securitySchemes` koje klijent mora da koristi. Objavljuje se na `https://<host>/.well-known/agent-card.json`. Starije implementacije koje prate specifikaciju 0.2.x koriste `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** jedinica rada. Poruka kreira zadatak (sa `id` i `contextId` koje generiše server), a klijent ga kasnije čita, otkazuje ili se pretplaćuje na njega.<sup>[[1]](#references)</sup>
- **Transporti:** JSON-RPC 2.0 preko HTTP-a (uz SSE za streaming), gRPC i HTTP+JSON REST binding.<sup>[[1]](#references)</sup>
- **Autentifikacija:** akreditivi se prosleđuju u HTTP zaglavljima (na primer, `Authorization: Bearer ...`), nikada unutar JSON-RPC payload-a. Agent Card navodi koja je šema obavezna.<sup>[[1]](#references)</sup>

Nazivi metoda su se menjali između verzija, zato isprobajte oba skupa:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operacija | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Slanje poruke | `message/send` | `SendMessage` | `POST /message:send` |
| Slanje u streaming režimu | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Preuzimanje zadatka | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Izlistavanje zadataka | - | `ListTasks` | `GET /tasks` |
| Otkazivanje zadatka | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Podešavanje konfiguracije push-notifikacija | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Proširena kartica | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Specifikacija 1.0 koristi zaglavlje `A2A-Version` (ili parametar zahteva) za izbor verzije, a zahtevi bez njega tretiraju se kao verzija 0.3.<sup>[[1]](#references)</sup>

## Otkrivanje

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Sa kartice zabeležite:

- Svaki `url` servisa: u verziji 1.0 nalaze se pod `supportedInterfaces`, dok starije kartice mogu da imaju `url` na najvišem nivou. Zabeležite svaku krajnju tačku i transport, uključujući interna imena hostova, staging URL-ove i alternativne portove.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: pokazuju šta agent može da radi i koji alati ili podaci stoje iza njega.
- `securitySchemes` / `security`: ako su prazni ili nedostaju, agent je verovatno predviđen za pozivanje bez kredencijala.
- `capabilities.pushNotifications` i `capabilities.extendedAgentCard` (u verziji 0.3 `supportsAuthenticatedExtendedCard`).

Specifikacija kaže da javna kartica ne treba da sadrži kredencijale ni interne detalje implementacije, pa su interni URL-ovi, ključevi ili detaljni spiskovi alata u javnoj kartici već nalaz.<sup>[[1]](#references)</sup>

### Sukob imena Agent Card-a u hostu sa više agenata

`name` kartice je ljudima čitljiva oznaka, a ne stabilni identitet za rutiranje.<sup>[[1]](#references)[[5]](#references)</sup> Ako host registruje dva različita udaljena peer-a pod istim lokalnim imenom, njegovo stablo agenata, generisano ime alata, mapa klijenata ili ruta posrednika može da pošalje zadatak namenjen pouzdanom peer-u drugom peer-u.<sup>[[5]](#references)</sup> Za to je potrebno da peer pod kontrolom napadača bude prihvaćen u **istom prostoru imena za rutiranje**; samo objavljivanje duplikata kartice na Internetu nije dovoljno.<sup>[[5]](#references)</sup>

Testirajte putanju hosta od **prihvatanja do slanja** pomoću dva peer-a pod vašom kontrolom, različitih URL-ova i bezazlenog markera:<sup>[[5]](#references)</sup>

1. Zabeležite karticu, izvorno poreklo i lokalni selektor pouzdanog peer-a. Registrujte drugi peer čija kartica ima isto `name`, ali čiji URL vodi do krajnje tačke koju kontrolišete.
2. Pokrenite operaciju koja bira pouzdanog peer-a po imenu. Isprobajte oba redosleda registracije i, ako imena postaju identifikatori alata, uobičajenu normalizaciju imena na hostu. Zabeležite koja krajnja tačka prima marker i koji agent vraća odgovor.
3. Promenite samo ime druge kartice i ponovite test. Ako zahtev stigne do druge krajnje tačke samo u slučaju sukoba imena, to dokazuje slanje pogrešnom peer-u. Posebno proverite da li je zaista priložen neki osetljiv kontekst ili kredencijal; sam sukob imena **ne** dokazuje prenos kredencijala ili ovlašćenja alata.

Ako pozivalac koristi fiksnu krajnju tačku vezanu za izvorno poreklo, umesto da razrešava ime kartice, ovaj test nije primenljiv.<sup>[[5]](#references)</sup> Za naknadne odgovore zlonamernog peer-a i uticaj prompt injection-a, pogledajte [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary).

## Testiranje A2A krajnjih tačaka

### Slanje zadatka bez autentifikacije

Pošaljite minimalnu poruku bez kredencijala na svaki `url` naveden na kartici:

```bash
# 0.2 / 0.3 style
curl -s https://target/a2a -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"message/send",
  "params":{"message":{"role":"user","messageId":"6f1c2b9e-0000-4000-8000-000000000001",
            "parts":[{"kind":"text","text":"Reply only with the word PONG."}]}}}'

# 1.0 style
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER","messageId":"6f1c2b9e-0000-4000-8000-000000000002",
            "parts":[{"text":"Reply only with the word PONG."}]}}}'
```

Rezultat `Task` ili `Message` sa `PONG`, kada kartica navodi bezbednosnu šemu, znači da se autentifikacija ne sprovodi na RPC endpointu (može da se sprovodi samo na UI-ju ili na kartici). Ako kartica ne navodi šemu, proverite čemu agent može da pristupi preko svojih veština: agent bez autentifikacije koji može da čita interne podatke ili poziva alate predstavlja isto što i API bez autentifikacije za te alate.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Specifikacija zahteva da server pri svakom zahtevu proveri da li pozivalac sme da pristupi zadatku i da ograniči `ListTasks` na pozivaoca, čak i kada filter nije naveden.<sup>[[1]](#references)</sup> Testirajte ovo sa dva identiteta (A i B):

1. Kao A, kreirajte zadatak i sačuvajte njegov `id` i `contextId`.
2. Kao B (ili bez akreditiva), pozovite `tasks/get` / `GetTask` sa A-ovim `id`, a zatim pozovite `ListTasks` bez parametara.
3. Takođe pokušajte da otkažete A-ov zadatak i da se pretplatite na njega, pa pošaljite novu poruku kao B koja sadrži A-ov `taskId` ili `contextId` (time bi se tekst koji je poslao B dodao u A-ov razgovor).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Ranjivo: B dobija A-ovu istoriju, artefakte ili status, ili može da promeni A-ov zadatak. Bezbedno: `TaskNotFoundError`, bez razlike između „postoji, ali nije tvoj“ i „ne postoji“.<sup>[[1]](#references)</sup> ID-jevi zadataka su često UUID-jevi, zato ih potražite na mestima gde mogu da procure (deljeni linkovi, logovi, sadržaji push obaveštenja, poruke o greškama).

### SSRF preko webhook-a za push obaveštenja

Kada je `capabilities.pushNotifications` true, klijent agentu daje URL webhook-a, a agent kasnije šalje `POST` zahteve sa ažuriranjima zadataka na taj URL. Specifikacija kaže da agenti treba da odbijaju privatne opsege, localhost i link-local adrese i da koriste allowlist-e.<sup>[[1]](#references)</sup> Napravite zadatak, registrujte konfiguraciju push obaveštenja čiji `url` pokazuje na vaš OAST host da biste potvrdili odlazne zahteve, a zatim (samo ako to opseg dozvoljava) pokušajte i sa internim ciljevima kao što su `http://127.0.0.1:<port>/` ili `http://169.254.169.254/`. Uporedite greške i vreme odziva da biste mapirali interne servise. Agent ovim zahtevima dodaje i konfigurisano zaglavlje za autentifikaciju, zato proverite da li se ono šalje hostu koji je izabrao napadač kada možete da promenite URL konfiguracije drugog korisnika. Pogledajte [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Delovi sa file URL-om kao druga SSRF ulazna tačka

A2A 1.0 dozvoljava da poruka ili artefakt sadrže referencu na datoteku kao `Part` sa `url` (0.3 koristi `kind: "file"` i `file.uri`).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> Protokol prenosi referencu; njeno preuzimanje je ponašanje aplikacije, a ne zahtev A2A SDK-a.<sup>[[6]](#references)</sup> Ovo je odvojeno od URL-a callback-a za push obaveštenja iznad. Testirajte oba smera: datoteku koju klijent šalje A2A serveru i URL datoteke koji peer sa nižim nivoom poverenja vraća orkestratoru.<sup>[[1]](#references)[[6]](#references)</sup>

Za autorizovani 1.0 JSON-RPC endpoint, zamenite uobičajeni tekstualni deo URL-om do jedinstvene OAST putanje i proverite **koja komponenta** šalje zahtev:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Samo ako ga primalac dereferencira, testirajte odredišta unutar opsega, preusmeravanja i promene DNS rezolucije pomoću [SSRF workflow](../pentesting-web/ssrf-server-side-request-forgery/). Važeći `Part` ili uspešan odgovor na zadatak sami po sebi ne dokazuju SSRF; potvrdite da li je došlo do preuzimanja sa odredišta i da li sadržaj stiže do agenta.<sup>[[6]](#references)</sup>

### Pristup proširenoj agent kartici

`GetExtendedAgentCard` mora da zahteva autentifikaciju i može da vrati više veština i konfiguracije nego javna kartica.<sup>[[1]](#references)</sup> Pozovite ga bez akreditiva i sa identitetom niskih privilegija, pa uporedite rezultat sa javnom karticom.

### Konfiguracija push obaveštenja i curenje akreditiva tokom zadatka

Konfiguracije push obaveštenja čuvaju URL webhook-a i akreditive koje agent šalje na njega. Specifikacija zahteva da se pri svakoj operaciji nad konfiguracijom push obaveštenja (create, get, list, delete) proveri da li pozivalac ima pristup zadatku.<sup>[[1]](#references)</sup> Ponovite test sa dva identiteta iz [odeljka o task IDOR](#task-idor-tasksget-gettask-cancel-subscribe) na ovim rutama. Konfiguracija drugog korisnika koja može da se pročita otkriva webhook token, a ako može da se menja, ažuriranja zadataka tog korisnika mogu se preusmeriti na vaš host.

Kada je agentu potrebno dodatno ovlašćenje tokom zadatka, on prebacuje zadatak u `TASK_STATE_AUTH_REQUIRED`. Klijent može da obezbedi ovlašćenje van kanala; specifikacija navodi da agenti moraju da prime akreditive van kanala, osim ako nije dogovoren mehanizam unutar kanala. Razmena unutar kanala može da prenese akreditiv kroz lanac A2A agenata i da ga izloži svakom agentu u tom lancu.<sup>[[1]](#references)</sup> U testu orkestratora proverite da li se akreditiv koji korisnik daje za jednog nizvodnog agenta pojavljuje u porukama, artefaktima ili istoriji zadataka koje drugi agenti (ili drugi korisnici putem task IDOR-a) mogu da pročitaju.

Polja agent kartice i rezultati zadataka takođe su nepouzdan ulaz za agenta koji ih poziva. Testirajte ih tehnikama indirektne prompt injection u odeljku [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) i proverama poverenja između agenata u odeljku [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).



## References

- [1] [Specifikacija protokola A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Predstavljamo Agent2Agent Protocol (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Specifikacija A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Specifikacija A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Napadi sudarom imena agenata u multi-agent sistemima](https://arxiv.org/abs/2609.27624)
- [6] [Bezbednosni vodič za A2A .NET SDK](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [Vodič za migraciju na A2A Python v1.0](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
