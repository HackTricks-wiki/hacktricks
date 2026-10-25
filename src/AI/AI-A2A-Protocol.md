# A2A (Agent2Agent) Protocol Security

{{#include ../banners/hacktricks-training.md}}

## Šta je A2A

A2A (Agent2Agent) je otvoreni protokol koji omogućava jednom AI agentu da otkrije drugog agenta i pošalje mu zadatak preko HTTP-a. MCP povezuje agenta sa **alatima i podacima**; A2A povezuje agenta sa **drugim agentima**, koji su obično udaljene usluge u vlasništvu drugog tima ili kompanije. A2A server je veb API sa LLM agentom u pozadini, pa sopstveni objekti protokola (agent cards, tasks, push-notification webhooks, extended cards) zahtevaju posebne provere autentifikacije, IDOR-a i SSRF-a, pored uobičajenog testiranja API-ja.<sup>[[1]](#references)[[2]](#references)</sup>

Glavni delovi su:

- **Agent Card:** JSON dokument koji opisuje agenta: ime, opis, veštine, URL-ove usluga, podržane transporte, mogućnosti (streaming, push notifications, extended card) i `securitySchemes` koje klijent mora da koristi. Objavljuje se na `https://<host>/.well-known/agent-card.json`. Starije implementacije koje prate spec 0.2.x koriste `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** jedinica posla. Poruka kreira task (sa serverski generisanim `id` i `contextId`), a klijent ga kasnije čita, otkazuje ili se pretplaćuje na njega.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 preko HTTP-a (sa SSE za streaming), gRPC i HTTP+JSON REST binding.<sup>[[1]](#references)</sup>
- **Authentication:** akreditivi se šalju u HTTP zaglavljima (na primer `Authorization: Bearer ...`), nikada unutar JSON-RPC payload-a. Agent card navodi koja je šema obavezna.<sup>[[1]](#references)</sup>

Nazivi metoda su se menjali između verzija, pa isprobajte oba skupa:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operacija | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Slanje poruke | `message/send` | `SendMessage` | `POST /message:send` |
| Streaming slanje | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Dohvatanje task-a | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Navođenje task-ova | - | `ListTasks` | `GET /tasks` |
| Otkazivanje task-a | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Konfiguracija push notification-a | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Specifikacija 1.0 koristi zaglavlje `A2A-Version` (ili parametar zahteva) za izbor verzije; zahtevi bez njega tretiraju se kao 0.3.<sup>[[1]](#references)</sup>

## Otkrivanje

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Sa kartice zabeležite:

- Svaki servisni `url` (često interno ime hosta, staging URL ili drugi port od onog na javnom sajtu).
- `skills`: pokazuju šta agent može da radi i koji alati ili podaci stoje iza njega.
- `securitySchemes` / `security`: ako su prazni ili nedostaju, agent je verovatno predviđen za pozivanje bez kredencijala.
- `capabilities.pushNotifications` i `capabilities.extendedAgentCard` (u verziji 0.3 `supportsAuthenticatedExtendedCard`).

Specifikacija kaže da javna kartica ne bi trebalo da sadrži kredencijale ili detalje interne implementacije, tako da su interni URL-ovi, ključevi ili detaljni spiskovi alata na javnoj kartici već nalaz.<sup>[[1]](#references)</sup>

## Testiranje A2A krajnjih tačaka

### Slanje zadatka bez autentifikacije

Pošaljite minimalnu poruku bez ikakvih kredencijala na svaki `url` naveden na kartici:

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

`Task` ili `Message` rezultat sa `PONG`, kada kartica navodi bezbednosnu šemu, znači da se autentifikacija ne sprovodi na RPC endpointu (možda se sprovodi samo na UI-ju ili na kartici). Ako kartica ne navodi šemu, proverite do čega mogu da dopru agentove veštine: neautentifikovani agent koji može da čita interne podatke ili poziva alate predstavlja isto što i neautentifikovani API za te alate.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Specifikacija zahteva da server pri svakom zahtevu proveri da li pozivalac sme da pristupi zadatku i da ograniči `ListTasks` na pozivaoca, čak i kada nije naveden nijedan filter.<sup>[[1]](#references)</sup> Testirajte ovo sa dva identiteta (A i B):

1. Kao A, kreirajte zadatak i sačuvajte njegov `id` i `contextId`.
2. Kao B (ili bez kredencijala), pozovite `tasks/get` / `GetTask` sa A-ovim `id`, a zatim pozovite `ListTasks` bez parametara.
3. Isprobajte i cancel i subscribe nad A-ovim zadatkom, a zatim pošaljite novu poruku kao B, u koju uključite A-ov `taskId` или `contextId` (tako bi se B-ов tekst dodao u A-ов razgovor).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Ranjivo: B prima istoriju, artefakte ili status od A, ili može da promeni A-ov task. Bezbedno: `TaskNotFoundError`, bez razlike između „postoji, ali nije tvoj“ i „ne postoji“.<sup>[[1]](#references)</sup> ID-jevi taskova su često UUID-ovi, zato ih potraži na mestima gde mogu da procure (deljeni linkovi, logovi, payload-i push obaveštenja, poruke o greškama).

### SSRF webhook-a push obaveštenja

Kada je `capabilities.pushNotifications` true, klijent agentu prosleđuje URL webhook-a, a agent kasnije šalje `POST` zahteve sa ažuriranjima taska na taj URL. Specifikacija kaže da agenti treba da odbijaju privatne opsege, localhost i link-local adrese i da koriste allowliste.<sup>[[1]](#references)</sup> Kreiraj task, registruj konfiguraciju push obaveštenja čiji `url` upućuje na tvoj OAST host da potvrdiš odlazne zahteve, a zatim (samo ako opseg to dozvoljava) ciljaj interne adrese kao što su `http://127.0.0.1:<port>/` ili `http://169.254.169.254/`. Uporedi greške i vreme odziva da mapiraš interne servise. Agent ovim zahtevima dodaje i konfigurisano zaglavlje za autentifikaciju, zato proveri da li se ono šalje hostu kog kontroliše napadač kada možeš da promeniš URL konfiguracije drugog korisnika. Pogledaj [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Pristup proširenoj kartici agenta

`GetExtendedAgentCard` mora da zahteva autentifikaciju i može da vrati više veština i konfiguracije nego javna kartica.<sup>[[1]](#references)</sup> Pozovi ga bez akreditiva i sa identitetom sa niskim privilegijama, pa uporedi rezultat sa javnom karticom.

### Konfiguracija push obaveštenja i curenje akreditiva u task-u

Konfiguracije push obaveštenja čuvaju URL webhook-a i akreditive koje agent šalje na njega. Specifikacija zahteva da svaka operacija nad konfiguracijom push obaveštenja (create, get, list, delete) proveri da li pozivalac ima pristup tasku.<sup>[[1]](#references)</sup> Ponovi test sa dva identiteta iz [odeljka o IDOR-u taskova](#task-idor-tasksget-gettask-cancel-subscribe) na ovim rutama. Konfiguracija drugog korisnika koja može da se pročita otkriva token webhook-a, a ona koju može da menja preusmerava ažuriranja taskova tog korisnika na tvoj host.

Kada agentu tokom taska zatreba dodatna autorizacija, on prebacuje task u `TASK_STATE_AUTH_REQUIRED`. Klijent može da organizuje autorizaciju van kanala; specifikacija kaže da agenti moraju da dobiju akreditive van kanala, osim ako nije dogovoren mehanizam unutar kanala. Razmena unutar kanala može da prosledi akreditiv kroz lanac A2A agenata i izloži ga svakom agentu u tom lancu.<sup>[[1]](#references)</sup> U testu orkestratora proveri da li se akreditiv koji korisnik daje za jednog nizvodnog agenta pojavljuje u porukama, artefaktima ili istoriji taska koje mogu da pročitaju drugi agenti (ili drugi korisnici preko IDOR-a taskova).

Polja kartice agenta i rezultati taska takođe su nepouzdani ulazi za agenta koji ih poziva. Testiraj ih tehnikama indirektnog prompt injection-a iz [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) i proverama poverenja između agenata iz [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [Specifikacija A2A protokola](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Najava Agent2Agent protokola (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Specifikacija A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Specifikacija A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
