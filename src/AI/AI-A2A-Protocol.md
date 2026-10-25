# Bezpieczeństwo protokołu A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## Czym jest A2A

A2A (Agent2Agent) to otwarty protokół, który pozwala jednemu agentowi AI odkryć innego agenta i zlecić mu zadanie przez HTTP. MCP łączy agenta z **narzędziami i danymi**; A2A łączy agenta z **innymi agentami**, które zwykle są zdalnymi usługami należącymi do innego zespołu lub firmy. Serwer A2A to web API z agentem LLM po drugiej stronie, dlatego własne obiekty protokołu (karty agentów, zadania, webhooki powiadomień push, karty rozszerzone) wymagają konkretnych testów uwierzytelniania, IDOR i SSRF podczas standardowego testowania API.<sup>[[1]](#references)[[2]](#references)</sup>

Główne elementy:

- **Agent Card:** dokument JSON opisujący agenta: nazwę, opis, umiejętności, adresy URL usług, obsługiwane transporty, możliwości (streaming, powiadomienia push, karta rozszerzona) oraz `securitySchemes`, których musi użyć klient. Jest publikowany pod adresem `https://<host>/.well-known/agent-card.json`. Starsze wdrożenia zgodne ze specyfikacją 0.2.x używają `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** jednostka pracy. Wiadomość tworzy zadanie (z wygenerowanymi przez serwer `id` i `contextId`), a klient później je odczytuje, anuluje lub subskrybuje.<sup>[[1]](#references)</sup>
- **Transporty:** JSON-RPC 2.0 przez HTTP (z SSE do streamingu), gRPC oraz powiązanie REST HTTP+JSON.<sup>[[1]](#references)</sup>
- **Uwierzytelnianie:** dane uwierzytelniające są przekazywane w nagłówkach HTTP (na przykład `Authorization: Bearer ...`), nigdy w payloadzie JSON-RPC. Karta agenta określa wymagany schemat.<sup>[[1]](#references)</sup>

Nazwy metod zmieniały się między wersjami, dlatego wypróbuj oba zestawy:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operacja | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Wyślij wiadomość | `message/send` | `SendMessage` | `POST /message:send` |
| Wyślij strumieniowo | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Pobierz zadanie | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Wyświetl listę zadań | - | `ListTasks` | `GET /tasks` |
| Anuluj zadanie | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Konfiguracja powiadomień push | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Karta rozszerzona | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Specyfikacja 1.0 używa nagłówka `A2A-Version` (lub parametru żądania) do wyboru wersji, a żądania bez niego są traktowane jako wersja 0.3.<sup>[[1]](#references)</sup>

## Odkrywanie

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Z karty zapisz:

- Każdy `url` usługi (często wewnętrzną nazwę hosta, adres URL środowiska staging lub inny port niż w publicznej witrynie).
- `skills`: pokazują, co agent potrafi i jakie narzędzia lub dane są z nim powiązane.
- `securitySchemes` / `security`: jeśli są puste lub ich brakuje, agent prawdopodobnie ma być wywoływany bez poświadczeń.
- `capabilities.pushNotifications` i `capabilities.extendedAgentCard` (w wersji 0.3 `supportsAuthenticatedExtendedCard`).

Specyfikacja mówi, że publiczna karta nie powinna zawierać poświadczeń ani szczegółów wewnętrznej implementacji, więc wewnętrzne adresy URL, klucze lub szczegółowe listy narzędzi w publicznej karcie już stanowią finding.<sup>[[1]](#references)</sup>

## Testowanie endpointów A2A

### Wysyłanie zadań bez uwierzytelniania

Wyślij minimalną wiadomość bez żadnych poświadczeń na każdy `url` wymieniony w karcie:

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

Wynik `Task` lub `Message` z `PONG`, gdy karta deklaruje schemat zabezpieczeń, oznacza, że uwierzytelnianie nie jest wymuszane na endpointcie RPC (może być wymuszane tylko w UI lub na karcie). Jeśli karta nie deklaruje żadnego schematu, sprawdź, do czego mogą uzyskać dostęp umiejętności agenta: nieuwierzytelniony agent, który może odczytywać wewnętrzne dane lub wywoływać narzędzia, stanowi taki sam problem jak nieuwierzytelnione API udostępniające te narzędzia.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Specyfikacja wymaga, aby serwer przy każdym żądaniu sprawdzał, czy wywołujący może uzyskać dostęp do zadania, oraz ograniczał `ListTasks` do zadań wywołującego, nawet jeśli nie podano żadnego filtra.<sup>[[1]](#references)</sup> Przetestuj to przy użyciu dwóch tożsamości (A i B):

1. Jako A utwórz zadanie i zapisz jego `id` oraz `contextId`.
2. Jako B (lub bez danych uwierzytelniających) wywołaj `tasks/get` / `GetTask` z `id` A, a następnie `ListTasks` bez parametrów.
3. Spróbuj również anulować zadanie A i zasubskrybować je, a także wysłać jako B nową wiadomość zawierającą `taskId` lub `contextId` A (dodałoby to tekst B do konwersacji A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Podatne: B otrzymuje historię, artefakty lub status A albo może zmienić zadanie A. Bezpieczne: `TaskNotFoundError`, bez różnicy między „istnieje, ale nie należy do ciebie” a „nie istnieje”.<sup>[[1]](#references)</sup> Identyfikatory zadań to często UUID-y, więc szukaj ich w miejscach, w których mogą wyciec (udostępnione linki, logi, ładunki powiadomień push, komunikaty o błędach).

### SSRF przez webhook powiadomień push

Gdy `capabilities.pushNotifications` ma wartość true, klient przekazuje agentowi adres URL webhooka, a agent wysyła później żądania `POST` z aktualizacjami zadania na ten adres. Specyfikacja mówi, że agenci powinni odrzucać prywatne zakresy adresów, localhost i adresy link-local oraz stosować listy dozwolonych adresów.<sup>[[1]](#references)</sup> Utwórz zadanie, zarejestruj konfigurację powiadomień push, której `url` wskazuje na twój host OAST, aby potwierdzić żądania wychodzące, a następnie (tylko jeśli pozwala na to zakres testów) skieruj ją na cele wewnętrzne, takie jak `http://127.0.0.1:<port>/` lub `http://169.254.169.254/`. Porównaj błędy i czas odpowiedzi, aby zmapować usługi wewnętrzne. Agent dodaje też do tych żądań skonfigurowany nagłówek uwierzytelniający, więc sprawdź, czy nie jest wysyłany do hosta wybranego przez atakującego, jeśli możesz zmienić URL konfiguracji innego użytkownika. Zobacz [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Dostęp do rozszerzonej karty agenta

`GetExtendedAgentCard` musi wymagać uwierzytelnienia i może zwracać więcej umiejętności oraz konfiguracji niż karta publiczna.<sup>[[1]](#references)</sup> Wywołaj tę metodę bez poświadczeń i z tożsamością o niskich uprawnieniach, a następnie porównaj wynik z kartą publiczną.

### Konfiguracja powiadomień push i wycieki poświadczeń w ramach zadania

Konfiguracje powiadomień push przechowują adres URL webhooka i poświadczenia wysyłane na ten adres przez agenta. Specyfikacja wymaga, aby każda operacja na konfiguracji powiadomień push (tworzenie, odczyt, listowanie, usuwanie) weryfikowała, czy wywołujący może uzyskać dostęp do zadania.<sup>[[1]](#references)</sup> Powtórz test z dwiema tożsamościami opisany w [sekcji task IDOR](#task-idor-tasksget-gettask-cancel-subscribe) dla tych endpointów. Możliwość odczytu konfiguracji innego użytkownika ujawnia token webhooka, a możliwość jej modyfikacji przekierowuje aktualizacje zadań tego użytkownika na twój host.

Gdy agent potrzebuje dodatkowego uwierzytelnienia podczas zadania, zmienia stan zadania na `TASK_STATE_AUTH_REQUIRED`. Klient może zorganizować uwierzytelnienie poza pasmem; specyfikacja mówi, że agenci muszą otrzymywać poświadczenia poza pasmem, chyba że uzgodniono mechanizm in-band. Wymiana in-band może przekazać poświadczenie w łańcuchu agentów A2A i ujawnić je każdemu agentowi w tym łańcuchu.<sup>[[1]](#references)</sup> W teście orkiestratora sprawdź, czy poświadczenie przekazane przez użytkownika jednemu agentowi podrzędnemu pojawia się w wiadomościach, artefaktach lub historii zadania, które mogą odczytać inni agenci (lub inni użytkownicy przez task IDOR).

Pola karty agenta i wyniki zadań również są niezaufanymi danymi wejściowymi dla agenta wywołującego. Przetestuj je technikami indirect prompt injection opisanymi w [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) oraz kontrolami zaufania między agentami z [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [Specyfikacja protokołu A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Blog Google Developers — ogłoszenie protokołu Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Specyfikacja A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Specyfikacja A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
