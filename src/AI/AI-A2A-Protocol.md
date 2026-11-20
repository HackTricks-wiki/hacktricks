# Bezpieczeństwo protokołu A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## Czym jest A2A

A2A (Agent2Agent) to otwarty protokół, który pozwala jednemu agentowi AI wykryć innego agenta i zlecić mu pracę przez HTTP. MCP łączy agenta z **narzędziami i danymi**; A2A łączy agenta z **innymi agentami**, które zwykle są zdalnymi usługami należącymi do innego zespołu lub firmy. Serwer A2A to web API z agentem LLM po drugiej stronie, dlatego własne obiekty protokołu (karty agentów, zadania, webhooki powiadomień push, rozszerzone karty) wymagają dodatkowych kontroli uwierzytelniania, IDOR i SSRF podczas standardowego testowania API.<sup>[[1]](#references)[[2]](#references)</sup>

Główne elementy:

- **Agent Card:** dokument JSON opisujący agenta: nazwę, opis, umiejętności, adresy URL usługi, obsługiwane transporty, możliwości (strumieniowanie, powiadomienia push, rozszerzona karta) oraz `securitySchemes`, których musi używać klient. Jest publikowany pod adresem `https://<host>/.well-known/agent-card.json`. Starsze wdrożenia zgodne ze specyfikacją 0.2.x używają `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** jednostka pracy. Wiadomość tworzy zadanie (z wygenerowanymi przez serwer wartościami `id` i `contextId`), a klient może później je odczytać, anulować lub subskrybować.<sup>[[1]](#references)</sup>
- **Transporty:** JSON-RPC 2.0 przez HTTP (z SSE do strumieniowania), gRPC oraz powiązanie REST HTTP+JSON.<sup>[[1]](#references)</sup>
- **Uwierzytelnianie:** dane uwierzytelniające umieszcza się w nagłówkach HTTP (na przykład `Authorization: Bearer ...`), nigdy w treści JSON-RPC. Agent Card wskazuje wymagany schemat.<sup>[[1]](#references)</sup>

Nazwy metod zmieniały się między wersjami, dlatego sprawdź oba zestawy:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operacja | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Wyślij wiadomość | `message/send` | `SendMessage` | `POST /message:send` |
| Wysyłanie strumieniowe | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Pobierz zadanie | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Wyświetl listę zadań | - | `ListTasks` | `GET /tasks` |
| Anuluj zadanie | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Konfiguracja powiadomień push | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Rozszerzona karta | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Specyfikacja 1.0 używa nagłówka `A2A-Version` (lub parametru żądania) do wyboru wersji; żądania bez niego są traktowane jako wersja 0.3.<sup>[[1]](#references)</sup>

## Wykrywanie

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Z karty zanotuj:

- Każde `url` usługi: w wersji 1.0 znajdują się one w `supportedInterfaces`, natomiast starsze karty mogą udostępniać `url` na najwyższym poziomie. Zapisz każdy endpoint i transport, w tym wewnętrzne nazwy hostów, staging URLs i alternatywne porty.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: pokazują, co agent potrafi oraz jakie narzędzia lub dane się za nim kryją.
- `securitySchemes` / `security`: jeśli są puste lub ich brakuje, prawdopodobnie agent jest przeznaczony do wywoływania bez poświadczeń.
- `capabilities.pushNotifications` i `capabilities.extendedAgentCard` (w wersji 0.3 `supportsAuthenticatedExtendedCard`).

Specyfikacja mówi, że publiczna karta nie powinna zawierać poświadczeń ani wewnętrznych szczegółów implementacji, więc wewnętrzne URL-e, klucze lub szczegółowe listy narzędzi w publicznej karcie same w sobie stanowią znalezisko.<sup>[[1]](#references)</sup>

### Kolizja nazwy Agent Card w hoście wieloagentowym

`name` karty to czytelna dla człowieka etykieta, a nie stabilna tożsamość routingu.<sup>[[1]](#references)[[5]](#references)</sup> Jeśli host zarejestruje dwóch różnych zdalnych peerów pod tą samą lokalną nazwą, jego drzewo agentów, wygenerowana nazwa narzędzia, mapa klientów lub trasa brokera mogą skierować zadanie przeznaczone dla zaufanego peera do drugiego peera.<sup>[[5]](#references)</sup> Wymaga to dopuszczenia peera kontrolowanego przez atakującego do **tej samej przestrzeni nazw routingu**; samo opublikowanie zduplikowanej karty w Internecie nie wystarczy.<sup>[[5]](#references)</sup>

Przetestuj ścieżkę hosta od **dopuszczenia do dyspozycji** z użyciem dwóch kontrolowanych peerów, różnych URL-i i nieszkodliwego znacznika:<sup>[[5]](#references)</sup>

1. Zapisz kartę zaufanego peera, jego origin i lokalny selektor. Zarejestruj drugiego peera, którego karta ma tę samą wartość `name`, ale którego URL wskazuje na kontrolowany przez Ciebie endpoint.
2. Uruchom operację, która wybiera zaufanego peera po nazwie. Wypróbuj obie kolejności rejestracji, a jeśli nazwy stają się identyfikatorami narzędzi — zastosuj zwykłą normalizację nazw używaną przez hosta. Sprawdź, który endpoint otrzymuje znacznik i który agent zwraca odpowiedź.
3. Zmień tylko nazwę drugiej karty i powtórz test. Jeśli żądanie dociera do drugiego endpointu wyłącznie w przypadku kolizji, oznacza to, że zostało skierowane do niewłaściwego peera. Osobno sprawdź, czy rzeczywiście dołączono jakikolwiek poufny kontekst lub poświadczenie; sama kolizja nazw **nie** dowodzi przekazania poświadczeń ani uprawnień do narzędzi.

Jeśli wywołujący używa stałego endpointu powiązanego z origin, zamiast rozwiązywać nazwę karty, ten test nie ma zastosowania.<sup>[[5]](#references)</sup> W kwestii późniejszych odpowiedzi złośliwego peera i skutków prompt injection zapoznaj się z [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary).

## Testowanie endpointów A2A

### Wysyłanie zadań bez uwierzytelnienia

Wyślij minimalną wiadomość bez żadnych poświadczeń do każdego `url` wymienionego w karcie:

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

Wynik `Task` lub `Message` z `PONG`, gdy karta deklaruje schemat zabezpieczeń, oznacza, że uwierzytelnianie nie jest wymuszane na endpointcie RPC (może być wymuszane tylko w UI lub na karcie). Jeśli karta nie deklaruje żadnego schematu, sprawdź, do czego mają dostęp umiejętności agenta: nieuwierzytelniony agent, który może odczytywać dane wewnętrzne lub wywoływać narzędzia, stanowi takie samo zagrożenie jak nieuwierzytelnione API udostępniające te narzędzia.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Spec wymaga, aby serwer przy każdym żądaniu sprawdzał, czy wywołujący może uzyskać dostęp do zadania, oraz ograniczał `ListTasks` do zadań wywołującego, nawet gdy nie podano żadnego filtra.<sup>[[1]](#references)</sup> Przetestuj to z dwiema tożsamościami (A i B):

1. Jako A utwórz zadanie i zapisz jego `id` oraz `contextId`.
2. Jako B (lub bez danych uwierzytelniających) wywołaj `tasks/get` / `GetTask` z `id` należącym do A, a następnie `ListTasks` bez parametrów.
3. Spróbuj też anulować zadanie A i zasubskrybować je, a jako B wyślij nową wiadomość zawierającą `taskId` lub `contextId` należące do A (spowoduje to dodanie tekstu B do konwersacji A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Podatne: B otrzymuje historię, artefakty lub stan A albo może zmienić jego zadanie. Bezpieczne: `TaskNotFoundError`, bez rozróżnienia między „istnieje, ale nie należy do ciebie” a „nie istnieje”.<sup>[[1]](#references)</sup> Identyfikatory zadań to często UUID, więc szukaj ich tam, gdzie mogą wyciekać (współdzielone linki, logi, payloady powiadomień push, komunikaty o błędach).

### SSRF przez webhook powiadomień push

Gdy `capabilities.pushNotifications` ma wartość true, klient przekazuje agentowi adres URL webhooka, a agent później wysyła na ten adres żądania `POST` z aktualizacjami zadań. Specyfikacja mówi, że agenci powinni odrzucać prywatne zakresy adresów, localhost i adresy link-local oraz korzystać z list dozwolonych.<sup>[[1]](#references)</sup> Utwórz zadanie, zarejestruj konfigurację powiadomień push, której `url` wskazuje na twój host OAST, aby potwierdzić żądania wychodzące, a następnie (tylko jeśli pozwala na to zakres testu) skieruj ją na cele wewnętrzne, takie jak `http://127.0.0.1:<port>/` lub `http://169.254.169.254/`. Porównaj błędy i czas odpowiedzi, aby zmapować usługi wewnętrzne. Agent dodaje też skonfigurowany nagłówek uwierzytelniający do tych żądań, więc sprawdź, czy nie jest wysyłany do hosta wybranego przez atakującego, jeśli możesz zmienić URL konfiguracji innego użytkownika. Zobacz [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Części File-URL jako drugi punkt wejścia SSRF

A2A 1.0 pozwala, aby wiadomość lub artefakt zawierały odwołanie do pliku jako `Part` z `url` (w wersji 0.3 używa się `kind: "file"` i `file.uri`).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> Protokół przenosi odwołanie; pobieranie pliku jest działaniem aplikacji, a nie wymogiem SDK A2A.<sup>[[6]](#references)</sup> To osobny mechanizm od omówionego wyżej URL-a callbacku powiadomień push. Przetestuj oba kierunki: plik dostarczony przez klienta do serwera A2A oraz URL pliku zwrócony przez peer o niższym poziomie zaufania do orkiestratora.<sup>[[1]](#references)[[6]](#references)</sup>

W autoryzowanym punkcie końcowym JSON-RPC 1.0 zastąp zwykłą część tekstową adresem URL do unikalnej ścieżki OAST i sprawdź, **który komponent** wysyła żądanie:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Tylko jeśli odbiorca wykona dereferencję, testuj objęte zakresem wewnętrzne cele, przekierowania i zmiany rozwiązywania DNS, korzystając z [workflow SSRF](../pentesting-web/ssrf-server-side-request-forgery/). Samo prawidłowe `Part` lub pomyślna odpowiedź na zadanie nie potwierdzają SSRF; potwierdź pobranie danych z miejsca docelowego oraz to, czy pobrana zawartość dociera do agenta.<sup>[[6]](#references)</sup>

### Dostęp do rozszerzonej karty agenta

`GetExtendedAgentCard` musi wymagać uwierzytelnienia i może zwracać więcej umiejętności oraz konfiguracji niż karta publiczna.<sup>[[1]](#references)</sup> Wywołaj tę metodę bez poświadczeń i z tożsamością o niskich uprawnieniach, a następnie porównaj wynik z kartą publiczną.

### Konfiguracja powiadomień push i wycieki poświadczeń w trakcie zadania

Konfiguracje powiadomień push przechowują URL webhooka oraz poświadczenia wysyłane przez agenta. Specyfikacja wymaga, aby każda operacja na konfiguracji powiadomień push (utworzenie, odczyt, wyświetlenie listy, usunięcie) weryfikowała, czy wywołujący może uzyskać dostęp do zadania.<sup>[[1]](#references)</sup> Powtórz test z dwiema tożsamościami opisany w [sekcji task IDOR](#task-idor-tasksget-gettask-cancel-subscribe) dla tych tras. Odczytywalna konfiguracja innego użytkownika ujawnia token webhooka, a możliwość jej modyfikacji przekierowuje aktualizacje zadań tego użytkownika na Twój host.

Gdy agent potrzebuje dodatkowego uwierzytelnienia w trakcie zadania, zmienia stan zadania na `TASK_STATE_AUTH_REQUIRED`. Klient może zorganizować uwierzytelnienie poza pasmem; specyfikacja mówi, że agenci muszą otrzymywać poświadczenia poza pasmem, chyba że uzgodniono mechanizm in-band. Wymiana in-band może przekazać poświadczenie przez łańcuch agentów A2A i ujawnić je każdemu agentowi w tym łańcuchu.<sup>[[1]](#references)</sup> Podczas testu orkiestratora sprawdź, czy poświadczenie podane przez użytkownika dla jednego agenta dalszego etapu pojawia się w wiadomościach, artefaktach lub historii zadania, które mogą odczytać inni agenci (lub inni użytkownicy przez task IDOR).

Pola karty agenta i wyniki zadań są również niezaufanymi danymi wejściowymi dla agenta wywołującego. Testuj je za pomocą technik pośredniego prompt injection opisanych w [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) oraz kontroli zaufania między agentami z [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).



## References

- [1] [Specyfikacja protokołu A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Blog Google Developers — Zapowiedź protokołu Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Specyfikacja A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Specyfikacja A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Ataki wykorzystujące kolizje nazw agentów w systemach wieloagentowych](https://arxiv.org/abs/2609.27624)
- [6] [Przewodnik bezpieczeństwa A2A .NET SDK](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [Przewodnik migracji A2A Python v1.0](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
