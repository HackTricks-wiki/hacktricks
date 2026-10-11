# Metodologia bezpieczeństwa agentów AI

{{#include ../banners/hacktricks-training.md}}

Ocena agenta powinna śledzić **ścieżkę od danych wejściowych kontrolowanych przez atakującego do zewnętrznie obserwowalnego efektu**. Jailbreaking, zmiany osobowości i ujawnienie system promptu dowodzą, że można wpływać na kanał rozumowania, ale najpoważniejszym znaleziskiem jest łańcuch prowadzący do dostępu do danych, nieautoryzowanego działania narzędzia, downstream injection sink, utrwalenia lub innego agenta.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) przydaje się do oznaczania zakresu testów (przejęcie celu, niewłaściwe użycie narzędzi, nadużycie uprawnień, łańcuch dostaw, wykonanie kodu, zatruwanie pamięci, zaufanie między agentami, awarie kaskadowe, zaufanie człowieka i nieposłuszne agenty). Używaj tych oznaczeń po zbudowaniu ścieżki ataku od początku do końca, zamiast traktować nieoczekiwany tekst modelu jako koniec testu.<sup>[[1]](#references)[[2]](#references)</sup>

## Zbuduj mapę celu

Przed przygotowaniem payloadów zapisz te pięć wymiarów dla każdego przepływu pracy agenta:<sup>[[2]](#references)</sup>

| Wymiar | Co należy zinwentaryzować | Pytanie dotyczące bezpieczeństwa |
|---|---|---|
| **Niezaufane dane wejściowe** | Parametry czatu/API, URL-e, dokumenty, e-maile, zgłoszenia, wpisy kalendarza, pobrane fragmenty, pamięć, wyniki narzędzi i komunikaty agentów równorzędnych | Gdzie atakujący może umieścić treść, która później trafi do kontekstu modelu? |
| **Narzędzia** | Nazwy i schematy narzędzi, skutki uboczne, automatyczne wykonywanie, zachowanie dotyczące potwierdzeń i narzędzia ładowane dynamicznie | Które wywołania odczytują sekrety, zapisują dane, wysyłają wiadomości, usuwają dane, wykonują kod lub przekazują wartość? |
| **Uprawnienia** | Delegowanie przez użytkownika, konta usługowe, tokeny API, czas życia poświadczeń, zakres tenantów/zasobów i zasięg sieci | Jako jaka tożsamość wykonywane jest każde wywołanie i czy autoryzacja jest ponownie sprawdzana na granicy narzędzia? |
| **Przetwarzanie** | Konstruktory zapytań, powłoki, pobieranie URL-i, silniki szablonów, interpretery, parsery, operacje na plikach i deserializatory | Gdzie dane wygenerowane przez model stają się składnią dla innego interpretera? |
| **Wyjście** | Odpowiedzi, renderowany Markdown/HTML, linki, pobieranie obrazów, webhooki, e-maile, pliki, logi, raporty, metryki i ruch między agentami | Który obserwowalny kanał może przenosić sekret lub wywołać żądanie wtórne? |

Nie sprowadzaj tego do listy reklamowanych integracji. Przydatny materiał powinien mapować każde źródło na dokładne miejsce w kontekście, do którego trafia, dostępne w tym miejscu narzędzia, poświadczenia używane przez każde narzędzie, dalszy interpreter i każdą trasę egress. To samo narzędzie może mieć niewielki wpływ, gdy używa tokenu odczytu przypisanego do użytkownika, a krytyczny — gdy korzysta ze współdzielonych poświadczeń administratora.<sup>[[2]](#references)</sup>

## Rozpoznanie

### Zmapuj wszystkie ścieżki dostarczania i pozyskiwania danych

Zacznij od powierzchni dostarczania (web, mobile, API, e-mail, platforma czatu, rozszerzenie przeglądarki) i przechwyć ruch klient-backend. Sprawdź pola ukryte przez UI, parametry wyszukiwania/autouzupełniania/filtrowania, obiekty stanu konwersacji, zadania przesyłania i indeksowania, odpowiedzi narzędzi oraz ruch subagentów. Klienci dostępni wyłącznie na urządzeniach mobilnych mogą wymagać emulatora i instrumentacji do ominięcia certificate pinning, zanim widoczny stanie się rzeczywisty schemat żądania.<sup>[[2]](#references)</sup>

Następnie zmapuj stos działający pod modelem: framework orkiestracji, składanie promptów, magazyny retrieval i pamięci, środowisko uruchomieniowe (na przykład Python, kontener lub WASM), podmontowane woluminy, usługi hosta, wewnętrzne API, dostęp do metadanych chmury i sąsiednie sieci. Domyślne ustawienia frameworka mają znaczenie, ponieważ niektóre „wywołania narzędzi” są realizowane przez generowanie lub ewaluację kodu; granica środowiska uruchomieniowego/sandboxa decyduje, czy wynik pozostanie ograniczony.<sup>[[2]](#references)</sup>

### Rozpoznaj routing za pomocą niedestrukcyjnych sond

Porównaj żądanie mieszczące się w zakresie z kilkoma niezwiązanymi żądaniami, zachowując pełną odpowiedź, kod statusu, opóźnienie i zachowanie strumieniowania. Stabilne odrzucenie przed jakimkolwiek rozumowaniem zależnym od zadania może wskazywać na oddzielny gateway/classifier; odmowa uwzględniająca kontekst sugeruje, że żądanie dotarło do modelu; pusta lub wyłącznie ekstrakcyjna odpowiedź może wskazywać na wyszukiwanie słów kluczowych lub wąski retrieval. Traktuj to jako hipotezy i weryfikuj je, odtwarzając tę samą sondę przez alternatywne pola API i ścieżki pozyskiwania danych.<sup>[[2]](#references)</sup>

Rozpoznanie jest zakończone, gdy ocena pozwala wskazać najwcześniejsze źródło kontrolowane przez atakującego, które zmienia zachowanie agenta, **oraz** narzędzia, tożsamości, interpretery i wyjścia dostępne z tego źródła.<sup>[[2]](#references)</sup>

## Wykorzystanie: przekrocz granicę zaufania

Testuj kanały, a nie tylko brzmienie promptu. Zacznij od bezpośredniej injection, aby ustalić, co blokuje widoczna ścieżka wejściowa, a następnie powtórz równoważną próbę przez mniej widoczne ścieżki wymienione poniżej:<sup>[[2]](#references)</sup>

- **Treści pośrednie:** strony, pliki, e-maile, zgłoszenia, metadane, tekst alternatywny, komentarze HTML, tekst poza ekranem lub znaki o zerowej szerokości. Techniki dostarczania payloadów opisano w [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection).
- **Retrieval i pamięć:** zatruj treść, która zostanie pobrana później, lub stan, który zostanie wczytany ponownie w kolejnych sesjach. Zapisz, czy usunięcie oryginalnego źródła usuwa również wywołane zachowanie.
- **Wyniki narzędzi i agenci równorzędni:** umieść znacznik w odpowiedzi narzędzia lub komunikacie między agentami, aby sprawdzić, czy ruch wewnętrzny omija filtry stosowane wyłącznie do danych wejściowych użytkownika i końcowego wyjścia.
- **Łańcuch dostaw:** sprawdź deskryptory narzędzi, pluginy, połączone serwery, umiejętności, modele i zależności pod kątem zaufanych źródeł instrukcji. Testy specyficzne dla MCP opisano w [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Zatwierdzanie przez człowieka:** porównaj rzeczywiste ustrukturyzowane wywołanie narzędzia z tekstem zatwierdzenia wygenerowanym przez model. Sprawdź, czy wpływ atakującego może pominąć cel, zakres, dotknięte obiekty lub nieodwracalne skutki uboczne.

Najpierw użyj nieszkodliwego, unikatowego znacznika. Zachowaj artefakt źródłowy, złożony kontekst (jeśli jest widoczny), wybrane wywołanie narzędzia, dane zatwierdzenia, żądanie/odpowiedź backendu i stan końcowy. Dzięki temu można odróżnić rzeczywisty wpływ od halucynowanego twierdzenia, że działanie zostało wykonane.<sup>[[2]](#references)</sup>

## Wykonanie: udowodnij rzeczywisty wpływ

Istnieją dwie odrębne ścieżki od wpływu do skutku:<sup>[[2]](#references)</sup>

1. **Nadużycie możliwości:** autoryzowane narzędzie już realizuje cel. Przykłady obejmują odczytanie rekordu jednego tenanta i zapisanie go w raporcie widocznym dla atakującego, wysłanie e-maila, zmianę rekordów, usunięcie pliku lub zainicjowanie płatności. Nie jest wymagany żaden wtórny błąd oprogramowania.
2. **Wykorzystanie downstream sink:** dane wyjściowe modelu, na które wpływa atakujący, stają się składnią dla innego komponentu. Sprawdź zapytania do baz danych pod kątem [SQL injection](../pentesting-web/sql-injection/README.md) lub [NoSQL injection](../pentesting-web/nosql-injection.md), skrypty powłoki pod kątem [command injection](../pentesting-web/command-injection.md), wybrane URL-e pod kątem [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operacje na plikach pod kątem directory traversal, ewaluatory szablonów/kodu pod kątem RCE, a parsery obiektów pod kątem [unsafe deserialization](../pentesting-web/deserialization/README.md).

Dla każdego kandydata udowodnij następujący łańcuch:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Integracja tylko do odczytu nadal może zostać wykorzystana, jeśli dowolny późniejszy komponent może opublikować odczytane przez nią dane. Testuj zwykłe odpowiedzi oraz mniej oczywiste kanały egress, takie jak linki kontrolowane przez atakującego, automatyczne pobieranie obrazów, webhooki, logi, raporty, liczniki, powiadomienia i wiadomości do innych agentów.<sup>[[2]](#references)</sup>

## Działania na celach

Po potwierdzeniu jednego działania oceń pełny blast radius, zamiast kończyć test na pierwszym widocznym efekcie:<sup>[[2]](#references)</sup>

- **Eksfiltracja:** sekrety, rekordy użytkowników, pliki wewnętrzne, dane rozmów lub treści promptu/kontekstu wydostają się przez obserwowalny kanał.
- **Nieautoryzowane działanie:** agent wykorzystuje legalne uprawnienia do zapisu, aby zrealizować cel atakującego.
- **Odmowa usługi:** destrukcyjne narzędzia lub powtarzane kosztowne operacje wpływają na integralność lub dostępność.
- **Utrzymanie dostępu:** zatrute dane pamięci, zaindeksowane treści, zaufany stan lub zmiany środowiska wykonawczego przetrwają sesję, w której powstały, albo usunięcie źródła.
- **Propagacja:** zaufany agent równorzędny wykorzystuje wiadomość lub współdzielony stan skompromitowanego agenta i powtarza działanie, używając własnych narzędzi i poświadczeń.

Poziom zagrożenia powinien zależeć od dostępnych danych, faktycznych uprawnień, podatności sinka na wykorzystanie, egress, utrzymania dostępu i propagacji — a nie od tego, jak zaskakująco brzmi tekst wygenerowany przez model.<sup>[[2]](#references)</sup>

## Zabezpieczenia do weryfikacji podczas oceny

Filtry promptów i lepszy system prompt mogą zwiększyć koszt ataku, ale nie należy traktować ich jako granic autoryzacji. Zweryfikuj poniższe zabezpieczenia, ponownie przeprowadzając ten sam łańcuch przez bezpośrednie dane wejściowe, treści pośrednie, pamięć, narzędzia i agentów równorzędnych:<sup>[[2]](#references)</sup>

- Deterministyczna warstwa polityk sprawdza uwierzytelnionego użytkownika, dzierżawcę, obiekt, działanie i miejsce docelowe przy **każdym wywołaniu narzędzia**; model nie może podać ani nadpisać tożsamości wywołującego.
- Uprawnienia do odczytu i zapisu korzystają z osobnych poświadczeń o minimalnych uprawnieniach i krótkim czasie ważności; narzędzia o dużym wpływie są udostępniane tylko na żądanie i nigdy nie wykonują się automatycznie na podstawie zaimportowanych treści.
- Ruch wychodzący z sieci i wewnętrzne miejsca docelowe są niezależnie dodawane do listy dozwolonych; dostęp środowiska wykonawczego do endpointów metadanych, zamontowanych sekretów i sąsiednich usług jest blokowany, o ile nie jest wymagany.
- Interfejs zatwierdzania jest generowany na podstawie kanonicznego, ustrukturyzowanego żądania i pokazuje dokładne argumenty, tożsamość, miejsce docelowe, obiekty, których dotyczy działanie, oraz skutki uboczne — a nie swobodnie sformułowane podsumowanie modelu.
- Powodzenie jest weryfikowane w systemie docelowym lub systemie ewidencyjnym. Opis agenta, żądanie wywołania narzędzia ani przekierowanie HTTP nie stanowią dowodu deklarowanej zmiany stanu.
- Wpisy pamięci i retrieval zachowują pochodzenie i etykiety zaufania, można je unieważnić, a przed ich użyciem do późniejszego działania ponownie sprawdza się autoryzację.
- Wiadomości między agentami są uwierzytelniane i autoryzowane jako niezaufane żądania; reputacja agenta równorzędnego ani jego karta agenta nie delegują domyślnie uprawnień odbiorcy do korzystania z narzędzi.

## References

- [1] [OWASP Top 10 dla aplikacji agentowych na 2026 rok](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Przewodnik hakera po atakowaniu agentów AI](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
