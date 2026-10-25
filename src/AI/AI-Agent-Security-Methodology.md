# Metodyka bezpieczeństwa agentów AI

{{#include ../banners/hacktricks-training.md}}

Ocena agenta powinna śledzić **drogę od danych wejściowych kontrolowanych przez atakującego do zewnętrznie obserwowalnego skutku**. Jailbreaking, zmiany charakteru i ujawnienie system promptu dowodzą, że można wpływać na kanał wnioskowania, ale najpoważniejsze ustalenie to łańcuch prowadzący do dostępu do danych, nieautoryzowanego działania narzędzia, punktu wstrzyknięcia w dalszym etapie, utrwalenia dostępu lub innego agenta.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) przydaje się do oznaczania zakresu testów (przejęcie celu, niewłaściwe użycie narzędzi, nadużycie uprawnień, łańcuch dostaw, wykonanie kodu, zatrucie pamięci, zaufanie między agentami, awarie kaskadowe, zaufanie człowieka i niekontrolowane agenty). Używaj tych etykiet po zbudowaniu kompleksowej ścieżki ataku, a nie traktuj nieoczekiwanego tekstu modelu jako końca testu.<sup>[[1]](#references)[[2]](#references)</sup>

## Zmapuj cel

Przed przygotowaniem payloadów zanotuj te pięć wymiarów dla każdego przepływu pracy agenta:<sup>[[2]](#references)</sup>

| Wymiar | Co uwzględnić | Pytanie dotyczące bezpieczeństwa |
|---|---|---|
| **Niezaufane dane wejściowe** | Parametry czatu/API, adresy URL, dokumenty, e-maile, zgłoszenia, wpisy kalendarza, pobrane fragmenty, pamięć, wyniki narzędzi i wiadomości od agentów współpracujących | Gdzie atakujący może umieścić treść, która później trafi do kontekstu modelu? |
| **Narzędzia** | Nazwy i schematy narzędzi, skutki uboczne, automatyczne wykonanie, sposób potwierdzania i narzędzia ładowane dynamicznie | Które wywołania odczytują sekrety, zapisują stan, wysyłają wiadomości, usuwają dane, wykonują kod lub przekazują wartość? |
| **Uprawnienia** | Delegowanie przez użytkownika, konta usługowe, tokeny API, okres ważności poświadczeń, zakres tenantów/zasobów i dostęp do sieci | W imieniu jakiej tożsamości działa każde wywołanie i czy autoryzacja jest ponownie sprawdzana na granicy narzędzia? |
| **Przetwarzanie** | Konstruktorzy zapytań, powłoki, mechanizmy pobierania URL, silniki szablonów, interpretery, parsery, operacje na plikach i deserializatory | Gdzie dane wygenerowane przez model stają się składnią dla innego interpretera? |
| **Wyjście** | Odpowiedzi, renderowany Markdown/HTML, linki, pobierane obrazy, webhooki, e-maile, pliki, logi, raporty, metryki i ruch między agentami | Który obserwowalny kanał może przenosić sekret lub wywołać dodatkowe żądanie? |

Nie sprowadzaj tego do listy reklamowanych integracji. Przydatny materiał powinien mapować każde źródło na dokładne miejsce w kontekście, do którego trafia, dostępne w tym miejscu narzędzia, poświadczenia używane przez każde narzędzie, dalszy interpreter i wszystkie drogi eksfiltracji. To samo narzędzie może mieć niewielki wpływ, gdy używa tokenu odczytu przypisanego do użytkownika, i krytyczny, gdy korzysta ze współdzielonych poświadczeń administratora.<sup>[[2]](#references)</sup>

## Rozpoznanie

### Zmapuj wszystkie ścieżki dostarczania i pobierania danych

Zacznij od powierzchni dostępu (web, urządzenia mobilne, API, e-mail, platforma czatu, rozszerzenie przeglądarki) i przechwyć ruch między klientem a backendem przez proxy. Sprawdź pola ukryte przez interfejs, parametry wyszukiwania/autouzupełniania/filtrowania, obiekty stanu konwersacji, zadania przesyłania i indeksowania, odpowiedzi narzędzi oraz ruch między podrzędnymi agentami. Klienci dostępni wyłącznie na urządzeniach mobilnych mogą wymagać emulatora i instrumentacji, aby ominąć certificate pinning i ujawnić rzeczywisty schemat żądania.<sup>[[2]](#references)</sup>

Następnie zmapuj stos działający pod modelem: framework orkiestracji, składanie promptu, magazyny wyszukiwania i pamięci, środowisko uruchomieniowe (na przykład Python, kontener lub WASM), podmontowane woluminy, usługi hosta, wewnętrzne API, dostęp do metadanych cloud i sąsiednie sieci. Domyślne ustawienia frameworka mają znaczenie, ponieważ niektóre „wywołania narzędzi” są realizowane przez generowanie lub ewaluację kodu; granica środowiska uruchomieniowego/sandboxa określa, czy rezultat pozostaje odizolowany.<sup>[[2]](#references)</sup>

### Rozpoznaj routing za pomocą niedestrukcyjnych testów

Porównaj żądanie mieszczące się w zakresie z kilkoma niezwiązanymi żądaniami, zachowując pełną odpowiedź, kod statusu, opóźnienie i zachowanie streamingu. Stabilne odrzucenie przed rozpoczęciem rozumowania związanego z zadaniem może wskazywać na osobną bramę/klasyfikator; odmowa zależna od kontekstu sugeruje, że żądanie dotarło do modelu; pusta lub wyłącznie ekstrakcyjna odpowiedź może wskazywać na wyszukiwanie słów kluczowych lub ograniczone pobieranie danych. Traktuj to jako hipotezy i potwierdzaj je, ponawiając ten sam test przez alternatywne pola API i ścieżki pobierania danych.<sup>[[2]](#references)</sup>

Rozpoznanie jest zakończone, gdy ocena pozwala wskazać najwcześniejsze źródło kontrolowane przez atakującego, które zmienia zachowanie agenta, **oraz** narzędzia, tożsamości, interpretery i wyjścia osiągalne z tego źródła.<sup>[[2]](#references)</sup>

## Wykorzystanie: przekrocz granicę zaufania

Testuj kanały, nie tylko treść promptu. Zacznij od bezpośredniego injection, aby ustalić, co blokuje widoczny punkt wejścia, a następnie przetestuj równoważne zamiary przez mniej widoczne ścieżki poniżej:<sup>[[2]](#references)</sup>

- **Treści pośrednie:** strony, pliki, e-maile, zgłoszenia, metadane, tekst alternatywny, komentarze HTML, tekst poza ekranem lub znaki o zerowej szerokości. Techniki dostarczania payloadów opisano w [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection).
- **Pobieranie danych i pamięć:** zatruj treść, która zostanie pobrana później, lub stan, który zostanie ponownie załadowany w kolejnych sesjach. Zapisz, czy usunięcie oryginalnego źródła zatrzymuje niepożądane zachowanie.
- **Wyniki narzędzi i agenci współpracujący:** umieść znacznik w odpowiedzi narzędzia lub wiadomości między agentami, aby sprawdzić, czy ruch wewnętrzny omija filtry stosowane wyłącznie do danych wejściowych użytkownika i końcowego wyjścia.
- **Łańcuch dostaw:** sprawdź opisy narzędzi, pluginy, połączone serwery, umiejętności, modele i zależności traktowane jako zaufane źródła instrukcji. Testy specyficzne dla MCP opisano w [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Zatwierdzanie przez człowieka:** porównaj rzeczywiste, ustrukturyzowane wywołanie narzędzia z wygenerowanym przez model tekstem zatwierdzenia. Sprawdź, czy wpływ atakującego może doprowadzić do pominięcia celu, zakresu, obiektów objętych działaniem lub nieodwracalnych skutków ubocznych.

Najpierw użyj nieszkodliwego, unikalnego znacznika. Zachowaj źródłowy artefakt, złożony kontekst, jeśli można go podejrzeć, wybrane wywołanie narzędzia, dane zatwierdzenia, żądanie/odpowiedź backendu i końcowy stan. Pozwoli to odróżnić rzeczywisty wpływ od halucynacji, że działanie zostało wykonane.<sup>[[2]](#references)</sup>

### Tekst przypominający politykę w ocenie ryzyka narzędzia

Bramka narzędzi oparta na modelu może otrzymać tekst kontrolowany przez atakującego w kontekście klasyfikacji, który poza tym jest użyteczny. Na przykład eksperymentalny `AutoModeMiddleware` LangChain przekazuje proponowane wywołanie narzędzia, jego argumenty, opcjonalny opis narzędzia oraz do 30 ostatnich wiadomości klasyfikatorowi TypeSafe `is_risky`. Middleware blokuje skonfigurowane narzędzia, gdy zwrócone prawdopodobieństwo Noul wynosi co najmniej `0.5`; narzędzia spoza listy nie są przez niego klasyfikowane.<sup>[[5]](#references)</sup> TypeSafe ostrzega również, że adwersarialny tekst w stanie może wpłynąć na klasyfikację, nawet jeśli stan ma być traktowany jako dane.<sup>[[6]](#references)</sup>

**Fałszywa polityka** różni się od samego podszywania się pod wiadomość systemową. Umieszcza alternatywne etykiety lub definicje ryzyka w stanie o niższym poziomie zaufania i skłania klasyfikator do użycia tych definicji zamiast kryteriów określonych przez dewelopera. W teście Datadog edytowalne przez użytkownika `profile_description` kopiowano do argumentów narzędzia wraz z `can_edit:false`. Tekst przypominający politykę uzasadniał, że próba zapisu wiąże się z niskim ryzykiem, ponieważ osobna kontrola uprawnień powinna ją odrzucić przed jakąkolwiek zmianą. W 40 próbach średnia ocena `is_risky` spadła z `0.893` do `0.290`, podczas gdy bezpośrednie porównanie z podszywaniem się pod rolę dało średnią `0.905`. Spadek średniej poniżej `0.5` nie dowodzi, że każda pojedyncza próba przeszła przez bramkę, a eksperyment **nie** wykazał wykonania nieautoryzowanego zapisu.<sup>[[7]](#references)</sup>

Testując tę granicę, odróżniaj werdykt klasyfikatora od rzeczywistego wyniku autoryzacji narzędzia. Sprawdź, które edytowalne pola trafiają do klasyfikatora, porównaj to samo proponowane działanie z tekstem przypominającym politykę i bez niego oraz niezależnie zweryfikuj końcowy stan. Osobna kontrola uprawnień musi nadal korzystać z uprawnień uwierzytelnionego użytkownika żądającego operacji, a nie z uprawnień konta usługowego konektora.<sup>[[7]](#references)</sup> Inne tryby awarii klasyfikatorów opisano w [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass); [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) dotyczą innej granicy routingu i poświadczeń.

### Izolacja kontekstu podrzędnego agenta

Podrzędny agent Claude Agent SDK, który nie działa w trybie fork, otrzymuje własny `AgentDefinition.prompt`, prompt delegujący i dostępne narzędzia, ale nie system promptu ani konwersacji agenta nadrzędnego. Jeśli w jego definicji pominięto `tools`, dziedziczy narzędzia dostępne dla podrzędnych agentów; plik projektu `CLAUDE.md` może być nadal ładowany. Oznacza to, że ograniczenie promptu agenta nadrzędnego nie stanowi wiarygodnej granicy, jeśli podrzędny agent może używać tych samych narzędzi systemu plików lub wykonywania kodu.<sup>[[4]](#references)</sup>

Przetestuj tę granicę, porównując bezpośrednie żądanie, które agent nadrzędny odrzuca, z tym samym zadaniem delegowanym nazwanemu podrzędnemu agentowi. NCC Group informuje, że odmówione wyliczenie plików systemu operacyjnego powiodło się po przedstawieniu zadania podrzędnemu agentowi jako nieszkodliwej „mapy układu”.<sup>[[3]](#references)</sup>

Sprawdź rzeczywiste wywołania narzędzi podrzędnego agenta i efektywną listę dozwolonych narzędzi, a nie tylko końcową odpowiedź agenta nadrzędnego; potwierdź, czy podrzędny agent uzyskał dostęp do plików niedostępnych dla agenta nadrzędnego.<sup>[[4]](#references)</sup> To błąd dziedziczenia guardrails, a nie dowód na [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) lub ucieczkę z kontenera.<sup>[[3]](#references)[[4]](#references)</sup>

## Wykonanie: potwierdź rzeczywisty wpływ

Istnieją dwie odrębne ścieżki od wpływu do skutku:<sup>[[2]](#references)</sup>

1. **Nadużycie możliwości:** autoryzowane narzędzie już realizuje cel. Przykłady obejmują odczytanie rekordu jednego tenanta i zapisanie go w raporcie widocznym dla atakującego, wysłanie e-maila, zmianę rekordów, usunięcie pliku lub zainicjowanie płatności. Nie jest potrzebny dodatkowy błąd oprogramowania.
2. **Wykorzystanie dalszego punktu przetwarzania:** wynik modelu, na który wpłynął atakujący, staje się składnią dla innego komponentu. Sprawdź zapytania do baz danych pod kątem [SQL injection](../pentesting-web/sql-injection/README.md) lub [NoSQL injection](../pentesting-web/nosql-injection.md), skrypty powłoki pod kątem [command injection](../pentesting-web/command-injection.md), wybrane adresy URL pod kątem [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operacje na plikach pod kątem path traversal, ewaluatory szablonów/kodu pod kątem RCE, a parsery obiektów pod kątem [unsafe deserialization](../pentesting-web/deserialization/README.md).

Dla każdego potencjalnego przypadku potwierdź ten łańcuch:<sup>[[2]](#references)</sup>

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

Po potwierdzeniu jednego działania oceń cały zakres jego skutków, zamiast kończyć test na pierwszym widocznym efekcie:<sup>[[2]](#references)</sup>

- **Eksfiltracja:** sekrety, rekordy użytkowników, pliki wewnętrzne, dane rozmów lub treści promptów/kontekstu wydostają się przez obserwowalny kanał.
- **Nieautoryzowane działanie:** agent wykorzystuje legalne uprawnienia do zapisu, aby zrealizować cel atakującego.
- **Odmowa usługi:** narzędzia destrukcyjne lub powtarzane kosztowne operacje wpływają na integralność albo dostępność.
- **Trwałość:** zatruta pamięć, zaindeksowane treści, zaufany stan lub zmiany środowiska uruchomieniowego utrzymują się po zakończeniu sesji, w której powstały, lub po usunięciu źródła.
- **Propagacja:** zaufany agent równorzędny korzysta z wiadomości lub współdzielonego stanu przejętego agenta i powtarza działanie, używając własnych narzędzi i poświadczeń.

Poziom zagrożenia powinien zależeć od dostępnych danych, efektywnych uprawnień, podatności sinka na wykorzystanie, egress, trwałości i propagacji — a nie od tego, jak zaskakująco brzmi tekst wygenerowany przez model.<sup>[[2]](#references)</sup>

## Kontrole do sprawdzenia podczas oceny

Filtry promptów i lepszy prompt systemowy mogą podnieść koszt ataku, ale nie należy traktować ich jako granic autoryzacji. Sprawdź poniższe kontrole, ponownie uruchamiając ten sam łańcuch przez bezpośrednie dane wejściowe, treści pośrednie, pamięć, narzędzia i agentów równorzędnych:<sup>[[2]](#references)</sup>

- Deterministyczna warstwa zasad sprawdza uwierzytelnionego użytkownika, dzierżawcę, obiekt, działanie i miejsce docelowe przy **każdym wywołaniu narzędzia**; model nie może podać ani nadpisać tożsamości wywołującego.
- Uprawnienia do odczytu i zapisu korzystają z oddzielnych poświadczeń o minimalnych uprawnieniach i krótkim czasie ważności; narzędzia o dużym wpływie są udostępniane tylko wtedy, gdy są potrzebne, i nigdy nie wykonują się automatycznie na podstawie wczytanych treści.
- Ruch wychodzący z sieci i wewnętrzne miejsca docelowe są niezależnie od URL-i wybranych przez model ograniczone do listy dozwolonych; dostęp środowiska uruchomieniowego do endpointów metadanych, podmontowanych sekretów i sąsiednich usług jest blokowany, o ile nie jest wymagany.
- Interfejs zatwierdzania jest generowany na podstawie kanonicznego, ustrukturyzowanego żądania i pokazuje dokładne argumenty, tożsamość, miejsce docelowe, obiekty, których dotyczy działanie, oraz skutki uboczne — a nie swobodne podsumowanie modelu.
- Sukces jest weryfikowany w systemie docelowym lub systemie będącym źródłem prawdy. Opis agenta, żądanie wywołania narzędzia ani przekierowanie HTTP nie stanowią dowodu deklarowanej zmiany stanu.
- Wpisy pamięci i wyników wyszukiwania zachowują informacje o pochodzeniu i etykiety zaufania, można je unieważnić, a przy późniejszym użyciu do działania podlegają ponownej autoryzacji.
- Wiadomości między agentami są uwierzytelniane i autoryzowane jako niezaufane żądania; reputacja agenta równorzędnego ani jego karta agenta nie delegują automatycznie uprawnień odbiorcy do używania narzędzi.

Informacje o kartach agentów A2A, przepływach zadań i ich powierzchni ataku znajdziesz w dokumencie [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 dla aplikacji agentowych na 2026 rok](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Przewodnik hakera po atakowaniu agentów AI](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Jak trudno jest naprawdę wyprowadzić agenta AI z jego sandboxa?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagenci w SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Kod źródłowy middleware TypeSafe Auto Mode w LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Chropowatość modelu TypeSafe AI Jev: treści adwersarialne](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev jako sędzia: jak podrobiona polityka steruje Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
