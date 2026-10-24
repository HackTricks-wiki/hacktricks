# Metodologia bezpieczeństwa agentów AI

{{#include ../banners/hacktricks-training.md}}

Ocena agenta powinna śledzić **drogę od danych wejściowych kontrolowanych przez atakującego do zewnętrznie obserwowalnego skutku**. Jailbreaking, zmiany charakteru i ujawnienie system promptu dowodzą, że można wpływać na kanał rozumowania, ale najpoważniejszym ustaleniem jest łańcuch prowadzący do dostępu do danych, nieautoryzowanego działania narzędzia, downstream injection sink, utrwalenia dostępu lub innego agenta.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) przydaje się do etykietowania zakresu testów (przejęcie celu, niewłaściwe użycie narzędzi, nadużycie uprawnień, łańcuch dostaw, wykonanie kodu, zatrucie pamięci, zaufanie między agentami, awarie kaskadowe, zaufanie człowieka i nieposłuszni agenci). Używaj tych etykiet po zbudowaniu kompleksowej ścieżki ataku, zamiast traktować nieoczekiwany tekst wygenerowany przez model jako koniec testu.<sup>[[1]](#references)[[2]](#references)</sup>

## Zbuduj mapę celu

Przed przygotowaniem payloadów zapisz te pięć wymiarów dla każdego przepływu pracy agenta:<sup>[[2]](#references)</sup>

| Wymiar | Co należy zinwentaryzować | Pytanie dotyczące bezpieczeństwa |
|---|---|---|
| **Niezaufane dane wejściowe** | Parametry Chat/API, adresy URL, dokumenty, e-maile, zgłoszenia, wpisy w kalendarzu, pobrane fragmenty, pamięć, wyniki narzędzi i wiadomości od innych agentów | Gdzie atakujący może umieścić treść, która później trafi do kontekstu modelu? |
| **Narzędzia** | Nazwy i schematy narzędzi, skutki uboczne, automatyczne wykonanie, sposób potwierdzania i narzędzia ładowane dynamicznie | Które wywołania odczytują sekrety, zmieniają stan, wysyłają wiadomości, usuwają dane, wykonują kod lub przekazują wartość? |
| **Uprawnienia** | Delegowanie przez użytkownika, konta usługowe, tokeny API, czas ważności poświadczeń, zakres tenantów/zasobów i dostęp do sieci | Jako jaka tożsamość wykonywane jest każde wywołanie i czy autoryzacja jest ponownie sprawdzana na granicy narzędzia? |
| **Przetwarzanie** | Konstrukcje zapytań, powłoki, pobieracze URL-i, silniki szablonów, interpretery, parsery, operacje na plikach i deserializatory | Gdzie dane wygenerowane przez model stają się składnią dla innego interpretera? |
| **Wyjście** | Odpowiedzi, renderowany Markdown/HTML, linki, pobieranie obrazów, webhooki, e-maile, pliki, logi, raporty, metryki i ruch między agentami | Który obserwowalny kanał może przenosić sekret lub wywołać wtórne żądanie? |

Nie sprowadzaj tego do listy reklamowanych integracji. Przydatny artefakt mapuje każde źródło na dokładne miejsce w kontekście, do którego trafia, dostępne w tym miejscu narzędzia, poświadczenia używane przez każde narzędzie, downstream interpreter i wszystkie drogi wyjścia danych. To samo narzędzie może mieć niewielki wpływ przy tokenie odczytu przypisanym do użytkownika, a krytyczny — przy współdzielonych poświadczeniach administratora.<sup>[[2]](#references)</sup>

## Rozpoznanie

### Zmapuj wszystkie ścieżki dostarczania i przyjmowania danych

Zacznij od powierzchni dostępu (web, mobile, API, e-mail, platforma czatu, rozszerzenie przeglądarki) i przechwyć ruch klient–backend przez proxy. Sprawdź pola ukryte przez UI, parametry wyszukiwania/autouzupełniania/filtrowania, obiekty stanu konwersacji, zadania przesyłania i indeksowania, odpowiedzi narzędzi oraz ruch między agentami podrzędnymi. Klienci dostępni wyłącznie na urządzeniach mobilnych mogą wymagać emulatora i instrumentacji, aby ominąć certificate pinning i ujawnić rzeczywisty schemat żądania.<sup>[[2]](#references)</sup>

Następnie zmapuj stos pod modelem: framework orkiestracji, składanie promptu, magazyny wyszukiwania i pamięci, środowisko wykonawcze (na przykład Python, kontener lub WASM), zamontowane woluminy, usługi hosta, wewnętrzne API, dostęp do metadanych chmurowych oraz sąsiednie sieci. Domyślne ustawienia frameworka mają znaczenie, ponieważ niektóre „wywołania narzędzi” są realizowane przez generowanie lub ewaluację kodu; od granicy środowiska wykonawczego/sandboxa zależy, czy wynik pozostanie odizolowany.<sup>[[2]](#references)</sup>

### Rozpoznaj routing za pomocą niedestrukcyjnych sond

Porównaj żądanie mieszczące się w zakresie testu z kilkoma niezwiązanymi żądaniami, zachowując pełną odpowiedź, kod statusu, opóźnienie i zachowanie streamingu. Stabilna odmowa przed rozpoczęciem rozumowania dotyczącego konkretnego zadania może wskazywać na oddzielny gateway/classifier; odmowa uwzględniająca kontekst sugeruje, że żądanie dotarło do modelu; pusta lub wyłącznie ekstrakcyjna odpowiedź może wskazywać na wyszukiwanie słów kluczowych lub ograniczony retrieval. Traktuj to jako hipotezy i weryfikuj je, ponownie wysyłając tę samą sondę przez alternatywne pola API i ścieżki przyjmowania danych.<sup>[[2]](#references)</sup>

Rozpoznanie jest zakończone, gdy ocena potrafi wskazać najwcześniejsze źródło kontrolowane przez atakującego, które zmienia zachowanie agenta, **oraz** osiągalne z tego źródła narzędzia, tożsamości, interpretery i kanały wyjściowe.<sup>[[2]](#references)</sup>

## Eksploatacja: przekrocz granicę zaufania

Testuj kanały, a nie tylko sformułowania promptu. Zacznij od bezpośredniego injection, aby ustalić, co blokuje widoczna ścieżka dostępu, a następnie przetestuj równoważne intencje za pośrednictwem mniej widocznych ścieżek poniżej:<sup>[[2]](#references)</sup>

- **Treści pośrednie:** strony, pliki, e-maile, zgłoszenia, metadane, tekst alternatywny, komentarze HTML, tekst poza ekranem lub znaki o zerowej szerokości. Techniki dostarczania payloadów opisano w sekcji [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection).
- **Retrieval i pamięć:** zatruj treści, które zostaną pobrane później, albo stan, który zostanie ponownie załadowany w kolejnych sesjach. Zapisz, czy usunięcie pierwotnego źródła eliminuje to zachowanie.
- **Wyniki narzędzi i inni agenci:** umieść znacznik w odpowiedzi narzędzia lub wiadomości między agentami, aby sprawdzić, czy wewnętrzny ruch omija filtry stosowane wyłącznie do danych wejściowych użytkownika i końcowego wyjścia.
- **Łańcuch dostaw:** sprawdź deskryptory narzędzi, pluginy, połączone serwery, umiejętności, modele i zależności jako zaufane źródła instrukcji. Testy specyficzne dla MCP opisano w sekcji [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Zatwierdzanie przez człowieka:** porównaj rzeczywiste, ustrukturyzowane wywołanie narzędzia z tekstem zatwierdzenia wygenerowanym przez model. Sprawdź, czy wpływ atakującego może pominąć miejsce docelowe, zakres, obiekty, których dotyczy działanie, lub nieodwracalne skutki uboczne.

Najpierw użyj nieszkodliwego, unikatowego znacznika. Zachowaj artefakt źródłowy, złożony kontekst — jeśli można go zaobserwować — wybrane wywołanie narzędzia, dane zatwierdzenia, żądanie/odpowiedź backendu i stan końcowy. Pozwoli to odróżnić rzeczywisty wpływ od halucynacji, że działanie zostało wykonane.<sup>[[2]](#references)</sup>

### Tekst stylizowany na politykę w module oceny ryzyka narzędzi

Modelowy mechanizm kontroli narzędzi może otrzymywać tekst kontrolowany przez atakującego w kontekście klasyfikacji, który poza tym jest przydatny. Na przykład eksperymentalny `AutoModeMiddleware` w LangChain wysyła do klasyfikatora TypeSafe `is_risky` proponowane wywołanie narzędzia, jego argumenty, opcjonalny opis narzędzia oraz do 30 ostatnich wiadomości. Blokuje skonfigurowane narzędzia, gdy zwrócone prawdopodobieństwo Noul wynosi co najmniej `0.5`; narzędzia spoza listy nie są klasyfikowane przez ten middleware.<sup>[[5]](#references)</sup> TypeSafe ostrzega również, że tekst adwersarialny w stanie może wpływać na klasyfikację, nawet gdy stan ma służyć jako dane.<sup>[[6]](#references)</sup>

**Podrobiona polityka** różni się od zwykłego podawania się za wiadomość systemową. Umieszcza alternatywne etykiety lub definicje ryzyka w stanie o niższym poziomie zaufania i zachęca klasyfikator, by użył tych definicji zamiast kryteriów określonych przez developera. W teście Datadog edytowalny przez użytkownika `profile_description` był kopiowany do argumentów narzędzia wraz z `can_edit:false`. Tekst przypominający politykę argumentował, że próba zapisu wiąże się z niskim ryzykiem, ponieważ osobna kontrola uprawnień powinna ją odrzucić przed jakąkolwiek modyfikacją. W 40 próbach średni wynik `is_risky` spadł z `0.893` do `0.290`, podczas gdy bezpośrednie podszywanie się pod rolę dało średnio `0.905`. Spadek średniej poniżej `0.5` nie dowodzi, że każda pojedyncza próba przeszła przez mechanizm kontroli, a eksperyment **nie** wykazał wykonania nieautoryzowanego zapisu.<sup>[[7]](#references)</sup>

Testując tę granicę, rozróżniaj werdykt klasyfikatora od faktycznego wyniku autoryzacji narzędzia. Sprawdź, które edytowalne pola trafiają do klasyfikatora, porównaj to samo proponowane działanie z tekstem przypominającym politykę i bez niego, a następnie niezależnie zweryfikuj stan końcowy. Osobna kontrola uprawnień musi nadal korzystać z uprawnień uwierzytelnionego użytkownika, a nie praw konta usługowego łącznika.<sup>[[7]](#references)</sup> Inne tryby awarii klasyfikatorów opisano w sekcji [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass); [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) dotyczą innej granicy routingu i poświadczeń.

### Izolacja kontekstu subagenta

Subagent Claude Agent SDK działający bez forka otrzymuje własny `AgentDefinition.prompt`, prompt delegujący i dostępne narzędzia, ale nie system promptu ani konwersacji agenta nadrzędnego. Jeśli w jego definicji pominięto `tools`, dziedziczy narzędzia dostępne dla subagentów; może też nadal ładować się projektowy `CLAUDE.md`. Oznacza to, że ograniczenie promptu dotyczące wyłącznie agenta nadrzędnego jest zawodną granicą, jeśli agent podrzędny może używać tych samych narzędzi systemu plików lub wykonywania kodu.<sup>[[4]](#references)</sup>

Przetestuj tę granicę, porównując bezpośrednie żądanie, którego agent nadrzędny odmawia, z tym samym zadaniem delegowanym do nazwanego subagenta. NCC Group informuje, że odmowa wyliczenia plików systemu operacyjnego została ominięta, gdy zadanie przedstawiono agentowi podrzędnemu jako nieszkodliwą „mapę układu”.<sup>[[3]](#references)</sup>

Sprawdź rzeczywiste wywołania narzędzi przez agenta podrzędnego i efektywną listę dozwolonych narzędzi, a nie tylko końcową odpowiedź agenta nadrzędnego; potwierdź, czy agent podrzędny uzyskał dostęp do plików, do których agent nadrzędny nie powinien mieć dostępu.<sup>[[4]](#references)</sup> To błąd dziedziczenia zabezpieczeń, a nie dowód na [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) lub ucieczkę z kontenera.<sup>[[3]](#references)[[4]](#references)</sup>

## Wykonanie: udowodnij rzeczywisty wpływ

Istnieją dwie odrębne ścieżki od wpływu do skutku:<sup>[[2]](#references)</sup>

1. **Nadużycie możliwości:** autoryzowane narzędzie już realizuje cel. Przykłady obejmują odczytanie rekordu jednego tenanta i zapisanie go w raporcie widocznym dla atakującego, wysłanie e-maila, zmianę rekordów, usunięcie pliku lub zainicjowanie płatności. Nie jest wymagany żaden dodatkowy błąd oprogramowania.
2. **Eksploatacja downstream sink:** treść wyjściowa modelu, na którą wpłynął atakujący, staje się składnią dla innego komponentu. Sprawdź zapytania do baz danych pod kątem [SQL injection](../pentesting-web/sql-injection/README.md) lub [NoSQL injection](../pentesting-web/nosql-injection.md), skrypty powłoki pod kątem [command injection](../pentesting-web/command-injection.md), wybrane adresy URL pod kątem [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operacje na plikach pod kątem path traversal, ewaluatory szablonów/kodu pod kątem RCE oraz parsery obiektów pod kątem [unsafe deserialization](../pentesting-web/deserialization/README.md).

Dla każdego przypadku udowodnij następujący łańcuch:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Integracja tylko do odczytu nadal może zostać wykorzystana, jeśli dowolny późniejszy komponent może opublikować odczytane przez nią dane. Testuj zwykłe odpowiedzi oraz mniej oczywiste kanały wyprowadzania danych, takie jak kontrolowane przez atakującego linki, automatyczne pobieranie obrazów, webhooki, logi, raporty, liczniki, powiadomienia i wiadomości do innych agentów.<sup>[[2]](#references)</sup>

## Działania realizujące cele

Po potwierdzeniu jednego działania oceń pełny zakres jego skutków, zamiast poprzestawać na pierwszym widocznym efekcie:<sup>[[2]](#references)</sup>

- **Eksfiltracja:** sekrety, rekordy użytkowników, pliki wewnętrzne, dane konwersacji lub treści promptów i kontekstu opuszczają system przez obserwowalny kanał.
- **Nieautoryzowane działanie:** agent wykorzystuje legalne uprawnienia do zapisu, aby zrealizować cel atakującego.
- **Odmowa usługi:** destrukcyjne narzędzia lub powtarzane, kosztowne operacje wpływają na integralność lub dostępność.
- **Trwałość:** zatruta pamięć, indeksowana treść, zaufany stan lub zmiany w środowisku uruchomieniowym przetrwają sesję, która je zainicjowała, lub usunięcie źródła.
- **Propagacja:** zaufany agent równorzędny korzysta z wiadomości lub współdzielonego stanu przejętego agenta i powtarza działanie, używając własnych narzędzi i poświadczeń.

Poziom zagrożenia powinien zależeć od dostępnych danych, efektywnych uprawnień, podatności sinka na wykorzystanie, kanałów wyprowadzania danych, trwałości i propagacji — a nie od tego, jak zaskakująco brzmi tekst wygenerowany przez model.<sup>[[2]](#references)</sup>

## Kontrole do zweryfikowania podczas oceny

Filtry promptów i lepszy system prompt mogą zwiększyć koszt ataku, ale nie należy traktować ich jako granic autoryzacji. Zweryfikuj poniższe kontrole, ponownie przeprowadzając ten sam łańcuch przez bezpośrednie dane wejściowe, treści pośrednie, pamięć, narzędzia i agentów równorzędnych:<sup>[[2]](#references)</sup>

- Deterministyczna warstwa polityk sprawdza uwierzytelnionego użytkownika, tenant, obiekt, działanie i miejsce docelowe przy **każdym wywołaniu narzędzia**; model nie może podać ani nadpisać tożsamości wywołującego.
- Uprawnienia do odczytu i zapisu korzystają z oddzielnych, minimalnych, krótkotrwałych poświadczeń; narzędzia o dużym wpływie są udostępniane tylko na żądanie i nigdy nie wykonują się automatycznie na podstawie wczytanej treści.
- Ruch wychodzący z sieci i wewnętrzne miejsca docelowe są niezależnie od adresów URL wybranych przez model ograniczone do listy dozwolonych; dostęp środowiska uruchomieniowego do endpointów metadanych, zamontowanych sekretów i sąsiednich usług jest blokowany, chyba że jest wymagany.
- Interfejs zatwierdzania jest generowany na podstawie kanonicznego, ustrukturyzowanego żądania i pokazuje dokładne argumenty, tożsamość, miejsce docelowe, obiekty, których dotyczy działanie, oraz skutki uboczne — a nie swobodne podsumowanie modelu.
- Sukces jest weryfikowany w systemie docelowym lub systemie ewidencji. Opis agenta, żądanie wywołania narzędzia ani przekierowanie HTTP nie potwierdzają deklarowanej zmiany stanu.
- Wpisy pamięci i wyszukiwania zachowują pochodzenie i etykiety zaufania, można je unieważnić, a przy użyciu do późniejszego działania ponownie przeprowadza się autoryzację.
- Wiadomości między agentami są uwierzytelniane i autoryzowane jako niezaufane żądania; reputacja agenta równorzędnego ani jego karta agenta nie delegują pośrednio uprawnień odbiorcy do narzędzi.

## References

- [1] [OWASP Top 10 dla aplikacji agentowych na 2026 rok](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Przewodnik hakera po atakowaniu agentów AI](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Jak trudno jest naprawdę wyprowadzić agenta AI z jego sandboxa?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagenci w SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Kod źródłowy middleware TypeSafe Auto Mode w LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Poszarpane zachowanie modelu TypeSafe AI Jev: treści adversarialne](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev jako sędzia: jak fałszywa polityka steruje Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
