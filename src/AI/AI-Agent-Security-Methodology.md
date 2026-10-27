# Metodologia bezpieczeństwa agentów AI

{{#include ../banners/hacktricks-training.md}}

Ocena agenta powinna śledzić **drogę od danych wejściowych kontrolowanych przez atakującego do zewnętrznie obserwowalnego skutku**. Jailbreaking, zmiana charakteru i ujawnienie system promptu dowodzą, że można wpływać na kanał wnioskowania, ale najpoważniejszym ustaleniem jest łańcuch prowadzący do dostępu do danych, nieautoryzowanego działania narzędzia, downstream injection sink, utrwalenia dostępu lub innego agenta.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) przydaje się do oznaczania zakresu testów (przejęcie celu, niewłaściwe użycie narzędzi, nadużycie uprawnień, łańcuch dostaw, wykonanie kodu, zatrucie pamięci, zaufanie między agentami, awarie kaskadowe, zaufanie człowieka i niekontrolowani agenci). Używaj tych etykiet po zbudowaniu kompleksowej ścieżki ataku, zamiast uznawać nieoczekiwany tekst wygenerowany przez model za koniec testu.<sup>[[1]](#references)[[2]](#references)</sup>

## Zbuduj mapę celu

Zanim przygotujesz payloady, dla każdego przepływu pracy agenta opisz te pięć wymiarów:<sup>[[2]](#references)</sup>

| Wymiar | Co należy uwzględnić | Pytanie dotyczące bezpieczeństwa |
|---|---|---|
| **Niezaufane dane wejściowe** | Parametry czatu/API, adresy URL, dokumenty, e-maile, zgłoszenia, wpisy kalendarza, pobrane fragmenty, pamięć, wyniki narzędzi i wiadomości od agentów równorzędnych | Gdzie atakujący może umieścić treść, która później trafi do kontekstu modelu? |
| **Narzędzia** | Nazwy i schematy narzędzi, skutki uboczne, automatyczne wykonywanie, sposób potwierdzania i narzędzia ładowane dynamicznie | Które wywołania odczytują sekrety, zmieniają stan, wysyłają wiadomości, usuwają dane, wykonują kod lub przekazują wartość? |
| **Uprawnienia** | Delegowanie przez użytkownika, konta usługowe, tokeny API, okres ważności poświadczeń, zakres tenantów/zasobów i zasięg sieciowy | W ramach jakiej tożsamości wykonywane jest każde wywołanie i czy autoryzacja jest ponawiana na granicy narzędzia? |
| **Przetwarzanie** | Konstruktory zapytań, powłoki, mechanizmy pobierania URL-i, silniki szablonów, interpretery, parsery, operacje na plikach i deserializatory | Gdzie dane wygenerowane przez model stają się składnią dla innego interpretera? |
| **Wyjście** | Odpowiedzi, renderowany Markdown/HTML, linki, pobieranie obrazów, webhooki, e-maile, pliki, logi, raporty, metryki i ruch między agentami | Którym obserwowalnym kanałem może wyciec sekret lub zostać wywołane żądanie wtórne? |

Nie sprowadzaj tego do listy reklamowanych integracji. Przydatny artefakt mapuje każde źródło na dokładne miejsce w kontekście, do którego trafia, dostępne w tym momencie narzędzia, poświadczenie używane przez każde narzędzie, downstream interpreter oraz wszystkie ścieżki egress. To samo narzędzie może mieć mały wpływ, gdy używa tokenu odczytu ograniczonego do użytkownika, i krytyczny — gdy korzysta ze wspólnych poświadczeń administratora.<sup>[[2]](#references)</sup>

## Rozpoznanie

### Zmapuj wszystkie ścieżki dostarczania i ingestii

Zacznij od powierzchni dostarczania (web, mobile, API, e-mail, platforma czatu, rozszerzenie przeglądarki) i przechwyć ruch między klientem a backendem za pomocą proxy. Sprawdź pola ukryte przez UI, parametry wyszukiwania/autouzupełniania/filtrowania, obiekty stanu konwersacji, zadania przesyłania i indeksowania, odpowiedzi narzędzi oraz ruch między subagentami. Klienci dostępni wyłącznie na urządzeniach mobilnych mogą wymagać emulatora i instrumentacji do ominięcia certificate pinning, zanim widoczny stanie się rzeczywisty schemat żądań.<sup>[[2]](#references)</sup>

Następnie zmapuj warstwy pod modelem: framework orkiestracji, składanie promptów, magazyny retrieval i pamięci, środowisko wykonawcze (np. Python, kontener lub WASM), zamontowane woluminy, usługi hosta, wewnętrzne API, dostępność cloud metadata i sąsiednie sieci. Domyślne ustawienia frameworka mają znaczenie, ponieważ niektóre „wywołania narzędzi” są realizowane przez generowanie lub ewaluację kodu; granica runtime/sandbox decyduje, czy wynik pozostanie odizolowany.<sup>[[2]](#references)</sup>

### Rozpoznaj routing za pomocą nieniszczących sond

Porównaj żądanie mieszczące się w zakresie testu z kilkoma niezwiązanymi żądaniami, zachowując pełną odpowiedź, kod statusu, opóźnienie i zachowanie streamingu. Stabilne odrzucenie, zanim rozpocznie się rozumowanie dotyczące konkretnego zadania, może wskazywać na osobną bramę/klasyfikator; odmowa uwzględniająca kontekst sugeruje, że żądanie dotarło do modelu; pusta lub wyłącznie ekstrakcyjna odpowiedź może wskazywać na wyszukiwanie słów kluczowych albo ograniczony retrieval. Traktuj to jako hipotezy i potwierdź je, ponownie wysyłając tę samą sondę przez alternatywne pola API i ścieżki ingestii.<sup>[[2]](#references)</sup>

Rozpoznanie jest zakończone, gdy ocena pozwala wskazać najwcześniejsze źródło kontrolowane przez atakującego, które zmienia zachowanie agenta, **oraz** narzędzia, tożsamości, interpretery i wyjścia dostępne z tego źródła.<sup>[[2]](#references)</sup>

## Eksploatacja: przekrocz granicę zaufania

Testuj kanały, a nie tylko brzmienie promptu. Zacznij od bezpośredniego injection, aby ustalić, co blokuje widoczny interfejs, a następnie sprawdź równoważny zamiar za pośrednictwem mniej widocznych ścieżek:<sup>[[2]](#references)</sup>

- **Treści pośrednie:** strony, pliki, e-maile, zgłoszenia, metadane, tekst alt, komentarze HTML, tekst poza ekranem lub znaki o zerowej szerokości. Techniki dostarczania payloadów opisano w sekcji [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection).
- **Retrieval i pamięć:** zatruj treść, która zostanie pobrana później, albo stan, który zostanie ponownie załadowany w kolejnych sesjach. Zapisz, czy usunięcie oryginalnego źródła eliminuje zachowanie.
- **Wyniki narzędzi i agenci równorzędni:** umieść marker w odpowiedzi narzędzia lub wiadomości między agentami, aby sprawdzić, czy wewnętrzny ruch omija filtry stosowane wyłącznie do danych wejściowych użytkownika i końcowego wyjścia.
- **Łańcuch dostaw:** sprawdź deskryptory narzędzi, pluginy, połączone serwery, umiejętności, modele i zależności jako zaufane źródła instrukcji. Testy specyficzne dla MCP opisano w sekcji [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Zatwierdzanie przez człowieka:** porównaj rzeczywiste, ustrukturyzowane wywołanie narzędzia z tekstem zatwierdzenia wygenerowanym przez model. Sprawdź, czy wpływ atakującego może spowodować pominięcie miejsca docelowego, zakresu, obiektów objętych działaniem lub nieodwracalnych skutków ubocznych.

Najpierw użyj nieszkodliwego, unikalnego markera. Zachowaj artefakt źródłowy, złożony kontekst, jeśli jest widoczny, wybrane wywołanie narzędzia, dane zatwierdzenia, żądanie/odpowiedź backendu i stan końcowy. Pozwoli to odróżnić rzeczywisty wpływ od halucynacji, że działanie zostało wykonane.<sup>[[2]](#references)</sup>

### Tekst imitujący politykę w mechanizmie oceny ryzyka narzędzia

Bramka narzędzi oparta na modelu może otrzymywać tekst kontrolowany przez atakującego w kontekście klasyfikacji, który poza tym jest przydatny. Na przykład eksperymentalny `AutoModeMiddleware` w LangChain przesyła proponowane wywołanie narzędzia, jego argumenty, opcjonalny opis narzędzia i do 30 ostatnich wiadomości do klasyfikatora `is_risky` TypeSafe. Blokuje skonfigurowane narzędzia, gdy zwrócone prawdopodobieństwo Noul wynosi co najmniej `0.5`; narzędzia nieuwzględnione na liście nie są klasyfikowane przez ten middleware.<sup>[[5]](#references)</sup> TypeSafe ostrzega również, że tekst adwersarialny w stanie może wpłynąć na klasyfikację, nawet gdy stan ma służyć jako dane.<sup>[[6]](#references)</sup>

**Sfałszowana polityka** różni się od zwykłego twierdzenia, że tekst jest wiadomością systemową. Polega na umieszczeniu alternatywnych etykiet lub definicji ryzyka w stanie o niższym poziomie zaufania i nakłanianiu klasyfikatora, by użył tych definicji zamiast kryteriów określonych przez dewelopera. W teście Datadog edytowalne przez użytkownika `profile_description` skopiowano do argumentów narzędzia wraz z `can_edit:false`. Tekst przypominający politykę argumentował, że próba zapisu wiąże się z niskim ryzykiem, ponieważ osobne sprawdzenie uprawnień powinno ją odrzucić przed jakąkolwiek zmianą. W 40 przebiegach średni wynik `is_risky` spadł z `0.893` do `0.290`, podczas gdy średnia w bezpośrednim porównaniu ze spoofingiem roli wyniosła `0.905`. Spadek średniej poniżej `0.5` nie dowodzi, że każda pojedyncza próba ominęła bramkę, a eksperyment **nie** wykazał wykonania nieautoryzowanego zapisu.<sup>[[7]](#references)</sup>

Testując tę granicę, odróżnij werdykt klasyfikatora od rzeczywistego wyniku autoryzacji narzędzia. Sprawdź, które edytowalne pola docierają do klasyfikatora, porównaj to samo proponowane działanie z tekstem przypominającym politykę i bez niego, a następnie niezależnie zweryfikuj stan końcowy. Osobne sprawdzenie uprawnień musi nadal korzystać z uprawnień uwierzytelnionego żądającego, a nie z uprawnień konta usługowego konektora.<sup>[[7]](#references)</sup> Inne tryby awarii klasyfikatorów opisano w sekcji [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass); [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) dotyczą innej granicy routingu i poświadczeń.

### Izolacja kontekstu subagenta

Subagent Claude Agent SDK, który nie jest fork, otrzymuje własny `AgentDefinition.prompt`, prompt delegacji oraz dostępne mu narzędzia, ale nie otrzymuje system promptu ani konwersacji agenta nadrzędnego. Jeśli w jego definicji pominięto `tools`, dziedziczy narzędzia dostępne subagentom; może nadal ładować się projektowy `CLAUDE.md`. Oznacza to, że ograniczenie promptu dotyczące wyłącznie agenta nadrzędnego nie stanowi wiarygodnej granicy, gdy agent podrzędny może korzystać z tych samych narzędzi do pracy z systemem plików lub wykonywania kodu.<sup>[[4]](#references)</sup>

Przetestuj tę granicę, porównując bezpośrednie żądanie, którego agent nadrzędny odmawia, z tym samym zadaniem delegowanym nazwanemu subagentowi. NCC Group informuje, że odmówione wyliczenie plików systemu operacyjnego powiodło się, gdy przedstawiono je agentowi podrzędnemu jako nieszkodliwą „mapę układu”.<sup>[[3]](#references)</sup>

Sprawdź rzeczywiste wywołania narzędzi przez agenta podrzędnego i efektywną listę dozwolonych narzędzi, a nie tylko końcową odpowiedź agenta nadrzędnego; potwierdź, czy agent podrzędny uzyskał dostęp do plików, do których agent nadrzędny nie miałby dostępu.<sup>[[4]](#references)</sup> Jest to awaria dziedziczenia guardrail, a nie dowód na ucieczkę z [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) lub kontenera.<sup>[[3]](#references)[[4]](#references)</sup>

### Mobilni agenci GUI: instrukcje na ekranie i zmiana celu akcji

Agent GUI na telefonie może wysyłać każdy zrzut ekranu do modelu w chmurze, zanim wybierze kolejne działanie w innej aplikacji. Aby przetestować **pośrednie visual injection**, umieść tekst kontrolowany przez atakującego w SMS-ie, e-mailu lub na stronie, którą agent ma sprawdzić podczas autoryzowanego zadania. Porównaj bezpośredni prompt zadania z tą samą instrukcją widoczną wyłącznie na zrzucie ekranu, a następnie sprawdź kolejne działanie i decyzję dotyczącą operacji wysokiego ryzyka. W ocenianym asystencie `checkPrompt` po stronie klienta filtrował bezpośredni tekst zadania, ale nie stosował równoważnego filtrowania do treści na zrzutach ekranu. Jest to mobilny, międzyaplikacyjny wariant [agentic-browser screenshot injection](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md), a nie metoda ominięcia uwierzytelniania komponentów Androida.<sup>[[9]](#references)</sup>

Przykładowy test skutków ubocznych wykorzystuje formularz kontrolowany przez atakującego, który prosi agenta o wypełnienie poufnych pól, a następnie prosi człowieka o kliknięcie „upload”, podczas gdy strona wysyła wypełnione pola natychmiast po ich zmianie. Przekazanie kontroli człowiekowi nie chroni danych, które kod strony już wysłał; zweryfikuj rzeczywiste wysłanie, zamiast uznawać relację agenta za dowód. Źródło przedstawia to jako możliwy schemat, a nie udowodnione przejęcie każdego asystenta.<sup>[[9]](#references)</sup>

**GUI TOCTOU / zmiana celu akcji** to odrębny tryb awarii: agent planuje wprowadzenie danych na podstawie ekranu widocznego w chwili `t0`, ale interfejs na pierwszym planie zmienia się, zanim dane zostaną wprowadzone w chwili `t1`.<sup>[[8]](#references)</sup> Późniejszy zrzut ekranu z chwili `t2` nie cofnie już wykonanej akcji.<sup>[[9]](#references)</sup> W autoryzowanym teście Androida można zastosować następujący schemat:<sup>[[8]](#references)</sup>

1. Określ współrzędne kontrolki docelowej na ekranie i umieść nieszkodliwą kontrolkę w tym samym miejscu w kontrolowanej aplikacji.
2. Utrzymuj tę aplikację widoczną do chwili, gdy agent ją zaobserwuje, a następnie wywołaj zwykłą zmianę aplikacji na pierwszym planie w czasie między obserwacją a działaniem.
3. Sprawdź, czy zaplanowane dotknięcie trafia w kontrolkę nowej aplikacji, i zweryfikuj wynikowy stan w aplikacji docelowej, zamiast polegać na relacji agenta.

Pierwotne badanie zmiany celu akcji demonstruje ją za pomocą aplikacji, która nie ma niebezpiecznych uprawnień; opisuje również powtarzanie zmiany podczas pętli odzyskiwania zadania przez agenta w przepływach wieloetapowych.<sup>[[8]](#references)</sup>

**Nie** zakładaj, że ten mechanizm działa tak samo w każdym asystencie. W ocenie Doubao `OpClickUI` pomijał kliknięcia, jeśli zmieniła się aktywność najwyższego poziomu, i porównywał zrzuty ekranu, gdy `OpOpenApp` pojawiło się w trzech poprzednich krokach. Pojedyncze i podwójne dotknięcia oraz długie naciśnięcia zapewniały więc niewiele wiarygodnych możliwości sterowania momentem przez atakującego. `OpTypeText`, `OpSwipeUI` i `OpScrollWheelAction` nie miały równoważnych zabezpieczeń, ale raport ocenił ich praktyczny wpływ jako bardziej ograniczony.<sup>[[9]](#references)</sup>

## Wykonanie: udowodnij rzeczywisty wpływ

Istnieją dwie odrębne drogi od wpływu do skutku:<sup>[[2]](#references)</sup>

1. **Nadużycie możliwości:** autoryzowane narzędzie już realizuje cel. Przykłady obejmują odczytanie rekordu z jednego tenanta i zapisanie go w raporcie widocznym dla atakującego, wysłanie e-maila, zmianę rekordów, usunięcie pliku lub zainicjowanie płatności. Nie jest wymagany żaden dodatkowy błąd oprogramowania.
2. **Eksploatacja downstream sink:** dane wyjściowe modelu, na które wpływa atakujący, stają się składnią dla innego komponentu. Sprawdź zapytania do bazy danych pod kątem [SQL injection](../pentesting-web/sql-injection/README.md) lub [NoSQL injection](../pentesting-web/nosql-injection.md), wrappery powłoki pod kątem [command injection](../pentesting-web/command-injection.md), wybrane adresy URL pod kątem [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operacje na plikach pod kątem path traversal, evaluatory szablonów/kodu pod kątem RCE oraz parsery obiektów pod kątem [unsafe deserialization](../pentesting-web/deserialization/README.md).

Dla każdego potencjalnego przypadku udowodnij następujący łańcuch:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Integracja tylko do odczytu nadal może zostać wykorzystana, jeśli dowolny późniejszy komponent może opublikować odczytane przez nią dane. Testuj zwykłe odpowiedzi oraz mniej oczywiste kanały egress, takie jak linki kontrolowane przez atakującego, automatyczne pobieranie obrazów, webhooki, logi, raporty, liczniki, powiadomienia i wiadomości do innych agentów.<sup>[[2]](#references)</sup>

## Działania realizujące cele

Po potwierdzeniu jednego działania oceń cały zasięg skutków, zamiast kończyć test na pierwszym widocznym efekcie:<sup>[[2]](#references)</sup>

- **Eksfiltracja:** sekrety, rekordy użytkowników, pliki wewnętrzne, dane konwersacji lub treść promptu/kontekstu opuszczają system przez obserwowalny kanał.
- **Nieautoryzowane działanie:** agent wykorzystuje uprawnione możliwości zapisu do realizacji celu atakującego.
- **Odmowa usługi:** destrukcyjne narzędzia lub wielokrotnie wykonywane kosztowne operacje wpływają na integralność lub dostępność.
- **Trwałość:** zatrute dane pamięci, indeksowana treść, zaufany stan lub zmiany środowiska uruchomieniowego utrzymują się po zakończeniu sesji lub usunięciu źródła.
- **Propagacja:** zaufany agent równorzędny przetwarza wiadomość lub współdzielony stan skompromitowanego agenta i powtarza działanie, korzystając z własnych narzędzi i poświadczeń.

Ocena dotkliwości powinna uwzględniać dostępne dane, efektywne uprawnienia, podatność punktu docelowego, egress, trwałość i propagację, a nie to, jak zaskakująco brzmi tekst modelu.<sup>[[2]](#references)</sup>

## Zabezpieczenia do sprawdzenia podczas oceny

Filtry promptów i lepszy prompt systemowy mogą podnieść koszt ataku, ale nie należy traktować ich jako granic autoryzacji. Sprawdź poniższe zabezpieczenia, ponownie przeprowadzając ten sam łańcuch przez bezpośrednie dane wejściowe, treści pośrednie, pamięć, narzędzia i agentów równorzędnych:<sup>[[2]](#references)</sup>

- Deterministyczna warstwa polityk sprawdza uwierzytelnionego użytkownika, dzierżawcę, obiekt, działanie i miejsce docelowe przy **każdym wywołaniu narzędzia**; model nie może podać ani nadpisać tożsamości wywołującego.
- Uprawnienia do odczytu i zapisu korzystają z oddzielnych, przyznających minimalne uprawnienia poświadczeń o krótkim czasie ważności; narzędzia o dużym wpływie są udostępniane tylko wtedy, gdy są potrzebne, i nigdy nie wykonują działań automatycznie na podstawie zaimportowanej treści.
- Egress sieciowy i wewnętrzne miejsca docelowe są niezależnie od adresów URL wybranych przez model ograniczone do list dozwolonych; dostęp środowiska uruchomieniowego do endpointów metadanych, zamontowanych sekretów i sąsiednich usług jest blokowany, chyba że jest wymagany.
- Interfejs zatwierdzania jest generowany na podstawie kanonicznego, ustrukturyzowanego żądania i pokazuje dokładne argumenty, tożsamość, miejsce docelowe, obiekty, których dotyczy działanie, oraz skutki uboczne — a nie swobodne podsumowanie modelu.
- Powodzenie jest weryfikowane w systemie docelowym lub systemie ewidencji. Opis agenta, żądanie wywołania narzędzia ani przekierowanie HTTP nie stanowią dowodu deklarowanej zmiany stanu.
- Wpisy pamięci i systemu wyszukiwania zachowują informacje o pochodzeniu i etykiety zaufania, można je unieważnić, a ich użycie do późniejszego działania wymaga ponownej autoryzacji.
- Wiadomości między agentami są uwierzytelniane i autoryzowane jako niezaufane żądania; reputacja agenta równorzędnego ani jego karta agenta nie delegują domyślnie narzędzi odbiorcy.

Informacje o kartach agentów A2A, przepływach zadań i ich powierzchni ataku znajdziesz w [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 dla aplikacji agentowych na 2026 rok](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Przewodnik hakera po atakowaniu agentów AI](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Jak trudno jest naprawdę wydostać agenta AI z jego sandboxa?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagenci w SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Kod źródłowy middleware TypeSafe Auto Mode w LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Nierówne możliwości modelu TypeSafe AI Jev: treści adwersarialne](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev jako sędzia: jak fałszywa polityka wpływa na Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Manipulacja bez uprawnień: czy możemy ufać agentom GUI opartym na dużych modelach multimodalnych?](https://arxiv.org/html/2601.12349v1)
- [9] [Gdy asystent AI staje się częścią łańcucha ataku hakera | Analiza bezpieczeństwa telefonu Doubao](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
