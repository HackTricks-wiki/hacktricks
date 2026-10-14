# Metodologia bezpieczeństwa agentów AI

{{#include ../banners/hacktricks-training.md}}

Ocena agenta powinna śledzić **drogę od danych wejściowych kontrolowanych przez atakującego do zewnętrznie obserwowalnego skutku**. Jailbreaking, zmiany charakteru i ujawnienie system promptu dowodzą, że można wpłynąć na kanał rozumowania, ale najpoważniejszym ustaleniem jest łańcuch prowadzący do dostępu do danych, nieautoryzowanego działania narzędzia, sinka podatnego na downstream injection, utrwalenia lub innego agenta.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) przydaje się do oznaczania zakresu testów (przejęcie celu, niewłaściwe użycie narzędzi, nadużycie uprawnień, łańcuch dostaw, wykonanie kodu, zatruwanie pamięci, zaufanie między agentami, awarie kaskadowe, zaufanie człowieka i nieposłuszni agenci). Używaj tych etykiet po zbudowaniu kompleksowej ścieżki ataku, zamiast uznawać nieoczekiwany tekst modelu za koniec testu.<sup>[[1]](#references)[[2]](#references)</sup>

## Zbuduj mapę celu

Przed przygotowaniem payloadów odnotuj te pięć wymiarów dla każdego przepływu pracy agenta:<sup>[[2]](#references)</sup>

| Wymiar | Co zinwentaryzować | Pytanie dotyczące bezpieczeństwa |
|---|---|---|
| **Niezaufane dane wejściowe** | Parametry Chat/API, adresy URL, dokumenty, e-maile, zgłoszenia, wpisy w kalendarzu, pobrane fragmenty, pamięć, wyniki narzędzi i wiadomości agentów równorzędnych | Gdzie atakujący może umieścić treść, która później trafi do kontekstu modelu? |
| **Narzędzia** | Nazwy i schematy narzędzi, skutki uboczne, automatyczne wykonywanie, sposób potwierdzania i dynamicznie ładowane narzędzia | Które wywołania odczytują sekrety, zapisują stan, wysyłają wiadomości, usuwają dane, wykonują kod lub przekazują wartość? |
| **Uprawnienia** | Delegowanie przez użytkownika, konta usługowe, tokeny API, okres ważności poświadczeń, zakres tenantów/zasobów i dostęp do sieci | W ramach jakiej tożsamości wykonywane jest każde wywołanie i czy autoryzacja jest ponownie sprawdzana na granicy narzędzia? |
| **Przetwarzanie** | Konstruktor zapytań, powłoki, narzędzia pobierające URL-e, silniki szablonów, interpretery, parsery, operacje na plikach i deserializatory | Gdzie dane wygenerowane przez model stają się składnią dla innego interpretera? |
| **Wyjście** | Odpowiedzi, renderowany Markdown/HTML, linki, pobieranie obrazów, webhooki, e-maile, pliki, logi, raporty, metryki i ruch między agentami | Który obserwowalny kanał może przenosić sekret lub wywołać wtórne żądanie? |

Nie sprowadzaj tego do listy reklamowanych integracji. Przydatny artefakt mapuje każde źródło na dokładne miejsce w kontekście, do którego trafia, dostępne w tym miejscu narzędzia, poświadczenia używane przez każde narzędzie, dalszy interpreter i wszystkie drogi eksfiltracji. To samo narzędzie może mieć niewielki wpływ przy tokenie odczytu przypisanym do użytkownika, a krytyczny — przy współdzielonych poświadczeniach administratora.<sup>[[2]](#references)</sup>

## Rozpoznanie

### Zmapuj wszystkie ścieżki dostarczania i pobierania danych

Zacznij od powierzchni dostarczania (web, urządzenia mobilne, API, e-mail, platforma czatu, rozszerzenie przeglądarki) i przeanalizuj ruch klient–backend za pomocą proxy. Sprawdź pola ukryte przez interfejs, parametry wyszukiwania/autouzupełniania/filtrowania, obiekty stanu konwersacji, zadania przesyłania i indeksowania, odpowiedzi narzędzi oraz ruch między agentami podrzędnymi. W przypadku klientów dostępnych tylko na urządzeniach mobilnych może być konieczny emulator i instrumentacja omijająca certificate pinning, zanim ujawni się rzeczywisty schemat żądań.<sup>[[2]](#references)</sup>

Następnie zmapuj stos działający pod modelem: framework orkiestracji, składanie promptów, magazyny danych retrieval i pamięci, środowisko wykonawcze (na przykład Python, kontener lub WASM), podmontowane woluminy, usługi hosta, wewnętrzne API, dostęp do cloud metadata oraz sąsiednie sieci. Domyślne ustawienia frameworka mają znaczenie, ponieważ niektóre „wywołania narzędzi” są realizowane przez generowanie lub ewaluację kodu; granica środowiska wykonawczego/sandboxa decyduje, czy wynik pozostanie odizolowany.<sup>[[2]](#references)</sup>

### Ustal routing za pomocą niedestrukcyjnych sond

Porównaj żądanie mieszczące się w zakresie testu z kilkoma niezwiązanymi żądaniami, zachowując pełną odpowiedź, kod statusu, opóźnienie i zachowanie strumieniowania. Powtarzalne odrzucenie przed rozpoczęciem rozumowania dotyczącego konkretnego zadania może wskazywać na odrębną bramę/klasyfikator; odmowa zależna od kontekstu sugeruje, że żądanie dotarło do modelu; pusta lub wyłącznie ekstrakcyjna odpowiedź może wskazywać na wyszukiwanie słów kluczowych lub ograniczony retrieval. Traktuj te obserwacje jako hipotezy i potwierdzaj je, odtwarzając tę samą sondę przez alternatywne pola API i ścieżki pobierania danych.<sup>[[2]](#references)</sup>

Rozpoznanie jest zakończone, gdy ocena pozwala wskazać najwcześniejsze źródło kontrolowane przez atakującego, które zmienia zachowanie agenta, **oraz** narzędzia, tożsamości, interpretery i wyjścia dostępne z tego źródła.<sup>[[2]](#references)</sup>

## Eksploatacja: przekrocz granicę zaufania

Testuj kanały, a nie tylko sformułowania promptów. Zacznij od bezpośredniej injection, aby ustalić, co blokuje widoczny punkt wejścia, a następnie powtórz równoważną próbę za pośrednictwem mniej widocznych ścieżek wymienionych poniżej:<sup>[[2]](#references)</sup>

- **Treści pośrednie:** strony, pliki, e-maile, zgłoszenia, metadane, tekst alternatywny, komentarze HTML, tekst poza ekranem lub znaki o zerowej szerokości. Techniki dostarczania payloadów opisano w [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection).
- **Retrieval i pamięć:** zatruj treść, która zostanie pobrana później, lub stan, który zostanie ponownie załadowany podczas kolejnych sesji. Odnotuj, czy usunięcie pierwotnego źródła eliminuje dane zachowanie.
- **Wynik narzędzia i agenci równorzędni:** umieść znacznik w odpowiedzi narzędzia lub wiadomości między agentami, aby sprawdzić, czy ruch wewnętrzny omija filtry stosowane wyłącznie do danych wejściowych użytkownika i końcowego wyjścia.
- **Łańcuch dostaw:** sprawdź deskryptory narzędzi, pluginy, podłączone serwery, skills, modele i zależności traktowane jako zaufane źródła instrukcji. Testy dotyczące MCP opisano w [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Zatwierdzanie przez człowieka:** porównaj rzeczywiste, ustrukturyzowane wywołanie narzędzia z wygenerowanym przez model tekstem zatwierdzającym. Sprawdź, czy wpływ atakującego może spowodować pominięcie celu, zakresu, obiektów, których dotyczy operacja, lub nieodwracalnych skutków ubocznych.

Najpierw użyj nieszkodliwego, unikalnego znacznika. Zachowaj artefakt źródłowy, złożony kontekst (jeśli jest widoczny), wybrane wywołanie narzędzia, dane zatwierdzenia, żądanie/odpowiedź backendu i stan końcowy. Pozwoli to odróżnić rzeczywisty wpływ od zmyślonego twierdzenia, że doszło do działania.<sup>[[2]](#references)</sup>

### Izolacja kontekstu subagenta

Subagent Claude Agent SDK działający bez forka otrzymuje własny `AgentDefinition.prompt`, prompt delegowania i dostępne narzędzia, ale nie system prompt ani konwersację rodzica. Jeśli w jego definicji pominięto `tools`, dziedziczy narzędzia dostępne subagentom; projektowy plik `CLAUDE.md` może nadal zostać załadowany. Oznacza to, że ograniczenie zawarte wyłącznie w promptcie rodzica nie stanowi niezawodnej granicy, jeśli dziecko może korzystać z tego samego systemu plików lub narzędzi wykonawczych.<sup>[[4]](#references)</sup>

Przetestuj tę granicę, porównując bezpośrednie żądanie, którego rodzic odmawia, z tym samym zadaniem delegowanym do nazwanego subagenta. NCC Group informuje, że wyliczenie plików systemu operacyjnego, któremu odmówił rodzic, powiodło się po przeformułowaniu zadania dla dziecka jako nieszkodliwej „mapy układu”.<sup>[[3]](#references)</sup>

Sprawdź rzeczywiste wywołania narzędzi dziecka i efektywną listę dozwolonych narzędzi, a nie tylko końcową odpowiedź rodzica; potwierdź, czy dziecko uzyskało dostęp do plików niedostępnych dla rodzica.<sup>[[4]](#references)</sup> To błąd dziedziczenia guardrails, a nie dowód na ucieczkę z [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) lub kontenera.<sup>[[3]](#references)[[4]](#references)</sup>

## Wykonanie: udowodnij rzeczywisty wpływ

Istnieją dwie odrębne ścieżki od wpływu do skutku:<sup>[[2]](#references)</sup>

1. **Nadużycie możliwości:** autoryzowane narzędzie już realizuje cel. Przykłady to odczytanie rekordu jednego tenanta i zapisanie go w raporcie widocznym dla atakującego, wysłanie e-maila, zmiana rekordów, usunięcie pliku lub zainicjowanie płatności. Nie jest wymagany żaden wtórny błąd oprogramowania.
2. **Eksploatacja downstream sinka:** treść modelu sterowana przez atakującego staje się składnią dla innego komponentu. Sprawdź konstruktory zapytań do baz danych pod kątem [SQL injection](../pentesting-web/sql-injection/README.md) lub [NoSQL injection](../pentesting-web/nosql-injection.md), wrappery powłoki pod kątem [command injection](../pentesting-web/command-injection.md), wybrane adresy URL pod kątem [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operacje na plikach pod kątem path traversal, ewaluatory szablonów/kodu pod kątem RCE, a parsery obiektów pod kątem [unsafe deserialization](../pentesting-web/deserialization/README.md).

Dla każdego przypadku udowodnij następujący łańcuch:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Integracja tylko do odczytu nadal może zostać wykorzystana, jeśli dowolny późniejszy komponent może opublikować odczytane przez nią dane. Testuj zwykłe odpowiedzi oraz mniej oczywiste kanały wyprowadzania danych, takie jak linki kontrolowane przez atakującego, automatyczne pobieranie obrazów, webhooki, logi, raporty, liczniki, powiadomienia i wiadomości do innych agentów.<sup>[[2]](#references)</sup>

## Działania na celach

Po potwierdzeniu jednego działania oceń pełny zakres jego skutków, zamiast poprzestawać na pierwszym widocznym efekcie:<sup>[[2]](#references)</sup>

- **Eksfiltracja:** sekrety, rekordy użytkowników, pliki wewnętrzne, dane konwersacji lub zawartość promptu/kontekstu opuszczają system przez obserwowalny kanał.
- **Nieautoryzowane działanie:** agent wykorzystuje legalne uprawnienia do zapisu, aby zrealizować cel atakującego.
- **Odmowa usługi:** narzędzia destrukcyjne lub wielokrotnie wykonywane kosztowne operacje wpływają na integralność lub dostępność.
- **Trwałość:** zatruta pamięć, zindeksowana zawartość, zaufany stan lub zmiany środowiska wykonawczego przetrwają sesję lub usunięcie źródła, które je spowodowało.
- **Propagacja:** zaufany agent równorzędny wykorzystuje wiadomość lub współdzielony stan naruszonego agenta i powtarza działanie przy użyciu własnych narzędzi i poświadczeń.

Poziom zagrożenia powinien zależeć od dostępnych danych, efektywnych uprawnień, podatności sinka na wykorzystanie, kanałów wyprowadzania danych, trwałości i propagacji — a nie od tego, jak zaskakująco brzmi tekst modelu.<sup>[[2]](#references)</sup>

## Zabezpieczenia do zweryfikowania podczas oceny

Filtry promptów i lepszy prompt systemowy mogą podnieść koszt ataku, ale nie należy traktować ich jako granic autoryzacji. Zweryfikuj poniższe zabezpieczenia, ponownie przeprowadzając ten sam łańcuch przez bezpośrednie dane wejściowe, treści pośrednie, pamięć, narzędzia i agentów równorzędnych:<sup>[[2]](#references)</sup>

- Deterministyczna warstwa polityk sprawdza uwierzytelnionego użytkownika, tenant, obiekt, działanie i miejsce docelowe przy **każdym wywołaniu narzędzia**; model nie może podać ani nadpisać tożsamości wywołującego.
- Uprawnienia do odczytu i zapisu korzystają z oddzielnych poświadczeń o minimalnych uprawnieniach i krótkim czasie ważności; narzędzia o dużym wpływie są udostępniane tylko w razie potrzeby i nigdy nie wykonują działań automatycznie na podstawie zaimportowanej treści.
- Kanały wychodzące z sieci i wewnętrzne miejsca docelowe są niezależnie dodawane do listy dozwolonych, a wybór URL-i przez model nie ma na to wpływu; dostęp środowiska wykonawczego do endpointów metadanych, zamontowanych sekretów i sąsiednich usług jest blokowany, o ile nie jest wymagany.
- Interfejs zatwierdzania jest generowany z kanonicznego, ustrukturyzowanego żądania i pokazuje dokładne argumenty, tożsamość, miejsce docelowe, obiekty, których dotyczy działanie, oraz skutki uboczne — a nie swobodne podsumowanie wygenerowane przez model.
- Powodzenie jest weryfikowane w systemie docelowym lub systemie będącym źródłem prawdy. Opis agenta, żądanie wywołania narzędzia ani przekierowanie HTTP nie stanowią dowodu deklarowanej zmiany stanu.
- Wpisy pamięci i systemów wyszukiwania zachowują informacje o pochodzeniu i etykiety zaufania, można je unieważnić, a ich użycie do późniejszego działania wymaga ponownej autoryzacji.
- Wiadomości między agentami są uwierzytelniane i autoryzowane jako niezaufane żądania; reputacja agenta ani jego karta nie delegują domyślnie narzędzi odbiorcy.

## References

- [1] [OWASP Top 10 dla aplikacji agentowych na 2026 rok](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Przewodnik hakera po atakowaniu agentów AI](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Jak trudno jest naprawdę wydostać agenta AI z jego piaskownicy?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagenci w SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
{{#include ../banners/hacktricks-training.md}}
