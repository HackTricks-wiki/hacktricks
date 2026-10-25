# Zagrożenia związane z AI

{{#include ../banners/hacktricks-training.md}}

## 10 najważniejszych podatności machine learning według OWASP

OWASP zidentyfikowało 10 najważniejszych podatności machine learning, które mogą wpływać na systemy AI. Mogą one prowadzić do różnych problemów z bezpieczeństwem, w tym zatruwania danych, odwracania modelu i ataków adwersarialnych. Zrozumienie tych podatności ma kluczowe znaczenie dla budowania bezpiecznych systemów AI.

Zaktualizowaną i szczegółową listę 10 najważniejszych podatności machine learning można znaleźć w projekcie [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Atak manipulacją danymi wejściowymi**: Atakujący wprowadza niewielkie, często niewidoczne zmiany w **danych wejściowych**, aby skłonić model do podjęcia błędnej decyzji.\
    *Przykład*: Kilka plamek farby na znaku stopu sprawia, że samochód autonomiczny „widzi” znak ograniczenia prędkości.

- **Atak zatruwaniem danych**: **Zbiór treningowy** zostaje celowo zanieczyszczony szkodliwymi próbkami, które uczą model niebezpiecznych reguł.\
*Przykład*: Pliki malware są błędnie oznaczane jako „nieszkodliwe” w zbiorze treningowym programu antywirusowego, przez co podobne malware może później uniknąć wykrycia.

- **Atak odwracaniem modelu**: Analizując odpowiedzi, atakujący buduje **model odwrotny**, który odtwarza wrażliwe cechy oryginalnych danych wejściowych.\
*Przykład*: Odtworzenie obrazu MRI pacjenta na podstawie przewidywań modelu wykrywającego raka.

- **Atak wnioskowaniem o przynależności**: Adwersarz sprawdza, czy **konkretny rekord** został użyty podczas treningu, analizując różnice w poziomie pewności modelu.\
*Przykład*: Potwierdzenie, że transakcja bankowa danej osoby znajduje się w danych treningowych modelu wykrywania oszustw.

- **Kradzież modelu**: Wielokrotne wysyłanie zapytań pozwala atakującemu poznać granice decyzyjne i **sklonować działanie modelu** (oraz własność intelektualną).\
*Przykład*: Pozyskanie wystarczającej liczby par pytań i odpowiedzi z API ML-as-a-Service, aby zbudować niemal równoważny model lokalny.

- **Atak na łańcuch dostaw AI**: Przejęcie dowolnego komponentu (**danych, bibliotek, wstępnie wytrenowanych wag, CI/CD**) w **potoku ML** może doprowadzić do uszkodzenia modeli na dalszych etapach.\
*Przykład*: Zatruta zależność z repozytorium modeli instaluje model analizy sentymentu z backdoorem w wielu aplikacjach.

- **Atak na transfer learning**: Szkodliwa logika zostaje osadzona we **wstępnie wytrenowanym modelu** i przetrwa dostrajanie do zadania ofiary.\
*Przykład*: Sieć bazowa do rozpoznawania obrazów z ukrytym wyzwalaczem nadal błędnie klasyfikuje obrazy po dostosowaniu jej do obrazowania medycznego.

- **Zniekształcenie modelu**: Subtelnie stronnicze lub błędnie oznaczone dane **zmieniają wyniki modelu**, aby sprzyjały celom atakującego.\
*Przykład*: Wstrzyknięcie „czystych” wiadomości spamowych oznaczonych jako niebędące spamem sprawia, że filtr antyspamowy przepuszcza podobne wiadomości w przyszłości.

- **Atak na integralność wyników**: Atakujący **zmienia przewidywania modelu podczas przesyłania**, nie modyfikując samego modelu, i wprowadza w błąd systemy korzystające z jego wyników.\
*Przykład*: Zmiana werdyktu klasyfikatora malware z „złośliwy” na „nieszkodliwy”, zanim plik trafi do etapu kwarantanny.

- **Zatrucie modelu** --- Bezpośrednie, ukierunkowane zmiany w **parametrach modelu**, często po uzyskaniu dostępu z prawem zapisu, w celu zmiany jego działania.\
*Przykład*: Zmiana wag modelu wykrywania oszustw działającego produkcyjnie, aby transakcje z określonych kart były zawsze zatwierdzane.


## Zagrożenia SAIF Google

Framework [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) firmy Google przedstawia różne zagrożenia związane z systemami AI:<sup>[[2]](#references)</sup>

- **Zatruwanie danych**: Szkodliwi aktorzy modyfikują dane treningowe lub dostrajające albo dodają do nich nowe próbki, aby obniżyć dokładność, osadzić backdoory lub zniekształcić wyniki, naruszając integralność modelu na każdym etapie cyklu życia danych.

- **Nieautoryzowane dane treningowe**: Wykorzystywanie chronionych prawem autorskim, wrażliwych lub niezatwierdzonych zbiorów danych wiąże się z ryzykiem prawnym, etycznym i wydajnościowym, ponieważ model uczy się na danych, do których użycia nie miał uprawnień.

- **Manipulacja kodem źródłowym modelu**: Manipulacja kodem modelu, zależnościami lub wagami przed treningiem lub w jego trakcie, dokonana przez atakujących z łańcucha dostaw lub osoby z wewnątrz organizacji, może osadzić ukrytą logikę, która przetrwa nawet ponowny trening.

- **Nadmierne przetwarzanie danych**: Słabe mechanizmy retencji i nadzoru nad danymi sprawiają, że systemy przechowują lub przetwarzają więcej danych osobowych, niż to konieczne, zwiększając ryzyko ich ujawnienia i niezgodności z przepisami.

- **Eksfiltracja modelu**: Atakujący kradną pliki lub wagi modelu, powodując utratę własności intelektualnej i umożliwiając tworzenie usług kopiujących model lub przeprowadzanie kolejnych ataków.

- **Manipulacja wdrożonym modelem**: Adwersarze modyfikują artefakty modelu lub infrastrukturę usługową, przez co działający model różni się od zatwierdzonej wersji, co może zmienić jego zachowanie.

- **Odmowa dostępu do usługi ML**: Zalewanie API zapytaniami lub wysyłanie danych wejściowych typu „sponge” może wyczerpać zasoby obliczeniowe lub energię i wyłączyć model, podobnie jak w klasycznych atakach DoS.

- **Inżynieria wsteczna modelu**: Gromadząc dużą liczbę par danych wejściowych i wyjściowych, atakujący mogą sklonować lub destylować model, co sprzyja tworzeniu produktów naśladujących oryginał i dostosowanych ataków adwersarialnych.

- **Niezabezpieczony zintegrowany komponent**: Podatne wtyczki, agenci lub usługi nadrzędne pozwalają atakującym wstrzykiwać kod lub eskalować uprawnienia w potoku AI.

- **Prompt Injection**: Konstruowanie promptów — bezpośrednio lub pośrednio — w celu przemycenia instrukcji, które nadpisują intencje systemu i skłaniają model do wykonania niezamierzonych poleceń.

- **Obejście zabezpieczeń modelu**: Starannie przygotowane dane wejściowe skłaniają model do błędnej klasyfikacji, halucynowania lub generowania niedozwolonych treści, podważając bezpieczeństwo i zaufanie.

- **Ujawnienie wrażliwych danych**: Model ujawnia prywatne lub poufne informacje z danych treningowych lub kontekstu użytkownika, naruszając prywatność i przepisy.

- **Wywnioskowanie wrażliwych danych**: Model wyciąga wnioski na temat cech osobistych, które nie zostały mu podane, powodując nowe zagrożenia dla prywatności.

- **Niezabezpieczone wyniki modelu**: Niesanitowane odpowiedzi przekazują użytkownikom lub systemom dalszego przetwarzania szkodliwy kod, dezinformację lub nieodpowiednie treści.

- **Nieautoryzowane działania**: Agenci zintegrowani z systemem autonomicznie wykonują niezamierzone działania w świecie rzeczywistym (zapis plików, wywołania API, zakupy itp.) bez odpowiedniego nadzoru użytkownika.

## Macierz MITRE AI ATLAS

[Macierz MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS) zapewnia kompleksowe ramy do zrozumienia i ograniczania zagrożeń związanych z systemami AI. Klasyfikuje różne techniki i taktyki ataków, których adwersarze mogą używać przeciwko modelom AI, a także sposoby wykorzystania systemów AI do przeprowadzania różnych ataków.<sup>[[3]](#references)</sup>

## LLMJacking (kradzież tokenów i odsprzedaż dostępu do LLM hostowanych w chmurze)

Atakujący kradną aktywne tokeny sesji lub poświadczenia cloud API i bez uprawnień wywołują płatne LLM hostowane w chmurze. Dostęp jest często odsprzedawany za pośrednictwem reverse proxy, które przekazują żądania przez konto ofiary, np. wdrożenia „oai-reverse-proxy”. Skutki obejmują straty finansowe, niewłaściwe użycie modelu niezgodne z zasadami oraz przypisanie działań do dzierżawy ofiary.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP:
- Pozyskiwanie tokenów z zainfekowanych komputerów deweloperów lub przeglądarek; kradzież sekretów CI/CD; kupowanie wyciekłych cookies.<sup>[[5]](#references)</sup>
- Uruchomienie reverse proxy, które przekazuje żądania do prawdziwego dostawcy, ukrywa klucz upstream i obsługuje wielu klientów jednocześnie.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Nadużywanie bezpośrednich endpointów modelu bazowego w celu ominięcia zabezpieczeń dla przedsiębiorstw i limitów szybkości.<sup>[[4]](#references)</sup>

Środki zaradcze:
- Powiąż tokeny z odciskiem urządzenia, zakresami adresów IP i atestacją klienta; stosuj krótkie terminy ważności i wymagaj MFA przy odświeżaniu.
- Ogranicz zakres kluczy do minimum (bez dostępu do narzędzi, tylko do odczytu tam, gdzie to możliwe); rotuj klucze w przypadku anomalii.
- Kieruj cały ruch po stronie serwera przez bramę polityk, która wymusza stosowanie filtrów bezpieczeństwa, limitów dla poszczególnych tras i izolacji dzierżaw.
- Monitoruj nietypowe wzorce użycia (nagłe skoki wydatków, nietypowe regiony, ciągi UA) i automatycznie unieważniaj podejrzane sesje.
- Zamiast długotrwałych statycznych kluczy API używaj mTLS lub podpisanych JWT wystawianych przez IdP.

## Zabezpieczanie wnioskowania przez samodzielnie hostowane LLM

Uruchomienie lokalnego serwera LLM do obsługi poufnych danych tworzy inną powierzchnię ataku niż korzystanie z API hostowanych w chmurze: endpointy wnioskowania i debugowania mogą ujawniać prompty, stos usługowy zwykle udostępnia reverse proxy, a węzły urządzeń GPU dają dostęp do rozbudowanych powierzchni `ioctl()`. Jeśli oceniasz lub wdrażasz lokalną usługę wnioskowania on-prem, sprawdź co najmniej poniższe kwestie.<sup>[[8]](#references)</sup>

### Wyciek promptów przez endpointy debugowania i monitorowania

Traktuj API wnioskowania jako **wrażliwą usługę wieloużytkownikową**. Trasy debugowania lub monitorowania mogą ujawniać treść promptów, stan slotów, metadane modelu lub wewnętrzne informacje o kolejce. W `llama.cpp` endpoint `/slots` jest szczególnie wrażliwy, ponieważ udostępnia stan poszczególnych slotów i służy wyłącznie do ich inspekcji lub zarządzania nimi.<sup>[[8]](#references)</sup>

Aby przeprowadzić black-box fingerprinting i testy ujawnionych runnerów modeli oraz powiązanych usług AI, sprawdź [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Umieść reverse proxy przed serwerem wnioskowania i **domyślnie odrzucaj żądania**.
- Dodaj do allowlisty tylko dokładne kombinacje metod HTTP i ścieżek wymagane przez klienta/UI.
- Jeśli to możliwe, wyłącz endpointy introspekcji bezpośrednio w backendzie, na przykład `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Powiąż reverse proxy z `127.0.0.1` i udostępniaj je przez uwierzytelniony transport, taki jak przekierowanie lokalnego portu SSH, zamiast publikować je w sieci LAN.

Przykładowa allowlista w nginx:

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

### Kontenery rootless bez sieci i gniazda UNIX

Jeśli demon wnioskowania obsługuje nasłuchiwanie na gnieździe UNIX, wybierz tę opcję zamiast TCP i uruchom kontener **bez stosu sieciowego**:<sup>[[8]](#references)</sup>

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

Korzyści:
- `--network none` eliminuje ekspozycję TCP/IP na ruch przychodzący i wychodzący oraz pozwala uniknąć pomocników działających w przestrzeni użytkownika, których w przeciwnym razie potrzebowałyby kontenery rootless.
- Socket UNIX pozwala używać uprawnień POSIX/ACL na ścieżce socketu jako pierwszej warstwy kontroli dostępu.
- `--userns=keep-id` i rootless Podman ograniczają skutki ucieczki z kontenera, ponieważ root w kontenerze nie jest rootem na hoście.
- Montowanie modeli tylko do odczytu zmniejsza ryzyko ich modyfikacji z wnętrza kontenera.

W przypadku wdrożeń trwałych te same ograniczenia można skonfigurować za pomocą jednostek Podman Quadlet. Jeśli dostęp do GPU jest delegowany przez Container Device Interface, specyfikacja urządzeń CDI powinna być możliwie wąska, zamiast udostępniać wszystkie węzły akceleratorów.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Ograniczanie liczby węzłów urządzeń GPU

W przypadku wnioskowania z użyciem GPU pliki `/dev/nvidia*` stanowią wartościowe lokalne powierzchnie ataku, ponieważ udostępniają rozbudowane procedury obsługi sterownika `ioctl()` oraz potencjalnie współdzielone ścieżki zarządzania pamięcią GPU.<sup>[[8]](#references)</sup>

- Nie pozostawiaj plików `/dev/nvidia*` z prawem zapisu dla wszystkich.
- Ogranicz dostęp do `nvidia`, `nvidiactl` i `nvidia-uvm` za pomocą `NVreg_DeviceFileUID/GID/Mode`, reguł udev i ACL, tak aby mogły je otwierać tylko mapowane identyfikatory UID kontenerów.
- Na hostach do wnioskowania bez interfejsu graficznego blokuj niepotrzebne moduły, takie jak `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem`.
- Załaduj wstępnie tylko wymagane moduły podczas uruchamiania systemu, zamiast pozwalać środowisku wykonawczemu na ich doraźne ładowanie za pomocą `modprobe` podczas uruchamiania wnioskowania.

Przykład:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Jednym z ważnych punktów do sprawdzenia jest **`/dev/nvidia-uvm`**. Nawet jeśli workload nie używa jawnie `cudaMallocManaged()`, nowsze środowiska uruchomieniowe CUDA mogą nadal wymagać `nvidia-uvm`. Ponieważ to urządzenie jest współdzielone i obsługuje zarządzanie wirtualną pamięcią GPU, należy traktować je jako powierzchnię narażenia na wyciek danych między tenantami. Jeśli backend wnioskowania to obsługuje, backend Vulkan może być interesującym kompromisem, ponieważ może całkowicie wyeliminować konieczność udostępniania `nvidia-uvm` kontenerowi.<sup>[[8]](#references)</sup>

### Izolacja LSM dla workerów wnioskowania

AppArmor/SELinux/seccomp należy stosować jako dodatkową warstwę ochrony procesu wnioskowania:<sup>[[8]](#references)</sup>

- Zezwalaj wyłącznie na współdzielone biblioteki, ścieżki modeli, katalog gniazd i węzły urządzeń GPU, które są rzeczywiście wymagane.
- Jawnie blokuj niebezpieczne uprawnienia, takie jak `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Ustaw katalog modelu jako tylko do odczytu, a zapisy dozwól wyłącznie w katalogach gniazd i pamięci podręcznej środowiska uruchomieniowego.
- Monitoruj logi odmów, ponieważ dostarczają przydatnych danych telemetrycznych do wykrywania prób ucieczki z oczekiwanego zachowania przez serwer modelu lub payload po eksploatacji.

Przykładowe reguły AppArmor dla workera korzystającego z GPU:

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

## Phantom Squatting: domeny halucynowane przez LLM jako wektor ataku na łańcuch dostaw AI

Phantom squatting to **odpowiednik slopsquattingu dla domen/URL-i**. Zamiast halucynować nieistniejącą nazwę pakietu, LLM halucynuje wiarygodną domenę **portalu, API, webhooka, rozliczeń, SSO, pobierania lub pomocy technicznej** prawdziwej marki, a atakujący rejestruje tę przestrzeń nazw, zanim użyje jej człowiek lub agent.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ma to znaczenie, ponieważ w wielu przepływach pracy wspomaganych przez AI wynik modelu traktowany jest jako **zaufana zależność**:
- Deweloperzy wklejają sugerowany endpoint do kodu lub integracji CI/CD.
- Agenci AI automatycznie pobierają dokumentację, schematy, pliki APK, ZIP lub adresy docelowe webhooków.
- Wygenerowane instrukcje operacyjne lub dokumentacja mogą zawierać fałszywy URL, jakby był wiarygodny.

### Przebieg ataku

1. **Zbadaj powierzchnię halucynacji**: zadawaj pytania dotyczące konkretnej marki i realistycznych przepływów pracy, takich jak portale `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` lub `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizuj kandydatów**: rozwiązuj wygenerowane URL-e, sprowadzaj odpowiedzi NXDOMAIN do nadrzędnej domeny, którą można zarejestrować, i usuwaj duplikaty z rodzin promptów. Zbiory promptów powinny być zróżnicowane, na przykład przez odrzucanie niemal identycznych promptów z użyciem **podobieństwa Jaccarda**.
3. **Nadaj priorytet przewidywalnym halucynacjom**:
   - **Thermal Hallucination Persistence (THP)**: ta sama fałszywa domena pojawia się przy różnych wartościach temperatury, w tym niskich, takich jak `T=0.1`.
   - **Konsensus między modelami**: wiele rodzin LLM generuje tę samą fałszywą domenę.
4. **Zarejestruj i uzbrój** domenę nadrzędną, a następnie udostępniaj phishing, fałszywe pliki APK/ZIP do pobrania, narzędzia do wyłudzania danych uwierzytelniających, złośliwe dokumenty lub endpointy API zbierające sekrety/payloady webhooków. **Halucynacje dotyczące samej domeny** najłatwiej monetyzować, ponieważ atakujący kontroluje całą przestrzeń nazw; halucynacje dotyczące subdomen/ścieżek również można wykorzystać, jeśli znormalizowana domena nadrzędna nie jest zarejestrowana.
5. **Wykorzystaj okno zerowej reputacji**: nowo zarejestrowane domeny często nie mają historii na listach blokowanych, reputacji URL ani dojrzałej telemetrii, więc mogą omijać zabezpieczenia, dopóki systemy wykrywania nie nadrobią zaległości. Atakujący mogą wydłużyć to okno, stosując nieszkodliwe odpowiedzi widoczne tylko dla crawlerów, ukrywanie przekierowań, bramki CAPTCHA lub opóźnione przygotowanie payloadu.

### Dlaczego jest to niebezpieczne dla agentów

W przypadku człowieka domena zwykle nadal wymaga kliknięcia i wykonania kolejnej czynności. W **agentowym przepływie pracy** LLM może być jednocześnie **przynętą** i **wykonawcą**: agent otrzymuje halucynowany URL, pobiera go, analizuje odpowiedź, a następnie może ujawnić tokeny, wykonać instrukcje, pobrać zależność lub umieścić zatrute dane w CI/CD bez jakiejkolwiek weryfikacji przez człowieka.<sup>[[12]](#references)</sup>

### Przykładowe prompty atakującego

Najskuteczniejsze prompty zwykle przypominają normalne zadania korporacyjne, a nie jawne przynęty phishingowe:<sup>[[12]](#references)</sup>
- „Jaki jest adres URL piaskownicy płatności dla integracji `<brand>`?”
- „Jakiego endpointu webhooka użyć do powiadomień o kompilacjach `<brand>`?”
- „Gdzie znajduje się portal świadczeń pracowniczych / rozliczeń / SSO dla `<brand>`?”
- „Podaj bezpośredni link do pobrania aplikacji APK na Androida lub klienta desktopowego dla `<brand>`.”

### Odwrócenie podejścia na obronne

Potraktuj to jako problem proaktywnego monitorowania domen, a nie tylko problem prompt injection:<sup>[[12]](#references)</sup>
- Zbuduj **zbiór promptów dotyczących marek** i okresowo sonduj LLM-y, z których korzystają Twoi użytkownicy/agenci.
- Zapisuj halucynowane URL-e i śledź, które z nich są stabilne w różnych temperaturach/modelach.
- Śledź **Adversarial Exploitation Window (AEW)**: czas między pierwszą halucynacją a rejestracją przez atakującego. Dodatnie AEW oznacza, że obrońcy mogą wcześniej zarejestrować domenę, skierować ją do sinkhole'a lub zablokować przed uzbrojeniem.
- Monitoruj zmiany **NXDOMAIN → zarejestrowana** dla domen nadrzędnych.
- Po rejestracji sprawdź rejestratora, datę utworzenia, serwery nazw, ochronę prywatności, zawartość strony, zrzuty ekranu, status strony parkingowej i podobieństwo zasobów marki.
- Dodaj bramki polityk, aby agenci/deweloperzy **domyślnie nie ufali domenom wygenerowanym przez LLM**: wymagaj list dozwolonych, walidacji własności, kontroli CT/RDAP lub zatwierdzenia przez człowieka przed pierwszym użyciem.

Zjawisko to wpisuje się jednocześnie w kilka kategorii ryzyka AI: **atak na łańcuch dostaw AI**, **niebezpieczne wyniki modelu** oraz **nieautoryzowane działania**, gdy agenci autonomicznie korzystają z halucynowanego URL-a.

## References

- [1] [OWASP Top 10 — podatności uczenia maszynowego](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) — zagrożenia](https://saif.google/secure-ai-framework/risks)
- [3] [Macierz zagrożeń MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 — zagrożenia związane z LLM-ami wspomagającymi kodowanie: szkodliwe treści, nadużycia i oszustwa](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig — LLMjacking: skradzione poświadczenia chmurowe wykorzystane w nowym ataku AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Omówienie schematu LLMJacking — The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (odsprzedaż skradzionego dostępu do LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv — szczegółowa analiza wdrożenia lokalnego serwera LLM o niskich uprawnieniach](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README serwera llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlety Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specyfikacja CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 — Phantom Squatting: domeny halucynowane przez AI jako wektor ataku na łańcuch dostaw oprogramowania](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket — Slopsquatting: jak halucynacje AI napędzają nową klasę ataków na łańcuch dostaw](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
