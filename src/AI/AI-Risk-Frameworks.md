# Ryzyka związane z AI

{{#include ../banners/hacktricks-training.md}}

## 10 najważniejszych podatności uczenia maszynowego według OWASP

OWASP wskazała 10 najważniejszych podatności uczenia maszynowego, które mogą dotyczyć systemów AI. Mogą one prowadzić do różnych problemów z bezpieczeństwem, w tym zatruwania danych, odwracania modelu i ataków adwersarialnych. Zrozumienie tych podatności ma kluczowe znaczenie przy tworzeniu bezpiecznych systemów AI.

Aktualną i szczegółową listę 10 najważniejszych podatności uczenia maszynowego znajdziesz w projekcie [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Atakujący wprowadza drobne, często niewidoczne zmiany w **danych wejściowych**, aby skłonić model do podjęcia błędnej decyzji.\
    *Przykład*: Kilka plamek farby na znaku stopu sprawia, że autonomiczny samochód „widzi” znak ograniczenia prędkości.

- **Data Poisoning Attack**: **Zbiór treningowy** zostaje celowo zanieczyszczony błędnymi próbkami, przez co model uczy się szkodliwych reguł.\
*Przykład*: Binarne pliki malware zostają oznaczone jako „nieszkodliwe” w zbiorze treningowym programu antywirusowego, dzięki czemu podobne malware może później uniknąć wykrycia.

- **Model Inversion Attack**: Analizując odpowiedzi modelu, atakujący tworzy **model odwrotny**, który odtwarza wrażliwe cechy oryginalnych danych wejściowych.\
*Przykład*: Odtworzenie obrazu MRI pacjenta na podstawie predykcji modelu wykrywającego raka.

- **Membership Inference Attack**: Adwersarz sprawdza, czy **konkretny rekord** został użyty podczas treningu, analizując różnice w poziomie pewności modelu.\
*Przykład*: Potwierdzenie, że transakcja bankowa danej osoby znajduje się w danych treningowych modelu wykrywającego oszustwa.

- **Model Theft**: Wielokrotne wysyłanie zapytań pozwala atakującemu poznać granice decyzyjne i **sklonować zachowanie modelu** (oraz własność intelektualną).\
*Przykład*: Zebranie wystarczającej liczby par pytań i odpowiedzi z API ML-as-a-Service, by zbudować lokalny model o niemal równoważnych możliwościach.

- **AI Supply‑Chain Attack**: Przejęcie dowolnego komponentu (**danych, bibliotek, wstępnie wytrenowanych wag, CI/CD**) w **potoku ML** w celu uszkodzenia modeli na dalszych etapach.\
*Przykład*: Zainfekowana zależność z repozytorium modeli instaluje model analizy sentymentu z backdoorem w wielu aplikacjach.

- **Transfer Learning Attack**: Złośliwa logika zostaje zaszyta w **wstępnie wytrenowanym modelu** i przetrwa fine-tuning na zadaniu ofiary.\
*Przykład*: Model bazowy do analizy obrazów z ukrytym wyzwalaczem nadal zmienia etykiety po dostosowaniu go do obrazowania medycznego.

- **Model Skewing**: Subtelnie stronnicze lub błędnie oznaczone dane **przesuwają wyniki modelu**, realizując cele atakującego.\
*Przykład*: Wstrzyknięcie „czystych” wiadomości spamowych oznaczonych jako ham sprawia, że filtr antyspamowy przepuszcza podobne wiadomości w przyszłości.

- **Output Integrity Attack**: Atakujący **modyfikuje predykcje modelu podczas przesyłania**, nie zmieniając samego modelu, i w ten sposób oszukuje systemy dalszego przetwarzania.\
*Przykład*: Zmiana werdyktu klasyfikatora malware z „złośliwy” na „nieszkodliwy”, zanim plik trafi do etapu kwarantanny.

- **Model Poisoning** --- Bezpośrednie, ukierunkowane zmiany w **parametrach modelu**, często po uzyskaniu dostępu z uprawnieniami do zapisu, w celu zmiany jego zachowania.\
*Przykład*: Zmiana wag produkcyjnego modelu wykrywającego oszustwa tak, by transakcje z określonych kart zawsze były zatwierdzane.


## Ryzyka według Google SAIF

Framework [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) firmy Google opisuje różne ryzyka związane z systemami AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Złośliwi aktorzy zmieniają lub wstrzykują dane treningowe i dostrajające, aby obniżyć dokładność, zaszyć backdoory lub zniekształcić wyniki, osłabiając integralność modelu w całym cyklu życia danych.

- **Unauthorized Training Data**: Wykorzystywanie chronionych prawem autorskim, wrażliwych lub nieautoryzowanych zbiorów danych wiąże się z ryzykiem prawnym, etycznym i wydajnościowym, ponieważ model uczy się na danych, których nie wolno mu było używać.

- **Model Source Tampering**: Manipulowanie kodem modelu, jego zależnościami lub wagami przed treningiem albo w jego trakcie — przez atak na łańcuch dostaw lub osobę z dostępem wewnętrznym — może zaszyć ukrytą logikę, która przetrwa nawet ponowny trening.

- **Excessive Data Handling**: Słabe mechanizmy przechowywania danych i zarządzania nimi sprawiają, że systemy przechowują lub przetwarzają więcej danych osobowych, niż to konieczne, zwiększając ryzyko ich ujawnienia i naruszenia zgodności z przepisami.

- **Model Exfiltration**: Atakujący kradną pliki lub wagi modelu, co prowadzi do utraty własności intelektualnej i umożliwia tworzenie imitujących usług lub przeprowadzanie kolejnych ataków.

- **Model Deployment Tampering**: Adwersarze modyfikują artefakty modelu lub infrastrukturę obsługującą model, przez co działający model różni się od zatwierdzonej wersji, co może zmienić jego zachowanie.

- **Denial of ML Service**: Zalewanie API żądaniami lub wysyłanie wejść typu „sponge” może wyczerpać zasoby obliczeniowe lub energię i wyłączyć model, podobnie jak w klasycznych atakach DoS.

- **Model Reverse Engineering**: Zbierając dużą liczbę par wejście-wyjście, atakujący mogą sklonować model lub stworzyć jego model destylowany, co sprzyja powstawaniu imitujących produktów i dostosowanych ataków adwersarialnych.

- **Insecure Integrated Component**: Podatne wtyczki, agenty lub usługi zewnętrzne umożliwiają atakującym wstrzyknięcie kodu lub eskalację uprawnień w potoku AI.

- **Prompt Injection**: Tworzenie promptów, bezpośrednio lub pośrednio, w celu przemycenia instrukcji nadpisujących zamierzenia systemu i skłonienia modelu do wykonania niezamierzonych poleceń.

- **Model Evasion**: Starannie przygotowane dane wejściowe skłaniają model do błędnej klasyfikacji, halucynowania lub generowania niedozwolonych treści, osłabiając bezpieczeństwo i zaufanie.

- **Sensitive Data Disclosure**: Model ujawnia prywatne lub poufne informacje ze swoich danych treningowych lub kontekstu użytkownika, naruszając prywatność i przepisy.

- **Inferred Sensitive Data**: Model wnioskuje o cechach osobistych, które nigdy nie zostały podane, powodując nowe zagrożenia dla prywatności.

- **Insecure Model Output**: Niesanitowane odpowiedzi przekazują użytkownikom lub systemom dalszego przetwarzania szkodliwy kod, dezinformację albo nieodpowiednie treści.

- **Rogue Actions**: Zintegrowane z systemem autonomiczne agenty wykonują niezamierzone operacje w świecie rzeczywistym (zapis plików, wywołania API, zakupy itd.) bez odpowiedniego nadzoru użytkownika.

## Macierz MITRE AI ATLAS

[Macierz MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS) to kompleksowy framework pomagający zrozumieć i ograniczać ryzyka związane z systemami AI. Klasyfikuje różne techniki ataków i taktyki, których adwersarze mogą użyć przeciwko modelom AI, a także sposoby wykorzystania systemów AI do przeprowadzania różnych ataków.<sup>[[3]](#references)</sup>

## LLMJacking (kradzież tokenów i odsprzedaż dostępu do LLM hostowanych w chmurze)

Atakujący kradną aktywne tokeny sesji lub dane uwierzytelniające do cloud API i bez upoważnienia wywołują płatne LLM hostowane w chmurze. Dostęp jest często odsprzedawany za pośrednictwem reverse proxy, które pośredniczą w dostępie do konta ofiary, np. wdrożeń „oai-reverse-proxy”. Konsekwencje obejmują straty finansowe, użycie modelu niezgodne z zasadami oraz przypisanie działań do tenanta ofiary.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Wykradanie tokenów z zainfekowanych komputerów deweloperów lub przeglądarek; kradzież sekretów CI/CD; kupowanie ujawnionych cookies.<sup>[[5]](#references)</sup>
- Uruchomienie reverse proxy, które przekazuje żądania do prawdziwego dostawcy, ukrywa upstream key i obsługuje wielu klientów.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Nadużywanie bezpośrednich endpointów modeli bazowych w celu ominięcia zabezpieczeń enterprise i limitów żądań.<sup>[[4]](#references)</sup>

**Ponowne użycie klucza API na hoście:** Po przejęciu hosta implant może wysyłać żądania do modelu API bezpośrednio z hosta ofiary i przekazywać odpowiedzi przez C2, bez wyprowadzania cloud API key ani uruchamiania lokalnego AI CLI. W zaobserwowanym handlerze klucz dostarczony przez C2 ma pierwszeństwo; jeśli go nie ma, implant odczytuje `OPENAI_API_KEY` ze środowiska własnego procesu. Użycie konta ofiary wymaga więc prawidłowego klucza widocznego dla tego procesu oraz dostępu do modelu API. Prompt operatora trafia do Chat Completions API, a wynik modelu i zużycie tokenów wracają przez C2. Może to spowodować wykorzystanie płatnego dostępu ofiary do modelu bez uruchamiania narzędzi AI dewelopera, w przeciwieństwie do nadużyć związanych z [lokalnym AI CLI lub konfiguracją MCP](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md).<sup>[[14]](#references)</sup>

Środki zaradcze:
- Powiąż tokeny z odciskiem urządzenia, zakresami adresów IP i atestacją klienta; stosuj krótkie terminy ważności i odnawianie z MFA.
- Ogranicz uprawnienia kluczy do minimum (bez dostępu do narzędzi, tylko do odczytu, gdy ma to zastosowanie); rotuj klucze w razie anomalii.
- Kieruj cały ruch przez serwerowy gateway zasad, który egzekwuje filtry bezpieczeństwa, limity dla poszczególnych tras i izolację tenantów.
- Monitoruj nietypowe wzorce użycia (nagłe skoki wydatków, nietypowe regiony, ciągi UA) i automatycznie unieważniaj podejrzane sesje.
- Zamiast długowiecznych statycznych kluczy API preferuj mTLS lub podpisane JWT wydane przez IdP.

## Zabezpieczanie inferencji w self-hosted LLM

Uruchomienie lokalnego serwera LLM do pracy z poufnymi danymi tworzy inną powierzchnię ataku niż korzystanie z API hostowanych w chmurze: endpointy inferencji i debugowania mogą ujawniać prompty, stos obsługujący model zwykle udostępnia reverse proxy, a węzły urządzeń GPU zapewniają dostęp do rozbudowanych powierzchni `ioctl()`. Jeśli oceniasz lub wdrażasz lokalną usługę inferencji, sprawdź co najmniej poniższe kwestie.<sup>[[8]](#references)</sup>

### Ujawnienie promptów przez endpointy debugowania i monitorowania

Traktuj API inferencji jako **wrażliwą usługę dla wielu użytkowników**. Trasy debugowania lub monitorowania mogą ujawniać treść promptów, stan slotów, metadane modelu lub informacje o wewnętrznej kolejce. W `llama.cpp` endpoint `/slots` jest szczególnie wrażliwy, ponieważ ujawnia stan poszczególnych slotów i służy wyłącznie do ich inspekcji oraz zarządzania nimi.<sup>[[8]](#references)</sup>

Aby przeprowadzić fingerprinting i testy black-box udostępnionych runnerów modeli oraz powiązanych usług AI, sprawdź [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Umieść reverse proxy przed serwerem inferencji i **domyślnie blokuj ruch**.
- Dodaj do allowlisty wyłącznie dokładne kombinacje metod HTTP i ścieżek wymagane przez klienta lub UI.
- Jeśli to możliwe, wyłącz endpointy introspekcji w samym backendzie, na przykład za pomocą `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Powiąż reverse proxy z `127.0.0.1` i udostępniaj je przez uwierzytelniony transport, taki jak lokalne przekierowanie portu SSH, zamiast publikować je w sieci LAN.

Przykładowa allowlista dla nginx:

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

### Kontenery rootless bez sieci i z gniazdami UNIX

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
- `--network none` eliminuje ekspozycję TCP/IP przychodzącą i wychodzącą oraz pozwala uniknąć helperów działających w przestrzeni użytkownika, których w przeciwnym razie potrzebowałyby kontenery rootless.
- Socket UNIX pozwala używać uprawnień POSIX/ACL na ścieżce socketu jako pierwszej warstwy kontroli dostępu.
- `--userns=keep-id` i rootless Podman ograniczają skutki container breakout, ponieważ root w kontenerze nie jest rootem hosta.
- Montowanie modeli tylko do odczytu zmniejsza ryzyko ich modyfikacji z wnętrza kontenera.

W przypadku wdrożeń trwałych te same ograniczenia można określić za pomocą jednostek Podman Quadlet. Jeśli dostęp do GPU jest delegowany za pośrednictwem Container Device Interface, specyfikacja urządzenia CDI powinna być możliwie wąska — zamiast udostępniać każdy węzeł akceleratora.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Ograniczanie liczby węzłów urządzeń GPU

W przypadku inferencji wspomaganej przez GPU pliki `/dev/nvidia*` stanowią atrakcyjne lokalne powierzchnie ataku, ponieważ udostępniają rozbudowane procedury obsługi sterownika `ioctl()` oraz potencjalnie współdzielone ścieżki zarządzania pamięcią GPU.<sup>[[8]](#references)</sup>

- Nie pozostawiaj `/dev/nvidia*` z uprawnieniami do zapisu dla wszystkich.
- Ogranicz dostęp do `nvidia`, `nvidiactl` i `nvidia-uvm` za pomocą `NVreg_DeviceFileUID/GID/Mode`, reguł udev i ACL, tak aby mogły je otwierać wyłącznie UID kontenera używany w mapowaniu.
- Na hostach do inferencji bez interfejsu graficznego umieść niepotrzebne moduły, takie jak `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem`, na czarnej liście.
- Wczytuj wstępnie tylko wymagane moduły podczas uruchamiania systemu, zamiast pozwalać środowisku uruchomieniowemu na wywoływanie `modprobe` w trakcie uruchamiania inferencji.

Przykład:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Jednym z ważnych punktów do sprawdzenia jest **`/dev/nvidia-uvm`**. Nawet jeśli workload nie używa jawnie `cudaMallocManaged()`, nowsze środowiska uruchomieniowe CUDA mogą nadal wymagać `nvidia-uvm`. Ponieważ to urządzenie jest współdzielone i obsługuje zarządzanie pamięcią wirtualną GPU, należy traktować je jako powierzchnię narażenia danych między tenantami. Jeśli backend inference to obsługuje, backend Vulkan może być interesującym kompromisem, ponieważ może całkowicie wyeliminować potrzebę udostępniania `nvidia-uvm` kontenerowi.<sup>[[8]](#references)</sup>

### Ograniczanie procesów inference za pomocą LSM

AppArmor/SELinux/seccomp należy stosować jako dodatkową warstwę ochrony procesu inference:<sup>[[8]](#references)</sup>

- Zezwalaj tylko na współdzielone biblioteki, ścieżki modeli, katalog gniazd i węzły urządzeń GPU, które są rzeczywiście wymagane.
- Jawnie blokuj wysokiego ryzyka uprawnienia, takie jak `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Ustaw katalog modelu jako tylko do odczytu, a ścieżki zapisu ogranicz wyłącznie do katalogów gniazd runtime i cache.
- Monitoruj logi odmów, ponieważ zapewniają przydatne dane telemetryczne do wykrywania prób ucieczki poza oczekiwane zachowanie przez serwer modelu lub payload post-exploitation.

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

Ma to znaczenie, ponieważ w wielu procesach wspomaganych przez AI wynik modelu jest traktowany jako **zaufana zależność**:
- Programiści wklejają sugerowany endpoint do kodu lub integracji CI/CD.
- Agenci AI automatycznie pobierają dokumentację, schematy, pliki APK, ZIP lub adresy webhooków.
- Wygenerowane runbooki lub dokumentacja mogą zawierać fałszywy URL, jakby był wiarygodny.

### Przebieg ataku

1. **Zbadaj powierzchnię halucynacji**: zadawaj pytania dotyczące konkretnej marki i realistycznych procesów, takich jak portale `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` lub `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizuj kandydatów**: rozwiązuj wygenerowane URL-e, sprowadzaj odpowiedzi NXDOMAIN do nadrzędnej domeny możliwej do rejestracji i usuwaj duplikaty rodzin promptów. Zbiory promptów powinny być zróżnicowane; można na przykład odrzucać niemal identyczne pozycje na podstawie **podobieństwa Jaccarda**.
3. **Priorytetyzuj przewidywalne halucynacje**:
   - **Thermal Hallucination Persistence (THP)**: ta sama fałszywa domena pojawia się przy różnych wartościach temperatury, także niskich, takich jak `T=0.1`.
   - **Konsensus między modelami**: wiele rodzin LLM generuje tę samą fałszywą domenę.
4. **Zarejestruj i uzbrój** nadrzędną domenę, a następnie hostuj strony phishingowe, fałszywe pliki APK/ZIP do pobrania, narzędzia do kradzieży danych logowania, złośliwe dokumenty lub endpointy API zbierające sekrety/dane z webhooków. **Halucynacje dotyczące samej domeny** najłatwiej monetyzować, ponieważ atakujący kontroluje całą przestrzeń nazw; halucynacje dotyczące subdomen/ścieżek również można wykorzystać, jeśli znormalizowana domena nadrzędna nie jest zarejestrowana.
5. **Wykorzystaj okres zerowej reputacji**: nowo zarejestrowane domeny często nie mają historii na listach blokowanych, reputacji URL-i ani rozwiniętej telemetrii, więc mogą omijać zabezpieczenia, dopóki mechanizmy wykrywania nie nadążą. Atakujący mogą wydłużyć ten okres, udostępniając crawlerom nieszkodliwe odpowiedzi, stosując ukrywanie przekierowań, bramki CAPTCHA lub opóźnione dostarczanie ładunku.

### Dlaczego jest to niebezpieczne dla agentów

W przypadku człowieka fałszywa domena zwykle wymaga kliknięcia i wykonania kolejnej czynności. W **procesie agentowym** LLM może być jednocześnie **przynętą** i **wykonawcą**: agent otrzymuje halucynowany URL, pobiera go, analizuje odpowiedź, a następnie może ujawnić tokeny, wykonać instrukcje, pobrać zależność lub wprowadzić zatrute dane do CI/CD bez weryfikacji przez człowieka.<sup>[[12]](#references)</sup>

### Praktyczne prompty atakującego

Prompty o dużej skuteczności zwykle przypominają typowe zadania korporacyjne, a nie jawne przynęty phishingowe:<sup>[[12]](#references)</sup>
- „Jaki jest adres URL sandboxa płatności dla integracji `<brand>`?”
- „Jakiego endpointu webhooka użyć do powiadomień o kompilacjach `<brand>`?”
- „Gdzie znajduje się portal świadczeń pracowniczych / rozliczeń / SSO dla `<brand>`?”
- „Podaj bezpośredni link do pobrania pliku APK na Androida lub klienta desktopowego dla `<brand>`.”

### Odwrócenie perspektywy obronnej

Traktuj to jako problem proaktywnego monitorowania domen, a nie tylko problem prompt injection:<sup>[[12]](#references)</sup>
- Utwórz **zbiór promptów dotyczących marki** i okresowo testuj za jego pomocą modele LLM, na których polegają użytkownicy/agenci.
- Zapisuj halucynowane URL-e i śledź, które z nich są stabilne w różnych temperaturach/modelach.
- Śledź **Adversarial Exploitation Window (AEW)**: czas między pierwszą halucynacją a rejestracją domeny przez atakującego. Dodatni AEW oznacza, że obrońcy mogą zarejestrować domenę, skierować ją do sinkhole'a lub zablokować przed jej uzbrojeniem.
- Monitoruj przejścia **NXDOMAIN → zarejestrowana** dla domen nadrzędnych.
- Po rejestracji sprawdź rejestratora, datę utworzenia, serwery nazw, ochronę prywatności, zawartość strony, zrzuty ekranu, status strony parkingowej i podobieństwo do zasobów marki.
- Dodaj mechanizmy kontroli, aby agenci/programiści **domyślnie nie ufali domenom wygenerowanym przez LLM**: wymagaj list dozwolonych, weryfikacji własności, kontroli CT/RDAP lub zgody człowieka przed pierwszym użyciem.

Zjawisko to wpisuje się jednocześnie w kilka kategorii ryzyka AI: **atak na łańcuch dostaw AI**, **niebezpieczne wyjście modelu** oraz **działania nieautoryzowane**, gdy agenci autonomicznie korzystają z halucynowanego URL-a.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [OWASP Top 10 podatności uczenia maszynowego](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – ryzyka](https://saif.google/secure-ai-framework/risks)
- [3] [Macierz zagrożeń MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Ryzyka związane z LLM-ami asystującymi w programowaniu: szkodliwe treści, nadużycia i oszustwa](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: skradzione dane uwierzytelniające do chmury wykorzystane w nowym ataku AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Przegląd schematu LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (odsprzedaż skradzionego dostępu do LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Dogłębna analiza wdrożenia lokalnego serwera LLM z niskimi uprawnieniami](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README serwera llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlety Podmana: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specyfikacja CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domeny halucynowane przez AI jako wektor ataku na łańcuch dostaw oprogramowania](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: jak halucynacje AI napędzają nową klasę ataków na łańcuch dostaw](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: nowa platforma command-and-control oparta na AI](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
