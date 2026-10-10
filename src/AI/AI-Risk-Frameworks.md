# Zagrożenia związane z AI

{{#include ../banners/hacktricks-training.md}}

## 10 najważniejszych podatności machine learning według OWASP

OWASP zidentyfikował 10 najważniejszych podatności machine learning, które mogą wpływać na systemy AI. Mogą one prowadzić do różnych problemów z bezpieczeństwem, w tym do zatruwania danych, inwersji modelu i ataków adwersarialnych. Zrozumienie tych podatności ma kluczowe znaczenie dla budowania bezpiecznych systemów AI.

Aktualną i szczegółową listę 10 najważniejszych podatności machine learning znajdziesz w projekcie [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Atakujący wprowadza niewielkie, często niewidoczne zmiany do **danych wejściowych**, aby model podjął błędną decyzję.\
    *Przykład*: Kilka plamek farby na znaku stopu sprawia, że samochód autonomiczny „widzi” znak ograniczenia prędkości.

- **Data Poisoning Attack**: **Zbiór treningowy** zostaje celowo zanieczyszczony błędnymi próbkami, przez co model uczy się szkodliwych reguł.\
*Przykład*: Pliki binarne malware zostają błędnie oznaczone jako „bezpieczne” w zbiorze treningowym programu antywirusowego, dzięki czemu podobne malware może później uniknąć wykrycia.

- **Model Inversion Attack**: Analizując wyniki, atakujący tworzy **model odwrotny**, który odtwarza wrażliwe cechy oryginalnych danych wejściowych.\
*Przykład*: Odtworzenie obrazu MRI pacjenta na podstawie predykcji modelu wykrywającego raka.

- **Membership Inference Attack**: Atakujący sprawdza, czy **konkretny rekord** został użyty podczas treningu, wykrywając różnice w poziomie pewności modelu.\
*Przykład*: Potwierdzenie, że transakcja bankowa danej osoby znajduje się w danych treningowych modelu wykrywającego oszustwa.

- **Model Theft**: Wielokrotne wysyłanie zapytań pozwala atakującemu poznać granice decyzyjne i **sklonować działanie modelu** (oraz jego własność intelektualną).\
*Przykład*: Zebranie wystarczającej liczby par pytań i odpowiedzi z API ML-as-a-Service, aby zbudować niemal równoważny model lokalny.

- **AI Supply‑Chain Attack**: Naruszenie dowolnego komponentu (**danych, bibliotek, wstępnie wytrenowanych wag, CI/CD**) w **potoku ML** może doprowadzić do uszkodzenia modeli pochodnych.\
*Przykład*: Zatruta zależność z model-hub instaluje model analizy sentymentu z backdoorem w wielu aplikacjach.

- **Transfer Learning Attack**: Złośliwa logika zostaje umieszczona w **wstępnie wytrenowanym modelu** i przetrwa fine-tuning na zadaniu ofiary.\
*Przykład*: Szkielet modelu wizyjnego z ukrytym wyzwalaczem nadal zmienia etykiety po dostosowaniu do obrazowania medycznego.

- **Model Skewing**: Subtelnie stronnicze lub błędnie oznaczone dane **przesuwają wyniki modelu**, wspierając cele atakującego.\
*Przykład*: Dodanie „czystych” e-maili spamowych oznaczonych jako ham sprawia, że filtr antyspamowy przepuszcza podobne wiadomości.

- **Output Integrity Attack**: Atakujący **modyfikuje predykcje modelu podczas przesyłania**, nie zmieniając samego modelu, i w ten sposób oszukuje systemy dalszego przetwarzania.\
*Przykład*: Zmiana werdyktu klasyfikatora malware z „złośliwy” na „bezpieczny”, zanim plik trafi do etapu kwarantanny.

- **Model Poisoning** --- Bezpośrednie, ukierunkowane modyfikacje samych **parametrów modelu**, często po uzyskaniu dostępu z prawami zapisu, w celu zmiany jego działania.\
*Przykład*: Zmiana wag modelu wykrywającego oszustwa w środowisku produkcyjnym tak, aby transakcje z określonych kart były zawsze zatwierdzane.


## Zagrożenia SAIF według Google

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) firmy Google przedstawia różne zagrożenia związane z systemami AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Złośliwe podmioty zmieniają lub wstrzykują dane treningowe lub dostrajające, aby obniżyć dokładność, umieścić backdoory lub zniekształcić wyniki, podważając integralność modelu na wszystkich etapach cyklu życia danych.

- **Unauthorized Training Data**: Wykorzystanie chronionych prawem autorskim, wrażliwych lub niedozwolonych zbiorów danych wiąże się z ryzykiem prawnym, etycznym i wydajnościowym, ponieważ model uczy się na danych, których nie wolno było użyć.

- **Model Source Tampering**: Manipulacja kodem modelu, zależnościami lub wagami przed treningiem albo w jego trakcie, przeprowadzona w ramach ataku na łańcuch dostaw lub przez osobę z wewnątrz, może wprowadzić ukrytą logikę, która przetrwa nawet ponowny trening.

- **Excessive Data Handling**: Słabe mechanizmy przechowywania danych i zarządzania nimi sprawiają, że systemy przechowują lub przetwarzają więcej danych osobowych, niż to konieczne, zwiększając ryzyko ujawnienia i braku zgodności.

- **Model Exfiltration**: Atakujący kradną pliki lub wagi modelu, powodując utratę własności intelektualnej i umożliwiając tworzenie usług naśladujących oryginał lub przeprowadzanie kolejnych ataków.

- **Model Deployment Tampering**: Atakujący modyfikują artefakty modelu lub infrastrukturę serwującą, przez co uruchomiony model różni się od zatwierdzonej wersji i może działać inaczej.

- **Denial of ML Service**: Zalewanie API żądaniami lub wysyłanie wejść typu „sponge” może wyczerpać zasoby obliczeniowe lub energię i unieruchomić model, podobnie jak w klasycznych atakach DoS.

- **Model Reverse Engineering**: Zbierając dużą liczbę par wejście-wyjście, atakujący mogą sklonować model lub przeprowadzić jego destylację, tworząc imitujące go produkty i spersonalizowane ataki adwersarialne.

- **Insecure Integrated Component**: Podatne wtyczki, agenty lub usługi nadrzędne pozwalają atakującym wstrzykiwać kod lub eskalować uprawnienia w potoku AI.

- **Prompt Injection**: Tworzenie promptów (bezpośrednio lub pośrednio), aby przemycić instrukcje nadpisujące zamierzenia systemu i skłonić model do wykonania niezamierzonych poleceń.

- **Model Evasion**: Starannie przygotowane dane wejściowe powodują błędną klasyfikację, halucynacje lub wygenerowanie niedozwolonych treści, osłabiając bezpieczeństwo i zaufanie.

- **Sensitive Data Disclosure**: Model ujawnia prywatne lub poufne informacje ze swoich danych treningowych lub kontekstu użytkownika, naruszając prywatność i przepisy.

- **Inferred Sensitive Data**: Model wnioskuje o cechach osobistych, których nigdy mu nie podano, powodując nowe szkody dla prywatności.

- **Insecure Model Output**: Niesanitowane odpowiedzi przekazują użytkownikom lub systemom dalszego przetwarzania szkodliwy kod, dezinformację lub nieodpowiednie treści.

- **Rogue Actions**: Zintegrowane autonomicznie agenty wykonują niezamierzone działania w świecie rzeczywistym (zapis plików, wywołania API, zakupy itp.) bez odpowiedniego nadzoru użytkownika.

## Macierz MITRE AI ATLAS

[Macierz MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS) zapewnia kompleksowe ramy do zrozumienia i ograniczania zagrożeń związanych z systemami AI. Klasyfikuje różne techniki i taktyki ataków, których przeciwnicy mogą używać przeciwko modelom AI, a także sposoby wykorzystania systemów AI do przeprowadzania różnych ataków.<sup>[[3]](#references)</sup>

## LLMJacking (kradzież tokenów i odsprzedaż dostępu do hostowanych w chmurze LLM)

Atakujący kradną aktywne tokeny sesji lub poświadczenia API w chmurze i bez upoważnienia wywołują płatne, hostowane w chmurze LLM. Dostęp jest często odsprzedawany za pośrednictwem reverse proxy, które pośredniczą w dostępie do konta ofiary, np. wdrożeń „oai-reverse-proxy”. Konsekwencje obejmują straty finansowe, użycie modelu niezgodne z polityką oraz przypisanie działań do dzierżawy ofiary.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP:
- Pozyskiwanie tokenów z zainfekowanych urządzeń deweloperów lub przeglądarek; kradzież sekretów CI/CD; kupowanie wykradzionych cookies.<sup>[[5]](#references)</sup>
- Uruchomienie reverse proxy, które przekazuje żądania do prawdziwego dostawcy, ukrywa klucz upstream i obsługuje wielu klientów.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Nadużywanie bezpośrednich endpointów modelu bazowego, aby ominąć zabezpieczenia i limity szybkości w przedsiębiorstwie.<sup>[[4]](#references)</sup>

Środki zaradcze:
- Powiąż tokeny z odciskiem urządzenia, zakresami adresów IP i atestacją klienta; stosuj krótkie czasy wygaśnięcia i odnawiaj tokeny przy użyciu MFA.
- Ogranicz zakres kluczy do niezbędnego minimum (bez dostępu do narzędzi, tylko do odczytu, jeśli ma to zastosowanie); zmieniaj klucze po wykryciu anomalii.
- Kieruj cały ruch po stronie serwera przez bramę polityk, która egzekwuje filtry bezpieczeństwa, limity dla poszczególnych tras i izolację dzierżaw.
- Monitoruj nietypowe wzorce użycia (nagłe skoki wydatków, nietypowe regiony, ciągi UA) i automatycznie unieważniaj podejrzane sesje.
- Zamiast długotrwałych statycznych kluczy API używaj mTLS lub podpisanych JWT wystawianych przez IdP.

## Zabezpieczanie inferencji self-hosted LLM

Uruchomienie lokalnego serwera LLM do obsługi poufnych danych tworzy inną powierzchnię ataku niż API hostowane w chmurze: endpointy inferencji i debugowania mogą ujawniać prompty, stos serwujący zwykle udostępnia reverse proxy, a węzły urządzeń GPU zapewniają dostęp do rozbudowanych interfejsów `ioctl()`. Jeśli oceniasz lub wdrażasz lokalną usługę inferencji, sprawdź co najmniej poniższe kwestie.<sup>[[8]](#references)</sup>

### Ujawnianie promptów przez endpointy debugowania i monitorowania

Traktuj API inferencji jako **wrażliwą usługę dla wielu użytkowników**. Trasy debugowania lub monitorowania mogą ujawniać treść promptów, stan slotów, metadane modelu lub wewnętrzne informacje o kolejce. W `llama.cpp` endpoint `/slots` jest szczególnie wrażliwy, ponieważ ujawnia stan poszczególnych slotów i jest przeznaczony wyłącznie do ich inspekcji lub zarządzania nimi.<sup>[[8]](#references)</sup>

- Umieść reverse proxy przed serwerem inferencji i **domyślnie odmawiaj dostępu**.
- Dodaj do allowlisty wyłącznie dokładne kombinacje metod HTTP i ścieżek wymagane przez klienta lub UI.
- W miarę możliwości wyłącz endpointy introspekcji bezpośrednio w backendzie, na przykład `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Powiąż reverse proxy z `127.0.0.1` i udostępniaj je przez uwierzytelniony transport, taki jak lokalne przekierowanie portu SSH, zamiast publikować je w sieci LAN.

Przykładowa allowlista nginx:

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

Jeśli daemon wnioskowania obsługuje nasłuchiwanie na gnieździe UNIX, wybierz tę opcję zamiast TCP i uruchom kontener **bez stosu sieciowego**:<sup>[[8]](#references)</sup>

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
- `--network none` eliminuje ekspozycję TCP/IP przychodzącą i wychodzącą oraz pozwala uniknąć pomocników działających w przestrzeni użytkownika, których w przeciwnym razie wymagałyby kontenery rootless.
- Gniazdo UNIX pozwala używać uprawnień POSIX/ACL na ścieżce gniazda jako pierwszej warstwy kontroli dostępu.
- `--userns=keep-id` i rootless Podman ograniczają skutki ucieczki z kontenera, ponieważ root w kontenerze nie jest rootem hosta.
- Montowanie modeli tylko do odczytu zmniejsza ryzyko ich modyfikacji z poziomu kontenera.

W przypadku wdrożeń trwałych te same ograniczenia można zdefiniować za pomocą jednostek Podman Quadlet. Jeśli dostęp do GPU jest delegowany przez Container Device Interface, specyfikacja urządzenia CDI powinna być jak najbardziej zawężona, zamiast udostępniać wszystkie węzły akceleratorów.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimalizacja węzłów urządzeń GPU

W przypadku wnioskowania wykorzystującego GPU pliki `/dev/nvidia*` stanowią cenne lokalne powierzchnie ataku, ponieważ udostępniają rozbudowane procedury obsługi sterownika `ioctl()` oraz potencjalnie współdzielone ścieżki zarządzania pamięcią GPU.<sup>[[8]](#references)</sup>

- Nie pozostawiaj plików `/dev/nvidia*` z prawem zapisu dla wszystkich użytkowników.
- Ogranicz dostęp do `nvidia`, `nvidiactl` i `nvidia-uvm` za pomocą `NVreg_DeviceFileUID/GID/Mode`, reguł udev i ACL, tak aby otwierać je mógł tylko zmapowany UID kontenera.
- Na hostach do wnioskowania bez monitora blokuj niepotrzebne moduły, takie jak `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem`.
- Załaduj wstępnie tylko wymagane moduły podczas uruchamiania systemu, zamiast pozwalać środowisku uruchomieniowemu na ich oportunistyczne ładowanie przez `modprobe` podczas uruchamiania wnioskowania.

Przykład:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Ważnym punktem przeglądu jest **`/dev/nvidia-uvm`**. Nawet jeśli obciążenie nie używa jawnie `cudaMallocManaged()`, nowsze środowiska uruchomieniowe CUDA mogą nadal wymagać `nvidia-uvm`. Ponieważ to urządzenie jest współdzielone i obsługuje zarządzanie pamięcią wirtualną GPU, należy traktować je jako powierzchnię narażenia danych między tenantami. Jeśli backend wnioskowania to obsługuje, backend Vulkan może być interesującym kompromisem, ponieważ może całkowicie wyeliminować potrzebę udostępniania `nvidia-uvm` kontenerowi.<sup>[[8]](#references)</sup>

### Ograniczanie dostępu workerów wnioskowania za pomocą LSM

AppArmor/SELinux/seccomp należy stosować jako dodatkową warstwę ochrony procesu wnioskowania:<sup>[[8]](#references)</sup>

- Zezwalaj wyłącznie na wymagane biblioteki współdzielone, ścieżki modeli, katalog gniazd i węzły urządzeń GPU.
- Jawnie blokuj uprawnienia wysokiego ryzyka, takie jak `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Ustaw katalog modelu jako tylko do odczytu, a zapisywalne ścieżki ogranicz wyłącznie do katalogów gniazd/cache środowiska uruchomieniowego.
- Monitoruj logi odmów dostępu, ponieważ dostarczają użytecznych danych telemetrycznych do wykrywania prób ucieczki model servera lub payloadu post-exploitation poza oczekiwane zachowanie.

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

Phantom squatting jest **odpowiednikiem slopsquattingu dla domen/URL-i**. Zamiast halucynować nieistniejącą nazwę pakietu, LLM halucynuje wiarygodną **domenę portalu, API, webhooka, rozliczeń, SSO, pobierania lub pomocy technicznej** prawdziwej marki, a atakujący rejestruje tę przestrzeń nazw, zanim użyje jej człowiek lub agent.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ma to znaczenie, ponieważ w wielu przepływach pracy wspomaganych przez AI wynik modelu jest traktowany jak **zaufana zależność**:
- Programiści wklejają sugerowany endpoint do kodu lub integracji CI/CD.
- Agenci AI automatycznie pobierają dokumentację, schematy, pliki APK, ZIP lub adresy webhooków.
- Wygenerowane instrukcje operacyjne lub dokumentacja mogą zawierać fałszywy URL, jakby był wiarygodny.

### Przebieg ataku

1. **Zbadaj powierzchnię halucynacji**: zadawaj pytania dotyczące konkretnej marki i realistycznych przepływów pracy, np. portali `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` lub `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizuj kandydatów**: rozwiąż wygenerowane URL-e, sprowadź odpowiedzi NXDOMAIN do nadrzędnej domeny możliwej do zarejestrowania i usuń duplikaty rodzin promptów. Zestawy promptów powinny być zróżnicowane, na przykład przez odrzucanie niemal identycznych promptów na podstawie **podobieństwa Jaccarda**.
3. **Nadaj priorytet przewidywalnym halucynacjom**:
   - **Thermal Hallucination Persistence (THP)**: ta sama fałszywa domena pojawia się przy różnych temperaturach, w tym niskich, takich jak `T=0.1`.
   - **Zgodność między modelami**: różne rodziny LLM generują tę samą fałszywą domenę.
4. **Zarejestruj i uzbrój** nadrzędną domenę, a następnie hostuj na niej strony phishingowe, fałszywe pliki APK/ZIP do pobrania, narzędzia do wykradania danych uwierzytelniających, złośliwe dokumenty lub endpointy API zbierające sekrety albo treści webhooków. **Halucynacje obejmujące samą domenę** najłatwiej wykorzystać do zarobku, ponieważ atakujący kontroluje całą przestrzeń nazw; halucynacje dotyczące subdomen lub ścieżek również można wykorzystać, jeśli znormalizowana domena nadrzędna nie jest zarejestrowana.
5. **Wykorzystaj okres zerowej reputacji**: nowo zarejestrowane domeny często nie mają historii na listach blokowanych, reputacji URL ani rozwiniętej telemetrii, więc mogą omijać zabezpieczenia, dopóki systemy wykrywania nie zareagują. Atakujący mogą wydłużyć ten okres, zwracając nieszkodliwe odpowiedzi wyłącznie crawlerom, stosując maskowanie przekierowań, bramki CAPTCHA lub opóźnione wdrażanie ładunku.

### Dlaczego jest to niebezpieczne w przypadku agentów

W przypadku człowieka fałszywa domena zwykle wymaga kliknięcia i wykonania kolejnej czynności. W **agentowym przepływie pracy** LLM może być zarówno **wabikiem**, jak i **wykonawcą**: agent otrzymuje halucynowany URL, pobiera go, analizuje odpowiedź, a następnie może ujawnić tokeny, wykonać instrukcje, pobrać zależność lub wprowadzić zatrute dane do CI/CD bez weryfikacji przez człowieka.<sup>[[12]](#references)</sup>

### Praktyczne prompty atakującego

Najskuteczniejsze prompty zwykle przypominają typowe zadania firmowe, a nie jawne próby phishingu:<sup>[[12]](#references)</sup>
- „Jaki jest URL sandboxa płatności dla integracji `<brand>`?”
- „Jakiego endpointu webhooka użyć do powiadomień o kompilacji `<brand>`?”
- „Gdzie znajduje się portal świadczeń pracowniczych / rozliczeń / SSO dla `<brand>`?”
- „Podaj bezpośredni link do pobrania pliku APK na Androida lub klienta desktopowego dla `<brand>`.”

### Odwrócenie podejścia obronnego

Traktuj to jako problem proaktywnego monitorowania domen, a nie tylko problem prompt injection:<sup>[[12]](#references)</sup>
- Utwórz **zestaw promptów dotyczących marki** i okresowo testuj LLM-y, na których polegają użytkownicy lub agenci.
- Zapisuj halucynowane URL-e i śledź, które z nich powtarzają się przy różnych temperaturach i modelach.
- Śledź **Adversarial Exploitation Window (AEW)**: czas między pierwszą halucynacją a rejestracją domeny przez atakującego. Dodatnia wartość AEW oznacza, że obrońcy mogą zarejestrować domenę, skierować ją do sinkhole’a lub zablokować przed jej uzbrojeniem.
- Monitoruj przejścia **NXDOMAIN → zarejestrowana** dla domen nadrzędnych.
- Po rejestracji sprawdź rejestratora, datę utworzenia, serwery nazw, ochronę prywatności, zawartość strony, zrzuty ekranu, status strony parkingowej i podobieństwo do zasobów marki.
- Wprowadź kontrolę polityk, aby agenci i programiści **nie ufali domyślnie domenom wygenerowanym przez LLM**: wymagaj list dozwolonych, weryfikacji własności, kontroli CT/RDAP lub zatwierdzenia przez człowieka przed pierwszym użyciem.

Zjawisko to należy jednocześnie do kilku kategorii ryzyka AI: **atak na łańcuch dostaw AI**, **niebezpieczne wyjście modelu** oraz **nieautoryzowane działania**, gdy agenci samodzielnie korzystają z halucynowanego URL-a.

## References

- [1] [OWASP Top 10 podatności uczenia maszynowego](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – zagrożenia](https://saif.google/secure-ai-framework/risks)
- [3] [Macierz zagrożeń MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Zagrożenia związane z LLM-ami wspomagającymi programowanie: szkodliwe treści, nadużycia i wprowadzanie w błąd](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: skradzione poświadczenia chmurowe wykorzystane w nowym ataku AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Omówienie procederu LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (odsprzedaż skradzionego dostępu do LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Dogłębna analiza wdrożenia lokalnego serwera LLM z ograniczonymi uprawnieniami](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README serwera llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlety Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Specyfikacja CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domeny halucynowane przez AI jako wektor ataku na łańcuch dostaw oprogramowania](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: jak halucynacje AI napędzają nową klasę ataków na łańcuch dostaw](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
