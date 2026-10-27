# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotypy Hacktricks i projekty motion design autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Uruchamianie HackTricks lokalnie

```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

Twoja lokalna kopia HackTricks będzie **dostępna pod adresem [http://localhost:3337](http://localhost:3337)** za mniej niż 5 minut (książka musi się zbudować, więc uzbrój się w cierpliwość).

Jeśli masz Docker Compose, możesz też po prostu uruchomić następujące polecenie z katalogu głównego repozytorium:

```bash
docker compose up
```

Ta konfiguracja używa dołączonego pliku `docker-compose.yml`, aby udostępnić aktualnie wybraną na hoście gałąź pod adresem [http://localhost:3337](http://localhost:3337) z automatycznym odświeżaniem. Aby zmienić język podczas korzystania z Compose, przed uruchomieniem usługi przełącz się na odpowiednią gałąź językową.

## Partnerzy HackTricks

---

## Przyjaciele HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber oferuje testy penetracyjne, audyty bezpieczeństwa, prace związane z exploitami i badaniami, narzędzia oraz usługi zwiększania świadomości w zakresie bezpieczeństwa. Na stronie opisuje zespół pentesterów, programistów i badaczy bezpieczeństwa z ponad dziesięcioletnim doświadczeniem.<sup>[[1]](#references)</sup>

Odwiedź ich **blog**: [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** wspiera też projekty open source z zakresu cyberbezpieczeństwa, takie jak HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti to dostawca usług crowdsourcingowych z zakresu bezpieczeństwa, oferujący programy bug bounty i testy penetracyjne za pośrednictwem globalnej społeczności badaczy. Platforma łączy stałe pokrycie w ramach bug bounty z usługami PTaaS na żądanie i zarządzanymi programami zgłaszania podatności.<sup>[[2]](#references)</sup>

**Wskazówka dotycząca bug bounty**: Dołącz do Intigriti przez [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i poznaj ich programy bug bounty.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security oferuje praktyczne szkolenia z zakresu bezpieczeństwa AI we własnym tempie, skierowane do inżynierów bezpieczeństwa, specjalistów AppSec i programistów. Certyfikacja AI Security obejmuje podstawy LLM i agentów, RAG i wektorowe bazy danych, modelowanie zagrożeń, ataki prompt injection i MCP oraz architekturę obronną.<sup>[[3]](#references)</sup>

👉 Więcej informacji o kursie AI Security:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** udostępnia API dla Google i innych wyszukiwarek, które zwracają ustrukturyzowane dane SERP z takimi funkcjami jak wyniki uwzględniające lokalizację, Maps, Shopping i Knowledge Graph.<sup>[[4]](#references)</sup>

Więcej informacji znajdziesz na ich [**blogu**](https://serpapi.com/blog/), wypróbuj przykład w ich [**playgroundzie**](https://serpapi.com/playground) lub [**utwórz bezpłatne konto**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** oferuje kursy z zakresu bezpieczeństwa urządzeń mobilnych i AI, realizowane we własnym tempie. Katalog obejmuje audyty i analizę wsteczną aplikacji mobilnych z użyciem narzędzi takich jak Ghidra, Frida i LLDB, a także laboratoria ataków i obrony AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Przejrzyj [katalog kursów 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** reklamuje platformę offensive AI, która mapuje kod i infrastrukturę, a następnie wykorzystuje agentów statycznych i dynamicznych do wykrywania i weryfikowania możliwych do wykorzystania słabości, dostarczając dowody w postaci proof of concept i wskazówki dotyczące naprawy.<sup>[[7]](#references)</sup>

**Wskazówka dotycząca bezpieczeństwa kodu**: Poznaj Naxus, aby wykrywać podatności w kodzie i infrastrukturze.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec oferuje testy penetracyjne, subskrypcje usług bezpieczeństwa, usługi kadrowe i ocenę podatności. Według informacji na stronie firma działa na całym świecie i zajmuje się bezpieczeństwem ofensywnym i defensywnym oraz zarządzaniem, ryzykiem i zgodnością.<sup>[[8]](#references)</sup>

Więcej informacji znajdziesz na ich [**stronie internetowej**](https://websec.net/en/) lub [**blogu**](https://websec.net/blog/).

Ponadto WebSec jest **zaangażowanym sponsorem HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Stworzone z myślą o pracy w terenie. Dostosowane do Ciebie.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) oferuje szkolenia z cyberbezpieczeństwa prowadzone przez ekspertów, z autorskimi materiałami i laboratoriami opartymi na rzeczywistej infrastrukturze. Programy są dostosowywane do potrzeb organizacji i obejmują cały proces od oceny po wdrożenie.<sup>[[9]](#references)</sup> W sprawie szkoleń szytych na miarę skontaktuj się z nimi [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Autorskie materiały i laboratoria
* Wsparcie najlepszych narzędzi i platform
* Projektowane i prowadzone przez praktyków

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions koncentruje się na doradztwie z zakresu cyberbezpieczeństwa dla sektora **edukacji** i **FinTech**, obejmującym oceny chmury, wewnętrzne i zewnętrzne testy penetracyjne, oceny podatności oraz wsparcie w zakresie zgodności.<sup>[[10]](#references)</sup>

Bądź na bieżąco z najnowszymi informacjami z zakresu cyberbezpieczeństwa, odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio to desktopowe IDE dla Kubernetes, oferujące wizualizację CloudMaps, nawigację po wielu klastrach, RBAC, Helm oraz widoki logów, YAML i terminala. Według dostawcy łączy się za pomocą kubeconfig bez instalowania agentów i obsługuje macOS, Windows, Linux oraz klastry odizolowane od sieci.<sup>[[11]](#references)</sup>

---

## Licencja i zastrzeżenie

Zobacz wpis HackTricks Values & FAQ w sekcji References poniżej.

## Statystyki GitHub

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certyfikacja AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Praktyczne bezpieczeństwo AI: ataki, obrona i zastosowania](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Link polecający Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Film o sponsorowaniu WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Kursy Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Wartości i FAQ HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
