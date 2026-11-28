# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotypy Hacktricks i projekt motion autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Uruchom HackTricks lokalnie

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

Jeśli masz Docker Compose, możesz też po prostu uruchomić poniższe polecenie z katalogu głównego repozytorium:

```bash
docker compose up
```

Ten plik używa dołączonego `docker-compose.yml`, aby udostępnić gałąź aktualnie pobraną na hoście pod adresem [http://localhost:3337](http://localhost:3337), z funkcją live reload. Aby zmienić język podczas korzystania z Compose, pobierz odpowiednią gałąź przed uruchomieniem usługi.

## Partnerzy HackTricks

---

## Przyjaciele HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber oferuje testy penetracyjne, audyty bezpieczeństwa, prace nad exploitami i badania, narzędzia oraz usługi zwiększające świadomość bezpieczeństwa. Na stronie opisuje swój zespół testerów penetracyjnych, programistów i badaczy bezpieczeństwa z ponad dziesięcioletnim doświadczeniem.<sup>[[1]](#references)</sup>

Zajrzyj na ich **blog**: [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** wspiera również projekty open source związane z cyberbezpieczeństwem, takie jak HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti to dostawca usług bezpieczeństwa crowdsourcingowego, który oferuje programy bug bounty i testy penetracyjne prowadzone przez globalną społeczność badaczy. Platforma łączy ciągłe programy bug bounty z usługami PTaaS na żądanie oraz zarządzanymi programami zgłaszania podatności.<sup>[[2]](#references)</sup>

**Wskazówka dotycząca bug bounty**: Dołącz do Intigriti przez [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i poznaj ich programy bug bounty.

---

### [Modern Security – platforma szkoleń z AI i bezpieczeństwa aplikacji](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security oferuje samodzielne, praktyczne szkolenia z bezpieczeństwa AI dla inżynierów bezpieczeństwa, specjalistów AppSec i programistów. Certyfikacja AI Security obejmuje podstawy LLM i agentów, RAG i wektorowe bazy danych, modelowanie zagrożeń, ataki prompt injection i MCP oraz architekturę obronną.<sup>[[3]](#references)</sup>

👉 Więcej informacji o kursie AI Security:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** udostępnia API do Google i innych wyszukiwarek, zwracające uporządkowane dane SERP z takimi funkcjami jak wyniki zależne od lokalizacji, Maps, Shopping i Knowledge Graph.<sup>[[4]](#references)</sup>

Więcej informacji znajdziesz na ich [**blogu**](https://serpapi.com/blog/), wypróbuj przykład w ich [**playgroundzie**](https://serpapi.com/playground) lub [**utwórz bezpłatne konto**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – szczegółowe kursy z bezpieczeństwa urządzeń mobilnych i AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** oferuje samodzielne kursy dotyczące bezpieczeństwa urządzeń mobilnych i AI. Jej oferta obejmuje audyt i reverse engineering aplikacji mobilnych przy użyciu narzędzi takich jak Ghidra, Frida i LLDB, a także laboratoria poświęcone atakom i obronie w obszarze AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Zapoznaj się z [katalogiem kursów 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – autonomiczne bezpieczeństwo ofensywne](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="Logo NaxusAI"><figcaption></figcaption></figure>

**Naxus** to oparta na AI platforma bezpieczeństwa ofensywnego, służąca do kompleksowego skanowania zewnętrznej powierzchni ataku, audytów aplikacji mobilnych, testów webowych black-box i przeglądów kodu źródłowego. Jej agenci weryfikują możliwe do wykorzystania podatności i przedstawiają możliwe do prześledzenia dowody, exploity proof-of-concept oraz konkretne zalecenia naprawcze.<sup>[[7]](#references)</sup>

**Wskazówka dotycząca audytów bezpieczeństwa**: Użyj Naxus do kompleksowych, autonomicznych audytów zewnętrznych zasobów, aplikacji mobilnych i webowych oraz kodu źródłowego.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec oferuje testy penetracyjne, abonamentowe usługi bezpieczeństwa, rekrutację specjalistów i ocenę podatności. Na stronie informuje o działalności międzynarodowej i usługach z zakresu bezpieczeństwa ofensywnego, bezpieczeństwa defensywnego oraz zarządzania, ryzyka i zgodności.<sup>[[8]](#references)</sup>

Więcej informacji znajdziesz na ich [**stronie internetowej**](https://websec.net/en/) lub [**blogu**](https://websec.net/blog/).

Oprócz powyższych działań WebSec jest również **zaangażowanym sponsorem HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="Logo cyberhelmets"><figcaption></figcaption></figure>


**Stworzone z myślą o pracy w terenie. Stworzone dla Ciebie.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) oferuje szkolenia z cyberbezpieczeństwa prowadzone przez ekspertów. Obejmują one tworzone na zamówienie materiały i laboratoria oparte na rzeczywistych infrastrukturach. Programy są dostosowane do potrzeb organizacji i obejmują działania od oceny po wdrożenie.<sup>[[9]](#references)</sup> W sprawie szkoleń na zamówienie skontaktuj się [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Tworzone na zamówienie materiały i laboratoria
* Wsparcie najlepszych narzędzi i platform
* Projektowane i prowadzone przez praktyków

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="Logo lasttower"><figcaption></figcaption></figure>

Last Tower Solutions koncentruje się na doradztwie w zakresie cyberbezpieczeństwa dla **edukacji** i **FinTech**, obejmującym ocenę bezpieczeństwa chmury, wewnętrzne i zewnętrzne testy penetracyjne, ocenę podatności oraz wsparcie w zakresie zgodności.<sup>[[10]](#references)</sup>

Bądź na bieżąco z najnowszymi informacjami o cyberbezpieczeństwie, odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

---

### [Beaki — jedzenie dopasowane do Ciebie](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Logo Beaki"><figcaption></figcaption></figure>

**Beaki** to spersonalizowany skaner żywności, licznik kalorii i narzędzie do śledzenia wartości odżywczych. Skanuj kody kreskowe i półki w supermarketach, fotografuj lub opisuj posiłki i menu restauracyjne, a następnie otrzymuj zrozumiałe oceny dostosowane do Twoich celów, diety, alergii i profilu zdrowotnego. Beaki śledzi również kalorie i makroskładniki oraz tworzy spersonalizowane plany posiłków z listami zakupów.<sup>[[11]](#references)</sup>

[**Pobierz Beaki bezpłatnie**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks) na Androida lub iPhone'a.

---

## Licencja i zastrzeżenie

Zobacz wpis HackTricks Values & FAQ w sekcji References poniżej.

## Statystyki GitHub

![Statystyki HackTricks w serwisie GitHub](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

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
- [11] [Beaki](https://www.beaki.app/)
- [12] [Polecenie HackTricks w Intigriti](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Film o sponsorowaniu WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Kursy Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Wartości i FAQ HackTricks](welcome/hacktricks-values-and-faq.md)

{{#include banners/hacktricks-training.md}}
