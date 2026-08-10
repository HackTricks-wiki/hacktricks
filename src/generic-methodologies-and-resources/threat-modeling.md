# Modelowanie zagrożeń

Witamy w kompleksowym przewodniku HackTricks po modelowaniu zagrożeń! Zapraszamy do zapoznania się z tym kluczowym aspektem cybersecurity, w ramach którego identyfikujemy potencjalne luki w systemie, rozumiemy je i opracowujemy strategie przeciwdziałania. Ten materiał stanowi przewodnik krok po kroku, zawierający przykłady z rzeczywistego świata, pomocne oprogramowanie oraz łatwe do zrozumienia wyjaśnienia. Jest przeznaczony zarówno dla początkujących, jak i doświadczonych praktyków, którzy chcą wzmocnić swoje zabezpieczenia cybersecurity.

### Często stosowane scenariusze

1. **Tworzenie oprogramowania**: Jako część Secure Software Development Life Cycle (SSDLC) modelowanie zagrożeń pomaga na wczesnych etapach tworzenia oprogramowania **identyfikować potencjalne źródła luk**.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: The Penetration Testing Execution Standard (PTES) uznaje modelowanie zagrożeń za wymagane do prawidłowego przeprowadzenia testów i wymaga udokumentowania zasobów biznesowych, procesów biznesowych, społeczności zagrożeń oraz ich możliwości.<sup>[[2]](#references)</sup>

### Model zagrożeń w skrócie

Model zagrożeń jest zazwyczaj przedstawiany jako diagram, obraz lub inna wizualna ilustracja planowanej architektury albo istniejącej aplikacji. Data-flow diagrams (DFDs) są powszechnym sposobem modelowania systemu i jego interakcji, natomiast modelowanie zagrożeń dodaje analizę ukierunkowaną na bezpieczeństwo.<sup>[[1]](#references)</sup>

W Microsoft Threat Modeling Tool czerwone przerywane linie wskazują granice zaufania; inne narzędzia mogą stosować odmienne konwencje wizualne.<sup>[[4]](#references)</sup> Aby usprawnić identyfikację ryzyka, zespoły mogą korzystać z triady CIA (Confidentiality, Integrity, Availability) lub kategorii zagrożeń STRIDE, jednak właściwa metodologia zależy od kontekstu i wymagań projektu.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### Triada CIA

Triada CIA to powszechnie uznawany model bezpieczeństwa informacji, którego nazwa oznacza Confidentiality, Integrity i Availability. Właściwości te są powszechnie używane do opisywania celów bezpieczeństwa danych i systemów.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Zapewnienie, że dane lub system nie są dostępne dla nieupoważnionych osób. Jest to centralny element bezpieczeństwa, wymagający odpowiednich mechanizmów kontroli dostępu, szyfrowania i innych środków zapobiegających naruszeniom danych.
2. **Integrity**: Dokładność, spójność i wiarygodność danych w całym ich cyklu życia. Zasada ta zapewnia, że dane nie zostaną zmienione ani naruszone przez nieupoważnione strony. Często obejmuje sumy kontrolne, hashing i inne metody weryfikacji danych.
3. **Availability**: Zapewnienie, że dane i usługi są dostępne dla upoważnionych użytkowników, gdy są potrzebne. Często wymaga to nadmiarowości, fault tolerance i konfiguracji high-availability, aby systemy działały nawet w obliczu zakłóceń.

### Metodologie modelowania zagrożeń

1. **STRIDE**: Podejście STRIDE firmy Microsoft kategoryzuje zagrożenia oprogramowania jako **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service i Elevation of Privilege**. Kategorie te pomagają analitykom identyfikować możliwe zagrożenia w każdym podatnym punkcie projektu.<sup>[[5]](#references)</sup>
2. **DREAD**: To podejście firmy Microsoft do oceny zagrożeń wykorzystuje **Damage, Reproducibility, Exploitability, Affected users i Discoverability**. Uzyskany wynik może pomóc w ustalaniu priorytetów zagrożeń przeznaczonych do ograniczenia.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Jest to siedmioetapowa metodologia **risk-centric**, obejmująca cele, zakres techniczny, dekompozycję aplikacji, analizę zagrożeń, analizę luk i słabości, modelowanie ataków oraz analizę ryzyka/wpływu.<sup>[[8]](#references)</sup>
4. **Trike**: Ten framework audytu bezpieczeństwa podchodzi do modelowania zagrożeń z perspektywy **risk-management** i obrony.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Metoda ta kładzie nacisk na skalowalne i użyteczne modele zagrożeń dla widoków aplikacji i operacji oraz może integrować się z cyklami życia developmentu i DevOps.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Utworzona przez CERT Division należący do Software Engineering Institute firmy Carnegie Mellon, OCTAVE jest opartą na ryzyku strategiczną metodą oceny i planowania, skoncentrowaną na ryzyku organizacyjnym, a nie wyłącznie na technologii.<sup>[[10]](#references)</sup>

## Tools

Dostępnych jest kilka tools i rozwiązań software'owych, które mogą **pomóc** w tworzeniu i zarządzaniu modelami zagrożeń. Oto kilka propozycji, które warto rozważyć.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite to wieloplatformowy crawler webowy dla security professionals, obsługujący mapowanie attack surface, wykrywanie endpointów i analizę web applications.<sup>[[6]](#references)</sup>

**Użycie**

1. Wybierz URL i rozpocznij Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Wyświetl Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon to bezpłatna, open-source'owa, wieloplatformowa aplikacja do modelowania zagrożeń, służąca do rysowania diagramów, sugerowania zagrożeń i rejestrowania działań zaradczych. Jest dostępna jako aplikacja webowa i desktopowa.<sup>[[7]](#references)</sup>

**Użycie**

1. Utwórz New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Czasami może to wyglądać tak:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Uruchom New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Zapisz New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Utwórz swój model

Możesz użyć tools takich jak SpiderSuite Crawler, aby uzyskać inspirację. Podstawowy model może wyglądać mniej więcej tak:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Krótkie wyjaśnienie dotyczące entities:

- Process (Sama entity, taka jak Webserver lub funkcjonalność webowa)
- Actor (Osoba, taka jak odwiedzający stronę, użytkownik lub administrator)
- Data Flow Line (Wskaźnik interakcji)
- Trust Boundary (Różne segmenty sieci lub zakresy.)
- Store (Miejsca przechowywania danych, takie jak Databases)

5. Utwórz Threat (Step 1)

Najpierw musisz wybrać layer, do którego chcesz dodać threat

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Teraz możesz utworzyć threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Pamiętaj, że istnieje różnica między Actor Threats i Process Threats. Jeśli dodasz threat do Actor, będziesz mógł wybrać tylko „Spoofing” i „Repudiation”. Jednak w naszym przykładzie dodajemy threat do entity typu Process, więc w oknie tworzenia threat zobaczymy:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Gotowe

Ukończony model powinien wyglądać mniej więcej tak. W ten sposób tworzysz prosty model zagrożeń za pomocą OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft Threat Modeling Tool to bezpłatne narzędzie do pobrania, służące do analizy projektu oprogramowania. Jego workflow tworzy diagram, identyfikuje zagrożenia oraz wspiera ich ograniczanie i walidację za pomocą podejścia STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Ściągawka dotycząca modelowania zagrożeń](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Modelowanie zagrożeń - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Podstawy bezpieczeństwa - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Pierwsze kroki z Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Modelowanie zagrożeń dla sterowników - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [Modelowanie zagrożeń PASTA: wyjaśnienie 7 etapów](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Dokument metodologii Trike v1](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Modelowanie zagrożeń: podsumowanie dostępnych metod](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
