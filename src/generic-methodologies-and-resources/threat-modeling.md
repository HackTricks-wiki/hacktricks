# Modelowanie zagrożeń

{{#include ../banners/hacktricks-training.md}}

Witamy w kompleksowym przewodniku HackTricks po modelowaniu zagrożeń! Rozpocznij eksplorację tego kluczowego aspektu cyberbezpieczeństwa, w ramach którego identyfikujemy potencjalne luki w systemie, poznajemy je i opracowujemy strategie ochrony przed nimi. Ten materiał stanowi przewodnik krok po kroku, zawierający przykłady z rzeczywistego świata, pomocne oprogramowanie oraz łatwe do zrozumienia wyjaśnienia. Jest odpowiedni zarówno dla początkujących, jak i doświadczonych praktyków, którzy chcą wzmocnić swoje zabezpieczenia cyberbezpieczeństwa.

### Często stosowane scenariusze

1. **Tworzenie oprogramowania**: W ramach Secure Software Development Life Cycle (SSDLC) modelowanie zagrożeń pomaga **identyfikować potencjalne źródła luk** na wczesnych etapach tworzenia oprogramowania.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) uznaje modelowanie zagrożeń za wymagane do prawidłowego przeprowadzenia testów i nakazuje dokumentowanie zasobów biznesowych, procesów biznesowych, społeczności zagrożeń oraz ich możliwości.<sup>[[2]](#references)</sup>

### Model zagrożeń w skrócie

Model zagrożeń jest zazwyczaj przedstawiany jako diagram, obraz lub inna wizualna ilustracja planowanej architektury albo istniejącej aplikacji. Diagramy przepływu danych (DFD) są powszechnym sposobem modelowania systemu i jego interakcji, natomiast modelowanie zagrożeń dodaje analizę skoncentrowaną na bezpieczeństwie.<sup>[[1]](#references)</sup>

W Microsoft Threat Modeling Tool czerwone linie przerywane wskazują granice zaufania; inne narzędzia mogą stosować odmienne konwencje wizualne.<sup>[[4]](#references)</sup> Aby usprawnić identyfikację ryzyka, zespoły mogą korzystać z triady CIA (Confidentiality, Integrity, Availability) lub kategorii zagrożeń STRIDE, jednak właściwa metodologia zależy od kontekstu i wymagań projektu.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### Triada CIA

Triada CIA to powszechnie uznawany model bezpieczeństwa informacji, którego nazwa oznacza Confidentiality, Integrity i Availability. Właściwości te są często używane do opisywania celów bezpieczeństwa danych i systemów.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Zapewnienie, że dane lub system nie są dostępne dla osób nieuprawnionych. Jest to kluczowy aspekt bezpieczeństwa, wymagający odpowiednich mechanizmów kontroli dostępu, szyfrowania oraz innych środków zapobiegających naruszeniom danych.
2. **Integrity**: Dokładność, spójność i wiarygodność danych w całym ich cyklu życia. Zasada ta zapewnia, że dane nie zostaną zmienione ani zmanipulowane przez nieuprawnione podmioty. Często obejmuje sumy kontrolne, hashing oraz inne metody weryfikacji danych.
3. **Availability**: Zapewnienie, że dane i usługi są dostępne dla uprawnionych użytkowników, gdy są potrzebne. Często wymaga to redundancji, odporności na awarie oraz konfiguracji high availability, aby systemy działały nawet w przypadku zakłóceń.

### Metodologie modelowania zagrożeń

1. **STRIDE**: Podejście STRIDE firmy Microsoft kategoryzuje zagrożenia dla oprogramowania jako **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service oraz Elevation of Privilege**. Kategorie te pomagają analitykom identyfikować możliwe zagrożenia w każdym podatnym punkcie projektu.<sup>[[5]](#references)</sup>
2. **DREAD**: To podejście firmy Microsoft do oceny zagrożeń nadaje im punktację na podstawie **Damage, Reproducibility, Exploitability, Affected users oraz Discoverability**. Uzyskany wynik może pomóc w ustalaniu priorytetów zagrożeń wymagających ograniczenia.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Jest to siedmioetapowa metodologia **risk-centric**, obejmująca cele, zakres techniczny, dekompozycję aplikacji, analizę zagrożeń, analizę luk i słabości, modelowanie ataku oraz analizę ryzyka/wpływu.<sup>[[8]](#references)</sup>
4. **Trike**: Ten framework audytu bezpieczeństwa podchodzi do modelowania zagrożeń z perspektywy **risk-management** i obrony.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Metoda ta kładzie nacisk na skalowalne i użyteczne modele zagrożeń dla widoków aplikacji i operacji oraz może integrować się z cyklami życia developmentu i DevOps.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Stworzona przez CERT Division należący do Software Engineering Institute na Carnegie Mellon University, OCTAVE jest opartą na ryzyku strategiczną metodą oceny i planowania, skoncentrowaną na ryzyku organizacyjnym, a nie wyłącznie na technologii.<sup>[[10]](#references)</sup>

## Narzędzia

Dostępnych jest kilka narzędzi i rozwiązań programowych, które mogą **pomóc** w tworzeniu i zarządzaniu modelami zagrożeń. Oto kilka propozycji, które warto rozważyć.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite to wieloplatformowy web crawler dla specjalistów ds. bezpieczeństwa, obsługujący mapowanie attack surface, wykrywanie endpointów oraz analizę aplikacji webowych.<sup>[[6]](#references)</sup>

**Użycie**

1. Wybierz URL i uruchom Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Wyświetl Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon to bezpłatna, open-source'owa, wieloplatformowa aplikacja do modelowania zagrożeń, służąca do rysowania diagramów, sugerowania zagrożeń i rejestrowania sposobów ich ograniczania. Jest dostępna jako aplikacja webowa i desktopowa.<sup>[[7]](#references)</sup>

**Użycie**

1. Utwórz nowy projekt

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Czasami może to wyglądać tak:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Uruchom nowy projekt

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Zapisz nowy projekt

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Utwórz swój model

Możesz użyć narzędzi takich jak SpiderSuite Crawler, aby uzyskać inspirację. Podstawowy model może wyglądać mniej więcej tak:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Krótkie wyjaśnienie dotyczące encji:

- Process (Sama encja, taka jak Webserver lub funkcjonalność webowa)
- Actor (Osoba, taka jak odwiedzający stronę, użytkownik lub administrator)
- Data Flow Line (Wskaźnik interakcji)
- Trust Boundary (Różne segmenty sieci lub zakresy.)
- Store (Miejsca przechowywania danych, takie jak bazy danych)

5. Utwórz zagrożenie (krok 1)

Najpierw musisz wybrać warstwę, do której chcesz dodać zagrożenie

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Teraz możesz utworzyć zagrożenie

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Pamiętaj, że istnieje różnica między zagrożeniami Actor i Process. Jeśli dodasz zagrożenie do Actor, będziesz mieć możliwość wyboru wyłącznie „Spoofing” i „Repudiation”. W naszym przykładzie dodajemy jednak zagrożenie do encji Process, dlatego w polu tworzenia zagrożenia zobaczymy:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Gotowe

Ukończony model powinien wyglądać mniej więcej tak. W ten sposób tworzysz prosty model zagrożeń za pomocą OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft Threat Modeling Tool to bezpłatne narzędzie do pobrania, służące do analizy projektu oprogramowania. Jego workflow tworzy diagram, identyfikuje zagrożenia oraz wspiera ich ograniczanie i walidację za pomocą podejścia STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Ściągawka modelowania zagrożeń](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Modelowanie zagrożeń - Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Podstawy bezpieczeństwa - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Rozpoczynanie pracy z Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Modelowanie zagrożeń dla sterowników - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [Modelowanie zagrożeń PASTA: wyjaśnienie 7 etapów](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Dokument metodologii Trike v1](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Modelowanie zagrożeń: podsumowanie dostępnych metod](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
