# Modelowanie zagrożeń

{{#include ../banners/hacktricks-training.md}}

## Modelowanie zagrożeń

Witamy w kompleksowym przewodniku HackTricks po modelowaniu zagrożeń! Rozpocznij eksplorację tego krytycznego aspektu cyberbezpieczeństwa, w ramach którego identyfikujemy potencjalne luki w systemie, poznajemy je i opracowujemy strategie przeciwdziałania. Ten wątek służy jako przewodnik krok po kroku, pełen przykładów z rzeczywistego świata, pomocnego oprogramowania i łatwych do zrozumienia wyjaśnień. Jest idealny zarówno dla początkujących, jak i doświadczonych praktyków, którzy chcą wzmocnić swoje zabezpieczenia cyberbezpieczeństwa.

### Często używane scenariusze

1. **Tworzenie oprogramowania**: W ramach Secure Software Development Life Cycle (SSDLC) modelowanie zagrożeń pomaga na wczesnych etapach tworzenia **identyfikować potencjalne źródła luk w zabezpieczeniach**.
2. **Penetration Testing**: Framework Penetration Testing Execution Standard (PTES) wymaga **modelowania zagrożeń w celu zrozumienia luk w systemie** przed przeprowadzeniem testu.

### Model zagrożeń w skrócie

Model zagrożeń jest zazwyczaj przedstawiany jako diagram, obraz lub inna forma wizualnej ilustracji przedstawiająca planowaną architekturę albo istniejącą strukturę aplikacji. Przypomina **diagram przepływu danych**, ale kluczowa różnica polega na jego projektowaniu zorientowanym na bezpieczeństwo.

Modele zagrożeń często zawierają elementy oznaczone na czerwono, symbolizujące potencjalne luki, ryzyka lub bariery. Aby usprawnić proces identyfikacji ryzyka, stosuje się triadę CIA (Confidentiality, Integrity, Availability), która stanowi podstawę wielu metodologii modelowania zagrożeń, z których jedną z najczęściej używanych jest STRIDE. Wybrana metodologia może się jednak różnić w zależności od konkretnego kontekstu i wymagań.

### Triada CIA

Triada CIA to powszechnie uznawany model w dziedzinie bezpieczeństwa informacji, oznaczający Confidentiality, Integrity i Availability. Te trzy filary stanowią podstawę, na której opiera się wiele środków i zasad bezpieczeństwa, w tym metodologie modelowania zagrożeń.

1. **Confidentiality**: Zapewnienie, że dane lub system nie są dostępne dla nieupoważnionych osób. Jest to centralny aspekt bezpieczeństwa, wymagający odpowiednich mechanizmów kontroli dostępu, szyfrowania i innych środków zapobiegających naruszeniom danych.
2. **Integrity**: Dokładność, spójność i wiarygodność danych w całym ich cyklu życia. Zasada ta zapewnia, że dane nie zostaną zmienione ani naruszone przez nieupoważnione strony. Często obejmuje sumy kontrolne, hashing i inne metody weryfikacji danych.
3. **Availability**: Zapewnienie, że dane i usługi są dostępne dla upoważnionych użytkowników, gdy są potrzebne. Często wymaga to redundancji, odporności na awarie i konfiguracji high-availability, aby systemy działały nawet w obliczu zakłóceń.

### Metodologie modelowania zagrożeń

1. **STRIDE**: Opracowana przez Microsoft metodologia STRIDE to akronim oznaczający **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service i Elevation of Privilege**. Każda kategoria reprezentuje rodzaj zagrożenia, a metodologia ta jest powszechnie stosowana na etapie projektowania programu lub systemu w celu identyfikacji potencjalnych zagrożeń.
2. **DREAD**: Jest to kolejna metodologia firmy Microsoft używana do oceny ryzyka zidentyfikowanych zagrożeń. DREAD oznacza **Damage potential, Reproducibility, Exploitability, Affected users i Discoverability**. Każdy z tych czynników jest oceniany, a wynik służy do ustalania priorytetów zidentyfikowanych zagrożeń.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Jest to siedmioetapowa metodologia **risk-centric**. Obejmuje definiowanie i identyfikowanie celów bezpieczeństwa, tworzenie zakresu technicznego, dekompozycję aplikacji, analizę zagrożeń, analizę luk oraz ocenę ryzyka i triage.
4. **Trike**: Jest to metodologia oparta na ryzyku, koncentrująca się na ochronie zasobów. Rozpoczyna się od perspektywy **risk management** i analizuje zagrożenia oraz luki w tym kontekście.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Podejście to ma być bardziej dostępne i integrować się ze środowiskami tworzenia Agile. Łączy elementy innych metodologii i koncentruje się na **wizualnych reprezentacjach zagrożeń**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Framework opracowany przez CERT Coordination Center, ukierunkowany na **organizacyjną ocenę ryzyka, a nie na konkretne systemy lub oprogramowanie**.

## Narzędzia

Dostępnych jest kilka narzędzi i rozwiązań programowych, które mogą **pomóc** w tworzeniu i zarządzaniu modelami zagrożeń. Oto kilka propozycji, które warto rozważyć.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Zaawansowany, wieloplatformowy i wielofunkcyjny web spider/crawler GUI dla profesjonalistów zajmujących się cyberbezpieczeństwem. Spider Suite może być używany do mapowania i analizy attack surface.

**Użycie**

1. Wybierz URL i rozpocznij Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Wyświetl Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Open-source'owy projekt OWASP. Threat Dragon jest zarówno aplikacją webową, jak i desktopową, która obejmuje tworzenie diagramów systemu oraz rule engine do automatycznego generowania zagrożeń i środków zaradczych.

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

Możesz użyć narzędzi takich jak SpiderSuite Crawler, aby uzyskać inspirację. Podstawowy model mógłby wyglądać mniej więcej tak:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Krótkie wyjaśnienie dotyczące encji:

- Process (Sama encja, np. Webserver lub funkcjonalność webowa)
- Actor (Osoba, np. Website Visitor, User lub Administrator)
- Data Flow Line (Wskaźnik interakcji)
- Trust Boundary (Różne segmenty sieci lub zakresy.)
- Store (Elementy, w których przechowywane są dane, np. Databases)

5. Utwórz Threat (krok 1)

Najpierw musisz wybrać warstwę, do której chcesz dodać zagrożenie.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Teraz możesz utworzyć zagrożenie.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Pamiętaj, że istnieje różnica między Actor Threats i Process Threats. Jeśli dodasz zagrożenie do elementu Actor, będziesz mieć możliwość wyboru wyłącznie opcji "Spoofing" i "Repudiation". Jeśli jednak w naszym przykładzie dodamy zagrożenie do encji Process, w polu tworzenia zagrożenia zobaczymy:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Gotowe

Ukończony model powinien wyglądać mniej więcej tak. W ten sposób tworzysz prosty model zagrożeń za pomocą OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Jest to bezpłatne narzędzie firmy Microsoft, które pomaga znajdować zagrożenia na etapie projektowania projektów programistycznych. Wykorzystuje metodologię STRIDE i szczególnie dobrze nadaje się dla osób tworzących oprogramowanie w stacku Microsoft.

{{#include ../banners/hacktricks-training.md}}
