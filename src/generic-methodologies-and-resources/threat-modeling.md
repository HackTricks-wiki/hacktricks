# Modelowanie zagrożeń

{{#include ../banners/hacktricks-training.md}}

## Modelowanie zagrożeń

Witamy w kompleksowym przewodniku HackTricks na temat modelowania zagrożeń! Rozpocznij eksplorację tego krytycznego aspektu cyberbezpieczeństwa, gdzie identyfikujemy, rozumiemy i opracowujemy strategie przeciwko potencjalnym lukom w systemie. Ten wątek służy jako przewodnik krok po kroku, pełen przykładów z rzeczywistego świata, pomocnego oprogramowania i łatwych do zrozumienia wyjaśnień. Idealny zarówno dla nowicjuszy, jak i doświadczonych praktyków, którzy chcą wzmocnić swoje obrony w zakresie cyberbezpieczeństwa.

### Powszechnie używane scenariusze

1. **Rozwój oprogramowania**: W ramach Bezpiecznego Cyklu Życia Rozwoju Oprogramowania (SSDLC) modelowanie zagrożeń pomaga w **identyfikacji potencjalnych źródeł luk** w wczesnych etapach rozwoju.
2. **Testowanie penetracyjne**: Standard Wykonania Testów Penetracyjnych (PTES) wymaga **modelowania zagrożeń, aby zrozumieć luki w systemie** przed przeprowadzeniem testu.

### Model zagrożeń w skrócie

Model zagrożeń jest zazwyczaj przedstawiany jako diagram, obraz lub inna forma wizualnej ilustracji, która przedstawia planowaną architekturę lub istniejącą budowę aplikacji. Przypomina **diagram przepływu danych**, ale kluczowa różnica polega na jego projektowaniu zorientowanym na bezpieczeństwo.

Modele zagrożeń często zawierają elementy oznaczone na czerwono, symbolizujące potencjalne luki, ryzyka lub bariery. Aby uprościć proces identyfikacji ryzyka, stosuje się triadę CIA (Poufność, Integralność, Dostępność), która stanowi podstawę wielu metodologii modelowania zagrożeń, z STRIDE jako jedną z najczęściej stosowanych. Jednak wybrana metodologia może się różnić w zależności od konkretnego kontekstu i wymagań.

### Triada CIA

Triada CIA to powszechnie uznawany model w dziedzinie bezpieczeństwa informacji, oznaczający Poufność, Integralność i Dostępność. Te trzy filary stanowią fundament, na którym opiera się wiele środków i polityk bezpieczeństwa, w tym metodologii modelowania zagrożeń.

1. **Poufność**: Zapewnienie, że dane lub system nie są dostępne dla nieautoryzowanych osób. To centralny aspekt bezpieczeństwa, wymagający odpowiednich kontroli dostępu, szyfrowania i innych środków zapobiegających naruszeniom danych.
2. **Integralność**: Dokładność, spójność i wiarygodność danych w całym ich cyklu życia. Ta zasada zapewnia, że dane nie są zmieniane ani manipulowane przez nieautoryzowane strony. Często obejmuje sumy kontrolne, haszowanie i inne metody weryfikacji danych.
3. **Dostępność**: Zapewnia, że dane i usługi są dostępne dla autoryzowanych użytkowników, gdy są potrzebne. Często wiąże się to z redundancją, odpornością na błędy i konfiguracjami wysokiej dostępności, aby systemy działały nawet w obliczu zakłóceń.

### Metodologie modelowania zagrożeń

1. **STRIDE**: Opracowane przez Microsoft, STRIDE to akronim od **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**. Każda kategoria reprezentuje rodzaj zagrożenia, a ta metodologia jest powszechnie stosowana w fazie projektowania programu lub systemu w celu identyfikacji potencjalnych zagrożeń.
2. **DREAD**: To kolejna metodologia od Microsoftu używana do oceny ryzyka zidentyfikowanych zagrożeń. DREAD oznacza **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**. Każdy z tych czynników jest oceniany, a wynik jest używany do priorytetyzacji zidentyfikowanych zagrożeń.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): To siedmiostopniowa, **zorientowana na ryzyko** metodologia. Obejmuje definiowanie i identyfikowanie celów bezpieczeństwa, tworzenie zakresu technicznego, dekompozycję aplikacji, analizę zagrożeń, analizę luk oraz ocenę ryzyka/triage.
4. **Trike**: To metodologia oparta na ryzyku, która koncentruje się na obronie aktywów. Zaczyna się od perspektywy **zarządzania ryzykiem** i analizuje zagrożenia oraz luki w tym kontekście.
5. **VAST** (Visual, Agile, and Simple Threat modeling): To podejście ma na celu bycie bardziej dostępnym i integruje się w środowiskach rozwoju Agile. Łączy elementy z innych metodologii i koncentruje się na **wizualnych reprezentacjach zagrożeń**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Opracowane przez Centrum Koordynacji CERT, to ramy są skierowane na **ocenę ryzyka organizacyjnego, a nie konkretnych systemów lub oprogramowania**.

## Narzędzia

Istnieje kilka narzędzi i rozwiązań programowych, które mogą **pomóc** w tworzeniu i zarządzaniu modelami zagrożeń. Oto kilka, które warto rozważyć.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Zaawansowany, wieloplatformowy i wielofunkcyjny interfejs graficzny dla profesjonalistów w dziedzinie cyberbezpieczeństwa. Spider Suite może być używany do mapowania i analizy powierzchni ataku.

**Użycie**

1. Wybierz URL i przeszukaj

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Zobacz wykres

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Projekt open-source od OWASP, Threat Dragon to zarówno aplikacja webowa, jak i desktopowa, która obejmuje diagramowanie systemu oraz silnik reguł do automatycznego generowania zagrożeń/łagodzeń.

**Użycie**

1. Utwórz nowy projekt

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Czasami może to wyglądać tak:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Uruchom nowy projekt

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Zapisz nowy projekt

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Stwórz swój model

Możesz użyć narzędzi takich jak SpiderSuite Crawler, aby zainspirować się, podstawowy model mógłby wyglądać tak

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Tylko trochę wyjaśnienia na temat podmiotów:

- Proces (Podmiot sam w sobie, taki jak serwer WWW lub funkcjonalność webowa)
- Aktor (Osoba, taka jak odwiedzający stronę, użytkownik lub administrator)
- Linia przepływu danych (Wskaźnik interakcji)
- Granica zaufania (Różne segmenty lub zakresy sieci.)
- Magazyn (Miejsca, w których przechowywane są dane, takie jak bazy danych)

5. Utwórz zagrożenie (Krok 1)

Najpierw musisz wybrać warstwę, do której chcesz dodać zagrożenie

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Teraz możesz stworzyć zagrożenie

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Pamiętaj, że istnieje różnica między zagrożeniami aktorów a zagrożeniami procesów. Jeśli dodasz zagrożenie do aktora, będziesz mógł wybrać tylko "Spoofing" i "Repudiation". Jednak w naszym przykładzie dodajemy zagrożenie do podmiotu procesu, więc zobaczymy to w oknie tworzenia zagrożenia:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Gotowe

Teraz twój ukończony model powinien wyglądać mniej więcej tak. I tak tworzy się prosty model zagrożeń z OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

To darmowe narzędzie od Microsoftu, które pomaga w znajdowaniu zagrożeń w fazie projektowania projektów oprogramowania. Używa metodologii STRIDE i jest szczególnie odpowiednie dla tych, którzy rozwijają na stosie Microsoftu.


{{#include ../banners/hacktricks-training.md}}
