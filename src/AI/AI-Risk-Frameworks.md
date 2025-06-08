# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp zidentyfikował 10 najważniejszych podatności w uczeniu maszynowym, które mogą wpływać na systemy AI. Te podatności mogą prowadzić do różnych problemów z bezpieczeństwem, w tym do zanieczyszczenia danych, inwersji modelu i ataków adwersarialnych. Zrozumienie tych podatności jest kluczowe dla budowania bezpiecznych systemów AI.

Aby uzyskać zaktualizowaną i szczegółową listę 10 najważniejszych podatności w uczeniu maszynowym, zapoznaj się z projektem [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Atak manipulacji danymi wejściowymi**: Napastnik dodaje drobne, często niewidoczne zmiany do **danych przychodzących**, aby model podjął błędną decyzję.\
*Przykład*: Kilka kropli farby na znaku stopu oszukuje samochód autonomiczny, sprawiając, że "widzi" znak ograniczenia prędkości.

- **Atak zanieczyszczenia danych**: **Zbiór treningowy** jest celowo zanieczyszczany złymi próbkami, ucząc model szkodliwych reguł.\
*Przykład*: Złośliwe pliki są błędnie oznaczane jako "nieszkodliwe" w zbiorze treningowym oprogramowania antywirusowego, co pozwala podobnemu złośliwemu oprogramowaniu przejść później.

- **Atak inwersji modelu**: Poprzez badanie wyników, napastnik buduje **model odwrotny**, który rekonstruuje wrażliwe cechy oryginalnych danych wejściowych.\
*Przykład*: Odtworzenie obrazu MRI pacjenta na podstawie prognoz modelu wykrywania nowotworów.

- **Atak inferencji członkostwa**: Adwersarz sprawdza, czy **konkretna rekord** był użyty podczas treningu, zauważając różnice w pewności.\
*Przykład*: Potwierdzenie, że transakcja bankowa danej osoby pojawia się w danych treningowych modelu wykrywania oszustw.

- **Kradzież modelu**: Powtarzające się zapytania pozwalają napastnikowi poznać granice decyzji i **sklonować zachowanie modelu** (i IP).\
*Przykład*: Zbieranie wystarczającej liczby par Q&A z API ML-as-a-Service, aby zbudować lokalny model o zbliżonej wydajności.

- **Atak na łańcuch dostaw AI**: Kompromitacja dowolnego komponentu (dane, biblioteki, wstępnie wytrenowane wagi, CI/CD) w **pipeline ML**, aby zanieczyścić modele downstream.\
*Przykład*: Zainfekowana zależność w modelu-hub instaluje model analizy sentymentu z tylnym dostępem w wielu aplikacjach.

- **Atak transfer learning**: Złośliwa logika jest wprowadzana do **wstępnie wytrenowanego modelu** i przetrwa dostosowanie do zadania ofiary.\
*Przykład*: Podstawa wizji z ukrytym wyzwalaczem nadal zmienia etykiety po dostosowaniu do obrazowania medycznego.

- **Zniekształcenie modelu**: Subtelnie stronnicze lub błędnie oznaczone dane **przesuwają wyniki modelu** na korzyść agendy napastnika.\
*Przykład*: Wstrzykiwanie "czystych" e-maili spamowych oznaczonych jako ham, aby filtr spamowy przepuszczał podobne przyszłe e-maile.

- **Atak na integralność wyników**: Napastnik **zmienia prognozy modelu w tranzycie**, a nie sam model, oszukując systemy downstream.\
*Przykład*: Zmiana werdyktu klasyfikatora złośliwego oprogramowania z "złośliwego" na "nieszkodliwy" przed etapem kwarantanny pliku.

- **Zatrucie modelu** --- Bezpośrednie, celowe zmiany w **parametrach modelu**, często po uzyskaniu dostępu do zapisu, aby zmienić zachowanie.\
*Przykład*: Dostosowanie wag w modelu wykrywania oszustw w produkcji, aby transakcje z określonych kart były zawsze zatwierdzane.


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) opisuje różne ryzyka związane z systemami AI:

- **Zanieczyszczenie danych**: Złośliwi aktorzy zmieniają lub wprowadzają dane treningowe/tuningowe, aby obniżyć dokładność, wprowadzić tylne drzwi lub zniekształcić wyniki, podważając integralność modelu w całym cyklu życia danych.

- **Nieautoryzowane dane treningowe**: Wchłanianie danych objętych prawami autorskimi, wrażliwych lub niedozwolonych tworzy zobowiązania prawne, etyczne i wydajnościowe, ponieważ model uczy się z danych, których nigdy nie miał prawa używać.

- **Manipulacja źródłem modelu**: Manipulacja kodem modelu, zależnościami lub wagami w łańcuchu dostaw lub przez insiderów przed lub w trakcie treningu może wprowadzić ukrytą logikę, która przetrwa nawet po ponownym treningu.

- **Nadmierne przetwarzanie danych**: Słabe kontrole dotyczące przechowywania i zarządzania danymi prowadzą do tego, że systemy przechowują lub przetwarzają więcej danych osobowych niż to konieczne, zwiększając ryzyko narażenia i zgodności.

- **Ekstrakcja modelu**: Napastnicy kradną pliki/wagi modelu, powodując utratę własności intelektualnej i umożliwiając usługi naśladujące lub ataki następcze.

- **Manipulacja wdrożeniem modelu**: Adwersarze modyfikują artefakty modelu lub infrastrukturę serwującą, tak że działający model różni się od zatwierdzonej wersji, potencjalnie zmieniając zachowanie.

- **Odmowa usługi ML**: Zatopienie API lub wysyłanie "gąbkowych" danych wejściowych może wyczerpać zasoby obliczeniowe/energię i wyłączyć model, naśladując klasyczne ataki DoS.

- **Inżynieria odwrotna modelu**: Zbierając dużą liczbę par wejście-wyjście, napastnicy mogą sklonować lub destylować model, napędzając produkty imitacyjne i dostosowane ataki adwersarialne.

- **Niezabezpieczony zintegrowany komponent**: Wrażliwe wtyczki, agenci lub usługi upstream pozwalają napastnikom wstrzykiwać kod lub eskalować uprawnienia w ramach pipeline AI.

- **Wstrzykiwanie poleceń**: Tworzenie poleceń (bezpośrednio lub pośrednio), aby przemycić instrukcje, które nadpisują intencje systemu, sprawiając, że model wykonuje niezamierzone polecenia.

- **Unikanie modelu**: Starannie zaprojektowane dane wejściowe wywołują błędną klasyfikację modelu, halucynacje lub generowanie niedozwolonej treści, erodując bezpieczeństwo i zaufanie.

- **Ujawnienie wrażliwych danych**: Model ujawnia prywatne lub poufne informacje z danych treningowych lub kontekstu użytkownika, naruszając prywatność i przepisy.

- **Wnioskowane wrażliwe dane**: Model dedukuje osobiste atrybuty, które nigdy nie zostały podane, tworząc nowe szkody dla prywatności poprzez wnioskowanie.

- **Niezabezpieczone wyjście modelu**: Niezdezynfekowane odpowiedzi przekazują szkodliwy kod, dezinformację lub nieodpowiednią treść użytkownikom lub systemom downstream.

- **Działania rogue**: Autonomicznie zintegrowane agenty wykonują niezamierzone operacje w rzeczywistości (zapisy plików, wywołania API, zakupy itp.) bez odpowiedniego nadzoru użytkownika.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) provides a comprehensive framework for understanding and mitigating risks associated with AI systems. It categorizes various attack techniques and tactics that adversaries may use against AI models and also how to use AI systems to perform different attacks.


{{#include ../banners/hacktricks-training.md}}
