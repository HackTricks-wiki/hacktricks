# Red Teaming Web3 skoncentrowane na wartości (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) klasyfikuje działania i techniki adwersarzy wymierzone w systemy aktywów cyfrowych.<sup>[[1]](#references)</sup> Traktuj go jako **podstawę modelowania zagrożeń**: zinwentaryzuj każdy komponent, który może emitować, wyceniać, autoryzować lub kierować aktywami, przypisz te punkty styku do technik AADAPT, a następnie opracuj scenariusze red-teamowe, które sprawdzą, czy środowisko jest odporne na nieodwracalne straty finansowe.

## 1. Zinwentaryzuj komponenty przenoszące wartość
Przygotuj mapę wszystkiego, co może wpływać na stan wartości, nawet jeśli działa poza łańcuchem.<sup>[[2]](#references)</sup>

- **Usługi podpisywania powierniczego** (klastry HSM/KMS, Vault/KMaaS, API podpisywania używane przez boty lub zadania back-office). Zapisz identyfikatory kluczy, zasady, tożsamości automatyzacji i procedury zatwierdzania.
- **Ścieżki administracyjne i aktualizacji** kontraktów (administratorzy proxy, timelocki governance, klucze awaryjnego wstrzymania, rejestry parametrów). Uwzględnij, kto lub co może je wywołać oraz przy jakim kworum lub opóźnieniu.
- **Logika protokołów on-chain** obsługująca pożyczki, AMM, vaulty, staking, mosty lub szyny rozliczeniowe. Udokumentuj przyjmowane przez nią niezmienniki (ceny z oracle, współczynniki zabezpieczenia, częstotliwość rebalansowania…).
- **Automatyzacja off-chain** tworząca transakcje (boty market-makingowe, pipeline’y CI/CD, zadania cron, funkcje serverless). Często przechowuje klucze API lub tożsamości usług, które mogą żądać podpisów.
- **Oracle i źródła danych** (skład agregatora, kworum, progi odchyleń, częstotliwość aktualizacji). Odnotuj wszystkie źródła upstream wykorzystywane przez zautomatyzowaną logikę ryzyka.
- **Mosty i routery cross-chain** (kontrakty lock/mint, relayerzy, zadania rozliczeniowe) łączące łańcuchy lub stosy powiernicze.

Rezultat: diagram przepływu wartości pokazujący, jak przemieszczają się aktywa, kto autoryzuje ich transfer i które sygnały zewnętrzne wpływają na logikę biznesową.

## 2. Powiąż komponenty z działaniami AADAPT
Przełóż taksonomię AADAPT na konkretne potencjalne ataki dla poszczególnych komponentów.<sup>[[2]](#references)</sup>

| Komponent | Główny obszar AADAPT |
| --- | --- |
| Infrastruktura podpisywania/KMS | Kradzież poświadczeń, obejście zasad, nadużycie podpisywania, przejęcie governance |
| Oracle/źródła danych | Zatruwanie danych wejściowych, manipulowanie agregacją, obchodzenie progów odchyleń |
| Protokoły on-chain | Manipulacja ekonomiczna z użyciem flash-loanów, łamanie niezmienników, zmiana konfiguracji parametrów |
| Pipeline’y automatyzacji | Przejęte tożsamości botów/CI, powtórzenie wsadowe, nieautoryzowane wdrożenie |
| Mosty/routery | Unikanie wykrycia cross-chain, szybkie pranie z przeskokami, desynchronizacja rozliczeń |

Takie mapowanie gwarantuje, że testujesz nie tylko kontrakty, ale też każdą tożsamość i automatyzację, które mogą pośrednio sterować przepływem wartości.

## 3. Ustal priorytety na podstawie wykonalności ataku i wpływu biznesowego

1. **Słabości operacyjne**: ujawnione poświadczenia CI, nadmierne uprawnienia ról IAM, błędnie skonfigurowane zasady KMS, konta automatyzacji mogące żądać dowolnych podpisów, publiczne buckety z konfiguracją mostów itp.
2. **Słabości specyficzne dla wartości**: podatne parametry oracle, kontrakty z możliwością aktualizacji bez wielostronnych zatwierdzeń, płynność podatna na flash-loany, działania governance omijające timelocki.

Przechodź przez kolejkę jak adwersarz: zacznij od operacyjnych punktów zaczepienia, które mogą zadziałać już teraz, a następnie przejdź do złożonych ścieżek manipulacji protokołem i mechanizmami ekonomicznymi.<sup>[[2]](#references)</sup>

## 4. Przeprowadzaj testy w kontrolowanych środowiskach realistycznych pod względem produkcji
- **Forki mainnetów / izolowane testnety**: odtwórz bytecode, storage i płynność, aby ścieżki flash-loanów, odchylenia oracle i przepływy przez mosty działały od początku do końca bez używania prawdziwych środków.<sup>[[2]](#references)</sup>
- **Planowanie zasięgu rażenia**: przed uruchomieniem scenariusza zdefiniuj wyłączniki awaryjne, moduły możliwe do wstrzymania, procedury rollbacku i klucze administracyjne przeznaczone wyłącznie do testów.
- **Koordynacja interesariuszy**: powiadom powierników, operatorów oracle, partnerów obsługujących mosty i zespoły compliance, aby ich zespoły monitorujące spodziewały się takiego ruchu.
- **Zatwierdzenie prawne**: udokumentuj zakres, upoważnienie i warunki przerwania testu, jeśli symulacje mogą objąć regulowane szyny płatnicze.

## 5. Telemetria dopasowana do technik AADAPT
Skonfiguruj strumienie telemetrii tak, aby każdy scenariusz dostarczał użytecznych danych do wykrywania.<sup>[[2]](#references)</sup>

- **Ślady na poziomie łańcucha**: pełne grafy wywołań, zużycie gasu, nonce’y transakcji, znaczniki czasu bloków — do odtworzenia pakietów flash-loanów, struktur przypominających reentrancy i przeskoków między kontraktami.
- **Logi aplikacji/API**: powiąż każdą transakcję on-chain z tożsamością człowieka lub automatyzacji (identyfikator sesji, klient OAuth, klucz API, identyfikator zadania CI), uwzględniając adresy IP i metody uwierzytelniania.
- **Logi KMS/HSM**: identyfikator klucza, podmiot wywołujący, wynik weryfikacji zasad, adres docelowy i kody przyczyn dla każdego podpisu. Ustal bazowy poziom dla okien zmian i operacji wysokiego ryzyka.
- **Metadane oracle/źródeł danych**: skład źródeł dla każdej aktualizacji, zgłoszona wartość, odchylenie od średniej kroczącej, uruchomione progi i wykorzystane ścieżki failover.
- **Ślady mostów/swapów**: skoreluj zdarzenia lock/mint/unlock pomiędzy łańcuchami za pomocą identyfikatorów korelacji, identyfikatorów łańcuchów, tożsamości relayerów i czasu między przeskokami.
- **Wskaźniki anomalii**: metryki pochodne, takie jak skoki poślizgu, nietypowe współczynniki zabezpieczenia, nienaturalne zagęszczenie gasu czy szybkość transferów cross-chain.

Oznaczaj wszystkie dane identyfikatorami scenariuszy lub syntetycznymi identyfikatorami użytkowników, aby analitycy mogli powiązać obserwacje z testowaną techniką AADAPT.

## 6. Cykl purple team i metryki dojrzałości
1. Uruchom scenariusz w kontrolowanym środowisku i zarejestruj wykrycia (alerty, dashboardy, powiadomienia dla osób reagujących).<sup>[[2]](#references)</sup>
2. Przyporządkuj każdy krok do konkretnych technik AADAPT oraz obserwacji z warstw chain/app/KMS/oracle/bridge.
3. Opracuj i wdroż hipotezy detekcyjne (reguły progowe, wyszukiwanie korelacji, kontrole niezmienników).
4. Powtarzaj testy, aż średni czas wykrycia (MTTD) i średni czas opanowania incydentu (MTTC) osiągną akceptowalne wartości biznesowe, a procedury reagowania będą niezawodnie zatrzymywać utratę wartości.

Śledź dojrzałość programu w trzech obszarach:<sup>[[2]](#references)</sup>
- **Widoczność**: każda krytyczna ścieżka wartości ma telemetrię w każdej warstwie.
- **Pokrycie**: odsetek priorytetowych technik AADAPT przetestowanych od początku do końca.
- **Reakcja**: zdolność do wstrzymania kontraktów, unieważnienia kluczy lub zamrożenia przepływów przed nieodwracalną stratą.

Typowe kamienie milowe: (1) ukończona inwentaryzacja wartości i mapowanie AADAPT, (2) pierwszy scenariusz end-to-end z wdrożonymi mechanizmami wykrywania, (3) kwartalne cykle purple team rozszerzające pokrycie i skracające MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Szablony scenariuszy
Skorzystaj z tych powtarzalnych schematów, aby projektować symulacje bezpośrednio powiązane z działaniami AADAPT.<sup>[[2]](#references)</sup>

### Scenariusz A – Manipulacja ekonomiczna z użyciem flash-loana
- **Cel**: pożyczyć kapitał dostępny przez jedną transakcję, aby zniekształcić ceny/płynność AMM i uruchomić błędnie wycenione pożyczki, likwidacje lub emisje przed spłatą.
- **Wykonanie**:
  1. Uruchom fork docelowego łańcucha i zasil pule płynnością zbliżoną do produkcyjnej.
  2. Pożycz dużą kwotę nominalną za pomocą flash-loana.
  3. Wykonaj odpowiednio dobrane swapy, aby przekroczyć granice cenowe/progowe, na których opiera się logika pożyczek, vaultów lub instrumentów pochodnych.
  4. Natychmiast po zniekształceniu wywołaj kontrakt będący celem (pożycz, zlikwiduj, wyemituj), a następnie spłać flash-loana.
- **Pomiar**: Czy udało się naruszyć niezmiennik? Czy uruchomiły się monitory poślizgu/odchyleń cenowych, wyłączniki awaryjne lub mechanizmy wstrzymania governance? Ile czasu zajęło analityce wykrycie nietypowego wzorca gasu/grafu wywołań?

### Scenariusz B – Zatruwanie oracle/źródła danych
- **Cel**: ustalić, czy zmanipulowane źródła danych mogą uruchomić destrukcyjne działania automatyczne (masowe likwidacje, nieprawidłowe rozliczenia).
- **Wykonanie**:
  1. W forku/testnecie wdróż złośliwe źródło danych lub zmień wagi agregatora/kworum/częstotliwość aktualizacji tak, by przekroczyć tolerowane odchylenie.
  2. Pozwól zależnym kontraktom pobrać zatrute wartości i wykonać standardową logikę.
- **Pomiar**: Alerty o wartościach spoza zakresu na poziomie źródła danych, aktywacja zapasowego oracle, egzekwowanie granic min./maks. oraz opóźnienie między pojawieniem się anomalii a reakcją operatora.

### Scenariusz C – Nadużycie poświadczeń/podpisywania
- **Cel**: sprawdzić, czy przejęcie pojedynczego podpisującego lub tożsamości automatyzacji umożliwia nieautoryzowane aktualizacje, zmiany parametrów lub opróżnienie skarbca.
- **Wykonanie**:
  1. Zinwentaryzuj tożsamości z wrażliwymi uprawnieniami do podpisywania (operatorzy, tokeny CI, konta usług wywołujące KMS/HSM, uczestnicy multisig).
  2. Zasymuluj przejęcie (ponownie użyj ich poświadczeń/kluczy w ramach zakresu laboratorium).
  3. Spróbuj wykonać uprzywilejowane działania: aktualizować proxy, zmieniać parametry ryzyka, emitować/wstrzymywać aktywa lub uruchamiać propozycje governance.
- **Pomiar**: Czy logi KMS/HSM generują alerty o anomaliach (pora dnia, zmiana adresu docelowego, seria operacji wysokiego ryzyka)? Czy zasady lub progi multisig mogą zapobiec jednostronnemu nadużyciu? Czy egzekwowane są limity przepustowości/tempa lub dodatkowe zatwierdzenia?

### Scenariusz D – Unikanie wykrycia cross-chain i luki w identyfikowalności
- **Cel**: ocenić, jak dobrze obrońcy potrafią śledzić i zatrzymywać aktywa szybko prane przez mosty, routery DEX i przeskoki przez rozwiązania zwiększające prywatność.
- **Wykonanie**:
  1. Połącz operacje lock/mint przez popularne mosty, przeplataj swapy/mixery na każdym etapie i utrzymuj identyfikatory korelacji dla poszczególnych przeskoków.
  2. Przyspiesz transfery, aby obciążyć opóźnienia monitorowania (wiele przeskoków w ciągu minut/bloków).
- **Pomiar**: Czas korelowania zdarzeń w telemetrii i komercyjnych narzędziach analityki blockchain, kompletność odtworzonej ścieżki, zdolność do wskazania punktów blokowania w prawdziwym incydencie oraz skuteczność alertów dotyczących nietypowej szybkości/wartości transferów cross-chain.

## References

- [1] [Framework cyberzagrożeń AADAPT(TM) dla aktywów cyfrowych (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Framework MITRE AADAPT jako plan działania dla Red Teamu (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
