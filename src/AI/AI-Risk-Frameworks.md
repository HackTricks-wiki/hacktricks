# Ryzyka AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp zidentyfikował top 10 podatności w systemach uczenia maszynowego, które mogą wpływać na systemy AI. Te podatności mogą prowadzić do różnych problemów bezpieczeństwa, w tym data poisoning, model inversion i adversarial attacks. Zrozumienie tych zagrożeń jest kluczowe dla budowy bezpiecznych systemów AI.

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: Atakujący wprowadza drobne, często niewidoczne zmiany do **incoming data**, tak by model podjął błędną decyzję.\
*Example*: Kilka kropek farby na znaku stopu oszukuje samochód autonomiczny, który "widzi" znak z ograniczeniem prędkości.

- **Data Poisoning Attack**: Zestaw **training set** jest celowo zanieczyszczony złośliwymi próbkami, ucząc model szkodliwych reguł.\
*Example*: Malware binaries są błędnie oznaczone jako "benign" w korpusie treningowym antywirusa, co pozwala podobnemu malware'owi przechodzić później niezauważonym.

- **Model Inversion Attack**: Poprzez badanie wyjść, atakujący buduje **reverse model**, który rekonstruuje wrażliwe cechy oryginalnych danych wejściowych.\
*Example*: Odtworzenie obrazu MRI pacjenta na podstawie predykcji modelu wykrywającego raka.

- **Membership Inference Attack**: Adwersarz sprawdza, czy **konkretny rekord** był używany podczas treningu, wykrywając różnice w poziomie ufności.\
*Example*: Potwierdzenie, że transakcja bankowa danej osoby pojawiła się w danych treningowych modelu wykrywającego oszustwa.

- **Model Theft**: Poprzez wielokrotne zapytania atakujący poznaje granice decyzji i potrafi **sklonować zachowanie modelu** (i IP).\
*Example*: Zebranie wystarczającej liczby par pytanie‑odpowiedź z API ML-as-a-Service, by zbudować lokalny model niemal równoważny oryginałowi.

- **AI Supply‑Chain Attack**: Kompromitacja dowolnego komponentu (dane, biblioteki, pre‑trained weights, CI/CD) w **ML pipeline** umożliwia skażenie modeli downstream.\
*Example*: Podmieniona zależność na model‑hub instaluje backdoored sentiment‑analysis model w wielu aplikacjach.

- **Transfer Learning Attack**: Złośliwa logika jest zaszyta w **pre‑trained model** i przetrwa fine‑tuning na zadaniu ofiary.\
*Example*: Vision backbone z ukrytym triggerem nadal zmienia etykiety po dostosowaniu do obrazowania medycznego.

- **Model Skewing**: Subtelnie uprzedzone lub błędnie oznaczone dane **przesuwają outputy modelu**, faworyzując agendę atakującego.\
*Example*: Wstrzyknięcie "czystych" spamów oznaczonych jako ham powoduje, że filtr spamowy przepuszcza podobne wiadomości w przyszłości.

- **Output Integrity Attack**: Atakujący **zmienia predykcje modelu w tranzycie**, nie modyfikując samego modelu, oszukując systemy downstream.\
*Example*: Zmiana verdictu klasyfikatora malware z "malicious" na "benign" zanim etap kwarantanny pliku go zobaczy.

- **Model Poisoning** --- Bezpośrednie, celowane zmiany w **parametrach modelu**, często po uzyskaniu dostępu zapisu, w celu zmiany zachowania.\
*Example*: Modyfikacja wag w produkcyjnym modelu wykrywającym oszustwa, aby transakcje z określonych kart były zawsze zatwierdzane.


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) opisuje różne ryzyka związane z systemami AI:

- **Data Poisoning**: Złośliwi aktorzy modyfikują lub wstrzykują dane treningowe/tuningowe, by pogorszyć dokładność, zaszyć backdoory lub zniekształcić wyniki, podważając integralność modelu w całym cyklu życia danych.

- **Unauthorized Training Data**: Pobieranie materiałów objętych prawami autorskimi, danych wrażliwych lub zbiorów bez uprawnień tworzy zobowiązania prawne, etyczne i wydajnościowe, ponieważ model uczy się z danych, których nie powinien używać.

- **Model Source Tampering**: Manipulacja supply‑chain lub przez insiderów kodem modelu, zależnościami lub weights przed lub w czasie treningu może zaszyć ukrytą logikę, która przetrwa nawet retraining.

- **Excessive Data Handling**: Słabe kontrole przechowywania i zarządzania danymi prowadzą do przechowywania lub przetwarzania więcej danych osobowych niż konieczne, zwiększając ekspozycję i ryzyko zgodności.

- **Model Exfiltration**: Atakujący kradnie pliki modelu/weights, powodując utratę własności intelektualnej i umożliwiając powielanie usług lub dalsze ataki.

- **Model Deployment Tampering**: Adwersarze modyfikują artefakty modelu lub infrastrukturę serwującą, tak że uruchomiony model różni się od zatwierdzonej wersji, potencjalnie zmieniając zachowanie.

- **Denial of ML Service**: Zalewanie API lub wysyłanie „sponge” inputs może wyczerpać zasoby obliczeniowe/energetyczne i wyłączyć model, odzwierciedlając klasyczne ataki DoS.

- **Model Reverse Engineering**: Poprzez zebranie dużej liczby par input‑output, atakujący może sklonować lub zdestylować model, napędzając produkty imitujące i spersonalizowane ataki adversarial.

- **Insecure Integrated Component**: Wrażliwe pluginy, agenty lub usługi upstream pozwalają atakującym wstrzyknąć kod lub eskalować przywileje w pipeline AI.

- **Prompt Injection**: Konstruowanie promptów (bezpośrednio lub pośrednio) w celu przemycenia instrukcji, które nadpisują intencję systemu, zmuszając model do wykonania niezamierzonych poleceń.

- **Model Evasion**: Starannie zaprojektowane inputy wywołują błędną klasyfikację, hallucinationy lub zwracanie zabronionych treści, podważając bezpieczeństwo i zaufanie.

- **Sensitive Data Disclosure**: Model ujawnia prywatne lub poufne informacje z danych treningowych lub kontekstu użytkownika, naruszając prywatność i regulacje.

- **Inferred Sensitive Data**: Model wyprowadza cechy osobiste, które nigdy nie były przekazane, tworząc nowe szkody prywatności przez inferencję.

- **Insecure Model Output**: Nieskanalizowane odpowiedzi przekazują szkodliwy kod, dezinformację lub nieodpowiednie treści użytkownikom lub systemom downstream.

- **Rogue Actions**: Autonomicznie zintegrowane agenty wykonują niezamierzone operacje w świecie rzeczywistym (zapis plików, wywołania API, zakupy itp.) bez odpowiedniego nadzoru użytkownika.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) dostarcza kompleksowego frameworku do zrozumienia i łagodzenia ryzyk związanych z systemami AI. Kategoryzuje różne techniki i taktyki ataków, których adwersarze mogą użyć przeciwko modelom AI, oraz sposoby wykorzystania systemów AI do przeprowadzania różnych ataków.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Atakujący kradną aktywne session tokens lub cloud API credentials i wywołują płatne, hostowane w chmurze LLMy bez autoryzacji. Dostęp jest często odsprzedawany przez reverse proxies, które frontują konto ofiary, np. deploymenty "oai-reverse-proxy". Konsekwencje obejmują straty finansowe, misuse modelu poza polityką oraz przypisanie aktywności do tenanta‑ofiary.

TTPs:
- Harvest tokens z zainfekowanych maszyn deweloperskich lub przeglądarek; kraść sekrety CI/CD; kupować leaked cookies.
- Stawiać reverse proxy, które przekazuje żądania do prawdziwego provider'a, ukrywając upstream key i multiplexując wielu klientów.
- Abuse direct base‑model endpoints, by obejść enterprise guardrails i rate limits.

Mitigations:
- Binduj tokens do odcisku urządzenia, zakresów IP i client attestation; egzekwuj krótkie wygaśnięcia i odświeżanie z MFA.
- Scope keys minimalnie (no tool access, read‑only tam gdzie to możliwe); rotuj przy anomaliach.
- Terminate cały ruch po stronie serwera za policy gateway, który egzekwuje filtry bezpieczeństwa, per‑route quotas i tenant isolation.
- Monitoruj nietypowe wzorce użycia (nagłe skoki wydatków, nietypowe regiony, UA strings) i automatycznie revoke'uj podejrzane sesje.
- Preferuj mTLS lub signed JWTs wydawane przez Twój IdP zamiast długożyjących statycznych API keys.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
