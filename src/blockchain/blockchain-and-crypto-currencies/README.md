# Blockchain i kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Inteligentne kontrakty** to programy wykonywane na blockchainie po spełnieniu określonych warunków, które automatyzują realizację umów bez pośredników.
- **Zdecentralizowane aplikacje (dApps)** bazują na inteligentnych kontraktach i mają przyjazny dla użytkownika interfejs oraz przejrzysty, możliwy do audytu back-end.
- **Tokeny i monety** różnią się tym, że monety służą jako pieniądz cyfrowy, a tokeny reprezentują wartość lub własność w określonym kontekście.
  - **Tokeny użytkowe** zapewniają dostęp do usług, a **tokeny zabezpieczające** oznaczają własność aktywów.
- **DeFi** oznacza zdecentralizowane finanse, oferujące usługi finansowe bez centralnych organów.
- **DEX** i **DAO** oznaczają odpowiednio zdecentralizowane platformy wymiany i zdecentralizowane autonomiczne organizacje.

Terminologię dotyczącą zleceń spot, futures, dźwigni i opcji używaną na rynkach krypto znajdziesz w sekcji [Terminy inwestycyjne](investment-terms.md).

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczne i uzgodnione zatwierdzanie transakcji na blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej w celu weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej liczby tokenów, co ogranicza zużycie energii w porównaniu z PoW.<sup>[[1]](#references)</sup>

## Podstawowe informacje o Bitcoinie

### Transakcje

Transakcje Bitcoin polegają na przesyłaniu środków między adresami. Są weryfikowane za pomocą podpisów cyfrowych, dzięki czemu przelewy może zainicjować wyłącznie właściciel klucza prywatnego.<sup>[[2]](#references)</sup>

#### Kluczowe elementy:

- **Transakcje wielopodpisowe** wymagają wielu podpisów, aby autoryzować transakcję.<sup>[[3]](#references)</sup>
- Transakcje składają się z **wejść** (źródło środków), **wyjść** (cel), **opłat** (płaconych górnikom) i **skryptów** (zasady transakcji).

### Lightning Network

Ma zwiększyć skalowalność Bitcoina, umożliwiając realizację wielu transakcji w ramach kanału i publikując na blockchainie tylko jego końcowy stan.

## Obawy dotyczące prywatności w Bitcoinie

Ataki na prywatność, takie jak **założenie wspólnej własności wejść** i **wykrywanie adresu reszty UTXO**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** zwiększają anonimowość, ukrywając powiązania między transakcjami użytkowników.

## Anonimowe pozyskiwanie Bitcoinów

Metody obejmują transakcje gotówkowe, kopanie i korzystanie z mixerów. **CoinJoin** łączy wiele transakcji, utrudniając ich śledzenie, a **PayJoin** maskuje CoinJoin jako zwykłą transakcję, zapewniając większą prywatność.

# Podsumowanie ataków na prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników często budzą obawy. Poniżej przedstawiono uproszczony przegląd kilku typowych metod, za pomocą których atakujący mogą naruszyć prywatność użytkowników Bitcoina.<sup>[[6]](#references)</sup>

## **Założenie wspólnej własności wejść**

Łączenie wejść należących do różnych użytkowników w jednej transakcji jest zazwyczaj rzadkie ze względu na złożoność takiego działania. Dlatego **często zakłada się, że dwa adresy wejściowe w tej samej transakcji należą do tego samego właściciela**.

## **Wykrywanie adresu reszty UTXO**

UTXO, czyli **niewydane wyjście transakcji**, musi zostać w całości wydane w ramach transakcji. Jeśli tylko jego część zostanie wysłana na inny adres, reszta trafia na nowy adres reszty. Obserwatorzy mogą założyć, że nowy adres należy do nadawcy, co narusza jego prywatność.

### Przykład

Aby temu przeciwdziałać, można skorzystać z usług mieszających lub używać wielu adresów, co pomaga ukryć właściciela.

## **Ujawnienie w serwisach społecznościowych i na forach**

Użytkownicy czasami udostępniają swoje adresy Bitcoin w internecie, przez co **łatwo powiązać adres z jego właścicielem**.

## **Analiza grafu transakcji**

Transakcje można przedstawić w postaci grafów, które ujawniają potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Heurystyka niepotrzebnego wejścia (heurystyka optymalnej reszty)**

Ta heurystyka polega na analizie transakcji z wieloma wejściami i wyjściami, aby odgadnąć, które wyjście stanowi resztę zwracaną nadawcy.

### Przykład

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Jeśli dodanie kolejnych wejść sprawi, że wyjście reszty będzie większe niż dowolne pojedyncze wejście, może to zmylić heurystykę.

## **Wymuszanie ponownego użycia adresów**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, łącząc w ten sposób adresy.

### Prawidłowe zachowanie portfela

Portfele powinny unikać używania monet otrzymanych na wcześniej używanych, pustych adresach, aby zapobiec temu wyciekowi prywatności.

## **Inne techniki analizy blockchaina**

- **Dokładne kwoty płatności:** Transakcje bez reszty prawdopodobnie zachodzą między dwoma adresami należącymi do tego samego użytkownika.
- **Okrągłe kwoty:** Okrągła kwota w transakcji sugeruje, że jest to płatność, a wyjście z nieokrągłą kwotą prawdopodobnie stanowi resztę.
- **Fingerprinting portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom rozpoznać używane oprogramowanie i potencjalnie ustalić adres reszty.
- **Korelacje kwot i czasu:** Ujawnienie czasu lub kwot transakcji może umożliwić ich śledzenie.

## **Analiza ruchu sieciowego**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Dotyczy to zwłaszcza podmiotów obsługujących wiele węzłów Bitcoin, co zwiększa ich możliwości monitorowania transakcji.

## Więcej

Pełną listę ataków na prywatność i metod ochrony znajdziesz na stronie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby anonimowego pozyskiwania bitcoinów

- **Transakcje gotówkowe**: Pozyskiwanie bitcoinów za gotówkę.
- **Alternatywy dla gotówki**: Kupowanie kart podarunkowych i wymienianie ich online na bitcoiny.
- **Mining**: Najbardziej prywatnym sposobem zarabiania bitcoinów jest mining, zwłaszcza prowadzony samodzielnie, ponieważ pule miningowe mogą znać adres IP minera. [Informacje o pulach miningowych](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie kradzież bitcoinów mogłaby być innym sposobem ich anonimowego pozyskania, jest jednak nielegalna i niezalecana.

## Usługi mieszające

Korzystając z usługi mieszającej, użytkownik może **wysłać bitcoiny** i otrzymać w zamian **inne bitcoiny**, co utrudnia ustalenie pierwotnego właściciela. Wymaga to jednak zaufania, że usługa nie będzie przechowywać logów i faktycznie zwróci bitcoiny. Alternatywne opcje mieszania obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji różnych użytkowników w jedną, utrudniając dopasowanie wejść do wyjść. Mimo swojej skuteczności transakcje z unikalnymi rozmiarami wejść i wyjść nadal mogą być potencjalnie śledzone.

Przykładowe transakcje, w których mogła zostać użyta funkcja CoinJoin: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz na stronie [CoinJoin](https://coinjoin.io/en). Informacje o mikserze opartym na smart kontrakcie Ethereum, który oddziela wpłaty od późniejszych wypłat, znajdziesz na stronie [Tornado Cash](https://tornado.cash).

## PayJoin

Odmiana CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych dla CoinJoin równych wyjść. Dzięki temu wykrycie jej jest niezwykle trudne, a stosowana przez podmioty nadzorujące transakcje heurystyka wspólnej własności wejść może przestać być skuteczna.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcje takie jak powyższa mogą być PayJoin, zwiększając prywatność i pozostając nieodróżnialnymi od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody nadzoru**, co czyni je obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki zapewniania prywatności w kryptowalutach

## **Metody synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, należy synchronizować portfele z blockchainem. Wyróżniają się dwie metody:

- **Pełny węzeł**: Pobranie całego blockchaina przez pełny węzeł zapewnia maksymalną prywatność. Wszystkie dokonane transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom ustalenie, którymi transakcjami lub adresami interesuje się użytkownik.
- **Filtrowanie bloków po stronie klienta**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, dzięki czemu portfele mogą identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry i pobierają pełne bloki tylko wtedy, gdy zostanie znalezione dopasowanie do adresów użytkownika.

## **Korzystanie z Tor w celu zachowania anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor w celu ukrycia adresu IP i zwiększenia prywatności podczas interakcji z siecią.

## **Zapobieganie ponownemu używaniu adresów**

Aby chronić prywatność, należy używać nowego adresu dla każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, łącząc transakcje z tym samym podmiotem. Współczesne portfele z założenia zniechęcają do ponownego używania adresów.

## **Strategie ochrony prywatności transakcji**

- **Wiele transakcji**: Podzielenie płatności na kilka transakcji może ukryć jej kwotę i udaremnić ataki naruszające prywatność.
- **Unikanie reszty**: Wybieranie transakcji, które nie wymagają wyjść reszty, zwiększa prywatność, zakłócając metody wykrywania reszty.
- **Wiele wyjść reszty**: Jeśli nie da się uniknąć reszty, wygenerowanie wielu wyjść reszty nadal może poprawić prywatność.

# **Monero: wzór anonimowości**

Monero zaprojektowano tak, aby priorytetowo traktowało prywatność transakcji.

# **Ethereum: gas i transakcje**

## **Zrozumienie gas**

Gas mierzy nakład obliczeniowy potrzebny do wykonania operacji w Ethereum i jest wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) obejmuje limit gas i opłatę bazową, a także opłatę priorytetową, która zachęca walidatora do uwzględnienia transakcji. Użytkownicy mogą ustawić maksymalną opłatę, aby nie przepłacić; nadwyżka zostanie zwrócona.<sup>[[5]](#references)</sup>

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart kontraktów. Wymagają opłaty i muszą zostać uwzględnione w bloku. Niezbędne informacje w transakcji to odbiorca, podpis nadawcy, wartość, opcjonalne dane, limit gas i opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, więc nie trzeba go umieszczać w danych transakcji.<sup>[[4]](#references)</sup>

Te praktyki i mechanizmy stanowią podstawę dla każdego, kto chce korzystać z kryptowalut, stawiając na pierwszym miejscu prywatność i bezpieczeństwo.

## Red Teaming Web3 skoncentrowany na wartości

- Sporządź wykaz komponentów przechowujących wartość (podpisujących, wyroczni, mostów, automatyzacji), aby ustalić, kto może przemieszczać środki i w jaki sposób.
- Powiąż każdy komponent z odpowiednimi taktykami MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków z użyciem flash loanów, wyroczni, poświadczeń i ataków cross-chain, aby zweryfikować ich skutki oraz udokumentować warunki wstępne umożliwiające wykorzystanie podatności.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitacja przepływu podpisywania Web3

- Modyfikacja łańcucha dostaw interfejsów portfeli może zmieniać ładunki EIP-712 tuż przed podpisaniem, umożliwiając przechwycenie prawidłowych podpisów w celu przejęcia proxy opartego na `delegatecall` (np. przez nadpisanie slotu 0 w Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstrakcja konta (ERC-4337)

- Do typowych trybów awarii smart kont należą obejście kontroli dostępu `EntryPoint`, niepodpisane pola gas, walidacja zmieniająca stan, replay ERC-1271 oraz drenaż opłat przez revert po walidacji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezpieczeństwo smart kontraktów

- Testowanie mutacyjne w celu wykrywania martwych punktów w zestawach testów:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integralność gościa ZK proof / zkVM

Gdy prover używa **zkVM** lub obwodu dowodowego dostosowanego do aplikacji, aby poświadczyć twierdzenie, weryfikator dowiaduje się jedynie, że **program gościa wykonał się zgodnie z zapisanym kodem**. Jeśli gość zawiera **niebezpieczną deserializację**, **niezdefiniowane zachowanie** lub **brakujące ograniczenia semantyczne**, złośliwy prover może wygenerować dowód, który przejdzie weryfikację, mimo że **publiczne metryki lub deklarowany niezmiennik są fałszywe**.<sup>[[7]](#references)</sup>

### Niebezpieczna deserializacja wewnątrz gości proof

- Traktuj prywatne dane świadka/obwodu jako **niezaufane dane wejściowe kontrolowane przez atakującego**, nawet jeśli są ukryte przez proof.
- Unikaj ich deserializacji za pomocą niezweryfikowanych funkcji pomocniczych, takich jak `rkyv::access_unchecked`, chyba że bajty zostały wcześniej zweryfikowane poza tym procesem.
- Dyskryminanty enumów, wskaźniki względne, długości i indeksy wczytywane z niezaufanych danych serializowanych muszą zostać zweryfikowane, zanim wpłyną na przepływ sterowania lub dostęp do pamięci.

Praktyczny wzorzec audytu:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Jeśli pole takie jak `op.kind` jest enumem, a atakujący może wstrzyknąć **wartość dyskryminanta spoza zakresu**, każde dalsze `match` na tej wartości staje się podejrzane.

### Ominięcie kontroli liczników przez jump table / UB

Jeśli Rust kompiluje duże `match` do **jump table**, nieprawidłowa wartość dyskryminanta enumu może prowadzić do **niezdefiniowanego przepływu sterowania**. Niebezpieczny wzorzec:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedno `match` aktualizuje **krytyczne dla bezpieczeństwa liczniki/ograniczenia**.
2. Drugie `match` realizuje **właściwą semantykę instrukcji**.
3. Wartość dyskryminanta spoza zakresu indeksuje pamięć za pierwszą jump table i trafia do kodu powiązanego z drugą.

W rezultacie operacja nadal się wykonuje, ale ścieżka księgowania zostaje pominięta. W zkVM może to umożliwić sfałszowanie dowodów, które wykazują niemożliwe metryki, takie jak mniejsza liczba gates, mniej kosztownych operacji lub inne fałszywe wartości ograniczonych zasobów.

Lista kontrolna:

- Szukaj enumów kontrolowanych przez atakującego, deserializowanych z danych wejściowych witness/prywatnych.
- Sprawdź powtarzające się instrukcje `match` dotyczące tego samego pola opcode/kind.
- Traktuj połączenie `unsafe` + deserializacji bez sprawdzania + dużego dispatchu opcode jako kombinację wysokiego ryzyka.
- W razie potrzeby wykonaj inżynierię wsteczną skompilowanego pliku binarnego; układ jump table może mieć większe znaczenie niż kod źródłowy.

### Brak ograniczeń semantycznych w odwracalnych/wyspecjalizowanych interpreterach

Nie sprawdzaj wyłącznie bezpieczeństwa pamięci; weryfikuj też **reguły semantyczne**, których dowód ma wymuszać.

W przypadku odwracalnych/zbliżonych do kwantowych zestawów instrukcji upewnij się, że operandy, które muszą być różne, są rzeczywiście ograniczone do różnych wartości. Operacja podobna do Toffoliego/CCX zaimplementowana jako:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

staje się niebezpieczne, jeśli gość nie odrzuci:

```text
op.q_control1 == op.q_control2 == op.q_target
```

W takim przypadku przejście sprowadza się do:

```text
q = q ^ (q & q) = 0
```

Tworzy to **deterministyczny prymityw resetowania**, który łamie założenia o odwracalności i umożliwia tańsze obliczenia niezgodne z przeznaczeniem. W systemach dowodów poświadczających użycie zasobów może to pozwolić atakującym spełnić kontrole funkcjonalne, a jednocześnie ominąć model kosztów, którego egzekwowanie zakłada weryfikator.

### Niedostatecznie ograniczone dane pomocnicze proverów i arytmetyka modularna

Wartości wczytywane ze stosu advice/witness są kontrolowane przez proverów, nawet jeśli opisuje się je jako wstępnie obliczone ilorazy, reszty, odwrotności lub wskazówki. Dowód potwierdza jedynie, że witness spełnia zaimplementowane ograniczenia; nie potwierdza, że wykonano zamierzone obliczenie, jeśli w tych ograniczeniach brakuje kontroli typu, zakresu lub postaci kanonicznej.<sup>[[13]](#references)</sup>

W przypadku funkcji pomocniczej do redukcji lub dzielenia euklidesowego sprawdź pełną relację całkowitoliczbową, a nie tylko końcowe odejmowanie lub mnożenie. Każda część `q` i `r` musi być ograniczona do zadeklarowanej szerokości, rekonstrukcja `x = q * m + r` musi być poprawna w zamierzonej reprezentacji liczb całkowitych, a kanoniczne ograniczenie `0 <= r < m` musi być egzekwowane. Zweryfikuj wartość **przed** przekazaniem jej do instrukcji o węższym typie `u32`/`u64`; operacja na węższym typie nie dowodzi wstecznie, że pierwotny element pola lub wartość wieloczęściowa miały oczekiwany typ.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Niepowodzenie `mod_12289` w Miden ilustruje schemat exploita: iloraz był sprawdzany jako 64-bitowa wartość złożona z dwóch limbów, ale reszta dostarczona przez advice trafiała do `u32overflowing_sub` bez równoważnej walidacji. Złośliwy prover mógł skoordynować nieprawidłowe wartości ilorazu i reszty, tak aby zaimplementowane ograniczenia odejmowania nadal były spełnione, a procedura zwracała niezgodną z matematyką resztę. Ponieważ ten wynik był używany przy weryfikacji Falcon, błąd soundness można było wykorzystać do fałszowania podpisów autoryzacyjnych, zamiast jedynie uzyskać błędny wynik arytmetyczny.<sup>[[13]](#references)</sup>

### Audytowanie kryptograficznych maszyn wirtualnych z niejawnym stosem

Języki stosowe ukrywają operandy, dlatego najpierw należy przekształcić instrukcje do IR, w którym każda pobierana i odkładana wartość stosu jest wyrażeniem z informacją o pochodzeniu. Następnie można przeprowadzić konserwatywną analizę:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Zbudować graf wywołań i wywnioskować wpływ procedur na stos wejściowy i wyjściowy.
2. Wykonać symbolicznie obsługiwane instrukcje i przekształcić przepływ sterowania do postaci SSA/ustrukturyzowanych wyrażeń.
3. Propagować fakty abstrakcyjne, takie jak `Unknown`, `ProvenU32`, `Bool`, pochodzenie wartości i inicjalizacja lokalnych, aż do osiągnięcia punktu stałego.
4. Wykrywać wartości pochodzące z advice, które docierają do typowanych operacji arytmetycznych lub miejsc wymagających wartości niezerowej bez sanitizera na **każdej** ścieżce wejściowej.
5. Porównywać zadeklarowane i wywnioskowane sygnatury oraz weryfikować, czy każde wyjście zachowuje wartości stosu należące do wywołującego.

Nieznaną sygnaturę lub nieobsługiwaną konstrukcję traktuj jako **lukę w analizie**, a nie jako wynik potwierdzający bezpieczeństwo. Wywołania dynamiczne, pętle, które nie zachowują stosu, oraz rozgałęzienia o różnym wpływie na stos mogą uniemożliwić wiarygodne śledzenie jego pozycji. Bezpieczniejszy dekompilator odrzuca takie przypadki lub je oznacza, zamiast generować prawdopodobnie wyglądający, lecz niepoprawny pseudokod.<sup>[[10]](#references)[[13]](#references)</sup>

W miejscach łączenia przepływu sterowania zachowuj daną właściwość tylko wtedy, gdy obowiązuje ona dla każdego poprzednika (na przykład `ProvenU32 join Unknown = Unknown`). Odróżniaj też osiągnięcie punktu stałego od przekroczenia limitu iteracji: tylko zbieżne, sound nadprzybliżenie może uzasadniać uznanie braku diagnostyki za dowód, że wszystkie reprezentowane wykonania spełniają daną własność.<sup>[[11]](#references)</sup>

### Używaj warunków dowodu, aby ujawniać ukryte preconditions

W przypadku małych zestawów instrukcji przekształć procedury w wykonywalny formalny model VM i dowiedź zarówno wyniku, jak i pełnej transformacji stosu. Twierdzenie powinno obejmować zakończenie działania, typowane dane wejściowe, oczekiwany prefiks wyjściowy oraz zachowanie nietkniętej części stosu wywołującego. Twierdzenie należy audytować równie starannie jak dowód: kernel może zweryfikować dowód dotyczący przypadkowo osłabionego twierdzenia.<sup>[[12]](#references)[[13]](#references)</sup>

Nieoczekiwane hipotezy są cennymi ustaleniami. Podczas przeglądu Miden dowód dla 64-bitowej rotacji w prawo wymagał `shift mod 32 != 0`, co ujawniło nieobsługiwany przypadek brzegowy dla dużych wartości, gdy przesunięcie było wielokrotnością 32. Inny dowód wykazał, że 256-bitowe `wrapping_mul` odrzucało wartości stosu należące do wywołującego. Dodaj wykryty przypadek brzegowy do testów, a następnie popraw implementację lub celowo zaostrz publiczne precondition, zamiast po cichu akceptować dodatkowe założenie.<sup>[[12]](#references)[[13]](#references)</sup>

### Co testować w systemach ZK

- Fuzzuj wszystkie parsery guest, podając nieprawidłowe kodowania witness/prywatnych danych wejściowych.
- Sprawdzaj walidację zakresu enum przed dispatchowaniem opcode.
- Dodawaj kontrole semantyczne dotyczące aliasowania operandów i innych nieprawidłowych postaci instrukcji.
- Śledź każde źródło advice/witness aż do typowanych miejsc użycia arytmetycznego i wymagaj walidacji na każdej ścieżce.<sup>[[11]](#references)[[13]](#references)</sup>
- Testuj pomocnicze funkcje arytmetyczne z niekanonicznymi limbami, resztami spoza zakresu i granicznymi wartościami przesunięcia.<sup>[[12]](#references)[[13]](#references)</sup>
- Sprawdzaj wysokość stosu i zachowanie wartości poniżej zadeklarowanych argumentów procedury przy każdym powrocie.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Porównuj raportowane/publiczne liczniki z niezależną implementacją referencyjną.
- Pamiętaj, że poprawny dowód może nadal dowodzić **błędnego twierdzenia**, jeśli program guest zawiera błąd.

## Autoryzacja zależna od stanu

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploity DeFi/AMM

Jeśli badasz praktyczne exploity DEX-ów i AMM-ów (hooki Uniswap v4, nadużycia zaokrągleń/precyzji, swapy przekraczające próg, których efekt wzmacnia flash loan), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

W przypadku wieloaktywowych pul ważonych, które buforują wirtualne salda i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Wyjaśnienie klucza publicznego i prywatnego - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Czym są transakcje z wieloma podpisami? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transakcje | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas i opłaty | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Prywatność - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Pokonaliśmy quantum cryptanalysis w proof of zero-knowledge Google’a](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zabezpieczanie kryptowalut opartych na krzywych eliptycznych przed zagrożeniami kwantowymi: szacunki zasobów i środki zaradcze (załatana wersja)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repozytorium proof-of-concept Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Architektura dekompilatora MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Silnik analizy statycznej MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Model MASM-to-Lean i dowody poprawności](https://github.com/trailofbits/masm-lean)
- [13] [Audytowanie w erze (wystarczająco dobrej) AI](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
