# Blockchain i kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Inteligentne kontrakty** to programy wykonywane na blockchainie po spełnieniu określonych warunków. Automatyzują realizację umów bez pośredników.
- **Zdecentralizowane aplikacje (dApps)** bazują na inteligentnych kontraktach i mają przyjazny dla użytkownika front-end oraz przejrzysty, możliwy do audytu back-end.
- **Tokeny i monety** różnią się tym, że monety służą jako cyfrowy pieniądz, a tokeny reprezentują wartość lub własność w określonym kontekście.
  - **Tokeny użytkowe** zapewniają dostęp do usług, a **tokeny security** oznaczają własność aktywów.
- **DeFi** to skrót od Decentralized Finance (zdecentralizowane finanse) — usługi finansowe bez centralnych organów.
- **DEX** i **DAO** oznaczają odpowiednio zdecentralizowane platformy wymiany i zdecentralizowane autonomiczne organizacje.

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczne i uzgodnione zatwierdzanie transakcji na blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej w celu weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej liczby tokenów, ograniczając zużycie energii w porównaniu z PoW.<sup>[[1]](#references)</sup>

## Podstawowe informacje o Bitcoinie

### Transakcje

Transakcje Bitcoin polegają na przesyłaniu środków między adresami. Są weryfikowane za pomocą podpisów cyfrowych, co gwarantuje, że przelew może zainicjować wyłącznie właściciel klucza prywatnego.<sup>[[2]](#references)</sup>

#### Kluczowe elementy:

- **Transakcje multisig** wymagają wielu podpisów, aby autoryzować transakcję.<sup>[[3]](#references)</sup>
- Transakcje składają się z **wejść** (źródła środków), **wyjść** (miejsca docelowego), **opłat** (płaconych minerom) i **skryptów** (reguł transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoina poprzez umożliwienie realizacji wielu transakcji w ramach kanału i publikowanie na blockchainie wyłącznie jego końcowego stanu.

## Problemy z prywatnością w Bitcoinie

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** zwiększają anonimowość, ukrywając powiązania między transakcjami użytkowników.

## Anonimowe pozyskiwanie Bitcoinów

Metody obejmują transakcje gotówkowe, mining i korzystanie z mixerów. **CoinJoin** łączy wiele transakcji, aby utrudnić ich śledzenie, natomiast **PayJoin** maskuje CoinJoiny jako zwykłe transakcje, zapewniając większą prywatność.

# Podsumowanie ataków na prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników często budzą obawy. Poniżej przedstawiono uproszczony opis kilku popularnych metod, za pomocą których atakujący mogą naruszyć prywatność w Bitcoinie.<sup>[[6]](#references)</sup>

## **Założenie wspólnego właściciela wejść**

Łączenie wejść należących do różnych użytkowników w jednej transakcji jest stosunkowo rzadkie ze względu na złożoność takiego działania. Dlatego często zakłada się, że **dwa adresy wejściowe w tej samej transakcji należą do tego samego właściciela**.

## **Wykrywanie adresu reszty UTXO**

UTXO, czyli **niewydane wyjście transakcji**, musi zostać w całości wydane w ramach transakcji. Jeśli na inny adres zostanie wysłana tylko jego część, pozostała kwota trafia na nowy adres reszty. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza jego prywatność.

### Przykład

Aby temu zapobiec, można skorzystać z usług mieszających lub używać wielu adresów, co utrudnia ustalenie ich właściciela.

## **Ujawnianie informacji w sieciach społecznościowych i na forach**

Użytkownicy czasami udostępniają swoje adresy Bitcoin w internecie, przez co **łatwo powiązać adres z jego właścicielem**.

## **Analiza grafu transakcji**

Transakcje można przedstawić jako grafy, które ujawniają potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Heurystyka niepotrzebnego wejścia (heurystyka optymalnej reszty)**

Ta heurystyka polega na analizowaniu transakcji z wieloma wejściami i wyjściami w celu odgadnięcia, które wyjście stanowi resztę zwracaną nadawcy.

### Przykład

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Jeśli dodanie kolejnych wejść sprawi, że wyjście reszty będzie większe niż którekolwiek z pojedynczych wejść, może to zmylić heurystykę.

## **Wymuszone ponowne użycie adresu**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, łącząc w ten sposób adresy.

### Prawidłowe zachowanie portfela

Portfele powinny unikać używania monet otrzymanych na wcześniej używane, puste adresy, aby zapobiec temu leak prywatności.

## **Inne techniki analizy blockchaina**

- **Dokładne kwoty płatności:** Transakcje bez reszty prawdopodobnie zachodzą między dwoma adresami należącymi do tego samego użytkownika.
- **Okrągłe kwoty:** Okrągła kwota w transakcji sugeruje, że jest to płatność, a nieokrągłe wyjście prawdopodobnie stanowi resztę.
- **Odcisk palca portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować używane oprogramowanie i potencjalnie adres reszty.
- **Korelacje kwot i czasu:** Ujawnienie czasu lub kwot transakcji może umożliwić ich śledzenie.

## **Analiza ruchu sieciowego**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Dotyczy to zwłaszcza sytuacji, gdy podmiot obsługuje wiele węzłów Bitcoin, co zwiększa jego możliwości monitorowania transakcji.

## Więcej

Pełną listę ataków na prywatność i sposobów obrony znajdziesz na stronie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby anonimowego zdobywania bitcoinów

- **Transakcje gotówkowe**: Zdobywanie bitcoinów za gotówkę.
- **Alternatywy dla gotówki**: Kupowanie kart podarunkowych i wymienianie ich online na bitcoiny.
- **Mining**: Najbardziej prywatnym sposobem zarabiania bitcoinów jest mining, zwłaszcza jeśli odbywa się samodzielnie, ponieważ pule miningowe mogą znać adres IP górnika. [Informacje o pulach miningowych](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie kradzież bitcoinów może być innym sposobem na ich anonimowe zdobycie, choć jest nielegalna i niezalecana.

## Usługi miksujące

Korzystając z usługi miksującej, użytkownik może **wysłać bitcoiny** i otrzymać w zamian **inne bitcoiny**, co utrudnia ustalenie pierwotnego właściciela. Wymaga to jednak zaufania, że usługa nie będzie przechowywać logów i faktycznie zwróci bitcoiny. Alternatywą są kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji różnych użytkowników w jedną, utrudniając dopasowanie wejść do wyjść. Mimo swojej skuteczności transakcje z unikalnymi rozmiarami wejść i wyjść nadal mogą być śledzone.

Przykładowe transakcje, w których mogło zostać użyte CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz na stronie [CoinJoin](https://coinjoin.io/en). Informacje o mikserze opartym na smart-kontrakcie Ethereum, który oddziela wpłaty od późniejszych wypłat, znajdziesz na stronie [Tornado Cash](https://tornado.cash).

## PayJoin

Odmiana CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych dla CoinJoin równych kwot wyjściowych. Dzięki temu jest niezwykle trudny do wykrycia i może unieważnić heurystykę wspólnego właściciela wejść, stosowaną przez podmioty monitorujące transakcje.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcje takie jak powyższa mogą być PayJoin, zwiększając prywatność, a jednocześnie pozostając nieodróżnialnymi od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody inwigilacji**, co czyni tę technikę obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki w zakresie prywatności w kryptowalutach

## **Techniki synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, kluczowa jest synchronizacja portfeli z łańcuchem bloków. Wyróżniają się dwie metody:

- **Full node**: Pobierając cały łańcuch bloków, full node zapewnia maksymalną prywatność. Wszystkie kiedykolwiek wykonane transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom ustalenie, którymi transakcjami lub adresami interesuje się użytkownik.
- **Filtrowanie bloków po stronie klienta**: Metoda ta polega na tworzeniu filtrów dla każdego bloku w łańcuchu bloków, dzięki czemu portfele mogą identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry i pobierają pełne bloki tylko wtedy, gdy zostanie znalezione dopasowanie do adresów użytkownika.

## **Wykorzystanie Tor do zachowania anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor w celu ukrycia adresu IP, co zwiększa prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu używaniu adresów**

Aby chronić prywatność, należy używać nowego adresu dla każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, łącząc transakcje z tym samym podmiotem. Współczesne portfele z założenia zniechęcają do ponownego używania adresów.

## **Strategie zapewniania prywatności transakcji**

- **Wiele transakcji**: Podzielenie płatności na kilka transakcji może utrudnić ustalenie jej kwoty, udaremniając ataki na prywatność.
- **Unikanie reszty**: Wybieranie transakcji, które nie wymagają wyjść reszty, zwiększa prywatność, zakłócając metody wykrywania reszty.
- **Wiele wyjść reszty**: Jeśli uniknięcie reszty nie jest możliwe, wygenerowanie wielu wyjść reszty może mimo to poprawić prywatność.

# **Monero: symbol anonimowości**

Monero zaprojektowano tak, aby priorytetowo traktowało prywatność transakcji.

# **Ethereum: gas i transakcje**

## **Zrozumienie gas**

Gas mierzy nakład obliczeniowy potrzebny do wykonania operacji w Ethereum i jest wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) wymaga określenia limitu gas i opłaty bazowej, a także opłaty priorytetowej zachęcającej walidatora do uwzględnienia jej w bloku. Użytkownicy mogą ustawić maksymalną opłatę, aby nie zapłacić zbyt dużo; nadwyżka zostanie zwrócona.<sup>[[5]](#references)</sup>

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart kontraktów. Wymagają opłaty i muszą zostać uwzględnione w bloku. Kluczowe informacje w transakcji to odbiorca, podpis nadawcy, wartość, opcjonalne dane, limit gas i opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, więc nie trzeba go umieszczać w danych transakcji.<sup>[[4]](#references)</sup>

Te praktyki i mechanizmy stanowią podstawę dla każdego, kto chce korzystać z kryptowalut, stawiając na pierwszym miejscu prywatność i bezpieczeństwo.

## Red Teaming Web3 skoncentrowany na wartości

- Sporządź wykaz komponentów przechowujących lub obsługujących wartość (podpisujących, wyroczni, mostów, automatyzacji), aby ustalić, kto może przenosić środki i w jaki sposób.
- Powiąż każdy komponent z odpowiednimi taktykami MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków obejmujące flash loan, wyrocznie, dane uwierzytelniające i transakcje międzyłańcuchowe, aby zweryfikować ich wpływ oraz udokumentować warunki wstępne umożliwiające wykorzystanie podatności.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Przejęcie procesu podpisywania w Web3

- Manipulacja łańcuchem dostaw interfejsów portfeli może modyfikować payloady EIP-712 tuż przed podpisaniem, pozyskując prawidłowe podpisy umożliwiające przejęcie proxy opartego na delegatecall (np. nadpisanie slot-0 Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstrakcja kont (ERC-4337)

- Typowe tryby awarii smart account obejmują obejście kontroli dostępu `EntryPoint`, niepodpisane pola gas, walidację ze zmianą stanu, ponowne odtwarzanie ERC-1271 oraz drenaż opłat przez revert po walidacji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezpieczeństwo smart kontraktów

- Testy mutacyjne pozwalające znaleźć luki w zestawach testów:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integralność dowodów ZK / gościa zkVM

Gdy prover używa **zkVM** lub specyficznego dla aplikacji obwodu dowodowego, aby poświadczyć twierdzenie, weryfikator dowiaduje się jedynie, że **program gościa wykonał się zgodnie z kodem**. Jeśli gość zawiera **niebezpieczną deserializację**, **niezdefiniowane zachowanie** lub **brakujące ograniczenia semantyczne**, złośliwy prover może wygenerować dowód, który przejdzie weryfikację, mimo że **publiczne metryki lub deklarowany niezmiennik są fałszywe**.<sup>[[7]](#references)</sup>

### Niebezpieczna deserializacja wewnątrz gości dowodowych

- Traktuj prywatne witnessy i bajty obwodu jako **niezaufane dane wejściowe kontrolowane przez atakującego**, nawet jeśli są ukryte przez dowód.
- Unikaj ich deserializacji za pomocą niezweryfikowanych helperów, takich jak `rkyv::access_unchecked`, chyba że bajty zostały wcześniej zweryfikowane poza tym procesem.
- Dyskryminanty wariantów enum, wskaźniki względne, długości i indeksy wczytywane z niezaufanych danych serializowanych muszą zostać zweryfikowane, zanim wpłyną na sterowanie przepływem lub dostęp do pamięci.

Praktyczny schemat audytu:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Jeśli pole takie jak `op.kind` jest enumem, a atakujący może wstrzyknąć **wartość discriminant spoza zakresu**, każdy dalszy `match` na tej wartości staje się podejrzany.

### Ominięcie liczników UB przez jump table

Jeśli Rust kompiluje duży `match` do **jump table**, nieprawidłowa wartość discriminant enumu może prowadzić do **niezdefiniowanego przepływu sterowania**. Niebezpieczny wzorzec wygląda następująco:<sup>[[7]](#references)[[9]](#references)</sup>

1. Pierwszy `match` aktualizuje **krytyczne dla bezpieczeństwa liczniki/ograniczenia**.
2. Drugi `match` realizuje **właściwą semantykę instrukcji**.
3. Wartość discriminant spoza zakresu indeksuje poza pierwszą jump table i trafia do kodu powiązanego z drugą.

W rezultacie operacja nadal jest wykonywana, ale ścieżka zliczania zostaje pominięta. W zkVM może to umożliwić sfałszowanie dowodów, które wykazują niemożliwe metryki, takie jak mniejsza liczba bramek, kosztownych operacji lub innych ograniczonych zasobów.

Lista kontrolna:

- Szukaj enumów kontrolowanych przez atakującego, deserializowanych z danych wejściowych świadka/prywatnych.
- Sprawdzaj powtarzające się instrukcje `match` dotyczące tego samego pola opcode/kind.
- Traktuj połączenie `unsafe` + deserializacji bez kontroli + rozbudowanego dispatchu opcode jako kombinację wysokiego ryzyka.
- W razie potrzeby przeprowadź inżynierię wsteczną wygenerowanego pliku binarnego; układ jump table może mieć większe znaczenie niż kod źródłowy.

### Brak ograniczeń semantycznych w odwracalnych/wyspecjalizowanych interpreterach

Nie sprawdzaj wyłącznie bezpieczeństwa pamięci; weryfikuj też **reguły semantyczne**, których dowód ma pilnować.

W przypadku odwracalnych lub przypominających kwantowe zestawów instrukcji upewnij się, że operandy, które muszą być różne, są faktycznie ograniczone tak, by były różne. Operacja typu Toffoli/CCX zaimplementowana jako:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

staje się niebezpieczne, jeśli gość tego nie odrzuci:

```text
op.q_control1 == op.q_control2 == op.q_target
```

W takim przypadku przejście sprowadza się do:

```text
q = q ^ (q & q) = 0
```

Tworzy to **deterministyczny prymityw resetowania**, który łamie założenia o odwracalności i umożliwia tańsze, niezamierzone obliczenia. W systemach dowodów poświadczających użycie zasobów pozwala to atakującym spełniać kontrole funkcjonalne, a jednocześnie omijać model kosztów, który — jak sądzi weryfikator — jest egzekwowany.

### Niedostatecznie ograniczone wskazówki provera i arytmetyka modularna

Wartości wczytane ze **stosu advice/witness są kontrolowane przez prover**, nawet jeśli opisano je jako wstępnie obliczone ilorazy, reszty, odwrotności lub wskazówki. Dowód potwierdza jedynie, że witness spełnia zaimplementowane ograniczenia; nie potwierdza, że wykonano zamierzone obliczenie, jeśli w tych ograniczeniach brakuje kontroli typu, zakresu lub postaci kanonicznej.<sup>[[13]](#references)</sup>

W przypadku funkcji pomocniczej do redukcji lub dzielenia euklidesowego sprawdź pełną relację na liczbach całkowitych, a nie tylko końcowe odejmowanie lub mnożenie. Każde limb `q` i `r` musi być ograniczone do zadeklarowanej szerokości, rekonstrukcja `x = q * m + r` musi być poprawna w zamierzonej reprezentacji liczb całkowitych, a ograniczenie kanoniczne `0 <= r < m` musi być egzekwowane. Sprawdź wartość **przed** przekazaniem jej do instrukcji o węższym typie `u32`/`u64`; operacja na węższym typie nie dowodzi wstecznie, że pierwotny element pola lub wartość wielolimnowa miały oczekiwany typ.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Niepowodzenie `mod_12289` w Miden ilustruje wzorzec exploita: iloraz był sprawdzany jako 64-bitowa wartość składająca się z dwóch limbów, ale reszta dostarczona przez advice trafiała do `u32overflowing_sub` bez równoważnej walidacji. Złośliwy prover mógł skoordynować nieprawidłowe wartości ilorazu i reszty tak, by zaimplementowane ograniczenia odejmowania nadal były spełnione, mimo że procedura zwracała resztę niezgodną z wynikiem matematycznym. Ponieważ ten wynik trafiał do weryfikacji Falcon, błąd soundness można było wykorzystać do sfałszowania podpisów autoryzacyjnych, a nie tylko do uzyskania nieprawidłowego wyniku arytmetycznego.<sup>[[13]](#references)</sup>

### Audyt kryptograficznych maszyn wirtualnych z niejawnym stosem

Języki stosowe ukrywają operandy, dlatego najpierw przekształć instrukcje do IR, w którym każda pobierana i odkładana wartość stosu jest wyrażeniem z informacją o pochodzeniu. Następnie można zastosować konserwatywny pipeline analizy, który:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Buduje graf wywołań i wnioskuje o efektach procedur na stosie wejściowym i wyjściowym.
2. Wykonuje symbolicznie obsługiwane instrukcje i przekształca przepływ sterowania w wyrażenia SSA/strukturalne.
3. Propaguje abstrakcyjne fakty, takie jak `Unknown`, `ProvenU32`, `Bool`, pochodzenie wartości i lokalna inicjalizacja, aż do osiągnięcia punktu stałego.
4. Wykrywa wartości pochodzące z advice, które trafiają do operacji arytmetycznych wymagających określonego typu lub do miejsc wymagających wartości niezerowej, bez walidacji na **każdej** ścieżce wejściowej.
5. Porównuje zadeklarowane i wywnioskowane sygnatury oraz weryfikuje, czy każde wyjście zachowuje wartości stosu należące do wywołującego.

Nieznaną sygnaturę lub nieobsługiwaną konstrukcję traktuj jako **lukę w analizie**, a nie czysty wynik. Wywołania dynamiczne, pętle niezachowujące stosu i gałęzie o różnych efektach na stosie mogą uniemożliwić rzetelne śledzenie pozycji na stosie; bezpieczniejszy dekompilator odrzuca takie przypadki lub oznacza je jako nieobsługiwane, zamiast generować wiarygodnie wyglądający, ale niepoprawny pseudokod.<sup>[[10]](#references)[[13]](#references)</sup>

W punktach połączenia przepływu sterowania zachowuj daną właściwość tylko wtedy, gdy jest prawdziwa dla każdego poprzednika (na przykład `ProvenU32 join Unknown = Unknown`). Rozróżniaj też osiągnięcie zbieżności punktu stałego od przekroczenia limitu iteracji: tylko zbieżne, sound przybliżenie nadmierne może uzasadniać traktowanie braku diagnostyki jako dowodu, że wszystkie reprezentowane wykonania spełniają daną właściwość.<sup>[[11]](#references)</sup>

### Ujawnianie ukrytych warunków wstępnych za pomocą zobowiązań dowodowych

W przypadku małych zestawów instrukcji przekształć procedury w wykonywalny formalny model VM i udowodnij zarówno wynik, jak i pełną transformację stosu. Twierdzenie powinno obejmować zakończenie, typowane dane wejściowe, oczekiwany prefiks wyjściowy oraz zachowanie nietkniętego stosu wywołującego. Treść twierdzenia audytuj równie starannie jak dowód: kernel może zweryfikować dowód przypadkowo osłabionego twierdzenia.<sup>[[12]](#references)[[13]](#references)</sup>

Nieoczekiwane założenia są cennymi ustaleniami. Podczas przeglądu Miden dowód dla 64-bitowego obrotu w prawo wymagał `shift mod 32 != 0`, ujawniając przypadek brzegowy, w którym duże wartości powodowały błąd, gdy przesunięcie było wielokrotnością 32; inny dowód wykazał, że 256-bitowe `wrapping_mul` odrzucało wartości stosu należące do wywołującego. Dodaj odkryty przypadek brzegowy do testów, a następnie napraw implementację lub celowo zaostrz publiczny warunek wstępny, zamiast po cichu akceptować dodatkowe założenie.<sup>[[12]](#references)[[13]](#references)</sup>

### Co testować w systemach ZK

- Fuzzuj wszystkie parsery guest, używając niepoprawnych kodowań witness/private-input.
- Sprawdzaj walidację zakresu enum przed dispatchowaniem opcode.
- Dodawaj kontrole semantyczne dotyczące aliasowania operandów i innych nieprawidłowych form instrukcji.
- Śledź każde źródło advice/witness aż do każdego miejsca użycia arytmetyki typowanej i wymagaj walidacji na każdej ścieżce.<sup>[[11]](#references)[[13]](#references)</sup>
- Testuj pomocnicze funkcje arytmetyczne z niekanonicznymi limbami, resztami spoza zakresu i brzegowymi wartościami przesunięcia.<sup>[[12]](#references)[[13]](#references)</sup>
- Sprawdzaj wysokość stosu i zachowanie wartości poniżej zadeklarowanych argumentów procedury przy każdym powrocie.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Porównuj zgłaszane/publiczne liczniki z niezależną implementacją referencyjną.
- Pamiętaj, że poprawny dowód może dowodzić **niewłaściwego twierdzenia**, jeśli program guest zawiera błędy.

## Autoryzacja zależna od stanu

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploity DeFi/AMM

Jeśli badasz praktyczne exploity DEX-ów i AMM (hooki Uniswap v4, nadużycia zaokrągleń/precyzji, swapy przekraczające progi dzięki flash loanom), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

W przypadku ważonych pul multi-asset, które buforują wirtualne salda i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

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
- [7] [Trail of Bits - Pokonaliśmy zero-knowledge proof Google dotyczący kryptoanalizy kwantowej](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zabezpieczanie kryptowalut opartych na krzywych eliptycznych przed zagrożeniami kwantowymi: szacunki zasobów i środki zaradcze (poprawiona wersja)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repozytorium proof-of-concept Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Architektura dekompilatora MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Silnik analizy statycznej MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Model MASM-to-Lean i dowody poprawności](https://github.com/trailofbits/masm-lean)
- [13] [Audyt w erze (wystarczająco dobrego) AI](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
