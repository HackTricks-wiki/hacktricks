# Blockchain i kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

Ten rozdział omawia koncepcje blockchaina i bezpieczeństwo on-chain. W przypadku wystawionego na dostęp peera Bitcoin zacznij od [enumeracji usługi Bitcoin P2P](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); w przypadku frontendu przeglądarkowego, połączenia z portfelem lub backendu off-chain skorzystaj z [pentestów DApp](../../pentesting-web/dapps-DecentralizedApplications.md). Informacje o operacjach zapewniających prywatność w kryptowalutach i ich ograniczeniach znajdziesz w [rozdziale o prywatności kryptowalut](../../privacy/cryptocurrency-privacy.md).

## Podstawowe pojęcia

- **Smart Contracts** to programy wykonywane na blockchainie po spełnieniu określonych warunków. Automatyzują realizację umów bez pośredników.
- **Decentralized Applications (dApps)** bazują na smart contracts i mają przyjazny dla użytkownika frontend oraz przejrzysty, podlegający audytowi backend.
- **Tokeny i monety** różnią się tym, że monety pełnią funkcję cyfrowego pieniądza, a tokeny reprezentują wartość lub własność w określonych kontekstach.
  - **Tokeny użytkowe** zapewniają dostęp do usług, a **tokeny papierów wartościowych** oznaczają własność aktywów.
- **DeFi** to skrót od Decentralized Finance — usług finansowych bez centralnych organów.
- **DEX** i **DAO** oznaczają odpowiednio zdecentralizowane giełdy oraz zdecentralizowane organizacje autonomiczne.

Terminy dotyczące zleceń spot, futures, dźwigni finansowej i opcji używane na rynkach kryptowalut opisano w [terminologii inwestycyjnej](investment-terms.md).

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczne i uzgodnione zatwierdzanie transakcji w blockchainie:

- **Proof of Work (PoW)** wykorzystuje moc obliczeniową do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej liczby tokenów, ograniczając zużycie energii w porównaniu z PoW.<sup>[[1]](#references)</sup>

## Podstawy Bitcoin

### Transakcje

Transakcje Bitcoin polegają na przesyłaniu środków między adresami. Są weryfikowane za pomocą podpisów cyfrowych, co gwarantuje, że transfer może zainicjować wyłącznie właściciel klucza prywatnego.<sup>[[2]](#references)</sup>

#### Kluczowe elementy:

- **Transakcje multisignature** wymagają wielu podpisów, aby autoryzować transakcję.<sup>[[3]](#references)</sup>
- Transakcje składają się z **wejść** (źródło środków), **wyjść** (cel), **opłat** (płaconych minerom) i **skryptów** (reguły transakcji).

### Lightning Network

Ma zwiększyć skalowalność Bitcoin, umożliwiając wykonywanie wielu transakcji w ramach kanału i publikując w blockchainie tylko stan końcowy.

## Problemy z prywatnością w Bitcoin

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** zwiększają anonimowość, ukrywając powiązania między transakcjami użytkowników.

## Anonimowe pozyskiwanie bitcoinów

Metody obejmują handel za gotówkę, mining i korzystanie z mixerów. **CoinJoin** łączy wiele transakcji, utrudniając ich śledzenie, a **PayJoin** ukrywa CoinJoiny jako zwykłe transakcje, zapewniając większą prywatność.

# Podsumowanie ataków na prywatność Bitcoin

W świecie Bitcoin prywatność transakcji i anonimowość użytkowników często budzą obawy. Poniżej przedstawiono uproszczony przegląd kilku typowych metod, za pomocą których atakujący mogą naruszyć prywatność Bitcoin.<sup>[[6]](#references)</sup>

## **Założenie o wspólnym właścicielu wejść**

Łączenie wejść należących do różnych użytkowników w jednej transakcji jest stosunkowo rzadkie ze względu na związane z tym komplikacje. Dlatego często **zakłada się, że dwa adresy wejściowe w tej samej transakcji należą do jednego właściciela**.

## **Wykrywanie adresu reszty UTXO**

UTXO, czyli **niewydane wyjście transakcji**, musi zostać wydane w całości w ramach transakcji. Jeśli na inny adres zostanie wysłana tylko część środków, pozostała kwota trafia na nowy adres reszty. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza jego prywatność.

### Przykład

Aby temu zapobiec, można korzystać z usług mieszających lub używać wielu adresów, co utrudnia ustalenie ich właściciela.

## **Ujawnienie w mediach społecznościowych i na forach**

Użytkownicy czasami udostępniają swoje adresy Bitcoin w internecie, co **ułatwia powiązanie adresu z jego właścicielem**.

## **Analiza grafu transakcji**

Transakcje można przedstawić jako grafy, które ujawniają potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Heurystyka zbędnego wejścia (heurystyka optymalnej reszty)**

Ta heurystyka polega na analizie transakcji z wieloma wejściami i wyjściami w celu odgadnięcia, które wyjście stanowi resztę zwracaną nadawcy.

### Przykład

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Jeśli dodanie kolejnych wejść sprawi, że wyjście reszty będzie większe niż którekolwiek pojedyncze wejście, może to zmylić heurystykę.

## **Wymuszone ponowne użycie adresu**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, łącząc w ten sposób adresy.

### Prawidłowe zachowanie portfela

Portfele powinny unikać używania monet otrzymanych na wcześniej używanych, pustych adresach, aby zapobiec temu wyciekowi prywatności.

## **Inne techniki analizy blockchaina**

- **Dokładne kwoty płatności:** Transakcje bez reszty prawdopodobnie odbywają się między dwoma adresami należącymi do tego samego użytkownika.
- **Okrągłe kwoty:** Okrągła kwota w transakcji sugeruje, że jest to płatność, a wyjście z nieokrągłą kwotą prawdopodobnie stanowi resztę.
- **Fingerprinting portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom rozpoznać używane oprogramowanie i potencjalnie ustalić adres reszty.
- **Korelacje kwot i czasu:** Ujawnienie czasu lub kwot transakcji może umożliwić ich śledzenie.

## **Analiza ruchu sieciowego**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Dotyczy to szczególnie podmiotów obsługujących wiele węzłów Bitcoin, co zwiększa ich możliwości monitorowania transakcji.

## Więcej

Pełną listę ataków na prywatność i metod obrony znajdziesz na stronie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby anonimowego zdobywania bitcoinów

- **Transakcje gotówkowe**: Zdobywanie bitcoinów za gotówkę.
- **Alternatywy dla gotówki**: Kupowanie kart podarunkowych i wymienianie ich online na bitcoiny.
- **Mining**: Najbardziej prywatnym sposobem zdobywania bitcoinów jest mining, szczególnie prowadzony samodzielnie, ponieważ pule miningowe mogą znać adres IP minera. [Informacje o pulach miningowych](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie kradzież bitcoinów mogłaby być innym sposobem ich anonimowego zdobycia, jednak jest nielegalna i niezalecana.

## Usługi mixingowe

Korzystając z usługi mixingowej, użytkownik może **wysłać bitcoiny** i otrzymać w zamian **inne bitcoiny**, co utrudnia ustalenie pierwotnego właściciela. Wymaga to jednak zaufania, że usługa nie będzie przechowywać logów i faktycznie zwróci bitcoiny. Alternatywne opcje mixingu obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji różnych użytkowników w jedną, utrudniając dopasowanie wejść do wyjść. Mimo skuteczności tej metody transakcje z unikalnymi kwotami wejść i wyjść nadal mogą być możliwe do wyśledzenia.

Przykłady transakcji, w których mogło zostać użyte CoinJoin: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz na stronie [CoinJoin](https://coinjoin.io/en). Informacje o mixerze opartym na smart kontrakcie Ethereum, który oddziela wpłaty od późniejszych wypłat, znajdziesz na stronie [Tornado Cash](https://tornado.cash).

## PayJoin

Odmiana CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych dla CoinJoin równych wyjść. Dzięki temu jest niezwykle trudna do wykrycia i może podważyć heurystykę wspólnego właściciela wejść stosowaną przez podmioty monitorujące transakcje.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcje takie jak powyższa mogą być transakcjami PayJoin, zwiększającymi prywatność i jednocześnie nieodróżnialnymi od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody nadzoru**, co czyni je obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki ochrony prywatności w kryptowalutach

## **Techniki synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, kluczowa jest synchronizacja portfeli z blockchainem. Wyróżniają się dwie metody:

- **Pełny węzeł**: Pobierając cały blockchain, pełny węzeł zapewnia maksymalną prywatność. Wszystkie kiedykolwiek wykonane transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom ustalenie, którymi transakcjami lub adresami interesuje się użytkownik.
- **Filtrowanie bloków po stronie klienta**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, dzięki czemu portfele mogą identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry, a pełne bloki pobierają tylko wtedy, gdy znajdą dopasowanie do adresów użytkownika.

## **Wykorzystanie Tor w celu zachowania anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor w celu ukrycia adresu IP i zwiększenia prywatności podczas interakcji z siecią.

## **Unikanie ponownego używania adresów**

Aby chronić prywatność, należy używać nowego adresu dla każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, łącząc transakcje z tym samym podmiotem. Współczesne portfele z założenia zniechęcają do ponownego używania adresów.

## **Strategie ochrony prywatności transakcji**

- **Wiele transakcji**: Podzielenie płatności na kilka transakcji może utrudnić ustalenie jej kwoty i udaremnić ataki na prywatność.
- **Unikanie reszty**: Wybieranie transakcji, które nie wymagają wyjść reszty, zwiększa prywatność, utrudniając stosowanie metod wykrywania reszty.
- **Wiele wyjść reszty**: Jeśli uniknięcie reszty nie jest możliwe, utworzenie wielu wyjść reszty może nadal zwiększyć prywatność.

# **Monero: latarnia anonimowości**

Monero zaprojektowano tak, aby priorytetowo traktowało prywatność transakcji.

# **Ethereum: gas i transakcje**

## **Zrozumienie gas**

Gas mierzy nakład obliczeniowy potrzebny do wykonania operacji w Ethereum, a jego cena jest wyrażana w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) uwzględnia limit gas i opłatę bazową, a także opłatę priorytetową zachęcającą walidatora do uwzględnienia transakcji. Użytkownicy mogą ustawić maksymalną opłatę, aby nie przepłacić; nadwyżka zostanie zwrócona.<sup>[[5]](#references)</sup>

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart contractów. Wymagają opłaty i muszą zostać uwzględnione w bloku. Istotne informacje w transakcji to odbiorca, podpis nadawcy, wartość, opcjonalne dane, limit gas i opłaty. Warto zauważyć, że adres nadawcy jest wywnioskowywany z podpisu, więc nie trzeba umieszczać go w danych transakcji.<sup>[[4]](#references)</sup>

Te praktyki i mechanizmy są podstawą dla każdego, kto chce korzystać z kryptowalut, stawiając na pierwszym miejscu prywatność i bezpieczeństwo.

## Red Teaming Web3 zorientowany na wartość

- Sporządź wykaz komponentów przechowujących wartość (signers, oracles, bridges, automatyzacja), aby ustalić, kto może przenosić środki i w jaki sposób.
- Przypisz każdy komponent do odpowiednich taktyk MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków z wykorzystaniem flash loanów, oracles, poświadczeń i ataków cross-chain, aby zweryfikować wpływ i udokumentować możliwe do wykorzystania warunki wstępne.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Naruszenie procesu podpisywania w Web3

- Manipulacja łańcuchem dostaw interfejsów portfeli może zmieniać payloady EIP-712 tuż przed podpisaniem, umożliwiając pozyskiwanie prawidłowych podpisów do przejęć proxy opartych na delegatecall (np. nadpisania slot-0 pola masterCopy w Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstrakcja kont (ERC-4337)

- Typowe tryby awarii smart accountów obejmują obejście kontroli dostępu `EntryPoint`, niepodpisane pola gas, walidację zależną od stanu, ponowne użycie ERC-1271 oraz drenowanie opłat przez revert po walidacji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezpieczeństwo smart contractów

- Testowanie mutacyjne w celu wykrycia martwych punktów w zestawach testów:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integralność guestów ZK Proof / zkVM

Gdy prover używa **zkVM** lub specyficznego dla aplikacji obwodu dowodowego do potwierdzenia twierdzenia, verifier dowiaduje się jedynie, że **guest program został wykonany zgodnie z zapisem**. Jeśli guest zawiera **niebezpieczną deserializację**, **niezdefiniowane zachowanie** lub **brak ograniczeń semantycznych**, złośliwy prover może wygenerować dowód, który przejdzie weryfikację, mimo że **publiczne metryki lub deklarowany niezmiennik są nieprawdziwe**.<sup>[[7]](#references)</sup>

### Niebezpieczna deserializacja wewnątrz guestów dowodowych

- Traktuj prywatny witness/dane obwodu jako **niezaufane dane wejściowe kontrolowane przez atakującego**, nawet jeśli są ukryte przez dowód.
- Unikaj ich deserializacji za pomocą niesprawdzonych helperów, takich jak `rkyv::access_unchecked`, chyba że dane zostały już zweryfikowane poza tym procesem.
- Dyskryminanty enumów, wskaźniki względne, długości i indeksy wczytywane z niezaufanych danych serializowanych muszą zostać zweryfikowane, zanim wpłyną na przepływ sterowania lub dostęp do pamięci.

Praktyczny wzorzec audytu:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Jeśli pole takie jak `op.kind` jest enumem i atakujący może wstrzyknąć **dyskryminant spoza zakresu**, każdy dalszy `match` na tej wartości staje się podejrzany.

### Ominięcie kontroli przez jump table / UB

Jeśli Rust kompiluje duży `match` do **jump table**, nieprawidłowy dyskryminant enumu może prowadzić do **niezdefiniowanego przepływu sterowania**. Niebezpieczny wzorzec:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jeden `match` aktualizuje **liczniki/ograniczenia krytyczne dla bezpieczeństwa**.
2. Drugi `match` realizuje **właściwą semantykę instrukcji**.
3. Dyskryminant spoza zakresu indeksuje poza pierwszą jump table i trafia do kodu powiązanego z drugą.

Wynik: operacja nadal zostaje wykonana, ale ścieżka rozliczania zostaje pominięta. W zkVM może to umożliwić sfałszowanie dowodów, które wykazują niemożliwe metryki, takie jak mniejsza liczba bramek, mniej kosztownych operacji lub inne sfałszowane zasoby podlegające limitom.

Lista kontrolna:

- Wyszukaj enumy kontrolowane przez atakującego, deserializowane z witness/prywatnych danych wejściowych.
- Sprawdź powtarzające się instrukcje `match` operujące na tym samym polu opcode/kind.
- Traktuj połączenie `unsafe` + deserializacji bez kontroli + rozbudowanej obsługi opcode jako połączenie wysokiego ryzyka.
- W razie potrzeby przeprowadź inżynierię wsteczną wygenerowanego pliku binarnego; układ jump table może mieć większe znaczenie niż kod źródłowy.

### Brak ograniczeń semantycznych w odwracalnych/wyspecjalizowanych interpreterach

Nie sprawdzaj wyłącznie bezpieczeństwa pamięci; sprawdzaj także **reguły semantyczne**, których dowód ma wymuszać.

W przypadku odwracalnych/zbliżonych do kwantowych zestawów instrukcji upewnij się, że operandy, które muszą być różne, są rzeczywiście ograniczone tak, by były różne. Operacja podobna do Toffoli/CCX zaimplementowana jako:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

staje się niebezpieczne, jeśli system gościa nie odrzuca:

```text
op.q_control1 == op.q_control2 == op.q_target
```

W takim przypadku przejście sprowadza się do:

```text
q = q ^ (q & q) = 0
```

Tworzy to **deterministyczną prymitywę resetowania**, łamiąc założenia o odwracalności i umożliwiając tańsze obliczenia niezgodne z przeznaczeniem. W systemach dowodów poświadczających użycie zasobów może to pozwolić atakującym spełnić kontrole funkcjonalne, jednocześnie omijając model kosztów, który — jak sądzi weryfikator — jest egzekwowany.

### Niedostatecznie ograniczone wskazówki prover’a i arytmetyka modularna

Wartości wczytane ze **stosu advice/witness są kontrolowane przez prover’a**, nawet jeśli opisano je jako wcześniej obliczone ilorazy, reszty, odwrotności lub wskazówki. Dowód potwierdza jedynie, że witness spełnia zaimplementowane ograniczenia; nie potwierdza, że wykonano zamierzone obliczenie, jeśli w tych ograniczeniach brakuje kontroli typu, zakresu lub postaci kanonicznej.<sup>[[13]](#references)</sup>

W przypadku funkcji pomocniczej do redukcji lub dzielenia euklidesowego sprawdź pełną relację między liczbami całkowitymi, a nie tylko końcowe odejmowanie lub mnożenie. Każda część `q` i `r` musi być ograniczona do zadeklarowanej szerokości, równość `x = q * m + r` musi zachodzić w zamierzonej reprezentacji liczb całkowitych, a kanoniczne ograniczenie `0 <= r < m` musi być egzekwowane. Zweryfikuj wartość **przed** przekazaniem jej do instrukcji o węższym typie `u32`/`u64`; operacja na węższym typie nie dowodzi wstecznie, że pierwotny element pola lub wartość wieloczęściowa miały oczekiwany typ.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Awaria `mod_12289` w Miden ilustruje schemat exploita: iloraz był sprawdzany jako 64-bitowa wartość złożona z dwóch limbów, ale reszta dostarczona przez advice trafiała do `u32overflowing_sub` bez równoważnej walidacji. Złośliwy prover mógł skoordynować nieprawidłowe wartości ilorazu i reszty tak, by zaimplementowane ograniczenia odejmowania nadal były spełnione, a procedura zwracała nieresztę matematyczną. Ponieważ ten wynik był wykorzystywany przy weryfikacji Falcon, błąd soundness można było eskalować do fałszywych podpisów autoryzacyjnych, zamiast ograniczać się do błędnego wyniku arytmetycznego.<sup>[[13]](#references)</sup>

### Audytowanie kryptograficznych maszyn wirtualnych z niejawnym stosem

Języki stosowe ukrywają operandy, dlatego najpierw przekształć instrukcje do IR, w którym każda pobrana i wytworzona wartość stosu jest wyrażeniem z informacją o pochodzeniu. Zachowawczy potok analizy może następnie:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Zbudować graf wywołań i wywnioskować efekty procedur na stosie wejściowym/wyjściowym.
2. Wykonać symbolicznie obsługiwane instrukcje i przekształcić przepływ sterowania w wyrażenia SSA/strukturalne.
3. Propagować abstrakcyjne fakty, takie jak `Unknown`, `ProvenU32`, `Bool`, pochodzenie wartości i lokalna inicjalizacja, aż do osiągnięcia punktu stałego.
4. Wykrywać wartości pochodzące z advice, które trafiają do arytmetyki typowanej lub miejsc wymagających wartości niezerowej bez sanitizatora na **każdej** ścieżce wejściowej.
5. Porównywać zadeklarowane i wywnioskowane sygnatury oraz weryfikować, czy każde wyjście zachowuje wartości stosu należące do wywołującego.

Nieznaną sygnaturę lub nieobsługiwaną konstrukcję traktuj jako **lukę w analizie**, a nie czysty wynik. Wywołania dynamiczne, pętle niezachowujące stosu i rozgałęzienia o różnym wpływie na stos mogą uniemożliwić rzetelne śledzenie pozycji na stosie; bezpieczniejszy dekompilator odrzuca takie przypadki lub je oznacza, zamiast generować wiarygodny, lecz niepoprawny pseudokod.<sup>[[10]](#references)[[13]](#references)</sup>

W miejscach łączenia przepływu sterowania zachowuj właściwość tylko wtedy, gdy jest spełniona dla każdego poprzednika (na przykład `ProvenU32 join Unknown = Unknown`). Rozróżniaj też osiągnięcie zbieżności punktu stałego od przekroczenia limitu iteracji: tylko zbieżne, rzetelne nadprzybliżenie może uzasadniać uznanie braku diagnostyki za dowód, że wszystkie reprezentowane wykonania spełniają daną właściwość.<sup>[[11]](#references)</sup>

### Ujawnianie ukrytych warunków wstępnych za pomocą obowiązków dowodowych

W przypadku małych zestawów instrukcji przekształć procedury w wykonywalny formalny model VM i udowodnij zarówno wynik, jak i pełną transformację stosu. Twierdzenie powinno obejmować zakończenie działania, typowane dane wejściowe, oczekiwany prefiks wyjściowy oraz zachowanie nietkniętego stosu wywołującego. Treść twierdzenia audytuj równie starannie jak dowód: kernel może zweryfikować dowód przypadkowo osłabionego twierdzenia.<sup>[[12]](#references)[[13]](#references)</sup>

Nieoczekiwane założenia to przydatne ustalenia. Podczas przeglądu Miden dowód 64-bitowej rotacji w prawo wymagał `shift mod 32 != 0`, co ujawniło przypadek brzegowy powodujący błąd dla dużych danych wejściowych, gdy przesunięcie było wielokrotnością 32; inny dowód wykazał, że 256-bitowe `wrapping_mul` odrzucało wartości stosu należące do wywołującego. Dodaj wykryty przypadek brzegowy do testów, a następnie popraw implementację albo celowo zaostrz publiczny warunek wstępny, zamiast po cichu akceptować dodatkowe założenie.<sup>[[12]](#references)[[13]](#references)</sup>

### Co testować w systemach ZK

- Fuzzuj wszystkie parsery guest przy użyciu nieprawidłowych kodowań witness/prywatnych danych wejściowych.
- Wymagaj walidacji zakresu enum przed dispatchowaniem opcode.
- Dodaj kontrole semantyczne aliasowania operandów i innych nieprawidłowych form instrukcji.
- Śledź każde źródło advice/witness aż do każdego miejsca użycia w arytmetyce typowanej i wymagaj walidacji na każdej ścieżce.<sup>[[11]](#references)[[13]](#references)</sup>
- Testuj pomocnicze funkcje arytmetyczne z nienormatywnymi limbami, resztami spoza zakresu i granicznymi wartościami przesunięcia.<sup>[[12]](#references)[[13]](#references)</sup>
- Wymagaj zgodności wysokości stosu i zachowania wartości znajdujących się poniżej zadeklarowanych argumentów procedury przy każdym powrocie.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Porównuj zgłaszane/publiczne liczniki z niezależną implementacją referencyjną.
- Pamiętaj, że poprawny dowód może nadal dowodzić **niewłaściwego twierdzenia**, jeśli program guest zawiera błąd.

## Autoryzacja zależna od stanu

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Eksploity DeFi/AMM

Jeśli interesuje Cię praktyczne wykorzystywanie DEX-ów i AMM-ów (hooki Uniswap v4, nadużycia zaokrągleń/precyzji, swapy przekraczające progi przy użyciu flash loan), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

W przypadku wieloaktywnowych pul ważonych, które buforują wirtualne salda i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Klucz publiczny i klucz prywatny — wyjaśnienie - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
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
- [13] [Audytowanie w epoce (wystarczająco dobrej) AI](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
