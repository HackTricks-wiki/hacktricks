# Blockchain i kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Smart Contracts** to programy wykonywane na blockchainie po spełnieniu określonych warunków, które automatyzują realizację umów bez pośredników.
- **Decentralized Applications (dApps)** bazują na smart contracts i mają przyjazny dla użytkownika front-end oraz przejrzysty, możliwy do audytu back-end.
- **Tokens & Coins** różnią się tym, że coins służą jako cyfrowy pieniądz, a tokens reprezentują wartość lub własność w określonych kontekstach.
  - **Utility Tokens** zapewniają dostęp do usług, a **Security Tokens** oznaczają własność aktywów.
- **DeFi** oznacza Decentralized Finance, czyli usługi finansowe bez centralnych organów.
- **DEX** i **DAOs** oznaczają odpowiednio Decentralized Exchange Platforms i Decentralized Autonomous Organizations.

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczną i uzgodnioną walidację transakcji na blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej liczby tokens, zmniejszając zużycie energii w porównaniu z PoW.<sup>[[1]](#references)</sup>

## Podstawy Bitcoin

### Transakcje

Transakcje Bitcoin polegają na przesyłaniu środków między adresami. Są walidowane za pomocą podpisów cyfrowych, co gwarantuje, że transfery może inicjować wyłącznie właściciel klucza prywatnego.<sup>[[2]](#references)</sup>

#### Kluczowe elementy:

- **Multisignature Transactions** wymagają wielu podpisów, aby zatwierdzić transakcję.<sup>[[3]](#references)</sup>
- Transakcje składają się z **inputs** (źródło środków), **outputs** (miejsce docelowe), **fees** (opłaty dla minerów) oraz **scripts** (reguły transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoin, umożliwiając realizację wielu transakcji w ramach kanału i publikując na blockchainie wyłącznie jego stan końcowy.

## Problemy z prywatnością Bitcoin

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** zwiększają anonimowość, ukrywając powiązania między transakcjami użytkowników.

## Anonimowe pozyskiwanie Bitcoin

Metody obejmują transakcje gotówkowe, mining i korzystanie z mixers. **CoinJoin** łączy wiele transakcji, aby utrudnić śledzenie, a **PayJoin** maskuje CoinJoins jako zwykłe transakcje, zapewniając większą prywatność.

# Podsumowanie ataków na prywatność Bitcoin

W świecie Bitcoin prywatność transakcji i anonimowość użytkowników często budzą obawy. Oto uproszczony przegląd kilku typowych metod, za pomocą których atakujący mogą naruszyć prywatność Bitcoin.<sup>[[6]](#references)</sup>

## **Założenie wspólnego właściciela wejść**

Łączenie wejść różnych użytkowników w jednej transakcji jest zazwyczaj rzadkie ze względu na związaną z tym złożoność. Dlatego **często zakłada się, że dwa adresy wejściowe w tej samej transakcji należą do tego samego właściciela**.

## **Wykrywanie adresu reszty UTXO**

UTXO, czyli **Unspent Transaction Output**, musi zostać wydane w całości w ramach transakcji. Jeśli tylko jego część zostanie wysłana na inny adres, pozostała kwota trafia na nowy adres reszty. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza jego prywatność.

### Przykład

Aby temu zapobiec, można skorzystać z usług mieszających lub używać wielu adresów, co pomaga ukryć ich właściciela.

## **Ujawnianie informacji w sieciach społecznościowych i na forach**

Użytkownicy czasami udostępniają swoje adresy Bitcoin w internecie, przez co **łatwo powiązać adres z jego właścicielem**.

## **Analiza grafu transakcji**

Transakcje można przedstawić jako grafy, ujawniające potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Heurystyka zbędnego wejścia (heurystyka optymalnej reszty)**

Ta heurystyka polega na analizowaniu transakcji z wieloma wejściami i wyjściami, aby odgadnąć, które wyjście stanowi resztę zwracaną nadawcy.

### Przykład

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Jeśli dodanie kolejnych wejść sprawi, że wyjście change będzie większe niż którekolwiek pojedyncze wejście, może to zmylić heurystykę.

## **Wymuszone ponowne użycie adresu**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, łącząc w ten sposób adresy.

### Prawidłowe działanie portfela

Portfele powinny unikać używania monet otrzymanych na wcześniej używanych, pustych adresach, aby zapobiec temu privacy leak.

## **Inne techniki analizy blockchaina**

- **Dokładne kwoty płatności:** Transakcje bez reszty prawdopodobnie zachodzą między dwoma adresami należącymi do tego samego użytkownika.
- **Równe kwoty:** Okrągła kwota w transakcji sugeruje, że jest to płatność, a wyjście z nieokrągłą kwotą prawdopodobnie stanowi resztę.
- **Fingerprinting portfela:** Różne portfele mają charakterystyczne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować użyte oprogramowanie i potencjalnie adres reszty.
- **Korelacje kwot i czasu:** Ujawnienie czasu lub kwot transakcji może ułatwić ich śledzenie.

## **Analiza ruchu sieciowego**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Dotyczy to zwłaszcza podmiotów obsługujących wiele węzłów Bitcoin, co zwiększa ich możliwości monitorowania transakcji.

## Więcej

Pełną listę ataków na prywatność i metod obrony znajdziesz na stronie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby anonimowego pozyskiwania bitcoinów

- **Transakcje gotówkowe**: Pozyskiwanie bitcoinów za gotówkę.
- **Alternatywy dla gotówki**: Kupowanie kart podarunkowych i wymienianie ich online na bitcoiny.
- **Mining**: Najbardziej prywatnym sposobem zarabiania bitcoinów jest mining, szczególnie prowadzony samodzielnie, ponieważ pool miningowe mogą znać adres IP minera. [Informacje o poolach miningowych](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie kradzież bitcoinów może być kolejnym sposobem anonimowego ich pozyskania, ale jest nielegalna i niezalecana.

## Usługi miksujące

Korzystając z usługi miksującej, użytkownik może **wysłać bitcoiny** i otrzymać w zamian **inne bitcoiny**, co utrudnia ustalenie pierwotnego właściciela. Wymaga to jednak zaufania, że usługa nie prowadzi logów i rzeczywiście zwróci bitcoiny. Alternatywą są kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji różnych użytkowników w jedną, utrudniając dopasowanie wejść do wyjść. Mimo skuteczności tej metody transakcje z unikalnymi kwotami wejść i wyjść nadal mogą być śledzone.

Przykładowe transakcje, w których mogło zostać użyte CoinJoin: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz na stronie [CoinJoin](https://coinjoin.io/en). Informacje o mikserze opartym na smart contract Ethereum, który oddziela wpłaty od późniejszych wypłat, znajdziesz na stronie [Tornado Cash](https://tornado.cash).

## PayJoin

Odmiana CoinJoin, **PayJoin** (lub P2EP), ukrywa transakcję między dwiema stronami (np. klientem i sprzedawcą), przedstawiając ją jako zwykłą transakcję, bez charakterystycznych dla CoinJoin równych kwot wyjść. Dzięki temu jest niezwykle trudna do wykrycia i może unieważnić heurystykę wspólnego właściciela wejść stosowaną przez podmioty monitorujące transakcje.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcje takie jak powyższa mogą być PayJoin, zwiększając prywatność, a jednocześnie pozostając nieodróżnialnymi od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody nadzoru**, co czyni tę technikę obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki ochrony prywatności w kryptowalutach

## **Techniki synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, kluczowa jest synchronizacja portfeli z blockchainem. Wyróżniają się dwie metody:

- **Pełny węzeł**: Pobierając cały blockchain, pełny węzeł zapewnia maksymalną prywatność. Wszystkie dotychczasowe transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom ustalenie, którymi transakcjami lub adresami interesuje się użytkownik.
- **Filtrowanie bloków po stronie klienta**: Metoda ta polega na tworzeniu filtrów dla każdego bloku w blockchainie, dzięki czemu portfele mogą identyfikować powiązane transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry i pobierają pełne bloki tylko wtedy, gdy znajdą dopasowanie do adresów użytkownika.

## **Korzystanie z Tor w celu zachowania anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor, aby ukryć adres IP i zwiększyć prywatność podczas komunikacji z siecią.

## **Zapobieganie ponownemu użyciu adresów**

Aby chronić prywatność, należy używać nowego adresu dla każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, łącząc transakcje z tym samym podmiotem. Współczesne portfele z założenia zniechęcają do ponownego używania adresów.

## **Strategie ochrony prywatności transakcji**

- **Wiele transakcji**: Podzielenie płatności na kilka transakcji może utrudnić ustalenie kwoty transakcji i udaremnić ataki na prywatność.
- **Unikanie reszty**: Wybieranie transakcji, które nie wymagają wyjść reszty, zwiększa prywatność, zakłócając metody wykrywania reszty.
- **Wiele wyjść reszty**: Jeśli uniknięcie reszty nie jest możliwe, utworzenie wielu wyjść reszty również może poprawić prywatność.

# **Monero: wzór anonimowości**

Monero zaprojektowano tak, aby priorytetowo traktowało prywatność transakcji.

# **Ethereum: gas i transakcje**

## **Zrozumienie gas**

Gas mierzy nakład obliczeniowy potrzebny do wykonania operacji w Ethereum, a jego cena jest wyrażana w **gwei**. Na przykład transakcja kosztująca 2 310 000 gwei (czyli 0,00231 ETH) uwzględnia limit gas i opłatę bazową, a także opłatę priorytetową zachęcającą walidatora do uwzględnienia transakcji. Użytkownicy mogą ustawić opłatę maksymalną, aby nie zapłacić zbyt wiele; nadwyżka zostanie zwrócona.<sup>[[5]](#references)</sup>

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart contractów. Wymagają opłaty i muszą zostać uwzględnione w bloku. Do niezbędnych informacji w transakcji należą odbiorca, podpis nadawcy, wartość, opcjonalne dane, limit gas i opłaty. Warto zauważyć, że adres nadawcy jest wyznaczany na podstawie podpisu, więc nie trzeba go umieszczać w danych transakcji.<sup>[[4]](#references)</sup>

Te praktyki i mechanizmy stanowią podstawę dla każdego, kto chce korzystać z kryptowalut, stawiając na pierwszym miejscu prywatność i bezpieczeństwo.

## Red Teaming Web3 ukierunkowany na wartość

- Sporządź wykaz komponentów przechowujących wartość (podpisujących, wyroczni, mostów, mechanizmów automatyzacji), aby ustalić, kto i w jaki sposób może przenosić środki.
- Powiąż każdy komponent z odpowiednimi taktykami MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków z wykorzystaniem flash loanów, wyroczni, poświadczeń i ataków cross-chain, aby zweryfikować wpływ oraz udokumentować warunki wstępne umożliwiające wykorzystanie podatności.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Przejęcie procesu podpisywania w Web3

- Manipulacja łańcuchem dostaw interfejsów portfeli może zmieniać payloady EIP-712 tuż przed podpisaniem, pozyskując prawidłowe podpisy do przejęcia proxy opartego na delegatecall (np. przez nadpisanie slotu 0 pola masterCopy w Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstrakcja kont (ERC-4337)

- Typowe tryby awarii smart accountów obejmują ominięcie kontroli dostępu `EntryPoint`, niepodpisane pola gas, walidację zależną od stanu, ponowne użycie podpisu ERC-1271 oraz drenaż opłat przez revert po walidacji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezpieczeństwo smart contractów

- Testowanie mutacyjne w celu wykrywania martwych punktów w zestawach testów:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integralność gościa ZK Proof / zkVM

Gdy prover używa **zkVM** lub specyficznego dla aplikacji obwodu dowodowego, aby poświadczyć twierdzenie, weryfikator dowiaduje się jedynie, że **program gościa wykonał się zgodnie z zapisem**. Jeśli gość zawiera **niebezpieczną deserializację**, **niezdefiniowane zachowanie** lub **brakujące ograniczenia semantyczne**, złośliwy prover może wygenerować dowód, który przejdzie weryfikację, mimo że **publiczne metryki lub deklarowany niezmiennik są fałszywe**.<sup>[[7]](#references)</sup>

### Niebezpieczna deserializacja wewnątrz gości dowodowych

- Traktuj prywatne dane witness/bajty obwodu jako **niezaufane dane wejściowe kontrolowane przez atakującego**, nawet jeśli są ukryte przez dowód.
- Unikaj ich deserializacji za pomocą niezabezpieczonych helperów, takich jak `rkyv::access_unchecked`, chyba że bajty zostały wcześniej zweryfikowane poza tym mechanizmem.
- Dyskryminanty enumów, wskaźniki względne, długości i indeksy wczytane z niezaufanych zserializowanych danych muszą zostać zweryfikowane, zanim wpłyną na przepływ sterowania lub dostęp do pamięci.

Praktyczny schemat audytu:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Jeśli pole takie jak `op.kind` jest enumem, a atakujący może wstrzyknąć **wartość discriminant spoza zakresu**, każde dalsze `match` na tej wartości budzi podejrzenia.

### Obejście liczników przez jump table / UB

Jeśli Rust kompiluje duże `match` do **jump table**, nieprawidłowa wartość discriminant enuma może prowadzić do **niezdefiniowanego przepływu sterowania**. Niebezpieczny wzorzec wygląda tak:<sup>[[7]](#references)[[9]](#references)</sup>

1. Pierwsze `match` aktualizuje **liczniki/ograniczenia krytyczne dla bezpieczeństwa**.
2. Drugie `match` realizuje **właściwą semantykę instrukcji**.
3. Wartość discriminant spoza zakresu indeksuje tablicę pierwszego `match` poza jej granicami i trafia do kodu powiązanego z drugim `match`.

Wynik: operacja nadal zostaje wykonana, ale ścieżka rozliczania zostaje pominięta. W zkVM może to umożliwić sfałszowanie dowodów, które wykazują niemożliwe metryki, takie jak mniejsza liczba bramek, mniej kosztownych operacji lub inne zafałszowane ograniczone zasoby.

Lista kontrolna podczas przeglądu:

- Szukaj enumów kontrolowanych przez atakującego, deserializowanych z witness/prywatnych danych wejściowych.
- Sprawdź powtarzające się instrukcje `match` dotyczące tego samego pola opcode/kind.
- Traktuj połączenie `unsafe` + deserializacji bez kontroli + rozbudowanego dispatchu opcode jako wysokie ryzyko.
- W razie potrzeby wykonaj inżynierię wsteczną skompilowanego pliku binarnego; układ jump table może mieć większe znaczenie niż kod źródłowy.

### Brak ograniczeń semantycznych w odwracalnych/specjalizowanych interpreterach

Nie sprawdzaj wyłącznie bezpieczeństwa pamięci; zweryfikuj też **reguły semantyczne**, których dowód ma pilnować.

W przypadku odwracalnych/zbliżonych do kwantowych zestawów instrukcji upewnij się, że argumenty, które muszą być różne, są rzeczywiście ograniczone warunkiem różności. Operacja podobna do Toffoli/CCX, zaimplementowana jako:<sup>[[7]](#references)[[8]](#references)</sup>

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

Tworzy to **deterministyczny prymityw resetowania**, podważając założenia o odwracalności i umożliwiając tańsze obliczenia niezgodne z przeznaczeniem. W systemach proof, które poświadczają zużycie zasobów, atakujący mogą dzięki temu spełnić kontrole funkcjonalne, omijając model kosztów, którego egzekwowania oczekuje weryfikator.

### Co testować w systemach ZK

- Fuzzuj wszystkie parsery guest, używając nieprawidłowych kodowań witness/prywatnych danych wejściowych.
- Sprawdzaj poprawność zakresu enum przed dispatchowaniem opcode.
- Dodaj kontrole semantyczne dotyczące aliasowania operandów i innych nieprawidłowych form instrukcji.
- Porównuj zgłaszane/publiczne liczniki z niezależną implementacją referencyjną.
- Pamiętaj, że poprawny proof może nadal dowodzić **niewłaściwego twierdzenia**, jeśli program guest zawiera błędy.

## Autoryzacja zależna od stanu

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Wykorzystywanie DeFi/AMM

Jeśli badasz praktyczne wykorzystywanie DEX-ów i AMM (hooki Uniswap v4, nadużycia zaokrągleń/precyzji, swapy przekraczające progi i wzmacniane przez flash loan), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

W przypadku wieloassetowych pul ważonych, które przechowują w cache wirtualne salda i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

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
- [7] [Trail of Bits - Pokonaliśmy zero-knowledge proof Google’a w kryptanalizie kwantowej](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zabezpieczanie kryptowalut opartych na krzywych eliptycznych przed zagrożeniami kwantowymi: szacunki zasobów i środki zaradcze (poprawiona wersja)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repozytorium proof-of-concept Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
