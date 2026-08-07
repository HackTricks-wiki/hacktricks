# Blockchain i kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Inteligentne kontrakty** są definiowane jako programy wykonywane na blockchainie po spełnieniu określonych warunków, automatyzujące realizację umów bez pośredników.
- **Zdecentralizowane aplikacje (dApps)** bazują na inteligentnych kontraktach, oferując przyjazny dla użytkownika front-end oraz przejrzysty i audytowalny back-end.
- **Tokeny i monety** różnią się tym, że monety służą jako cyfrowy pieniądz, natomiast tokeny reprezentują wartość lub własność w określonych kontekstach.
- **Tokeny użytkowe** zapewniają dostęp do usług, a **tokeny zabezpieczone aktywami** oznaczają własność aktywów.
- **DeFi** oznacza zdecentralizowane finanse, oferujące usługi finansowe bez centralnych organów.
- **DEX** i **DAO** oznaczają odpowiednio zdecentralizowane platformy wymiany oraz zdecentralizowane organizacje autonomiczne.

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczną i uzgodnioną walidację transakcji w blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej w celu weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej ilości tokenów, zmniejszając zużycie energii w porównaniu z PoW.<sup>[[1]](#references)</sup>

## Podstawy Bitcoin

### Transakcje

Transakcje Bitcoin polegają na transferze środków między adresami. Transakcje są zatwierdzane za pomocą podpisów cyfrowych, co gwarantuje, że transfery może inicjować wyłącznie właściciel klucza prywatnego.<sup>[[2]](#references)</sup>

#### Kluczowe elementy:

- **Transakcje wielopodpisowe** wymagają wielu podpisów w celu autoryzacji transakcji.<sup>[[3]](#references)</sup>
- Transakcje składają się z **wejść** (źródło środków), **wyjść** (miejsce docelowe), **opłat** (płaconych minerom) oraz **skryptów** (reguły transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoin poprzez umożliwienie realizacji wielu transakcji w ramach kanału i publikowanie w blockchainie wyłącznie stanu końcowego.

## Problemy z prywatnością Bitcoin

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** zwiększają anonimowość poprzez ukrywanie powiązań transakcji między użytkownikami.

## Anonimowe nabywanie Bitcoinów

Metody obejmują transakcje gotówkowe, mining oraz korzystanie z mixerów. **CoinJoin** łączy wiele transakcji, aby utrudnić śledzenie, natomiast **PayJoin** maskuje CoinJoin jako zwykłą transakcję, zapewniając większą prywatność.

# Ataki na prywatność Bitcoin

# Podsumowanie ataków na prywatność Bitcoin

W świecie Bitcoin prywatność transakcji i anonimowość użytkowników często budzą obawy. Poniżej przedstawiono uproszczony przegląd kilku popularnych metod, za pomocą których atakujący mogą naruszyć prywatność Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Zazwyczaj rzadko łączy się wejścia należące do różnych użytkowników w jednej transakcji ze względu na związaną z tym złożoność. Dlatego **dwa adresy wejściowe w tej samej transakcji często uznaje się za należące do tego samego właściciela**.

## **UTXO Change Address Detection**

UTXO, czyli **Unspent Transaction Output**, musi zostać w całości wydane w ramach transakcji. Jeśli tylko jego część zostanie wysłana na inny adres, pozostała kwota trafia na nowy adres reszty. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza prywatność.

### Przykład

Aby temu przeciwdziałać, można korzystać z usług mieszających lub wielu adresów w celu utrudnienia ustalenia własności.

## **Social Networks & Forums Exposure**

Użytkownicy czasami udostępniają swoje adresy Bitcoin online, przez co **łatwo powiązać adres z jego właścicielem**.

## **Transaction Graph Analysis**

Transakcje można wizualizować jako grafy, ujawniając potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heurystyka ta opiera się na analizie transakcji z wieloma wejściami i wyjściami w celu odgadnięcia, które wyjście stanowi resztę wracającą do nadawcy.

### Przykład
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Jeśli dodanie większej liczby inputs sprawi, że change output będzie większy niż dowolny pojedynczy input, może to zmylić heuristic.

## **Forced Address Reuse**

Atakujący mogą wysyłać małe kwoty na wcześniej używane adresy, mając nadzieję, że odbiorca połączy je z innymi inputs w przyszłych transakcjach, łącząc tym samym adresy.

### Correct Wallet Behavior

Wallety powinny unikać używania coins otrzymanych na już używanych, pustych adresach, aby zapobiegać temu privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcje bez change prawdopodobnie odbywają się między dwoma adresami należącymi do tego samego użytkownika.
- **Round Numbers:** Okrągła kwota w transakcji sugeruje, że jest to płatność, a output z nieokrągłą kwotą prawdopodobnie stanowi change.
- **Wallet Fingerprinting:** Różne wallety mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować używane software i potencjalnie adres change.
- **Amount & Timing Correlations:** Ujawnienie czasów lub kwot transakcji może sprawić, że transakcje będą możliwe do prześledzenia.

## **Traffic Analysis**

Monitorowanie network traffic może potencjalnie pozwolić atakującym powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Jest to szczególnie prawdziwe, jeśli dany podmiot obsługuje wiele Bitcoin nodes, zwiększając swoje możliwości monitorowania transakcji.

## More

Kompleksową listę privacy attacks i defenses znajdziesz na stronie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Nabywanie bitcoinów za gotówkę.
- **Cash Alternatives**: Kupowanie gift cards i wymienianie ich online na bitcoin.
- **Mining**: Najbardziej prywatną metodą zarabiania bitcoinów jest mining, szczególnie wykonywany samodzielnie, ponieważ mining pools mogą znać adres IP minera. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretycznie kradzież bitcoinów mogłaby być inną metodą anonimowego ich zdobycia, jednak jest nielegalna i niezalecana.

## Mixing Services

Korzystając z mixing service, użytkownik może **wysyłać bitcoiny** i otrzymywać w zamian **inne bitcoiny**, co utrudnia prześledzenie pierwotnego właściciela. Wymaga to jednak zaufania, że usługa nie będzie przechowywać logów i faktycznie zwróci bitcoiny. Alternatywne opcje mixingu obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji od różnych użytkowników w jedną, komplikując proces każdemu, kto próbuje dopasować inputs do outputs. Pomimo skuteczności transakcje z unikalnymi rozmiarami inputs i outputs nadal mogą być potencjalnie śledzone.

Przykładowe transakcje, które mogły wykorzystywać CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` oraz `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz na stronie [CoinJoin](https://coinjoin.io/en). Aby poznać podobną usługę dla Ethereum, sprawdź [Tornado Cash](https://tornado.cash), która anonimizuje transakcje za pomocą środków od minerów.

## PayJoin

Odmiana CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i merchantem) jako zwykłą transakcję, bez charakterystycznych równych outputs typowych dla CoinJoin. Dzięki temu jest niezwykle trudna do wykrycia i może unieważnić common-input-ownership heuristic używaną przez podmioty monitorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje takie jak powyższa mogą być PayJoin, zwiększając prywatność i pozostając nieodróżnialnymi od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin mogłoby znacząco zakłócić tradycyjne metody nadzoru**, co czyni je obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki dotyczące prywatności w kryptowalutach

## **Techniki synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, kluczowa jest synchronizacja portfeli z blockchainem. Wyróżniają się dwie metody:

- **Pełny węzeł**: Pobranie całego blockchaina zapewnia maksymalną prywatność. Wszystkie kiedykolwiek wykonane transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom ustalenie, które transakcje lub adresy interesują użytkownika.
- **Filtrowanie bloków po stronie klienta**: Metoda ta polega na tworzeniu filtrów dla każdego bloku w blockchainie, umożliwiając portfelom identyfikowanie istotnych transakcji bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry i pobierają pełne bloki tylko wtedy, gdy zostanie znalezione dopasowanie do adresów użytkownika.

## **Wykorzystanie Tor w celu zapewnienia anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor w celu ukrycia adresu IP i zwiększenia prywatności podczas interakcji z siecią.

## **Zapobieganie ponownemu użyciu adresów**

Aby chronić prywatność, należy używać nowego adresu dla każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, ponieważ umożliwia powiązanie transakcji z tym samym podmiotem. Nowoczesne portfele z założenia zniechęcają do ponownego używania adresów.

## **Strategie zapewniania prywatności transakcji**

- **Wiele transakcji**: Podzielenie płatności na kilka transakcji może ukryć kwotę transakcji, udaremniając ataki na prywatność.
- **Unikanie reszty**: Wybieranie transakcji, które nie wymagają wyjść reszty, zwiększa prywatność poprzez zakłócanie metod wykrywania reszty.
- **Wiele wyjść reszty**: Jeśli uniknięcie reszty nie jest możliwe, wygenerowanie wielu wyjść reszty nadal może poprawić prywatność.

# **Monero: Filar anonimowości**

Monero odpowiada na potrzebę całkowitej anonimowości w transakcjach cyfrowych, ustanawiając wysoki standard prywatności.

# **Ethereum: Gas i transakcje**

## **Zrozumienie Gas**

Gas mierzy wysiłek obliczeniowy wymagany do wykonania operacji w Ethereum i jest wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) obejmuje limit gas oraz opłatę bazową, a także napiwek zachęcający minerów. Użytkownicy mogą ustawić maksymalną opłatę, aby mieć pewność, że nie zapłacą zbyt dużo, a nadwyżka zostanie zwrócona.<sup>[[5]](#references)</sup>

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart contractów. Wymagają opłaty i muszą zostać zminowane. Najważniejsze informacje w transakcji obejmują odbiorcę, podpis nadawcy, wartość, opcjonalne dane, limit gas oraz opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, więc nie trzeba umieszczać go w danych transakcji.<sup>[[4]](#references)</sup>

Praktyki i mechanizmy te stanowią podstawę dla każdego, kto chce korzystać z kryptowalut, traktując priorytetowo prywatność i bezpieczeństwo.

## Value-Centric Web3 Red Teaming

- Sporządź inwentaryzację komponentów przechowujących wartość (signers, oracles, bridges, automation), aby zrozumieć, kto i w jaki sposób może przenosić środki.
- Przypisz każdy komponent do odpowiednich taktyk MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków flash-loan/oracle/credential/cross-chain, aby zweryfikować wpływ i udokumentować warunki wstępne umożliwiające wykorzystanie.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitacja Web3 Signing Workflow

- Manipulacja w łańcuchu dostaw interfejsów portfeli może zmienić payloady EIP-712 tuż przed podpisaniem, pozyskując prawidłowe podpisy do przejęcia proxy opartego na delegatecall (np. nadpisania slot-0 masterCopy Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Typowe tryby awarii smart-account obejmują omijanie kontroli dostępu `EntryPoint`, niepodpisane pola gas, walidację stanową, replay ERC-1271 oraz drenaż opłat przez revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezpieczeństwo smart contractów

- Mutation testing w celu znalezienia ślepych punktów w zestawach testów:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integralność guestów ZK Proof / zkVM

Gdy prover używa **zkVM** lub specyficznego dla aplikacji obwodu proof w celu poświadczenia twierdzenia, verifier dowiaduje się jedynie, że **guest program został wykonany zgodnie z kodem**. Jeśli guest zawiera **niebezpieczną deserializację**, **niezdefiniowane zachowanie** lub **brakujące ograniczenia semantyczne**, złośliwy prover może wygenerować proof, który przejdzie weryfikację, mimo że **publiczne metryki lub deklarowany niezmiennik są fałszywe**.<sup>[[7]](#references)</sup>

### Niebezpieczna deserializacja wewnątrz guestów proof

- Traktuj prywatne witness/circuit bytes jako **niezaufane dane wejściowe atakującego**, nawet jeśli są ukryte przez proof.
- Unikaj deserializowania ich za pomocą niekontrolowanych helperów, takich jak `rkyv::access_unchecked`, chyba że bajty zostały wcześniej zwalidowane poza tym procesem.
- Discriminants enumów, wskaźniki względne, długości i indeksy wczytywane z niezaufanych danych serializowanych muszą zostać zwalidowane, zanim wpłyną na sterowanie przepływem lub dostęp do pamięci.

Praktyczny schemat audytu:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Jeśli pole takie jak `op.kind` jest enumem, a atakujący może wstrzyknąć **discriminant spoza zakresu**, każda dalsza instrukcja `match` korzystająca z tej wartości staje się podejrzana.

### Obejście liczników przez jump table / UB

Jeśli Rust obniży duże `match` do **jump table**, nieprawidłowy discriminant enuma może doprowadzić do **niezdefiniowanego przepływu sterowania**. Niebezpieczny wzorzec wygląda następująco:<sup>[[7]](#references)[[9]](#references)</sup>

1. Pierwszy `match` aktualizuje **krytyczne dla bezpieczeństwa liczniki/ograniczenia**.
2. Drugi `match` wykonuje **właściwą semantykę instrukcji**.
3. Discriminant spoza zakresu indeksuje pamięć za pierwszą jump table i trafia do kodu powiązanego z drugą.

Wynik: operacja nadal się wykonuje, ale ścieżka rozliczania zostaje pominięta. W zkVM może to umożliwić sfałszowanie dowodów zgłaszających niemożliwe metryki, takie jak mniejsza liczba gate'ów, mniejsza liczba kosztownych operacji lub inne sfałszowane ograniczone zasoby.

Lista kontrolna podczas przeglądu:

- Szukaj enumów kontrolowanych przez atakującego, deserializowanych z witness/prywatnych danych wejściowych.
- Sprawdzaj powtarzające się instrukcje `match` korzystające z tego samego pola opcode/kind.
- Traktuj połączenie `unsafe` + deserializacja bez sprawdzania + duży dispatch opcode jako wysoce ryzykowne.
- W razie potrzeby wykonaj reverse engineering wygenerowanego binary; układ jump table może mieć większe znaczenie niż kod źródłowy.

### Brak ograniczeń semantycznych w odwracalnych/specjalizowanych interpreterach

Nie sprawdzaj wyłącznie bezpieczeństwa pamięci; sprawdź również **reguły semantyczne**, których egzekwowanie ma zapewniać dowód.

W przypadku odwracalnych/kwantowych zestawów instrukcji upewnij się, że operandy, które muszą być różne, są rzeczywiście ograniczone warunkiem różności. Operacja podobna do Toffoliego/CCX zaimplementowana jako:<sup>[[7]](#references)[[8]](#references)</sup>
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
This creates a **deterministyczny prymityw resetowania**, łamiąc założenia odwracalności i umożliwiając tańsze obliczenia niezgodne z przeznaczeniem. W systemach dowodowych, które poświadczają zużycie zasobów, może to pozwolić atakującym spełnić kontrole funkcjonalne, jednocześnie omijając model kosztów, którego egzekwowanie zakłada weryfikator.

### Co testować w systemach ZK

- Fuzzuj wszystkie guest parsers za pomocą niepoprawnie sformowanych kodowań witness/private-input.
- Weryfikuj zakres enum przed dispatchowaniem opcode.
- Dodaj kontrole semantyczne dotyczące aliasowania operandów i innych nieprawidłowych form instrukcji.
- Porównuj zgłaszane/public counters z niezależną implementacją referencyjną.
- Pamiętaj, że poprawny proof może nadal dowodzić **nieprawidłowego stwierdzenia**, jeśli guest program zawiera błąd.

## Eksploatacja DeFi/AMM

Jeśli badasz praktyczną eksploatację DEX-ów i AMM-ów (hooks w Uniswap v4, nadużycia zaokrągleń/precyzji, swapy przekraczające progi i wzmacniane przez flash loan), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

W przypadku wieloassetowych weighted pools, które buforują virtual balances i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## Referencje

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Wyjaśnienie klucza publicznego i klucza prywatnego - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Czym są transakcje multisignature? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transakcje | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas i opłaty | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Prywatność - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Pokonaliśmy zero-knowledge proof Google dotyczący kryptanalizy kwantowej](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zabezpieczanie kryptowalut opartych na krzywych eliptycznych przed zagrożeniami kwantowymi: szacunki zasobów i środki zaradcze (spatchowana wersja)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repozytorium proof-of-concept Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
