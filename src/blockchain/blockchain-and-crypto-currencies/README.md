# Blockchain i kryptowaluty

## Podstawowe pojęcia

- **Smart Contracts** są definiowane jako programy wykonywane na blockchainie po spełnieniu określonych warunków, automatyzujące realizację umów bez pośredników.
- **Decentralized Applications (dApps)** bazują na smart contracts, oferując przyjazny dla użytkownika front-end oraz przejrzysty i możliwy do audytu back-end.
- **Tokens & Coins** różnią się tym, że coins służą jako cyfrowy pieniądz, podczas gdy tokens reprezentują wartość lub własność w określonych kontekstach.
- **Utility Tokens** zapewniają dostęp do usług, a **Security Tokens** oznaczają własność aktywów.
- **DeFi** oznacza Decentralized Finance, oferujące usługi finansowe bez centralnych władz.
- **DEX** i **DAOs** oznaczają odpowiednio Decentralized Exchange Platforms oraz Decentralized Autonomous Organizations.

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczną i uzgodnioną walidację transakcji na blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej w celu weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej ilości tokenów, zmniejszając zużycie energii w porównaniu z PoW.<sup>[[1]](#references)</sup>

## Podstawy Bitcoin

### Transakcje

Transakcje Bitcoin obejmują transfer środków między adresami. Transakcje są zatwierdzane za pomocą podpisów cyfrowych, co gwarantuje, że transfery może inicjować wyłącznie właściciel klucza prywatnego.<sup>[[2]](#references)</sup>

#### Kluczowe elementy:

- **Multisignature Transactions** wymagają wielu podpisów w celu autoryzacji transakcji.<sup>[[3]](#references)</sup>
- Transakcje składają się z **inputs** (źródła środków), **outputs** (miejsca docelowego), **fees** (opłat wypłacanych minerom) oraz **scripts** (reguł transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoin poprzez umożliwienie wykonywania wielu transakcji w ramach kanału i rozgłaszanie do blockchaina wyłącznie stanu końcowego.

## Problemy z prywatnością Bitcoin

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** zwiększają anonimowość poprzez ukrywanie powiązań między transakcjami użytkowników.

## Anonimowe pozyskiwanie Bitcoinów

Metody obejmują transakcje gotówkowe, mining oraz korzystanie z mixerów. **CoinJoin** łączy wiele transakcji, aby utrudnić śledzenie, natomiast **PayJoin** maskuje CoinJoins jako zwykłe transakcje, zapewniając większą prywatność.

# Podsumowanie ataków na prywatność Bitcoin

W świecie Bitcoin prywatność transakcji i anonimowość użytkowników często budzą obawy. Poniżej przedstawiono uproszczony przegląd kilku typowych metod, za pomocą których atakujący mogą naruszyć prywatność Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Zwykle rzadko łączy się inputs pochodzące od różnych użytkowników w ramach jednej transakcji ze względu na związaną z tym złożoność. Dlatego **dwa adresy inputs w tej samej transakcji często uznaje się za należące do tego samego właściciela**.

## **UTXO Change Address Detection**

UTXO, czyli **Unspent Transaction Output**, musi zostać wydane w całości w ramach transakcji. Jeśli tylko jego część zostanie wysłana na inny adres, pozostała kwota trafia na nowy adres reszty. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza prywatność.

### Przykład

Aby temu zapobiec, usługi mieszające lub korzystanie z wielu adresów mogą pomóc ukryć własność.

## **Social Networks & Forums Exposure**

Użytkownicy czasami udostępniają swoje adresy Bitcoin online, przez co **łatwo powiązać adres z jego właścicielem**.

## **Transaction Graph Analysis**

Transakcje można przedstawiać w formie grafów, ujawniając potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heurystyka ta opiera się na analizie transakcji z wieloma inputs i outputs w celu odgadnięcia, który output stanowi resztę zwracaną nadawcy.

### Przykład
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Jeśli dodanie większej liczby inputów sprawia, że wynik zmiany jest większy niż dowolny pojedynczy input, może to zmylić heurystykę.

## **Wymuszone ponowne użycie adresu**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi inputami w przyszłych transakcjach, łącząc w ten sposób adresy.

### Prawidłowe działanie portfela

Portfele powinny unikać używania coinów otrzymanych na już używanych, pustych adresach, aby zapobiec temu privacy leak.

## **Inne techniki analizy blockchaina**

- **Dokładne kwoty płatności:** Transakcje bez reszty prawdopodobnie odbywają się między dwoma adresami należącymi do tego samego użytkownika.
- **Zaokrąglone liczby:** Zaokrąglona kwota w transakcji sugeruje, że jest to płatność, a kwota na wyjściu, która nie jest zaokrąglona, prawdopodobnie stanowi resztę.
- **Fingerprinting portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować używane oprogramowanie i potencjalnie adres reszty.
- **Korelacje kwot i czasu:** Ujawnienie czasu lub kwot transakcji może sprawić, że transakcje będzie można śledzić.

## **Analiza ruchu**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Jest to szczególnie prawdziwe, jeśli podmiot obsługuje wiele węzłów Bitcoin, zwiększając swoje możliwości monitorowania transakcji.

## Więcej

Kompleksową listę ataków na prywatność i metod ochrony znajdziesz na stronie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby anonimowego zdobywania Bitcoinów

- **Transakcje gotówkowe:** Zdobywanie bitcoinów za gotówkę.
- **Alternatywy dla gotówki:** Kupowanie kart podarunkowych i wymienianie ich online na bitcoiny.
- **Mining:** Najbardziej prywatnym sposobem zarabiania bitcoinów jest mining, szczególnie wykonywany samodzielnie, ponieważ mining pools mogą znać adres IP minera. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież:** Teoretycznie kradzież bitcoinów mogłaby być kolejną metodą anonimowego ich zdobycia, jednak jest nielegalna i niezalecana.

## Usługi mieszające

Korzystając z usługi mieszającej, użytkownik może **wysłać bitcoiny** i otrzymać w zamian **inne bitcoiny**, co utrudnia prześledzenie pierwotnego właściciela. Wymaga to jednak zaufania, że usługa nie będzie przechowywać logów i faktycznie zwróci bitcoiny. Alternatywne opcje mieszania obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji różnych użytkowników w jedną, komplikując proces dopasowywania inputów do outputów. Mimo swojej skuteczności transakcje z unikalnymi rozmiarami inputów i outputów nadal mogą być potencjalnie śledzone.

Przykładowe transakcje, które mogły wykorzystywać CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` oraz `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz na stronie [CoinJoin](https://coinjoin.io/en). Informacje o mixerze opartym na smart contractcie Ethereum, który oddziela wpłaty od późniejszych wypłat, znajdziesz na stronie [Tornado Cash](https://tornado.cash).

## PayJoin

Odmiana CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych równych outputów CoinJoin. Sprawia to, że jest ona niezwykle trudna do wykrycia i może unieważnić heurystykę wspólnego właściciela inputów używaną przez podmioty monitorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje takie jak powyższa mogą być PayJoin, zwiększając prywatność przy jednoczesnym zachowaniu nieodróżnialności od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin mogłoby znacząco zakłócić tradycyjne metody surveillance**, czyniąc je obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki dotyczące prywatności w kryptowalutach

## **Techniki synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, kluczowe jest synchronizowanie portfeli z blockchainem. Wyróżniają się dwie metody:

- **Full node**: Pobierając cały blockchain, full node zapewnia maksymalną prywatność. Wszystkie kiedykolwiek wykonane transakcje są przechowywane lokalnie, co uniemożliwia adversaries ustalenie, którymi transakcjami lub adresami interesuje się użytkownik.
- **Client-side block filtering**: Metoda ta polega na tworzeniu filtrów dla każdego bloku w blockchainie, dzięki czemu portfele mogą identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lightweight wallets pobierają te filtry i pobierają pełne bloki tylko wtedy, gdy znalezione zostanie dopasowanie do adresów użytkownika.

## **Wykorzystanie Tor do zapewnienia anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się używanie Tor w celu ukrycia adresu IP, co zwiększa prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu użyciu adresów**

Aby chronić prywatność, należy używać nowego adresu dla każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, łącząc transakcje z tym samym podmiotem. Nowoczesne portfele zniechęcają do ponownego używania adresów poprzez swoją konstrukcję.

## **Strategie zapewniania prywatności transakcji**

- **Multiple transactions**: Podzielenie płatności na kilka transakcji może ukryć kwotę transakcji, udaremniając ataki na prywatność.
- **Change avoidance**: Wybieranie transakcji, które nie wymagają wyjść reszty, zwiększa prywatność poprzez zakłócanie metod wykrywania reszty.
- **Multiple change outputs**: Jeśli uniknięcie reszty nie jest możliwe, wygenerowanie wielu wyjść reszty nadal może poprawić prywatność.

# **Monero: Latarnia anonimowości**

Monero zostało zaprojektowane tak, aby priorytetowo traktować prywatność transakcji.

# **Ethereum: Gas i transakcje**

## **Zrozumienie Gas**

Gas mierzy moc obliczeniową potrzebną do wykonania operacji w Ethereum i jest wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (lub 0.00231 ETH) obejmuje limit gas i opłatę bazową, a także opłatę priorytetową zachęcającą do uwzględnienia transakcji przez validator. Użytkownicy mogą ustawić maksymalną opłatę, aby upewnić się, że nie zapłacą zbyt dużo, a nadwyżka zostanie zwrócona.<sup>[[5]](#references)</sup>

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart contractów. Wymagają opłaty i muszą zostać uwzględnione w bloku. Podstawowe informacje w transakcji obejmują odbiorcę, podpis nadawcy, wartość, opcjonalne dane, limit gas i opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, więc nie musi być zawarty w danych transakcji.<sup>[[4]](#references)</sup>

Praktyki i mechanizmy te stanowią podstawę dla każdego, kto chce korzystać z kryptowalut, jednocześnie traktując prywatność i bezpieczeństwo priorytetowo.

## Red Teaming Web3 skoncentrowany na wartości

- Sporządź inwentaryzację komponentów przechowujących wartość (signers, oracles, bridges, automation), aby zrozumieć, kto może przenosić środki i w jaki sposób.
- Przypisz każdy komponent do odpowiednich taktyk MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków flash-loan/oracle/credential/cross-chain, aby zweryfikować wpływ i udokumentować warunki wstępne umożliwiające exploitację.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitacja procesu podpisywania Web3

- Manipulacja w łańcuchu dostaw interfejsów portfeli może zmienić payloady EIP-712 tuż przed podpisaniem, pozyskując prawidłowe podpisy do przejęcia proxy opartego na delegatecall (np. nadpisania slot-0 elementu Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Typowe tryby awarii smart-account obejmują omijanie kontroli dostępu `EntryPoint`, niepodpisane pola gas, walidację stanową, replay ERC-1271 oraz drenaż opłat poprzez revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezpieczeństwo smart contractów

- Mutation testing w celu znalezienia luk w zestawach testów:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integralność ZK Proof / zkVM Guest

Gdy prover używa **zkVM** lub obwodu proof przeznaczonego dla konkretnej aplikacji do potwierdzenia twierdzenia, verifier dowiaduje się jedynie, że **guest program wykonał się zgodnie z implementacją**. Jeśli guest zawiera **niebezpieczną deserializację**, **undefined behavior** lub **brakujące ograniczenia semantyczne**, złośliwy prover może wygenerować proof, który przejdzie weryfikację, mimo że **public metrics lub deklarowany invariant są fałszywe**.<sup>[[7]](#references)</sup>

### Niebezpieczna deserializacja wewnątrz proof guests

- Traktuj prywatne witness/circuit bytes jako **niezaufane dane wejściowe atakującego**, nawet jeśli są ukryte przez proof.
- Unikaj deserializacji za pomocą niezweryfikowanych helperów, takich jak `rkyv::access_unchecked`, chyba że bytes zostały wcześniej zwalidowane out-of-band.
- Enum discriminants, relative pointers, lengths i indexes wczytane z niezaufanych serialized data muszą zostać zwalidowane, zanim wpłyną na sterowanie przepływem lub dostęp do pamięci.

Praktyczny wzorzec audytu:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Jeśli pole takie jak `op.kind` jest enumem, a atakujący może wstrzyknąć **discriminant spoza zakresu**, każde dalsze `match` na tej wartości staje się podejrzane.

### Obejście liczników / UB za pomocą jump table

Jeśli Rust obniży duży `match` do **jump table**, nieprawidłowy discriminant enuma może spowodować **niezdefiniowany przepływ sterowania**. Niebezpieczny wzorzec wygląda następująco:<sup>[[7]](#references)[[9]](#references)</sup>

1. Pierwszy `match` aktualizuje **krytyczne dla bezpieczeństwa liczniki/ograniczenia**.
2. Drugi `match` wykonuje **właściwą semantykę instrukcji**.
3. Discriminant spoza zakresu indeksuje obszar za pierwszą jump table i trafia do kodu powiązanego z drugą.

Wynik: operacja nadal jest wykonywana, ale ścieżka rozliczania zostaje pominięta. W zkVM może to umożliwić sfałszowanie proofów, które zgłaszają niemożliwe metryki, takie jak mniejsza liczba gates, mniejsza liczba kosztownych operacji lub inne sfałszowane ograniczone zasoby.

Lista kontrolna podczas przeglądu:

- Szukaj kontrolowanych przez atakującego enumów deserializowanych z witness/private input.
- Sprawdzaj powtarzające się instrukcje `match` dotyczące tego samego pola opcode/kind.
- Traktuj połączenie `unsafe` + unchecked deserialization + duży dispatch opcode jako kombinację wysokiego ryzyka.
- W razie potrzeby wykonaj reverse engineering wygenerowanego binarium; układ jump table może mieć większe znaczenie niż kod źródłowy.

### Brak ograniczeń semantycznych w odwracalnych/specjalizowanych interpreterach

Nie ograniczaj się do walidowania bezpieczeństwa pamięci; waliduj również **reguły semantyczne**, których egzekwowanie ma zapewnić proof.

W przypadku odwracalnych/podobnych do kwantowych zestawów instrukcji upewnij się, że operandy, które muszą być różne, są faktycznie ograniczone do różnych wartości. Operacja podobna do Toffoli/CCX zaimplementowana jako:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
staje się niebezpieczne, jeśli gość nie odrzuci:
```text
op.q_control1 == op.q_control2 == op.q_target
```
W takim przypadku przejście upraszcza się do:
```text
q = q ^ (q & q) = 0
```
Tworzy to **deterministyczny prymityw resetowania**, łamiąc założenia odwracalności i umożliwiając tańsze, niezamierzone obliczenia. W systemach proof, które poświadczają zużycie zasobów, może to pozwolić atakującym spełnić kontrole funkcjonalne przy jednoczesnym ominięciu modelu kosztów, którego egzekwowanie zakłada verifier.

### Co testować w systemach ZK

- Fuzzuj wszystkie parsery guest za pomocą niepoprawnie sformatowanych kodowań witness/private-input.
- Wymuś walidację zakresu enum przed dispatchem opcode.
- Dodaj kontrole semantyczne aliasingu operandów i innych niepoprawnych form instrukcji.
- Porównuj zgłaszane/publiczne liczniki z niezależną implementacją referencyjną.
- Pamiętaj, że poprawny proof nadal może dowodzić **niepoprawnego twierdzenia**, jeśli program guest zawiera błąd.

## Eksploatacja DeFi/AMM

Jeśli badasz praktyczną eksploatację DEX-ów i AMM-ów (hooks Uniswap v4, nadużycie zaokrągleń/precyzji, swapy przekraczające progi, wzmacniane przez flash loan), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

W przypadku wieloaktywnych weighted pools, które cache'ują wirtualne salda i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Wyjaśnienie klucza publicznego i prywatnego - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Czym są transakcje multi-signature? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transakcje | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas i opłaty | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Prywatność - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Pokonaliśmy quantum cryptanalysis w zero-knowledge proof firmy Google](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zabezpieczanie kryptowalut opartych na krzywych eliptycznych przed zagrożeniami kwantowymi: szacunki zasobów i środki zaradcze (spatchowana wersja)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repozytorium proof-of-concept Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
