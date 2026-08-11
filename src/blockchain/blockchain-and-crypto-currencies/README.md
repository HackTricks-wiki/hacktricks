# Blockchain i kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Inteligentne kontrakty (Smart Contracts)** są definiowane jako programy, które wykonują się na blockchainie po spełnieniu określonych warunków, automatyzując realizację umów bez pośredników.
- **Zdecentralizowane aplikacje (dApps)** bazują na inteligentnych kontraktach, oferując przyjazny dla użytkownika front-end oraz przejrzysty i możliwy do audytowania back-end.
- **Tokeny i monety (Tokens & Coins)** różnią się tym, że monety służą jako cyfrowe pieniądze, podczas gdy tokeny reprezentują wartość lub własność w określonych kontekstach.
- **Tokeny użytkowe (Utility Tokens)** zapewniają dostęp do usług, a **Security Tokens** oznaczają własność aktywów.
- **DeFi** oznacza zdecentralizowane finanse (Decentralized Finance), oferujące usługi finansowe bez centralnych organów.
- **DEX** i **DAO** oznaczają odpowiednio zdecentralizowane platformy wymiany (Decentralized Exchange Platforms) oraz zdecentralizowane organizacje autonomiczne (Decentralized Autonomous Organizations).

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczne i uzgodnione zatwierdzanie transakcji na blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej w celu weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej liczby tokenów, zmniejszając zużycie energii w porównaniu z PoW.<sup>[[1]](#references)</sup>

## Podstawy Bitcoin

### Transakcje

Transakcje Bitcoin polegają na transferze środków między adresami. Transakcje są zatwierdzane za pomocą podpisów cyfrowych, co gwarantuje, że tylko właściciel klucza prywatnego może zainicjować transfery.<sup>[[2]](#references)</sup>

#### Kluczowe komponenty:

- **Transakcje wielopodpisowe (Multisignature Transactions)** wymagają wielu podpisów w celu autoryzacji transakcji.<sup>[[3]](#references)</sup>
- Transakcje składają się z **wejść** (źródło środków), **wyjść** (miejsce docelowe), **opłat** (płaconych minerom) oraz **skryptów** (reguły transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoin poprzez umożliwienie realizacji wielu transakcji w ramach kanału i rozgłaszanie do blockchaina wyłącznie stanu końcowego.

## Problemy z prywatnością Bitcoin

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** zwiększają anonimowość poprzez ukrywanie powiązań transakcji między użytkownikami.

## Anonimowe nabywanie Bitcoinów

Metody obejmują transakcje gotówkowe, mining oraz korzystanie z mixerów. **CoinJoin** łączy wiele transakcji, aby utrudnić śledzenie, natomiast **PayJoin** ukrywa CoinJoin jako zwykłe transakcje, zapewniając większą prywatność.

# Podsumowanie ataków na prywatność Bitcoin

W świecie Bitcoin prywatność transakcji i anonimowość użytkowników są często przedmiotem obaw. Poniżej przedstawiono uproszczony przegląd kilku powszechnych metod, za pomocą których atakujący mogą naruszyć prywatność Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Zazwyczaj rzadko zdarza się, aby wejścia od różnych użytkowników były łączone w jednej transakcji ze względu na związaną z tym złożoność. Dlatego **często zakłada się, że dwa adresy wejściowe w tej samej transakcji należą do tego samego właściciela**.

## **UTXO Change Address Detection**

UTXO, czyli **Unspent Transaction Output**, musi zostać w całości wydane w ramach transakcji. Jeśli tylko jego część zostanie wysłana na inny adres, pozostała kwota trafia na nowy adres reszty. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza prywatność.

### Przykład

Aby temu przeciwdziałać, można korzystać z usług mieszających lub wielu adresów w celu ukrycia własności.

## **Social Networks & Forums Exposure**

Użytkownicy czasami udostępniają swoje adresy Bitcoin w Internecie, co **ułatwia powiązanie adresu z jego właścicielem**.

## **Transaction Graph Analysis**

Transakcje można przedstawiać w formie grafów, ujawniając potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heurystyka ta opiera się na analizie transakcji z wieloma wejściami i wyjściami w celu odgadnięcia, które wyjście stanowi resztę wracającą do nadawcy.

### Przykład
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Jeśli dodanie większej liczby inputów sprawia, że wynik zmiany jest większy niż dowolny pojedynczy input, może to zmylić heurystykę.

## **Wymuszone ponowne użycie adresu**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi inputami w przyszłych transakcjach, łącząc w ten sposób adresy ze sobą.

### Prawidłowe zachowanie portfela

Portfele powinny unikać używania środków otrzymanych na już używane, puste adresy, aby zapobiec temu wyciekowi prywatności.

## **Inne techniki analizy blockchaina**

- **Dokładne kwoty płatności:** Transakcje bez reszty prawdopodobnie zachodzą między dwoma adresami należącymi do tego samego użytkownika.
- **Liczby zaokrąglone:** Zaokrąglona kwota w transakcji sugeruje, że jest to płatność, a wyjście z niezaokrągloną kwotą prawdopodobnie stanowi resztę.
- **Fingerprinting portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować używane oprogramowanie i potencjalnie adres reszty.
- **Korelacje kwot i czasu:** Ujawnienie czasu lub kwot transakcji może sprawić, że transakcje będzie można śledzić.

## **Analiza ruchu**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Jest to szczególnie prawdopodobne, jeśli podmiot obsługuje wiele węzłów Bitcoin, zwiększając swoje możliwości monitorowania transakcji.

## Więcej

Aby uzyskać pełną listę ataków na prywatność i metod obrony, odwiedź [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby anonimowego uzyskania bitcoinów

- **Transakcje gotówkowe**: Nabywanie bitcoinów za gotówkę.
- **Alternatywy dla gotówki**: Kupowanie kart podarunkowych i wymienianie ich online na bitcoiny.
- **Mining**: Najbardziej prywatną metodą zarabiania bitcoinów jest mining, zwłaszcza prowadzony samodzielnie, ponieważ mining pools mogą znać adres IP minera. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie kradzież bitcoinów mogłaby być kolejną metodą anonimowego ich pozyskania, jednak jest nielegalna i niezalecana.

## Usługi mieszania

Korzystając z usługi mieszania, użytkownik może **wysłać bitcoiny** i otrzymać w zamian **inne bitcoiny**, co utrudnia prześledzenie pierwotnego właściciela. Wymaga to jednak zaufania, że usługa nie będzie przechowywać logów i faktycznie zwróci bitcoiny. Alternatywne opcje mieszania obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji różnych użytkowników w jedną, komplikując proces każdemu, kto próbuje dopasować inputy do outputów. Pomimo swojej skuteczności transakcje z unikalnymi rozmiarami inputów i outputów nadal mogą być potencjalnie śledzone.

Przykładowe transakcje, w których mogła zostać użyta metoda CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` oraz `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz na stronie [CoinJoin](https://coinjoin.io/en). Aby poznać mixer oparty na smart contractcie Ethereum, który oddziela depozyty od późniejszych wypłat, zobacz [Tornado Cash](https://tornado.cash).

## PayJoin

Odmiana CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych jednakowych outputów CoinJoin. Sprawia to, że jej wykrycie jest niezwykle trudne i może unieważnić heurystykę wspólnego właściciela inputów używaną przez podmioty monitorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje takie jak powyższa mogłyby być PayJoin, zwiększając prywatność i pozostając nieodróżnialnymi od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin mogłoby znacząco zakłócić tradycyjne metody nadzoru**, co czyni je obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki zapewniania prywatności w kryptowalutach

## **Techniki synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, kluczowe jest synchronizowanie portfeli z blockchainem. Wyróżniają się dwie metody:

- **Full node**: Pobranie całego blockchaina zapewnia maksymalną prywatność. Wszystkie kiedykolwiek wykonane transakcje są przechowywane lokalnie, co uniemożliwia adversaries ustalenie, którymi transakcjami lub adresami interesuje się użytkownik.
- **Client-side block filtering**: Metoda ta polega na tworzeniu filtrów dla każdego bloku w blockchainie, umożliwiając portfelom identyfikowanie odpowiednich transakcji bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lightweight wallets pobierają te filtry i pobierają pełne bloki tylko wtedy, gdy znalezione zostanie dopasowanie do adresów użytkownika.

## **Wykorzystanie Tor do zapewnienia anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się używanie Tor w celu ukrycia adresu IP, co zwiększa prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu użyciu adresów**

W celu ochrony prywatności należy używać nowego adresu dla każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, łącząc transakcje z tym samym podmiotem. Nowoczesne portfele zniechęcają do ponownego używania adresów poprzez swoją konstrukcję.

## **Strategie zapewniania prywatności transakcji**

- **Multiple transactions**: Podzielenie płatności na kilka transakcji może ukryć kwotę transakcji, udaremniając privacy attacks.
- **Change avoidance**: Wybieranie transakcji, które nie wymagają outputs reszty, zwiększa prywatność poprzez zakłócanie metod wykrywania reszty.
- **Multiple change outputs**: Jeśli uniknięcie reszty nie jest możliwe, wygenerowanie wielu outputs reszty nadal może poprawić prywatność.

# **Monero: Latarnia anonimowości**

Monero zostało zaprojektowane z myślą o priorytetowym traktowaniu prywatności transakcji.

# **Ethereum: Gas i transakcje**

## **Zrozumienie Gas**

Gas mierzy wysiłek obliczeniowy potrzebny do wykonania operacji w Ethereum i jest wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) obejmuje limit gas oraz opłatę bazową, a także opłatę priorytetową zachęcającą validatora do uwzględnienia transakcji. Użytkownicy mogą ustawić maksymalną opłatę, aby nie zapłacić zbyt dużo, a nadwyżka zostanie zwrócona.<sup>[[5]](#references)</sup>

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart contractów. Wymagają opłaty i muszą zostać uwzględnione w bloku. Podstawowe informacje w transakcji obejmują odbiorcę, podpis nadawcy, wartość, opcjonalne dane, limit gas oraz opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, więc nie musi znajdować się w danych transakcji.<sup>[[4]](#references)</sup>

Praktyki i mechanizmy te stanowią podstawę dla każdego, kto chce korzystać z kryptowalut, traktując prywatność i bezpieczeństwo priorytetowo.

## Red Teaming Web3 skoncentrowany na wartości

- Sporządź inwentaryzację komponentów przechowujących wartość (signers, oracles, bridges, automation), aby zrozumieć, kto może przenosić środki i w jaki sposób.
- Zmapuj każdy komponent na odpowiednie taktyki MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków flash-loan/oracle/credential/cross-chain, aby zweryfikować wpływ i udokumentować możliwe do wykorzystania warunki wstępne.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Przejęcie workflow podpisywania Web3

- Manipulacja w łańcuchu dostaw interfejsów portfeli może modyfikować payloads EIP-712 tuż przed podpisaniem, pozyskując prawidłowe podpisy do przejęcia proxy opartego na delegatecall (np. nadpisania slot-0 masterCopy w Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstrakcja kont (ERC-4337)

- Typowe tryby awarii smart-account obejmują omijanie kontroli dostępu `EntryPoint`, niepodpisane pola gas, walidację stateful, replay ERC-1271 oraz drenaż opłat przez revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezpieczeństwo smart contractów

- Mutation testing w celu znalezienia blind spots w test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integralność guestów ZK Proof / zkVM

Gdy prover używa **zkVM** lub obwodu proof wyspecjalizowanego dla danej aplikacji w celu potwierdzenia twierdzenia, verifier dowiaduje się jedynie, że **guest program został wykonany zgodnie z zapisem**. Jeśli guest zawiera **unsafe deserialization**, **undefined behavior** lub **missing semantic constraints**, złośliwy prover może wygenerować proof, który przejdzie weryfikację, podczas gdy **public metrics lub deklarowany invariant są fałszywe**.<sup>[[7]](#references)</sup>

### Unsafe deserialization wewnątrz guestów proof

- Traktuj prywatne witness/circuit bytes jako **untrusted attacker input**, nawet jeśli są ukryte przez proof.
- Unikaj deserializacji za pomocą unchecked helpers, takich jak `rkyv::access_unchecked`, chyba że bytes zostały już zwalidowane out-of-band.
- Enum discriminants, relative pointers, lengths i indexes wczytane z niezaufanych serialized data muszą zostać zwalidowane, zanim wpłyną na control flow lub memory access.

Praktyczny wzorzec audytu:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Jeśli pole takie jak `op.kind` jest enumem, a attacker może wstrzyknąć **discriminant spoza zakresu**, każdy downstream `match` na tej wartości staje się podejrzany.

### Obejście liczników przez jump table / UB

Jeśli Rust obniży duży `match` do **jump table**, nieprawidłowy discriminant enuma może doprowadzić do **undefined control flow**. Niebezpieczny wzorzec to:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jeden `match` aktualizuje **krytyczne dla bezpieczeństwa liczniki/ograniczenia**.
2. Drugi `match` wykonuje **właściwą semantykę instrukcji**.
3. Discriminant spoza zakresu indeksuje obszar za pierwszą jump table i trafia do kodu powiązanego z drugą.

Rezultat: operacja nadal się wykonuje, ale ścieżka rozliczania zostaje pominięta. W zkVM może to umożliwić sfałszowanie proofów zgłaszających niemożliwe metryki, takie jak mniejsza liczba gates, mniejsza liczba drogich operacji lub inne sfałszowane ograniczone zasoby.

Lista kontrolna podczas review:

- Szukaj kontrolowanych przez attackera enumów deserializowanych z witness/private input.
- Sprawdzaj powtarzające się instrukcje `match` używające tego samego pola opcode/kind.
- Traktuj połączenie `unsafe` + unchecked deserialization + duży dispatch opcode jako kombinację wysokiego ryzyka.
- W razie potrzeby wykonaj reverse engineering wygenerowanego binary; układ jump table może mieć większe znaczenie niż source.

### Brak ograniczeń semantycznych w reversible/specialized interpreterach

Nie sprawdzaj wyłącznie bezpieczeństwa pamięci; sprawdzaj również **reguły semantyczne**, których proof ma wymuszać.

W przypadku reversible/quantum-like instruction sets upewnij się, że operandy, które muszą być różne, są faktycznie ograniczone tak, aby były różne. Operacja podobna do Toffoli/CCX zaimplementowana jako:<sup>[[7]](#references)[[8]](#references)</sup>
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
Tworzy to **deterministic reset primitive**, łamiąc założenia odwracalności i umożliwiając tańsze obliczenia niezgodne z przeznaczeniem. W systemach proof, które poświadczają użycie zasobów, może to pozwolić atakującym spełnić kontrole funkcjonalne przy jednoczesnym ominięciu modelu kosztów, którego egzekwowanie zakłada verifier.

### Co testować w systemach ZK

- Fuzzuj wszystkie guest parsers za pomocą niepoprawnie sformatowanych kodowań witness/private-input.
- Wymuś walidację zakresu enum przed dispatchingiem opcode.
- Dodaj kontrole semantyczne aliasingu operandów i innych niepoprawnych form instrukcji.
- Porównuj zgłaszane/publiczne liczniki z niezależną implementacją referencyjną.
- Pamiętaj, że valid proof może nadal dowodzić **nieprawidłowego statementu**, jeśli guest program zawiera błąd.

## DeFi/AMM Exploitation

Jeśli badasz praktyczne exploitation DEX-ów i AMM-ów (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

W przypadku multi-asset weighted pools, które cache'ują virtual balances i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

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
- [7] [Trail of Bits - Pokonaliśmy zero-knowledge proof Google'a dotyczący quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zabezpieczanie kryptowalut opartych na krzywych eliptycznych przed zagrożeniami kwantowymi: szacunki zasobów i środki zaradcze (wersja po poprawkach)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repozytorium proof-of-concept Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
