# Blockchain i Kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Smart Contracts** są definiowane jako programy wykonywane na blockchainie po spełnieniu określonych warunków, automatyzujące realizację umów bez pośredników.
- **Decentralized Applications (dApps)** bazują na smart contracts, oferując przyjazny dla użytkownika front-end oraz przejrzysty i możliwy do audytu back-end.
- **Tokens & Coins** różnią się tym, że coins służą jako cyfrowy pieniądz, podczas gdy tokens reprezentują wartość lub własność w określonych kontekstach.
- **Utility Tokens** zapewniają dostęp do usług, a **Security Tokens** oznaczają własność aktywów.
- **DeFi** oznacza Decentralized Finance, oferujące usługi finansowe bez centralnych organów.
- **DEX** i **DAOs** oznaczają odpowiednio Decentralized Exchange Platforms oraz Decentralized Autonomous Organizations.

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczne i uzgodnione zatwierdzanie transakcji na blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej w celu weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od validatorów posiadania określonej ilości tokens, zmniejszając zużycie energii w porównaniu z PoW.<sup>[[1]](#references)</sup>

## Podstawy Bitcoin

### Transakcje

Transakcje Bitcoin obejmują transfer środków między adresami. Transakcje są zatwierdzane za pomocą podpisów cyfrowych, co zapewnia, że tylko właściciel private key może inicjować transfery.<sup>[[2]](#references)</sup>

#### Kluczowe elementy:

- **Multisignature Transactions** wymagają wielu podpisów do autoryzacji transakcji.<sup>[[3]](#references)</sup>
- Transakcje składają się z **inputs** (źródło środków), **outputs** (miejsce docelowe), **fees** (opłacane minerom) oraz **scripts** (reguły transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoin poprzez umożliwienie wykonywania wielu transakcji w ramach kanału i transmitowanie do blockchaina wyłącznie stanu końcowego.

## Kwestie prywatności Bitcoin

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** zwiększają anonimowość poprzez ukrywanie powiązań transakcji między użytkownikami.

## Anonimowe pozyskiwanie Bitcoinów

Metody obejmują transakcje gotówkowe, mining oraz korzystanie z mixers. **CoinJoin** łączy wiele transakcji, aby utrudnić śledzenie, natomiast **PayJoin** maskuje CoinJoins jako zwykłe transakcje, zapewniając większą prywatność.

# Podsumowanie ataków na prywatność Bitcoin

W świecie Bitcoin prywatność transakcji i anonimowość użytkowników są często przedmiotem obaw. Poniżej przedstawiono uproszczony przegląd kilku typowych metod, za pomocą których attackers mogą naruszać prywatność Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Łączenie inputs pochodzących od różnych użytkowników w jednej transakcji jest zazwyczaj rzadkie ze względu na związane z tym komplikacje. Dlatego **dwa adresy inputs w tej samej transakcji często uznaje się za należące do tego samego właściciela**.

## **UTXO Change Address Detection**

UTXO, czyli **Unspent Transaction Output**, musi zostać w całości wydane w ramach transakcji. Jeśli tylko jego część zostanie wysłana na inny adres, reszta trafia na nowy change address. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, naruszając jego prywatność.

### Przykład

Aby temu przeciwdziałać, mixing services lub korzystanie z wielu adresów może pomóc ukryć własność.

## **Social Networks & Forums Exposure**

Użytkownicy czasami udostępniają swoje adresy Bitcoin online, co **ułatwia powiązanie adresu z jego właścicielem**.

## **Transaction Graph Analysis**

Transakcje można przedstawiać w formie grafów, ujawniając potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heurystyka ta opiera się na analizie transakcji zawierających wiele inputs i outputs w celu odgadnięcia, który output stanowi change zwracany nadawcy.

### Przykład
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Jeśli dodanie większej liczby wejść sprawia, że wynik zmiany jest większy niż dowolne pojedyncze wejście, może to zmylić heurystykę.

## **Wymuszone ponowne użycie adresów**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, łącząc w ten sposób adresy ze sobą.

### Prawidłowe zachowanie portfela

Portfele powinny unikać używania monet otrzymanych na już używanych, pustych adresach, aby zapobiegać temu wyciekowi prywatności.

## **Inne techniki analizy blockchaina**

- **Dokładne kwoty płatności:** Transakcje bez reszty prawdopodobnie zachodzą między dwoma adresami należącymi do tego samego użytkownika.
- **Zaokrąglone liczby:** Zaokrąglona kwota w transakcji sugeruje, że jest to płatność, a wyjście niezaokrąglone prawdopodobnie stanowi resztę.
- **Fingerprinting portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom identyfikować używane oprogramowanie i potencjalnie adres reszty.
- **Korelacje kwot i czasu:** Ujawnienie czasów lub kwot transakcji może sprawić, że transakcje będą możliwe do prześledzenia.

## **Analiza ruchu sieciowego**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Jest to szczególnie prawdziwe, jeśli podmiot obsługuje wiele węzłów Bitcoin, zwiększając swoje możliwości monitorowania transakcji.

## Więcej

Pełną listę ataków na prywatność i sposobów ochrony znajdziesz na stronie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby anonimowego zdobywania Bitcoinów

- **Transakcje gotówkowe:** Zdobywanie bitcoinów za gotówkę.
- **Alternatywy dla gotówki:** Kupowanie kart podarunkowych i wymienianie ich online na bitcoiny.
- **Mining:** Najbardziej prywatną metodą zarabiania bitcoinów jest mining, zwłaszcza prowadzony samodzielnie, ponieważ mining pools mogą znać adres IP minera. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież:** Teoretycznie kradzież bitcoinów mogłaby być kolejną metodą anonimowego ich zdobycia, jednak jest nielegalna i niezalecana.

## Usługi mieszające

Korzystając z usługi mieszającej, użytkownik może **wysłać bitcoiny** i otrzymać w zamian **inne bitcoiny**, co utrudnia prześledzenie pierwotnego właściciela. Wymaga to jednak zaufania, że usługa nie będzie przechowywać logów i rzeczywiście zwróci bitcoiny. Alternatywne opcje mieszania obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji różnych użytkowników w jedną, komplikując proces dopasowywania wejść do wyjść. Pomimo swojej skuteczności transakcje z unikalnymi rozmiarami wejść i wyjść nadal mogą potencjalnie być śledzone.

Przykładowe transakcje, w których mógł zostać użyty CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` oraz `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz na stronie [CoinJoin](https://coinjoin.io/en). Informacje o mixerze smart-contractów Ethereum, który oddziela wpłaty od późniejszych wypłat, znajdziesz na stronie [Tornado Cash](https://tornado.cash).

## PayJoin

Odmiana CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych równych wyjść typowych dla CoinJoin. Sprawia to, że jest ona niezwykle trudna do wykrycia i może unieważnić heurystykę wspólnego właściciela wejść używaną przez podmioty monitorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje takie jak powyższa mogą być typu PayJoin, zwiększając prywatność i pozostając nieodróżnialnymi od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin mogłoby znacząco zakłócić tradycyjne metody nadzoru**, co czyni je obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki dotyczące prywatności w kryptowalutach

## **Techniki synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, kluczowa jest synchronizacja portfeli z blockchainem. Wyróżniają się dwie metody:

- **Full node**: Pobranie całego blockchaina zapewnia maksymalną prywatność. Wszystkie wykonane kiedykolwiek transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom ustalenie, które transakcje lub adresy interesują użytkownika.
- **Client-side block filtering**: Metoda ta polega na tworzeniu filtrów dla każdego bloku w blockchainie, dzięki czemu portfele mogą identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry i pobierają pełne bloki dopiero wtedy, gdy znalezione zostanie dopasowanie do adresów użytkownika.

## **Wykorzystanie Tor w celu zapewnienia anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor w celu ukrycia adresu IP i zwiększenia prywatności podczas interakcji z siecią.

## **Zapobieganie ponownemu użyciu adresów**

Aby chronić prywatność, należy używać nowego adresu dla każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, ponieważ umożliwia powiązanie transakcji z tym samym podmiotem. Nowoczesne portfele z założenia zniechęcają do ponownego używania adresów.

## **Strategie zapewniania prywatności transakcji**

- **Wiele transakcji**: Podzielenie płatności na kilka transakcji może ukryć kwotę transakcji, udaremniając ataki na prywatność.
- **Unikanie reszty**: Wybieranie transakcji, które nie wymagają wyjść reszty, zwiększa prywatność poprzez zakłócanie metod wykrywania reszty.
- **Wiele wyjść reszty**: Jeśli uniknięcie reszty nie jest możliwe, wygenerowanie wielu wyjść reszty nadal może poprawić prywatność.

# **Monero: Latarnia anonimowości**

Monero zostało zaprojektowane z myślą o priorytetowym traktowaniu prywatności transakcji.

# **Ethereum: Gas i transakcje**

## **Zrozumienie Gas**

Gas mierzy wysiłek obliczeniowy wymagany do wykonania operacji w Ethereum i jest wyceniany w **gwei**. Na przykład transakcja kosztująca 2 310 000 gwei (lub 0,00231 ETH) obejmuje limit gas oraz opłatę bazową, a także opłatę priorytetową zachęcającą validatora do uwzględnienia transakcji. Użytkownicy mogą ustawić maksymalną opłatę, aby nie przepłacić, a nadwyżka zostanie zwrócona.<sup>[[5]](#references)</sup>

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart contractów. Wymagają opłaty i muszą zostać uwzględnione w bloku. Niezbędne informacje w transakcji obejmują odbiorcę, podpis nadawcy, wartość, opcjonalne dane, limit gas oraz opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, dzięki czemu nie musi być zawarty w danych transakcji.<sup>[[4]](#references)</sup>

Te praktyki i mechanizmy stanowią podstawę dla każdego, kto chce korzystać z kryptowalut, priorytetowo traktując prywatność i bezpieczeństwo.

## Red Teaming Web3 skoncentrowany na wartości

- Sporządź inwentaryzację komponentów przechowujących wartość (signers, oracles, bridges, automation), aby zrozumieć, kto może przenosić środki i w jaki sposób.
- Zmapuj każdy komponent do odpowiednich taktyk MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków z użyciem flash loan, oracle, credentials i cross-chain, aby zweryfikować wpływ oraz udokumentować warunki wstępne umożliwiające exploitację.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Naruszenie procesu podpisywania w Web3

- Manipulacja łańcuchem dostaw interfejsów portfeli może modyfikować payloady EIP-712 tuż przed podpisaniem, pozyskując prawidłowe podpisy do przejęcia proxy opartych na delegatecall (np. nadpisania slot-0 masterCopy w Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstrakcja kont (ERC-4337)

- Typowe tryby awarii smart account obejmują obchodzenie kontroli dostępu `EntryPoint`, niepodpisane pola gas, walidację stanową, replay ERC-1271 oraz drenaż opłat poprzez revert po walidacji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezpieczeństwo smart contractów

- Mutation testing w celu wykrywania luk w zestawach testów:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integralność dowodów ZK / gościa zkVM

Gdy prover używa **zkVM** lub obwodu dowodowego przeznaczonego dla konkretnej aplikacji do poświadczenia twierdzenia, verifier dowiaduje się jedynie, że **program gościa wykonał się zgodnie z kodem**. Jeśli gość zawiera **niebezpieczną deserializację**, **niezdefiniowane zachowanie** lub **brakujące ograniczenia semantyczne**, złośliwy prover może wygenerować dowód, który przejdzie weryfikację, mimo że **publiczne metryki lub deklarowany inwariant są fałszywe**.<sup>[[7]](#references)</sup>

### Niebezpieczna deserializacja wewnątrz gości dowodowych

- Traktuj prywatne bajty witness/circuit jako **niezaufane dane wejściowe atakującego**, nawet jeśli są ukryte przez dowód.
- Unikaj deserializacji za pomocą niekontrolowanych helperów, takich jak `rkyv::access_unchecked`, chyba że bajty zostały wcześniej zwalidowane poza tym mechanizmem.
- Wartości discriminantów enumów, wskaźniki względne, długości i indeksy wczytywane z niezaufanych danych serializowanych muszą zostać zwalidowane, zanim wpłyną na sterowanie przepływem lub dostęp do pamięci.

Praktyczny wzorzec audytu:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Jeśli pole takie jak `op.kind` jest enumem, a attacker może wstrzyknąć **discriminant spoza zakresu**, każde downstream `match` na tej wartości staje się podejrzane.

### Ominięcie liczników UB / jump table

Jeśli Rust obniży duży `match` do **jump table**, nieprawidłowy discriminant enuma może spowodować **undefined control flow**. Niebezpieczny wzorzec wygląda następująco:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jeden `match` aktualizuje **krytyczne dla bezpieczeństwa liczniki/ograniczenia**.
2. Drugi `match` wykonuje **właściwą semantykę instrukcji**.
3. Discriminant spoza zakresu indeksuje pamięć za pierwszą jump table i trafia do kodu powiązanego z drugą.

Rezultat: operacja nadal się wykonuje, ale ścieżka rozliczania zostaje pominięta. W zkVM może to umożliwić sfałszowanie proofów, które zgłaszają niemożliwe metryki, takie jak mniejsza liczba gate’ów, mniejsza liczba kosztownych operacji lub inne sfałszowane ograniczone zasoby.

Lista kontrolna podczas przeglądu:

- Szukaj kontrolowanych przez attackera enumów deserializowanych z witness/private input.
- Sprawdzaj powtarzające się instrukcje `match` dotyczące tego samego pola opcode/kind.
- Traktuj połączenie `unsafe` + unchecked deserialization + duży dispatch opcode jako kombinację wysokiego ryzyka.
- W razie potrzeby wykonaj reverse engineering wygenerowanego binary; układ jump table może mieć większe znaczenie niż source.

### Brak ograniczeń semantycznych w reversible/specialized interpreterach

Nie sprawdzaj wyłącznie bezpieczeństwa pamięci; sprawdzaj również **reguły semantyczne**, których enforce’owanie ma zapewnić proof.

W przypadku reversible/quantum-like instruction sets upewnij się, że operandy, które muszą być różne, są faktycznie ograniczone do wartości różnych od siebie. Operacja podobna do Toffoli/CCX zaimplementowana jako:<sup>[[7]](#references)[[8]](#references)</sup>
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
Tworzy to **deterministyczny prymityw resetowania**, łamiąc założenia odwracalności i umożliwiając tańsze obliczenia niezgodne z przeznaczeniem. W systemach dowodów poświadczających użycie zasobów może to pozwolić atakującym spełnić kontrole funkcjonalne, jednocześnie omijając model kosztów, którego egzekwowanie zakłada weryfikator.

### Co testować w systemach ZK

- Fuzzuj wszystkie guest parsery za pomocą zniekształconych kodowań witness/private-input.
- Weryfikuj zakres enum przed dispatchowaniem opcode.
- Dodaj kontrole semantyczne aliasingu operandów i innych nieprawidłowych form instrukcji.
- Porównuj zgłaszane/publiczne liczniki z niezależną implementacją referencyjną.
- Pamiętaj, że prawidłowy proof nadal może dowodzić **nieprawidłowego twierdzenia**, jeśli guest program zawiera błąd.

## Autoryzacja zależna od stanu

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Eksploatacja DeFi/AMM

Jeśli badasz praktyczną eksploatację DEX-ów i AMM-ów (hooks Uniswap v4, nadużycia zaokrągleń/precyzji, swapy przekraczające progi i wzmacniane przez flash loan), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

W przypadku ważonych pooli obsługujących wiele aktywów, które cache'ują wirtualne salda i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

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
- [7] [Trail of Bits - Pokonaliśmy zero-knowledge proof Google'a dotyczący kryptanalizy kwantowej](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zabezpieczanie kryptowalut opartych na krzywych eliptycznych przed zagrożeniami kwantowymi: szacunki zasobów i środki zaradcze (poprawiona wersja)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repozytorium proof-of-concept Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
