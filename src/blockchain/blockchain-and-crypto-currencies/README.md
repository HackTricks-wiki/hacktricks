# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** to programy wykonywane na blockchain, gdy spełnione są określone warunki, automatyzujące realizację umów bez pośredników.
- **Decentralized Applications (dApps)** opierają się na smart contracts, oferując przyjazny dla użytkownika front-end i transparentny, audytowalny back-end.
- **Tokens & Coins** rozróżniają, gdzie coins służą jako cyfrowe pieniądze, podczas gdy tokens reprezentują wartość lub własność w określonych kontekstach.
- **Utility Tokens** dają dostęp do usług, a **Security Tokens** oznaczają własność aktywów.
- **DeFi** oznacza Decentralized Finance, oferując usługi finansowe bez centralnych organów.
- **DEX** i **DAOs** odnoszą się odpowiednio do Decentralized Exchange Platforms i Decentralized Autonomous Organizations.

## Consensus Mechanisms

Mechanisms konsensusu zapewniają bezpieczną i uzgodnioną walidację transakcji na blockchain:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od validatorzy posiadania określonej liczby tokens, zmniejszając zużycie energii w porównaniu z PoW.

## Bitcoin Essentials

### Transactions

Transakcje Bitcoin obejmują transfer środków między addressami. Transakcje są walidowane za pomocą podpisów cyfrowych, zapewniając, że tylko właściciel private key może inicjować transfery.

#### Key Components:

- **Multisignature Transactions** wymagają wielu podpisów do autoryzacji transakcji.
- Transakcje składają się z **inputs** (źródło środków), **outputs** (cel), **fees** (płacone minerom) oraz **scripts** (zasady transakcji).

### Lightning Network

Ma na celu poprawę skalowalności Bitcoin poprzez umożliwienie wielu transakcji w ramach kanału, przy czym do blockchain jest transmitowany tylko stan końcowy.

## Bitcoin Privacy Concerns

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** poprawiają anonimowość, ukrywając powiązania transakcji między użytkownikami.

## Acquiring Bitcoins Anonymously

Metody obejmują transakcje gotówkowe, mining i używanie mixers. **CoinJoin** miesza wiele transakcji, utrudniając śledzenie, natomiast **PayJoin** maskuje CoinJoins jako zwykłe transakcje, zwiększając prywatność.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

W świecie Bitcoin prywatność transakcji i anonimowość użytkowników są często przedmiotem zainteresowania. Oto uproszczony przegląd kilku popularnych metod, za pomocą których atakujący mogą naruszyć prywatność Bitcoin.

## **Common Input Ownership Assumption**

Zazwyczaj rzadko zdarza się, aby inputy różnych użytkowników były łączone w jednej transakcji ze względu na złożoność tego procesu. Dlatego **dwa addressy input w tej samej transakcji są często uznawane za należące do tego samego właściciela**.

## **UTXO Change Address Detection**

UTXO, czyli **Unspent Transaction Output**, musi zostać całkowicie wydany w transakcji. Jeśli tylko część jest wysyłana na inny address, pozostała kwota trafia na nowy change address. Obserwatorzy mogą założyć, że ten nowy address należy do nadawcy, co narusza prywatność.

### Example

Aby to ograniczyć, usługi mixingowe lub używanie wielu addressów mogą pomóc ukryć własność.

## **Social Networks & Forums Exposure**

Użytkownicy czasami udostępniają swoje addressy Bitcoin online, co sprawia, że **łatwo powiązać address z jego właścicielem**.

## **Transaction Graph Analysis**

Transakcje można wizualizować jako grafy, ujawniając potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ta heurystyka opiera się na analizie transakcji z wieloma inputami i outputami, aby odgadnąć, który output jest change zwracanym do nadawcy.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Jeśli dodanie większej liczby inputów sprawia, że change output jest większy niż którykolwiek pojedynczy input, może to zmylić heurystykę.

## **Forced Address Reuse**

Atakujący mogą wysyłać małe kwoty na wcześniej używane address, licząc, że odbiorca połączy je z innymi inputami w przyszłych transactions, przez co adresy zostaną ze sobą powiązane.

### Correct Wallet Behavior

Wallets powinny unikać używania coinów otrzymanych na już używanych, pustych addresses, aby zapobiec temu privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions bez change najpewniej zachodzą między dwoma address owned by the same user.
- **Round Numbers:** Zaokrąglona kwota w transaction sugeruje, że to payment, a niezaokrąglony output jest najpewniej change.
- **Wallet Fingerprinting:** Różne wallets mają unikalne wzorce tworzenia transactions, co pozwala analitykom zidentyfikować użyte software i potencjalnie change address.
- **Amount & Timing Correlations:** Ujawnienie czasu lub kwot transactions może sprawić, że będą one możliwe do śledzenia.

## **Traffic Analysis**

Monitorując network traffic, atakujący mogą potencjalnie powiązać transactions lub blocks z adresami IP, naruszając privacy userów. Jest to szczególnie prawdziwe, jeśli jakiś podmiot obsługuje wiele Bitcoin nodes, zwiększając swoją zdolność do monitorowania transactions.

## More

Aby uzyskać pełną listę privacy attacks i defenses, odwiedź [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Pozyskanie bitcoinów za gotówkę.
- **Cash Alternatives**: Zakup gift cards i wymiana ich online na bitcoin.
- **Mining**: Najbardziej prywatnym sposobem zarabiania bitcoinów jest mining, zwłaszcza gdy odbywa się solo, ponieważ mining pools mogą znać IP address minera. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretycznie kradzież bitcoinów mogłaby być kolejnym sposobem na anonimowe ich pozyskanie, choć jest to nielegalne i niezalecane.

## Mixing Services

Korzystając z mixing service, user może **wysłać bitcoins** i otrzymać w zamian **inne bitcoins**, co utrudnia ustalenie pierwotnego ownera. Wymaga to jednak zaufania, że service nie zachowa logs i faktycznie zwróci bitcoins. Alternatywą są Bitcoin casinos.

## CoinJoin

**CoinJoin** łączy wiele transactions od różnych userów w jedną, utrudniając proces każdemu, kto próbuje dopasować inputy do outputów. Mimo swojej skuteczności, transactions o unikalnych rozmiarach inputów i outputów nadal mogą być potencjalnie śledzone.

Przykładowe transactions, które mogły używać CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` oraz `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz w [CoinJoin](https://coinjoin.io/en). Podobną usługę w Ethereum sprawdź w [Tornado Cash](https://tornado.cash), która anonimizuje transactions za pomocą środków od miners.

## PayJoin

Wariant CoinJoin, **PayJoin** (lub P2EP), maskuje transaction między dwiema stronami (np. customer i merchant) jako zwykłą transaction, bez charakterystycznych dla CoinJoin równych outputs. To sprawia, że wykrycie jest bardzo trudne i może unieważniać common-input-ownership heuristic używaną przez podmioty monitorujące transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje takie jak powyższa mogą być PayJoin, zwiększając prywatność, a jednocześnie pozostając nieodróżnialne od standardowych transakcji bitcoin.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody surveillance**, czyniąc je obiecującym rozwiązaniem w dążeniu do transactional privacy.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Aby zachować privacy i security, synchronizacja wallets z blockchain jest kluczowa. Wyróżniają się dwie metody:

- **Full node**: Pobierając cały blockchain, full node zapewnia maksymalną privacy. Wszystkie kiedykolwiek wykonane transakcje są przechowywane lokalnie, co uniemożliwia adversaries ustalenie, które transakcje lub addresses interesują usera.
- **Client-side block filtering**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchain, umożliwiając wallets identyfikowanie powiązanych transakcji bez ujawniania konkretnych zainteresowań network observers. Lightweight wallets pobierają te filtry, ściągając pełne bloki tylko wtedy, gdy zostanie znalezione dopasowanie z addressami usera.

## **Utilizing Tor for Anonymity**

Biorąc pod uwagę, że Bitcoin działa w sieci peer-to-peer, zalecane jest używanie Tor do maskowania adresu IP, co zwiększa privacy podczas interakcji z network.

## **Preventing Address Reuse**

Aby chronić privacy, kluczowe jest używanie nowego address dla każdej transakcji. Ponowne używanie addresses może naruszyć privacy przez powiązanie transakcji z tym samym podmiotem. Nowoczesne wallets zniechęcają do ponownego używania address dzięki swojej konstrukcji.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Podzielenie płatności na kilka transakcji może ukryć kwotę transaction, utrudniając privacy attacks.
- **Change avoidance**: Wybór transakcji, które nie wymagają change outputs, poprawia privacy przez zakłócanie change detection methods.
- **Multiple change outputs**: Jeśli unikanie change nie jest możliwe, generowanie wielu change outputs nadal może poprawić privacy.

# **Monero: A Beacon of Anonymity**

Monero odpowiada na potrzebę absolutnej anonymity w cyfrowych transakcjach, wyznaczając wysoki standard dla privacy.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas mierzy computational effort potrzebny do wykonania operations w Ethereum, wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (lub 0.00231 ETH) obejmuje gas limit i base fee, a także tip zachęcający miners. Userzy mogą ustawić max fee, aby upewnić się, że nie przepłacą, a nadwyżka zostaje zwrócona.

## **Executing Transactions**

Transakcje w Ethereum obejmują sender i recipient, którymi mogą być adresy user lub smart contract. Wymagają fee i muszą zostać mined. Niezbędne informacje w transakcji obejmują recipient, signature sendera, value, opcjonalne data, gas limit i fees. Co istotne, address sendera jest wyprowadzany z signature, więc nie trzeba go umieszczać w danych transakcji.

Te practices i mechanizmy są podstawą dla każdego, kto chce korzystać z cryptocurrencies, jednocześnie priorytetowo traktując privacy i security.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes include bypassing `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, and fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Gdy prover używa **zkVM** lub aplikacyjnego proof circuit do poświadczenia claim, verifier dowiaduje się jedynie, że **guest program wykonał się tak, jak został napisany**. Jeśli guest zawiera **unsafe deserialization**, **undefined behavior** lub **missing semantic constraints**, malicious prover może wygenerować proof, który się weryfikuje, podczas gdy **public metrics lub deklarowany invariant są fałszywe**.

### Unsafe deserialization inside proof guests

- Traktuj prywatne witness/circuit bytes jako **untrusted attacker input** nawet jeśli są ukryte przez proof.
- Unikaj deserializowania ich za pomocą niezweryfikowanych helperów, takich jak `rkyv::access_unchecked`, chyba że bytes zostały już wcześniej zweryfikowane poza tym kanałem.
- Enum discriminants, relative pointers, lengths i indexes pobrane z niezaufanych serialized data muszą zostać zweryfikowane, zanim wpłyną na control flow lub memory access.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Jeśli pole takie jak `op.kind` jest enum i atakujący może wstrzyknąć **discriminant spoza zakresu**, każdy downstream `match` na tej wartości staje się podejrzany.

### Jump-table / UB bypass

Jeśli Rust sprowadza duży `match` do **jump table**, nieprawidłowy enum discriminant może spowodować **undefined control flow**. Niebezpieczny wzorzec to:

1. Jeden `match` aktualizuje **security-critical counters/constraints**.
2. Drugi `match` wykonuje **real instruction semantics**.
3. Discriminant spoza zakresu indeksuje poza pierwszą jump table i trafia w kod powiązany z drugą.

Wynik: operacja nadal się wykonuje, ale ścieżka rozliczająca jest pominięta. W zkVM może to sfałszować dowody, które raportują niemożliwe metryki, takie jak mniej gates, mniej kosztownych operacji albo inne podrobione bounded resources.

Checklist do review:

- Szukaj enum kontrolowanych przez atakującego, deserializowanych z witness/private input.
- Sprawdzaj powtarzające się instrukcje `match` nad tym samym polem opcode/kind.
- Traktuj `unsafe` + unchecked deserialization + duży opcode dispatch jako kombinację wysokiego ryzyka.
- W razie potrzeby reverse engineer wygenerowany binarny plik; układ jump table może mieć większe znaczenie niż source.

### Brak constraints semantycznych w reversible/specialized interpreters

Nie sprawdzaj tylko bezpieczeństwa pamięci; sprawdzaj też **semantic rules**, które proof ma egzekwować.

Dla reversible/quantum-like instruction sets upewnij się, że operandy, które muszą być distinct, są faktycznie constrained to be distinct. Operacja podobna do Toffoli/CCX zaimplementowana jako:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
staje się niebezpieczne, jeśli gość nie odrzuca:
```text
op.q_control1 == op.q_control2 == op.q_target
```
W takim przypadku przejście sprowadza się do:
```text
q = q ^ (q & q) = 0
```
This creates a **deterministic reset primitive**, breaking reversibility assumptions and enabling cheaper non-intended computations. In proof systems that attest resource usage, this can let attackers satisfy functional checks while bypassing the cost model the verifier believes is being enforced.

### Co testować w systemach ZK

- Fuzz all guest parsers with malformed witness/private-input encodings.
- Assert enum range validation before opcode dispatch.
- Add semantic checks for operand aliasing and other invalid instruction forms.
- Compare reported/public counters against an independent reference implementation.
- Remember that a valid proof can still prove the **wrong statement** if the guest program is buggy.

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
