# Blockchain i Kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Smart Contracts** są definiowane jako programy, które wykonują się na blockchainie, gdy spełnione są określone warunki, automatyzując wykonywanie umów bez pośredników.
- **Decentralized Applications (dApps)** opierają się na Smart Contracts, posiadając przyjazny front-end i przejrzyste, audytowalne back-endy.
- **Tokens & Coins** rozróżniają się tym, że coins pełnią rolę cyfrowych pieniędzy, podczas gdy tokens reprezentują wartość lub własność w określonych kontekstach.
- **Utility Tokens** dają dostęp do usług, a **Security Tokens** oznaczają własność aktywów.
- **DeFi** oznacza Decentralized Finance (zdecentralizowane finanse), oferując usługi finansowe bez centralnych władz.
- **DEX** i **DAOs** oznaczają odpowiednio Decentralized Exchange Platforms (zdecentralizowane platformy wymiany) i Decentralized Autonomous Organizations (zdecentralizowane organizacje autonomiczne).

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczną i uzgodnioną weryfikację transakcji w blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej ilości tokenów, zmniejszając zużycie energii w porównaniu z PoW.

## Podstawy Bitcoina

### Transakcje

Transakcje Bitcoin polegają na przesyłaniu środków między adresami. Transakcje są weryfikowane za pomocą podpisów cyfrowych, co zapewnia, że tylko właściciel klucza prywatnego może inicjować przelewy.

#### Kluczowe komponenty:

- **Multisignature Transactions** wymagają wielu podpisów do autoryzacji transakcji.
- Transakcje składają się z **inputs** (źródło środków), **outputs** (odbiorcy), **fees** (opłaty wypłacane górnikom) oraz **scripts** (zasady transakcji).

### Lightning Network

Lightning Network ma na celu zwiększenie skalowalności Bitcoina poprzez umożliwienie wielu transakcji w ramach kanału, przy jednoczesnym publikowaniu w blockchainie jedynie stanu końcowego.

## Obawy dotyczące prywatności Bitcoina

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** zwiększają anonimowość poprzez zaciemnianie powiązań transakcji między użytkownikami.

## Pozyskiwanie Bitcoinów anonimowo

Metody obejmują transakcje gotówkowe, kopanie oraz użycie mixers. **CoinJoin** miesza wiele transakcji, aby utrudnić śledzenie, podczas gdy **PayJoin** maskuje CoinJoins jako zwykłe transakcje w celu zwiększenia prywatności.

# Ataki na prywatność Bitcoina

# Podsumowanie ataków na prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników często budzą obawy. Poniżej uproszczony przegląd kilku powszechnych metod, dzięki którym atakujący mogą naruszyć prywatność Bitcoina.

## **Common Input Ownership Assumption**

Zazwyczaj rzadko zdarza się, by inputs od różnych użytkowników były łączone w jednej transakcji z powodu związanej z tym złożoności. W związku z tym **dwa adresy wejściowe (inputs) w tej samej transakcji są często uznawane za należące do tego samego właściciela**.

## **UTXO Change Address Detection**

UTXO, czyli **Unspent Transaction Output**, musi być wydane w całości w transakcji. Jeśli tylko część zostanie wysłana na inny adres, reszta trafia na nowy adres zmiany (change address). Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza prywatność.

### Przykład

Aby to ograniczyć, usługi mieszające lub użycie wielu adresów mogą pomóc zamaskować własność.

## **Social Networks & Forums Exposure**

Użytkownicy czasami udostępniają swoje adresy Bitcoin online, co sprawia, że **łatwo powiązać adres z jego właścicielem**.

## **Transaction Graph Analysis**

Transakcje można zwizualizować jako grafy, ujawniając potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ta heurystyka opiera się na analizie transakcji z wieloma inputs i outputs, aby odgadnąć, który output jest resztą zwracającą się do nadawcy.

### Przykład
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Wymuszone ponowne użycie adresu**

Atakujący mogą wysyłać małe kwoty na wcześniej używane adresy, licząc, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, w ten sposób łącząc adresy.

### Poprawne zachowanie portfela

Portfele powinny unikać używania bitcoinów otrzymanych na już użytych, pustych adresach, aby zapobiec temu privacy leak.

## **Inne techniki analizy blockchain**

- **Exact Payment Amounts:** Transakcje bez change prawdopodobnie dotyczą dwóch adresów należących do tego samego użytkownika.
- **Round Numbers:** Zaokrąglona kwota w transakcji sugeruje płatność, przy czym niezaokrąglony output prawdopodobnie jest change.
- **Wallet Fingerprinting:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować używane oprogramowanie i potencjalnie change address.
- **Amount & Timing Correlations:** Ujawnienie czasów lub kwot transakcji może uczynić je możliwymi do namierzenia.

## **Analiza ruchu**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Szczególnie dotyczy to podmiotów, które obsługują wiele węzłów Bitcoin, co zwiększa ich zdolność do monitorowania transakcji.

## More

Aby uzyskać kompleksową listę ataków na prywatność i środków obrony, odwiedź [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby na pozyskanie Bitcoinów anonimowo

- **Cash Transactions**: Pozyskiwanie bitcoinów za pomocą gotówki.
- **Cash Alternatives**: Kupowanie kart podarunkowych i wymiana ich online na bitcoin.
- **Mining**: Najbardziej prywatną metodą zdobywania bitcoinów jest mining, szczególnie gdy jest wykonywane solo, ponieważ pule miningowe mogą znać IP minera. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretycznie kradzież bitcoinów mogłaby być inną metodą ich pozyskania anonimowo, choć jest to nielegalne i niezalecane.

## Usługi mieszające

Korzystając z usługi mieszającej, użytkownik może **wysłać bitcoiny** i otrzymać **inne bitcoiny w zamian**, co utrudnia wyśledzenie pierwotnego właściciela. Wymaga to jednak zaufania do usługi, że nie prowadzi logów i faktycznie zwróci bitcoiny. Alternatywy do mixingu obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji od różnych użytkowników w jedną, utrudniając dopasowanie inputów do outputów. Pomimo skuteczności, transakcje o unikalnych rozmiarach inputów i outputów nadal mogą być śledzone.

Przykładowe transakcje, które mogły użyć CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` oraz `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

Wariant CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych równych outputs typowych dla CoinJoin. To czyni ją niezwykle trudną do wykrycia i może unieważnić common-input-ownership heuristic stosowaną przez podmioty nadzorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje takie jak powyższa mogą być PayJoin, zwiększając prywatność przy jednoczesnym pozostawaniu nieodróżnialnymi od standardowych transakcji bitcoin.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody nadzoru**, co czyni go obiecującym rozwiązaniem w dążeniu do prywatności transakcyjnej.

# Najlepsze praktyki prywatności w kryptowalutach

## **Techniki synchronizacji Wallet**

Aby zachować prywatność i bezpieczeństwo, synchronizacja wallet z blockchainem jest kluczowa. Wyróżniają się dwie metody:

- **Full node**: Pobierając cały blockchain, Full node zapewnia maksymalną prywatność. Wszystkie dokonane transakcje są przechowywane lokalnie, co uniemożliwia osobom trzecim ustalenie, które transakcje lub adresy interesują użytkownika.
- **Client-side block filtering**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, pozwalając walletom identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lightweight wallets pobierają te filtry, pobierając pełne bloki tylko wtedy, gdy znajdzie się dopasowanie do adresów użytkownika.

## **Korzystanie z Tor dla anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się używanie Tor w celu zamaskowania adresu IP, co zwiększa prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu użyciu adresu**

Aby chronić prywatność, ważne jest używanie nowego adresu dla każdej transakcji. Ponowne użycie adresów może zagrozić prywatności poprzez powiązanie transakcji z tym samym podmiotem. Nowoczesne wallety zniechęcają do ponownego użycia adresów przez swoje projektowanie.

## **Strategie dla prywatności transakcji**

- **Multiple transactions**: Podział płatności na kilka transakcji może zacierać kwotę transakcji, przeciwdziałając atakom na prywatność.
- **Change avoidance**: Wybieranie transakcji, które nie wymagają change outputs, zwiększa prywatność przez utrudnienie metod wykrywania change.
- **Multiple change outputs**: Jeśli uniknięcie change nie jest możliwe, wygenerowanie wielu change outputs może nadal poprawić prywatność.

# **Monero: Latarnia anonimowości**

Monero odpowiada na potrzebę absolutnej anonimowości w transakcjach cyfrowych, ustanawiając wysoki standard prywatności.

# **Ethereum: Gas i transakcje**

## **Zrozumienie Gas**

Gas mierzy wysiłek obliczeniowy potrzebny do wykonania operacji na Ethereum, wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) obejmuje gas limit i base fee oraz tip, aby zachęcić minerów. Użytkownicy mogą ustawić max fee, aby nie przepłacić — nadmiar jest zwracany.

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart contract. Wymagają opłaty i muszą zostać zminowane. Istotne informacje w transakcji to odbiorca, podpis nadawcy, wartość, opcjonalne dane, gas limit oraz opłaty. Co istotne, adres nadawcy jest wyprowadzany z podpisu, dzięki czemu nie trzeba go umieszczać w danych transakcji.

Te praktyki i mechanizmy są podstawą dla każdego, kto chce angażować się w kryptowaluty, priorytetyzując prywatność i bezpieczeństwo.

## Value-Centric Web3 Red Teaming

- Inwentaryzuj komponenty niosące wartość (signers, oracles, bridges, automation), aby zrozumieć, kto może przemieszczać środki i w jaki sposób.
- Odwzoruj każdy komponent do odpowiednich MITRE AADAPT tactics, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków flash-loan/oracle/credential/cross-chain, aby zweryfikować wpływ i udokumentować warunki umożliwiające eksploatację.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs może modyfikować EIP-712 payloads tuż przed podpisaniem, pozyskując prawidłowe podpisy do delegatecall-based proxy takeovers (np. nadpisanie slot-0 Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Smart Contract Security

- Mutation testing, aby znaleźć słabe punkty w zestawach testów:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
