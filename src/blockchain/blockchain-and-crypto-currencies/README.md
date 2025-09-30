# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** są definiowane jako programy wykonywane na blockchainie, gdy spełnione są określone warunki, automatyzując wykonanie umów bez pośredników.
- **Decentralized Applications (dApps)** bazują na smart contracts, posiadając przyjazny dla użytkownika frontend oraz przejrzysty, audytowalny backend.
- **Tokens & Coins** rozróżniają się tym, że coins pełnią rolę cyfrowych pieniędzy, podczas gdy tokens reprezentują wartość lub własność w określonych kontekstach.
- **Utility Tokens** dają dostęp do usług, a **Security Tokens** oznaczają własność aktywów.
- **DeFi** oznacza Decentralized Finance, oferujące usługi finansowe bez centralnych organów.
- **DEX** i **DAOs** odnoszą się odpowiednio do Decentralized Exchange Platforms i Decentralized Autonomous Organizations.

## Consensus Mechanisms

Mechanizmy konsensusu zapewniają bezpieczną i zgodną walidację transakcji na blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej ilości tokenów, zmniejszając zużycie energii w porównaniu do PoW.

## Bitcoin Essentials

### Transactions

Transakcje Bitcoin polegają na przesyłaniu środków między adresami. Transakcje są walidowane za pomocą podpisów cyfrowych, co zapewnia, że tylko właściciel klucza prywatnego może inicjować transfery.

#### Key Components:

- **Multisignature Transactions** wymagają wielu podpisów do autoryzacji transakcji.
- Transakcje składają się z **inputs** (źródło środków), **outputs** (miejsce docelowe), **fees** (płacone górnikom) i **scripts** (reguły transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoina przez umożliwienie wielu transakcji w ramach kanału, przy jednoczesnym raportowaniu do blockchaina tylko stanu końcowego.

## Bitcoin Privacy Concerns

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** poprawiają anonimowość przez zaciemnianie powiązań transakcji między użytkownikami.

## Acquiring Bitcoins Anonymously

Metody obejmują transakcje gotówkowe, mining oraz użycie mixerów. **CoinJoin** miesza wiele transakcji, aby utrudnić śledzenie, podczas gdy **PayJoin** udaje zwykłe transakcje, żeby dodatkowo ukryć CoinJoins.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników są często przedmiotem obaw. Oto uproszczony przegląd kilku powszechnych metod, za pomocą których atakujący mogą naruszyć prywatność użytkowników Bitcoina.

## **Common Input Ownership Assumption**

Rzadko się zdarza, by inputs od różnych użytkowników były łączone w jednej transakcji ze względu na złożoność procesu. W związku z tym **dwa adresy źródłowe w tej samej transakcji są często uznawane za należące do tego samego właściciela**.

## **UTXO Change Address Detection**

UTXO, czyli Unspent Transaction Output, musi zostać w całości zużyte w transakcji. Jeśli tylko jej część zostanie wysłana na inny adres, pozostała część trafia na nowy adres change. Obserwatorzy mogą przypuszczać, że ten nowy adres należy do nadawcy, co narusza prywatność.

### Example

Aby to złagodzić, usługi mieszające lub używanie wielu adresów może pomóc w zaciemnieniu własności.

## **Social Networks & Forums Exposure**

Użytkownicy czasami udostępniają swoje adresy Bitcoin online, co sprawia, że **łatwo powiązać adres z jego właścicielem**.

## **Transaction Graph Analysis**

Transakcje można zwizualizować jako grafy, ujawniając potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ta heurystyka opiera się na analizie transakcji z wieloma inputs i outputs, aby odgadnąć, który output jest change zwracanym do nadawcy.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, mając nadzieję, że odbiorca połączy je z innymi inputs w przyszłych transakcjach, przez co adresy zostaną powiązane.

### Correct Wallet Behavior

Portfele powinny unikać używania coinów otrzymanych na już użyte, puste adresy, aby zapobiec temu privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcje bez change są prawdopodobnie między dwoma adresami należącymi do tego samego użytkownika.
- **Round Numbers:** Zaokrąglona kwota w transakcji sugeruje, że to płatność, a niezaokrąglone wyjście prawdopodobnie jest change.
- **Wallet Fingerprinting:** Różne wallets mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować używane oprogramowanie i potencjalnie change address.
- **Amount & Timing Correlations:** Ujawnienie czasu lub kwot transakcji może umożliwić ich wyśledzenie.

## **Traffic Analysis**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, kompromitując prywatność użytkownika. Szczególnie prawdziwe, jeśli podmiot obsługuje wiele węzłów Bitcoin, co zwiększa jego zdolność do monitorowania transakcji.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Pozyskanie bitcoin przez użycie gotówki.
- **Cash Alternatives**: Kupowanie gift cards i wymiana ich online na bitcoin.
- **Mining**: Najbardziej prywatną metodą zdobywania bitcoinów jest mining, szczególnie w trybie solo, ponieważ mining pools mogą znać adres IP górnika. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretycznie kradzież bitcoinów mogłaby być inną metodą ich anonimowego pozyskania, chociaż jest to nielegalne i niezalecane.

## Mixing Services

Korzystając z mixing service, użytkownik może **send bitcoins** i otrzymać **different bitcoins in return**, co utrudnia wyśledzenie pierwotnego właściciela. Jednak wymaga to zaufania do usługi, że nie prowadzi logów i rzeczywiście zwróci bitcoiny. Alternatywami mixingu są kasyna Bitcoin.

## CoinJoin

CoinJoin łączy wiele transakcji od różnych użytkowników w jedną, utrudniając dopasowanie inputs do outputs. Mimo skuteczności, transakcje o unikalnych rozmiarach inputs i outputs wciąż mogą być śledzone.

Przykładowe transakcje, które mogły używać CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych równych outputs typowych dla CoinJoin. To sprawia, że jest ona niezwykle trudna do wykrycia i może unieważnić common-input-ownership heuristic używaną przez podmioty nadzorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje takie jak powyższe mogą być PayJoin, zwiększając prywatność, jednocześnie pozostając nieodróżnialne od standardowych transakcji bitcoin.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody nadzoru**, czyniąc to obiecującym rozwiązaniem w dążeniu do prywatności transakcyjnej.

# Najlepsze praktyki dotyczące prywatności w kryptowalutach

## **Techniki synchronizacji portfeli**

Aby utrzymać prywatność i bezpieczeństwo, synchronizacja portfeli z blockchainem jest kluczowa. Wyróżniają się dwie metody:

- **Full node**: Pobierając cały blockchain, full node zapewnia maksymalną prywatność. Wszystkie kiedykolwiek dokonane transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom ustalenie, które transakcje lub adresy interesują użytkownika.
- **Client-side block filtering**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, co pozwala portfelom identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lightweight wallets pobierają te filtry, pobierając pełne bloki tylko wtedy, gdy znajdzie się dopasowanie do adresów użytkownika.

## **Wykorzystanie Tora dla anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tora, aby zamaskować swój adres IP, zwiększając prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu użyciu adresów**

Aby chronić prywatność, ważne jest używanie nowego adresu dla każdej transakcji. Ponowne użycie adresów może narazić prywatność przez powiązanie transakcji z tą samą jednostką. Nowoczesne portfele zniechęcają do ponownego użycia adresów przez swój projekt.

## **Strategie prywatności transakcji**

- **Multiple transactions**: Podzielenie płatności na kilka transakcji może zniekształcić widoczność kwoty transakcji, uniemożliwiając ataki na prywatność.
- **Change avoidance**: Wybieranie transakcji, które nie wymagają change outputs, zwiększa prywatność przez zakłócanie metod wykrywania change.
- **Multiple change outputs**: Jeśli uniknięcie change nie jest możliwe, wygenerowanie wielu change outputs może nadal poprawić prywatność.

# **Monero: bastion anonimowości**

Monero odpowiada na potrzebę absolutnej anonimowości w transakcjach cyfrowych, ustanawiając wysoki standard prywatności.

# **Ethereum: gas i transakcje**

## **Zrozumienie gas**

Gas mierzy nakład obliczeniowy potrzebny do wykonania operacji na Ethereum, wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) obejmuje limit gas i opłatę bazową, z napiwkiem dla górników. Użytkownicy mogą ustawić maksymalną opłatę, aby uniknąć przepłacenia; nadpłata jest zwracana.

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być zarówno adresy użytkowników, jak i smart contractów. Wymagają opłaty i muszą zostać zamnięte (mined). Istotne informacje w transakcji to odbiorca, podpis nadawcy, wartość, opcjonalne dane, limit gas i opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, co eliminuje konieczność umieszczania go w danych transakcji.

Te praktyki i mechanizmy są podstawą dla każdego, kto chce korzystać z kryptowalut, priorytetowo traktując prywatność i bezpieczeństwo.

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Źródła

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

{{#include ../../banners/hacktricks-training.md}}
