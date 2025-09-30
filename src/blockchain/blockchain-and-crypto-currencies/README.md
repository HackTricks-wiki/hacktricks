# Blockchain i Kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Smart Contracts** są definiowane jako programy, które wykonują się na blockchainie, gdy spełnione są określone warunki, automatyzując realizację umów bez pośredników.
- **Decentralized Applications (dApps)** opierają się na smart contracts, oferując przyjazny dla użytkownika front-end oraz przejrzysty, audytowalny back-end.
- **Tokens & Coins** rozróżniają się tym, że coins służą jako cyfrowe pieniądze, podczas gdy tokens reprezentują wartość lub własność w określonych kontekstach.
- **Utility Tokens** dają dostęp do usług, a **Security Tokens** oznaczają własność aktywów.
- **DeFi** oznacza Decentralized Finance, oferując usługi finansowe bez centralnych władz.
- **DEX** i **DAOs** odnoszą się odpowiednio do Decentralized Exchange Platforms i Decentralized Autonomous Organizations.

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczną i uzgodnioną weryfikację transakcji w blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga, aby walidatorzy posiadali określoną ilość tokenów, redukując zużycie energii w porównaniu do PoW.

## Podstawy Bitcoina

### Transakcje

Transakcje Bitcoin polegają na przesyłaniu środków między adresami. Transakcje są weryfikowane za pomocą podpisów cyfrowych, co zapewnia, że tylko właściciel klucza prywatnego może inicjować przelewy.

#### Kluczowe elementy:

- **Multisignature Transactions** wymagają wielu podpisów do autoryzacji transakcji.
- Transakcje składają się z **inputs** (źródło środków), **outputs** (miejsce docelowe), **fees** (płaconych górnikom) i **scripts** (zasady transakcji).

### Lightning Network

Ma na celu poprawę skalowalności Bitcoina poprzez umożliwienie wielu transakcji wewnątrz kanału, wysyłając do blockchaina jedynie stan końcowy.

## Zagadnienia prywatności Bitcoina

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** zwiększają anonimowość, zaciemniając powiązania transakcji między użytkownikami.

## Pozyskiwanie Bitcoinów anonimowo

Metody obejmują transakcje za gotówkę, mining oraz użycie mixers. **CoinJoin** miesza wiele transakcji, aby utrudnić śledzenie, podczas gdy **PayJoin** maskuje CoinJoins jako zwykłe transakcje dla zwiększenia prywatności.

# Ataki na prywatność Bitcoina

# Podsumowanie ataków na prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników często budzą obawy. Oto uproszczony przegląd kilku powszechnych metod, za pomocą których atakujący mogą naruszyć prywatność Bitcoina.

## **Common Input Ownership Assumption**

Zwykle rzadko zdarza się, by inputs od różnych użytkowników były łączone w jednej transakcji ze względu na złożoność tego procesu. Dlatego **dwa adresy input w tej samej transakcji często uznaje się za należące do tego samego właściciela**.

## **UTXO Change Address Detection**

UTXO, czyli **Unspent Transaction Output**, musi zostać w całości wykorzystany w transakcji. Jeśli tylko część zostanie wysłana na inny adres, reszta trafia na nowy change address. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza prywatność.

### Przykład

Aby to złagodzić, usługi mixingowe lub korzystanie z wielu adresów mogą pomóc zaciemnić własność.

## **Social Networks & Forums Exposure**

Użytkownicy czasami udostępniają swoje adresy Bitcoin online, co sprawia, że **łatwo jest powiązać adres z jego właścicielem**.

## **Transaction Graph Analysis**

Transakcje można wizualizować jako grafy, ujawniając potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ta heurystyka opiera się na analizie transakcji z wieloma inputs i outputs w celu odgadnięcia, który output jest change zwracającym się do nadawcy.

### Przykład
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Atakujący mogą wysyłać małe kwoty na wcześniej używane adresy, licząc że odbiorca połączy je z innymi inputs w przyszłych transakcjach, w ten sposób łącząc adresy.

### Correct Wallet Behavior

Wallets powinny unikać używania coins otrzymanych na już użytych, pustych adresach, aby zapobiec temu privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcje bez change są prawdopodobnie między dwoma adresami należącymi do tego samego użytkownika.
- **Round Numbers:** Zaokrąglona kwota w transakcji sugeruje płatność, a niezaokrąglone wyjście prawdopodobnie jest change.
- **Wallet Fingerprinting:** Różne wallets mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować używane oprogramowanie i potencjalnie change address.
- **Amount & Timing Correlations:** Ujawnienie czasu lub kwoty transakcji może uczynić transakcje śledzalnymi.

## **Traffic Analysis**

Monitorując network traffic, attackers mogą potencjalnie powiązać transakcje lub bloki z adresami IP, kompromitując prywatność użytkowników. Jest to szczególnie prawdziwe, jeśli podmiot obsługuje wiele Bitcoin nodes, zwiększając swoją zdolność do monitorowania transakcji.

## More

Aby uzyskać pełną listę ataków na prywatność i obrony, odwiedź [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Pozyskanie bitcoin za gotówkę.
- **Cash Alternatives**: Kupowanie gift cards i wymiana ich online na bitcoin.
- **Mining**: Najbardziej prywatna metoda zdobywania bitcoinów to mining, szczególnie gdy wykonywana solo, ponieważ mining pools mogą znać IP kopacza. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretycznie kradzież bitcoinów mogłaby być metodą anonimowego pozyskania, choć jest to nielegalne i niezalecane.

## Mixing Services

Używając mixing service, użytkownik może wysłać bitcoins i otrzymać inne bitcoins w zamian, co utrudnia śledzenie pierwotnego właściciela. Wymaga to jednak zaufania do usługi, że nie będzie przechowywać logów i że faktycznie zwróci bitcoins. Alternatywne opcje mixingowe obejmują Bitcoin casinos.

## CoinJoin

CoinJoin łączy wiele transakcji od różnych użytkowników w jedną, komplikując proces dopasowywania inputs do outputs. Pomimo skuteczności, transakcje z unikalnymi rozmiarami inputów i outputów nadal mogą być potencjalnie śledzone.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje takie jak powyższa mogą być PayJoin, zwiększając prywatność przy pozostawaniu nie do odróżnienia od standardowych transakcji bitcoin.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody nadzoru**, co czyni go obiecującym rozwiązaniem w dążeniu do prywatności transakcyjnej.

# Najlepsze praktyki prywatności w kryptowalutach

## **Techniki synchronizacji portfeli**

Aby zachować prywatność i bezpieczeństwo, synchronizacja portfeli z blockchainem jest kluczowa. Wyróżniają się dwie metody:

- **Full node**: Poprzez pobranie całego blockchainu, Full node zapewnia maksymalną prywatność. Wszystkie kiedykolwiek wykonane transakcje są przechowywane lokalnie, przez co przeciwnicy nie są w stanie ustalić, które transakcje lub adresy interesują użytkownika.
- **Client-side block filtering**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, pozwalając portfelom identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lightweight wallets pobierają te filtry, pobierając pełne bloki tylko wtedy, gdy zostanie znalezione dopasowanie do adresów użytkownika.

## **Wykorzystanie Tor dla anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się używanie Tor do maskowania adresu IP, co zwiększa prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu użyciu adresu**

Aby chronić prywatność, ważne jest używanie nowego adresu przy każdej transakcji. Ponowne użycie adresów może zagrozić prywatności poprzez powiązanie transakcji z tym samym podmiotem. Nowoczesne portfele zniechęcają do ponownego używania adresów poprzez swój projekt.

## **Strategie prywatności transakcji**

- **Multiple transactions**: Podzielenie płatności na kilka transakcji może ukryć kwotę transakcji, uniemożliwiając ataki na prywatność.
- **Change avoidance**: Wybieranie transakcji, które nie wymagają wyjść z resztą (change outputs), zwiększa prywatność poprzez zakłócanie metod wykrywania reszty.
- **Multiple change outputs**: Jeśli uniknięcie reszty nie jest możliwe, wygenerowanie wielu change outputs może i tak poprawić prywatność.

# **Monero: Latarnia anonimowości**

Monero odpowiada na potrzebę absolutnej anonimowości w transakcjach cyfrowych, ustanawiając wysoki standard prywatności.

# **Ethereum: Gas i transakcje**

## **Zrozumienie Gas**

Gas mierzy wysiłek obliczeniowy potrzebny do wykonania operacji na Ethereum, wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) obejmuje limit gas, opłatę bazową i tip jako zachętę dla górników. Użytkownicy mogą ustawić maksymalną opłatę, aby nie przepłacić — nadpłata jest zwracana.

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być zarówno adresy użytkowników, jak i smart contract. Wymagają opłaty i muszą zostać potwierdzone przez górników. Podstawowe informacje w transakcji to odbiorca, podpis nadawcy, wartość, opcjonalne dane, limit gas i opłaty. Co istotne, adres nadawcy jest wyprowadzany z podpisu, co eliminuje potrzebę umieszczania go w danych transakcji.

Te praktyki i mechanizmy są podstawą dla każdego, kto chce korzystać z kryptowalut, priorytetowo traktując prywatność i bezpieczeństwo.

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
