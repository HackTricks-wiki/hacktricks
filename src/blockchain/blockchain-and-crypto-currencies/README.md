# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** są definiowane jako programy wykonujące się na blockchainie, gdy spełnione są określone warunki, automatyzując realizację umów bez pośredników.
- **Decentralized Applications (dApps)** bazują na smart contractach i posiadają przyjazny dla użytkownika front-end oraz przejrzyste, audytowalne zaplecze.
- **Tokens & Coins** rozróżniają się tym, że coins służą jako cyfrowe pieniądze, podczas gdy tokens reprezentują wartość lub własność w określonych kontekstach.
- **Utility Tokens** dają dostęp do usług, a **Security Tokens** oznaczają posiadanie aktywów.
- **DeFi** oznacza Decentralized Finance, zapewniając usługi finansowe bez centralnych władz.
- **DEX** i **DAOs** odnoszą się odpowiednio do Decentralized Exchange Platforms i Decentralized Autonomous Organizations.

## Consensus Mechanisms

Mechanizmy konsensusu zapewniają bezpieczną i zgodną walidację transakcji na blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej ilości tokenów, zmniejszając zużycie energii w porównaniu z PoW.

## Bitcoin Essentials

### Transactions

Transakcje Bitcoin polegają na przekazywaniu środków między adresami. Transakcje są walidowane za pomocą podpisów cyfrowych, co zapewnia, że tylko właściciel klucza prywatnego może inicjować przekazy.

#### Key Components:

- **Multisignature Transactions** wymagają wielu podpisów do autoryzacji transakcji.
- Transakcje składają się z **inputs** (źródło środków), **outputs** (miejsce docelowe), **fees** (płacone minerom) oraz **scripts** (reguły transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoina przez umożliwienie wielu transakcji w obrębie kanału, przy jednoczesnym publikowaniu na blockchainie tylko stanu końcowego.

## Bitcoin Privacy Concerns

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** poprawiają anonimowość poprzez zaciemnianie powiązań między transakcjami użytkowników.

## Acquiring Bitcoins Anonymously

Metody obejmują transakcje za gotówkę, mining oraz użycie mixerów. **CoinJoin** miesza wiele transakcji, aby utrudnić śledzenie, podczas gdy **PayJoin** maskuje CoinJoin jako zwykłe transakcje dla zwiększenia prywatności.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników często budzą obawy. Oto uproszczone zestawienie kilku powszechnych metod, dzięki którym atakujący mogą naruszyć prywatność Bitcoina.

## **Common Input Ownership Assumption**

Zwykle rzadko łączy się inputy od różnych użytkowników w jednej transakcji z powodu złożoności z tym związanej. Dlatego **dwa adresy będące inputami w tej samej transakcji są często zakładane jako należące do tego samego właściciela**.

## **UTXO Change Address Detection**

UTXO, czyli **Unspent Transaction Output**, musi zostać w całości wydane w transakcji. Jeśli tylko część zostanie wysłana na inny adres, pozostałość trafia na nowy adres change. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza prywatność.

### Example

Aby to złagodzić, usługi mixingowe lub używanie wielu adresów może pomóc w zaciemnieniu własności.

## **Social Networks & Forums Exposure**

Użytkownicy czasem udostępniają swoje adresy Bitcoin online, co sprawia, że **łatwo powiązać adres z jego właścicielem**.

## **Transaction Graph Analysis**

Transakcje można wizualizować jako grafy, ujawniając potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ta heurystyka opiera się na analizie transakcji z wieloma inputami i outputami, aby odgadnąć, który output jest change zwracanym nadawcy.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Jeśli dodanie większej liczby wejść (inputs) sprawia, że wyjście z resztą (change output) jest większe niż któreś pojedyncze wejście, może to zmylić heurystykę.

## **Wymuszone ponowne użycie adresu**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi inputami w przyszłych transakcjach, łącząc w ten sposób adresy.

### Prawidłowe zachowanie portfela

Portfele powinny unikać używania środków otrzymanych na już używanych, pustych adresach, aby zapobiec temu privacy leak.

## **Inne techniki analizy blockchain**

- **Dokładne kwoty płatności:** Transakcje bez reszty są prawdopodobnie pomiędzy dwoma adresami należącymi do tego samego użytkownika.
- **Zaokrąglone liczby:** Zaokrąglona kwota w transakcji sugeruje, że to płatność, a niezaokrąglone wyjście prawdopodobnie jest resztą.
- **Fingerprinting portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować używane oprogramowanie i potencjalnie adres reszty.
- **Korelacje kwoty i czasu:** Ujawnienie czasu lub kwot transakcji może uczynić transakcje możliwymi do śledzenia.

## **Analiza ruchu sieciowego**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, narażając prywatność użytkowników. Szczególnie dotyczy to sytuacji, gdy podmiot obsługuje wiele węzłów Bitcoin, co zwiększa jego zdolność do monitorowania transakcji.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby zdobycia bitcoinów anonimowo

- **Transakcje gotówkowe**: Pozyskanie bitcoinów za gotówkę.
- **Alternatywy dla gotówki**: Kupowanie kart upominkowych i wymienianie ich online na bitcoiny.
- **Mining**: Najbardziej prywatną metodą zdobycia bitcoinów jest mining, zwłaszcza gdy odbywa się solo, ponieważ mining pools mogą znać adres IP górnika. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie kradzież bitcoinów mogłaby być kolejną metodą zdobycia ich anonimowo, choć jest to nielegalne i niezalecane.

## Usługi mieszające

Korzystając z usługi mieszającej, użytkownik może **wysłać bitcoiny** i otrzymać w zamian **inne bitcoiny**, co utrudnia powiązanie z pierwotnym właścicielem. Jednak wymaga to zaufania do usługi, że nie prowadzi logów i że rzeczywiście zwróci bitcoiny. Alternatywne opcje mieszania to kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji od różnych użytkowników w jedną, utrudniając dopasowanie inputów do outputów. Mimo skuteczności, transakcje z unikalnymi rozmiarami inputów i outputów nadal mogą być potencjalnie śledzone.

Przykładowe transakcje, które mogły używać CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

Wariant CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję pomiędzy dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych równych wyjść typowych dla CoinJoin. To sprawia, że jest niezwykle trudna do wykrycia i może unieważnić heurystykę common-input-ownership stosowaną przez podmioty monitorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje takie jak powyższe mogą być PayJoin, zwiększając prywatność i pozostając jednocześnie nieodróżnialne od standardowych transakcji bitcoin.

**Wykorzystanie PayJoin mogłoby znacząco zakłócić tradycyjne metody nadzoru**, co czyni je obiecującym rozwiązaniem w dążeniu do prywatności transakcyjnej.

# Najlepsze praktyki dotyczące prywatności w kryptowalutach

## **Techniki synchronizacji portfeli**

Aby zachować prywatność i bezpieczeństwo, synchronizacja portfeli z blockchainem jest kluczowa. Wyróżniają się dwie metody:

- **Full node**: Poprzez pobranie całego blockchaina, full node zapewnia maksymalną prywatność. Wszystkie kiedykolwiek wykonane transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom ustalenie, które transakcje lub adresy interesują użytkownika.
- **Client-side block filtering**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, co pozwala portfelom identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry, pobierając pełne bloki tylko wtedy, gdy znajdzie się dopasowanie do adresów użytkownika.

## **Wykorzystanie Tor dla anonimowości**

Biorąc pod uwagę, że Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor w celu ukrycia adresu IP, co zwiększa prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu użyciu adresów**

Aby chronić prywatność, ważne jest używanie nowego adresu przy każdej transakcji. Ponowne użycie adresów może zagrozić prywatności, łącząc transakcje z tą samą jednostką. Nowoczesne portfele zniechęcają do ponownego użycia adresów poprzez swoje zaprojektowanie.

## **Strategie prywatności transakcji**

- **Multiple transactions**: Podział płatności na kilka transakcji może zamaskować kwotę transakcji, utrudniając ataki na prywatność.
- **Change avoidance**: Wybór transakcji, które nie wymagają outputów change, zwiększa prywatność poprzez zakłócanie metod wykrywania change.
- **Multiple change outputs**: Jeśli uniknięcie change nie jest możliwe, wygenerowanie wielu outputów change nadal może poprawić prywatność.

# **Monero: latarnia anonimowości**

Monero odpowiada na potrzebę absolutnej anonimowości w transakcjach cyfrowych, ustanawiając wysoki standard prywatności.

# **Ethereum: Gas i transakcje**

## **Zrozumienie Gas**

Gas mierzy nakład obliczeniowy potrzebny do wykonania operacji w Ethereum, wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) obejmuje gas limit i base fee, z tipem, by zachęcić miners. Użytkownicy mogą ustawić max fee, aby nie przepłacać — nadmiar jest zwracany.

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart contract. Wymagają opłaty i muszą zostać mined. Istotne informacje w transakcji to odbiorca, podpis nadawcy, wartość, opcjonalne dane, gas limit i opłaty. Co ważne, adres nadawcy jest wyprowadzany z podpisu, co eliminuje konieczność umieszczania go w danych transakcji.

Te praktyki i mechanizmy stanowią podstawę dla każdego, kto chce korzystać z kryptowalut, priorytetowo traktując prywatność i bezpieczeństwo.

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

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
