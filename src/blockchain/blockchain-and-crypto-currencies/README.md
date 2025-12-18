# Blockchain i Kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Smart Contracts** są definiowane jako programy, które wykonują się na blockchainie, gdy spełnione są określone warunki, automatyzując wykonanie umów bez pośredników.
- **Decentralized Applications (dApps)** opierają się na smart contracts i mają przyjazny dla użytkownika front-end oraz przejrzyste, audytowalne zaplecze.
- **Tokeny i monety (Tokens & Coins)** rozróżniają się tym, że monety służą jako cyfrowe pieniądze, podczas gdy tokeny reprezentują wartość lub własność w określonych kontekstach.
- **Utility Tokens** dają dostęp do usług, a **Security Tokens** oznaczają prawo własności do aktywów.
- **DeFi** to skrót od Decentralized Finance, oferujący usługi finansowe bez centralnych organów.
- **DEX** i **DAOs** odnoszą się odpowiednio do Decentralized Exchange Platforms i Decentralized Autonomous Organizations.

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczną i zgodną walidację transakcji na blockchainie:

- **Proof of Work (PoW)** polega na mocy obliczeniowej do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania pewnej ilości tokenów, zmniejszając zużycie energii w porównaniu do PoW.

## Podstawy Bitcoina

### Transakcje

Transakcje Bitcoina obejmują przesyłanie środków między adresami. Transakcje są weryfikowane za pomocą podpisów cyfrowych, co gwarantuje, że tylko właściciel klucza prywatnego może inicjować transfery.

#### Kluczowe składniki:

- **Multisignature Transactions** wymagają wielu podpisów do autoryzacji transakcji.
- Transakcje składają się z **inputs** (źródło środków), **outputs** (miejsce docelowe), **fees** (opłaty dla górników) oraz **scripts** (reguły transakcji).

### Lightning Network

Celem jest zwiększenie skalowalności Bitcoina przez umożliwienie wielu transakcji w kanale, przy jednoczesnym publikowaniu na blockchainie tylko stanu końcowego.

## Problemy z prywatnością Bitcoina

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** poprawiają anonimowość, zaciemniając powiązania transakcji między użytkownikami.

## Pozyskiwanie Bitcoinów anonimowo

Metody obejmują transakcje gotówkowe, mining oraz użycie mixerów. **CoinJoin** miesza wiele transakcji, aby utrudnić śledzenie, podczas gdy **PayJoin** maskuje CoinJoin jako zwykłe transakcje dla zwiększenia prywatności.

# Ataki na prywatność Bitcoina

# Podsumowanie ataków na prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników są często problematyczne. Poniżej uproszczony przegląd kilku powszechnych metod, dzięki którym atakujący mogą naruszyć prywatność Bitcoina.

## Założenie Common Input Ownership

Zazwyczaj rzadko zdarza się, by inputs od różnych użytkowników były łączone w jednej transakcji z powodu złożoności. Dlatego **dwa adresy będące inputami w tej samej transakcji często są uznawane za należące do tego samego właściciela**.

## Wykrywanie adresu zmiany UTXO (UTXO Change Address Detection)

UTXO, czyli **Unspent Transaction Output**, musi być całkowicie wykorzystany w transakcji. Jeśli tylko część jest wysłana na inny adres, pozostała część trafia na nowy adres zmiany. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza prywatność.

### Przykład

Aby to zmitigować, usługi mixingowe lub użycie wielu adresów mogą pomóc zaciemnić własność.

## Ujawnianie w sieciach społecznościowych i forach

Użytkownicy czasem udostępniają swoje adresy Bitcoin online, co sprawia, że **łatwo powiązać adres z jego właścicielem**.

## Analiza grafu transakcji

Transakcje można zwizualizować jako grafy, ujawniając potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## Heurystyka niepotrzebnych inputów (Unnecessary Input Heuristic / Optimal Change Heuristic)

Ta heurystyka opiera się na analizie transakcji z wieloma inputami i outputami, aby odgadnąć, który output jest resztą zwracaną nadawcy.

### Przykład
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Atakujący mogą wysyłać małe kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi inputami w przyszłych transakcjach, łącząc w ten sposób adresy.

### Correct Wallet Behavior

Portfele powinny unikać używania monet otrzymanych na już używanych, pustych adresach, aby zapobiec temu privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcje bez change są prawdopodobnie między dwoma adresami należącymi do tego samego użytkownika.
- **Round Numbers:** Okrągła kwota w transakcji sugeruje, że jest to płatność, a niestandardowy output prawdopodobnie jest change.
- **Wallet Fingerprinting:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować używane oprogramowanie i potencjalnie change address.
- **Amount & Timing Correlations:** Ujawnienie czasu lub kwot transakcji może uczynić transakcje możliwymi do prześledzenia.

## **Traffic Analysis**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, co zagraża prywatności użytkownika. Jest to szczególnie prawdziwe, jeśli podmiot obsługuje wiele węzłów Bitcoin, zwiększając swoją zdolność do monitorowania transakcji.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Pozyskanie bitcoin przez gotówkę.
- **Cash Alternatives**: Zakup kart podarunkowych i wymiana ich online na bitcoin.
- **Mining**: Najbardziej prywatny sposób na zdobycie bitcoin to mining, szczególnie wykonywany solo, ponieważ pule miningowe mogą znać adres IP górnika. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretycznie kradzież bitcoin mogłaby być inną metodą na anonimowe zdobycie ich, chociaż jest nielegalna i niezalecana.

## Mixing Services

By using a mixing service, a user can **send bitcoins** and receive **different bitcoins in return**, which makes tracing the original owner difficult. Yet, this requires trust in the service not to keep logs and to actually return the bitcoins. Alternative mixing options include Bitcoin casinos.

## CoinJoin

**CoinJoin** łączy wiele transakcji od różnych użytkowników w jedną, utrudniając dopasowanie inputów do outputów. Mimo skuteczności, transakcje z unikalnymi rozmiarami inputów i outputów mogą nadal być potencjalnie prześledzone.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), masks the transaction między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych równych outputów typowych dla CoinJoin. To sprawia, że jest niezwykle trudna do wykrycia i może unieważnić common-input-ownership heuristic używaną przez podmioty nadzorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje podobne do powyższych mogą być PayJoin, zwiększając prywatność, a jednocześnie pozostając nieodróżnialnymi od standardowych transakcji bitcoin.

**Wykorzystanie PayJoin może istotnie zakłócić tradycyjne metody nadzoru**, czyniąc to obiecującym kierunkiem w dążeniu do prywatności transakcyjnej.

# Najlepsze praktyki ochrony prywatności w kryptowalutach

## **Techniki synchronizacji portfeli**

Aby zachować prywatność i bezpieczeństwo, synchronizacja portfeli z blockchainem jest kluczowa. Wyróżniają się dwie metody:

- **Full node**: Poprzez pobranie całego blockchaina, full node zapewnia maksymalną prywatność. Wszystkie dokonane transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom ustalenie, które transakcje lub adresy interesują użytkownika.
- **Client-side block filtering**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, pozwalając portfelom identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry i pobierają pełne bloki tylko wtedy, gdy filtr dopasuje się do adresów użytkownika.

## **Korzystanie z Tor dla anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się używanie Tor do ukrycia adresu IP, co zwiększa prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu użyciu adresów**

Aby chronić prywatność, ważne jest używanie nowego adresu dla każdej transakcji. Ponowne użycie adresów może zagrozić prywatności, łącząc transakcje z tym samym podmiotem. Nowoczesne portfele zniechęcają do ponownego użycia adresów poprzez swoją konstrukcję.

## **Strategie prywatności transakcji**

- **Wiele transakcji**: Podzielenie płatności na kilka transakcji może ukryć kwotę transakcji, uniemożliwiając ataki na prywatność.
- **Unikanie wyjść na resztę**: Wybieranie transakcji, które nie wymagają wyjść na resztę, zwiększa prywatność, utrudniając wykrywanie reszty.
- **Wiele wyjść na resztę**: Jeśli uniknięcie wyjść na resztę nie jest możliwe, wygenerowanie wielu wyjść na resztę może nadal poprawić prywatność.

# **Monero: wzorzec anonimowości**

Monero odpowiada na potrzebę absolutnej anonimowości w transakcjach cyfrowych, wyznaczając wysoki standard prywatności.

# **Ethereum: Gas i transakcje**

## **Zrozumienie gas**

Gas mierzy wysiłek obliczeniowy potrzebny do wykonania operacji na Ethereum, wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) obejmuje limit gas i base fee oraz napiwek (tip) motywujący górników. Użytkownicy mogą ustawić max fee, aby nie przepłacić; nadwyżka jest zwracana.

## **Wykonywanie transakcji**

Transakcje w Ethereum angażują nadawcę i odbiorcę, którymi mogą być zarówno adresy użytkowników, jak i smart contractów. Wymagają opłaty i muszą zostać zakonfirmowane (mined). Kluczowe informacje w transakcji to odbiorca, podpis nadawcy, wartość, opcjonalne dane, gas limit i opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, co eliminuje konieczność umieszczania go explicite w danych transakcji.

Te praktyki i mechanizmy są fundamentem dla każdego, kto chce uczestniczyć w świecie kryptowalut, priorytetowo traktując prywatność i bezpieczeństwo.

## Value-Centric Web3 Red Teaming

- Sporządź inwentarz komponentów przechowujących wartość (signers, oracles, bridges, automation), aby zrozumieć, kto i w jaki sposób może przemieszczać środki.
- Mapuj każdy komponent do odpowiednich taktyk MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz ciągi ataków flash-loan/oracle/credential/cross-chain, aby zweryfikować wpływ i udokumentować podatne warunki wstępne.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

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

## Eksploatacja DeFi/AMM

Jeśli badacie praktyczną eksploatację DEXów i AMM (Uniswap v4 hooks, nadużycia zaokrągleń/precyzji, swapy przekraczające progi wzmocnione flash‑loan), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Dla multi-asset weighted pools, które buforują (cache) wirtualne salda i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
