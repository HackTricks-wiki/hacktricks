# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** są definiowane jako programy wykonujące się na blockchainie, gdy spełnione są określone warunki, automatyzując realizację umów bez pośredników.
- **Decentralized Applications (dApps)** budują się w oparciu o smart contracty, posiadając przyjazny dla użytkownika front-end i przejrzysty, audytowalny back-end.
- **Tokens & Coins** rozróżniają się tym, że coins służą jako cyfrowe pieniądze, podczas gdy tokens reprezentują wartość lub własność w określonych kontekstach.
- **Utility Tokens** dają dostęp do usług, a **Security Tokens** oznaczają posiadanie aktywów.
- **DeFi** oznacza Decentralized Finance, oferując usługi finansowe bez centralnych władz.
- **DEX** i **DAOs** odnoszą się odpowiednio do Decentralized Exchange Platforms i Decentralized Autonomous Organizations.

## Consensus Mechanisms

Mechanizmy konsensusu zapewniają bezpieczną i zgodną weryfikację transakcji na blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej ilości tokenów, zmniejszając zużycie energii w porównaniu z PoW.

## Bitcoin Essentials

### Transactions

Transakcje Bitcoin polegają na przesyłaniu środków między adresami. Transakcje są weryfikowane za pomocą podpisów cyfrowych, co zapewnia, że tylko właściciel klucza prywatnego może inicjować transfery.

#### Key Components:

- **Multisignature Transactions** wymagają wielu podpisów do autoryzacji transakcji.
- Transakcje składają się z **inputs** (źródło środków), **outputs** (cel), **fees** (opłacane minerom) oraz **scripts** (reguły transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoina, pozwalając na wielokrotne transakcje w ramach kanału, a jedynie końcowy stan jest broadcastowany do blockchaina.

## Bitcoin Privacy Concerns

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** poprawiają anonimowość poprzez zaciemnianie powiązań transakcji między użytkownikami.

## Acquiring Bitcoins Anonymously

Metody obejmują transakcje gotówkowe, mining oraz korzystanie z mixers. **CoinJoin** miesza wiele transakcji, aby utrudnić śledzenie, podczas gdy **PayJoin** maskuje CoinJoins jako zwykłe transakcje dla zwiększenia prywatności.

# Bitcoin — ataki na prywatność

# Podsumowanie ataków na prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników często budzą obawy. Oto uproszczony przegląd kilku powszechnych metod, za pomocą których atakujący mogą naruszyć prywatność Bitcoina.

## **Założenie wspólnej własności wejść**

Rzadko zdarza się, by inputs od różnych użytkowników były łączone w jednej transakcji ze względu na złożoność procesu. W związku z tym **dwa adresy wejściowe w tej samej transakcji są często uznawane za należące do tego samego właściciela**.

## **Wykrywanie adresu resztkowego UTXO**

UTXO, czyli **Unspent Transaction Output**, musi zostać w całości wykorzystany w transakcji. Jeśli tylko jej część jest wysłana na inny adres, pozostała część trafia na nowy adres resztkowy. Obserwatorzy mogą założyć, że nowy adres należy do nadawcy, co narusza prywatność.

### Przykład

Aby temu przeciwdziałać, usługi mieszające lub używanie wielu adresów może pomóc w zaciemnieniu własności.

## **Ujawnianie na portalach społecznościowych i forach**

Użytkownicy czasami udostępniają swoje adresy Bitcoin publicznie, co sprawia, że **łatwo powiązać adres z jego właścicielem**.

## **Analiza grafu transakcji**

Transakcje można wizualizować jako grafy, ujawniając potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Heurystyka zbędnych wejść (heurystyka optymalnej reszty)**

Ta heurystyka opiera się na analizie transakcji z wieloma inputs i outputs, aby zgadnąć, który output jest resztą zwracaną nadawcy.

### Przykład
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Jeśli dodanie większej liczby inputów powoduje, że wartość wyjścia reszty jest większa niż którykolwiek pojedynczy input, może to zmylić heurystykę.

## **Forced Address Reuse**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc, że odbiorca połączy je z innymi inputami w przyszłych transakcjach, łącząc w ten sposób adresy.

### Correct Wallet Behavior

Portfele powinny unikać wykorzystywania coinów otrzymanych na już używanych, pustych adresach, aby zapobiec temu privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcje bez change są prawdopodobnie między dwoma adresami należącymi do tego samego użytkownika.
- **Round Numbers:** Zaokrąglona wartość w transakcji sugeruje, że jest to płatność, a niezaokrąglone wyjście najprawdopodobniej jest change.
- **Wallet Fingerprinting:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować używane oprogramowanie i potencjalnie adres change.
- **Amount & Timing Correlations:** Ujawnienie czasu lub kwot transakcji może uczynić je namierzalnymi.

## **Traffic Analysis**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkownika. Szczególnie prawdziwe, jeśli podmiot obsługuje wiele węzłów Bitcoin, co zwiększa jego zdolność do monitorowania transakcji.

## More

Aby uzyskać kompleksową listę ataków na prywatność i obrony, odwiedź [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby zdobycia Bitcoinów anonimowo

- **Cash Transactions**: Nabycie bitcoinów za gotówkę.
- **Cash Alternatives**: Kupowanie kart podarunkowych i wymiana ich online na bitcoiny.
- **Mining**: Najbardziej prywatną metodą zarabiania bitcoinów jest mining, zwłaszcza gdy robi się to solo, ponieważ mining pools mogą znać adres IP minera. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretycznie kradzież bitcoinów mogłaby być inną metodą ich anonimowego pozyskania, chociaż jest to nielegalne i niezalecane.

## Mixing Services

Korzystając z usługi mieszającej, użytkownik może **wysłać bitcoiny** i otrzymać **inne bitcoiny w zamian**, co utrudnia ustalenie pierwotnego właściciela. Jednak wymaga to zaufania do usługi, że nie będzie przechowywać logów i faktycznie zwróci bitcoiny. Alternatywne opcje mieszania obejmują kasyna Bitcoin.

## CoinJoin

CoinJoin łączy wiele transakcji od różnych użytkowników w jedną, utrudniając dopasowanie inputów do outputów. Pomimo skuteczności, transakcje z unikalnymi rozmiarami inputów i outputów wciąż mogą być śledzone.

Przykładowe transakcje, które mogły używać CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji: odwiedź [CoinJoin](https://coinjoin.io/en). Dla podobnej usługi na Ethereum sprawdź [Tornado Cash](https://tornado.cash), która anonimizuje transakcje za pomocą środków od minerów.

## PayJoin

Wariant CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję pomiędzy dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych równych wyjść typowych dla CoinJoin. To sprawia, że jest ona niezwykle trudna do wykrycia i może unieważnić heurystykę common-input-ownership używaną przez podmioty nadzorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje podobne do powyższych mogą być PayJoin, zwiększając prywatność, a jednocześnie pozostając nieodróżnialne od standardowych transakcji bitcoin.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody nadzoru**, co czyni je obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki dotyczące prywatności w kryptowalutach

## **Techniki synchronizacji walletów**

Aby zachować prywatność i bezpieczeństwo, kluczowa jest synchronizacja walletów z blockchainem. Dwie metody wyróżniają się:

- **Full node**: Pobierając cały blockchain, full node zapewnia maksymalną prywatność. Wszystkie kiedykolwiek wykonane transakcje są przechowywane lokalnie, co uniemożliwia przeciwnikom ustalenie, które transakcje lub adresy interesują użytkownika.
- **Client-side block filtering**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, pozwalając walletom identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lightweight wallets pobierają te filtry, pobierając pełne bloki tylko wtedy, gdy wystąpi dopasowanie do adresów użytkownika.

## **Wykorzystanie Tor dla anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się używanie Tor w celu ukrycia adresu IP, co zwiększa prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu używaniu adresów**

Aby chronić prywatność, ważne jest używanie nowego adresu do każdej transakcji. Ponowne użycie adresów może naruszyć prywatność poprzez łączenie transakcji z tym samym podmiotem. Nowoczesne wallety zniechęcają do ponownego użycia adresów poprzez swój design.

## **Strategie dla prywatności transakcji**

- **Multiple transactions**: Rozdzielenie płatności na kilka transakcji może zamazać informację o kwocie transakcji, utrudniając ataki na prywatność.
- **Change avoidance**: Wybieranie transakcji, które nie wymagają change outputs, poprawia prywatność, zaburzając metody wykrywania change.
- **Multiple change outputs**: Jeśli uniknięcie change nie jest możliwe, wygenerowanie wielu change outputs może nadal poprawić prywatność.

# **Monero: latarnia anonimowości**

Monero odpowiada na potrzebę absolutnej anonimowości w cyfrowych transakcjach, ustanawiając wysoki standard prywatności.

# **Ethereum: Gas i transakcje**

## **Zrozumienie Gas**

Gas mierzy nakład obliczeniowy potrzebny do wykonania operacji na Ethereum, wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) obejmuje limit gazu i opłatę bazową, oraz tip, aby zachęcić górników. Użytkownicy mogą ustawić max fee, by nie przepłacić — nadwyżka jest zwracana.

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart contractów. Wymagają opłaty i muszą zostać zminowane. Istotne informacje w transakcji to odbiorca, podpis nadawcy, wartość, opcjonalne dane, limit gazu i opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, co eliminuje potrzebę umieszczania go w danych transakcji.

Te praktyki i mechanizmy są podstawą dla każdego, kto chce uczestniczyć w kryptowalutach z priorytetem na prywatność i bezpieczeństwo.

## Value-Centric Web3 Red Teaming

- Sporządź inwentaryzację komponentów niosących wartość (signers, oracles, bridges, automation), aby zrozumieć, kto może przemieszczać środki i w jaki sposób.
- Mapuj każdy komponent do odpowiednich taktyk MITRE AADAPT, by ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków flash-loan/oracle/credential/cross-chain, aby zweryfikować wpływ i udokumentować eksploatowalne warunki wstępne.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitacja procesu podpisywania Web3

- Supply-chain tampering of wallet UIs może zmieniać EIP-712 payloads tuż przed podpisaniem, zbierając ważne podpisy do przejęć proxy opartych na delegatecall (np. nadpisanie slot-0 Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Typowe tryby awarii smart-accountów obejmują obchodzenie kontroli dostępu `EntryPoint`, niezapodpisane pola gazu, walidację stanową, replay ERC-1271 oraz wyciskanie opłat poprzez revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing w celu znalezienia martwych punktów w zestawach testowych:

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

Jeśli badacz praktycznej eksploatacji DEXes i AMMów (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) — sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Dla multi-asset weighted pools, które cachują virtual balances i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
