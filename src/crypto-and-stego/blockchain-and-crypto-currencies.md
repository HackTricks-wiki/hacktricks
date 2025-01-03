{{#include ../banners/hacktricks-training.md}}

## Podstawowe Pojęcia

- **Smart Contracts** to programy, które wykonują się na blockchainie, gdy spełnione są określone warunki, automatyzując realizację umów bez pośredników.
- **Decentralized Applications (dApps)** opierają się na smart contracts, oferując przyjazny interfejs użytkownika oraz przejrzysty, audytowalny backend.
- **Tokens & Coins** różnią się tym, że monety służą jako cyfrowe pieniądze, podczas gdy tokeny reprezentują wartość lub własność w określonych kontekstach.
- **Utility Tokens** dają dostęp do usług, a **Security Tokens** oznaczają własność aktywów.
- **DeFi** oznacza Decentralized Finance, oferując usługi finansowe bez centralnych władz.
- **DEX** i **DAOs** odnoszą się do Decentralized Exchange Platforms i Decentralized Autonomous Organizations, odpowiednio.

## Mechanizmy Konsensusu

Mechanizmy konsensusu zapewniają bezpieczne i uzgodnione walidacje transakcji na blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga, aby walidatorzy posiadali określoną ilość tokenów, co zmniejsza zużycie energii w porównaniu do PoW.

## Podstawy Bitcoina

### Transakcje

Transakcje Bitcoinowe polegają na transferze środków między adresami. Transakcje są weryfikowane za pomocą podpisów cyfrowych, co zapewnia, że tylko właściciel klucza prywatnego może inicjować transfery.

#### Kluczowe Komponenty:

- **Multisignature Transactions** wymagają wielu podpisów do autoryzacji transakcji.
- Transakcje składają się z **inputs** (źródło funduszy), **outputs** (cel), **fees** (płatne górnikom) oraz **scripts** (zasady transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoina, pozwalając na wiele transakcji w ramach jednego kanału, transmitując tylko końcowy stan do blockchaina.

## Problemy z Prywatnością Bitcoina

Ataki na prywatność, takie jak **Common Input Ownership** i **UTXO Change Address Detection**, wykorzystują wzorce transakcji. Strategie takie jak **Mixers** i **CoinJoin** poprawiają anonimowość, zaciemniając powiązania transakcyjne między użytkownikami.

## Nabywanie Bitcoinów Anonimowo

Metody obejmują transakcje gotówkowe, kopanie oraz korzystanie z mixerów. **CoinJoin** łączy wiele transakcji, aby skomplikować śledzenie, podczas gdy **PayJoin** maskuje CoinJoins jako zwykłe transakcje dla zwiększonej prywatności.

# Ataki na Prywatność Bitcoina

# Podsumowanie Ataków na Prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników są często przedmiotem obaw. Oto uproszczony przegląd kilku powszechnych metod, za pomocą których napastnicy mogą naruszyć prywatność Bitcoina.

## **Założenie Własności Wspólnego Wejścia**

Zazwyczaj rzadko zdarza się, aby wejścia od różnych użytkowników były łączone w jednej transakcji z powodu związanej z tym złożoności. Dlatego **dwa adresy wejściowe w tej samej transakcji często zakłada się, że należą do tego samego właściciela**.

## **Wykrywanie Adresu Zmiany UTXO**

UTXO, czyli **Unspent Transaction Output**, musi być całkowicie wydany w transakcji. Jeśli tylko część z niego jest wysyłana na inny adres, reszta trafia na nowy adres zmiany. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza prywatność.

### Przykład

Aby to złagodzić, usługi miksujące lub korzystanie z wielu adresów mogą pomóc w zaciemnieniu własności.

## **Ekspozycja w Sieciach Społecznościowych i Forach**

Użytkownicy czasami dzielą się swoimi adresami Bitcoinowymi w Internecie, co sprawia, że **łatwo jest powiązać adres z jego właścicielem**.

## **Analiza Grafów Transakcji**

Transakcje można wizualizować jako grafy, ujawniające potencjalne powiązania między użytkownikami na podstawie przepływu funduszy.

## **Heurystyka Niepotrzebnego Wejścia (Heurystyka Optymalnej Zmiany)**

Ta heurystyka opiera się na analizie transakcji z wieloma wejściami i wyjściami, aby zgadnąć, które wyjście jest zmianą wracającą do nadawcy.

### Przykład
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Jeśli dodanie większej liczby wejść sprawia, że wyjście zmienia się na większe niż jakiekolwiek pojedyncze wejście, może to zmylić heurystykę.

## **Wymuszone Ponowne Użycie Adresu**

Napastnicy mogą wysyłać małe kwoty na wcześniej używane adresy, mając nadzieję, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, łącząc w ten sposób adresy.

### Prawidłowe Zachowanie Portfela

Portfele powinny unikać używania monet otrzymanych na już używanych, pustych adresach, aby zapobiec temu wyciekowi prywatności.

## **Inne Techniki Analizy Blockchain**

- **Dokładne Kwoty Płatności:** Transakcje bez reszty prawdopodobnie odbywają się między dwoma adresami należącymi do tego samego użytkownika.
- **Okrągłe Liczby:** Okrągła liczba w transakcji sugeruje, że jest to płatność, a nieokrągłe wyjście prawdopodobnie jest resztą.
- **Odcisk Portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować używane oprogramowanie i potencjalnie adres zmiany.
- **Korelacje Kwoty i Czasu:** Ujawnienie czasów lub kwot transakcji może sprawić, że transakcje będą śledzone.

## **Analiza Ruchu**

Monitorując ruch w sieci, napastnicy mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Jest to szczególnie prawdziwe, jeśli podmiot obsługuje wiele węzłów Bitcoin, co zwiększa ich zdolność do monitorowania transakcji.

## Więcej

Aby uzyskać pełną listę ataków na prywatność i obrony, odwiedź [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe Transakcje Bitcoin

## Sposoby na Uzyskanie Bitcoinów Anonimowo

- **Transakcje Gotówkowe**: Nabywanie bitcoinów za gotówkę.
- **Alternatywy Gotówkowe**: Zakup kart podarunkowych i wymiana ich online na bitcoiny.
- **Kopanie**: Najbardziej prywatną metodą zdobywania bitcoinów jest kopanie, szczególnie gdy jest wykonywane samodzielnie, ponieważ pule wydobywcze mogą znać adres IP górnika. [Informacje o Pulach Wydobywczych](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie, kradzież bitcoinów mogłaby być inną metodą na ich anonimowe zdobycie, chociaż jest to nielegalne i niezalecane.

## Usługi Mieszania

Korzystając z usługi mieszania, użytkownik może **wysłać bitcoiny** i otrzymać **inne bitcoiny w zamian**, co utrudnia śledzenie oryginalnego właściciela. Jednak wymaga to zaufania do usługi, aby nie prowadziła logów i rzeczywiście zwróciła bitcoiny. Alternatywne opcje mieszania obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji od różnych użytkowników w jedną, co komplikuje proces dla każdego, kto próbuje dopasować wejścia do wyjść. Pomimo swojej skuteczności, transakcje z unikalnymi rozmiarami wejść i wyjść mogą nadal być potencjalnie śledzone.

Przykładowe transakcje, które mogły używać CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Aby uzyskać więcej informacji, odwiedź [CoinJoin](https://coinjoin.io/en). Dla podobnej usługi na Ethereum, sprawdź [Tornado Cash](https://tornado.cash), która anonimizuje transakcje z funduszami od górników.

## PayJoin

Wariant CoinJoin, **PayJoin** (lub P2EP), ukrywa transakcję między dwiema stronami (np. klientem a sprzedawcą) jako zwykłą transakcję, bez charakterystycznych równych wyjść typowych dla CoinJoin. To sprawia, że jest niezwykle trudne do wykrycia i może unieważnić heurystykę wspólnego posiadania wejść używaną przez podmioty monitorujące transakcje.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcje takie jak powyższe mogą być PayJoin, zwiększając prywatność, jednocześnie pozostając nieodróżnialnymi od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody nadzoru**, co czyni to obiecującym rozwojem w dążeniu do prywatności transakcyjnej.

# Najlepsze praktyki dotyczące prywatności w kryptowalutach

## **Techniki synchronizacji portfeli**

Aby zachować prywatność i bezpieczeństwo, synchronizacja portfeli z blockchainem jest kluczowa. Dwie metody wyróżniają się:

- **Pełny węzeł**: Pobierając cały blockchain, pełny węzeł zapewnia maksymalną prywatność. Wszystkie transakcje kiedykolwiek dokonane są przechowywane lokalnie, co uniemożliwia przeciwnikom zidentyfikowanie, które transakcje lub adresy interesują użytkownika.
- **Filtrowanie bloków po stronie klienta**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, co pozwala portfelom identyfikować odpowiednie transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry, ściągając pełne bloki tylko wtedy, gdy znajdą dopasowanie z adresami użytkownika.

## **Wykorzystanie Tora dla anonimowości**

Biorąc pod uwagę, że Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tora, aby ukryć swój adres IP, zwiększając prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu używaniu adresów**

Aby chronić prywatność, ważne jest, aby używać nowego adresu dla każdej transakcji. Ponowne używanie adresów może narazić prywatność, łącząc transakcje z tym samym podmiotem. Nowoczesne portfele zniechęcają do ponownego używania adresów poprzez swój design.

## **Strategie dla prywatności transakcji**

- **Wiele transakcji**: Podzielenie płatności na kilka transakcji może zaciemnić kwotę transakcji, utrudniając ataki na prywatność.
- **Unikanie reszty**: Wybieranie transakcji, które nie wymagają zwrotu reszty, zwiększa prywatność, zakłócając metody wykrywania reszty.
- **Wiele zwrotów reszty**: Jeśli unikanie reszty nie jest możliwe, generowanie wielu zwrotów reszty może nadal poprawić prywatność.

# **Monero: Latarnia anonimowości**

Monero odpowiada na potrzebę absolutnej anonimowości w transakcjach cyfrowych, ustanawiając wysoki standard prywatności.

# **Ethereum: Gaz i transakcje**

## **Zrozumienie gazu**

Gaz mierzy wysiłek obliczeniowy potrzebny do wykonania operacji na Ethereum, wyceniany w **gwei**. Na przykład, transakcja kosztująca 2,310,000 gwei (lub 0.00231 ETH) wiąże się z limitem gazu i opłatą podstawową, z napiwkiem dla zachęcenia górników. Użytkownicy mogą ustawić maksymalną opłatę, aby upewnić się, że nie przepłacają, a nadwyżka jest zwracana.

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart kontraktów. Wymagają one opłaty i muszą być wydobywane. Kluczowe informacje w transakcji obejmują odbiorcę, podpis nadawcy, wartość, opcjonalne dane, limit gazu i opłaty. Co ważne, adres nadawcy jest dedukowany z podpisu, eliminując potrzebę jego umieszczania w danych transakcji.

Te praktyki i mechanizmy są podstawowe dla każdego, kto chce zaangażować się w kryptowaluty, priorytetowo traktując prywatność i bezpieczeństwo.

## Odniesienia

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

{{#include ../banners/hacktricks-training.md}}
