# Blockchain i kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Smart Contracts** to programy, które wykonują się na blockchainie po spełnieniu określonych warunków, automatyzując realizację umów bez pośredników.
- **Decentralized Applications (dApps)** opierają się na smart contracts i mają przyjazny dla użytkownika interfejs oraz przejrzysty, audytowalny backend.
- **Tokens & Coins** różnią się tym, że coins służą jako pieniądz cyfrowy, a tokens reprezentują wartość lub własność w określonym kontekście.
  - **Utility Tokens** zapewniają dostęp do usług, a **Security Tokens** oznaczają prawo własności do aktywów.
- **DeFi** to skrót od Decentralized Finance, czyli finansów zdecentralizowanych, oferujących usługi finansowe bez centralnych organów.
- **DEX** i **DAOs** oznaczają odpowiednio zdecentralizowane platformy wymiany i zdecentralizowane organizacje autonomiczne.

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczną i uzgodnioną weryfikację transakcji na blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej w celu weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej liczby tokenów, zmniejszając zużycie energii w porównaniu z PoW.<sup>[[1]](#references)</sup>

## Podstawowe informacje o Bitcoinie

### Transakcje

Transakcje Bitcoin polegają na przesyłaniu środków między adresami. Są weryfikowane za pomocą podpisów cyfrowych, co gwarantuje, że transfer może zainicjować wyłącznie właściciel klucza prywatnego.<sup>[[2]](#references)</sup>

#### Główne elementy:

- **Transakcje multisig** wymagają wielu podpisów, aby autoryzować transakcję.<sup>[[3]](#references)</sup>
- Transakcje składają się z **wejść** (źródła środków), **wyjść** (miejsca docelowego), **opłat** (płaconych minerom) i **skryptów** (reguł transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoina, umożliwiając przeprowadzanie wielu transakcji w ramach kanału i publikując na blockchainie wyłącznie jego stan końcowy.

## Kwestie prywatności Bitcoina

Ataki na prywatność, takie jak **wspólne właścicielstwo wejść** i **wykrywanie adresu reszty UTXO**, wykorzystują wzorce transakcji. Strategie takie jak **mixery** i **CoinJoin** zwiększają anonimowość, ukrywając powiązania między transakcjami użytkowników.

## Anonimowe nabywanie Bitcoinów

Metody obejmują transakcje gotówkowe, mining i korzystanie z mixerów. **CoinJoin** łączy wiele transakcji, utrudniając śledzenie, a **PayJoin** ukrywa CoinJoins jako zwykłe transakcje, zwiększając prywatność.

# Podsumowanie ataków na prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników często budzą obawy. Oto uproszczony przegląd kilku popularnych metod, za pomocą których atakujący mogą naruszyć prywatność użytkowników Bitcoina.<sup>[[6]](#references)</sup>

## **Założenie wspólnego właścicielstwa wejść**

Łączenie wejść od różnych użytkowników w jednej transakcji jest na ogół rzadkie ze względu na związaną z tym złożoność. Dlatego **często zakłada się, że dwa adresy wejściowe w tej samej transakcji należą do tego samego właściciela**.

## **Wykrywanie adresu reszty UTXO**

UTXO, czyli **niewydane wyjście transakcji**, musi zostać w całości wydane w ramach transakcji. Jeśli jego część zostanie wysłana na inny adres, pozostała kwota trafia na nowy adres reszty. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza jego prywatność.

### Przykład

Aby temu przeciwdziałać, można skorzystać z usług mieszających lub używać wielu adresów, by utrudnić ustalenie właściciela.

## **Ujawnianie informacji w mediach społecznościowych i na forach**

Użytkownicy czasami udostępniają swoje adresy Bitcoin w internecie, przez co **łatwo powiązać adres z jego właścicielem**.

## **Analiza grafu transakcji**

Transakcje można przedstawić w formie grafów, które ujawniają potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Heurystyka zbędnego wejścia (heurystyka optymalnej reszty)**

Ta heurystyka polega na analizowaniu transakcji z wieloma wejściami i wyjściami, aby odgadnąć, które wyjście stanowi resztę zwracaną nadawcy.

### Przykład

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Jeśli dodanie kolejnych wejść sprawi, że kwota reszty będzie większa niż wartość dowolnego pojedynczego wejścia, może to zmylić heurystykę.

## **Wymuszone ponowne użycie adresu**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, łącząc w ten sposób adresy.

### Prawidłowe zachowanie portfela

Portfele powinny unikać wykorzystywania monet otrzymanych na używanych już, pustych adresach, aby zapobiec temu wyciekowi prywatności.

## **Inne techniki analizy blockchaina**

- **Dokładne kwoty płatności:** Transakcje bez reszty prawdopodobnie odbywają się między dwoma adresami należącymi do tego samego użytkownika.
- **Okrągłe kwoty:** Okrągła kwota w transakcji sugeruje, że jest to płatność, a wyjście z nieokrągłą kwotą prawdopodobnie stanowi resztę.
- **Fingerprinting portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, dzięki czemu analitycy mogą zidentyfikować używane oprogramowanie i potencjalnie adres reszty.
- **Korelacje kwot i czasu:** Ujawnienie czasu lub kwot transakcji może umożliwić ich śledzenie.

## **Analiza ruchu sieciowego**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Dotyczy to szczególnie podmiotów obsługujących wiele węzłów Bitcoin, co zwiększa ich możliwości monitorowania transakcji.

## Więcej informacji

Kompletną listę ataków na prywatność i metod obrony znajdziesz na stronie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby anonimowego zdobywania bitcoinów

- **Transakcje gotówkowe**: Zdobywanie bitcoinów za gotówkę.
- **Alternatywy dla gotówki**: Kupowanie kart podarunkowych i wymienianie ich online na bitcoiny.
- **Mining**: Najbardziej prywatnym sposobem zarabiania bitcoinów jest mining, zwłaszcza prowadzony samodzielnie, ponieważ mining poole mogą znać adres IP minera. [Informacje o mining poolach](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie kradzież bitcoinów może być innym sposobem ich anonimowego zdobycia, ale jest nielegalna i niezalecana.

## Usługi mieszające

Korzystając z usługi mieszającej, użytkownik może **wysłać bitcoiny** i otrzymać w zamian **inne bitcoiny**, co utrudnia ustalenie pierwotnego właściciela. Wymaga to jednak zaufania, że usługa nie przechowuje logów i faktycznie zwróci bitcoiny. Alternatywne sposoby mieszania obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji różnych użytkowników w jedną, utrudniając dopasowanie wejść do wyjść. Mimo swojej skuteczności transakcje z unikalnymi rozmiarami wejść i wyjść nadal mogą być śledzone.

Przykłady transakcji, w których mogła zostać użyta metoda CoinJoin: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz na stronie [CoinJoin](https://coinjoin.io/en). Informacje o mixerze dla smart kontraktów Ethereum, który oddziela wpłaty od późniejszych wypłat, znajdziesz na stronie [Tornado Cash](https://tornado.cash).

## PayJoin

Odmiana CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych dla CoinJoin równych wyjść. Dzięki temu jest niezwykle trudna do wykrycia i może unieważnić heurystykę wspólnego właściciela wejść używaną przez podmioty monitorujące transakcje.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcje takie jak powyższa mogą być PayJoin, zwiększając prywatność i pozostając nieodróżnialnymi od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin mogłoby znacząco zakłócić tradycyjne metody nadzoru**, co czyni je obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki ochrony prywatności w kryptowalutach

## **Metody synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, należy synchronizować portfele z blockchainem. Wyróżniają się dwie metody:

- **Pełny węzeł**: Pobranie całego blockchaina zapewnia maksymalną prywatność. Wszystkie dotychczasowe transakcje są przechowywane lokalnie, przez co przeciwnicy nie mogą ustalić, którymi transakcjami lub adresami interesuje się użytkownik.
- **Filtrowanie bloków po stronie klienta**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, dzięki czemu portfele mogą wykrywać istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry i pobierają pełne bloki tylko wtedy, gdy znajdą dopasowanie do adresów użytkownika.

## **Korzystanie z Tor w celu zachowania anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor, aby ukryć adres IP i zwiększyć prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu używaniu adresów**

Aby chronić prywatność, należy używać nowego adresu dla każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, łącząc transakcje z tym samym podmiotem. Współczesne portfele z założenia zniechęcają do ponownego używania adresów.

## **Strategie ochrony prywatności transakcji**

- **Wiele transakcji**: Podział płatności na kilka transakcji może ukryć jej kwotę i udaremnić ataki naruszające prywatność.
- **Unikanie reszty**: Wybór transakcji niewymagających wyjść reszty zwiększa prywatność, utrudniając stosowanie metod wykrywania reszty.
- **Wiele wyjść reszty**: Jeśli uniknięcie reszty nie jest możliwe, utworzenie wielu wyjść reszty nadal może zwiększyć prywatność.

# **Monero: symbol anonimowości**

Monero zaprojektowano tak, aby priorytetowo traktowało prywatność transakcji.

# **Ethereum: gas i transakcje**

## **Czym jest gas**

Gas mierzy nakład obliczeniowy potrzebny do wykonania operacji w Ethereum i jest wyceniany w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) obejmuje limit gasu i opłatę bazową, a także opłatę priorytetową zachęcającą walidatora do uwzględnienia jej w bloku. Użytkownicy mogą ustawić maksymalną opłatę, aby nie zapłacić zbyt dużo; nadwyżka jest zwracana.<sup>[[5]](#references)</sup>

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart kontraktów. Wymagają opłaty i muszą zostać uwzględnione w bloku. Do podstawowych informacji w transakcji należą: odbiorca, podpis nadawcy, wartość, opcjonalne dane, limit gasu i opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, więc nie trzeba go umieszczać w danych transakcji.<sup>[[4]](#references)</sup>

Te praktyki i mechanizmy są podstawą dla każdego, kto chce korzystać z kryptowalut, stawiając na prywatność i bezpieczeństwo.

## Value-Centric Web3 Red Teaming

- Sporządź inwentaryzację komponentów przechowujących lub przenoszących wartość (podpisujących, wyroczni, mostów, automatyzacji), aby ustalić, kto może przenosić środki i w jaki sposób.
- Powiąż każdy komponent z odpowiednimi taktykami MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków z użyciem flash loanów, wyroczni, poświadczeń i ataków międzyłańcuchowych, aby zweryfikować ich skutki i udokumentować warunki wstępne umożliwiające wykorzystanie podatności.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Przejęcie przepływu podpisywania Web3

- Manipulacja łańcuchem dostaw interfejsów portfeli może zmieniać ładunki EIP-712 tuż przed podpisaniem, pozyskując prawidłowe podpisy umożliwiające przejęcie proxy opartego na delegatecall (np. nadpisanie slot-0 pola masterCopy w Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstrakcja konta (ERC-4337)

- Typowe tryby awarii smart kont obejmują obejście kontroli dostępu `EntryPoint`, niepodpisane pola gasu, walidację zależną od stanu, ponowne odtwarzanie ERC-1271 oraz drenaż opłat przez revert po walidacji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezpieczeństwo smart kontraktów

- Testowanie mutacyjne w celu wykrywania luk w zestawach testów:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integralność gościa ZK Proof / zkVM

Gdy prover używa **zkVM** lub obwodu dowodzącego specyficznego dla aplikacji, aby potwierdzić twierdzenie, weryfikator dowiaduje się jedynie, że **program gościa wykonał się zgodnie z kodem**. Jeśli gość zawiera **niebezpieczną deserializację**, **niezdefiniowane zachowanie** lub **brak wymaganych ograniczeń semantycznych**, złośliwy prover może wygenerować dowód, który przejdzie weryfikację, mimo że **publiczne metryki lub deklarowany niezmiennik są fałszywe**.<sup>[[7]](#references)</sup>

### Niebezpieczna deserializacja wewnątrz gości dowodów

- Traktuj prywatne dane świadka/obwodu jako **niezaufane dane wejściowe kontrolowane przez atakującego**, nawet jeśli są ukryte przez dowód.
- Unikaj ich deserializacji za pomocą niezabezpieczonych funkcji pomocniczych, takich jak `rkyv::access_unchecked`, chyba że bajty zostały wcześniej zweryfikowane poza tym procesem.
- Wartości enum, wskaźniki względne, długości i indeksy wczytane z niezaufanych danych serializowanych muszą zostać zweryfikowane, zanim wpłyną na przepływ sterowania lub dostęp do pamięci.

Praktyczny schemat audytu:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Jeśli pole takie jak `op.kind` jest enumem, a atakujący może wstrzyknąć **wartość discriminant spoza zakresu**, każde dalsze `match` na tej wartości staje się podejrzane.

### Jump-table / UB counter bypass

Jeśli Rust kompiluje duży `match` do **jump table**, nieprawidłowa wartość discriminant enumu może spowodować **niezdefiniowany przepływ sterowania**. Niebezpieczny wzorzec wygląda następująco:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedna instrukcja `match` aktualizuje **krytyczne dla bezpieczeństwa liczniki/ograniczenia**.
2. Druga instrukcja `match` wykonuje **właściwą semantykę instrukcji**.
3. Wartość discriminant spoza zakresu indeksuje element poza pierwszą jump table i trafia do kodu powiązanego z drugą.

W rezultacie operacja nadal zostaje wykonana, ale ścieżka zliczania jest pomijana. W zkVM może to umożliwić sfałszowanie dowodów, które zgłaszają niemożliwe metryki, takie jak mniejsza liczba bramek, mniej kosztownych operacji lub inne sfałszowane zasoby objęte limitami.

Lista kontrolna:

- Szukaj enumów kontrolowanych przez atakującego, deserializowanych z danych witness/prywatnych.
- Sprawdź powtarzające się instrukcje `match` operujące na tym samym polu opcode/kind.
- Traktuj połączenie `unsafe` + deserializacji bez kontroli + dużego dispatchu opcode jako wysoce ryzykowne.
- W razie potrzeby przeprowadź inżynierię wsteczną wygenerowanego pliku binarnego; układ jump table może mieć większe znaczenie niż kod źródłowy.

### Brak ograniczeń semantycznych w odwracalnych/wyspecjalizowanych interpreterach

Nie sprawdzaj wyłącznie bezpieczeństwa pamięci; weryfikuj również **reguły semantyczne**, których ma wymagać dowód.

W przypadku odwracalnych/zbliżonych do kwantowych zestawów instrukcji upewnij się, że operandy, które muszą być różne, są faktycznie ograniczone tak, by były różne. Operacja w stylu Toffoliego/CCX zaimplementowana jako:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

staje się niebezpieczne, jeśli system gościa tego nie odrzuci:

```text
op.q_control1 == op.q_control2 == op.q_target
```

W takim przypadku przejście sprowadza się do:

```text
q = q ^ (q & q) = 0
```

Tworzy to **deterministyczną prymitywę resetowania**, łamiąc założenia o odwracalności i umożliwiając tańsze obliczenia niezgodne z przeznaczeniem. W systemach dowodowych, które poświadczają zużycie zasobów, pozwala to atakującym spełnić kontrole funkcjonalne, a jednocześnie ominąć model kosztów, który — zdaniem weryfikatora — jest egzekwowany.

### Co testować w systemach ZK

- Fuzzuj wszystkie parsery guest, używając nieprawidłowo sformatowanych kodowań witness/prywatnych danych wejściowych.
- Wymagaj walidacji zakresu enum przed przekazaniem sterowania do opcode.
- Dodaj kontrole semantyczne dotyczące aliasowania operandów i innych nieprawidłowych form instrukcji.
- Porównuj zgłaszane/publiczne liczniki z niezależną implementacją referencyjną.
- Pamiętaj, że prawidłowy dowód nadal może dowodzić **niewłaściwego twierdzenia**, jeśli program guest zawiera błędy.

## Autoryzacja zależna od stanu

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploity DeFi/AMM

Jeśli badasz praktyczne exploity DEX-ów i AMM-ów (hooki Uniswap v4, nadużycia zaokrągleń/precyzji, swapy przekraczające progi, których wpływ zwiększają flash loany), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

W przypadku wieloassetowych pul ważonych, które buforują wirtualne salda i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Dowód stawki - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Wyjaśnienie klucza publicznego i prywatnego - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Czym są transakcje z wieloma podpisami? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transakcje | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas i opłaty | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Prywatność - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Złamaliśmy zero-knowledge proof Google’a dotyczący kryptoanalizy kwantowej](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zabezpieczanie kryptowalut opartych na krzywych eliptycznych przed zagrożeniami kwantowymi: szacunki zasobów i środki zaradcze (załatana wersja)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repozytorium proof-of-concept Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
