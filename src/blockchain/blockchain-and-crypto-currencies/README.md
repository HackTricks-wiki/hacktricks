# Blockchain i kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Smart kontrakty** to programy uruchamiane na blockchainie po spełnieniu określonych warunków, które automatyzują realizację umów bez pośredników.
- **Zdecentralizowane aplikacje (dApps)** bazują na smart kontraktach i mają przyjazny dla użytkownika front-end oraz przejrzysty, poddający się audytowi back-end.
- **Tokeny i coiny** różnią się tym, że coiny pełnią funkcję cyfrowego pieniądza, a tokeny reprezentują wartość lub własność w określonym kontekście.
  - **Utility tokens** zapewniają dostęp do usług, a **security tokens** oznaczają własność aktywów.
- **DeFi** to skrót od Decentralized Finance — zdecentralizowanych finansów oferujących usługi finansowe bez centralnych organów.
- **DEX** i **DAO** to odpowiednio zdecentralizowane platformy wymiany oraz zdecentralizowane organizacje autonomiczne.

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczne i uzgodnione zatwierdzanie transakcji w blockchainie:

- **Proof of Work (PoW)** wykorzystuje moc obliczeniową do weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej liczby tokenów, ograniczając zużycie energii w porównaniu z PoW.<sup>[[1]](#references)</sup>

## Podstawowe informacje o Bitcoinie

### Transakcje

Transakcje Bitcoin polegają na przesyłaniu środków między adresami. Są weryfikowane za pomocą podpisów cyfrowych, dzięki czemu transfer może zainicjować wyłącznie właściciel klucza prywatnego.<sup>[[2]](#references)</sup>

#### Główne elementy:

- **Transakcje multisig** wymagają wielu podpisów, aby autoryzować transakcję.<sup>[[3]](#references)</sup>
- Transakcje składają się z **wejść** (źródło środków), **wyjść** (cel), **opłat** (płaconych minerom) i **skryptów** (reguły transakcji).

### Lightning Network

Ma zwiększyć skalowalność Bitcoina, umożliwiając realizację wielu transakcji w ramach kanału i publikując w blockchainie wyłącznie jego końcowy stan.

## Zagrożenia dla prywatności w Bitcoinie

Ataki na prywatność, takie jak **wspólna własność wejść** i **wykrywanie adresu reszty UTXO**, wykorzystują wzorce transakcji. Metody takie jak **miksery** i **CoinJoin** zwiększają anonimowość, ukrywając powiązania między transakcjami użytkowników.

## Anonimowe pozyskiwanie Bitcoinów

Metody obejmują transakcje gotówkowe, mining i korzystanie z mikserów. **CoinJoin** łączy wiele transakcji, aby utrudnić śledzenie, a **PayJoin** maskuje CoinJoin jako zwykłą transakcję, zapewniając większą prywatność.

# Podsumowanie ataków na prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników często budzą obawy. Poniżej przedstawiono uproszczony opis kilku typowych metod, za pomocą których atakujący mogą naruszyć prywatność w Bitcoinie.<sup>[[6]](#references)</sup>

## **Założenie wspólnej własności wejść**

Łączenie wejść należących do różnych użytkowników w jednej transakcji jest na ogół rzadkie ze względu na związaną z tym złożoność. Dlatego **często zakłada się, że dwa adresy wejściowe w tej samej transakcji należą do tego samego właściciela**.

## **Wykrywanie adresu reszty UTXO**

UTXO, czyli **niewydane wyjście transakcji**, musi zostać wydane w całości w ramach transakcji. Jeśli na inny adres zostanie wysłana tylko jego część, reszta trafia na nowy adres reszty. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza jego prywatność.

### Przykład

Aby ograniczyć to zagrożenie, można skorzystać z usług mieszających albo używać wielu adresów, co utrudnia ustalenie właściciela.

## **Ujawnianie informacji w sieciach społecznościowych i na forach**

Użytkownicy czasami publikują swoje adresy Bitcoin w Internecie, przez co **łatwo powiązać adres z jego właścicielem**.

## **Analiza grafu transakcji**

Transakcje można przedstawić jako grafy, które ujawniają potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Heurystyka zbędnego wejścia (heurystyka optymalnej reszty)**

Heurystyka ta polega na analizie transakcji z wieloma wejściami i wyjściami w celu odgadnięcia, które wyjście stanowi resztę zwracaną nadawcy.

### Przykład

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Jeśli dodanie kolejnych wejść sprawi, że wyjście reszty będzie większe niż dowolne pojedyncze wejście, może to zmylić heurystykę.

## **Wymuszone ponowne użycie adresu**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, łącząc w ten sposób adresy.

### Prawidłowe zachowanie portfela

Portfele powinny unikać używania monet otrzymanych na wcześniej używanych, pustych adresach, aby zapobiec temu privacy leak.

## **Inne techniki analizy blockchaina**

- **Dokładne kwoty płatności:** Transakcje bez reszty prawdopodobnie zachodzą między dwoma adresami należącymi do tego samego użytkownika.
- **Okrągłe kwoty:** Okrągła kwota w transakcji sugeruje, że jest to płatność, a wyjście z nieokrągłą kwotą prawdopodobnie stanowi resztę.
- **Fingerprinting portfela:** Różne portfele mają unikalne wzorce tworzenia transakcji, co pozwala analitykom zidentyfikować użyte oprogramowanie i potencjalnie adres reszty.
- **Korelacje kwot i czasu:** Ujawnienie czasu lub kwot transakcji może umożliwić ich śledzenie.

## **Analiza ruchu sieciowego**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Dotyczy to szczególnie sytuacji, gdy podmiot obsługuje wiele węzłów Bitcoin, co zwiększa jego możliwości monitorowania transakcji.

## Więcej informacji

Kompleksową listę ataków na prywatność i metod obrony znajdziesz na stronie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby anonimowego zdobywania bitcoinów

- **Transakcje gotówkowe**: Zdobywanie bitcoinów za gotówkę.
- **Alternatywy dla gotówki**: Kupowanie kart podarunkowych i wymienianie ich online na bitcoiny.
- **Mining**: Najbardziej prywatnym sposobem zdobywania bitcoinów jest mining, zwłaszcza samodzielny, ponieważ pule miningowe mogą znać adres IP górnika. [Informacje o pulach miningowych](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie kradzież bitcoinów może być innym sposobem anonimowego ich zdobycia, ale jest nielegalna i niezalecana.

## Usługi mieszające

Korzystając z usługi mieszającej, użytkownik może **wysłać bitcoiny** i otrzymać w zamian **inne bitcoiny**, co utrudnia prześledzenie pierwotnego właściciela. Wymaga to jednak zaufania, że usługa nie będzie przechowywać logów i faktycznie zwróci bitcoiny. Alternatywne sposoby mieszania obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji różnych użytkowników w jedną, utrudniając dopasowanie wejść do wyjść. Mimo skuteczności tej metody transakcje z unikalnymi wielkościami wejść i wyjść nadal można potencjalnie prześledzić.

Przykładowe transakcje, w których mogło zostać użyte CoinJoin, to `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz na stronie [CoinJoin](https://coinjoin.io/en). Informacje o mixerze opartym na smart contractach Ethereum, który oddziela wpłaty od późniejszych wypłat, znajdziesz na stronie [Tornado Cash](https://tornado.cash).

## PayJoin

Odmiana CoinJoin — **PayJoin** (lub P2EP) — maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych dla CoinJoin równych wyjść. Dzięki temu jest niezwykle trudna do wykrycia i może podważyć heurystykę wspólnej własności wejść stosowaną przez podmioty monitorujące transakcje.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcje takie jak powyższa mogą być transakcjami PayJoin, zwiększającymi prywatność, a jednocześnie nierozróżnialnymi od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin może znacząco utrudnić stosowanie tradycyjnych metod nadzoru**, co czyni tę technologię obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki zapewniania prywatności w kryptowalutach

## **Techniki synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, kluczowa jest synchronizacja portfeli z blockchainem. Wyróżniają się dwie metody:

- **Pełny węzeł**: Pobranie całego blockchaina przez pełny węzeł zapewnia maksymalną prywatność. Wszystkie wykonane transakcje są przechowywane lokalnie, przez co przeciwnicy nie są w stanie ustalić, którymi transakcjami lub adresami interesuje się użytkownik.
- **Filtrowanie bloków po stronie klienta**: Ta metoda polega na tworzeniu filtrów dla każdego bloku w blockchainie, dzięki czemu portfele mogą identyfikować istotne transakcje bez ujawniania konkretnych zainteresowań obserwatorom sieci. Lekkie portfele pobierają te filtry i pobierają pełne bloki tylko wtedy, gdy znajdą dopasowanie do adresów użytkownika.

## **Wykorzystanie Tor w celu zachowania anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor, aby ukryć adres IP i zwiększyć prywatność podczas interakcji z siecią.

## **Zapobieganie ponownemu używaniu adresów**

Aby chronić prywatność, należy używać nowego adresu przy każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, łącząc transakcje z tym samym podmiotem. Współczesne portfele z założenia zniechęcają do ponownego używania adresów.

## **Strategie zapewniania prywatności transakcji**

- **Wiele transakcji**: Podzielenie płatności na kilka transakcji może utrudnić ustalenie jej kwoty, udaremniając ataki naruszające prywatność.
- **Unikanie reszty**: Wybieranie transakcji, które nie wymagają wyjść reszty, zwiększa prywatność, zakłócając metody wykrywania reszty.
- **Wiele wyjść reszty**: Jeśli nie da się uniknąć reszty, wygenerowanie wielu wyjść reszty również może zwiększyć prywatność.

# **Monero: symbol anonimowości**

Monero zaprojektowano tak, aby priorytetowo traktować prywatność transakcji.

# **Ethereum: gas i transakcje**

## **Zrozumienie gas**

Gas mierzy nakład obliczeniowy potrzebny do wykonania operacji w Ethereum; jego cenę określa się w **gwei**. Na przykład transakcja kosztująca 2,310,000 gwei (czyli 0.00231 ETH) obejmuje limit gas i opłatę bazową, a także opłatę priorytetową zachęcającą walidatora do uwzględnienia jej w bloku. Użytkownicy mogą ustawić maksymalną opłatę, aby nie zapłacić za dużo; nadwyżka zostanie zwrócona.<sup>[[5]](#references)</sup>

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart contractów. Wymagają opłaty i muszą zostać uwzględnione w bloku. Do najważniejszych informacji w transakcji należą odbiorca, podpis nadawcy, wartość, opcjonalne dane, limit gas i opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, więc nie trzeba go umieszczać w danych transakcji.<sup>[[4]](#references)</sup>

Te praktyki i mechanizmy stanowią podstawę dla każdego, kto chce korzystać z kryptowalut, stawiając na pierwszym miejscu prywatność i bezpieczeństwo.

## Red teaming Web3 skoncentrowany na wartości

- Sporządź wykaz komponentów przechowujących wartość (podpisujących, wyroczni, mostów, automatyzacji), aby ustalić, kto może przenosić środki i w jaki sposób.
- Przyporządkuj każdy komponent do odpowiednich taktyk MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków z wykorzystaniem flash loan, wyroczni, poświadczeń i ataków cross-chain, aby zweryfikować ich wpływ oraz udokumentować warunki wstępne umożliwiające wykorzystanie podatności.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Przejęcie workflow podpisywania w Web3

- Manipulacja łańcuchem dostaw interfejsów portfeli może zmienić payloady EIP-712 tuż przed podpisaniem, pozyskując prawidłowe podpisy do przejęcia proxy opartego na delegatecall (np. przez nadpisanie slotu 0 pola masterCopy Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstrakcja konta (ERC-4337)

- Typowe tryby awarii smart account obejmują obejście kontroli dostępu `EntryPoint`, niepodpisane pola gas, walidację zależną od stanu, ponowne użycie ERC-1271 oraz drenowanie opłat przez revert po walidacji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezpieczeństwo smart contractów

- Testowanie mutacyjne w celu wykrywania martwych punktów w zestawach testowych:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integralność dowodów ZK / gości zkVM

Gdy prover używa **zkVM** lub obwodu dowodowego specyficznego dla aplikacji, aby poświadczyć twierdzenie, verifier dowiaduje się jedynie, że **program gościa wykonał się zgodnie z kodem**. Jeśli gość zawiera **niebezpieczną deserializację**, **niezdefiniowane zachowanie** lub **brak ograniczeń semantycznych**, złośliwy prover może wygenerować dowód, który przejdzie weryfikację, mimo że **publiczne metryki lub deklarowany niezmiennik są fałszywe**.<sup>[[7]](#references)</sup>

### Niebezpieczna deserializacja wewnątrz gości proof

- Traktuj prywatny witness/obwód jako **niezaufane dane wejściowe kontrolowane przez atakującego**, nawet jeśli są ukryte przez proof.
- Unikaj deserializowania ich za pomocą niesprawdzonych helperów, takich jak `rkyv::access_unchecked`, chyba że bajty zostały już zweryfikowane poza tym procesem.
- Wartości enum discriminant, wskaźniki względne, długości i indeksy pobrane z niezaufanych danych serializowanych muszą zostać zweryfikowane, zanim wpłyną na przepływ sterowania lub dostęp do pamięci.

Praktyczny schemat audytu:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Jeśli pole takie jak `op.kind` jest enumem, a atakujący może wstrzyknąć **wartość dyskryminantu spoza zakresu**, każde dalsze `match` na tej wartości budzi podejrzenia.

### Obejście liczników przez tablicę skoków / UB

Jeśli Rust kompiluje duże `match` do **tablicy skoków**, nieprawidłowa wartość dyskryminantu enuma może prowadzić do **niezdefiniowanego przepływu sterowania**. Niebezpieczny wzorzec:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedno `match` aktualizuje **liczniki/ograniczenia krytyczne dla bezpieczeństwa**.
2. Drugie `match` wykonuje **właściwą semantykę instrukcji**.
3. Wartość dyskryminantu spoza zakresu indeksuje pamięć poza pierwszą tablicą skoków i trafia do kodu powiązanego z drugą.

Wynik: operacja nadal jest wykonywana, ale ścieżka zliczania zostaje pominięta. W zkVM może to umożliwić spreparowanie dowodów, które podają niemożliwe metryki, takie jak mniejsza liczba bramek, mniej kosztownych operacji lub inne sfałszowane ograniczone zasoby.

Lista kontrolna podczas przeglądu:

- Szukaj enumów kontrolowanych przez atakującego, deserializowanych z danych świadka/prywatnego wejścia.
- Sprawdź powtarzające się instrukcje `match` używające tego samego pola opcode/kind.
- Połączenie `unsafe` + deserializacji bez sprawdzania + rozbudowanego dispatchu opcode traktuj jako sytuację wysokiego ryzyka.
- W razie potrzeby przeprowadź inżynierię wsteczną wygenerowanego pliku binarnego; układ tablic skoków może mieć większe znaczenie niż kod źródłowy.

### Brak ograniczeń semantycznych w odwracalnych/wyspecjalizowanych interpreterach

Nie sprawdzaj wyłącznie bezpieczeństwa pamięci; sprawdź również **reguły semantyczne**, które ma egzekwować dowód.

W przypadku odwracalnych/zbliżonych do kwantowych zestawów instrukcji upewnij się, że operandy, które muszą być różne, są faktycznie ograniczone tak, aby były różne. Operacja podobna do Toffoliego/CCX zaimplementowana jako:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

staje się niebezpieczne, jeśli system gościa nie odrzuci:

```text
op.q_control1 == op.q_control2 == op.q_target
```

W takim przypadku przejście sprowadza się do:

```text
q = q ^ (q & q) = 0
```

Tworzy to **deterministyczny mechanizm resetowania**, który łamie założenia o odwracalności i umożliwia tańsze obliczenia niezgodne z przeznaczeniem. W systemach dowodowych, które poświadczają wykorzystanie zasobów, atakujący mogą dzięki temu spełnić kontrole funkcjonalne, jednocześnie omijając model kosztów, którego egzekwowania oczekuje weryfikator.

### Co testować w systemach ZK

- Testuj fuzzingiem wszystkie parsery guest, przekazując im nieprawidłowo sformatowane kodowania witness/prywatnych danych wejściowych.
- Sprawdzaj zakres wartości enum przed dispatchowaniem opcode.
- Dodaj kontrole semantyczne aliasowania operandów i innych nieprawidłowych form instrukcji.
- Porównuj zgłaszane/publiczne liczniki z niezależną implementacją referencyjną.
- Pamiętaj, że prawidłowy proof może dowodzić **niewłaściwego stwierdzenia**, jeśli program guest zawiera błędy.

## Autoryzacja zależna od stanu

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Wykorzystywanie DeFi/AMM

Jeśli badasz praktyczne wykorzystywanie DEX-ów i AMM (hooki Uniswap v4, nadużycia zaokrągleń/precyzji, swapy przekraczające próg, których efekt wzmacniają flash loan), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

W przypadku pul ważonych z wieloma aktywami, które buforują wirtualne salda i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake — Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Wyjaśnienie klucza publicznego i prywatnego — Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Czym są transakcje z wieloma podpisami? — Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transakcje | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas i opłaty | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Prywatność — Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits — Pokonaliśmy zero-knowledge proof Google'a dotyczący kryptoanalizy kwantowej](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zabezpieczanie kryptowalut opartych na krzywych eliptycznych przed zagrożeniami kwantowymi: szacunki zasobów i środki zaradcze (załatana wersja)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repozytorium proof-of-concept Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
