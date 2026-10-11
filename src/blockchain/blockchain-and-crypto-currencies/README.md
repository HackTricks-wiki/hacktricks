# Blockchain i kryptowaluty

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe pojęcia

- **Inteligentne kontrakty** to programy, które są uruchamiane na blockchainie po spełnieniu określonych warunków i automatyzują realizację umów bez pośredników.
- **Zdecentralizowane aplikacje (dApps)** opierają się na inteligentnych kontraktach i oferują przyjazny dla użytkownika interfejs oraz przejrzysty, możliwy do audytu backend.
- **Tokeny i monety** różnią się tym, że monety służą jako pieniądz cyfrowy, a tokeny reprezentują wartość lub własność w określonym kontekście.
  - **Tokeny użytkowe** zapewniają dostęp do usług, a **tokeny papierów wartościowych** oznaczają własność aktywów.
- **DeFi** to skrót od Decentralized Finance (zdecentralizowane finanse), czyli usług finansowych bez centralnych organów.
- **DEX** i **DAO** oznaczają odpowiednio zdecentralizowane platformy wymiany oraz zdecentralizowane organizacje autonomiczne.

## Mechanizmy konsensusu

Mechanizmy konsensusu zapewniają bezpieczne i uzgodnione zatwierdzanie transakcji w blockchainie:

- **Proof of Work (PoW)** opiera się na mocy obliczeniowej w celu weryfikacji transakcji.
- **Proof of Stake (PoS)** wymaga od walidatorów posiadania określonej liczby tokenów, ograniczając zużycie energii w porównaniu z PoW.<sup>[[1]](#references)</sup>

## Podstawowe informacje o Bitcoinie

### Transakcje

Transakcje Bitcoin polegają na przesyłaniu środków między adresami. Są weryfikowane za pomocą podpisów cyfrowych, co gwarantuje, że transfer może zainicjować wyłącznie właściciel klucza prywatnego.<sup>[[2]](#references)</sup>

#### Kluczowe elementy:

- **Transakcje wielopodpisowe** wymagają wielu podpisów, aby autoryzować transakcję.<sup>[[3]](#references)</sup>
- Transakcje składają się z **wejść** (źródła środków), **wyjść** (celu), **opłat** (płaconych górnikom) oraz **skryptów** (zasad transakcji).

### Lightning Network

Ma na celu zwiększenie skalowalności Bitcoina, umożliwiając przeprowadzanie wielu transakcji w ramach kanału i publikując w blockchainie tylko jego stan końcowy.

## Problemy z prywatnością w Bitcoinie

Ataki na prywatność, takie jak **współwłasność wejść** i **wykrywanie adresu reszty UTXO**, wykorzystują wzorce transakcji. Strategie takie jak **miksery** i **CoinJoin** zwiększają anonimowość, ukrywając powiązania między transakcjami użytkowników.

## Anonimowe pozyskiwanie bitcoinów

Metody obejmują transakcje gotówkowe, mining i korzystanie z mikserów. **CoinJoin** łączy wiele transakcji, aby utrudnić ich śledzenie, a **PayJoin** maskuje CoinJoin jako zwykłą transakcję, zapewniając większą prywatność.

# Podsumowanie ataków na prywatność Bitcoina

W świecie Bitcoina prywatność transakcji i anonimowość użytkowników często budzą obawy. Oto uproszczony przegląd kilku popularnych metod, za pomocą których atakujący mogą naruszyć prywatność użytkowników Bitcoina.<sup>[[6]](#references)</sup>

## **Założenie o wspólnym właścicielu wejść**

Łączenie wejść należących do różnych użytkowników w jednej transakcji jest na ogół rzadkie ze względu na złożoność takiego działania. Dlatego **często zakłada się, że dwa adresy wejściowe w tej samej transakcji należą do tego samego właściciela**.

## **Wykrywanie adresu reszty UTXO**

UTXO, czyli **niewydane wyjście transakcji**, musi zostać w całości wydane w transakcji. Jeśli tylko jego część zostanie wysłana na inny adres, reszta trafia na nowy adres reszty. Obserwatorzy mogą założyć, że ten nowy adres należy do nadawcy, co narusza jego prywatność.

### Przykład

Aby temu zapobiec, można skorzystać z usług mieszających lub używać wielu adresów, co utrudnia ustalenie ich właściciela.

## **Ujawnianie danych w sieciach społecznościowych i na forach**

Użytkownicy czasami udostępniają swoje adresy Bitcoin w internecie, przez co **łatwo powiązać adres z jego właścicielem**.

## **Analiza grafu transakcji**

Transakcje można przedstawić w postaci grafów, które ujawniają potencjalne powiązania między użytkownikami na podstawie przepływu środków.

## **Heurystyka niepotrzebnego wejścia (heurystyka optymalnej reszty)**

Ta heurystyka polega na analizowaniu transakcji z wieloma wejściami i wyjściami, aby odgadnąć, które wyjście stanowi resztę zwracaną nadawcy.

### Przykład

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Jeśli dodanie kolejnych wejść sprawi, że wyjście reszty będzie większe niż którekolwiek pojedyncze wejście, może to zmylić heurystykę.

## **Wymuszone ponowne użycie adresów**

Atakujący mogą wysyłać niewielkie kwoty na wcześniej używane adresy, licząc na to, że odbiorca połączy je z innymi wejściami w przyszłych transakcjach, wiążąc w ten sposób adresy ze sobą.

### Prawidłowe działanie portfela

Portfele powinny unikać wykorzystywania monet otrzymanych na używanych wcześniej, pustych adresach, aby zapobiec temu leakowi prywatności.

## **Inne techniki analizy blockchaina**

- **Dokładne kwoty płatności:** Transakcje bez reszty prawdopodobnie zachodzą między dwoma adresami należącymi do tego samego użytkownika.
- **Okrągłe kwoty:** Okrągła kwota w transakcji sugeruje, że jest to płatność, a wyjście z nieokrągłą kwotą prawdopodobnie stanowi resztę.
- **Odcisk palca portfela:** Różne portfele mają charakterystyczne wzorce tworzenia transakcji, dzięki czemu analitycy mogą rozpoznać używane oprogramowanie i potencjalnie adres reszty.
- **Korelacje kwot i czasu:** Ujawnienie czasu lub kwot transakcji może umożliwić ich śledzenie.

## **Analiza ruchu sieciowego**

Monitorując ruch sieciowy, atakujący mogą potencjalnie powiązać transakcje lub bloki z adresami IP, naruszając prywatność użytkowników. Dotyczy to zwłaszcza podmiotów obsługujących wiele węzłów Bitcoin, co zwiększa ich możliwości monitorowania transakcji.

## Więcej informacji

Kompleksową listę ataków na prywatność i metod obrony znajdziesz na stronie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimowe transakcje Bitcoin

## Sposoby anonimowego zdobywania bitcoinów

- **Transakcje gotówkowe**: Zdobywanie bitcoinów za gotówkę.
- **Alternatywy dla gotówki**: Kupowanie kart podarunkowych i wymienianie ich online na bitcoiny.
- **Mining**: Najbardziej prywatną metodą zdobywania bitcoinów jest mining, zwłaszcza prowadzony samodzielnie, ponieważ pule miningowe mogą znać adres IP minera. [Informacje o pulach miningowych](https://en.bitcoin.it/wiki/Pooled_mining)
- **Kradzież**: Teoretycznie kradzież bitcoinów może być innym sposobem ich anonimowego zdobycia, ale jest nielegalna i niezalecana.

## Usługi mieszające

Korzystając z usługi mieszającej, użytkownik może **wysłać bitcoiny** i otrzymać w zamian **inne bitcoiny**, co utrudnia ustalenie pierwotnego właściciela. Wymaga to jednak zaufania, że usługa nie będzie przechowywać logów i faktycznie zwróci bitcoiny. Alternatywne opcje mieszania obejmują kasyna Bitcoin.

## CoinJoin

**CoinJoin** łączy wiele transakcji różnych użytkowników w jedną, utrudniając dopasowanie wejść do wyjść. Mimo skuteczności tej metody transakcje z unikalnymi rozmiarami wejść i wyjść nadal mogą być śledzone.

Przykłady transakcji, w których mogła zostać użyta metoda CoinJoin: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Więcej informacji znajdziesz na stronie [CoinJoin](https://coinjoin.io/en). Informacje o mixerze opartym na smart kontrakcie Ethereum, który oddziela wpłaty od późniejszych wypłat, znajdziesz na stronie [Tornado Cash](https://tornado.cash).

## PayJoin

Odmiana CoinJoin, **PayJoin** (lub P2EP), maskuje transakcję między dwiema stronami (np. klientem i sprzedawcą) jako zwykłą transakcję, bez charakterystycznych dla CoinJoin równych kwot wyjściowych. Dzięki temu jest niezwykle trudna do wykrycia i może podważyć heurystykę wspólnego właściciela wejść stosowaną przez podmioty monitorujące transakcje.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcje takie jak powyższa mogą być transakcjami PayJoin, zwiększającymi prywatność i jednocześnie nierozróżnialnymi od standardowych transakcji bitcoinowych.

**Wykorzystanie PayJoin może znacząco zakłócić tradycyjne metody nadzoru**, co czyni je obiecującym rozwiązaniem w dążeniu do prywatności transakcji.

# Najlepsze praktyki dotyczące prywatności w kryptowalutach

## **Techniki synchronizacji portfela**

Aby zachować prywatność i bezpieczeństwo, należy synchronizować portfele z blockchainem. Wyróżniają się dwie metody:

- **Pełny węzeł**: Pobranie całego blockchaina przez pełny węzeł zapewnia maksymalną prywatność. Wszystkie kiedykolwiek wykonane transakcje są przechowywane lokalnie, więc przeciwnicy nie mogą ustalić, którymi transakcjami lub adresami interesuje się użytkownik.
- **Filtrowanie bloków po stronie klienta**: Metoda ta polega na tworzeniu filtrów dla każdego bloku w blockchainie. Dzięki nim portfele mogą identyfikować istotne transakcje bez ujawniania obserwatorom sieci konkretnych zainteresowań użytkownika. Lekkie portfele pobierają te filtry i pobierają pełne bloki tylko wtedy, gdy znajdą dopasowanie do adresów użytkownika.

## **Wykorzystanie Tor do zapewnienia anonimowości**

Ponieważ Bitcoin działa w sieci peer-to-peer, zaleca się korzystanie z Tor, aby ukryć adres IP i zwiększyć prywatność podczas korzystania z sieci.

## **Zapobieganie ponownemu używaniu adresów**

Aby chronić prywatność, należy używać nowego adresu dla każdej transakcji. Ponowne używanie adresów może naruszyć prywatność, łącząc transakcje z tym samym podmiotem. Współczesne portfele z założenia zniechęcają do ponownego używania adresów.

## **Strategie zapewniania prywatności transakcji**

- **Wiele transakcji**: Podzielenie płatności na kilka transakcji może utrudnić ustalenie jej kwoty i udaremnić ataki na prywatność.
- **Unikanie reszty**: Wybór transakcji, które nie wymagają wyjść reszty, zwiększa prywatność, zakłócając metody wykrywania reszty.
- **Wiele wyjść reszty**: Jeśli uniknięcie reszty nie jest możliwe, utworzenie wielu wyjść reszty może nadal zwiększyć prywatność.

# **Monero: wzór anonimowości**

Monero zaprojektowano tak, aby priorytetowo traktowało prywatność transakcji.

# **Ethereum: gas i transakcje**

## **Zrozumienie gas**

Gas mierzy nakład obliczeniowy wymagany do wykonania operacji w Ethereum; jego cenę wyraża się w **gwei**. Na przykład transakcja kosztująca 2 310 000 gwei (czyli 0,00231 ETH) ma limit gas i opłatę bazową, a także opłatę priorytetową zachęcającą walidatorów do uwzględnienia jej w bloku. Użytkownicy mogą ustawić maksymalną opłatę, aby nie zapłacić zbyt dużo; nadwyżka zostanie zwrócona.<sup>[[5]](#references)</sup>

## **Wykonywanie transakcji**

Transakcje w Ethereum obejmują nadawcę i odbiorcę, którymi mogą być adresy użytkowników lub smart contractów. Wymagają opłaty i muszą zostać uwzględnione w bloku. Kluczowe informacje w transakcji to odbiorca, podpis nadawcy, wartość, opcjonalne dane, limit gas i opłaty. Warto zauważyć, że adres nadawcy jest wyprowadzany z podpisu, więc nie trzeba go umieszczać w danych transakcji.<sup>[[4]](#references)</sup>

Te praktyki i mechanizmy stanowią podstawę dla każdego, kto chce korzystać z kryptowalut, stawiając na pierwszym miejscu prywatność i bezpieczeństwo.

## Red teaming Web3 skoncentrowany na wartości

- Zrób inwentaryzację komponentów przechowujących wartość (signerów, oracle, bridge’ów, automatyzacji), aby ustalić, kto i w jaki sposób może przenosić środki.
- Przyporządkuj każdy komponent do odpowiednich taktyk MITRE AADAPT, aby ujawnić ścieżki eskalacji uprawnień.
- Przećwicz łańcuchy ataków z użyciem flash loanów, oracle, danych uwierzytelniających i ataków cross-chain, aby zweryfikować wpływ i udokumentować warunki wstępne umożliwiające wykorzystanie podatności.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitacja procesu podpisywania w Web3

- Modyfikacja interfejsów portfeli w ramach ataku na łańcuch dostaw może zmienić payloady EIP-712 tuż przed podpisaniem, umożliwiając przechwycenie prawidłowych podpisów i przejęcie proxy opartego na delegatecall (np. przez nadpisanie slotu 0 pola masterCopy w Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstrakcja kont (ERC-4337)

- Typowe tryby awarii smart accountów obejmują obejście kontroli dostępu `EntryPoint`, niepodpisane pola gas, walidację ze zmianą stanu, replay ERC-1271 i drenowanie opłat przez revert po walidacji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezpieczeństwo smart contractów

- Testowanie mutacyjne w celu wykrywania luk w zestawach testów:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integralność dowodów ZK / gości zkVM

Gdy prover używa **zkVM** lub obwodu dowodowego specyficznego dla aplikacji, aby potwierdzić twierdzenie, verifier dowiaduje się jedynie, że **program gościa wykonał się zgodnie z kodem**. Jeśli gość zawiera **niebezpieczną deserializację**, **niezdefiniowane zachowanie** lub **brak wymaganych ograniczeń semantycznych**, złośliwy prover może wygenerować dowód, który przejdzie weryfikację, mimo że **publiczne metryki lub deklarowany niezmiennik są fałszywe**.<sup>[[7]](#references)</sup>

### Niebezpieczna deserializacja wewnątrz gości dowodu

- Traktuj prywatne witnessy i bajty obwodu jako **niezaufane dane wejściowe kontrolowane przez atakującego**, nawet jeśli są ukryte przez dowód.
- Unikaj ich deserializacji za pomocą niezabezpieczonych helperów, takich jak `rkyv::access_unchecked`, chyba że bajty zostały wcześniej zweryfikowane poza tym mechanizmem.
- Wartości discriminantów enumów, wskaźniki względne, długości i indeksy odczytane z niezaufanych, serializowanych danych muszą zostać zweryfikowane, zanim wpłyną na przepływ sterowania lub dostęp do pamięci.

Praktyczny schemat audytu:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Jeśli pole takie jak `op.kind` jest enumem, a atakujący może wstrzyknąć **dyskryminant spoza zakresu**, każdy dalszy `match` na tej wartości staje się podejrzany.

### Ominięcie liczników przez jump table / UB

Jeśli Rust kompiluje duży `match` do **jump table**, nieprawidłowy dyskryminant enuma może prowadzić do **niezdefiniowanego przepływu sterowania**. Niebezpieczny wzorzec wygląda tak:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jeden `match` aktualizuje **krytyczne dla bezpieczeństwa liczniki/ograniczenia**.
2. Drugi `match` realizuje **właściwą semantykę instrukcji**.
3. Dyskryminant spoza zakresu indeksuje element poza pierwszą jump table i trafia do kodu powiązanego z drugą.

W rezultacie operacja nadal zostaje wykonana, ale ścieżka zliczania jest pomijana. W zkVM może to umożliwić sfałszowanie dowodów, które wykazują niemożliwe metryki, takie jak mniejsza liczba bramek, mniejsza liczba kosztownych operacji lub inne sfałszowane ograniczone zasoby.

Lista kontrolna:

- Szukaj enumów kontrolowanych przez atakującego, deserializowanych z danych świadka/prywatnych danych wejściowych.
- Sprawdzaj powtarzające się instrukcje `match` dotyczące tego samego pola opcode/kind.
- Traktuj połączenie `unsafe` + deserializacji bez kontroli + dużego dispatchu opcode jako kombinację wysokiego ryzyka.
- W razie potrzeby wykonaj inżynierię wsteczną wygenerowanego pliku binarnego; układ jump table może mieć większe znaczenie niż kod źródłowy.

### Brak ograniczeń semantycznych w odwracalnych/wyspecjalizowanych interpreterach

Nie sprawdzaj wyłącznie bezpieczeństwa pamięci; sprawdzaj również **reguły semantyczne**, których przestrzeganie ma wymuszać dowód.

W przypadku odwracalnych/zbliżonych do kwantowych zestawów instrukcji upewnij się, że operandy, które muszą być różne, są faktycznie ograniczone do różnych wartości. Operacja podobna do Toffoli/CCX zaimplementowana jako:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

staje się niebezpieczne, jeśli gość nie odrzuci:

```text
op.q_control1 == op.q_control2 == op.q_target
```

W takim przypadku przejście sprowadza się do:

```text
q = q ^ (q & q) = 0
```

Tworzy to **deterministyczny prymityw resetowania**, podważając założenia o odwracalności i umożliwiając tańsze obliczenia niezgodne z przeznaczeniem. W systemach proof attesting resource usage może to pozwolić atakującym przejść kontrole funkcjonalne, a jednocześnie ominąć model kosztów, który — zdaniem weryfikatora — jest egzekwowany.

### Co testować w systemach ZK

- Fuzzuj wszystkie guest parsery, używając nieprawidłowych kodowań witness/private-input.
- Sprawdzaj zakres wartości enum przed dispatchowaniem opcode.
- Dodaj kontrole semantyczne aliasowania operandów i innych nieprawidłowych form instrukcji.
- Porównuj raportowane/publiczne liczniki z niezależną implementacją referencyjną.
- Pamiętaj, że poprawny proof może nadal dowodzić **niewłaściwego twierdzenia**, jeśli guest program zawiera błąd.

## Autoryzacja zależna od stanu

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Eksploatacja DeFi/AMM

Jeśli badasz praktyczną eksploatację DEX-ów i AMM-ów (hooki Uniswap v4, nadużycia zaokrągleń/precyzji, swapy przekraczające progi, których efekt wzmacniają flash loany), sprawdź:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

W przypadku wieloassetowych pul ważonych, które buforują wirtualne salda i mogą zostać zatrute, gdy `supply == 0`, zapoznaj się z:

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
- [7] [Trail of Bits — Pokonaliśmy zero-knowledge proof Google’a w kwantowej kryptoanalizie](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zabezpieczanie kryptowalut opartych na krzywych eliptycznych przed zagrożeniami kwantowymi: szacunki zasobów i środki zaradcze (poprawiona wersja)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repozytorium proof-of-concept Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
