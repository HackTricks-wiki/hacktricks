# Kryptografia symetryczna

{{#include ../../banners/hacktricks-training.md}}

## Na co zwracać uwagę w CTF-ach

- **Niewłaściwe użycie trybu**: wzorce ECB, podatność CBC na modyfikacje, ponowne użycie nonce w CTR/GCM.
- **Padding oracles**: różne błędy/czasy odpowiedzi dla nieprawidłowego paddingu.
- **Pomylenie MAC**: używanie CBC-MAC z wiadomościami o zmiennej długości lub błędy typu MAC-then-encrypt.
- **XOR wszędzie**: szyfry strumieniowe i niestandardowe konstrukcje często sprowadzają się do XOR z keystreamem.

## Tryby AES i niewłaściwe użycie

NIST definiuje tryby poufności ECB, CBC i CTR w SP 800-38A oraz szyfrowanie uwierzytelnione GCM w SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB leak patterns: identyczne bloki plaintextu → identyczne bloki ciphertextu. Umożliwia to:

- Cut-and-paste / zmianę kolejności bloków
- Usuwanie bloków (jeśli format pozostaje prawidłowy)

Jeśli możesz kontrolować plaintext i obserwować ciphertext (lub cookies), spróbuj utworzyć powtarzające się bloki (np. wiele `A`) i poszukaj powtórzeń.

### CBC: Cipher Block Chaining

- CBC jest **podatny na modyfikacje**: zmiana bitów w `C[i-1]` odwraca przewidywalne bity w `P[i]`, jednocześnie uszkadzając `P[i-1]`. Modyfikacja IV pozwala zaatakować pierwszy blok plaintextu bez uszkadzania wcześniejszego bloku plaintextu.
- Jeśli system ujawnia, czy padding jest prawidłowy czy nieprawidłowy, możesz mieć **padding oracle**.

### CTR

CTR zmienia AES w szyfr strumieniowy: `C = P XOR keystream`.

Jeśli nonce/IV zostanie ponownie użyty z tym samym kluczem:

- `C1 XOR C2 = P1 XOR P2` (klasyczne ponowne użycie keystreamu)
- Znając plaintext, możesz odzyskać keystream i odszyfrować inne wiadomości.

**Wzorce wykorzystania ponownego użycia nonce/IV**

- Odzyskaj keystream wszędzie tam, gdzie plaintext jest znany lub możliwy do odgadnięcia:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Zastosuj odzyskane bajty keystreamu do odszyfrowania dowolnego innego ciphertextu utworzonego z użyciem tej samej kombinacji key+IV i na tych samych offsetach.
- Dane o silnej strukturze (np. certyfikaty ASN.1/X.509, nagłówki plików, JSON/CBOR) zawierają duże obszary znanego plaintextu. Często można wykonać XOR ciphertextu certyfikatu z przewidywalną treścią certyfikatu, aby wyprowadzić keystream, a następnie odszyfrować inne sekrety zaszyfrowane z użyciem ponownie użytego IV. Zobacz także [TLS & Certificates](../tls-and-certificates/README.md), aby poznać typowe układy certyfikatów.<sup>[[1]](#references)</sup>
- Gdy wiele sekretów w **tym samym serializowanym formacie/rozmiarze** jest szyfrowanych z użyciem tej samej kombinacji key+IV, wyrównanie pól leak nawet bez pełnego znanego plaintextu. Przykład: klucze RSA PKCS#8 o tym samym rozmiarze modułu umieszczają czynniki pierwsze na odpowiadających sobie offsetach (około 99,6% wyrównania dla 2048 bitów). Wykonanie XOR dwóch ciphertextów z użyciem ponownie użytego keystreamu izoluje `p ⊕ p'` / `q ⊕ q'`, co można odzyskać brute-force w kilka sekund.<sup>[[1]](#references)</sup>
- Domyślne IV w bibliotekach (np. stałe `000...01`) są krytycznym footgunem: każde szyfrowanie powtarza ten sam keystream, zmieniając CTR w ponownie używany one-time pad.<sup>[[1]](#references)</sup>

**Podatność CTR na modyfikacje**

- CTR zapewnia wyłącznie poufność: zmiana bitów w ciphertext deterministycznie zmienia te same bity w plaintext. Bez authentication tag atakujący może niezauważenie manipulować danymi (np. modyfikować klucze, flagi lub wiadomości).
- Używaj AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 itd.) i wymuszaj weryfikację taga, aby wykrywać zmiany bitów.

### GCM

GCM również poważnie zawodzi przy ponownym użyciu nonce. Jeśli ta sama kombinacja key+nonce zostanie użyta więcej niż raz, zwykle otrzymasz:

- Ponowne użycie keystreamu podczas szyfrowania (podobnie jak w CTR), umożliwiające odzyskanie plaintextu, gdy znany jest dowolny plaintext.
- Utratę gwarancji integralności. W zależności od tego, co zostanie ujawnione (wiele par message/tag z tym samym nonce), atakujący mogą być w stanie fałszować tagi.

Wskazówki operacyjne:

- Traktuj "nonce reuse" w AEAD jako krytyczną podatność.
- Odporne na niewłaściwe użycie AEAD, takie jak AES-GCM-SIV, ograniczają skutki ponownego użycia nonce. Wywołujący nadal powinien dostarczać unikalne nonce zgodnie z wymaganiami interfejsu konstrukcji; przypadkowe ponowne użycie ma ograniczone konsekwencje w porównaniu ze zwykłym GCM.<sup>[[3]](#references)[[4]](#references)</sup>
- Jeśli masz wiele ciphertextów z tym samym nonce, zacznij od sprawdzenia zależności w stylu `C1 XOR C2 = P1 XOR P2`.

### Narzędzia

- [CyberChef](https://gchq.github.io/CyberChef/) do szybkich eksperymentów.<sup>[[8]](#references)</sup>
- Pakiet [PyCryptodome](https://www.pycryptodome.org/) dla Python do tworzenia skryptów.<sup>[[9]](#references)</sup>

## Wzorce wykorzystania ECB

ECB (Electronic Code Book) szyfruje każdy blok niezależnie:

- identyczne bloki plaintextu → identyczne bloki ciphertextu
- leak struktury i umożliwia ataki w stylu cut-and-paste

![Diagram blokowy deszyfrowania w trybie ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Pomysł na wykrycie: wzorzec tokenu/cookie

Jeśli logujesz się kilka razy i **zawsze otrzymujesz to samo cookie**, ciphertext może być deterministyczny (ECB lub stały IV).

Jeśli utworzysz dwóch użytkowników z w większości identycznymi układami plaintextu (np. długimi powtarzającymi się znakami) i zobaczysz powtarzające się bloki ciphertextu na tych samych offsetach, ECB jest głównym podejrzanym.

### Wzorce wykorzystania

#### Usuwanie całych bloków

Jeśli format tokenu wygląda na przykład tak: `<username>|<password>`, a granica bloku jest wyrównana, czasami możesz utworzyć użytkownika tak, aby blok `admin` był wyrównany, a następnie usunąć poprzedzające bloki, aby uzyskać prawidłowy token dla `admin`.

#### Przenoszenie bloków

Jeśli backend toleruje padding/dodatkowe spacje (`admin` vs `admin    `), możesz:

- Wyrównać blok zawierający `admin   `
- Zamienić/użyć ponownie tego bloku ciphertextu w innym tokenie

## Padding Oracle

### Co to jest

W trybie CBC, jeśli serwer ujawnia (bezpośrednio lub pośrednio), czy odszyfrowany plaintext ma **prawidłowy padding PKCS#7**, często możesz:<sup>[[7]](#references)</sup>

- Odszyfrować ciphertext bez klucza
- Utworzyć ciphertext, który odszyfruje się do wybranego plaintextu, gdy możesz przesyłać spreparowane poprzedzające bloki lub IV, a aplikacja akceptuje wynikową wiadomość z prawidłowym paddingiem

Oracle może mieć postać:

- Konkretnego komunikatu błędu
- Innego statusu HTTP / rozmiaru odpowiedzi
- Różnicy czasu odpowiedzi

### Praktyczne wykorzystanie

PadBuster to klasyczne narzędzie:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Przykład:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notatki:

- Rozmiar bloku często wynosi `16` dla AES.
- `-encoding 0` oznacza Base64.
- Użyj `-error`, jeśli oracle opiera się na konkretnym ciągu znaków.

### Dlaczego to działa

Deszyfrowanie CBC oblicza `P[i] = D(C[i]) XOR C[i-1]`. Modyfikując bajty w `C[i-1]` i obserwując, czy padding jest poprawny, możesz odzyskać `P[i]` bajt po bajcie.

## Bit-flipping in CBC

Nawet bez padding oracle CBC jest podatny na modyfikacje. Jeśli możesz zmodyfikować bloki ciphertextu, a aplikacja używa odszyfrowanego plaintextu jako ustrukturyzowanych danych (np. `role=user`), możesz odwrócić określone bity, aby zmienić wybrane bajty plaintextu na konkretnej pozycji w następnym bloku.

Typowy wzorzec CTF:

- Token = `IV || C1 || C2 || ...`
- Kontrolujesz bajty w `C[i]`
- Celujesz w bajty plaintextu w `P[i+1]`, ponieważ `P[i+1] = D(C[i+1]) XOR C[i]`

Samo w sobie nie jest to przełamaniem poufności, ale jest częstym prymitywem eskalacji uprawnień, gdy brakuje integralności.

## CBC-MAC

CBC-MAC jest bezpieczny tylko w określonych warunkach (zwłaszcza dla **wiadomości o stałej długości** i przy poprawnym rozdzieleniu domen). AES-CMAC to standaryzowana konstrukcja, która bezpiecznie obsługuje dane wejściowe o zmiennej długości.<sup>[[5]](#references)</sup>

### Klasyczny wzorzec forgery dla zmiennej długości

CBC-MAC jest zwykle obliczany następująco:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Jeśli możesz uzyskać tagi dla wybranych wiadomości, często możesz stworzyć tag dla konkatenacji (lub powiązanej konstrukcji) bez znajomości klucza, wykorzystując sposób, w jaki CBC łączy bloki.

Często pojawia się to w cookies/tokenach CTF, w których username lub rola są zabezpieczane za pomocą CBC-MAC.

### Bezpieczniejsze alternatywy

- Używaj HMAC (SHA-256/512)
- Używaj CMAC (AES-CMAC) poprawnie
- Dołączaj długość wiadomości / rozdzielenie domen

## Szyfry strumieniowe: XOR i RC4

### Model mentalny

Większość sytuacji związanych z szyframi strumieniowymi sprowadza się do:

`ciphertext = plaintext XOR keystream`

Zatem:

- Jeśli znasz plaintext, odzyskujesz keystream.
- Jeśli keystream jest ponownie używany (ta sama kombinacja key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Szyfrowanie oparte na XOR

Jeśli znasz dowolny fragment plaintextu na pozycji `i`, możesz odzyskać bajty keystreamu i odszyfrować inne ciphertexty na tych pozycjach.

Automatyczne solvery:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 to przestarzały szyfr strumieniowy; szyfrowanie i deszyfrowanie są tą samą operacją XOR. Znane biasy sprawiają, że nie nadaje się on do nowych systemów, a TLS wyraźnie zabrania używania jego zestawów szyfrów.<sup>[[6]](#references)</sup>

Jeśli możesz uzyskać wynik szyfrowania RC4 znanego plaintextu przy użyciu tego samego klucza, możesz odzyskać keystream i odszyfrować inne wiadomości o tej samej długości/przesunięciu.

Referencyjny writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Nieostrożność a kunszt w kryptografii](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A – Zalecenie dotyczące trybów działania szyfrów blokowych](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D – Zalecenie dotyczące Galois/Counter Mode (GCM) i GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 – AES-GCM-SIV: Uwierzytelnione szyfrowanie odporne na niewłaściwe użycie nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 – Algorytm AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 – Zakaz zestawów szyfrów RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide – Testowanie padding oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Dokumentacja PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
