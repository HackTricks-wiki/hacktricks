# Szyfrowanie symetryczne

{{#include ../../banners/hacktricks-training.md}}

## Na co zwracać uwagę w CTF-ach

- **Niewłaściwe użycie trybu**: wzorce ECB, malleability CBC, ponowne użycie nonce w CTR/GCM.
- **Padding oracles**: różne błędy/czasy odpowiedzi dla nieprawidłowego paddingu.
- **Pomylenie MAC**: używanie CBC-MAC dla wiadomości o zmiennej długości lub błędy typu MAC-then-encrypt.
- **XOR wszędzie**: szyfry strumieniowe i niestandardowe konstrukcje często sprowadzają się do XOR z keystreamem.

## Tryby AES i ich niewłaściwe użycie

### ECB: Electronic Codebook

ECB leaks patterns: identyczne bloki plaintextu → identyczne bloki ciphertextu. Umożliwia to:

- Cut-and-paste / zmianę kolejności bloków
- Usuwanie bloków (jeśli format pozostanie poprawny)

Jeśli możesz kontrolować plaintext i obserwować ciphertext (lub cookies), spróbuj tworzyć powtarzające się bloki (np. wiele `A`) i szukać powtórzeń.

### CBC: Cipher Block Chaining

- CBC jest **malleable**: zmiana bitów w `C[i-1]` powoduje przewidywalną zmianę bitów w `P[i]`.
- Jeśli system ujawnia, czy padding jest prawidłowy, możesz mieć **padding oracle**.

### CTR

CTR zmienia AES w szyfr strumieniowy: `C = P XOR keystream`.

Jeśli nonce/IV zostanie ponownie użyty z tym samym kluczem:

- `C1 XOR C2 = P1 XOR P2` (klasyczne ponowne użycie keystreamu)
- Znając plaintext, możesz odzyskać keystream i odszyfrować inne dane.

**Wzorce eksploatacji ponownego użycia nonce/IV**

- Odzyskaj keystream wszędzie tam, gdzie plaintext jest znany lub możliwy do odgadnięcia:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Zastosuj odzyskane bajty keystreamu do odszyfrowania dowolnego innego ciphertextu utworzonego przy użyciu tego samego klucza+IV i tych samych offsetów.
- Dane o wysoce strukturalnym formacie (np. certyfikaty ASN.1/X.509, nagłówki plików, JSON/CBOR) dostarczają dużych obszarów znanego plaintextu. Często można wykonać XOR ciphertextu certyfikatu z przewidywalną zawartością certyfikatu, aby wyprowadzić keystream, a następnie odszyfrować inne sekrety zaszyfrowane przy użyciu ponownie użytego IV. Zobacz także [TLS & Certificates](../tls-and-certificates/README.md), aby poznać typowe układy certyfikatów.<sup>[[1]](#references)</sup>
- Gdy wiele sekretów o **tym samym serializowanym formacie/rozmiarze** jest szyfrowanych przy użyciu tego samego klucza+IV, wyrównanie pól leaks nawet bez pełnego znanego plaintextu. Przykład: klucze RSA PKCS#8 o tym samym rozmiarze modułu umieszczają czynniki pierwsze na odpowiadających sobie offsetach (wyrównanie na poziomie ~99,6% dla 2048 bitów). Wykonanie XOR dwóch ciphertextów przy użyciu ponownie użytego keystreamu izoluje `p ⊕ p'` / `q ⊕ q'`, które można odzyskać brute-force w kilka sekund.<sup>[[1]](#references)</sup>
- Domyślne IV w bibliotekach (np. stałe `000...01`) to krytyczny footgun: każde szyfrowanie powtarza ten sam keystream, zmieniając CTR w ponownie używany one-time pad.<sup>[[1]](#references)</sup>

**Malleability CTR**

- CTR zapewnia wyłącznie poufność: zmiana bitów w ciphertext deterministycznie zmienia te same bity w plaintexcie. Bez tagu uwierzytelniającego atakujący mogą niezauważenie modyfikować dane (np. zmieniać klucze, flagi lub wiadomości).
- Używaj AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 itd.) i wymuszaj weryfikację tagu, aby wykrywać zmiany bitów.

### GCM

GCM również poważnie zawodzi przy ponownym użyciu nonce. Jeśli ten sam klucz+nonce zostanie użyty więcej niż raz, zazwyczaj otrzymasz:

- Ponowne użycie keystreamu podczas szyfrowania (tak jak w CTR), umożliwiające odzyskanie plaintextu, gdy znany jest dowolny plaintext.
- Utratę gwarancji integralności. Zależnie od tego, co zostanie ujawnione (wiele par wiadomość/tag przy tym samym nonce), atakujący mogą być w stanie sfałszować tagi.

Wskazówki operacyjne:

- Traktuj „ponowne użycie nonce” w AEAD jako krytyczną podatność.
- Misuse-resistant AEAD (np. GCM-SIV) ogranicza skutki niewłaściwego użycia nonce, ale nadal wymaga unikalnych nonce/IV.
- Jeśli masz wiele ciphertextów przy tym samym nonce, zacznij od sprawdzenia zależności w stylu `C1 XOR C2 = P1 XOR P2`.

### Narzędzia

- CyberChef do szybkich eksperymentów: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` do tworzenia skryptów

## Wzorce eksploatacji ECB

ECB (Electronic Code Book) szyfruje każdy blok niezależnie:

- identyczne bloki plaintextu → identyczne bloki ciphertextu
- leaks to strukturę i umożliwia ataki w stylu cut-and-paste

![Diagram blokowy deszyfrowania w trybie ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Pomysł na wykrycie: wzorzec tokenu/cookie

Jeśli logujesz się kilka razy i **zawsze otrzymujesz to samo cookie**, ciphertext może być deterministyczny (ECB lub stały IV).

Jeśli utworzysz dwóch użytkowników z w większości identycznymi układami plaintextu (np. z długimi powtarzającymi się znakami) i zobaczysz powtarzające się bloki ciphertextu na tych samych offsetach, ECB jest głównym podejrzanym.

### Wzorce eksploatacji

#### Usuwanie całych bloków

Jeśli format tokenu wygląda na przykład tak: `<username>|<password>` i granica bloku jest właściwie wyrównana, czasami możesz utworzyć użytkownika tak, aby blok `admin` był wyrównany, a następnie usunąć poprzedzające go bloki, uzyskując prawidłowy token dla `admin`.

#### Przenoszenie bloków

Jeśli backend akceptuje padding/dodatkowe spacje (`admin` vs `admin    `), możesz:

- Wyrównać blok zawierający `admin   `
- Zamienić/ponownie użyć tego bloku ciphertextu w innym tokenie

## Padding Oracle

### Co to jest

W trybie CBC, jeśli serwer ujawnia (bezpośrednio lub pośrednio), czy odszyfrowany plaintext ma **prawidłowy padding PKCS#7**, często możesz:

- Odszyfrować ciphertext bez klucza
- Zaszyfrować wybrany plaintext (sfałszować ciphertext)

Oracle może być:

- Konkretny komunikat błędu
- Inny status HTTP / rozmiar odpowiedzi
- Różnica czasu odpowiedzi

### Praktyczna eksploatacja

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
- Użyj `-error`, jeśli oracle zwraca określony string.

### Dlaczego to działa

Deszyfrowanie CBC oblicza `P[i] = D(C[i]) XOR C[i-1]`. Modyfikując bajty w `C[i-1]` i obserwując, czy padding jest prawidłowy, możesz odzyskać `P[i]` bajt po bajcie.

## Bit-flipping in CBC

Nawet bez padding oracle CBC jest podatny na modyfikacje. Jeśli możesz modyfikować bloki ciphertextu, a aplikacja używa odszyfrowanego plaintextu jako ustrukturyzowanych danych (np. `role=user`), możesz odwracać określone bity, aby zmieniać wybrane bajty plaintextu na wybranej pozycji w następnym bloku.

Typowy schemat CTF:

- Token = `IV || C1 || C2 || ...`
- Kontrolujesz bajty w `C[i]`
- Celujesz w bajty plaintextu w `P[i+1]`, ponieważ `P[i+1] = D(C[i+1]) XOR C[i]`

Samo w sobie nie jest to złamaniem poufności, ale jest częstym prymitywem eskalacji uprawnień, gdy brakuje integralności.

## CBC-MAC

CBC-MAC jest bezpieczny tylko w określonych warunkach (w szczególności dla **wiadomości o stałej długości** i przy prawidłowym rozdzieleniu domen).

### Klasyczny schemat forgery dla zmiennej długości

CBC-MAC jest zwykle obliczany następująco:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Jeśli możesz uzyskiwać tagi dla wybranych wiadomości, często możesz stworzyć tag dla konkatenacji (lub powiązanej konstrukcji) bez znajomości klucza, wykorzystując sposób, w jaki CBC łączy bloki.

Często pojawia się to w cookies/tokenach CTF, które obliczają MAC dla nazwy użytkownika lub roli za pomocą CBC-MAC.

### Bezpieczniejsze alternatywy

- Używaj HMAC (SHA-256/512)
- Używaj CMAC (AES-CMAC) prawidłowo
- Uwzględnij długość wiadomości / rozdzielenie domen

## Stream ciphers: XOR and RC4

### Model mentalny

Większość sytuacji związanych ze stream ciphers sprowadza się do:

`ciphertext = plaintext XOR keystream`

Zatem:

- Jeśli znasz plaintext, odzyskujesz keystream.
- Jeśli keystream jest ponownie używany (ten sam key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Szyfrowanie oparte na XOR

Jeśli znasz dowolny fragment plaintextu na pozycji `i`, możesz odzyskać bajty keystreamu i odszyfrować inne ciphertexty na tych pozycjach.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 jest stream cipher; szyfrowanie i deszyfrowanie to ta sama operacja.

Jeśli możesz uzyskać szyfrowanie RC4 znanego plaintextu przy użyciu tego samego klucza, możesz odzyskać keystream i odszyfrować inne wiadomości o tej samej długości/przesunięciu.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Nieostrożność kontra kunszt w kryptografii](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
