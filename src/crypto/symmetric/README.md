# Kryptografia symetryczna

{{#include ../../banners/hacktricks-training.md}}

## Na co zwracać uwagę w CTFs

- **Nieprawidłowe użycie trybu**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: różne błędy/czasy odpowiedzi dla złego paddingu.
- **MAC confusion**: użycie CBC-MAC dla wiadomości o zmiennej długości, lub błędy typu MAC-then-encrypt.
- **XOR everywhere**: szyfry strumieniowe i niestandardowe konstrukcje często sprowadzają się do XOR z keystream.

## Tryby AES i nadużycia

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. That enables:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

Jeśli możesz kontrolować plaintext i obserwować ciphertext (lub cookies), spróbuj zrobić powtarzające się bloki (np. wiele `A`s) i sprawdź powtórzenia.

### CBC: Cipher Block Chaining

- CBC jest **modyfikowalny**: odwrócenie bitów w `C[i-1]` powoduje przewidywalne zmiany w `P[i]`.
- Jeśli system ujawnia prawidłowy padding vs nieprawidłowy padding, możesz mieć **padding oracle**.

### CTR

CTR zamienia AES w szyfr strumieniowy: `C = P XOR keystream`.

Jeśli nonce/IV jest ponownie użyty z tym samym kluczem:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Przy znanym plaintext można odzyskać keystream i odszyfrować inne.

### GCM

GCM również źle się łamie przy ponownym użyciu nonce. Jeśli ten sam key+nonce jest użyty więcej niż raz, zwykle dostaniesz:

- Keystream reuse dla szyfrowania (jak CTR), umożliwiając odzyskanie plaintext gdy jakikolwiek plaintext jest znany.
- Utrata gwarancji integralności. W zależności od tego, co jest ujawniane (wiele par message/tag pod tym samym nonce), atakujący może być w stanie sfabrykować tagi.

Wskazówki operacyjne:

- Traktuj "nonce reuse" w AEAD jako krytyczną podatność.
- Jeśli masz wiele ciphertext pod tym samym nonce, zacznij od sprawdzenia relacji w stylu `C1 XOR C2 = P1 XOR P2`.

### Narzędzia

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## Wzorce wykorzystania ECB

ECB (Electronic Code Book) szyfruje każdy blok niezależnie:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Pomysł na wykrycie: token/cookie pattern

Jeśli logujesz się kilka razy i **zawsze dostajesz ten sam cookie**, ciphertext może być deterministyczny (ECB lub fixed IV).

Jeśli utworzysz dwóch użytkowników z w większości identycznym układem plaintext (np. długie powtarzające się znaki) i zobaczysz powtarzające się bloki ciphertext w tych samych offsetach, ECB jest głównym podejrzanym.

### Wzorce eksploatacji

#### Usuwanie całych bloków

Jeśli format tokenu wygląda jak `<username>|<password>` i granica bloku się wyrównuje, czasami możesz tak skonstruować użytkownika, żeby blok `admin` pojawił się wyrównany, a następnie usunąć wcześniejsze bloki, by uzyskać ważny token dla `admin`.

#### Przenoszenie bloków

Jeśli backend toleruje padding/extra spaces (`admin` vs `admin    `), możesz:

- Wyrównaj blok zawierający `admin   `
- Zamień/ponownie użyj tego bloku ciphertext w innym tokenie

## Padding Oracle

### Czym jest

W trybie CBC, jeśli serwer ujawnia (bezpośrednio lub pośrednio), czy odszyfrowany plaintext ma **valid PKCS#7 padding**, często możesz:

- Odszyfrować ciphertext bez klucza
- Zaszyfrować wybrany plaintext (sfabrykować ciphertext)

Oracle może mieć postać:

- Konkretnej wiadomości o błędzie
- Innego statusu HTTP / rozmiaru odpowiedzi
- Różnicy czasu

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
- Użyj `-error`, jeśli oracle zwraca konkretny ciąg znaków.

### Why it works

Odszyfrowanie CBC oblicza `P[i] = D(C[i]) XOR C[i-1]`. Modyfikując bajty w `C[i-1]` i obserwując, czy padding jest prawidłowy, możesz odzyskać `P[i]` bajt po bajcie.

## Bit-flipping in CBC

Even without a padding oracle, CBC is malleable. If you can modify ciphertext blocks and the application uses the decrypted plaintext as structured data (e.g., `role=user`), you can flip specific bits to change selected plaintext bytes at a chosen position in the next block.

Typowy wzorzec CTF:

- Token = `IV || C1 || C2 || ...`
- Kontrolujesz bajty w `C[i]`
- Celujesz w bajty plaintextu w `P[i+1]`, ponieważ `P[i+1] = D(C[i+1]) XOR C[i]`

To nie jest samo w sobie złamanie poufności, ale jest powszechnym prymitywem eskalacji uprawnień, gdy brakuje integralności.

## CBC-MAC

CBC-MAC jest bezpieczny tylko w określonych warunkach (szczególnie **wiadomości o stałej długości** i poprawna separacja domen).

### Classic variable-length forgery pattern

CBC-MAC jest zwykle obliczany jako:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Jeśli możesz uzyskać tagi dla wybranych wiadomości, często możesz stworzyć tag dla konkatenacji (lub powiązanej konstrukcji) bez znajomości klucza, wykorzystując sposób, w jaki CBC łączy bloki.

Często pojawia się to w cookies/tokenach CTF, które MAC-ują nazwę użytkownika lub rolę za pomocą CBC-MAC.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Uwzględnij długość wiadomości / separację domen

## Stream ciphers: XOR and RC4

### The mental model

Większość sytuacji ze stream cipher sprowadza się do:

`ciphertext = plaintext XOR keystream`

Więc:

- Jeśli znasz plaintext, odzyskujesz keystream.
- Jeśli keystream jest używany ponownie (ten sam key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Jeśli znasz dowolny segment plaintextu na pozycji `i`, możesz odzyskać bajty keystream i odszyfrować inne szyfrogramy na tych pozycjach.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 is a stream cipher; encrypt/decrypt are the same operation.

Jeśli możesz uzyskać RC4 encryption znanego plaintextu pod tym samym kluczem, możesz odzyskać keystream i odszyfrować inne wiadomości o tej samej długości/przesunięciu.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
