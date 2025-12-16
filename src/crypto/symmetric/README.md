# Szyfrowanie symetryczne

{{#include ../../banners/hacktricks-training.md}}

## Na co zwracać uwagę w CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: różne błędy/czasy odpowiedzi dla niepoprawnego paddingu.
- **MAC confusion**: używanie CBC-MAC dla wiadomości o zmiennej długości, lub błędy typu MAC-then-encrypt.
- **XOR everywhere**: szyfry strumieniowe i niestandardowe konstrukcje często sprowadzają się do XOR z keystreamem.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: równe bloki tekstu jawnego → równe bloki tekstu zaszyfrowanego. To umożliwia:

- Cut-and-paste / block reordering
- Usuwanie bloków (jeśli format pozostaje poprawny)

Jeśli możesz kontrolować tekst jawny i obserwować ciphertext (lub cookies), spróbuj wygenerować powtarzające się bloki (np. wiele `A`) i sprawdź, czy pojawiają się powtórzenia.

### CBC: Cipher Block Chaining

- CBC jest **modyfikowalny**: przełączenie bitów w `C[i-1]` powoduje przewidywalne zmiany w `P[i]`.
- Jeśli system ujawnia rozróżnienie między poprawnym paddingiem a niepoprawnym, możesz mieć padding oracle.

### CTR

CTR zamienia AES w szyfr strumieniowy: `C = P XOR keystream`.

Jeśli nonce/IV jest ponownie używany z tym samym kluczem:

- `C1 XOR C2 = P1 XOR P2` (klasyczne ponowne użycie keystreamu)
- Przy znanym tekście jawnym można odzyskać keystream i odszyfrować inne wiadomości.

### GCM

GCM również zawodzi przy ponownym użyciu nonce. Jeśli ten sam key+nonce jest użyty więcej niż raz, zwykle występuje:

- Ponowne użycie keystreamu dla szyfrowania (jak w CTR), co umożliwia odzyskanie tekstu jawnego gdy jakikolwiek tekst jest znany.
- Utrata gwarancji integralności. W zależności od ujawnionych danych (wiele par message/tag pod tym samym nonce), atakujący może być w stanie sfałszować tagi.

Zalecenia operacyjne:

- Traktuj "nonce reuse" w AEAD jako krytyczną wadę.
- Jeśli masz wiele ciphertextów pod tym samym nonce, zacznij od sprawdzenia relacji typu `C1 XOR C2 = P1 XOR P2`.

### Narzędzia

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) szyfruje każdy blok niezależnie:

- równe bloki tekstu jawnego → równe bloki tekstu zaszyfrowanego
- to ujawnia strukturę i umożliwia ataki typu cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Jeśli logujesz się kilkakrotnie i **zawsze otrzymujesz ten sam cookie**, ciphertext może być deterministyczny (ECB lub stały IV).

Jeśli utworzysz dwóch użytkowników z w dużej mierze identycznym układem tekstu (np. długie powtarzające się znaki) i zobaczysz powtarzające się bloki ciphertext w tych samych offsetach, ECB jest głównym podejrzanym.

### Exploitation patterns

#### Removing entire blocks

Jeśli format tokena wygląda jak `<username>|<password>` i granica bloku się wyrównuje, czasami możesz spreparować użytkownika tak, żeby blok z `admin` był wyrównany, a następnie usunąć poprzedzające bloki, aby uzyskać ważny token dla `admin`.

#### Moving blocks

Jeśli backend toleruje padding/dodatkowe spacje (`admin` vs `admin    `), możesz:

- Wyrównać blok zawierający `admin   `
- Zamienić/ponownie użyć ten blok ciphertext w innym tokenie

## Padding Oracle

### Co to jest

W trybie CBC, jeśli serwer ujawnia (bezpośrednio lub pośrednio), czy odszyfrowany tekst jawny ma **poprawny PKCS#7 padding**, często możesz:

- Odszyfrować ciphertext bez klucza
- Zaszyfrować wybrany tekst jawny (podrobić ciphertext)

Oracle może być:

- Konkretna wiadomość błędu
- Różny status HTTP / rozmiar odpowiedzi
- Różnica w czasie odpowiedzi

### Practical exploitation

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Przykład:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Uwagi:

- Rozmiar bloku często wynosi `16` dla AES.
- `-encoding 0` oznacza Base64.
- Użyj `-error`, jeśli oracle jest konkretnym stringiem.

### Dlaczego to działa

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Poprzez modyfikowanie bajtów w `C[i-1]` i obserwowanie, czy padding jest poprawny, możesz odzyskać `P[i]` bajt po bajcie.

## Bit-flipping in CBC

Nawet bez padding oracle, CBC jest podatny na modyfikacje. Jeśli możesz modyfikować bloki szyfrogramu i aplikacja używa odszyfrowanego tekstu jawnego jako danych strukturalnych (np. `role=user`), możesz odwracać konkretne bity, by zmienić wybrane bajty tekstu jawnego na określonej pozycji w następnym bloku.

Typowy wzorzec CTF:

- Token = `IV || C1 || C2 || ...`
- Kontrolujesz bajty w `C[i]`
- Celujesz w bajty tekstu jawnego w `P[i+1]`, ponieważ `P[i+1] = D(C[i+1]) XOR C[i]`

Samo w sobie nie łamie poufności, ale jest to powszechny prymityw eskalacji uprawnień, gdy brakuje integralności.

## CBC-MAC

CBC-MAC jest bezpieczny tylko w określonych warunkach (w szczególności **wiadomości o stałej długości** i poprawne rozdzielenie domen).

### Classic variable-length forgery pattern

CBC-MAC jest zwykle obliczany jako:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Jeśli możesz uzyskać tagi dla wybranych wiadomości, często możesz sfałszować tag dla konkatenacji (lub powiązanej konstrukcji) bez znajomości klucza, wykorzystując sposób łączenia bloków w CBC.

Często pojawia się to w CTF cookie/tokens, które MAC-ują username lub role za pomocą CBC-MAC.

### Bezpieczniejsze alternatywy

- Użyj HMAC (SHA-256/512)
- Użyj CMAC (AES-CMAC) prawidłowo
- Dołącz długość wiadomości / rozdzielenie domen

## Stream ciphers: XOR and RC4

### The mental model

Większość przypadków szyfrów strumieniowych sprowadza się do:

`ciphertext = plaintext XOR keystream`

Więc:

- Jeśli znasz tekst jawny, odzyskasz keystream.
- Jeśli keystream jest ponownie użyty (ten sam key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Jeśli znasz dowolny segment plaintext na pozycji `i`, możesz odzyskać bajty keystream i odszyfrować inne szyfrogramy w tych pozycjach.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 jest szyfrem strumieniowym; encrypt/decrypt to ta sama operacja.

Jeśli możesz uzyskać RC4 encryption znanego plaintext przy tym samym key, możesz odzyskać keystream i odszyfrować inne wiadomości o tej samej długości/przesunięciu.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
