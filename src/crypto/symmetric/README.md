# Kryptografia symetryczna

{{#include ../../banners/hacktricks-training.md}}

## Na co zwracać uwagę w CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: różne błędy/czasy odpowiedzi dla złego paddingu.
- **MAC confusion**: użycie CBC-MAC dla wiadomości o zmiennej długości, lub błędy typu MAC-then-encrypt.
- **XOR everywhere**: stream ciphers i niestandardowe konstrukcje często sprowadzają się do XOR z keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. To umożliwia:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

Jeśli możesz kontrolować plaintext i obserwować ciphertext (lub cookies), spróbuj wygenerować powtarzające się bloki (np. wiele `A`) i sprawdź powtórzenia.

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Jeśli system ujawnia rozróżnienie między poprawnym paddingiem a niepoprawnym, możesz mieć **padding oracle**.

### CTR

CTR zamienia AES w stream cipher: `C = P XOR keystream`.

Jeśli nonce/IV jest ponownie używany z tym samym kluczem:

- `C1 XOR C2 = P1 XOR P2` (klasyczne reuse keystream)
- Przy znanym plaintext można odzyskać keystream i odszyfrować inne wiadomości.

**Nonce/IV reuse exploitation patterns**

- Odzyskaj keystream tam, gdzie plaintext jest znany/zgadniony:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Zastosuj odzyskane bajty keystream do odszyfrowania dowolnego innego ciphertext wygenerowanego z tym samym key+IV na tych samych offsetach.
- Dane o silnej strukturze (np. ASN.1/X.509 certificates, nagłówki plików, JSON/CBOR) dają duże regiony znanego-plaintext. Często możesz XORować ciphertext certyfikatu z przewidywalną częścią certyfikatu, żeby wyprowadzić keystream, a następnie odszyfrować inne sekrety szyfrowane pod ponownie używanym IV. Zobacz też [TLS & Certificates](../tls-and-certificates/README.md) dla typowych układów certyfikatów.
- Gdy wiele sekretów o tym samym serialized format/size jest szyfrowanych pod tym samym key+IV, wyrównanie pól wycieka nawet bez pełnego known plaintext. Przykład: PKCS#8 RSA keys o tym samym rozmiarze modulus umieszczają czynniki pierwsze w dopasowanych offsetach (~99.6% wyrównania dla 2048-bit). XOR dwóch ciphertext pod reuse keystream izoluje `p ⊕ p'` / `q ⊕ q'`, które można bruteforcować w sekundach.
- Domyślne IV w bibliotekach (np. stałe `000...01`) to krytyczny footgun: każde szyfrowanie powtarza ten sam keystream, zamieniając CTR w reuse one-time pad.

**CTR malleability**

- CTR zapewnia tylko confidentiality: zmiana bitów w ciphertext deterministycznie zmienia te same bity w plaintext. Bez tagu uwierzytelniającego, atakujący mogą modyfikować dane (np. modyfikować klucze, flagi lub wiadomości) bez wykrycia.
- Używaj AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, itd.) i egzekwuj weryfikację tagu, aby wykrywać bit-flipy.

### GCM

GCM też bardzo źle się zachowuje przy nonce reuse. Jeśli ten sam key+nonce jest użyty więcej niż raz, zwykle otrzymujesz:

- Keystream reuse dla szyfrowania (jak CTR), umożliwiając odzyskanie plaintext gdy jakikolwiek plaintext jest znany.
- Utratę gwarancji integralności. W zależności od ujawnionych informacji (wiele message/tag pairs pod tym samym nonce), atakujący mogą być w stanie sfałszować tagi.

Zalecenia operacyjne:

- Traktuj "nonce reuse" w AEAD jako krytyczną lukę.
- Misuse-resistant AEADs (np. GCM-SIV) redukują skutki nonce-misuse, ale nadal wymagają unikalnych nonces/IVs.
- Jeśli masz kilka ciphertext pod tym samym nonce, zacznij od sprawdzenia relacji w stylu `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) szyfruje każdy blok niezależnie:

- equal plaintext blocks → equal ciphertext blocks
- to ujawnia strukturę i umożliwia ataki typu cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Jeśli logujesz się kilka razy i **zawsze otrzymujesz ten sam cookie**, ciphertext może być deterministyczny (ECB albo fixed IV).

Jeśli utworzysz dwóch użytkowników o w większości identycznych layoutach plaintext (np. długie powtarzające się znaki) i zobaczysz powtarzające się bloki ciphertext w tych samych offsetach, ECB jest głównym podejrzanym.

### Exploitation patterns

#### Removing entire blocks

Jeżeli format tokena wygląda np. jak `<username>|<password>` i granica bloków się wyrównuje, czasem możesz spreparować użytkownika tak, żeby blok z `admin` znalazł się wyrównany, a następnie usunąć poprzedzające bloki, aby uzyskać ważny token dla `admin`.

#### Moving blocks

Jeżeli backend toleruje padding/dodatkowe spacje (`admin` vs `admin    `), możesz:

- Wyrównać blok, który zawiera `admin   `
- Zamienić/ponownie użyć ten ciphertext block w innym tokenie

## Padding Oracle

### Co to jest

W trybie CBC, jeśli serwer ujawnia (bezpośrednio lub pośrednio), czy odszyfrowany plaintext ma **valid PKCS#7 padding**, często możesz:

- Odszyfrować ciphertext bez klucza
- Szyfrować wybrany plaintext (forge ciphertext)

Oracle może być:

- Specyficzny komunikat o błędzie
- Inny HTTP status / rozmiar odpowiedzi
- Różnica w czasie odpowiedzi

### Practical exploitation

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notatki:

- Rozmiar bloku często wynosi `16` dla AES.
- `-encoding 0` oznacza Base64.
- Użyj `-error`, jeśli oracle zwraca konkretny ciąg.

### Dlaczego to działa

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Modyfikując bajty w `C[i-1]` i obserwując, czy padding jest prawidłowy, możesz odzyskać `P[i]` bajt po bajcie.

## Bit-flipping w CBC

Nawet bez padding oracle, CBC jest podatne na modyfikacje. Jeśli możesz zmieniać bloki szyfrogramu, a aplikacja traktuje odszyfrowany tekst jawny jako dane strukturalne (np. `role=user`), możesz flipować konkretne bity, aby zmienić wybrane bajty tekstu jawnego w wybranej pozycji w następnym bloku.

Typowy wzorzec CTF:

- Token = `IV || C1 || C2 || ...`
- Kontrolujesz bajty w `C[i]`
- Kierujesz się na bajty w `P[i+1]`, ponieważ `P[i+1] = D(C[i+1]) XOR C[i]`

To samo w sobie nie jest naruszeniem poufności, ale jest powszechną prymitywą eskalacji uprawnień, gdy brakuje integralności.

## CBC-MAC

CBC-MAC jest bezpieczny tylko w określonych warunkach (w szczególności **wiadomości o stałej długości** i poprawne rozdzielenie domen).

### Klasyczny wzorzec fałszerstwa dla wiadomości o zmiennej długości

CBC-MAC jest zwykle obliczany jako:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Jeśli możesz uzyskać tagi dla wybranych wiadomości, często możesz skonstruować tag dla konkatenacji (lub powiązanej konstrukcji) bez znajomości klucza, wykorzystując sposób, w jaki CBC łańcuchuje bloki.

Często pojawia się to w CTF-owych cookies/tokens, które MACują username lub role za pomocą CBC-MAC.

### Bezpieczniejsze alternatywy

- Używaj HMAC (SHA-256/512)
- Używaj prawidłowo CMAC (AES-CMAC)
- Uwzględnij długość wiadomości / rozdzielenie domen

## Szyfry strumieniowe: XOR i RC4

### Model mentalny

Większość sytuacji związanych z szyframi strumieniowymi sprowadza się do:

`ciphertext = plaintext XOR keystream`

Zatem:

- Jeśli znasz tekst jawny, odzyskujesz keystream.
- Jeśli keystream jest ponownie użyty (ten sam key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Szyfrowanie oparte na XOR

Jeśli znasz dowolny segment tekstu jawnego na pozycji `i`, możesz odzyskać bajty keystreamu i odszyfrować inne szyfrogramy na tych pozycjach.

Narzędzia automatyczne:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 jest szyfrem strumieniowym; szyfrowanie/odszyfrowanie to ta sama operacja.

Jeśli możesz uzyskać RC4 encryption znanego tekstu jawnego pod tym samym kluczem, możesz odzyskać keystream i odszyfrować inne wiadomości o tej samej długości/offsetcie.

Opis referencyjny (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Źródła

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
