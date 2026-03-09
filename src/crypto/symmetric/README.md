# Szyfrowanie symetryczne

{{#include ../../banners/hacktricks-training.md}}

## Na co zwracać uwagę w CTFs

- **Niewłaściwe użycie trybu**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: różne błędy/czasy reakcji dla złego paddingu.
- **MAC confusion**: użycie CBC-MAC dla wiadomości o zmiennej długości, lub błędy typu MAC-then-encrypt.
- **XOR everywhere**: stream ciphers i niestandardowe konstrukcje często sprowadzają się do XOR z keystream.

## AES: tryby i niewłaściwe użycie

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. To umożliwia:

- Cut-and-paste / block reordering
- Usuwanie bloków (jeśli format pozostaje poprawny)

Jeśli możesz kontrolować plaintext i obserwować ciphertext (lub cookies), spróbuj wygenerować powtarzające się bloki (np. wiele `A`) i szukaj powtórzeń.

### CBC: Cipher Block Chaining

- CBC jest modyfikowalny (**malleable**): zmiana bitów w `C[i-1]` powoduje przewidywalną zmianę bitów w `P[i]`.
- Jeśli system ujawnia rozróżnienie między valid a invalid padding, możesz mieć **padding oracle**.

### CTR

CTR zamienia AES w stream cipher: `C = P XOR keystream`.

Jeśli nonce/IV jest ponownie użyty z tym samym kluczem:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Mając znany/plaintext, możesz odzyskać keystream i odszyfrować inne.

**Nonce/IV reuse exploitation patterns**

- Odzyskaj keystream tam, gdzie plaintext jest znany/zgadywalny:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Zastosuj odzyskane bajty keystreamu, aby odszyfrować dowolny inny ciphertext wygenerowany tym samym key+IV na tych samych offsetach.
- Dane o silnej strukturze (np. ASN.1/X.509 certificates, file headers, JSON/CBOR) dają duże regiony known-plaintext. Często można XORować ciphertext certyfikatu z przewidywalną częścią certyfikatu, by wyprowadzić keystream, a następnie odszyfrować inne sekrety zaszyfrowane pod tym samym reused IV. Zobacz też [TLS & Certificates](../tls-and-certificates/README.md) dla typowych układów certyfikatów.
- Gdy wiele sekretów tego **samego zserializowanego formatu/rozmiaru** jest szyfrowanych pod tym samym key+IV, field alignment leaks nawet bez pełnego known plaintext. Przykład: PKCS#8 RSA keys o tym samym rozmiarze modułu umieszczają czynniki pierwsze na odpowiadających offsetach (~99.6% zgodności dla 2048-bit). XOR-owanie dwóch ciphertext pod reused keystream izoluje `p ⊕ p'` / `q ⊕ q'`, które można bruteforce'owo odzyskać w kilka sekund.
- Domyślne IV w bibliotekach (np. stałe `000...01`) są krytycznym footgun: każde szyfrowanie powtarza ten sam keystream, zmieniając CTR w reused one-time pad.

**CTR malleability**

- CTR zapewnia tylko poufność: zmiana bitów w ciphertext deterministycznie zmienia te same bity w plaintext. Bez authentication tag, atakujący mogą modyfikować dane (np. zmienić klucze, flagi lub wiadomości) bez wykrycia.
- Używaj AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, itp.) i egzekwuj weryfikację tagu, aby wykrywać bit-flipy.

### GCM

GCM także źle się łamie przy ponownym użyciu nonce. Jeśli ten sam key+nonce jest użyty więcej niż raz, zwykle otrzymujesz:

- Keystream reuse dla szyfrowania (jak CTR), umożliwiając odzyskanie plaintext, gdy jakikolwiek plaintext jest znany.
- Utratę gwarancji integralności. W zależności od tego, co jest ujawnione (wiele par message/tag pod tym samym nonce), atakujący może być w stanie sfałszować tagi.

Zalecenia operacyjne:

- Traktuj "nonce reuse" w AEAD jako krytyczną podatność.
- Misuse-resistant AEAD (np. GCM-SIV) zmniejszają skutki nonce-misuse, ale nadal wymagają unikalnych nonces/IVs.
- Jeśli masz wiele ciphertext pod tym samym nonce, zacznij od sprawdzenia relacji w stylu `C1 XOR C2 = P1 XOR P2`.

### Narzędzia

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## Wzorce eksploatacji ECB

ECB (Electronic Code Book) szyfruje każdy blok niezależnie:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Pomysł na wykrycie: token/cookie pattern

Jeśli logujesz się kilka razy i **zawsze otrzymujesz ten sam cookie**, ciphertext może być deterministyczny (ECB lub stałe IV).

Jeśli utworzysz dwóch użytkowników o w większości identycznych układach plaintext (np. długie powtarzające się znaki) i zobaczysz powtarzające się bloki ciphertext na tych samych offsetach, ECB jest głównym podejrzanym.

### Wzorce eksploatacji

#### Usuwanie całych bloków

Jeśli format tokena to coś w stylu `<username>|<password>` i granica bloków się wyrównuje, czasem możesz skonstruować użytkownika tak, żeby blok `admin` był wyrównany, a następnie usunąć poprzedzające bloki, by uzyskać ważny token dla `admin`.

#### Przenoszenie bloków

Jeśli backend toleruje padding/dodatkowe spacje (`admin` vs `admin    `), możesz:

- Wyrównać blok zawierający `admin   `
- Zamienić/ponownie użyć ten ciphertext block w innym tokenie

## Padding Oracle

### Co to jest

W trybie CBC, jeśli serwer ujawnia (bezpośrednio lub pośrednio), czy odszyfrowany plaintext ma **valid PKCS#7 padding**, często możesz:

- Odszyfrować ciphertext bez klucza
- Zaszyfrować wybrany plaintext (sfałszować ciphertext)

Oracle może być:

- Konkretna wiadomość o błędzie
- Inny HTTP status / rozmiar odpowiedzi
- Różnica w czasie odpowiedzi

### Praktyczne wykorzystanie

PadBuster is the classic tool:

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
- Użyj `-error` jeśli oracle jest konkretnym stringiem.

### Why it works

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Poprzez modyfikowanie bajtów w `C[i-1]` i obserwowanie, czy padding jest poprawny, możesz odzyskać `P[i]` bajt po bajcie.

## Bit-flipping in CBC

Nawet bez padding oracle, CBC jest modyfikowalny. Jeśli możesz modyfikować bloki szyfrogramu i aplikacja używa odszyfrowanego plaintextu jako danych strukturalnych (np. `role=user`), możesz odwrócić konkretne bity, aby zmienić wybrane bajty plaintextu na wybranej pozycji w następnym bloku.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- Kontrolujesz bajty w `C[i]`
- Celujesz w bajty plaintextu w `P[i+1]`, ponieważ `P[i+1] = D(C[i+1]) XOR C[i]`

To samo w sobie nie łamie poufności, ale jest to powszechne prymitywum eskalacji uprawnień, gdy brakuje integralności.

## CBC-MAC

CBC-MAC jest bezpieczny tylko pod określonymi warunkami (w szczególności **wiadomości o stałej długości** oraz poprawne rozdzielenie domen).

### Classic variable-length forgery pattern

CBC-MAC jest zwykle obliczany jako:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Jeśli możesz uzyskać tagi dla wybranych wiadomości, często możesz stworzyć tag dla konkatenacji (lub pokrewnej konstrukcji) bez znajomości klucza, wykorzystując sposób, w jaki CBC łączy bloki.

Często pojawia się to w CTF cookies/tokens, które MAC-ują username lub role za pomocą CBC-MAC.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### The mental model

Większość przypadków szyfrów strumieniowych sprowadza się do:

`ciphertext = plaintext XOR keystream`

Więc:

- Jeśli znasz plaintext, odzyskujesz keystream.
- Jeśli keystream jest ponownie użyty (ten sam key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Jeśli znasz dowolny segment plaintextu na pozycji `i`, możesz odzyskać bajty keystreamu i odszyfrować inne szyfrogramy na tych pozycjach.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 jest szyfrem strumieniowym; szyfrowanie/deszyfrowanie to ta sama operacja.

Jeśli możesz uzyskać szyfrowanie RC4 znanego plaintextu pod tym samym kluczem, możesz odzyskać keystream i odszyfrować inne wiadomości o tej samej długości/przesunięciu.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
