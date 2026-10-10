# Kryptografia symetryczna

{{#include ../../banners/hacktricks-training.md}}

## Na co zwracać uwagę w CTF-ach

- **Niewłaściwe użycie trybów**: wzorce ECB, podatność CBC na modyfikacje, ponowne użycie nonce w CTR/GCM.
- **Padding oracles**: różne błędy/czasy odpowiedzi dla nieprawidłowego paddingu.
- **Niejasności dotyczące MAC**: użycie CBC-MAC z wiadomościami o zmiennej długości lub błędy typu MAC-then-encrypt.
- **XOR wszędzie**: szyfry strumieniowe i własne konstrukcje często sprowadzają się do XOR ze strumieniem klucza.

## Tryby AES i ich niewłaściwe użycie

NIST określa tryby poufności ECB, CBC i CTR w dokumencie SP 800-38A oraz szyfrowanie uwierzytelnione GCM w dokumencie SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB ujawnia wzorce: identyczne bloki tekstu jawnego → identyczne bloki szyfrogramu. Umożliwia to:

- Ataki typu cut-and-paste / zmianę kolejności bloków
- Usuwanie bloków (jeśli format pozostaje prawidłowy)

Jeśli możesz kontrolować tekst jawny i obserwować szyfrogram (lub cookies), spróbuj utworzyć powtarzające się bloki (np. wiele znaków `A`) i sprawdź, czy się powtarzają.

### CBC: Cipher Block Chaining

- CBC jest **podatny na modyfikacje**: zmiana bitów w `C[i-1]` powoduje przewidywalną zmianę bitów w `P[i]`, a jednocześnie zniekształca `P[i-1]`. Modyfikacja IV pozwala zmienić pierwszy blok tekstu jawnego bez zniekształcania wcześniejszego bloku tekstu jawnego.
- Jeśli system ujawnia, czy padding jest prawidłowy, czy nieprawidłowy, możesz mieć do czynienia z **padding oracle**.

### CTR

CTR zmienia AES w szyfr strumieniowy: `C = P XOR keystream`.

Jeśli nonce/IV zostanie ponownie użyty z tym samym kluczem:

- `C1 XOR C2 = P1 XOR P2` (klasyczne ponowne użycie strumienia klucza)
- Znając tekst jawny, możesz odzyskać strumień klucza i odszyfrować inne wiadomości.

**Schematy wykorzystania ponownego użycia nonce/IV**

- Odzyskaj strumień klucza wszędzie tam, gdzie tekst jawny jest znany lub możliwy do odgadnięcia:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Zastosuj odzyskane bajty keystreamu do odszyfrowania innych ciphertextów utworzonych z użyciem tego samego key+IV na tych samych offsetach.
- Dane o wysoce ustrukturyzowanej formie (np. certyfikaty ASN.1/X.509, nagłówki plików, JSON/CBOR) zawierają duże fragmenty znanego plaintextu. Często można wykonać XOR ciphertextu certyfikatu z przewidywalnym ciałem certyfikatu, aby uzyskać keystream, a następnie odszyfrować inne sekrety zaszyfrowane z użyciem ponownie użytego IV. Zobacz też [TLS & Certificates](../tls-and-certificates/README.md), aby poznać typowe układy certyfikatów.<sup>[[1]](#references)</sup>
- Gdy wiele sekretów o **tym samym serializowanym formacie/rozmiarze** jest szyfrowanych z użyciem tego samego key+IV, wyrównanie pól ujawnia informacje nawet bez pełnego znanego plaintextu. Na przykład klucze RSA PKCS#8 o takim samym rozmiarze modulus umieszczają czynniki pierwsze na pasujących offsetach (wyrównanie na poziomie ~99,6% dla 2048-bitowych kluczy). Wykonanie XOR dwóch ciphertextów z użyciem ponownie użytego keystreamu pozwala wyodrębnić `p ⊕ p'` / `q ⊕ q'`, które można odzyskać metodą brute force w kilka sekund.<sup>[[1]](#references)</sup>
- Domyślne IV w bibliotekach (np. stała `000...01`) to poważna pułapka: każde szyfrowanie powtarza ten sam keystream, zmieniając CTR w ponownie użyty one-time pad.<sup>[[1]](#references)</sup>

**Malleability CTR**

- CTR zapewnia wyłącznie poufność: odwrócenie bitów w ciphertext deterministycznie odwraca te same bity w plaintext. Bez tagu uwierzytelniającego atakujący mogą niezauważenie modyfikować dane (np. zmieniać klucze, flagi lub wiadomości).
- Używaj AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 itd.) i wymagaj weryfikacji tagu, aby wykrywać odwrócenia bitów.

### GCM

GCM również poważnie zawodzi przy ponownym użyciu nonce. Jeśli ten sam key+nonce zostanie użyty więcej niż raz, zwykle dochodzi do:

- Ponownego użycia keystreamu podczas szyfrowania (jak w CTR), co umożliwia odzyskanie plaintextu, gdy znany jest jakikolwiek plaintext.
- Utraty gwarancji integralności. W zależności od tego, jakie dane są ujawnione (wiele par wiadomość/tag z tym samym nonce), atakujący mogą być w stanie sfałszować tagi.

Wskazówki operacyjne:

- Traktuj „ponowne użycie nonce” w AEAD jako krytyczną podatność.
- AEAD odporne na niewłaściwe użycie, takie jak AES-GCM-SIV, ograniczają skutki ponownego użycia nonce. Wywołujący nadal powinni podawać unikalne nonce zgodnie z wymaganiami interfejsu konstrukcji; przypadkowe ponowne użycie ma ograniczone konsekwencje w porównaniu ze zwykłym GCM.<sup>[[3]](#references)[[4]](#references)</sup>
- Jeśli masz wiele ciphertextów z tym samym nonce, zacznij od sprawdzenia zależności w rodzaju `C1 XOR C2 = P1 XOR P2`.

### Tools

- [CyberChef](https://gchq.github.io/CyberChef/) do szybkich eksperymentów.<sup>[[8]](#references)</sup>
- Pakiet [PyCryptodome](https://www.pycryptodome.org/) dla Pythona do tworzenia skryptów.<sup>[[9]](#references)</sup>

## Wzorce wykorzystania ECB

ECB (Electronic Code Book) szyfruje każdy blok niezależnie:

- identyczne bloki plaintextu → identyczne bloki ciphertextu
- ujawnia to strukturę i umożliwia ataki typu cut-and-paste

![Schemat blokowy deszyfrowania w trybie ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Pomysł na wykrycie: wzorzec tokena/cookie

Jeśli logujesz się kilka razy i **zawsze otrzymujesz to samo cookie**, ciphertext może być deterministyczny (ECB lub stałe IV).

Jeśli utworzysz dwóch użytkowników o w większości identycznym układzie plaintextu (np. z długimi ciągami powtarzających się znaków) i zauważysz powtarzające się bloki ciphertextu na tych samych offsetach, ECB jest głównym podejrzanym.

### Wzorce wykorzystania

#### Usuwanie całych bloków

Jeśli format tokena przypomina `<username>|<password>` i granica bloku jest odpowiednio wyrównana, czasem można utworzyć użytkownika tak, aby blok `admin` był wyrównany, a następnie usunąć poprzedzające bloki i uzyskać prawidłowy token dla `admin`.

#### Przenoszenie bloków

Jeśli backend akceptuje dopełnienie/spacje (`admin` vs `admin    `), można:

- Wyrównać blok zawierający `admin   `
- Podmienić/ponownie wykorzystać ten blok ciphertextu w innym tokenie

## Padding Oracle

### Co to jest

W trybie CBC, jeśli serwer ujawnia (bezpośrednio lub pośrednio), czy odszyfrowany plaintext ma **prawidłowe dopełnienie PKCS#7**, często można:<sup>[[7]](#references)</sup>

- Odszyfrować ciphertext bez klucza
- Utworzyć ciphertext, który odszyfruje się do wybranego plaintextu, jeśli można przesłać spreparowane poprzedzające bloki lub IV, a aplikacja akceptuje wiadomość z prawidłowym dopełnieniem

Oracle może mieć postać:

- Konkretnego komunikatu o błędzie
- Innego statusu HTTP / rozmiaru odpowiedzi
- Różnicy w czasie odpowiedzi

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

- Rozmiar bloku często wynosi `16` w AES.
- `-encoding 0` oznacza Base64.
- Użyj `-error`, jeśli oracle zwraca określony ciąg znaków.

### Dlaczego to działa

Deszyfrowanie CBC oblicza `P[i] = D(C[i]) XOR C[i-1]`. Modyfikując bajty w `C[i-1]` i obserwując, czy padding jest prawidłowy, możesz odzyskać `P[i]` bajt po bajcie.

## Bit-flipping in CBC

Nawet bez padding oracle CBC jest podatny na modyfikacje. Jeśli możesz modyfikować bloki szyfrogramu, a aplikacja używa odszyfrowanego tekstu jawnego jako danych strukturalnych (np. `role=user`), możesz zmieniać określone bity, aby zmodyfikować wybrane bajty tekstu jawnego na wskazanej pozycji w następnym bloku.

Typowy schemat CTF:

- Token = `IV || C1 || C2 || ...`
- Kontrolujesz bajty w `C[i]`
- Celem są bajty tekstu jawnego w `P[i+1]`, ponieważ `P[i+1] = D(C[i+1]) XOR C[i]`

Samo w sobie nie jest to złamaniem poufności, ale przy braku kontroli integralności często umożliwia eskalację uprawnień.

## CBC-MAC

CBC-MAC jest bezpieczny tylko pod określonymi warunkami (w szczególności dla **wiadomości o stałej długości** i przy prawidłowym rozdzieleniu domen). AES-CMAC to standaryzowana konstrukcja, która bezpiecznie obsługuje dane wejściowe o zmiennej długości.<sup>[[5]](#references)</sup>

### Klasyczny schemat fałszerstwa dla wiadomości o zmiennej długości

CBC-MAC jest zwykle obliczany jako:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Jeśli możesz uzyskać tagi dla wybranych wiadomości, często możesz skonstruować tag dla konkatenacji (lub powiązanej konstrukcji) bez znajomości klucza, wykorzystując sposób, w jaki CBC łączy bloki.

Często pojawia się to w ciasteczkach/tokenach CTF, w których CBC-MAC obliczany jest dla nazwy użytkownika lub roli.

### Bezpieczniejsze alternatywy

- Używaj HMAC (SHA-256/512)
- Używaj prawidłowo CMAC (AES-CMAC)
- Uwzględniaj długość wiadomości / rozdzielenie domen

## Szyfry strumieniowe: XOR i RC4

### Model mentalny

Większość sytuacji związanych z szyframi strumieniowymi sprowadza się do:

`ciphertext = plaintext XOR keystream`

Czyli:

- Jeśli znasz tekst jawny, odzyskasz strumień klucza.
- Jeśli strumień klucza zostanie ponownie użyty (ten sam klucz+nonce), `C1 XOR C2 = P1 XOR P2`.

### Szyfrowanie oparte na XOR

Jeśli znasz dowolny fragment tekstu jawnego na pozycji `i`, możesz odzyskać bajty strumienia klucza i odszyfrować inne szyfrogramy na tych pozycjach.

Automatyczne narzędzia:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 to przestarzały szyfr strumieniowy; szyfrowanie i deszyfrowanie sprowadzają się do tej samej operacji XOR. Znane biasy sprawiają, że nie nadaje się do nowych systemów, a TLS jawnie zabrania jego zestawów szyfrów.<sup>[[6]](#references)</sup>

Jeśli możesz uzyskać szyfrowanie RC4 znanego tekstu jawnego przy użyciu tego samego klucza, możesz odzyskać strumień klucza i odszyfrować inne wiadomości o tej samej długości i przesunięciu.

Referencyjny writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Niefrasobliwość a kunszt w kryptografii](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A – Zalecenie dotyczące trybów pracy szyfrów blokowych](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D – Zalecenie dotyczące Galois/Counter Mode (GCM) i GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 – AES-GCM-SIV: uwierzytelnione szyfrowanie odporne na niewłaściwe użycie nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 – Algorytm AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 – Zakaz zestawów szyfrów RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide – Testowanie pod kątem Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Dokumentacja PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
