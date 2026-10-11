# Hashes, MACs i KDF-y

{{#include ../../banners/hacktricks-training.md}}

## Typowe schematy CTF

- „Podpis” to w rzeczywistości `hash(secret || message)` → length extension.
- Hashes haseł bez salt → szybsze wielokrotne crackowanie i ataki z użyciem wstępnie obliczonych tablic.
- Mylenie hash z MAC (hash != uwierzytelnianie).

## Hash length extension attack

### Technika

Atak length-extension może być możliwy, gdy serwer oblicza „podpis” w rodzaju:

`sig = HASH(secret || message)`

i używa hash Merkle’a–Damgårda, takiego jak MD5, SHA-1 lub SHA-256.

Jeśli znasz:

- `message`
- `sig`
- funkcję hash
- (lub możesz brute-force’ować) `len(secret)`

możesz obliczyć prawidłowy podpis dla:

`message || padding || appended_data`

bez znajomości secret.<sup>[[1]](#references)</sup>

### Ważne ograniczenie: HMAC nie jest podatny

Ataki length-extension dotyczą podatnych konstrukcji z prefiksem, takich jak `HASH(secret || message)`. Nie ujawniają konstrukcji HMAC (na przykład HMAC-SHA256), która łączy klucz z osobnymi wewnętrznymi i zewnętrznymi operacjami hash.<sup>[[1]](#references)[[2]](#references)</sup>

### Narzędzia

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), powiązania Pythona dla narzędzia length-extension HashPump<sup>[[7]](#references)</sup>

### Dobre wyjaśnienie

[Wszystko, co musisz wiedzieć o atakach hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashowanie haseł i crackowanie

### Pierwsze pytania<sup>[[4]](#references)</sup>

- Czy hash ma **salt**? (szukaj formatów `salt$hash`)
- Czy to **szybki hash** (MD5/SHA1/SHA256), czy **wolny KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Czy masz **wskazówkę dotyczącą formatu** (tryb hashcat / format John)?

### Praktyczny workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Zidentyfikuj hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Jeśli hash nie ma salt i jest popularny: sprawdź internetowe bazy danych oraz narzędzia identyfikacyjne z sekcji dotyczącej workflow kryptograficznego.
3. W przeciwnym razie crackuj:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Typowe błędy, które możesz wykorzystać

- To samo hasło jest używane przez różnych użytkowników → crackuj jedno, a następnie pivotuj.
- Skrócone hashe / niestandardowe przekształcenia → znormalizuj i spróbuj ponownie.
- Słabe parametry KDF (np. mała liczba iteracji PBKDF2) → nadal można je złamać.

### Wyrocznia bcrypt z wybranym wejściem i dołączonym sekretem

Wywoływalna funkcja pomocnicza, która zwraca `bcrypt(user_input || secret)`, może ujawnić informacje o dołączonym sekrecie, jeśli jej implementacja bcrypt po cichu skraca wejście po 72 **bajtach**. Limit liczby znaków zastosowany przed kodowaniem UTF-8 nie wymusza tego limitu bajtów: znaki wielobajtowe mogą wypełnić wejście bcrypt, pozostawiając miejsce tylko na niewielki prefiks secret. Wybrane wejścia i zwrócone dla nich hashe mogą wtedy umożliwić offline’owe sprawdzanie bajtów kandydujących sufiksów. Wymaga to kontroli nad wejściem funkcji pomocniczej, znajomości jej dokładnego przekształcenia i kodowania oraz implementacji, która faktycznie skraca dane; sama wywoływalna funkcja pomocnicza lub hash bcrypt nie potwierdzają całego tego łańcucha. [Dokumentacja pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) informuje, że obecna metoda `hashpw` zgłasza błąd dla wejść dłuższych niż 72 bajty, podczas gdy wcześniejsze wersje po cichu je skracały. Inne wrappery mogą najpierw obliczać hash lub odrzucać długie wejścia, dlatego sprawdź zainstalowaną implementację, zamiast zakładać, że skraca dane.

Wykorzystanie odzyskanego secret przeciwko innemu kontu wymaga również dowodów, że ujawniony hash został wygenerowany przy użyciu tego **samego** secret i przekształcenia, a także osobnej ścieżki uwierzytelniania lub logowania. Funkcję haszującą uruchamianą jako root należy traktować jako wyrocznię tylko wtedy, gdy użytkownik o niższych uprawnieniach może ją wywołać zgodnie z obowiązującą polityką; pasywna enumeracja hosta nie musi jej wywoływać ani przekazywać wybranych haseł.

## References

- [1] [SkullSecurity - Wszystko, co musisz wiedzieć o atakach hash length-extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Kod uwierzytelniania wiadomości z kluczem oparty na hash](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Ściągawka dotycząca przechowywania haseł](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Przykładowe hashe hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opcje wiersza poleceń John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` — powiązania Pythona dla HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
