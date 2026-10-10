# Hashe, MAC-i i KDF-y

{{#include ../../banners/hacktricks-training.md}}

## Typowe schematy w CTF-ach

- „Podpis” to w rzeczywistości `hash(secret || message)` → length extension.
- Hashe haseł bez soli → szybsze wielokrotne łamanie i ataki z użyciem wstępnie obliczonych zestawów.
- Mylenie hasha z MAC (hash != uwierzytelnianie).

## Atak length extension

### Technika

Atak length-extension może być możliwy, gdy serwer oblicza „podpis” w rodzaju:

`sig = HASH(secret || message)`

i używa hasha Merkle’a-Damgårda, takiego jak MD5, SHA-1 lub SHA-256.

Jeśli znasz:

- `message`
- `sig`
- funkcję hashującą
- (lub możesz brute-force’ować) `len(secret)`

Możesz wtedy obliczyć prawidłowy podpis dla:

`message || padding || appended_data`

bez znajomości sekretu.<sup>[[1]](#references)</sup>

### Ważne ograniczenie: HMAC nie jest podatny

Ataki length-extension dotyczą podatnych konstrukcji z prefiksem, takich jak `HASH(secret || message)`. Nie ujawniają konstrukcji HMAC (na przykład HMAC-SHA256), która łączy klucz z oddzielnymi wewnętrznymi i zewnętrznymi operacjami haszowania.<sup>[[1]](#references)[[2]](#references)</sup>

### Narzędzia

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), powiązania Pythona z narzędziem length-extension HashPump<sup>[[7]](#references)</sup>

### Dobre wyjaśnienie

[Wszystko, co musisz wiedzieć o atakach length-extension na hashe](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Haszowanie i łamanie haseł

### Pierwsze pytania<sup>[[4]](#references)</sup>

- Czy hash jest **posolony**? (szukaj formatów `salt$hash`)
- Czy to **szybki hash** (MD5/SHA1/SHA256), czy **wolny KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Czy masz **wskazówkę dotyczącą formatu** (tryb hashcat / format John)?

### Praktyczny przebieg pracy<sup>[[5]](#references)[[6]](#references)</sup>

1. Zidentyfikuj hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Jeśli hash nie jest posolony i jest popularny: sprawdź internetowe bazy danych i narzędzia do identyfikacji z sekcji poświęconej procesowi pracy z kryptografią.
3. W pozostałych przypadkach spróbuj go złamać:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Typowe błędy, które możesz wykorzystać

- To samo hasło jest używane przez różnych użytkowników → złam jedno i zrób pivot.
- Obcięte hashe / niestandardowe przekształcenia → ujednolić format i spróbować ponownie.
- Słabe parametry KDF (np. mała liczba iteracji PBKDF2) → hash nadal da się złamać.

### Oracle bcrypt z wybranym wejściem i dołączonym sekretem

Wywoływalny helper zwracający `bcrypt(user_input || secret)` może ujawniać informacje o dołączonym sekrecie, jeśli jego implementacja bcrypt po cichu obcina wejście po 72 **bajtach**. Limit liczby znaków stosowany przed kodowaniem UTF-8 nie egzekwuje tego limitu bajtów: znaki wielobajtowe mogą wypełnić wejście bcrypt, pozostawiając miejsce tylko na mały prefiks sekretu. Wybrane wejścia i zwrócone dla nich hashe mogą wtedy umożliwić offline’owe sprawdzanie kandydatów na bajty sufiksu. Wymaga to kontroli nad wejściem helpera, znajomości dokładnego przekształcenia i kodowania oraz implementacji, która faktycznie obcina dane; sam wywoływalny helper lub hash bcrypt nie potwierdza całego łańcucha. [Dokumentacja pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) podaje, że obecna wersja `hashpw` zgłasza błąd dla wejść dłuższych niż 72 bajty, natomiast wcześniejsze wersje po cichu je obcinały. Inne wrappery mogą wstępnie haszować lub odrzucać długie wejścia, więc sprawdź zainstalowaną implementację, zamiast zakładać, że obcina dane.

Użycie odzyskanego sekretu wobec innego konta wymaga również dowodu, że ujawniony hash tego konta został wygenerowany przy użyciu **tego samego** sekretu i przekształcenia, a także osobnej ścieżki logowania lub dostępu do poświadczeń. Helper do haszowania uruchamiany jako root należy traktować jako oracle tylko wtedy, gdy użytkownik o niższych uprawnieniach może go wywołać zgodnie z obowiązującymi zasadami; pasywna enumeracja hosta nie wymaga jego uruchamiania ani przesyłania wybranych haseł.

## References

- [1] [SkullSecurity - Wszystko, co musisz wiedzieć o atakach length-extension na hashe](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Kod uwierzytelniania wiadomości oparty na kluczowanym hashu](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Ściągawka dotycząca przechowywania haseł](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Przykładowe hashe hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opcje wiersza poleceń John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: powiązania Pythona `hashpumpy` z HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
