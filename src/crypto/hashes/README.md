# Hashe, MAC-i i KDF-y

{{#include ../../banners/hacktricks-training.md}}

## Typowe schematy CTF

- „Podpis” to w rzeczywistości `hash(secret || message)` → length extension.
- Hashe haseł bez soli → szybsze wielokrotne łamanie i ataki z użyciem wstępnie obliczonych tablic.
- Mylenie hashy z MAC-ami (hash != uwierzytelnianie).

## Wyszukiwanie hashy MD5 dla wybranych danych wejściowych

Te przykłady w Pythonie wyszukują dwa różne wzorce wyników: wybrany sufiks MD5 oraz wartość MD5 zaczynającą się od `0e`, po którym występują wyłącznie cyfry. Ten drugi wzorzec ma znaczenie, gdy aplikacja luźno porównuje ciągi znaków zawierające liczby; zobacz zachowanie specyficzne dla PHP i uwagi dotyczące wersji w [luźnych porównaniach w PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force sufiksu hasha MD5

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### Generowanie hashów MD5 0e do luźnych porównań

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension attack

### Technika

Atak typu length extension może być możliwy, gdy serwer oblicza „podpis” w taki sposób:

`sig = HASH(secret || message)`

i używa funkcji skrótu Merkle’a-Damgårda, takiej jak MD5, SHA-1 lub SHA-256.

Jeśli znasz:

- `message`
- `sig`
- funkcję skrótu
- (lub możesz brute-force’ować) `len(secret)`

możesz obliczyć prawidłowy podpis dla:

`message || padding || appended_data`

bez znajomości sekretu.<sup>[[1]](#references)</sup>

### Ważne ograniczenie: HMAC nie jest podatny

Ataki typu length extension dotyczą podatnych konstrukcji z prefiksem, takich jak `HASH(secret || message)`. Nie pozwalają złamać konstrukcji HMAC (na przykład HMAC-SHA256), która łączy klucz z oddzielnymi wewnętrznymi i zewnętrznymi operacjami haszowania.<sup>[[1]](#references)[[2]](#references)</sup>

### Narzędzia

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), powiązania Python dla narzędzia HashPump do ataków typu length extension<sup>[[7]](#references)</sup>

### Dobre wyjaśnienie

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Niejednoznaczne haszowanie krotek i MAC-y

### Boundary-confusion attack

Przyrostowe API funkcji skrótu nie uwierzytelniają granic wywołań. `update(A); update(B)` haszuje ten sam ciąg bajtów co `update(A + B)`. Dlatego haszowanie lub obliczanie MAC-a dla surowego sklejenia nie uwierzytelnia krotki. Jeśli sąsiadujące pola mają zmienną długość, atakujący może podzielić bajty na inną krotkę bez znajdowania kolizji w używanej funkcji skrótu:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Staje się to podatne na atak, gdy weryfikator zakłada, że digest wiąże znaczenie pól, ale dane kontrolowane przez atakującego mogą trafić do innego parsera lub etapu protokołu, który wyznacza inne granice. Commitments mogą zyskać alternatywne otwarcia, a transkrypty Fiat-Shamir mogą być interpretowane jako inne stwierdzenia. HMAC zapobiega [hash length extension](#hash-length-extension-attack), ale `HMAC(K, A || B)` nadal ma tę niejednoznaczność kodowania krotek, ponieważ obie krotki dają te same bajty wiadomości.<sup>[[8]](#references)[[9]](#references)</sup>

Użyj tego procesu audytu, aby sprawdzić, czy niejednoznaczne kodowanie krotek przekracza granicę bezpieczeństwa.<sup>[[8]](#references)[[9]](#references)</sup>

1. Znajdź `HASH(A || B)`, `HMAC(K, A || B)` oraz kolejne wywołania `update()`/`Write()` dla co najmniej dwóch pól.
2. Oznacz każde pole kontrolowane przez atakującego lub o zmiennej długości. Spróbuj przenosić bajty między każdą parą granic, zachowując niezmienioną całą konkatenację. Uwzględnij puste pola.
3. Sprawdź schematy separatorów pod kątem bajtów separatorów, które mogą wystąpić w danych wejściowych, rozbieżności w escapowaniu oraz rozwiązań, które kodują długość tylko niektórych pól.
4. Prześledź sposób, w jaki każdy odbiorca parsuje uwierzytelnione bajty. Alternatywny podział ma znaczenie tylko wtedy, gdy zmienia decyzję dotyczącą bezpieczeństwa, stwierdzenie dowodu, rekord, transakcję lub otwarcie commitmentu. Pola o stałej szerokości lub kanoniczna, iniektywna serializacja zapobiegają temu konkretnemu atakowi.
5. Sprawdź, czy ten sam zakodowany digest jest akceptowany w innej wersji protokołu, typie wiadomości, rundzie lub aplikacji. Jawnie uwzględnij te konteksty zamiast polegać na tym, że wywołujący je rozdzielą.

### SequenceHash i SequenceMAC

SequenceHash to niezależna od hash funkcja konstrukcyjna dla sekwencji ciągów bajtów. Każda operacja `add()` jest atomowa: dopisuje wartość oraz stały, 16-bajtowy sufiks długości w kolejności little-endian do wewnętrznego hasha. Puste wartości pozostają odrębnymi obiektami. Zewnętrzny hash zapobiega ujawnieniu stanu wewnętrznego, który można rozszerzać przez dopisywanie, a opcjonalny ciąg dostosowujący zapewnia separację domen. Nie zastępuj `add()` zwykłymi wywołaniami metod zapisu z bazowego API hasha.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Wybierz customizer jako część definicji protokołu, uwzględniając wystarczające informacje do rozróżnienia aplikacji, wersji protokołu, typu wiadomości i rundy. SequenceHash nadal wymaga, aby wszystkie strony uzgodniły kolejność pól, kodowanie bajtów i kanoniczną serializację; nie chroni też przed pominiętym polem. Implementacje należy sprawdzić względem pośrednich i końcowych wektorów testowych C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Do uwierzytelniania SequenceMAC udostępnia ten sam interfejs kodowania atomowego i dostosowywania. Wymaga klucza o długości co najmniej 32 bajtów. W przeciwieństwie do wstępnego przetwarzania klucza w HMAC jego nagłówki wiążą się z dokładną długością klucza: długi klucz surowy nie jest równoważny jego prehashowi, a dodanie zerowych bajtów zmienia klucz. To rozróżnienie ma znaczenie, gdy komponenty akceptują różne reprezentacje klucza lub metadane dotyczące jego długości.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API oraz równoważne implementacje w Go i Rust są dostępne jako materiały referencyjne, ale implementacje protokołu powinny opierać się na aktualnej specyfikacji C2SP, a nie odtwarzać kodowanie na podstawie tego podsumowania.<sup>[[8]](#references)[[10]](#references)</sup>

## Hashowanie haseł i łamanie hashy

### Pierwsze pytania<sup>[[4]](#references)</sup>

- Czy hash jest **solony**? (szukaj formatów `salt$hash`)
- Czy to **szybki hash** (MD5/SHA1/SHA256), czy **wolny KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Czy masz **wskazówkę dotyczącą formatu** (tryb hashcat / format John)?

### Praktyczny przebieg pracy<sup>[[5]](#references)[[6]](#references)</sup>

1. Zidentyfikuj hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Jeśli hash jest niesolony i powszechny: sprawdź internetowe bazy danych i narzędzia do identyfikacji z sekcji dotyczącej pracy z kryptografią.
3. W przeciwnym razie spróbuj go złamać:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Typowe błędy, które możesz wykorzystać

- To samo hasło jest używane przez wielu użytkowników → złam jedno i przejdź dalej.
- Obcięte hashe / niestandardowe transformacje → znormalizuj i spróbuj ponownie.
- Słabe parametry KDF (np. niska liczba iteracji PBKDF2) → hash nadal można złamać.

### Oracle bcrypt z wybranym wejściem i dopisanym sekretem

Wywoływalna funkcja pomocnicza, która zwraca `bcrypt(user_input || secret)`, może ujawnić informacje o dopisanym sekrecie, jeśli jej implementacja bcrypt po cichu obcina wejście po 72 **bajtach**. Limit liczby znaków stosowany przed kodowaniem UTF-8 nie egzekwuje tego limitu bajtów: znaki wielobajtowe mogą wypełnić wejście bcrypt, pozostawiając miejsce tylko na krótki prefiks sekretu. Wybrane wejścia i zwrócone dla nich hashe mogą wtedy umożliwić offline’owe sprawdzanie bajtów z kandydatów na sufiks. Wymaga to kontroli nad wejściem funkcji pomocniczej, znajomości jej dokładnej transformacji i kodowania oraz implementacji, która faktycznie obcina dane; sama wywoływalna funkcja pomocnicza lub hash bcrypt nie potwierdzają tego ciągu zależności. [Dokumentacja pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) podaje, że obecna funkcja `hashpw` zgłasza błąd dla wejść dłuższych niż 72 bajty, podczas gdy wcześniejsze wersje po cichu je obcinały. Inne wrappery mogą wstępnie haszować lub odrzucać długie wejścia, więc sprawdź zainstalowaną implementację, zamiast zakładać, że obcina dane.

Użycie odzyskanego sekretu do uzyskania dostępu do innego konta wymaga również dowodów, że ujawniony hash został wygenerowany z użyciem **tego samego** sekretu i transformacji, a także odrębnego poświadczenia lub ścieżki logowania. Funkcję pomocniczą uruchamianą jako root należy traktować jako oracle tylko wtedy, gdy użytkownik o niższych uprawnieniach może ją wywołać zgodnie z obowiązującymi zasadami; pasywne rozpoznanie hosta nie musi jej uruchamiać ani przekazywać wybranych haseł.

## References

- [1] [SkullSecurity - Wszystko, co musisz wiedzieć o atakach z rozszerzeniem długości hashy](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Kod uwierzytelniający wiadomość oparty na kluczowanym hashu](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Ściągawka dotycząca przechowywania haseł](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Przykładowe hashe hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opcje wiersza poleceń John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: powiązania `hashpumpy` dla Pythona z HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Specyfikacja SequenceHash i SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: wielokrotne haszowanie dla każdego](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Implementacja SequenceHash w Pythonie](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Wektory testowe SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
