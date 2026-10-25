# Hashe, MAC-i i KDF-y

{{#include ../../banners/hacktricks-training.md}}

## Typowe schematy CTF

- „Podpis” to w rzeczywistości `hash(secret || message)` → length extension.
- Niesolone hashe haseł → szybsze wielokrotne łamanie i ataki z użyciem wstępnie obliczonych tablic.
- Mylenie hasha z MAC-em (hash != uwierzytelnianie).

## Wyszukiwanie hashy MD5 dla wybranego wejścia

Te przykłady w Pythonie wyszukują dwa różne wzorce wyników: wybrany sufiks MD5 oraz wartość MD5 zaczynającą się od `0e`, po której występują wyłącznie cyfry. Ten drugi wzorzec ma znaczenie, gdy aplikacja luźno porównuje ciągi znaków zawierające liczby; zobacz zachowanie specyficzne dla PHP i uwagi dotyczące wersji w [PHP loose comparisons](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

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

### Generowanie hashy MD5 0e do luźnych porównań

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

Atak typu length-extension może być możliwy, gdy serwer oblicza „podpis” w następujący sposób:

`sig = HASH(secret || message)`

i używa funkcji skrótu Merkle-Damgård, takiej jak MD5, SHA-1 lub SHA-256.

Jeśli znasz:

- `message`
- `sig`
- funkcję skrótu
- (lub możesz metodą brute-force ustalić) `len(secret)`

możesz obliczyć prawidłowy podpis dla:

`message || padding || appended_data`

bez znajomości sekretu.<sup>[[1]](#references)</sup>

### Ważne ograniczenie: HMAC nie jest podatny na ten atak

Ataki typu length-extension dotyczą podatnych konstrukcji z prefiksem, takich jak `HASH(secret || message)`. Nie umożliwiają ataku na konstrukcję HMAC (na przykład HMAC-SHA256), która łączy klucz z osobnymi wewnętrznymi i zewnętrznymi operacjami hashowania.<sup>[[1]](#references)[[2]](#references)</sup>

Informacje o tym, jak znaleźć i testować takie podpisy w API webowych, znajdziesz w sekcji [Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures).

### Narzędzia

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), powiązania z Pythonem dla narzędzia HashPump do ataków typu length-extension<sup>[[7]](#references)</sup>

### Dobre wyjaśnienie

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Niejednoznaczne hashowanie krotek i MAC

### Atak polegający na pomyleniu granic

Przyrostowe API hashujące nie uwierzytelniają granic wywołań. `update(A); update(B)` hashuje ten sam ciąg bajtów co `update(A + B)`. Dlatego hashowanie lub obliczanie MAC dla surowego konkatenowania nie uwierzytelnia krotki. Jeśli sąsiadujące pola mają zmienną długość, atakujący może podzielić bajty na nowo, tworząc inną krotkę bez znajdowania kolizji w bazowej funkcji skrótu:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Staje się to podatne na atak, gdy weryfikator zakłada, że digest wiąże znaczenie pól, ale dane kontrolowane przez atakującego mogą trafić do innego parsera lub etapu protokołu, który wyznacza inne granice. Commitmenty mogą mieć alternatywne otwarcia, a transkrypty Fiat-Shamir mogą być interpretowane jako inne stwierdzenia. HMAC zapobiega [wydłużaniu wiadomości hasha](#hash-length-extension-attack), ale `HMAC(K, A || B)` nadal jest podatny na tę niejednoznaczność kodowania krotek, ponieważ obie krotki dają te same bajty wiadomości.<sup>[[8]](#references)[[9]](#references)</sup>

Użyj poniższego schematu audytu, aby sprawdzić, czy niejednoznaczne kodowanie krotki przekracza granicę bezpieczeństwa.<sup>[[8]](#references)[[9]](#references)</sup>

1. Znajdź `HASH(A || B)`, `HMAC(K, A || B)` oraz kolejne wywołania `update()`/`Write()` dla co najmniej dwóch pól.
2. Oznacz każde pole kontrolowane przez atakującego lub o zmiennej długości. Spróbuj przenosić bajty przez każdą granicę, zachowując niezmienioną całą konkatenację. Uwzględnij puste pola.
3. Sprawdź schematy z separatorami pod kątem bajtów separatora, które mogą wystąpić w danych wejściowych, rozbieżności w escapowaniu oraz rozwiązań, które kodują długość tylko niektórych pól.
4. Prześledź, jak każdy odbiorca parsuje uwierzytelnione bajty. Alternatywny podział ma znaczenie tylko wtedy, gdy zmienia decyzję dotyczącą bezpieczeństwa, treść dowodu, rekord, transakcję lub otwarcie commitmentu. Pola o stałej szerokości lub kanoniczna, iniektywna serializacja zapobiegają temu konkretnemu atakowi.
5. Sprawdź, czy ten sam zakodowany digest jest akceptowany w innej wersji protokołu, typie wiadomości, rundzie lub aplikacji. Jawnie powiąż te konteksty, zamiast polegać na tym, że wywołujący będą je rozdzielać.

### SequenceHash i SequenceMAC

SequenceHash to konstrukcja niezależna od algorytmu hashującego, przeznaczona do sekwencji ciągów bajtów. Każde wywołanie `add()` jest atomowe: dopisuje wartość oraz stały 16-bajtowy sufiks długości w kolejności little-endian do wewnętrznego hasha. Puste wartości pozostają odrębnymi obiektami. Zewnętrzny hash zapobiega ujawnieniu wewnętrznego stanu, który można wydłużać, a opcjonalny ciąg dostosowujący zapewnia separację domen. Nie zastępuj `add()` zwykłymi zapisami za pomocą API bazowego algorytmu hashującego.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Wybierz customizer jako część definicji protokołu, uwzględniając wystarczające informacje, by odróżnić aplikację, wersję protokołu, typ wiadomości i rundę. SequenceHash nadal wymaga, aby wszystkie strony uzgodniły kolejność pól, kodowanie bajtów i kanoniczną serializację, a ponadto nie chroni przed pominięciem pola. Implementacje należy sprawdzić względem pośrednich i końcowych wektorów testowych C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Do uwierzytelniania SequenceMAC udostępnia taki sam interfejs kodowania atomowego i customizera. Wymaga klucza o długości co najmniej 32 bajtów. W przeciwieństwie do wstępnego przetwarzania klucza w HMAC, jego nagłówki wiążą się z dokładną długością klucza: długi surowy klucz nie jest równoważny jego prehashowi, a dopisanie bajtów zerowych zmienia klucz. To rozróżnienie ma znaczenie, gdy komponenty akceptują różne reprezentacje klucza lub metadane dotyczące jego długości.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Implementacje API w Pythonie oraz równoważne implementacje w Go i Rust są dostępne jako materiały referencyjne, ale implementacje protokołu powinny być zgodne z aktualną specyfikacją C2SP, a nie odtwarzać kodowanie na podstawie tego podsumowania.<sup>[[8]](#references)[[10]](#references)</sup>

## Hashowanie haseł i ich łamanie

### Pierwsze pytania<sup>[[4]](#references)</sup>

- Czy hash jest **salted**? (szukaj formatów `salt$hash`)
- Czy to **szybki hash** (MD5/SHA1/SHA256), czy **wolny KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Czy masz **wskazówkę dotyczącą formatu** (tryb hashcat / format John)?

### Praktyczny workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Zidentyfikuj hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Jeśli hash jest niesalted i powszechny: sprawdź internetowe bazy danych i narzędzia identyfikacyjne z sekcji o workflow kryptograficznym.
3. W pozostałych przypadkach złam go:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Częste błędy, które możesz wykorzystać

- To samo hasło jest używane przez wielu użytkowników → złam jedno i wykonaj pivot.
- Obcięte hashe / niestandardowe transformacje → znormalizuj je i spróbuj ponownie.
- Słabe parametry KDF (np. mała liczba iteracji PBKDF2) → nadal da się je złamać.

### Oracle bcrypt z wybranym wejściem i dołączonym sekretem

Wywoływalny helper zwracający `bcrypt(user_input || secret)` może ujawniać informacje o dołączonym sekrecie, jeśli jego implementacja bcrypt po cichu obcina wejście po 72 **bajtach**. Limit liczby znaków stosowany przed kodowaniem UTF-8 nie egzekwuje tego limitu bajtów: znaki wielobajtowe mogą wypełnić wejście bcrypt, pozostawiając miejsce tylko na krótki prefiks sekretu. Wybrane wejścia i zwrócone dla nich hashe mogą wtedy umożliwić offline'owe sprawdzanie bajtów potencjalnych sufiksów. Wymaga to kontroli nad wejściem helpera, znajomości dokładnej transformacji i kodowania oraz implementacji, która faktycznie obcina wejście; samo istnienie wywoływalnego helpera lub hasha bcrypt nie potwierdza całego łańcucha. [Dokumentacja pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) podaje, że obecne `hashpw` zgłasza błąd dla wejść dłuższych niż 72 bajty, podczas gdy wcześniejsze wersje po cichu je obcinały. Inne wrappery mogą wstępnie hashować lub odrzucać długie wejścia, więc sprawdź zainstalowaną implementację, zamiast zakładać obcinanie.

Użycie odzyskanego sekretu wobec innego konta wymaga również dowodów, że ujawniony hash został wygenerowany z użyciem **tego samego** sekretu i transformacji, a także osobnej ścieżki uwierzytelniania lub logowania. Helper do hashowania uruchamiany jako root należy uznać za oracle tylko wtedy, gdy użytkownik o niższych uprawnieniach może go wywołać zgodnie z obowiązującą polityką; pasywne rozpoznanie hosta nie musi go wywoływać ani przesyłać wybranych haseł.

## References

- [1] [SkullSecurity - Wszystko, co musisz wiedzieć o atakach z rozszerzeniem długości hasha](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Kod uwierzytelniający wiadomości oparty na kluczowanym hashu](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Ściągawka dotycząca przechowywania haseł](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Przykładowe hashe hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opcje wiersza poleceń John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` - powiązania Pythona dla HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Specyfikacja SequenceHash i SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multi-hashing dla każdego](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Implementacja SequenceHash w Pythonie](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Wektory testowe SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
