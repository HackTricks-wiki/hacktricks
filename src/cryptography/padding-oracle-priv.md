{{#include ../banners/hacktricks-training.md}}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

# CBC - Cipher Block Chaining

W trybie CBC **poprzedni zaszyfrowany blok jest używany jako IV** do XOR z następnym blokiem:

![https://defuse.ca/images/cbc_encryption.png](https://defuse.ca/images/cbc_encryption.png)

Aby odszyfrować CBC, wykonuje się **przeciwne** **operacje**:

![https://defuse.ca/images/cbc_decryption.png](https://defuse.ca/images/cbc_decryption.png)

Zauważ, że potrzebne jest użycie **klucza** **szyfrowania** i **IV**.

# Dopełnianie wiadomości

Ponieważ szyfrowanie jest wykonywane w **stałych** **rozmiarach** **bloków**, zazwyczaj potrzebne jest **dopełnienie** w **ostatnim** **bloku**, aby uzupełnić jego długość.\
Zazwyczaj używa się **PKCS7**, które generuje dopełnienie **powtarzając** **liczbę** **bajtów** **potrzebnych** do **uzupełnienia** bloku. Na przykład, jeśli ostatni blok brakuje 3 bajtów, dopełnienie będzie `\x03\x03\x03`.

Przyjrzyjmy się więcej przykładom z **2 blokami o długości 8 bajtów**:

| bajt #0 | bajt #1 | bajt #2 | bajt #3 | bajt #4 | bajt #5 | bajt #6 | bajt #7 | bajt #0  | bajt #1  | bajt #2  | bajt #3  | bajt #4  | bajt #5  | bajt #6  | bajt #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Zauważ, że w ostatnim przykładzie **ostatni blok był pełny, więc wygenerowano kolejny tylko z dopełnieniem**.

# Padding Oracle

Gdy aplikacja odszyfrowuje zaszyfrowane dane, najpierw odszyfrowuje dane; następnie usuwa dopełnienie. Podczas czyszczenia dopełnienia, jeśli **nieprawidłowe dopełnienie wywołuje wykrywalne zachowanie**, masz **wrażliwość na padding oracle**. Wykrywalne zachowanie może być **błędem**, **brakiem wyników** lub **wolniejszą odpowiedzią**.

Jeśli wykryjesz to zachowanie, możesz **odszyfrować zaszyfrowane dane** i nawet **szyfrować dowolny tekst jawny**.

## Jak wykorzystać

Możesz użyć [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster), aby wykorzystać ten rodzaj wrażliwości lub po prostu zrobić
```
sudo apt-get install padbuster
```
Aby przetestować, czy ciasteczko witryny jest podatne, możesz spróbować:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Kodowanie 0** oznacza, że **base64** jest używane (ale dostępne są inne, sprawdź menu pomocy).

Możesz również **wykorzystać tę lukę do szyfrowania nowych danych. Na przykład, wyobraź sobie, że zawartość ciasteczka to "**_**user=MyUsername**_**", wtedy możesz zmienić to na "\_user=administrator\_" i podnieść uprawnienia w aplikacji. Możesz to również zrobić używając `paduster`, określając parametr -plaintext**:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Jeśli strona jest podatna, `padbuster` automatycznie spróbuje znaleźć, kiedy występuje błąd paddingu, ale możesz również wskazać komunikat o błędzie, używając parametru **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## Teoria

W **podsumowaniu**, możesz zacząć odszyfrowywać zaszyfrowane dane, zgadując poprawne wartości, które mogą być użyte do stworzenia wszystkich **różnych paddingów**. Następnie atak padding oracle zacznie odszyfrowywać bajty od końca do początku, zgadując, która wartość **tworzy padding 1, 2, 3, itd**.

![](<../images/image (629) (1) (1).png>)

Wyobraź sobie, że masz zaszyfrowany tekst, który zajmuje **2 bloki** utworzone przez bajty od **E0 do E15**.\
Aby **odszyfrować** **ostatni** **blok** (**E8** do **E15**), cały blok przechodzi przez "odszyfrowanie bloku", generując **bajty pośrednie I0 do I15**.\
Na koniec każdy bajt pośredni jest **XORowany** z poprzednimi zaszyfrowanymi bajtami (E0 do E7). Tak więc:

- `C15 = D(E15) ^ E7 = I15 ^ E7`
- `C14 = I14 ^ E6`
- `C13 = I13 ^ E5`
- `C12 = I12 ^ E4`
- ...

Teraz możliwe jest **zmodyfikowanie `E7`, aż `C15` będzie `0x01`**, co również będzie poprawnym paddingiem. Tak więc, w tym przypadku: `\x01 = I15 ^ E'7`

Zatem, znajdując E'7, **możliwe jest obliczenie I15**: `I15 = 0x01 ^ E'7`

Co pozwala nam **obliczyć C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Znając **C15**, teraz możliwe jest **obliczenie C14**, ale tym razem brute-forcing paddingu `\x02\x02`.

Ten BF jest tak skomplikowany jak poprzedni, ponieważ możliwe jest obliczenie `E''15`, którego wartość to 0x02: `E''7 = \x02 ^ I15`, więc wystarczy znaleźć **`E'14`**, które generuje **`C14` równe `0x02`**.\
Następnie wykonaj te same kroki, aby odszyfrować C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Podążaj za tym łańcuchem, aż odszyfrujesz cały zaszyfrowany tekst.**

## Wykrywanie podatności

Zarejestruj konto i zaloguj się na to konto.\
Jeśli **logujesz się wiele razy** i zawsze otrzymujesz **ten sam cookie**, prawdopodobnie **coś** **jest nie tak** w aplikacji. **Cookie wysyłane z powrotem powinno być unikalne** za każdym razem, gdy się logujesz. Jeśli cookie jest **zawsze** **takie samo**, prawdopodobnie zawsze będzie ważne i nie **będzie sposobu, aby je unieważnić**.

Teraz, jeśli spróbujesz **zmodyfikować** **cookie**, możesz zobaczyć, że otrzymujesz **błąd** z aplikacji.\
Ale jeśli BF paddingu (używając padbuster na przykład), uda ci się uzyskać inne cookie ważne dla innego użytkownika. Ten scenariusz jest wysoce prawdopodobnie podatny na padbuster.

## Referencje

- [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{{#include ../banners/hacktricks-training.md}}
