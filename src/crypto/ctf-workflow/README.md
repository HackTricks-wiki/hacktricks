# Workflow Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Lista kontrolna triage

1. Ustal, z czym masz do czynienia: kodowaniem, szyfrowaniem, hashem, podpisem czy MAC.
2. Ustal, co jest kontrolowane: tekst jawny/szyfrogram, IV/nonce, klucz, oracle (padding/błąd/timing), częściowy wyciek.
3. Sklasyfikuj: symetryczne (AES/CTR/GCM), klucz publiczny (RSA/ECC), hash/MAC (SHA/MD5/HMAC), klasyczne (Vigenere/XOR).
4. Najpierw sprawdź najbardziej prawdopodobne możliwości: dekodowanie kolejnych warstw, XOR z tekstem jawnym, ponowne użycie nonce, niewłaściwe użycie trybu, zachowanie oracle.
5. Sięgaj po zaawansowane metody tylko wtedy, gdy są potrzebne: sieci (LLL/Coppersmith), SMT/Z3, side-channel.

## Zasoby online i narzędzia

Przydają się do rozpoznawania i rozwarstwiania danych lub szybkiego potwierdzania hipotez.

### Wyszukiwanie hashy

- Wyszukaj hash z zadania, jeśli wiadomo, że jest syntetyczny/publiczny.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Wyszukiwarka hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Nie przesyłaj prawdziwych hashy haseł ani poufnych materiałów z zadania do zewnętrznych usług wyszukiwania. Jeśli masz obawy dotyczące ujawnienia danych, warunków korzystania z usługi lub zasad konkursu, wybierz atak offline z użyciem wordlisty/reguł.

### Narzędzia pomocne w identyfikacji

- CyberChef (Magic, dekodowanie i konwersja).<sup>[[7]](#references)</sup>
- dCode (środowisko do szyfrów i kodowań).<sup>[[8]](#references)</sup>
- Boxentriq (narzędzia do łamania szyfrów podstawieniowych).<sup>[[9]](#references)</sup>

### Platformy treningowe / materiały referencyjne

- CryptoHack (praktyczne zadania z kryptografii).<sup>[[10]](#references)</sup>
- Cryptopals (klasyczne pułapki współczesnej kryptografii).<sup>[[11]](#references)</sup>

### Automatyczne dekodowanie

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (próbuje wielu systemów liczbowych i kodowań).<sup>[[13]](#references)</sup>

Informacje o kodzie źródłowym języków ezoterycznych i stanie niestandardowych interpreterów znajdziesz w [Crypto CTF Misc](../ctf-misc/).

## Kodowania i szyfry klasyczne

### Technika

Wiele zadań crypto CTF polega na nakładaniu kolejnych transformacji: kodowanie base + proste podstawienie + kompresja. Celem jest rozpoznanie kolejnych warstw i bezpieczne ich usunięcie.

### Kodowania: wypróbuj wiele systemów liczbowych

Jeśli podejrzewasz kodowanie warstwowe (base64 → base32 → …), wypróbuj:

- CyberChef „Magic”
- `codext` (python-codext): `codext <string>`

Typowe wskazówki:

- Base64: `A-Za-z0-9+/=` (często występuje dopełnienie `=`)
- Base32: `A-Z2-7=` (często występuje dużo dopełnienia `=`)
- Ascii85/Base85: gęsto rozmieszczone znaki interpunkcyjne; czasem ujęte w `<~ ~>`

### Podstawienie / szyfr monoalfabetyczny

- Narzędzie Boxentriq do łamania kryptogramów.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Odzyskiwanie na podstawie znanego tekstu jawnego w przypadku podstawionych nazw plików Base32

Jeśli zaciemniona nazwa pliku zawiera wyłącznie znaki `a-z2-7`, ma około `ceil(8 * byte_length / 5)` znaków po usunięciu stałego sufiksu, a ten sam tekst jawny daje taki sam wynik dla różnych plików, sprawdź hipotezę o **unpadded Base32, po którym następuje podstawienie symboli według stałego schematu**. Same te wskazówki nie stanowią dowodu. Zbierz przewidywalne nazwy plików i odpowiadające im szyfrogramy, zachowaj wielkość liter, zakoduj każdą nazwę tekstu jawnego w Base32 i dopasuj symbole pozycja po pozycji. Każdy powtarzający się symbol tekstu jawnego musi odpowiadać temu samemu symbolowi szyfrogramu, a odwzorowanie odwrotne również musi być jednoznaczne. W jednym przypadku ransomware pary `ntuser.ini` i `NTUSER.DAT` posłużyły do tego celu; pozwoliło to odzyskać nazwy plików, **a nie zawartość plików ani klucze szyfrowania**.<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

Jeśli cel zawiera niemapowane symbole, uzyskaj więcej znanych par lub permutuj wyłącznie mapowania nieużywanych symboli Base32. Przywróć padding do granicy ośmiu znaków, odrzucaj nieprawidłowe Base32 i zdekodowane nazwy zawierające znaki niedrukowalne, a następnie ponownie zakoduj pozostałe kandydatury i porównaj z **całym** oryginalnym ciphertextem. Powtarzające się bloki ciphertextu mogą dostarczyć dodatkowych wskazówek: w powyższym przypadku `3gpng2wv` mapowało się z powrotem na Base32 `gaydambq`, które dekoduje się do pięciu zer ASCII. Sama drukowalna kandydatura nie jest jednoznacznym dowodem.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Automatyczny łamacz szyfru Caesar od Nayuki.<sup>[[15]](#references)</sup>
- Narzędzie Atbash od Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Narzędzie Vigenère od dCode.<sup>[[8]](#references)</sup>
- Solver Vigenère od Guballa.<sup>[[17]](#references)</sup>

### Bacon cipher

Często występuje w grupach po 5 bitów lub 5 liter:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runy często są alfabetami podstawieniowymi; wyszukaj „futhark cipher” i spróbuj użyć tabel mapowania.

## Kompresja w zadaniach

### Technika

Kompresja stale pojawia się jako dodatkowa warstwa (zlib/deflate/gzip/xz/zstd), czasem zagnieżdżona. Jeśli wynik prawie daje się sparsować, ale wygląda jak śmieci, podejrzewaj kompresję.

### Szybka identyfikacja

- `file <blob>`
- Szukaj bajtów magicznych:
  - gzip: `1f 8b`
  - zlib: zazwyczaj `78 01`, `78 5e`, `78 9c` lub `78 da` (drugi bajt zależy od flag kompresji)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Surowy DEFLATE

CyberChef ma **Raw Deflate/Raw Inflate**, co często jest najszybszym rozwiązaniem, gdy blob wygląda na skompresowany, ale `zlib` zawodzi.

### Przydatne polecenia CLI

```bash
python3 - blob.bin <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
  try:
    print(zlib.decompress(data, wbits=wbits)[:200])
  except Exception:
    pass
PY
```

## Typowe konstrukcje kryptograficzne w CTF

### Technika

Pojawiają się często, ponieważ wynikają z realistycznych błędów programistów lub nieprawidłowego użycia popularnych bibliotek. Zwykle chodzi o rozpoznanie konstrukcji i zastosowanie znanego sposobu ekstrakcji lub rekonstrukcji.

### Fernet

Typowa wskazówka: dwa ciągi Base64 (token + klucz).

- Dekoder/notatki: dekoder Fernet Asecuritysite.<sup>[[18]](#references)</sup>
- W Pythonie: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Jeśli widzisz wiele udziałów i pojawia się próg `t`, prawdopodobnie chodzi o Shamir.

- Rekonstruktor online (wyłącznie dla niepoufnych udziałów z CTF).<sup>[[19]](#references)</sup>

### Formaty OpenSSL z solą

W CTF czasami otrzymuje się wyniki polecenia `openssl enc` (nagłówek często zaczyna się od `Salted__`).

Narzędzia pomocnicze do brute force:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Ogólny zestaw narzędzi

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Zalecana konfiguracja lokalna

Praktyczny zestaw narzędzi do CTF:

- Python oraz `pycryptodome` do prymitywów symetrycznych i szybkiego prototypowania.<sup>[[25]](#references)</sup>
- SageMath do arytmetyki modularnej, CRT, krat i zadań związanych z RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 do wyzwań opartych na ograniczeniach (gdy problem kryptograficzny można sprowadzić do ograniczeń).<sup>[[27]](#references)</sup>

Polecane pakiety Pythona:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```



## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [wyszukiwanie hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [narzędzia dCode](https://www.dcode.fr/tools-list)
- [9] [narzędzia Boxentriq do łamania kodów](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - automatyczne łamanie szyfru Cezara](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - szyfr Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [solver Vigenère’a Guballi](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - dekoder Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [rekonstruktor dzielenia sekretu Shamira](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [dokumentacja PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – łamanie schematów szyfrowania na leniwy sposób](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}
