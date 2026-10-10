# Workflow CTF związany z kryptografią

{{#include ../../banners/hacktricks-training.md}}

## Lista kontrolna triage

1. Ustal, z czym masz do czynienia: kodowaniem, szyfrowaniem, hashem, podpisem czy MAC.
2. Ustal, co jest kontrolowane: tekst jawny/szyfrogram, IV/nonce, klucz, oracle (padding/błąd/czas), częściowy wyciek.
3. Sklasyfikuj: symetryczne (AES/CTR/GCM), klucz publiczny (RSA/ECC), hash/MAC (SHA/MD5/HMAC), klasyczne (Vigenere/XOR).
4. Najpierw wykonaj testy o najwyższym prawdopodobieństwie powodzenia: dekodowanie kolejnych warstw, XOR ze znanym tekstem jawnym, ponowne użycie nonce, niewłaściwe użycie trybu, zachowanie oracle.
5. Sięgaj po zaawansowane metody tylko w razie potrzeby: kraty (LLL/Coppersmith), SMT/Z3, side-channel.

## Zasoby online i narzędzia

Przydają się, gdy zadanie polega na identyfikacji i zdejmowaniu kolejnych warstw albo gdy potrzebujesz szybko potwierdzić hipotezę.

### Wyszukiwanie hashy

- Wyszukaj hash z zadania, jeśli wiadomo, że jest sztuczny/publiczny.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Wyszukiwarka hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Nie przesyłaj prawdziwych hashy haseł ani poufnych materiałów z zadania do zewnętrznych serwisów wyszukujących. Jeśli masz obawy dotyczące ujawnienia danych, warunków korzystania z usługi lub zasad konkursu, wybierz atak offline z użyciem wordlisty/reguł.

### Narzędzia pomocne przy identyfikacji

- CyberChef (Magic, dekodowanie i konwersja).<sup>[[7]](#references)</sup>
- dCode (środowisko do testowania szyfrów i kodowań).<sup>[[8]](#references)</sup>
- Boxentriq (narzędzia do rozwiązywania szyfrów podstawieniowych).<sup>[[9]](#references)</sup>

### Platformy do ćwiczeń / materiały referencyjne

- CryptoHack (praktyczne zadania z kryptografii).<sup>[[10]](#references)</sup>
- Cryptopals (klasyczne pułapki współczesnej kryptografii).<sup>[[11]](#references)</sup>

### Automatyczne dekodowanie

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (próbuje wielu systemów liczbowych/kodowań).<sup>[[13]](#references)</sup>

## Kodowania i szyfry klasyczne

### Technika

Wiele zadań CTF z kryptografii polega na transformacjach nakładanych warstwami: kodowanie base + proste podstawienie + kompresja. Celem jest rozpoznanie warstw i bezpieczne zdejmowanie ich po kolei.

### Kodowania: wypróbuj wiele systemów liczbowych

Jeśli podejrzewasz kodowanie warstwowe (base64 → base32 → …), wypróbuj:

- CyberChef „Magic”
- `codext` (python-codext): `codext <string>`

Typowe oznaki:

- Base64: `A-Za-z0-9+/=` (znak dopełnienia `=` jest częsty)
- Base32: `A-Z2-7=` (często występuje dużo znaków dopełnienia `=`)
- Ascii85/Base85: dużo znaków interpunkcyjnych; czasem ujęte w `<~ ~>`

### Podstawienie / monoalfabetyczny

- Narzędzie Boxentriq do rozwiązywania kryptogramów.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Automatyczne narzędzie Nayuki do łamania szyfru Caesar.<sup>[[15]](#references)</sup>
- Narzędzie Rumkin Atbash.<sup>[[16]](#references)</sup>

### Vigenère

- Narzędzie dCode Vigenère.<sup>[[8]](#references)</sup>
- Narzędzie Guballa do łamania Vigenère.<sup>[[17]](#references)</sup>

### Szyfr Bacona

Często występuje w grupach po 5 bitów lub 5 liter:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runy

Runy często tworzą alfabet podstawieniowy; wyszukaj „futhark cipher” i spróbuj użyć tabel mapowania.

## Kompresja w zadaniach

### Technika

Kompresja stale pojawia się jako dodatkowa warstwa (zlib/deflate/gzip/xz/zstd), czasem zagnieżdżona. Jeśli wynik wygląda prawie jak poprawnie sparsowany, ale przypomina śmieci, podejrzewaj kompresję.

### Szybka identyfikacja

- `file <blob>`
- Szukaj magicznych bajtów:
  - gzip: `1f 8b`
  - zlib: często `78 01`, `78 5e`, `78 9c` lub `78 da` (drugi bajt zależy od flag kompresji)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ma **Raw Deflate/Raw Inflate** — często to najszybsza droga, gdy blob wygląda na skompresowany, ale `zlib` nie działa.

### Przydatne CLI

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

## Typowe konstrukcje kryptograficzne CTF

### Technika

Pojawiają się często, ponieważ wynikają z realistycznych błędów programistów lub nieprawidłowego użycia popularnych bibliotek. Zazwyczaj celem jest ich rozpoznanie i zastosowanie znanego sposobu ekstrakcji lub rekonstrukcji.

### Fernet

Typowa wskazówka: dwa ciągi Base64 (token + klucz).

- Dekoder/notatki: dekoder Fernet Asecuritysite.<sup>[[18]](#references)</sup>
- W Pythonie: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Jeśli widzisz wiele udziałów i wspomniano o progu `t`, prawdopodobnie chodzi o Shamir.

- Rekonstruktor online (tylko dla niewrażliwych udziałów CTF).<sup>[[19]](#references)</sup>

### Formaty OpenSSL z solą

CTF-y czasem udostępniają wyniki `openssl enc` (nagłówek często zaczyna się od `Salted__`).

Narzędzia pomocnicze do brute force:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Ogólny zestaw narzędzi

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Zalecana konfiguracja lokalna

Praktyczny zestaw narzędzi CTF:

- Python oraz `pycryptodome` do prymitywów symetrycznych i szybkiego prototypowania.<sup>[[25]](#references)</sup>
- SageMath do arytmetyki modularnej, CRT, krat oraz zadań związanych z RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 do wyzwań opartych na ograniczeniach (gdy problem kryptograficzny można sprowadzić do ograniczeń).<sup>[[27]](#references)</sup>

Sugerowane pakiety Pythona:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [wyszukiwarka hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [narzędzia dCode](https://www.dcode.fr/tools-list)
- [9] [Narzędzia Boxentriq do łamania szyfrów](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Automatyczny łamacz szyfru Cezara](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - szyfr Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [Narzędzie Guballa do rozwiązywania szyfru Vigenère’a](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - dekoder Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Rekonstruktor współdzielenia sekretu Shamira](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [Dokumentacja PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
