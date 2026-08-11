# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Lista kontrolna triage

1. Określ, co posiadasz: encoding, encryption, hash, signature czy MAC.
2. Ustal, co jest kontrolowane: plaintext/ciphertext, IV/nonce, klucz, oracle (padding/error/timing), częściowy leak.
3. Sklasyfikuj: symetryczne (AES/CTR/GCM), klucz publiczny (RSA/ECC), hash/MAC (SHA/MD5/HMAC), klasyczne (Vigenere/XOR).
4. Najpierw zastosuj kontrole o najwyższym prawdopodobieństwie powodzenia: dekodowanie warstw, known-plaintext XOR, ponowne użycie nonce, niewłaściwe użycie trybu, zachowanie oracle.
5. Sięgaj po zaawansowane metody tylko wtedy, gdy są wymagane: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Zasoby online i narzędzia

Są przydatne, gdy zadanie polega na identyfikacji i zdejmowaniu warstw albo gdy potrzebujesz szybko potwierdzić hipotezę.

### Wyszukiwanie hashy

- Wyszukaj hash challenge, jeśli wiadomo, że jest syntetyczny/publiczny.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Wyszukiwarka hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Nie przesyłaj prawdziwych hashy haseł ani poufnych materiałów challenge do zewnętrznych usług wyszukiwania. Jeśli obawiasz się ujawnienia danych, warunków korzystania z usługi lub zasad konkursu, preferuj offline wordlist/rule attack.

### Narzędzia pomocne przy identyfikacji

- CyberChef (Magic, dekodowanie i konwersja).<sup>[[7]](#references)</sup>
- dCode (playground dla cipher/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (solvery substytucji).<sup>[[9]](#references)</sup>

### Platformy do ćwiczeń / materiały referencyjne

- CryptoHack (praktyczne wyzwania z cryptography).<sup>[[10]](#references)</sup>
- Cryptopals (klasyczne problemy współczesnej cryptography).<sup>[[11]](#references)</sup>

### Automatyczne dekodowanie

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (próbuje wielu baz/encodingów).<sup>[[13]](#references)</sup>

## Encodingi i klasyczne ciphers

### Technika

Wiele zadań crypto w CTF to transformacje warstwowe: base encoding + prosta substytucja + kompresja. Celem jest identyfikacja warstw i bezpieczne ich zdejmowanie.

### Encodingi: wypróbuj wiele baz

Jeśli podejrzewasz encoding warstwowy (base64 → base32 → …), wypróbuj:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Typowe oznaki:

- Base64: `A-Za-z0-9+/=` (padding `=` jest częsty)
- Base32: `A-Z2-7=` (często dużo paddingu `=`)
- Ascii85/Base85: gęste znaki interpunkcyjne; czasami ujęte w `<~ ~>`

### Substytucja / monoalfabetyczna

- Solver kryptogramów Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Automatyczny breaker Caesar-cipher firmy Nayuki.<sup>[[15]](#references)</sup>
- Narzędzie Atbash firmy Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Narzędzie Vigenère firmy dCode.<sup>[[8]](#references)</sup>
- Solver Vigenère firmy Guballa.<sup>[[17]](#references)</sup>

### Bacon cipher

Często występuje jako grupy 5 bitów lub 5 liter:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runy

Runy są często alfabetami podstawieniowymi; wyszukaj „futhark cipher” i spróbuj użyć tabel mapowania.

## Kompresja w zadaniach

### Technika

Kompresja często pojawia się jako dodatkowa warstwa (zlib/deflate/gzip/xz/zstd), czasami zagnieżdżona. Jeśli dane wyjściowe prawie dają się sparsować, ale wyglądają jak śmieci, podejrzewaj kompresję.

### Szybka identyfikacja

- `file <blob>`
- Szukaj magicznych bajtów:
- gzip: `1f 8b`
- zlib: zazwyczaj `78 01`, `78 5e`, `78 9c` lub `78 da` (drugi bajt zależy od flag kompresji)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ma funkcje **Raw Deflate/Raw Inflate**, które często są najszybszym rozwiązaniem, gdy dane wyglądają na skompresowane, ale `zlib` zawodzi.

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
## Typowe konstrukty kryptograficzne CTF

### Technika

Pojawiają się często, ponieważ są realistycznymi błędami developerów lub wynikają z nieprawidłowego użycia popularnych bibliotek. Celem jest zazwyczaj rozpoznanie problemu i zastosowanie znanego workflow ekstrakcji lub rekonstrukcji.

### Fernet

Typowa wskazówka: dwa ciągi Base64 (token + key).

- Decoder/notatki: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- W Pythonie: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Jeśli widzisz wiele shares i wspomniany jest próg `t`, prawdopodobnie chodzi o Shamir.

- Online reconstructor (wyłącznie dla niepoufnych shares z CTF).<sup>[[19]](#references)</sup>

### OpenSSL salted formats

CTF-y czasami dostarczają wyniki `openssl enc` (nagłówek często zaczyna się od `Salted__`).

Narzędzia pomocnicze do bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Ogólny zestaw narzędzi

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Zalecana konfiguracja lokalna

Praktyczny stack CTF:

- Python oraz `pycryptodome` do primitive symetrycznych i szybkiego prototypowania.<sup>[[25]](#references)</sup>
- SageMath do arytmetyki modularnej, CRT, lattice oraz pracy z RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 do challenges opartych na constraints (gdy problem kryptograficzny sprowadza się do constraints).<sup>[[27]](#references)</sup>

Sugerowane pakiety Pythona:
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
- [15] [Nayuki - automatyczne narzędzie do łamania szyfru Cezara](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - szyfr Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [solver Vigenère’a Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - dekoder Ferneta](https://asecuritysite.com/encryption/ferdecode)
- [19] [rekonstruktor współdzielenia sekretu Shamira](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [dokumentacja PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
