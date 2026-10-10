# Crypto CTF tok rada

{{#include ../../banners/hacktricks-training.md}}

## Kontrolna lista za trijažu

1. Utvrdite šta imate: kodiranje naspram enkripcije, hash-a, potpisa ili MAC-a.
2. Utvrdite šta je pod vašom kontrolom: plaintext/ciphertext, IV/nonce, ključ, oracle (padding/error/timing), delimični leak.
3. Klasifikujte: simetrično (AES/CTR/GCM), javni ključ (RSA/ECC), hash/MAC (SHA/MD5/HMAC), klasično (Vigenere/XOR).
4. Prvo primenite provere s najvećom verovatnoćom uspeha: dekodirajte slojeve, known-plaintext XOR, ponovna upotreba nonce-a, pogrešna upotreba režima, ponašanje oracle-a.
5. Napredne metode koristite samo kada je potrebno: rešetke (LLL/Coppersmith), SMT/Z3, side-channel napadi.

## Online resursi i alati

Korisni su kada je zadatak identifikacija i uklanjanje slojeva ili kada vam je potrebna brza potvrda hipoteze.

### Pretraga hash-eva

- Potražite hash izazova ako je poznato da je sintetički/javan.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Pretraga na hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Ne šaljite stvarne password hash-eve niti poverljiv materijal izazova uslugama za pretragu trećih strana. Ako su važni zaštita podataka, uslovi korišćenja ili pravila takmičenja, prednost dajte offline napadu pomoću wordlist-e i pravila.

### Alati za identifikaciju

- CyberChef (Magic, dekodiranje i konverzija).<sup>[[7]](#references)</sup>
- dCode (okruženje za šifre/kodiranja).<sup>[[8]](#references)</sup>
- Boxentriq (alati za rešavanje supstitucionih šifara).<sup>[[9]](#references)</sup>

### Platforme za vežbu / reference

- CryptoHack (praktični kriptografski izazovi).<sup>[[10]](#references)</sup>
- Cryptopals (klasične zamke moderne kriptografije).<sup>[[11]](#references)</sup>

### Automatsko dekodiranje

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (isprobava brojne baze/kodiranja).<sup>[[13]](#references)</sup>

## Kodiranja i klasične šifre

### Tehnika

Mnogi CTF crypto zadaci sastoje se od niza transformacija: kodiranje u bazi + jednostavna supstitucija + kompresija. Cilj je identifikovati slojeve i bezbedno ih ukloniti.

### Kodiranja: isprobajte više baza

Ako sumnjate na slojevito kodiranje (base64 → base32 → …), isprobajte:

- CyberChef „Magic“
- `codext` (python-codext): `codext <string>`

Uobičajeni pokazatelji:

- Base64: `A-Za-z0-9+/=` (dopuna `=` je česta)
- Base32: `A-Z2-7=` (često ima mnogo znakova za dopunu `=`)
- Ascii85/Base85: gusta interpunkcija; ponekad omeđeno sa `<~ ~>`

### Supstitucija / monoalfabetska šifra

- Boxentriq alat za rešavanje kriptograma.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatski alat za razbijanje Caesar šifre.<sup>[[15]](#references)</sup>
- Rumkin Atbash alat.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère alat.<sup>[[8]](#references)</sup>
- Guballa Vigenère alat za rešavanje.<sup>[[17]](#references)</sup>

### Bacon šifra

Često se pojavljuje u grupama od 5 bitova ili 5 slova:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Rune

Rune su često supstitucioni alfabeti; pretražite „futhark cipher“ i isprobajte tabele preslikavanja.

## Kompresija u izazovima

### Tehnika

Kompresija se stalno pojavljuje kao dodatni sloj (zlib/deflate/gzip/xz/zstd), ponekad i ugnježden. Ako izlaz skoro može da se parsira, ali izgleda kao besmislica, posumnjajte na kompresiju.

### Brza identifikacija

- `file <blob>`
- Potražite magične bajtove:
  - gzip: `1f 8b`
  - zlib: obično `78 01`, `78 5e`, `78 9c` ili `78 da` (drugi bajt zavisi od oznaka kompresije)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Sirovi DEFLATE

CyberChef ima **Raw Deflate/Raw Inflate**, što je često najbrži način kada blob izgleda kompresovano, ali `zlib` ne uspeva.

### Korisne CLI komande

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

## Uobičajeni kripto obrasci u CTF-u

### Tehnika

Često se pojavljuju jer predstavljaju realistične greške programera ili pogrešnu upotrebu uobičajenih biblioteka. Cilj je obično da ih prepoznate i primenite poznati postupak za izdvajanje ili rekonstrukciju.

### Fernet

Tipičan nagoveštaj: dva Base64 niza (token + ključ).

- Dekoder/b beleške: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- U Python-u: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ako vidite više delova tajne i pominje se prag `t`, verovatno je u pitanju Shamir.

- Online alat za rekonstrukciju (samo za neosetljive CTF delove tajne).<sup>[[19]](#references)</sup>

### OpenSSL formati sa salt-om

CTF zadaci ponekad daju izlaze komande `openssl enc` (zaglavlje često počinje sa `Salted__`).

Alati za bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Opšti skup alata

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Preporučeno lokalno okruženje

Praktičan CTF skup alata:

- Python i `pycryptodome` za simetrične primitive i brzo pravljenje prototipa.<sup>[[25]](#references)</sup>
- SageMath za modularnu aritmetiku, CRT, rešetke i rad sa RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 za izazove zasnovane na ograničenjima (kada se kriptografija svede na ograničenja).<sup>[[27]](#references)</sup>

Preporučeni Python paketi:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [pretraga hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode alati](https://www.dcode.fr/tools-list)
- [9] [Boxentriq alati za razbijanje šifara](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - automatski alat za razbijanje Caesar šifre](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash šifra](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet dekoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [rekonstruktor Shamir secret-sharing šeme](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome dokumentacija](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
