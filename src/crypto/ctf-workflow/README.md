# Crypto CTF-werkvloei

{{#include ../../banners/hacktricks-training.md}}

## Triage-kontrolelys

1. Identifiseer wat jy het: encoding vs encryption vs hash vs signature vs MAC.
2. Bepaal wat beheer word: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), gedeeltelike leak.
3. Klassifiseer: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Pas eers die waarskynlikste kontroles toe: decode-lae, known-plaintext XOR, hergebruik van nonce, verkeerde gebruik van modus, oracle-gedrag.
5. Gaan slegs oor na gevorderde metodes wanneer nodig: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Aanlyn hulpbronne & nutsprogramme

Dit is nuttig wanneer die taak identifikasie en die afskilfering van lae behels, of wanneer jy ’n hipotese vinnig wil bevestig.

### Hash-opsoeke

- Soek na ’n challenge-hash wanneer dit bekend is dat dit sinteties/publiek is.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org search.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Moenie regte password-hashes of vertroulike challenge-materiaal by derdeparty-opsoekdienste indien nie. Verkies ’n aflyn woordelys-/reël-aanval wanneer openbaarmaking, diensvoorwaardes of kompetisiereëls ’n bekommernis is.

### Identifikasiehulpmiddels

- CyberChef (Magic, decoding en conversion).<sup>[[7]](#references)</sup>
- dCode (cipher/encoding-speelgrond).<sup>[[8]](#references)</sup>
- Boxentriq (substitution-oplossers).<sup>[[9]](#references)</sup>

### Oefenplatforms / verwysings

- CryptoHack (praktiese kriptografie-uitdagings).<sup>[[10]](#references)</sup>
- Cryptopals (klassieke slaggate in moderne kriptografie).<sup>[[11]](#references)</sup>

### Outomatiese decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (probeer baie bases/encodings).<sup>[[13]](#references)</sup>

## Encodings & klassieke ciphers

### Tegniek

Baie CTF-crypto-take bestaan uit gelaagde transformasies: base encoding + eenvoudige substitution + compression. Die doel is om die lae te identifiseer en dit veilig af te skil.

### Encodings: probeer baie bases

As jy gelaagde encoding vermoed (base64 → base32 → …), probeer:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Algemene leidrade:

- Base64: `A-Za-z0-9+/=` (padding `=` kom algemeen voor)
- Base32: `A-Z2-7=` (dikwels baie `=`-padding)
- Ascii85/Base85: digte leestekens; soms omring deur `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Herwinning met known-plaintext van vervangde Base32-lêername

Wanneer ’n verduisterde lêernaam slegs `a-z2-7` gebruik, uitbrei tot ongeveer `ceil(8 * byte_length / 5)` karakters nadat ’n vaste agtervoegsel verwyder is, en dieselfde plaintext dieselfde uitset vir verskillende lêers lewer, toets **unpadded Base32 gevolg deur ’n vaste simboolsubstitution**. Hierdie leidrade is nie op sigself bewys nie. Versamel voorspelbare lêername en hul ciphertexts, behou die hooflettergebruik, Base32-encodeer elke plaintext en belyn die simbole posisie vir posisie. Elke herhaalde plaintext-simbool moet na dieselfde ciphertext-simbool karteer, en die inverse kartering moet ook uniek wees. In een ransomware-geval het `ntuser.ini` en `NTUSER.DAT` sulke pare opgelewer; dit het lêername herwin, **nie lêerinhoud of encryption keys nie**.<sup>[[28]](#references)</sup>

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

As ’n teiken ongemapte simbole bevat, verkry meer bekende pare of permuteer slegs die ongebruikte Base32-simboolkarterings. Herstel padding tot ’n veelvoud van agt karakters, verwerp ongeldige Base32 en nie-drukbare gedekodeerde name, en enkodeer dan die oorlewende kandidate weer om die **hele** oorspronklike ciphertext te vergelyk. Herhaalde ciphertext-blokke kan bykomende raaiskote oplewer: in die geval hierbo is `3gpng2wv` teruggekoppel aan Base32 `gaydambq`, wat na vyf ASCII-nulle dekodeer. ’n Drukbare kandidaat alleen is nie unieke bewys nie.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki se outomatiese Caesar-cipher-kraker.<sup>[[15]](#references)</sup>
- Rumkin se Atbash-nutsding.<sup>[[16]](#references)</sup>

### Vigenère

- dCode se Vigenère-nutsding.<sup>[[8]](#references)</sup>
- Guballa se Vigenère-oplosser.<sup>[[17]](#references)</sup>

### Bacon cipher

Kom dikwels voor as groepe van 5 bisse of 5 letters:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runes is dikwels substitusie-alfabette; soek vir "futhark cipher" en probeer karteringstabelle.

## Kompressie in uitdagings

### Tegniek

Kompressie kom voortdurend voor as ’n ekstra laag (zlib/deflate/gzip/xz/zstd), soms genestel. As die uitvoer amper ontleedbaar is, maar soos gemors lyk, vermoed kompressie.

### Vinnige identifisering

- `file <blob>`
- Soek na magic bytes:
  - gzip: `1f 8b`
  - zlib: gewoonlik `78 01`, `78 5e`, `78 9c` of `78 da` (die tweede byte hang van die kompressievlae af)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef het **Raw Deflate/Raw Inflate**, wat dikwels die vinnigste oplossing is wanneer die blob saamgepers lyk, maar `zlib` misluk.

### Nuttige CLI

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

## Algemene CTF-kriptokonstruksies

### Tegniek

Dit kom gereeld voor omdat dit realistiese ontwikkelaarsfoute of algemene biblioteke is wat verkeerd gebruik word. Die doel is gewoonlik om dit te herken en ’n bekende ekstraksie- of rekonstruksiewerkvloei toe te pas.

### Fernet

Tipiese wenk: twee Base64-stringe (token + sleutel).

- Dekodeerder/notas: Asecuritysite Fernet-dekodeerder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

As jy verskeie aandele sien en ’n drempel `t` word genoem, is dit waarskynlik Shamir.

- Aanlynrekonstrueerder (slegs vir nie-sensitiewe CTF-aandele).<sup>[[19]](#references)</sup>

### OpenSSL-versoute formate

CTF’s gee soms `openssl enc`-uitsette (die kopskrif begin dikwels met `Salted__`).

Bruteforce-hulpmiddels:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Algemene gereedskapstel

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Aanbevole plaaslike opstelling

Praktiese CTF-stapel:

- Python plus `pycryptodome` vir simmetriese primitiewe en vinnige prototipering.<sup>[[25]](#references)</sup>
- SageMath vir modulêre rekenkunde, CRT, roosters en RSA/ECC-werk.<sup>[[26]](#references)</sup>
- Z3 vir uitdagings gebaseer op beperkings (wanneer die kriptografie tot beperkings herlei kan word).<sup>[[27]](#references)</sup>

Voorgestelde Python-pakkette:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org search](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode tools](https://www.dcode.fr/tools-list)
- [9] [Boxentriq code-breaking tools](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Automatic Caesar cipher breaker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet decoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing reconstructor](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome documentation](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Breaking encryption schemes the lazy way](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
