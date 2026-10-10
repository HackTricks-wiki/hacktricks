# Krypto-CTF-Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage-Checkliste

1. Bestimme, womit du es zu tun hast: Encoding vs. Verschlüsselung vs. Hash vs. Signatur vs. MAC.
2. Bestimme, was kontrolliert wird: Klartext/Chiffretext, IV/Nonce, Schlüssel, Oracle (Padding/Fehler/Timing), partielles Leakage.
3. Ordne es ein: symmetrisch (AES/CTR/GCM), Public-Key (RSA/ECC), Hash/MAC (SHA/MD5/HMAC), klassisch (Vigenere/XOR).
4. Prüfe zuerst die wahrscheinlichsten Ansätze: Decoding-Schichten, Known-Plaintext-XOR, Nonce-Wiederverwendung, fehlerhafte Modi, Oracle-Verhalten.
5. Greife nur bei Bedarf auf fortgeschrittene Methoden zurück: Lattices (LLL/Coppersmith), SMT/Z3, Side-Channels.

## Online-Ressourcen & Tools

Diese sind nützlich, wenn die Aufgabe darin besteht, etwas zu identifizieren und Schichten abzutragen, oder wenn du eine Hypothese schnell bestätigen möchtest.

### Hash-Lookups

- Suche nach einem Challenge-Hash, wenn bekannt ist, dass er synthetisch/öffentlich ist.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org-Suche.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Übermittle keine echten Passwort-Hashes oder vertraulichen Challenge-Daten an Lookup-Dienste von Drittanbietern. Wenn Offenlegung, Nutzungsbedingungen oder Wettbewerbsregeln bedenklich sind, verwende stattdessen offline einen Wordlist-/Rule-Angriff.

### Tools zur Identifizierung

- CyberChef (Magic, Decoding und Konvertierung).<sup>[[7]](#references)</sup>
- dCode (Spielwiese für Chiffren/Encodings).<sup>[[8]](#references)</sup>
- Boxentriq (Substitutionslöser).<sup>[[9]](#references)</sup>

### Übungsplattformen / Referenzen

- CryptoHack (praktische Kryptografie-Challenges).<sup>[[10]](#references)</sup>
- Cryptopals (klassische Fallstricke moderner Kryptografie).<sup>[[11]](#references)</sup>

### Automatisches Decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (probiert viele Basen/Encodings aus).<sup>[[13]](#references)</sup>

## Encodings & klassische Chiffren

### Technik

Viele Krypto-CTF-Aufgaben bestehen aus mehreren Transformationen: Base-Encoding + einfache Substitution + Komprimierung. Ziel ist es, die Schichten zu erkennen und sicher abzutragen.

### Encodings: viele Basen ausprobieren

Wenn du ein Encoding mit mehreren Schichten vermutest (base64 → base32 → …), probiere:

- CyberChef „Magic“
- `codext` (python-codext): `codext <string>`

Typische Hinweise:

- Base64: `A-Za-z0-9+/=` (Padding mit `=` ist üblich)
- Base32: `A-Z2-7=` (oft viel Padding mit `=`)
- Ascii85/Base85: viele Satzzeichen; manchmal von `<~ ~>` umschlossen

### Substitution / monoalphabetisch

- Boxentriq-Kryptogramm-Löser.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Automatischer Caesar-Chiffre-Knacker von Nayuki.<sup>[[15]](#references)</sup>
- Atbash-Tool von Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- dCode-Vigenère-Tool.<sup>[[8]](#references)</sup>
- Guballa-Vigenère-Löser.<sup>[[17]](#references)</sup>

### Bacon-Chiffre

Kommt oft als Gruppen von 5 Bits oder 5 Buchstaben vor:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runen sind häufig Substitutionsalphabete; suche nach „futhark cipher“ und probiere Mapping-Tabellen aus.

## Komprimierung in Challenges

### Technik

Komprimierung taucht ständig als zusätzliche Ebene auf (zlib/deflate/gzip/xz/zstd), manchmal auch verschachtelt. Wenn sich die Ausgabe fast parsen lässt, aber wie Kauderwelsch aussieht, solltest du Komprimierung vermuten.

### Schnelle Identifizierung

- `file <blob>`
- Achte auf Magic Bytes:
  - gzip: `1f 8b`
  - zlib: häufig `78 01`, `78 5e`, `78 9c` oder `78 da` (das zweite Byte hängt von den Komprimierungsflags ab)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef bietet **Raw Deflate/Raw Inflate**. Das ist oft der schnellste Weg, wenn der blob komprimiert aussieht, aber `zlib` fehlschlägt.

### Nützliche CLI-Tools

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

## Häufige CTF-Krypto-Konstrukte

### Technik

Diese treten häufig auf, weil es sich um realistische Entwicklerfehler oder um häufig falsch verwendete Bibliotheken handelt. Meist geht es darum, sie zu erkennen und einen bekannten Extraktions- oder Rekonstruktionsablauf anzuwenden.

### Fernet

Typischer Hinweis: zwei Base64-Zeichenfolgen (Token + Schlüssel).

- Decoder/Notizen: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Wenn mehrere Shares vorhanden sind und ein Schwellenwert `t` erwähnt wird, handelt es sich wahrscheinlich um Shamir.

- Online-Rekonstruktion (nur für nicht vertrauliche CTF-Shares).<sup>[[19]](#references)</sup>

### OpenSSL-Formate mit Salt

CTFs enthalten manchmal Ausgaben von `openssl enc` (der Header beginnt oft mit `Salted__`).

Brute-Force-Hilfsprogramme:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Allgemeines Toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Empfohlene lokale Einrichtung

Praktisches CTF-Setup:

- Python plus `pycryptodome` für symmetrische Primitive und schnelles Prototyping.<sup>[[25]](#references)</sup>
- SageMath für modulare Arithmetik, CRT, Gitter und RSA-/ECC-Arbeiten.<sup>[[26]](#references)</sup>
- Z3 für auf Bedingungen basierende Challenges (wenn sich die Kryptografie auf Bedingungen reduzieren lässt).<sup>[[27]](#references)</sup>

Empfohlene Python-Pakete:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [Suche auf hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash-Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode-Tools](https://www.dcode.fr/tools-list)
- [9] [Boxentriq-Tools zur Codeknackung](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Automatischer Caesar-Chiffre-Knacker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash-Chiffre](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa-Vigenère-Löser](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet-Dekodierer](https://asecuritysite.com/encryption/ferdecode)
- [19] [Rekonstruktion der Shamir-Geheimnisaufteilung](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome-Dokumentation](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
