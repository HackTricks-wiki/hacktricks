# Crypto-CTF-Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage-Checkliste

1. Identifiziere, was du vorliegen hast: Encoding vs. Encryption vs. Hash vs. Signature vs. MAC.
2. Bestimme, was kontrolliert wird: Plaintext/Ciphertext, IV/Nonce, Key, Oracle (Padding/Fehler/Timing), teilweise Leaks.
3. Klassifiziere: symmetrisch (AES/CTR/GCM), Public-Key (RSA/ECC), Hash/MAC (SHA/MD5/HMAC), klassisch (Vigenere/XOR).
4. Wende zuerst die Prüfungen mit der höchsten Wahrscheinlichkeit an: Decoding-Schichten, Known-Plaintext-XOR, Nonce-Wiederverwendung, falsche Modusverwendung, Oracle-Verhalten.
5. Wechsle nur bei Bedarf zu fortgeschrittenen Methoden: Lattices (LLL/Coppersmith), SMT/Z3, Side-Channels.

## Online-Ressourcen & Utilities

Diese sind nützlich, wenn es um die Identifikation und das schrittweise Entfernen von Schichten geht oder wenn du eine Hypothese schnell bestätigen musst.

### Hash-Suchen

- Suche nach einem Challenge-Hash, wenn bekannt ist, dass er synthetisch/öffentlich ist.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org search.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Übermittle keine echten Password-Hashes oder vertraulichen Challenge-Inhalte an Lookup-Services von Drittanbietern. Bevorzuge einen Offline-Wordlist-/Rule-Angriff, wenn Offenlegung, Nutzungsbedingungen oder Wettbewerbsregeln problematisch sein könnten.

### Hilfsmittel zur Identifikation

- CyberChef (Magic, Decoding und Konvertierung).<sup>[[7]](#references)</sup>
- dCode (Cipher-/Encoding-Spielplatz).<sup>[[8]](#references)</sup>
- Boxentriq (Substitution-Solver).<sup>[[9]](#references)</sup>

### Übungsplattformen / Ressourcen

- CryptoHack (praxisnahe Cryptography-Challenges).<sup>[[10]](#references)</sup>
- Cryptopals (klassische Schwachstellen moderner Cryptography).<sup>[[11]](#references)</sup>

### Automatisiertes Decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (probiert viele Bases/Encodings aus).<sup>[[13]](#references)</sup>

## Encodings & klassische Ciphers

### Technik

Viele Crypto-CTF-Aufgaben bestehen aus geschichteten Transformationen: Base-Encoding + einfache Substitution + Kompression. Ziel ist es, die Schichten zu identifizieren und sicher schrittweise zu entfernen.

### Encodings: viele Bases ausprobieren

Wenn du ein geschichtetes Encoding vermutest (base64 → base32 → …), probiere:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Typische Hinweise:

- Base64: `A-Za-z0-9+/=` (Padding mit `=` ist häufig)
- Base32: `A-Z2-7=` (oft viel `=`-Padding)
- Ascii85/Base85: dichte Interpunktion; manchmal in `<~ ~>` eingeschlossen

### Substitution / monoalphabetisch

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon Cipher

Erscheint häufig als Gruppen aus 5 Bits oder 5 Buchstaben:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runen

Runen sind häufig Substitutionsalphabete. Suche nach "futhark cipher" und versuche, Zuordnungstabellen zu verwenden.

## Kompression in Challenges

### Technik

Kompression tritt ständig als zusätzliche Ebene auf (zlib/deflate/gzip/xz/zstd), manchmal verschachtelt. Wenn die Ausgabe fast geparst werden kann, aber wie Datenmüll aussieht, solltest du Kompression vermuten.

### Schnelle Identifizierung

- `file <blob>`
- Suche nach Magic Bytes:
- gzip: `1f 8b`
- zlib: häufig `78 01`, `78 5e`, `78 9c` oder `78 da` (das zweite Byte hängt von den Kompressions-Flags ab)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef verfügt über **Raw Deflate/Raw Inflate**, was oft der schnellste Weg ist, wenn der Blob komprimiert aussieht, aber `zlib` fehlschlägt.

### Nützliche CLI
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
## Häufige CTF-Kryptokonstrukte

### Technique

Diese treten häufig auf, weil sie realistische Fehler von Entwicklern oder häufige, falsch verwendete Bibliotheken darstellen. Das Ziel ist normalerweise, sie zu erkennen und einen bekannten Workflow zur Extraktion oder Rekonstruktion anzuwenden.

### Fernet

Typischer Hinweis: zwei Base64-Strings (Token + Key).

- Decoder/Notizen: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Wenn du mehrere Shares siehst und ein Threshold `t` erwähnt wird, handelt es sich wahrscheinlich um Shamir.

- Online reconstructor (nur für nicht vertrauliche CTF-Shares).<sup>[[19]](#references)</sup>

### OpenSSL salted formats

CTFs enthalten manchmal Ausgaben von `openssl enc` (der Header beginnt häufig mit `Salted__`).

Bruteforce-Hilfsprogramme:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Allgemeines Toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Empfohlenes lokales Setup

Praktischer CTF-Stack:

- Python plus `pycryptodome` für symmetrische Primitives und schnelles Prototyping.<sup>[[25]](#references)</sup>
- SageMath für modulare Arithmetik, CRT, Gitter sowie RSA/ECC-Arbeiten.<sup>[[26]](#references)</sup>
- Z3 für constraint-basierte Challenges (wenn sich die Kryptografie auf Constraints reduzieren lässt).<sup>[[27]](#references)</sup>

Empfohlene Python-Pakete:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org-Suche](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash-Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode-Tools](https://www.dcode.fr/tools-list)
- [9] [Boxentriq-Tools zum Codeknacken](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Automatischer Caesar-Chiffre-Knacker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash-Chiffre](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa-Vigenere-Loser](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet-Dekodierer](https://asecuritysite.com/encryption/ferdecode)
- [19] [Rekonstruktor fur Shamir Secret Sharing](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome-Dokumentation](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
