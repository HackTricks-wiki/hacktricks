# Crypto-CTF-Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage-Checkliste

1. Stelle fest, womit du es zu tun hast: Encoding vs. Verschlüsselung vs. Hash vs. Signatur vs. MAC.
2. Ermittle, was kontrolliert wird: Klartext/Chiffretext, IV/Nonce, Schlüssel, Oracle (Padding/Fehler/Timing), partieller leak.
3. Ordne ein: symmetrisch (AES/CTR/GCM), Public-Key (RSA/ECC), Hash/MAC (SHA/MD5/HMAC), klassisch (Vigenere/XOR).
4. Führe zuerst die Prüfungen mit der höchsten Wahrscheinlichkeit durch: Encoding-Schichten dekodieren, XOR mit bekanntem Klartext, Nonce-Wiederverwendung, Missbrauch des Modus, Oracle-Verhalten.
5. Greife nur bei Bedarf auf fortgeschrittene Methoden zurück: Lattices (LLL/Coppersmith), SMT/Z3, Seitenkanäle.

## Online-Ressourcen & Utilities

Diese sind nützlich, wenn es darum geht, eine Aufgabe zu identifizieren und Schichten abzutragen oder eine Hypothese schnell zu überprüfen.

### Hash-Suche

- Suche nach einem Challenge-Hash, wenn bekannt ist, dass er synthetisch/öffentlich ist.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org-Suche.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Übermittle keine echten Passwort-Hashes oder vertraulichen Challenge-Daten an Suchdienste von Drittanbietern. Wenn Datenschutz, Nutzungsbedingungen oder Wettbewerbsregeln eine Rolle spielen, solltest du stattdessen offline einen Wordlist-/Rule-Angriff durchführen.

### Tools zur Identifizierung

- CyberChef (Magic, Decoding und Konvertierung).<sup>[[7]](#references)</sup>
- dCode (Spielwiese für Chiffren/Encodings).<sup>[[8]](#references)</sup>
- Boxentriq (Solver für Substitutionen).<sup>[[9]](#references)</sup>

### Übungsplattformen / Referenzen

- CryptoHack (praktische Kryptografie-Challenges).<sup>[[10]](#references)</sup>
- Cryptopals (klassische Fallstricke moderner Kryptografie).<sup>[[11]](#references)</sup>

### Automatisiertes Decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (probiert viele Basen/Encodings aus).<sup>[[13]](#references)</sup>

## Encodings & klassische Chiffren

### Technik

Viele Crypto-CTF-Aufgaben bestehen aus mehreren Transformationen: Base-Encoding + einfache Substitution + Komprimierung. Ziel ist es, die einzelnen Schichten zu identifizieren und sicher abzutragen.

### Encodings: viele Basen ausprobieren

Wenn du verschachtelte Encodings vermutest (base64 → base32 → …), probiere Folgendes aus:

- CyberChef „Magic“
- `codext` (python-codext): `codext <string>`

Typische Hinweise:

- Base64: `A-Za-z0-9+/=` (Padding mit `=` ist üblich)
- Base32: `A-Z2-7=` (oft viel Padding mit `=`)
- Ascii85/Base85: viele Satzzeichen; manchmal von `<~ ~>` umschlossen

### Substitution / monoalphabetisch

- Boxentriq Cryptogram Solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Wiederherstellung anhand von bekanntem Klartext bei substituierten Base32-Dateinamen

Wenn ein verschleierter Dateiname nur `a-z2-7` verwendet, nach dem Entfernen eines festen Suffixes auf etwa `ceil(8 * byte_length / 5)` Zeichen erweitert wird und derselbe Klartext bei verschiedenen Dateien stets dieselbe Ausgabe erzeugt, solltest du **ungepaddetes Base32 gefolgt von einer festen Symbolsubstitution** testen. Diese Hinweise sind für sich genommen kein Beweis. Sammle vorhersagbare Dateinamen und ihre Chiffretexte, bewahre die Groß-/Kleinschreibung bei, kodiere jeden Klartext mit Base32 und richte die Symbole positionweise aus. Jedes wiederholte Klartextsymbol muss stets auf dasselbe Chiffretextszeichen abgebildet werden; auch die inverse Abbildung muss eindeutig sein. In einem Ransomware-Fall lieferten `ntuser.ini` und `NTUSER.DAT` solche Paare. Damit ließen sich Dateinamen wiederherstellen, **nicht aber Dateiinhalte oder Verschlüsselungsschlüssel**.<sup>[[28]](#references)</sup>

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

Wenn ein Ziel nicht zugeordnete Symbole enthält, beschaffe weitere bekannte Paare oder permutiere nur die Zuordnungen der ungenutzten Base32-Symbole. Ergänze das Padding bis zu einer Länge von acht Zeichen, verwerfe ungültiges Base32 und nicht druckbare dekodierte Namen. Kodiere anschließend die verbleibenden Kandidaten erneut und vergleiche den **gesamten** ursprünglichen Ciphertext. Wiederholte Ciphertext-Blöcke können zusätzliche Vermutungen ermöglichen: Im obigen Fall wurde `3gpng2wv` auf Base32 `gaydambq` zurückgeführt, das zu fünf ASCII-Nullen dekodiert wird. Ein druckbarer Kandidat allein ist kein eindeutiger Beweis.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayukis automatischer Caesar-Chiffre-Entschlüsseler.<sup>[[15]](#references)</sup>
- Rumkin-Atbash-Tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode-Vigenère-Tool.<sup>[[8]](#references)</sup>
- Guballa-Vigenère-Solver.<sup>[[17]](#references)</sup>

### Bacon-Chiffre

Erscheint oft als Gruppen aus 5 Bits oder 5 Buchstaben:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runen sind häufig Substitutionsalphabete; suche nach „futhark cipher“ und probiere Zuordnungstabellen aus.

## Komprimierung in Challenges

### Technik

Komprimierung taucht ständig als zusätzliche Ebene auf (zlib/deflate/gzip/xz/zstd), manchmal auch verschachtelt. Wenn sich die Ausgabe fast parsen lässt, aber wie Datenmüll aussieht, solltest du Komprimierung vermuten.

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

CyberChef bietet **Raw Deflate/Raw Inflate**, was oft der schnellste Weg ist, wenn der Blob komprimiert aussieht, aber `zlib` fehlschlägt.

### Nützliches CLI

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

## Gängige CTF-Krypto-Konstrukte

### Technik

Diese tauchen häufig auf, weil es sich um realistische Entwicklerfehler oder um häufig falsch verwendete Bibliotheken handelt. Meist geht es darum, sie zu erkennen und einen bekannten Extraktions- oder Rekonstruktionsablauf anzuwenden.

### Fernet

Typischer Hinweis: zwei Base64-Strings (Token + Key).

- Decoder/Notizen: Asecuritysite-Fernet-Decoder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Wenn du mehrere Shares siehst und ein Schwellenwert `t` erwähnt wird, handelt es sich wahrscheinlich um Shamir.

- Online-Rekonstruktionstool (nur für nicht sensible CTF-Shares).<sup>[[19]](#references)</sup>

### OpenSSL-Formate mit Salt

CTFs liefern manchmal `openssl enc`-Ausgaben (der Header beginnt häufig mit `Salted__`).

Bruteforce-Hilfsprogramme:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Allgemeines Toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Empfohlene lokale Einrichtung

Praktischer CTF-Stack:

- Python plus `pycryptodome` für symmetrische Primitive und schnelles Prototyping.<sup>[[25]](#references)</sup>
- SageMath für modulare Arithmetik, CRT, Gitter und RSA/ECC-Arbeiten.<sup>[[26]](#references)</sup>
- Z3 für Challenges auf Basis von Nebenbedingungen (wenn sich die Kryptografie auf Nebenbedingungen reduzieren lässt).<sup>[[27]](#references)</sup>

Empfohlene Python-Pakete:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org-Suche](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode-Tools](https://www.dcode.fr/tools-list)
- [9] [Boxentriq-Tools zum Knacken von Codes](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki – Automatischer Caesar-Chiffre-Knacker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin – Atbash-Chiffre](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa-Vigenère-Solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite – Fernet-Decoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Rekonstruktion von Shamir Secret Sharing](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome-Dokumentation](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Verschlüsselungsverfahren auf die einfache Art knacken](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
