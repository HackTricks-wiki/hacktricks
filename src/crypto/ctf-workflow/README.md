# Crypto-CTF-Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage-Checkliste

1. Identifiziere, womit du es zu tun hast: Encoding, Verschlüsselung, Hash, Signatur oder MAC.
2. Bestimme, was kontrolliert wird: Klartext/Chiffretext, IV/Nonce, Schlüssel, Oracle (Padding/Fehler/Timing), partieller Leak.
3. Ordne es ein: symmetrisch (AES/CTR/GCM), Public-Key (RSA/ECC), Hash/MAC (SHA/MD5/HMAC), klassisch (Vigenere/XOR).
4. Wende zuerst die Prüfungen mit der höchsten Erfolgswahrscheinlichkeit an: Decoding-Ebenen, Known-plaintext-XOR, Nonce-Wiederverwendung, falsche Modusverwendung, Oracle-Verhalten.
5. Greife nur bei Bedarf auf fortgeschrittene Methoden zurück: Gitter (LLL/Coppersmith), SMT/Z3, Side-Channels.

## Online-Ressourcen & Tools

Diese sind nützlich, wenn es darum geht, eine Aufgabe zu identifizieren und Ebenen abzutragen, oder wenn du eine Hypothese schnell bestätigen möchtest.

### Hash-Suchen

- Suche nach einem Challenge-Hash, wenn bekannt ist, dass er synthetisch/öffentlich ist.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Suche auf hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Übermittle keine echten Passwort-Hashes oder vertraulichen Challenge-Daten an Suchdienste von Drittanbietern. Wenn Offenlegung, Nutzungsbedingungen oder Wettbewerbsregeln bedenklich sind, bevorzuge einen Offline-Angriff mit Wortliste und Regeln.

### Tools zur Identifizierung

- CyberChef (Magic, Decoding und Konvertierung).<sup>[[7]](#references)</sup>
- dCode (Spielwiese für Chiffren und Encodings).<sup>[[8]](#references)</sup>
- Boxentriq (Löser für Substitutionschiffren).<sup>[[9]](#references)</sup>

### Übungsplattformen / Referenzen

- CryptoHack (praktische Kryptografie-Challenges).<sup>[[10]](#references)</sup>
- Cryptopals (klassische Fallstricke moderner Kryptografie).<sup>[[11]](#references)</sup>

### Automatisiertes Decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (probiert viele Basen/Encodings aus).<sup>[[13]](#references)</sup>

Informationen zu Quellcode in esoterischen Sprachen und benutzerdefiniertem Interpreter-Zustand findest du unter [Crypto CTF Misc](../ctf-misc/).

## Encodings & klassische Chiffren

### Technik

Viele Crypto-CTF-Aufgaben bestehen aus mehreren Transformationen: Base-Encoding + einfache Substitution + Komprimierung. Ziel ist es, die Ebenen zu identifizieren und sicher abzutragen.

### Encodings: Probiere viele Basen aus

Wenn du ein mehrschichtiges Encoding vermutest (base64 → base32 → …), probiere Folgendes:

- CyberChef „Magic“
- `codext` (python-codext): `codext <string>`

Typische Hinweise:

- Base64: `A-Za-z0-9+/=` (Padding mit `=` kommt häufig vor)
- Base32: `A-Z2-7=` (oft mit viel Padding durch `=`)
- Ascii85/Base85: dichte Folge von Satzzeichen; manchmal von `<~ ~>` umschlossen

### Substitution / monoalphabetisch

- Boxentriq-Löser für Kryptogramme.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Known-plaintext-Recovery von Base32-Dateinamen mit Substitution

Wenn ein verschleierter Dateiname nur `a-z2-7` verwendet, nach dem Entfernen eines festen Suffixes ungefähr auf `ceil(8 * byte_length / 5)` Zeichen erweitert wird und derselbe Klartext in verschiedenen Dateien stets dieselbe Ausgabe erzeugt, solltest du **ungepaddetes Base32 gefolgt von einer festen Symbolsubstitution** testen. Diese Hinweise sind allein kein Beweis. Sammle vorhersagbare Dateinamen und ihre Chiffretexte, behalte die Groß-/Kleinschreibung bei, kodiere jeden Klartext mit Base32 und richte die Symbole positionsweise aus. Jedes wiederholte Klartextsymbol muss stets demselben Chiffresymbol zugeordnet sein; auch die umgekehrte Zuordnung muss eindeutig sein. In einem Ransomware-Fall lieferten `ntuser.ini` und `NTUSER.DAT` solche Paare; dadurch ließen sich Dateinamen wiederherstellen, **nicht aber Datei-Inhalte oder Verschlüsselungsschlüssel**.<sup>[[28]](#references)</sup>

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

Wenn ein Ziel nicht zugeordnete Symbole enthält, beschaffe weitere bekannte Paare oder permutiere nur die noch nicht verwendeten Base32-Symbolzuordnungen. Stelle das Padding wieder auf eine Länge ein, die durch acht teilbar ist, verwerfe ungültiges Base32 und dekodierte Namen mit nicht druckbaren Zeichen und kodiere anschließend die verbleibenden Kandidaten erneut, um den **gesamten** ursprünglichen Ciphertext zu vergleichen. Wiederholte Ciphertext-Blöcke können zusätzliche Vermutungen ermöglichen: Im obigen Fall wurde `3gpng2wv` auf Base32 `gaydambq` zurückgeführt, was fünf ASCII-Nullen ergibt. Ein druckbarer Kandidat allein ist kein eindeutiger Beweis.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

Erscheint oft als Gruppen aus 5 Bits oder 5 Buchstaben:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runen

Runen sind häufig Substitutionsalphabete; suche nach „futhark cipher“ und probiere Zuordnungstabellen aus.

## Kompression in Challenges

### Technik

Kompression kommt ständig als zusätzliche Ebene vor (zlib/deflate/gzip/xz/zstd), manchmal auch verschachtelt. Wenn die Ausgabe fast geparst werden kann, aber wie Kauderwelsch aussieht, vermute Kompression.

### Schnelle Erkennung

- `file <blob>`
- Achte auf Magic Bytes:
  - gzip: `1f 8b`
  - zlib: häufig `78 01`, `78 5e`, `78 9c` oder `78 da` (das zweite Byte hängt von den Kompressionsflags ab)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef bietet **Raw Deflate/Raw Inflate**, was oft der schnellste Weg ist, wenn der Blob komprimiert aussieht, aber `zlib` fehlschlägt.

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

## Gängige CTF-Krypto-Konstrukte

### Technik

Diese treten häufig auf, da es sich um realistische Entwicklerfehler oder häufig falsch verwendete Bibliotheken handelt. Meist geht es darum, sie zu erkennen und einen bekannten Extraktions- oder Rekonstruktionsablauf anzuwenden.

### Fernet

Typischer Hinweis: zwei Base64-Strings (Token + Key).

- Decoder/Notizen: Asecuritysite-Fernet-Decoder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Wenn mehrere Shares vorliegen und ein Schwellenwert `t` genannt wird, handelt es sich wahrscheinlich um Shamir.

- Online-Rekonstruktionstool (nur für nicht sensible CTF-Shares).<sup>[[19]](#references)</sup>

### OpenSSL-Salt-Formate

Bei CTFs werden manchmal `openssl enc`-Ausgaben bereitgestellt (der Header beginnt häufig mit `Salted__`).

Bruteforce-Hilfswerkzeuge:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Allgemeines Toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Empfohlene lokale Einrichtung

Praktischer CTF-Stack:

- Python plus `pycryptodome` für symmetrische Primitiven und schnelles Prototyping.<sup>[[25]](#references)</sup>
- SageMath für modulare Arithmetik, CRT, Gitter und RSA/ECC-Aufgaben.<sup>[[26]](#references)</sup>
- Z3 für Aufgaben mit Nebenbedingungen (wenn sich die Krypto auf Nebenbedingungen reduzieren lässt).<sup>[[27]](#references)</sup>

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
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode-Tools](https://www.dcode.fr/tools-list)
- [9] [Boxentriq-Codeknacker-Tools](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki – Automatischer Caesar-Chiffre-Knacker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin – Atbash-Chiffre](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa-Vigenère-Löser](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite – Fernet-Decoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir-Secret-Sharing-Rekonstruktion](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome-Dokumentation](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Verschlüsselungsverfahren auf die faule Art brechen](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}
