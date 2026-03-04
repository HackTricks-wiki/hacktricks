# Symmetrische Kryptographie

{{#include ../../banners/hacktricks-training.md}}

## Woran man in CTFs achten sollte

- **Missbrauch von Modi**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: unterschiedliche Fehler/Timings bei fehlerhaftem Padding.
- **MAC confusion**: Verwendung von CBC-MAC mit variablen Nachrichtenlängen oder MAC-then-encrypt-Fehler.
- **XOR überall**: Stream-Ciphers und benutzerdefinierte Konstruktionen reduzieren sich oft auf XOR mit einem Keystream.

## AES-Modi und Missbrauch

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Das ermöglicht:

- Cut-and-paste / block reordering
- Block deletion (wenn das Format weiterhin gültig bleibt)

Wenn du Plaintext kontrollieren und Ciphertext beobachten kannst (oder cookies), versuche wiederholte Blöcke zu erzeugen (z. B. viele `A`s) und suche nach Wiederholungen.

### CBC: Cipher Block Chaining

- CBC ist manipuliertbar: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Wenn das System gültiges Padding gegenüber ungültigem Padding unterscheidet, kann ein **padding oracle** vorliegen.

### CTR

CTR verwandelt AES in einen Stream Cipher: `C = P XOR keystream`.

Wenn ein nonce/IV mit demselben Schlüssel wiederverwendet wird:

- `C1 XOR C2 = P1 XOR P2` (klassische Keystream-Wiederverwendung)
- Mit known plaintext kannst du den Keystream rekonstruieren und andere decrypten.

**Nonce/IV reuse exploitation patterns**

- Recover keystream wherever plaintext is known/guessable:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Wende die rekonstruierten Keystream-Bytes an, um beliebige andere Ciphertexts zu decrypten, die mit demselben key+IV an den gleichen Offsets erzeugt wurden.
- Hochstrukturierte Daten (z. B. ASN.1/X.509 certificates, file headers, JSON/CBOR) liefern große known-plaintext-Regionen. Du kannst oft den Ciphertext des Zertifikats mit dem vorhersehbaren Zertifikatskörper XORen, um den Keystream abzuleiten und dann andere unter dem wiederverwendeten IV verschlüsselte Secrets zu decrypten. See also [TLS & Certificates](../tls-and-certificates/README.md) für typische Zertifikatslayouts.
- Wenn mehrere Secrets im selben serialisierten Format/Größe unter demselben key+IV verschlüsselt werden, leakt die Feldausrichtung auch ohne vollständigen known plaintext. Beispiel: PKCS#8 RSA keys derselben Modulus-Größe platzieren Primfaktoren an übereinstimmenden Offsets (~99.6% Alignment für 2048-bit). XORen von zwei Ciphertexts unter dem wiederverwendeten Keystream isoliert `p ⊕ p'` / `q ⊕ q'`, die in Sekunden brute-recoverbar sind.
- Default-IVs in Bibliotheken (z. B. konstantes `000...01`) sind eine kritische Fußangel: jede Verschlüsselung wiederholt denselben Keystream und verwandelt CTR in ein wiederverwendetes One-Time-Pad.

**CTR-Malleabilität**

- CTR bietet nur Vertraulichkeit: flipping bits in Ciphertext führt deterministisch zu den gleichen Bit-Änderungen im Plaintext. Ohne einen Authentifizierungs-Tag können Angreifer Daten (z. B. Keys, Flags oder Nachrichten) unentdeckt manipulieren.
- Verwende AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) und erzwinge Tag-Verifikation, um Bit-Flips zu erkennen.

### GCM

GCM bricht ebenfalls stark bei Nonce-Wiederverwendung. Wenn derselbe key+nonce mehr als einmal benutzt wird, erhält man typischerweise:

- Keystream-Wiederverwendung für die Verschlüsselung (wie bei CTR), was bei bekanntem Plaintext zur Plaintext-Rekonstruktion führt.
- Verlust der Integritätsgarantien. Je nachdem, was exponiert ist (mehrere message/tag-Paare unter derselben Nonce), können Angreifer möglicherweise Tags forgieren.

Betriebliche Hinweise:

- Behandle "nonce reuse" in AEAD als kritische Verwundbarkeit.
- Missbrauchsresistente AEADs (z. B. GCM-SIV) reduzieren die Folgen von Nonce-Missbrauch, erfordern aber dennoch eindeutige Nonces/IVs.
- Wenn du mehrere Ciphertexts unter derselben Nonce hast, starte mit der Prüfung von `C1 XOR C2 = P1 XOR P2`-artigen Relationen.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB-Exploitation-Patterns

ECB (Electronic Code Book) verschlüsselt jeden Block unabhängig:

- equal plaintext blocks → equal ciphertext blocks
- dies leakt Struktur und ermöglicht Cut-and-Paste-Angriffe

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Erkennungs-Idee: token/cookie pattern

Wenn du dich mehrmals einloggst und **immer denselben cookie** erhältst, kann der Ciphertext deterministisch sein (ECB oder fester IV).

Wenn du zwei Benutzer mit weitgehend identischen Plaintext-Layouts erstellst (z. B. lange wiederholte Zeichen) und an den gleichen Offsets wiederholte Ciphertext-Blöcke siehst, ist ECB sehr wahrscheinlich.

### Exploitation-Patterns

#### Removing entire blocks

Wenn das Token-Format etwa `<username>|<password>` ist und die Blockgrenze passt, kannst du manchmal einen Benutzer so gestalten, dass der `admin`-Block korrekt ausgerichtet ist, und dann die vorangehenden Blöcke entfernen, um ein gültiges Token für `admin` zu erhalten.

#### Moving blocks

Wenn das Backend Padding/Extra-Spaces (`admin` vs `admin    `) toleriert, kannst du:

- Einen Block ausrichten, der `admin   ` enthält
- Diesen Ciphertext-Block in ein anderes Token tauschen/wiederverwenden

## Padding Oracle

### Was es ist

Im CBC-Modus, wenn der Server (direkt oder indirekt) offenbart, ob der entschlüsselte Plaintext gültiges PKCS#7 padding hat, kannst du oft:

- Ciphertext ohne den Key decrypten
- Gewählten Plaintext encrypten (Ciphertext forgery)

Das Oracle kann sein:

- Eine spezifische Fehlermeldung
- Ein anderer HTTP-Status / andere Response-Größe
- Ein Timing-Unterschied

### Praktische Exploitation

PadBuster ist das klassische Tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Beispiel:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Hinweise:

- Blockgröße ist oft `16` für AES.
- `-encoding 0` bedeutet Base64.
- Verwende `-error`, wenn das oracle ein bestimmter String ist.

### Warum es funktioniert

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Durch Modifizieren von Bytes in `C[i-1]` und Beobachten, ob das Padding gültig ist, kannst du `P[i]` Byte für Byte wiederherstellen.

## Bit-flipping in CBC

Selbst ohne ein padding oracle ist CBC manipulierbar. Wenn du ciphertext-Blöcke modifizieren kannst und die Anwendung den entschlüsselten plaintext als strukturierte Daten verwendet (z.B. `role=user`), kannst du gezielt Bits umdrehen, um ausgewählte plaintext-Bytes an einer gewählten Position im nächsten Block zu verändern.

Typisches CTF-Muster:

- Token = `IV || C1 || C2 || ...`
- Du kontrollierst Bytes in `C[i]`
- Du zielst auf plaintext-Bytes in `P[i+1]`, weil `P[i+1] = D(C[i+1]) XOR C[i]`

Das ist für sich genommen kein Bruch der Vertraulichkeit, aber es ist eine gängige Eskalationsprimitive zur Privilegienerlangung, wenn Integrität fehlt.

## CBC-MAC

CBC-MAC ist nur unter bestimmten Bedingungen sicher (insbesondere **Nachrichten fester Länge** und korrekte Domain-Trennung).

### Klassisches Fälschungsmuster bei variablen Längen

CBC-MAC wird üblicherweise berechnet als:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Wenn du Tags für ausgewählte Nachrichten erhalten kannst, kannst du oft einen Tag für eine Verkettung (oder verwandte Konstruktion) erstellen, ohne den Schlüssel zu kennen, indem du ausnutzt, wie CBC die Blöcke verknüpft.

Das erscheint häufig in CTF-Cookies/Token, die Benutzername oder Rolle mit CBC-MAC absichern.

### Sicherere Alternativen

- Verwende HMAC (SHA-256/512)
- Verwende CMAC (AES-CMAC) korrekt
- Füge Nachrichtenlänge / Domain-Trennung hinzu

## Stream ciphers: XOR and RC4

### The mental model

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

Also:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

If you know any plaintext segment at position `i`, you can recover keystream bytes and decrypt other ciphertexts at those positions.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 is a stream cipher; encrypt/decrypt are the same operation.

If you can get RC4 encryption of known plaintext under the same key, you can recover the keystream and decrypt other messages of the same length/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
