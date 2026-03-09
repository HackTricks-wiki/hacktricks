# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Worauf man in CTFs achten sollte

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: unterschiedliche Fehler/Timings bei fehlerhafter Padding.
- **MAC confusion**: Verwendung von CBC-MAC mit variablen Nachrichtenlängen oder MAC-then-encrypt-Fehler.
- **XOR everywhere**: Stream-Ciphers und kundenspezifische Konstruktionen reduzieren sich oft auf XOR mit einem Keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks Muster: gleiche Plaintext-Blöcke → gleiche Ciphertext-Blöcke. Das ermöglicht:

- Cut-and-paste / Block-Reordering
- Block-Deletion (wenn das Format weiterhin gültig bleibt)

Wenn du Plaintext kontrollieren und Ciphertext (oder Cookies) beobachten kannst, versuche wiederholte Blöcke zu erzeugen (z. B. viele `A`s) und suche nach Wiederholungen.

### CBC: Cipher Block Chaining

- CBC ist **malleable**: Bit-Flips in `C[i-1]` führen zu vorhersagbaren Bit-Flips in `P[i]`.
- Wenn das System gültiges Padding vs. ungültiges Padding offenlegt, hast du möglicherweise ein **Padding Oracle**.

### CTR

CTR verwandelt AES in einen Stream-Cipher: `C = P XOR keystream`.

Wenn ein Nonce/IV mit demselben Schlüssel wiederverwendet wird:

- `C1 XOR C2 = P1 XOR P2` (klassische Keystream-Wiederverwendung)
- Mit bekanntem Plaintext kannst du den Keystream wiederherstellen und andere Ciphertexte entschlüsseln.

**Nonce/IV reuse exploitation patterns**

- Stelle den Keystream dort wieder her, wo Plaintext bekannt/ratbar ist:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Wende die wiederhergestellten Keystream-Bytes an, um beliebige andere Ciphertexte zu entschlüsseln, die mit demselben key+IV an denselben Offsets erzeugt wurden.
- Hochstrukturierte Daten (z. B. ASN.1/X.509-Zertifikate, File-Header, JSON/CBOR) liefern große known-plaintext-Bereiche. Du kannst oft den Ciphertext des Zertifikats mit dem vorhersehbaren Zertifikatskörper xor-en, um den Keystream zu gewinnen und dann andere unter dem wiederverwendeten IV verschlüsselte Geheimnisse zu entschlüsseln. Siehe auch [TLS & Certificates](../tls-and-certificates/README.md) für typische Zertifikats-Layouts.
- Wenn mehrere Geheimnisse desselben serialisierten Formats/Größe unter demselben key+IV verschlüsselt werden, leak Field-Alignment selbst ohne vollständigen Known-Plaintext. Beispiel: PKCS#8 RSA-Keys gleicher Modulus-Größe platzieren Primfaktoren an übereinstimmenden Offsets (~99.6% Alignment für 2048-bit). Das XORen zweier Ciphertexte unter demselbem Keystream isoliert `p ⊕ p'` / `q ⊕ q'`, die in Sekunden per Brute-Force wiederhergestellt werden können.
- Default-IVs in Libraries (z. B. konstantes `000...01`) sind ein kritisches Fußangeln: Jede Encryption wiederholt denselben Keystream und verwandelt CTR in ein wiederverwendetes One-Time-Pad.

**CTR malleability**

- CTR bietet nur Vertraulichkeit: Bit-Flips im Ciphertext führen deterministisch zu gleichen Bit-Flips im Plaintext. Ohne einen Authentifizierungstag können Angreifer Daten (z. B. Schlüssel, Flags oder Nachrichten) unbemerkt manipulieren.
- Verwende AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) und setze Tag-Verifikation durch, um Bit-Flips zu erkennen.

### GCM

GCM bricht ebenfalls bei Nonce-Wiederverwendung stark zusammen. Wenn derselbe key+nonce mehr als einmal verwendet wird, erhält man typischerweise:

- Keystream-Wiederverwendung für Encryption (wie CTR), was die Wiederherstellung von Plaintext ermöglicht, wenn irgendein Plaintext bekannt ist.
- Verlust der Integritätsgarantien. Abhängig davon, was offengelegt wird (mehrere Message/Tag-Paare unter derselben Nonce), können Angreifer möglicherweise Tags fälschen.

Operative Hinweise:

- Betrachte "nonce reuse" in AEAD als kritische Verwundbarkeit.
- Missuse-resistant AEADs (z. B. GCM-SIV) reduzieren die Folgen von Nonce-Misuse, erfordern aber trotzdem einzigartige Nonces/IVs.
- Wenn du mehrere Ciphertexte unter derselben Nonce hast, beginne damit, `C1 XOR C2 = P1 XOR P2`-artige Relationen zu prüfen.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) verschlüsselt jeden Block unabhängig:

- gleiche Plaintext-Blöcke → gleiche Ciphertext-Blöcke
- das leak Struktur und ermöglicht Cut-and-paste-Style-Angriffe

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Wenn du dich mehrmals einloggst und **immer denselben Cookie bekommst**, könnte der Ciphertext deterministisch sein (ECB oder fester IV).

Wenn du zwei Nutzer erstellst mit größtenteils identischen Plaintext-Layouts (z. B. lange wiederholte Zeichen) und an denselben Offsets wiederholte Ciphertext-Blöcke siehst, ist ECB ein starker Verdacht.

### Exploitation patterns

#### Removing entire blocks

Wenn das Token-Format so aussieht wie `<username>|<password>` und die Block-Grenze passt, kannst du manchmal einen Nutzer so erstellen, dass der `admin`-Block ausgerichtet erscheint und dann die davorliegenden Blöcke entfernen, um ein gültiges Token für `admin` zu erhalten.

#### Moving blocks

Wenn das Backend Padding/Extra-Spaces toleriert (`admin` vs `admin    `), kannst du:

- Einen Block so ausrichten, dass er `admin   ` enthält
- Diesen Ciphertext-Block in ein anderes Token austauschen/wiederverwenden

## Padding Oracle

### What it is

In CBC-Modus, wenn der Server (direkt oder indirekt) offenbart, ob der entschlüsselte Plaintext **gültiges PKCS#7-Padding** hat, kannst du häufig:

- Ciphertext ohne Schlüssel entschlüsseln
- Gewählten Plaintext verschlüsseln (Ciphertext fälschen)

Das Oracle kann sein:

- Eine spezifische Fehlermeldung
- Ein anderer HTTP-Status / unterschiedliche Response-Größe
- Ein Timing-Unterschied

### Practical exploitation

PadBuster ist das klassische Tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Hinweise:

- Blockgröße ist oft `16` bei AES.
- `-encoding 0` bedeutet Base64.
- Verwende `-error`, wenn das oracle ein bestimmter String ist.

### Warum es funktioniert

CBC-Entschlüsselung berechnet `P[i] = D(C[i]) XOR C[i-1]`. Durch Modifizieren von Bytes in `C[i-1]` und Beobachten, ob das Padding gültig ist, kannst du `P[i]` Byte für Byte wiederherstellen.

## Bit-flipping in CBC

Selbst ohne padding oracle ist CBC manipulierbar. Wenn du ciphertext-Blöcke modifizieren kannst und die Anwendung den entschlüsselten plaintext als strukturierte Daten verwendet (z. B. `role=user`), kannst du bestimmte Bits flippen, um ausgewählte plaintext-Bytes an einer gewählten Position im nächsten Block zu ändern.

Typisches CTF-Muster:

- Token = `IV || C1 || C2 || ...`
- Du kontrollierst Bytes in `C[i]`
- Du zielst auf plaintext-Bytes in `P[i+1]`, weil `P[i+1] = D(C[i+1]) XOR C[i]`

Das ist für sich genommen kein Bruch der Vertraulichkeit, aber es ist ein häufiges privilege-escalation primitive, wenn Integrität fehlt.

## CBC-MAC

CBC-MAC ist nur unter bestimmten Bedingungen sicher (insbesondere **fixed-length messages** und korrekte domain separation).

### Klassisches variable-length forgery-Muster

CBC-MAC wird üblicherweise berechnet als:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Wenn du Tags für ausgewählte Nachrichten erhalten kannst, kannst du oft einen Tag für eine Verkettung (oder verwandte Konstruktion) ohne Kenntnis des Schlüssels erstellen, indem du ausnutzt, wie CBC Blöcke verknüpft.

Das tritt häufig in CTF-Cookies/Token auf, die username oder role mit CBC-MAC MACen.

### Sicherere Alternativen

- Verwende HMAC (SHA-256/512)
- Verwende CMAC (AES-CMAC) korrekt
- Füge message length / domain separation hinzu

## Stream ciphers: XOR and RC4

### Mentales Modell

Die meisten Situationen mit stream ciphers lassen sich auf Folgendes reduzieren:

`ciphertext = plaintext XOR keystream`

Also:

- Wenn du plaintext kennst, rekonstruierst du den keystream.
- Wenn der keystream wiederverwendet wird (gleicher key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-basierte Verschlüsselung

Wenn du ein beliebiges plaintext-Segment an Position `i` kennst, kannst du keystream-Bytes wiederherstellen und andere ciphertexts an diesen Positionen entschlüsseln.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 ist ein stream cipher; encrypt/decrypt sind dieselbe Operation.

Wenn du RC4-Encryptions von bekanntem Plaintext unter demselben Key bekommst, kannst du den keystream rekonstruieren und andere Nachrichten derselben Länge/Offset entschlüsseln.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
