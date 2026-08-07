# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Worauf bei CTFs zu achten ist

- **Mode misuse**: ECB-Muster, CBC-Malleability, CTR/GCM-Nonce-Reuse.
- **Padding Oracles**: unterschiedliche Fehler/Timings bei ungültigem Padding.
- **MAC confusion**: Verwendung von CBC-MAC mit Nachrichten variabler Länge oder Fehler beim MAC-then-encrypt.
- **XOR überall**: Stream ciphers und eigene Konstruktionen reduzieren sich häufig auf XOR mit einem Keystream.

## AES modes und Misuse

### ECB: Electronic Codebook

ECB leakt Muster: gleiche Plaintext-Blöcke → gleiche Ciphertext-Blöcke. Das ermöglicht:

- Cut-and-paste / Block-Reordering
- Block deletion (wenn das Format gültig bleibt)

Wenn du den Plaintext kontrollieren und den Ciphertext (oder Cookies) beobachten kannst, versuche wiederholte Blöcke zu erzeugen (z. B. viele `A`s) und suche nach Wiederholungen.

### CBC: Cipher Block Chaining

- CBC ist **malleable**: Das Umdrehen von Bits in `C[i-1]` dreht vorhersehbare Bits in `P[i]` um.
- Wenn das System gültiges Padding von ungültigem Padding unterscheidet, hast du möglicherweise ein **padding oracle**.

### CTR

CTR verwandelt AES in eine Stream cipher: `C = P XOR keystream`.

Wenn ein Nonce/IV mit demselben Key wiederverwendet wird:

- `C1 XOR C2 = P1 XOR P2` (klassische Keystream-Reuse)
- Bei bekanntem Plaintext kannst du den Keystream wiederherstellen und andere Daten entschlüsseln.

**Nonce/IV-Reuse-Exploitation-Patterns**

- Stelle den Keystream überall dort wieder her, wo der Plaintext bekannt oder erratbar ist:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Wende die wiederhergestellten Keystream-Bytes auf jeden anderen Ciphertext an, der mit demselben Key+IV an denselben Offsets erzeugt wurde.
- Stark strukturierte Daten (z. B. ASN.1/X.509-Zertifikate, Datei-Header, JSON/CBOR) liefern große Bereiche mit bekanntem Plaintext. Du kannst häufig den Ciphertext des Zertifikats mit dem vorhersehbaren Zertifikatsinhalt XORen, um den Keystream abzuleiten, und anschließend andere mit dem wiederverwendeten IV verschlüsselte Secrets entschlüsseln. Siehe auch [TLS & Certificates](../tls-and-certificates/README.md) für typische Zertifikatslayouts.<sup>[[1]](#references)</sup>
- Wenn mehrere Secrets mit demselben serialisierten Format und derselben Größe unter demselben Key+IV verschlüsselt werden, kann die Feldausrichtung auch ohne vollständig bekannten Plaintext leaken. Beispiel: PKCS#8-RSA-Keys derselben Modulusgröße platzieren Primfaktoren an übereinstimmenden Offsets (ca. 99,6 % Alignment bei 2048 Bit). Das XORen zweier Ciphertexts unter dem wiederverwendeten Keystream isoliert `p ⊕ p'` / `q ⊕ q'`, was innerhalb von Sekunden per Brute-Force wiederhergestellt werden kann.<sup>[[1]](#references)</sup>
- Standard-IVs in Libraries (z. B. konstante Werte wie `000...01`) sind ein kritischer Footgun: Jede Verschlüsselung wiederholt denselben Keystream und verwandelt CTR in ein wiederverwendetes One-Time Pad.<sup>[[1]](#references)</sup>

**CTR-Malleability**

- CTR bietet ausschließlich Confidentiality: Das Umdrehen von Bits im Ciphertext dreht deterministisch dieselben Bits im Plaintext um. Ohne Authentication Tag können Angreifer Daten unbemerkt manipulieren (z. B. Keys, Flags oder Nachrichten verändern).
- Verwende AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 usw.) und erzwinge die Tag-Verifikation, um Bit-Flips zu erkennen.

### GCM

Auch GCM bricht bei Nonce-Reuse gravierend. Wenn derselbe Key+Nonce mehr als einmal verwendet wird, erhältst du typischerweise:

- Keystream-Reuse für die Verschlüsselung (wie bei CTR), wodurch die Wiederherstellung des Plaintexts ermöglicht wird, sobald irgendein Plaintext bekannt ist.
- Verlust der Integrity-Garantien. Abhängig davon, was offengelegt wird (mehrere Nachrichten/Tag-Paare unter demselben Nonce), können Angreifer möglicherweise Tags fälschen.

Operative Hinweise:

- Behandle „Nonce-Reuse“ in AEAD als kritische Vulnerability.
- Misuse-resistant AEADs (z. B. GCM-SIV) reduzieren die Auswirkungen von Nonce-Misuse, erfordern aber weiterhin eindeutige Nonces/IVs.
- Wenn du mehrere Ciphertexts unter demselben Nonce hast, beginne mit der Prüfung von Relationen der Form `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef für schnelle Experimente: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` für Scripting

## ECB-Exploitation-Patterns

ECB (Electronic Code Book) verschlüsselt jeden Block unabhängig:

- gleiche Plaintext-Blöcke → gleiche Ciphertext-Blöcke
- dadurch wird Struktur geleakt und Cut-and-paste-artige Angriffe werden ermöglicht

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection-Idee: Token/Cookie-Pattern

Wenn du dich mehrmals anmeldest und **immer dasselbe Cookie erhältst**, ist der Ciphertext möglicherweise deterministisch (ECB oder fixer IV).

Wenn du zwei User mit weitgehend identischen Plaintext-Layouts erstellst (z. B. langen Folgen wiederholter Zeichen) und wiederholte Ciphertext-Blöcke an denselben Offsets siehst, ist ECB ein Hauptverdächtiger.

### Exploitation-Patterns

#### Ganze Blöcke entfernen

Wenn das Token-Format etwa `<username>|<password>` lautet und die Blockgrenze ausgerichtet ist, kannst du manchmal einen User so erzeugen, dass der `admin`-Block ausgerichtet erscheint, und anschließend vorangehende Blöcke entfernen, um ein gültiges Token für `admin` zu erhalten.

#### Blöcke verschieben

Wenn das Backend Padding/zusätzliche Leerzeichen toleriert (`admin` vs `admin    `), kannst du:

- Einen Block ausrichten, der `admin   ` enthält
- Diesen Ciphertext-Block in ein anderes Token verschieben/wiederverwenden

## Padding Oracle

### Was es ist

Wenn der Server im CBC-Mode direkt oder indirekt offenlegt, ob der entschlüsselte Plaintext **gültiges PKCS#7-Padding** besitzt, kannst du häufig:

- Ciphertext ohne den Key entschlüsseln
- Gewählten Plaintext verschlüsseln (Ciphertext fälschen)

Das Oracle kann sein:

- Eine bestimmte Fehlermeldung
- Ein anderer HTTP-Status / eine andere Response-Größe
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
Notizen:

- Die Blockgröße beträgt bei AES häufig `16`.
- `-encoding 0` bedeutet Base64.
- Verwende `-error`, wenn der oracle eine bestimmte Zeichenfolge zurückgibt.

### Warum es funktioniert

Die CBC-Entschlüsselung berechnet `P[i] = D(C[i]) XOR C[i-1]`. Indem du Bytes in `C[i-1]` modifizierst und beobachtest, ob das Padding gültig ist, kannst du `P[i]` Byte für Byte wiederherstellen.

## Bit-flipping in CBC

Auch ohne einen padding oracle ist CBC malleable. Wenn du Ciphertext-Blöcke modifizieren kannst und die Anwendung den entschlüsselten Plaintext als strukturierte Daten verwendet (z. B. `role=user`), kannst du bestimmte Bits umdrehen, um ausgewählte Plaintext-Bytes an einer gewünschten Position im nächsten Block zu ändern.

Typisches CTF-Muster:

- Token = `IV || C1 || C2 || ...`
- Du kontrollierst Bytes in `C[i]`
- Du zielst auf Plaintext-Bytes in `P[i+1]`, weil `P[i+1] = D(C[i+1]) XOR C[i]`

Dies ist allein kein Bruch der Vertraulichkeit, aber ein häufig verwendbares Privilege-Escalation-Primitiv, wenn die Integrität fehlt.

## CBC-MAC

CBC-MAC ist nur unter bestimmten Bedingungen sicher (insbesondere bei **Nachrichten mit fester Länge** und korrekter Domain Separation).

### Klassisches Forgery-Muster bei variabler Länge

CBC-MAC wird üblicherweise wie folgt berechnet:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Wenn du Tags für ausgewählte Nachrichten erhalten kannst, kannst du häufig einen Tag für eine Konkatenation (oder eine verwandte Konstruktion) erstellen, ohne den Schlüssel zu kennen, indem du ausnutzt, wie CBC Blöcke verkettet.

Dies tritt häufig bei CTF-Cookies/Tokens auf, die Benutzernamen oder Rollen mit CBC-MAC authentisieren.

### Sicherere Alternativen

- Verwende HMAC (SHA-256/512)
- Verwende CMAC (AES-CMAC) korrekt
- Füge die Nachrichtenlänge / Domain Separation ein

## Stream ciphers: XOR und RC4

### Das mentale Modell

Die meisten Situationen mit Stream ciphers lassen sich reduzieren auf:

`ciphertext = plaintext XOR keystream`

Daher gilt:

- Wenn du den Plaintext kennst, kannst du den keystream wiederherstellen.
- Wenn der keystream wiederverwendet wird (derselbe Schlüssel+Nonce), gilt `C1 XOR C2 = P1 XOR P2`.

### XOR-basierte Verschlüsselung

Wenn du ein beliebiges Plaintext-Segment an Position `i` kennst, kannst du die keystream-Bytes wiederherstellen und andere Ciphertexts an diesen Positionen entschlüsseln.

Auto-Solver:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 ist eine Stream cipher; Ver- und Entschlüsselung sind dieselbe Operation.

Wenn du die RC4-Verschlüsselung eines bekannten Plaintexts mit demselben Schlüssel erhalten kannst, kannst du den keystream wiederherstellen und andere Nachrichten mit derselben Länge/Position entschlüsseln.

Referenz-Walkthrough (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Referenzen

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
