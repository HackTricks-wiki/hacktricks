# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Worauf man in CTFs achten sollte

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: verschiedene Fehler/Timings bei bad padding.
- **MAC confusion**: Verwendung von CBC-MAC mit Nachrichten variabler Länge oder MAC-then-encrypt-Fehler.
- **XOR everywhere**: Stream ciphers und benutzerdefinierte Konstruktionen laufen oft auf XOR mit einem keystream hinaus.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Das ermöglicht:

- Cut-and-paste / block reordering
- Block deletion (wenn das Format gültig bleibt)

Wenn du Plaintext kontrollieren und Ciphertext (oder Cookies) beobachten kannst, versuche, wiederholte Blöcke zu erzeugen (z. B. viele `A`s) und suche nach Wiederholungen.

### CBC: Cipher Block Chaining

- CBC ist **malleable**: Das Flippen von Bits in `C[i-1]` flippt vorhersehbare Bits in `P[i]`.
- Wenn das System gültiges Padding vs ungültiges Padding offenlegt, könntest du eine **padding oracle** haben.

### CTR

CTR verwandelt AES in einen Stream cipher: `C = P XOR keystream`.

Wenn ein nonce/IV mit demselben Key wiederverwendet wird:

- `C1 XOR C2 = P1 XOR P2` (klassische Keystream-Wiederverwendung)
- Mit bekanntem Plaintext kannst du den keystream rekonstruieren und andere Nachrichten entschlüsseln.

### GCM

GCM bricht ebenfalls schlimm bei nonce reuse zusammen. Wenn derselbe key+nonce mehr als einmal verwendet wird, erhält man typischerweise:

- Keystream-Wiederverwendung für Verschlüsselung (wie CTR), was die Wiederherstellung von Plaintext ermöglicht, wenn irgendein Plaintext bekannt ist.
- Verlust der Integritätsgarantien. Abhängig davon, was offengelegt wird (mehrere message/tag-Paare unter demselben Nonce), könnten Angreifer Tags fälschen.

Betriebliche Hinweise:

- Behandle "nonce reuse" in AEAD als kritische Schwachstelle.
- Wenn du mehrere Ciphertexts unter demselben Nonce hast, prüfe zuerst auf `C1 XOR C2 = P1 XOR P2`-Art Relationen.

### Tools

- CyberChef für schnelle Experimente: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` zum Scripting

## ECB exploitation patterns

ECB (Electronic Code Book) verschlüsselt jeden Block unabhängig:

- equal plaintext blocks → equal ciphertext blocks
- das leakt Struktur und ermöglicht Cut-and-paste-Style-Attacken

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Wenn du dich mehrmals einloggst und **immer denselben cookie bekommst**, kann der Ciphertext deterministisch sein (ECB oder fester IV).

Wenn du zwei users mit überwiegend identischen Plaintext-Layouts erzeugst (z. B. lange, wiederholte Zeichen) und wiederholte Ciphertext-Blöcke an denselben Offsets siehst, ist ECB ein Hauptverdächtiger.

### Exploitation patterns

#### Removing entire blocks

Wenn das Token-Format so aussieht: `<username>|<password>` und die Blockgrenze passt, kannst du manchmal einen User so craften, dass der `admin`-Block ausgerichtet ist und dann vorangehende Blöcke entfernen, um ein gültiges Token für `admin` zu erhalten.

#### Moving blocks

Wenn das Backend Padding/extra Spaces toleriert (`admin` vs `admin    `), kannst du:

- Einen Block ausrichten, der `admin   ` enthält
- Diesen Ciphertext-Block in ein anderes Token tauschen/wiederverwenden

## Padding Oracle

### Was es ist

In CBC mode, wenn der Server (direkt oder indirekt) offenbart, ob der entschlüsselte Plaintext **valid PKCS#7 padding** hat, kannst du oft:

- Ciphertext ohne Key decrypten
- Gewählten Plaintext verschlüsseln (Ciphertext forge)

Das Oracle kann sein:

- Eine spezifische Fehlermeldung
- Ein anderer HTTP-Status / andere response size
- Ein Timing-Unterschied

### Praktische Ausnutzung

PadBuster ist das klassische Tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Beispiel:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Warum es funktioniert

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Indem man Bytes in `C[i-1]` verändert und beobachtet, ob das padding gültig ist, kann man `P[i]` Byte für Byte wiederherstellen.

## Bit-flipping in CBC

Even without a padding oracle, CBC is malleable. If you can modify ciphertext blocks and the application uses the decrypted plaintext as structured data (e.g., `role=user`), you can flip specific bits to change selected plaintext bytes at a chosen position in the next block.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

This is not a break of confidentiality by itself, but it is a common privilege-escalation primitive when integrity is missing.

## CBC-MAC

CBC-MAC is secure only under specific conditions (notably **fixed-length messages** and correct domain separation).

### Classic variable-length forgery pattern

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

If you can obtain tags for chosen messages, you can often craft a tag for a concatenation (or related construction) without knowing the key, by exploiting how CBC chains blocks.

This frequently appears in CTF cookies/tokens that MAC username or role with CBC-MAC.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### The mental model

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

So:

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

{{#include ../../banners/hacktricks-training.md}}
