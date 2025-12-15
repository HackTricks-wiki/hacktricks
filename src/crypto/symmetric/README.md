# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Worauf man in CTFs achten sollte

- **Missbrauch von Modi**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: unterschiedliche Fehler/Messzeiten bei fehlerhaftem Padding.
- **MAC confusion**: Verwendung von CBC-MAC mit Nachrichten variabler Länge oder Fehler bei MAC-then-encrypt.
- **XOR everywhere**: Stream-Ciphers und benutzerdefinierte Konstruktionen reduzieren sich oft auf XOR mit einem keystream.

## AES-Modi und Missbrauch

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Das ermöglicht:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

Wenn du plaintext kontrollieren und ciphertext (oder Cookies) beobachten kannst, versuche wiederholte Blöcke zu erzeugen (z.B. viele `A`s) und nach Wiederholungen zu suchen.

### CBC: Cipher Block Chaining

- CBC ist **malleable**: Das Flippen von Bits in `C[i-1]` ändert vorhersehbar Bits in `P[i]`.
- Wenn das System gültiges vs. ungültiges Padding unterscheidet, könntest du eine **padding oracle** haben.

### CTR

CTR verwandelt AES in einen Stream-Cipher: `C = P XOR keystream`.

Wenn ein nonce/IV mit demselben key wiederverwendet wird:

- `C1 XOR C2 = P1 XOR P2` (klassische keystream-Wiederverwendung)
- Mit bekanntem plaintext kannst du den keystream wiederherstellen und andere entschlüsseln.

### GCM

GCM bricht ebenfalls bei nonce reuse stark zusammen. Wenn derselbe key+nonce mehr als einmal verwendet wird, erhält man typischerweise:

- Keystream reuse für die Verschlüsselung (wie CTR), was die Wiederherstellung von plaintext ermöglicht, wenn irgendein plaintext bekannt ist.
- Verlust der Integritätsgarantien. Abhängig davon, was exponiert wird (mehrere message/tag-Paare unter derselben nonce), könnten Angreifer Tags fälschen.

Betriebliche Anleitung:

- Behandle "nonce reuse" in AEAD als kritische Schwachstelle.
- Wenn du mehrere ciphertexts unter derselben nonce hast, prüfe zunächst `C1 XOR C2 = P1 XOR P2`-artige Relationen.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB-Ausnutzungsmuster

ECB (Electronic Code Book) verschlüsselt jeden Block unabhängig:

- equal plaintext blocks → equal ciphertext blocks
- das leaks Struktur und ermöglicht cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Erkennungsansatz: token/cookie-Muster

Wenn du dich mehrmals einloggst und **immer dasselbe Cookie erhältst**, könnte der ciphertext deterministisch sein (ECB oder fester IV).

Wenn du zwei Benutzer erstellst, deren plaintext-Layouts größtenteils identisch sind (z.B. lange wiederholte Zeichen) und du wiederholte ciphertext-Blöcke an denselben Offsets siehst, ist ECB ein Hauptverdächtiger.

### Exploitation-Muster

#### Entfernen ganzer Blöcke

Wenn das Token-Format so etwas wie `<username>|<password>` ist und die Blockgrenze ausgerichtet ist, kannst du manchmal einen Benutzer so erstellen, dass der `admin`-Block ausgerichtet erscheint und dann die vorhergehenden Blöcke entfernen, um ein gültiges Token für `admin` zu erhalten.

#### Verschieben von Blöcken

If the backend tolerates padding/extra spaces (`admin` vs `admin    `), you can:

- Align a block that contains `admin   `
- Swap/reuse that ciphertext block into another token

## Padding Oracle

### What it is

In CBC mode, if the server reveals (directly or indirectly) whether decrypted plaintext has **valid PKCS#7 padding**, you can often:

- Decrypt ciphertext without the key
- Encrypt chosen plaintext (forge ciphertext)

The oracle can be:

- A specific error message
- A different HTTP status / response size
- A timing difference

### Practical exploitation

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Warum es funktioniert

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Durch Modifizieren von Bytes in `C[i-1]` und Beobachten, ob das Padding gültig ist, kann man `P[i]` Byte für Byte wiederherstellen.

## Bit-flipping in CBC

Selbst ohne ein Padding-Oracle ist CBC manipulierbar. Wenn du Ciphertext-Blöcke verändern kannst und die Anwendung den entschlüsselten Plaintext als strukturierte Daten verwendet (z. B. `role=user`), kannst du bestimmte Bits umdrehen, um ausgewählte Plaintext-Bytes an einer gewählten Position im nächsten Block zu ändern.

Typisches CTF-Muster:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

Dies stellt für sich genommen keinen Bruch der Vertraulichkeit dar, ist aber eine häufige Primitive zur Privilegieneskalation, wenn Integrität fehlt.

## CBC-MAC

CBC-MAC ist nur unter bestimmten Bedingungen sicher (insbesondere **Nachrichten mit fester Länge** und korrekte Domain-Trennung).

### Klassisches Fälschungsmuster für variable Längen

CBC-MAC wird normalerweise berechnet als:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Wenn du Tags für gewählte Nachrichten erhalten kannst, kannst du oft einen Tag für eine Verkettung (oder verwandte Konstruktion) erstellen, ohne den Schlüssel zu kennen, indem du ausnutzt, wie CBC Blöcke verknüpft.

Das tritt häufig in CTF-Cookies/Token auf, die Benutzernamen oder Rollen mit CBC-MAC absichern.

### Sicherere Alternativen

- Verwende HMAC (SHA-256/512)
- Verwende CMAC (AES-CMAC) korrekt
- Füge Nachrichtenlänge / Domain-Trennung hinzu

## Stream-Chiffren: XOR und RC4

### Mentales Modell

Die meisten Stream-Cipher-Fälle lassen sich reduzieren auf:

`ciphertext = plaintext XOR keystream`

Also:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-basierte Verschlüsselung

Wenn du einen Plaintext-Abschnitt an Position `i` kennst, kannst du Keystream-Bytes wiederherstellen und andere Ciphertexte an diesen Positionen entschlüsseln.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 ist eine Stream-Chiffre; Verschlüsselung/Entschlüsselung sind dieselbe Operation.

Wenn du RC4-Verschlüsselungen von bekanntem Plaintext unter demselben Schlüssel erhalten kannst, kannst du den Keystream wiederherstellen und andere Nachrichten derselben Länge/Offset entschlüsseln.

Referenz-Writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
