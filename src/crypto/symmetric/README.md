# Symmetrische Kryptografie

{{#include ../../banners/hacktricks-training.md}}

## Worauf man in CTFs achten sollte

- **Missbrauch von Modi**: ECB-Muster, CBC-Malleability, Wiederverwendung von CTR/GCM-Nonces.
- **Padding-Oracles**: unterschiedliche Fehler/Zeiten bei ungültigem Padding.
- **MAC-Verwechslung**: Verwendung von CBC-MAC mit Nachrichten variabler Länge oder Fehler bei MAC-then-encrypt.
- **XOR überall**: Stream-Cipher und benutzerdefinierte Konstruktionen reduzieren sich häufig auf XOR mit einem Keystream.

## AES-Modi und Missbrauch

NIST spezifiziert die Vertraulichkeitsmodi ECB, CBC und CTR in SP 800-38A sowie authenticated encryption mit GCM in SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB leakt Muster: identische Klartextblöcke → identische Ciphertext-Blöcke. Das ermöglicht:

- Cut-and-paste / Neuanordnung von Blöcken
- Löschen von Blöcken (wenn das Format gültig bleibt)

Wenn du den Klartext kontrollieren und den Ciphertext (oder Cookies) beobachten kannst, versuche, wiederholte Blöcke zu erzeugen (z. B. viele `A`s), und suche nach Wiederholungen.

### CBC: Cipher Block Chaining

- CBC ist **malleable**: Das Umkehren von Bits in `C[i-1]` kehrt vorhersehbare Bits in `P[i]` um und beschädigt gleichzeitig `P[i-1]`. Das Ändern des IV zielt auf den ersten Klartextblock, ohne einen früheren Klartextblock zu beschädigen.
- Wenn das System gültiges von ungültigem Padding unterscheidet, hast du möglicherweise ein **padding oracle**.

### CTR

CTR verwandelt AES in eine Stream-Cipher: `C = P XOR keystream`.

Wenn ein Nonce/IV mit demselben Key wiederverwendet wird:

- `C1 XOR C2 = P1 XOR P2` (klassische Keystream-Wiederverwendung)
- Bei bekanntem Klartext kannst du den Keystream wiederherstellen und andere Nachrichten entschlüsseln.

**Muster zur Ausnutzung der Nonce/IV-Wiederverwendung**

- Stelle den Keystream überall dort wieder her, wo der Klartext bekannt oder erratbar ist:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Wende die wiederhergestellten Keystream-Bytes an denselben Offsets auf jeden anderen Ciphertext an, der mit demselben Key+IV erzeugt wurde, um ihn zu entschlüsseln.
- Stark strukturierte Daten (z. B. ASN.1/X.509-Zertifikate, Datei-Header, JSON/CBOR) liefern große Bereiche mit bekanntem Klartext. Häufig kannst du den Ciphertext des Zertifikats mit dem vorhersehbaren Zertifikatsinhalt XORen, um den Keystream abzuleiten, und anschließend andere unter dem wiederverwendeten IV verschlüsselte Geheimnisse entschlüsseln. Siehe auch [TLS & Certificates](../tls-and-certificates/README.md) für typische Zertifikatslayouts.<sup>[[1]](#references)</sup>
- Wenn mehrere Geheimnisse desselben **serialisierten Formats/derselben Größe** unter demselben Key+IV verschlüsselt werden, kann die Feldausrichtung auch ohne vollständig bekannten Klartext leaken. Beispiel: PKCS#8-RSA-Keys derselben Modulusgröße platzieren Primfaktoren an übereinstimmenden Offsets (~99,6 % Ausrichtung bei 2048 Bit). Das XORen zweier Ciphertexts unter dem wiederverwendeten Keystream isoliert `p ⊕ p'` / `q ⊕ q'`, die in Sekunden per Brute-Force wiederhergestellt werden können.<sup>[[1]](#references)</sup>
- Standard-IVs in Libraries (z. B. die konstante Zeichenfolge `000...01`) sind ein kritischer Fehler: Jede Verschlüsselung wiederholt denselben Keystream und verwandelt CTR in ein wiederverwendetes One-Time-Pad.<sup>[[1]](#references)</sup>

**CTR-Malleability**

- CTR bietet ausschließlich Vertraulichkeit: Das Umkehren von Bits im Ciphertext kehrt deterministisch dieselben Bits im Klartext um. Ohne einen Authentication-Tag können Angreifer Daten unbemerkt manipulieren (z. B. Keys, Flags oder Nachrichten ändern).
- Verwende AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 usw.) und erzwinge die Überprüfung des Tags, um Bit-Flips zu erkennen.

### GCM

GCM bricht bei der Wiederverwendung von Nonces ebenfalls vollständig zusammen. Wenn derselbe Key+Nonce mehr als einmal verwendet wird, erhält man typischerweise:

- Keystream-Wiederverwendung bei der Verschlüsselung (wie bei CTR), wodurch die Wiederherstellung des Klartexts möglich wird, sobald irgendein Klartext bekannt ist.
- Verlust der Integritätsgarantien. Je nachdem, was offengelegt wird (mehrere Nachrichten/Tag-Paare unter demselben Nonce), können Angreifer möglicherweise Tags fälschen.

Betriebshinweise:

- Betrachte die „Nonce-Wiederverwendung“ bei AEAD als kritische Schwachstelle.
- Misuse-resistant AEADs wie AES-GCM-SIV reduzieren die Folgen einer Nonce-Wiederverwendung. Aufrufer sollten weiterhin eindeutige Nonces bereitstellen, wie es die Schnittstelle der Konstruktion verlangt; eine versehentliche Wiederverwendung hat im Vergleich zu gewöhnlichem GCM begrenzte Folgen.<sup>[[3]](#references)[[4]](#references)</sup>
- Wenn du mehrere Ciphertexts unter demselben Nonce hast, prüfe zunächst Relationen nach dem Muster `C1 XOR C2 = P1 XOR P2`.

### Tools

- [CyberChef](https://gchq.github.io/CyberChef/) für schnelle Experimente.<sup>[[8]](#references)</sup>
- Pythons [PyCryptodome](https://www.pycryptodome.org/) package für Scripting.<sup>[[9]](#references)</sup>

## Muster zur ECB-Ausnutzung

ECB (Electronic Code Book) verschlüsselt jeden Block unabhängig:

- identische Klartextblöcke → identische Ciphertext-Blöcke
- dadurch wird die Struktur geleakt und Cut-and-paste-Angriffe werden ermöglicht

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Erkennungsidee: Token-/Cookie-Muster

Wenn du dich mehrmals anmeldest und **immer dasselbe Cookie erhältst**, ist der Ciphertext möglicherweise deterministisch (ECB oder ein fester IV).

Wenn du zwei Benutzer mit weitgehend identischen Klartextlayouts erstellst (z. B. mit langen Folgen wiederholter Zeichen) und wiederholte Ciphertext-Blöcke an denselben Offsets siehst, ist ECB ein naheliegender Verdacht.

### Ausnutzungsmuster

#### Ganze Blöcke entfernen

Wenn das Token-Format beispielsweise `<username>|<password>` lautet und die Blockgrenze passend ausgerichtet ist, kannst du manchmal einen Benutzer so erstellen, dass der `admin`-Block ausgerichtet erscheint, und anschließend vorhergehende Blöcke entfernen, um ein gültiges Token für `admin` zu erhalten.

#### Blöcke verschieben

Wenn das Backend Padding/zusätzliche Leerzeichen toleriert (`admin` vs `admin    `), kannst du:

- Einen Block ausrichten, der `admin   ` enthält
- Diesen Ciphertext-Block in ein anderes Token verschieben/wiederverwenden

## Padding Oracle

### Was es ist

Wenn der Server im CBC-Modus direkt oder indirekt offenlegt, ob der entschlüsselte Klartext **gültiges PKCS#7-Padding** enthält, kannst du häufig:<sup>[[7]](#references)</sup>

- Ciphertext ohne den Key entschlüsseln
- Einen Ciphertext erzeugen, der bei der Übermittlung präparierter vorhergehender Blöcke oder IVs zu einem ausgewählten Klartext entschlüsselt wird, sofern die Anwendung die daraus resultierende Nachricht mit gültigem Padding akzeptiert

Das Oracle kann Folgendes sein:

- Eine spezifische Fehlermeldung
- Ein anderer HTTP-Status / eine andere Antwortgröße
- Ein Zeitunterschied

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
Hinweise:

- Die Blockgröße beträgt bei AES häufig `16`.
- `-encoding 0` bedeutet Base64.
- Verwende `-error`, wenn der oracle eine bestimmte Zeichenfolge ist.

### Warum es funktioniert

Die CBC-Entschlüsselung berechnet `P[i] = D(C[i]) XOR C[i-1]`. Indem du Bytes in `C[i-1]` veränderst und beobachtest, ob das Padding gültig ist, kannst du `P[i]` Byte für Byte wiederherstellen.

## Bit-flipping in CBC

Auch ohne einen padding oracle ist CBC malleable. Wenn du Ciphertext-Blöcke verändern kannst und die Anwendung den entschlüsselten Plaintext als strukturierte Daten verwendet (z. B. `role=user`), kannst du bestimmte Bits umschalten, um ausgewählte Plaintext-Bytes an einer bestimmten Position im nächsten Block zu ändern.

Typisches CTF-Muster:

- Token = `IV || C1 || C2 || ...`
- Du kontrollierst Bytes in `C[i]`
- Du zielst auf Plaintext-Bytes in `P[i+1]`, weil `P[i+1] = D(C[i+1]) XOR C[i]`

Dies ist für sich genommen kein Bruch der Vertraulichkeit, aber ein häufiges Privilege-Escalation-Primitive, wenn die Integrität fehlt.

## CBC-MAC

CBC-MAC ist nur unter bestimmten Bedingungen sicher (insbesondere bei **Nachrichten fester Länge** und korrekter Domain Separation). AES-CMAC ist eine standardisierte Konstruktion, die Eingaben variabler Länge sicher verarbeitet.<sup>[[5]](#references)</sup>

### Klassisches Forgery-Muster bei variabler Länge

CBC-MAC wird normalerweise wie folgt berechnet:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Wenn du Tags für ausgewählte Nachrichten erhalten kannst, kannst du häufig einen Tag für eine Konkatenation (oder eine verwandte Konstruktion) erstellen, ohne den Key zu kennen, indem du ausnutzt, wie CBC Blöcke verkettet.

Dies tritt häufig bei CTF-Cookies/Tokens auf, die den Benutzernamen oder die Rolle mit CBC-MAC authentisieren.

### Sicherere Alternativen

- HMAC (SHA-256/512) verwenden
- CMAC (AES-CMAC) korrekt verwenden
- Nachrichtenlänge / Domain Separation einbeziehen

## Stream ciphers: XOR und RC4

### Das mentale Modell

Die meisten Situationen mit Stream ciphers lassen sich auf Folgendes reduzieren:

`ciphertext = plaintext XOR keystream`

Daher gilt:

- Wenn du den Plaintext kennst, kannst du den Keystream wiederherstellen.
- Wenn der Keystream wiederverwendet wird (derselbe Key+Nonce), gilt `C1 XOR C2 = P1 XOR P2`.

### XOR-basierte Verschlüsselung

Wenn du ein beliebiges Plaintext-Segment an Position `i` kennst, kannst du Keystream-Bytes wiederherstellen und andere Ciphertexts an diesen Positionen entschlüsseln.

Automatische Solver:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 ist ein veralteter Stream cipher; Ver- und Entschlüsselung verwenden dieselbe XOR-Operation. Seine bekannten Biases machen ihn für neue Systeme ungeeignet, und TLS verbietet seine Cipher Suites ausdrücklich.<sup>[[6]](#references)</sup>

Wenn du unter demselben Key eine RC4-Verschlüsselung von bekanntem Plaintext erhalten kannst, kannst du den Keystream wiederherstellen und andere Nachrichten mit derselben Länge bzw. demselben Offset entschlüsseln.

Referenz-Writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Nachlässigkeit versus handwerkliche Sorgfalt in der Kryptografie](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A – Empfehlung für Betriebsmodi von Blockchiffren](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D – Empfehlung für den Galois/Counter Mode (GCM) und GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 – AES-GCM-SIV: Authenticated Encryption mit Resistenz gegen Nonce-Missbrauch](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 – Der AES-CMAC-Algorithmus](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 – Verbot von RC4 Cipher Suites](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide – Testen auf Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome-Dokumentation](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
