# Symmetrische Kryptografie

{{#include ../../banners/hacktricks-training.md}}

## Worauf man bei CTFs achten sollte

- **Missbrauch von Modi**: ECB-Muster, CBC-Malleability, Wiederverwendung von Nonces bei CTR/GCM.
- **Padding-Oracles**: unterschiedliche Fehler oder Zeitverhalten bei ungültigem Padding.
- **MAC-Verwechslungen**: Verwendung von CBC-MAC mit Nachrichten variabler Länge oder Fehler bei MAC-then-encrypt.
- **Überall XOR**: Stream Ciphers und benutzerdefinierte Konstruktionen laufen oft auf XOR mit einem Keystream hinaus.

## AES-Modi und ihr Missbrauch

NIST legt die Vertraulichkeitsmodi ECB, CBC und CTR in SP 800-38A sowie die authentifizierte Verschlüsselung GCM in SP 800-38D fest.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB gibt Muster preis: gleiche Klartextblöcke → gleiche Chiffretextblöcke. Das ermöglicht:

- Cut-and-paste / Umordnen von Blöcken
- Löschen von Blöcken (wenn das Format gültig bleibt)

Wenn du den Klartext kontrollieren und den Chiffretext beobachten kannst (oder Cookies), versuche, wiederholte Blöcke zu erzeugen (z. B. viele `A`s), und achte auf Wiederholungen.

### CBC: Cipher Block Chaining

- CBC ist **malleable**: Das Umkippen von Bits in `C[i-1]` kippt vorhersehbare Bits in `P[i]` um und beschädigt zugleich `P[i-1]`. Durch Änderung des IV wird der erste Klartextblock gezielt verändert, ohne einen vorherigen Klartextblock zu beschädigen.
- Wenn das System gültiges und ungültiges Padding unterschiedlich behandelt, hast du möglicherweise ein **Padding Oracle**.

### CTR

CTR macht aus AES eine Stream Cipher: `C = P XOR keystream`.

Wird ein Nonce/IV mit demselben Schlüssel wiederverwendet:

- `C1 XOR C2 = P1 XOR P2` (klassische Wiederverwendung des Keystreams)
- Mit bekanntem Klartext kannst du den Keystream wiederherstellen und andere Nachrichten entschlüsseln.

**Muster zur Ausnutzung der Nonce/IV-Wiederverwendung**

- Stelle den Keystream überall dort wieder her, wo der Klartext bekannt ist oder erraten werden kann:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Wende die wiederhergestellten Keystream-Bytes auf andere Chiffrate an, die mit demselben Schlüssel und IV an denselben Offsets erzeugt wurden.
- Stark strukturierte Daten (z. B. ASN.1/X.509-Zertifikate, Datei-Header, JSON/CBOR) enthalten große Bereiche mit bekanntem Klartext. Oft kannst du den Chiffrattext des Zertifikats mit dem vorhersehbaren Zertifikatsinhalt XOR-verknüpfen, um den Keystream abzuleiten und anschließend andere mit demselben IV verschlüsselte Geheimnisse zu entschlüsseln. Siehe auch [TLS & Certificates](../tls-and-certificates/README.md) für typische Zertifikatslayouts.<sup>[[1]](#references)</sup>
- Wenn mehrere Geheimnisse im **gleichen serialisierten Format und mit gleicher Größe** unter demselben Schlüssel und IV verschlüsselt werden, verrät die Feldausrichtung Informationen, auch ohne vollständig bekannten Klartext. Beispiel: PKCS#8-RSA-Schlüssel derselben Modulusgröße platzieren Primfaktoren an übereinstimmenden Offsets (bei 2048 Bit etwa 99,6 % Übereinstimmung). XOR-verknüpft man zwei Chiffrate unter dem wiederverwendeten Keystream, erhält man `p ⊕ p'` / `q ⊕ q'`, die sich in Sekunden per Brute-Force wiederherstellen lassen.<sup>[[1]](#references)</sup>
- Standard-IVs in Bibliotheken (z. B. konstante Werte wie `000...01`) sind eine kritische Fehlerquelle: Jede Verschlüsselung wiederholt denselben Keystream und verwandelt CTR in ein wiederverwendetes One-Time Pad.<sup>[[1]](#references)</sup>

**CTR-Malleabilität**

- CTR gewährleistet nur Vertraulichkeit: Das Ändern von Bits im Chiffrat ändert deterministisch dieselben Bits im Klartext. Ohne Authentication Tag können Angreifer Daten unbemerkt manipulieren (z. B. Schlüssel, Flags oder Nachrichten verändern).
- Verwende AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 usw.) und erzwinge die Überprüfung des Tags, um Bit-Flips zu erkennen.

### GCM

Auch GCM wird bei Nonce-Wiederverwendung schwerwiegend kompromittiert. Wird derselbe Schlüssel und dieselbe Nonce mehrfach verwendet, erhält man typischerweise:

- Wiederverwendung des Keystreams bei der Verschlüsselung (wie bei CTR), wodurch sich Klartext wiederherstellen lässt, wenn ein Klartext bekannt ist.
- Verlust der Integritätsgarantien. Je nachdem, welche Daten offengelegt werden (mehrere Nachrichten-/Tag-Paare unter derselben Nonce), können Angreifer möglicherweise Tags fälschen.

Hinweise zum Betrieb:

- Behandle „Nonce-Wiederverwendung“ bei AEAD als kritische Schwachstelle.
- Missbrauchsresistente AEAD-Verfahren wie AES-GCM-SIV begrenzen die Folgen einer Nonce-Wiederverwendung. Aufrufer sollten weiterhin eindeutige Nonces bereitstellen, wie von der Schnittstelle der Konstruktion verlangt; eine versehentliche Wiederverwendung hat jedoch begrenztere Folgen als bei gewöhnlichem GCM.<sup>[[3]](#references)[[4]](#references)</sup>
- Wenn du mehrere Chiffrate unter derselben Nonce hast, beginne mit der Prüfung auf Beziehungen der Form `C1 XOR C2 = P1 XOR P2`.

### Tools

- [CyberChef](https://gchq.github.io/CyberChef/) für schnelle Experimente.<sup>[[8]](#references)</sup>
- Das Python-Paket [PyCryptodome](https://www.pycryptodome.org/) zum Scripting.<sup>[[9]](#references)</sup>

## ECB-Ausnutzungsmuster

ECB (Electronic Code Book) verschlüsselt jeden Block unabhängig:

- gleiche Klartextblöcke → gleiche Chiffratblöcke
- dadurch wird die Struktur offengelegt und werden Cut-and-Paste-Angriffe ermöglicht

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Erkennung: Muster bei Tokens/Cookies

Wenn du dich mehrmals anmeldest und **immer dasselbe Cookie erhältst**, könnte das Chiffrat deterministisch sein (ECB oder ein fester IV).

Wenn du zwei Benutzer mit weitgehend identischen Klartextlayouts erstellst (z. B. mit langen Folgen wiederholter Zeichen) und wiederholte Chiffratblöcke an denselben Offsets siehst, ist ECB ein Hauptverdächtiger.

### Ausnutzungsmuster

#### Ganze Blöcke entfernen

Wenn das Token-Format etwa `<username>|<password>` lautet und die Blockgrenze passend liegt, kannst du manchmal einen Benutzer so erstellen, dass der `admin`-Block passend ausgerichtet ist, und anschließend die vorangehenden Blöcke entfernen, um ein gültiges Token für `admin` zu erhalten.

#### Blöcke verschieben

Wenn das Backend Padding oder zusätzliche Leerzeichen toleriert (`admin` vs `admin    `), kannst du:

- Einen Block mit `admin   ` ausrichten
- Diesen Chiffratblock in ein anderes Token übernehmen oder wiederverwenden

## Padding Oracle

### Was es ist

Wenn der Server im CBC-Modus direkt oder indirekt verrät, ob der entschlüsselte Klartext **gültiges PKCS#7-Padding** enthält, kannst du oft:<sup>[[7]](#references)</sup>

- Chiffrate ohne den Schlüssel entschlüsseln
- Ein Chiffrat konstruieren, das zu einem gewählten Klartext entschlüsselt wird, wenn du manipulierte vorangehende Blöcke oder IVs übermitteln kannst und die Anwendung die resultierende Nachricht mit gültigem Padding akzeptiert

Das Oracle kann sich zeigen durch:

- Eine bestimmte Fehlermeldung
- Einen anderen HTTP-Status oder eine andere Antwortgröße
- Einen Timing-Unterschied

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
- Verwende `-error`, wenn das Oracle eine bestimmte Zeichenfolge ausgibt.

### Warum es funktioniert

Die CBC-Entschlüsselung berechnet `P[i] = D(C[i]) XOR C[i-1]`. Indem du Bytes in `C[i-1]` veränderst und beobachtest, ob das Padding gültig ist, kannst du `P[i]` Byte für Byte wiederherstellen.

## Bit-Flipping in CBC

Auch ohne ein padding oracle ist CBC manipulierbar. Wenn du Ciphertext-Blöcke verändern kannst und die Anwendung den entschlüsselten Klartext als strukturierte Daten verwendet (z. B. `role=user`), kannst du bestimmte Bits umschalten, um ausgewählte Klartextbytes an einer bestimmten Position im nächsten Block zu ändern.

Typisches CTF-Muster:

- Token = `IV || C1 || C2 || ...`
- Du kontrollierst Bytes in `C[i]`
- Du zielst auf Klartextbytes in `P[i+1]`, weil `P[i+1] = D(C[i+1]) XOR C[i]`

Das ist für sich genommen kein Bruch der Vertraulichkeit, aber bei fehlender Integrität eine gängige Methode zur Rechteausweitung.

## CBC-MAC

CBC-MAC ist nur unter bestimmten Bedingungen sicher (insbesondere bei **Nachrichten fester Länge** und korrekter Domänentrennung). AES-CMAC ist eine standardisierte Konstruktion, die Eingaben variabler Länge sicher verarbeitet.<sup>[[5]](#references)</sup>

### Klassisches Forgery-Muster bei variabler Nachrichtenlänge

CBC-MAC wird üblicherweise wie folgt berechnet:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Wenn du Tags für ausgewählte Nachrichten erhalten kannst, kannst du häufig ohne Kenntnis des Schlüssels einen Tag für eine Konkatenation (oder eine ähnliche Konstruktion) erstellen, indem du ausnutzt, wie CBC Blöcke verkettet.

Das kommt häufig bei CTF-Cookies/Tokens vor, die den Benutzernamen oder die Rolle mit CBC-MAC authentifizieren.

### Sicherere Alternativen

- HMAC (SHA-256/512) verwenden
- CMAC (AES-CMAC) korrekt verwenden
- Nachrichtenlänge und Domänentrennung einbeziehen

## Stromchiffren: XOR und RC4

### Das mentale Modell

Die meisten Situationen mit Stromchiffren lassen sich auf Folgendes reduzieren:

`ciphertext = plaintext XOR keystream`

Daher gilt:

- Wenn du den Klartext kennst, kannst du den Keystream wiederherstellen.
- Wenn der Keystream wiederverwendet wird (gleicher Schlüssel und gleiche Nonce), gilt `C1 XOR C2 = P1 XOR P2`.

### XOR-basierte Verschlüsselung

Wenn du ein beliebiges Klartextsegment an Position `i` kennst, kannst du Keystream-Bytes wiederherstellen und andere Ciphertexte an diesen Positionen entschlüsseln.

Autosolver:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 ist eine veraltete Stromchiffre; Ver- und Entschlüsselung sind dieselbe XOR-Operation. Aufgrund der bekannten Biases ist sie für neue Systeme ungeeignet, und TLS verbietet ihre Cipher Suites ausdrücklich.<sup>[[6]](#references)</sup>

Wenn du unter demselben Schlüssel eine RC4-Verschlüsselung von bekanntem Klartext erhalten kannst, kannst du den Keystream wiederherstellen und andere Nachrichten gleicher Länge und gleichen Offsets entschlüsseln.

Referenz-Write-up (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Nachlässigkeit versus handwerkliches Können in der Kryptografie](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A – Empfehlung für Betriebsmodi von Blockchiffren](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D – Empfehlung für den Galois/Counter Mode (GCM) und GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 – AES-GCM-SIV: Authentifizierte Verschlüsselung mit Schutz vor Nonce-Fehlverwendung](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 – Der AES-CMAC-Algorithmus](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 – Verbot von RC4 Cipher Suites](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide – Testen auf Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome-Dokumentation](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
