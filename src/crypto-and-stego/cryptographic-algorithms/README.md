# Kryptographische/Kompressionsalgorithmen

{{#include ../../banners/hacktricks-training.md}}

## Identifizierung von Algorithmen

Wenn du auf Code triffst, der **shift rights and lefts, xors und mehrere arithmetische Operationen** verwendet, ist es sehr wahrscheinlich, dass es sich um die Implementierung eines **kryptographischen Algorithmus** handelt. Hier werden einige Methoden gezeigt, um den verwendeten Algorithmus zu **identifizieren, ohne jeden Schritt reversen zu müssen**.

### API-Funktionen

**CryptDeriveKey**

Wenn diese Funktion verwendet wird, kannst du feststellen, welcher **Algorithmus verwendet wird**, indem du den Wert des zweiten Parameters überprüfst:

![](<../../images/image (156).png>)

Siehe hier die Tabelle der möglichen Algorithmen und deren zugewiesene Werte: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Komprimiert und dekomprimiert einen gegebenen Datenpuffer.

**CryptAcquireContext**

Aus den [Docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Die Funktion **CryptAcquireContext** wird verwendet, um ein Handle für einen bestimmten Key-Container innerhalb eines bestimmten cryptographic service provider (CSP) zu erhalten. **Dieses zurückgegebene Handle wird in Aufrufen von CryptoAPI**-Funktionen verwendet, die den ausgewählten CSP nutzen.

**CryptCreateHash**

Initiiert das Hashing eines Datenstroms. Wenn diese Funktion verwendet wird, kannst du feststellen, welcher **Algorithmus verwendet wird**, indem du den Wert des zweiten Parameters überprüfst:

![](<../../images/image (549).png>)

\
Siehe hier die Tabelle der möglichen Algorithmen und deren zugewiesene Werte: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code-Konstanten

Manchmal ist es sehr einfach, einen Algorithmus zu identifizieren, dank der Verwendung eines speziellen und eindeutigen Werts.

![](<../../images/image (833).png>)

Wenn du die erste Konstante in Google suchst, erhältst du Folgendes:

![](<../../images/image (529).png>)

Daher kannst du annehmen, dass die dekompilierte Funktion ein **sha256 calculator** ist.\
Du kannst jede der anderen Konstanten suchen und wirst wahrscheinlich dasselbe Ergebnis erhalten.

### Dateninfo

Wenn der Code keine signifikanten Konstanten enthält, könnte er **Informationen aus der .data section** laden.\
Du kannst auf diese Daten zugreifen, **das erste dword gruppieren** und wie oben gezeigt in google danach suchen:

![](<../../images/image (531).png>)

In diesem Fall findest du, wenn du nach **0xA56363C6** suchst, dass es mit den **Tabellen des AES-Algorithmus** in Verbindung steht.

## RC4 **(Symmetrische Kryptographie)**

### Eigenschaften

Es besteht aus 3 Hauptteilen:

- **Initialization stage/**: Erstellt eine **Tabelle von Werten von 0x00 bis 0xFF** (insgesamt 256 Bytes, 0x100). Diese Tabelle wird üblicherweise Substitution Box (oder SBox) genannt.
- **Scrambling stage**: Läuft durch die zuvor erstellte Tabelle (Schleife mit 0x100 Iterationen) und ändert jeden Wert mit **semi-random** Bytes. Um diese semi-random Bytes zu erzeugen, wird der RC4 **key** verwendet. RC4 **keys** können zwischen **1 und 256 Bytes** lang sein, empfohlen wird jedoch meist eine Länge über 5 Bytes. Häufig sind RC4-Keys 16 Bytes lang.
- **XOR stage**: Schließlich wird der Plaintext oder Ciphertext mit den zuvor erzeugten Werten **geXORt**. Die Funktion zum Verschlüsseln und Entschlüsseln ist dieselbe. Dazu wird so oft wie nötig durch die erzeugten 256 Bytes iteriert. Dies erkennt man in dekompiliertem Code häufig an einem **%256 (mod 256)**.

> [!TIP]
> **Um RC4 in einer Disassembly/dekompilierten Darstellung zu erkennen, kannst du nach 2 Schleifen der Größe 0x100 (unter Verwendung eines Keys) suchen und anschließend eine XOR-Operation der Eingabedaten mit den zuvor in den 2 Schleifen erzeugten 256 Werten, wahrscheinlich unter Verwendung von %256 (mod 256), prüfen.**

### **Initialization stage/Substitution Box:** (Beachte den als Zähler verwendeten Wert 256 und wie an jeder Stelle der 256 Zeichen eine 0 geschrieben wird)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetrische Kryptographie)**

### **Eigenschaften**

- Verwendung von **Substitution Boxes und Lookup-Tabellen**
- Es ist möglich, **AES anhand spezifischer Lookup-Tabellenwerte** (Konstanten) zu unterscheiden. _Beachte, dass die **Konstante** entweder im Binary **gespeichert** sein kann oder **dynamisch erzeugt** wird._
- Der **encryption key** muss durch **16** teilbar sein (häufig 32B) und üblicherweise wird ein **IV** von 16B verwendet.

### SBox-Konstanten

![](<../../images/image (208).png>)

## Serpent **(Symmetrische Kryptographie)**

### Eigenschaften

- Es ist selten, dass Malware es verwendet, aber es gibt Beispiele (Ursnif).
- Einfach zu bestimmen, ob ein Algorithmus Serpent ist oder nicht, basierend auf seiner Länge (extrem lange Funktion).

### Identifizierung

Im folgenden Bild ist zu sehen, wie die Konstante **0x9E3779B9** verwendet wird (beachte, dass diese Konstante auch von anderen Crypto-Algorithmen wie **TEA** - Tiny Encryption Algorithm verwendet wird).\
Beachte auch die **Größe der Schleife** (**132**) und die **Anzahl der XOR-Operationen** in den **disassembly**-Anweisungen und im **Code**-Beispiel:

![](<../../images/image (547).png>)

Wie bereits erwähnt, kann dieser Code in jedem Decompiler als eine **sehr lange Funktion** visualisiert werden, da **keine Jumps** darin sind. Der dekompilierte Code kann wie folgt aussehen:

![](<../../images/image (513).png>)

Daher ist es möglich, diesen Algorithmus zu identifizieren, indem man die **Magic-Number** und die **initialen XORs** prüft, eine **sehr lange Funktion** sieht und einige **Instruktionen** der langen Funktion **mit einer Implementierung** vergleicht (z. B. shift left um 7 und rotate left um 22).

## RSA **(Asymmetrische Kryptographie)**

### Eigenschaften

- Komplexer als symmetrische Algorithmen
- Es gibt keine Konstanten! (custom implementations sind schwer zu bestimmen)
- KANAL (ein Crypto-Analyzer) liefert für RSA keine Hinweise, da er auf Konstanten angewiesen ist.

### Identifizierung durch Vergleiche

![](<../../images/image (1113).png>)

- In Zeile 11 (links) gibt es ein `+7) >> 3`, was dem Ausdruck in Zeile 35 (rechts) `+7) / 8` entspricht.
- Zeile 12 (links) prüft, ob `modulus_len < 0x040` und in Zeile 36 (rechts) wird geprüft, ob `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Eigenschaften

- 3 Funktionen: Init, Update, Final
- Ähnliche Initialisierungsfunktionen

### Identifikation

**Init**

Du kannst beide anhand der Konstanten identifizieren. Beachte, dass sha_init eine Konstante hat, die MD5 nicht besitzt:

![](<../../images/image (406).png>)

**MD5 Transform**

Beachte die Verwendung von mehr Konstanten

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Kleiner und effizienter, da seine Funktion darin besteht, versehentliche Änderungen in Daten zu finden
- Verwendet Lookup-Tabellen (du kannst also Konstanten erkennen)

### Identifikation

Prüfe **Lookup-Tabellen-Konstanten**:

![](<../../images/image (508).png>)

Ein CRC-Hash-Algorithmus sieht ungefähr so aus:

![](<../../images/image (391).png>)

## APLib (Kompression)

### Eigenschaften

- Keine erkennbaren Konstanten
- Du kannst versuchen, den Algorithmus in Python zu implementieren und online nach ähnlichen Implementierungen suchen

### Identifikation

Der Graph ist ziemlich groß:

![](<../../images/image (207) (2) (1).png>)

Prüfe **3 Vergleiche, um ihn zu erkennen**:

![](<../../images/image (430).png>)

## Fehler bei der Implementierung elliptischer Kurven-Signaturen

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 verlangt, dass HashEdDSA-Verifizierer eine Signatur `sig = R || s` aufteilen und jeden Skalar mit `s \geq n` ablehnen, wobei `n` die Gruppenordnung ist. Die `elliptic` JS-Bibliothek hat diese Grenzprüfung übersprungen, sodass ein Angreifer, der ein gültiges Paar `(msg, R || s)` kennt, alternative Signaturen `s' = s + k·n` fälschen und weiterhin `sig' = R || s'` neu kodieren kann.
- Die Verifizierungsroutinen verwenden nur `s mod n`, daher werden alle `s'`, die zu `s` kongruent sind, akzeptiert, obwohl sie unterschiedliche Bytefolgen sind. Systeme, die Signaturen als kanonische Tokens behandeln (blockchain consensus, replay caches, DB keys usw.), können desynchronisiert werden, weil strikte Implementierungen `s'` ablehnen.
- Beim Auditieren anderer HashEdDSA-Implementierungen stelle sicher, dass der Parser sowohl den Punkt `R` als auch die Skalarlänge validiert; versuche, Vielfache von `n` an ein bekannt gutes `s` anzuhängen, um zu bestätigen, dass der Verifizierer korrekt ablehnt.

### ECDSA truncation vs. leading-zero hashes

- ECDSA-Verifizierer müssen nur die linksten `log2(n)` Bits des Nachrichtenhashes `H` verwenden. In `elliptic` berechnete der Truncation-Helper `delta = (BN(msg).byteLength()*8) - bitlen(n)`; der `BN`-Konstruktor entfernt führende Null-Bytes, sodass jeder Hash, der mit ≥4 Null-Bytes beginnt (auf Kurven wie secp192r1 mit 192-Bit-Ordnung), fälschlicherweise als nur 224 Bits statt 256 erschien.
- Der Verifizierer hat um 32 Bits statt 64 Bits nach rechts verschoben und erzeugte damit ein `E`, das nicht mit dem vom Signierer verwendeten Wert übereinstimmt. Gültige Signaturen auf diesen Hashes schlagen daher mit einer Wahrscheinlichkeit von ≈`2^-32` für SHA-256-Eingaben fehl.
- Füttere sowohl den „alles gut“-Vektor als auch Varianten mit führenden Nullen (z. B. Wycheproof `ecdsa_secp192r1_sha256_test.json` Fall `tc296`) in eine Zielimplementierung; wenn der Verifizierer nicht mit dem Signierer übereinstimmt, hast du einen ausnutzbaren Truncation-Bug gefunden.

### Exercising Wycheproof vectors against libraries
- Wycheproof liefert JSON-Testsets, die malformed points, malleable scalars, ungewöhnliche Hashes und andere Randfälle kodieren. Einen Harness um `elliptic` (oder jede andere Crypto-Library) zu bauen ist unkompliziert: lade das JSON, deserialisiere jeden Testfall und prüfe, ob die Implementierung dem erwarteten `result`-Flag entspricht.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Fehler sollten triagiert werden, um Spezifikationsverletzungen von false positives zu unterscheiden. Bei den beiden oben genannten Bugs wiesen die fehlschlagenden Wycheproof-Fälle unmittelbar auf fehlende Skalarbereichsprüfungen (EdDSA) und falsche Hash-Trunkierung (ECDSA) hin.
- Integriere das Test-Harness in CI, sodass Regressionen beim Skalarparsing, bei der Hash-Verarbeitung oder in der Gültigkeit von Koordinaten Tests auslösen, sobald sie eingeführt werden. Das ist besonders nützlich für high-level languages (JS, Python, Go), in denen subtile bignum-Konvertierungen leicht schiefgehen.

## Referenzen

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
