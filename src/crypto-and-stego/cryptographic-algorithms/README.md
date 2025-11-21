# Kryptographische/Kompressionsalgorithmen

{{#include ../../banners/hacktricks-training.md}}

## Erkennung von Algorithmen

Wenn du in einem Code auf **shift rights and lefts, xors and several arithmetic operations** stößt, ist es sehr wahrscheinlich, dass es sich um die Implementierung eines **cryptographic algorithm** handelt. Hier werden einige Möglichkeiten gezeigt, den verwendeten Algorithmus zu **identifizieren, ohne jeden Schritt reversen zu müssen**.

### API-Funktionen

**CryptDeriveKey**

Wenn diese Funktion verwendet wird, kannst du herausfinden, welcher **algorithm verwendet wird**, indem du den Wert des zweiten Parameters überprüfst:

![](<../../images/image (156).png>)

Sieh dir die Tabelle der möglichen Algorithmen und deren zugewiesene Werte hier an: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Komprimiert und dekomprimiert einen gegebenen Datenpuffer.

**CryptAcquireContext**

Aus den [Docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Die Funktion **CryptAcquireContext** wird verwendet, um ein Handle für einen bestimmten Key-Container innerhalb eines bestimmten cryptographic service provider (CSP) zu erhalten. **Dieses zurückgegebene Handle wird in Aufrufen an CryptoAPI-Funktionen verwendet, die den ausgewählten CSP nutzen.**

**CryptCreateHash**

Initiiert das Hashing eines Datenstroms. Wenn diese Funktion verwendet wird, kannst du herausfinden, welcher **algorithm verwendet wird**, indem du den Wert des zweiten Parameters überprüfst:

![](<../../images/image (549).png>)

\
Sieh dir die Tabelle der möglichen Algorithmen und deren zugewiesene Werte hier an: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code-Konstanten

Manchmal ist es sehr einfach, einen Algorithmus zu identifizieren, da er einen speziellen und eindeutigen Wert benutzt.

![](<../../images/image (833).png>)

Wenn du nach der ersten Konstante in Google suchst, erhältst du folgendes:

![](<../../images/image (529).png>)

Daher kannst du annehmen, dass die dekompilierte Funktion ein **sha256 calculator** ist.\
Du kannst jede der anderen Konstanten suchen und wirst (wahrscheinlich) dasselbe Ergebnis erhalten.

### Dateninfo

Wenn der Code keine aussagekräftigen Konstanten hat, lädt er möglicherweise **Informationen aus dem .data section**.\
Du kannst auf diese Daten zugreifen, **das erste dword gruppieren** und wie im vorherigen Abschnitt in Google suchen:

![](<../../images/image (531).png>)

In diesem Fall kannst du bei einer Suche nach **0xA56363C6** finden, dass es mit den **Tabellen des AES-Algorithmus** zusammenhängt.

## RC4 **(Symmetric Crypt)**

### Eigenschaften

Es besteht aus 3 Hauptteilen:

- **Initialization stage/**: Erzeugt eine **Tabelle von Werten von 0x00 bis 0xFF** (insgesamt 256 Bytes, 0x100). Diese Tabelle wird üblicherweise Substitution Box (oder SBox) genannt.
- **Scrambling stage**: Durchläuft die zuvor erstellte Tabelle (Schleife mit 0x100 Iterationen) und verändert jeden Wert mit **halb-zufälligen** Bytes. Um diese halb-zufälligen Bytes zu erzeugen, wird der RC4 **key** verwendet. RC4 **keys** können **zwischen 1 und 256 Bytes lang** sein, empfohlen wird jedoch meist eine Länge über 5 Bytes. Häufig sind RC4-Keys 16 Bytes lang.
- **XOR stage**: Schließlich wird der Klartext oder Ciphertext mit den zuvor erzeugten Werten **XORed**. Die Funktion zum Verschlüsseln und Entschlüsseln ist identisch. Dazu wird eine **Schleife über die erzeugten 256 Bytes** so oft wie nötig ausgeführt. Dies erkennt man in dekompiliertem Code oft an einem **%256 (mod 256)**.

> [!TIP]
> **Um RC4 in einer Disassembly/dekompilierten Darstellung zu identifizieren, kannst du nach 2 Schleifen der Größe 0x100 (mit Verwendung eines key) suchen und anschließend ein XOR der Eingabedaten mit den zuvor in den 2 Schleifen erzeugten 256 Werten prüfen, wahrscheinlich unter Verwendung von %256 (mod 256).**

### **Initialization stage/Substitution Box:** (Achte auf den als Zähler verwendeten Wert 256 und darauf, wie an jeder Position der 256 Zeichen eine 0 geschrieben wird)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### **Eigenschaften**

- Verwendung von **Substitution Boxes und Lookup-Tabellen**
- AES lässt sich oft **dank spezifischer Lookup-Tabellenwerte** (Konstanten) unterscheiden. _Beachte, dass die **Konstante** entweder **im Binary gespeichert** oder **dynamisch erzeugt** sein kann._
- Der **Verschlüsselungskey** muss durch **16 teilbar** sein (üblicherweise 32B) und normalerweise wird ein **IV** von 16B verwendet.

### SBox-Konstanten

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### Eigenschaften

- Es ist selten, Serpent in Malware zu finden, aber es gibt Beispiele (Ursnif)
- Einfach zu bestimmen, ob ein Algorithmus Serpent ist, basierend auf seiner Länge (extrem lange Funktion)

### Identifizierung

Im folgenden Bild fällt auf, wie die Konstante **0x9E3779B9** verwendet wird (beachte, dass diese Konstante auch von anderen crypto algorithms wie **TEA** - Tiny Encryption Algorithm - verwendet wird).\
Beachte außerdem die **Größe der Schleife** (**132**) und die **Anzahl der XOR-Operationen** in den Disassembly-Instruktionen und im Code-Beispiel:

![](<../../images/image (547).png>)

Wie bereits erwähnt, erscheint dieser Code in jedem Decompiler als eine **sehr lange Funktion**, da **keine Jumps** darin enthalten sind. Der dekompilierte Code kann wie folgt aussehen:

![](<../../images/image (513).png>)

Daher ist es möglich, diesen Algorithmus zu identifizieren, indem man die **Magic Number** und die **initialen XORs** prüft, eine **sehr lange Funktion** sieht und einige **Instruktionen** dieser langen Funktion **mit einer Implementierung** vergleicht (z. B. shift left um 7 und rotate left um 22).

## RSA **(Asymmetric Crypt)**

### Eigenschaften

- Komplexer als symmetrische Algorithmen
- Es gibt keine Konstanten! (Custom-Implementierungen sind schwer zu identifizieren)
- KANAL (ein crypto analyzer) liefert bei RSA keine Hinweise, da er auf Konstanten angewiesen ist.

### Identifizierung durch Vergleiche

![](<../../images/image (1113).png>)

- In Zeile 11 (links) gibt es ein `+7) >> 3`, was dem in Zeile 35 (rechts) entspricht: `+7) / 8`
- Zeile 12 (links) prüft `modulus_len < 0x040` und in Zeile 36 (rechts) wird `inputLen+11 > modulusLen` geprüft

## MD5 & SHA (hash)

### Eigenschaften

- 3 Funktionen: Init, Update, Final
- Ähnliche Initialisierungsfunktionen

### Erkennung

**Init**

Du kannst beide identifizieren, indem du die Konstanten prüfst. Beachte, dass sha_init eine Konstante hat, die MD5 nicht hat:

![](<../../images/image (406).png>)

**MD5 Transform**

Beachte die Verwendung mehrerer Konstanten

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Kleiner und effizienter, da die Funktion darin besteht, zufällige Änderungen an Daten zu finden
- Verwendet Lookup-Tabellen (daher kannst du Konstanten identifizieren)

### Erkennung

Prüfe **Lookup-Table-Konstanten**:

![](<../../images/image (508).png>)

Ein CRC-Hash-Algorithmus sieht so aus:

![](<../../images/image (391).png>)

## APLib (Compression)

### Eigenschaften

- Keine erkennbaren Konstanten
- Du kannst versuchen, den Algorithmus in Python zu implementieren und online nach ähnlichen Implementierungen suchen

### Erkennung

Der Graph ist ziemlich groß:

![](<../../images/image (207) (2) (1).png>)

Prüfe **3 Vergleiche, um ihn zu erkennen**:

![](<../../images/image (430).png>)

## Elliptic-Curve Signature Implementation Bugs

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 verlangt, dass HashEdDSA-Verifier eine Signatur `sig = R || s` aufteilen und jeden Skalar mit `s \geq n` ablehnen, wobei `n` die Gruppenordnung ist. Die `elliptic` JS-Bibliothek übersprang diese Schrankenprüfung, sodass ein Angreifer, der ein gültiges Paar `(msg, R || s)` kennt, alternative Signaturen `s' = s + k·n` fälschen und weiterhin `sig' = R || s'` neu kodieren kann.
- Die Verifikationsroutinen benutzen nur `s mod n`, daher werden alle `s'`, die zu `s` kongruent sind, akzeptiert, obwohl sie unterschiedliche Bytefolgen sind. Systeme, die Signaturen als kanonische Tokens behandeln (Blockchain-Consensus, Replay-Caches, DB-Keys usw.), können desynchronisiert werden, weil strikte Implementierungen `s'` ablehnen würden.
- Beim Auditieren anderer HashEdDSA-Implementierungen sicherstellen, dass der Parser sowohl den Punkt `R` als auch die Skalarlänge validiert; versuche, zu einem bekannten gültigen `s` Vielfache von `n` anzuhängen, um zu bestätigen, dass der Verifier geschlossen ablehnt.

### ECDSA truncation vs. leading-zero hashes

- ECDSA-Verifier müssen nur die linksten `log2(n)` Bits des Nachrichtenhashes `H` verwenden. In `elliptic` berechnete der Trunkierungshilfer `delta = (BN(msg).byteLength()*8) - bitlen(n)`; der `BN`-Konstruktor verwirft führende Nulloktette, sodass jeder Hash, der mit ≥4 Nullbytes beginnt (bei Kurven wie secp192r1 mit 192-bit Ordnung), fälschlicherweise als nur 224 Bit anstatt 256 angesehen wurde.
- Der Verifier schob um 32 Bits nach rechts statt um 64, wodurch ein `E` entstand, das nicht zum vom Signierer verwendeten Wert passte. Gültige Signaturen auf solchen Hashes schlagen daher mit Wahrscheinlichkeit ≈`2^-32` für SHA-256-Eingaben fehl.
- Führe sowohl den „alles in Ordnung“-Vektor als auch Varianten mit führenden Nullen (z. B. Wycheproof `ecdsa_secp192r1_sha256_test.json`, Fall `tc296`) gegen eine Zielimplementierung aus; wenn der Verifier vom Signierer abweicht, hast du einen ausnutzbaren Trunkierungsfehler gefunden.

### Wycheproof-Vektoren gegen Libraries testen
- Wycheproof liefert JSON-Testsets, die malformed points, malleable scalars, ungewöhnliche Hashes und andere Randfälle kodieren. Ein Harness um `elliptic` (oder jede crypto library) zu bauen ist unkompliziert: Lade das JSON, deserialisiere jeden Testfall und prüfe, dass die Implementierung mit dem erwarteten `result`-Flag übereinstimmt.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Fehler sollten triagiert werden, um Spezifikationsverletzungen von Fehlalarmen zu unterscheiden. Für die beiden oben genannten Bugs zeigten die fehlschlagenden Wycheproof-Fälle sofort fehlende Skalarbereichsprüfungen (EdDSA) und falsche Hash-Trunkierung (ECDSA) auf.
- Integriere das Test-Harness in die CI, sodass Regressionen beim Skalarparsing, bei der Hash-Verarbeitung oder bei der Gültigkeit von Koordinaten Tests auslösen, sobald sie eingeführt werden. Das ist besonders nützlich für High-Level-Sprachen (JS, Python, Go), in denen subtile bignum-Konvertierungen leicht schiefgehen.

## Referenzen

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
