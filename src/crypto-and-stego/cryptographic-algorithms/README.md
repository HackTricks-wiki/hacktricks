# Kryptografische/Kompressionsalgorithmen

{{#include ../../banners/hacktricks-training.md}}

## Identifizierung von Algorithmen

Wenn Sie in einem Code **Rechts- und Linksverschiebungen, Xors und mehrere arithmetische Operationen** verwenden, ist es sehr wahrscheinlich, dass es sich um die Implementierung eines **kryptografischen Algorithmus** handelt. Hier werden einige Möglichkeiten gezeigt, um **den verwendeten Algorithmus zu identifizieren, ohne jeden Schritt umkehren zu müssen**.

### API-Funktionen

**CryptDeriveKey**

Wenn diese Funktion verwendet wird, können Sie herausfinden, welcher **Algorithmus verwendet wird**, indem Sie den Wert des zweiten Parameters überprüfen:

![](<../../images/image (156).png>)

Überprüfen Sie hier die Tabelle der möglichen Algorithmen und deren zugewiesenen Werte: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Komprimiert und dekomprimiert einen gegebenen Datenpuffer.

**CryptAcquireContext**

Aus [den Dokumenten](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Die **CryptAcquireContext**-Funktion wird verwendet, um einen Handle für einen bestimmten Schlüsselcontainer innerhalb eines bestimmten kryptografischen Dienstanbieters (CSP) zu erwerben. **Dieser zurückgegebene Handle wird in Aufrufen von CryptoAPI**-Funktionen verwendet, die den ausgewählten CSP nutzen.

**CryptCreateHash**

Initiiert das Hashing eines Datenstroms. Wenn diese Funktion verwendet wird, können Sie herausfinden, welcher **Algorithmus verwendet wird**, indem Sie den Wert des zweiten Parameters überprüfen:

![](<../../images/image (549).png>)

\
Überprüfen Sie hier die Tabelle der möglichen Algorithmen und deren zugewiesenen Werte: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code-Konstanten

Manchmal ist es wirklich einfach, einen Algorithmus zu identifizieren, da er einen speziellen und einzigartigen Wert verwenden muss.

![](<../../images/image (833).png>)

Wenn Sie die erste Konstante bei Google suchen, erhalten Sie Folgendes:

![](<../../images/image (529).png>)

Daher können Sie annehmen, dass die dekompilierte Funktion ein **sha256-Rechner** ist.\
Sie können jede der anderen Konstanten suchen und Sie werden (wahrscheinlich) dasselbe Ergebnis erhalten.

### Dateninfo

Wenn der Code keine signifikante Konstante hat, könnte er **Informationen aus dem .data-Bereich laden**.\
Sie können auf diese Daten zugreifen, **die erste dword gruppieren** und sie in Google suchen, wie wir es im vorherigen Abschnitt getan haben:

![](<../../images/image (531).png>)

In diesem Fall, wenn Sie nach **0xA56363C6** suchen, können Sie feststellen, dass es mit den **Tabellen des AES-Algorithmus** verbunden ist.

## RC4 **(Symmetrische Kryptografie)**

### Eigenschaften

Es besteht aus 3 Hauptteilen:

- **Initialisierungsphase/**: Erstellt eine **Tabelle von Werten von 0x00 bis 0xFF** (insgesamt 256 Bytes, 0x100). Diese Tabelle wird häufig als **Substitutionsbox** (oder SBox) bezeichnet.
- **Scrambling-Phase**: Wird **durch die zuvor erstellte Tabelle** (Schleife von 0x100 Iterationen, erneut) schleifen und jeden Wert mit **semi-zufälligen** Bytes modifizieren. Um diese semi-zufälligen Bytes zu erstellen, wird der RC4 **Schlüssel verwendet**. RC4 **Schlüssel** können **zwischen 1 und 256 Bytes lang** sein, es wird jedoch normalerweise empfohlen, dass sie mehr als 5 Bytes betragen. Üblicherweise sind RC4-Schlüssel 16 Bytes lang.
- **XOR-Phase**: Schließlich wird der Klartext oder Chiffretext mit den zuvor erstellten Werten **XORed**. Die Funktion zum Verschlüsseln und Entschlüsseln ist dieselbe. Dazu wird eine **Schleife durch die erstellten 256 Bytes** so oft wie nötig durchgeführt. Dies wird normalerweise in einem dekompilierten Code mit einem **%256 (mod 256)** erkannt.

> [!TIP]
> **Um einen RC4 in einem Disassemblierungs-/dekompilierten Code zu identifizieren, können Sie nach 2 Schleifen der Größe 0x100 (unter Verwendung eines Schlüssels) suchen und dann ein XOR der Eingabedaten mit den 256 zuvor in den 2 Schleifen erstellten Werten wahrscheinlich unter Verwendung eines %256 (mod 256)**

### **Initialisierungsphase/Substitutionsbox:** (Beachten Sie die Zahl 256, die als Zähler verwendet wird, und wie eine 0 an jedem Platz der 256 Zeichen geschrieben wird)

![](<../../images/image (584).png>)

### **Scrambling-Phase:**

![](<../../images/image (835).png>)

### **XOR-Phase:**

![](<../../images/image (904).png>)

## **AES (Symmetrische Kryptografie)**

### **Eigenschaften**

- Verwendung von **Substitutionsboxen und Nachschlagetabellen**
- Es ist möglich, **AES anhand der Verwendung spezifischer Nachschlagetablenwerte** (Konstanten) zu unterscheiden. _Beachten Sie, dass die **Konstante** **im Binärformat gespeichert** oder _**dynamisch**_ **erstellt** werden kann._
- Der **Verschlüsselungsschlüssel** muss **durch 16** (normalerweise 32B) **teilbar** sein, und normalerweise wird ein **IV** von 16B verwendet.

### SBox-Konstanten

![](<../../images/image (208).png>)

## Serpent **(Symmetrische Kryptografie)**

### Eigenschaften

- Es ist selten, Malware zu finden, die es verwendet, aber es gibt Beispiele (Ursnif)
- Einfach zu bestimmen, ob ein Algorithmus Serpent ist oder nicht, basierend auf seiner Länge (extrem lange Funktion)

### Identifizierung

In der folgenden Abbildung beachten Sie, wie die Konstante **0x9E3779B9** verwendet wird (beachten Sie, dass diese Konstante auch von anderen Krypto-Algorithmen wie **TEA** -Tiny Encryption Algorithm verwendet wird).\
Beachten Sie auch die **Größe der Schleife** (**132**) und die **Anzahl der XOR-Operationen** in den **Disassemblierungs**-Anweisungen und im **Code**-Beispiel:

![](<../../images/image (547).png>)

Wie bereits erwähnt, kann dieser Code in jedem Decompiler als **sehr lange Funktion** visualisiert werden, da es **keine Sprünge** darin gibt. Der dekompilierte Code kann wie folgt aussehen:

![](<../../images/image (513).png>)

Daher ist es möglich, diesen Algorithmus zu identifizieren, indem man die **magische Zahl** und die **initialen XORs** überprüft, eine **sehr lange Funktion** sieht und einige **Anweisungen** der langen Funktion **mit einer Implementierung** (wie der Linksverschiebung um 7 und der Linksrotation um 22) vergleicht.

## RSA **(Asymmetrische Kryptografie)**

### Eigenschaften

- Komplexer als symmetrische Algorithmen
- Es gibt keine Konstanten! (benutzerdefinierte Implementierungen sind schwer zu bestimmen)
- KANAL (ein Krypto-Analyzer) kann keine Hinweise auf RSA zeigen, da er auf Konstanten angewiesen ist.

### Identifizierung durch Vergleiche

![](<../../images/image (1113).png>)

- In Zeile 11 (links) gibt es ein `+7) >> 3`, das dasselbe ist wie in Zeile 35 (rechts): `+7) / 8`
- Zeile 12 (links) überprüft, ob `modulus_len < 0x040` und in Zeile 36 (rechts) wird überprüft, ob `inputLen+11 > modulusLen`

## MD5 & SHA (Hash)

### Eigenschaften

- 3 Funktionen: Init, Update, Final
- Ähnliche Initialisierungsfunktionen

### Identifizieren

**Init**

Sie können beide identifizieren, indem Sie die Konstanten überprüfen. Beachten Sie, dass die sha_init eine Konstante hat, die MD5 nicht hat:

![](<../../images/image (406).png>)

**MD5 Transform**

Beachten Sie die Verwendung von mehr Konstanten

![](<../../images/image (253) (1) (1).png>)

## CRC (Hash)

- Kleiner und effizienter, da seine Funktion darin besteht, zufällige Änderungen in Daten zu finden
- Verwendet Nachschlagetabellen (so können Sie Konstanten identifizieren)

### Identifizieren

Überprüfen Sie **Nachschlagetabellenkonstanten**:

![](<../../images/image (508).png>)

Ein CRC-Hash-Algorithmus sieht wie folgt aus:

![](<../../images/image (391).png>)

## APLib (Kompression)

### Eigenschaften

- Nicht erkennbare Konstanten
- Sie können versuchen, den Algorithmus in Python zu schreiben und nach ähnlichen Dingen online zu suchen

### Identifizieren

Das Diagramm ist ziemlich groß:

![](<../../images/image (207) (2) (1).png>)

Überprüfen Sie **3 Vergleiche, um ihn zu erkennen**:

![](<../../images/image (430).png>)

{{#include ../../banners/hacktricks-training.md}}
