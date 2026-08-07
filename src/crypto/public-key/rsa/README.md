# RSA-Angriffe

{{#include ../../../banners/hacktricks-training.md}}

## Schnelle Triage

Sammle:

- `n`, `e`, `c` (sowie alle zusätzlichen Ciphertexts)
- Alle Beziehungen zwischen Nachrichten (gleicher Plaintext? gemeinsamer Modulus? strukturierter Plaintext?)
- Alle Leaks (teilweises `p/q`, Bits von `d`, `dp/dq`, bekanntes Padding)

Dann versuche:

- Faktorisierungsprüfung (Factordb / `sage: factor(n)` für kleinere Werte)
- Patterns bei kleinen Exponenten (`e=3`, Broadcast)
- Common modulus / wiederverwendete Primzahlen
- Lattice methods (Coppersmith/LLL), wenn etwas beinahe bekannt ist

## Häufige RSA-Angriffe

### Common modulus

Wenn zwei Ciphertexts `c1, c2` dieselbe **Nachricht** unter demselben **Modulus** `n`, aber mit unterschiedlichen Exponenten `e1, e2` verschlüsseln (und `gcd(e1,e2)=1` gilt), kannst du `m` mithilfe des erweiterten euklidischen Algorithmus wiederherstellen:

`m = c1^a * c2^b mod n`, wobei `a*e1 + b*e2 = 1`.

Beispielablauf:

1. Berechne `(a, b) = xgcd(e1, e2)`, sodass `a*e1 + b*e2 = 1`
2. Falls `a < 0`, interpretiere `c1^a` als `inv(c1)^{-a} mod n` (dasselbe gilt für `b`)
3. Multipliziere und reduziere modulo `n`

### Gemeinsame Primzahlen über mehrere Moduli

Wenn du mehrere RSA-Moduli aus derselben Challenge hast, prüfe, ob sie eine Primzahl gemeinsam haben:

- `gcd(n1, n2) != 1` bedeutet einen katastrophalen Fehler bei der Schlüsselerzeugung.

Dies tritt in CTFs häufig als Folge von "we generated many keys quickly" oder "bad randomness" auf.

### Sparse / short-sleeve-Moduli

Einige fehlerhafte Big-Integer-Generatoren leaken die Struktur direkt in den öffentlichen Modulus: Jeder Limb enthält nur ein kleines zufälliges Subfeld, während die übrigen Bits `0` sind. In der Praxis zeigt sich dies als **regelmäßig verteilte Nullblöcke** über `n`, häufig an 32-Bit- oder 128-Bit-Limbs ausgerichtet.<sup>[[1]](#references)</sup>

Schnelle Prüfungen:

- Gib `n` in Hexadezimaldarstellung aus und suche nach wiederholten Nullfenstern mit einem festen Abstand.
- Teile `n` erneut in Limbs (`2^32`, `2^64`, `2^128`) auf und prüfe, ob jeder Limb ungewöhnlich klein ist.
- Prüfe öffentliche SSH/TLS-Schlüssel mit Tools wie **badkeys**, wenn du eine schwache Generierung von Host-Keys vermutest.<sup>[[2]](#references)[[3]](#references)</sup>

Dies ist schwerwiegender als ein statistischer Bias: Wenn beide privaten Faktoren `p` und `q` short-sleeved sind, kann der Modulus **leicht zu faktorisieren** sein.<sup>[[1]](#references)</sup>

### Polynomiale Faktorisierung strukturierter RSA-Schlüssel

Für eine vermutete Limb-Breite `w` schreibe den Modulus zur Basis `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Da die Auswertung multiplikativ ist, gilt `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Wenn die Faktoren ebenfalls sparse Limb-Koeffizienten besitzen, gilt:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Angriffsschritte:

1. Rate die Limb-Breite `w`.
2. Wandle den öffentlichen Modulus `n` mithilfe der Basis `2^w` in `f_n(x)` um.
3. Faktorisiere `f_n(x)` über den ganzen Zahlen.
4. Werte die möglichen Faktoren wieder bei `B = 2^w` aus.
5. Überprüfe, welche Kandidaten multipliziert `n` ergeben.

Dies **bricht kein normales RSA**. Es funktioniert nur, wenn die Primfaktoren selbst sehr kleine, stark strukturierte Limb-Koeffizienten besitzen.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Die sparsamen Bytes sind nicht immer am unteren Ende jedes Limbs ausgerichtet. Wenn die direkte Umwandlung zur Basis `2^w` große Koeffizienten erzeugt, suche nach Verschiebungen `i,j`, sodass `2^i p` und `2^j q` in dieser Limb-Basis sparse werden. Das Produktpolynom kann weiterhin aus dem öffentlichen Modulus abgeleitet, faktorisiert und zu den ursprünglichen ganzzahligen Faktoren zusammengesetzt werden.<sup>[[1]](#references)</sup>

### Implementation smell: Byte-zu-Limb-RNG-Bug

Ein gefährliches Pattern besteht darin, die Anzahl der **32-Bit-Limbs** zu berechnen, nur so viele **Bytes** zu allozieren und diese in das Limb-Array zu kopieren:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Dies gibt jedem 32-Bit-Limb nur **8 Bits Entropie** sowie ein erzwungenes höchstes Bit im letzten Limb. Die resultierenden RSA-Primzahlen können oft allein aus dem Public Key erkannt und faktorisiert werden.<sup>[[1]](#references)</sup>

### Verwandter DSA-Fehlermodus

Wenn dieselbe fehlerhafte Big-Integer-Routine zur Generierung des privaten DSA-Exponenten wiederverwendet wird, kann der Public Key `y = g^x` einen **drastisch verkleinerten und strukturierten** Suchraum für `x` leaken. Sobald das Limb-Muster bekannt ist, können Discrete-Log-Angriffe wie **baby-step giant-step** gegen die öffentlichen Parameter praktikabel werden.<sup>[[1]](#references)</sup>

### Håstad broadcast / kleiner Exponent

Wenn derselbe Plaintext ohne korrektes Padding an mehrere Empfänger mit kleinem `e` (häufig `e=3`) gesendet wird, kann man `m` über CRT und eine ganzzahlige Wurzel wiederherstellen.

Technische Bedingung:

Wenn du `e` Ciphertexts derselben Nachricht unter paarweise teilerfremden Moduli `n_i` hast:

- Verwende CRT, um `M = m^e` über dem Produkt `N = Π n_i` wiederherzustellen
- Wenn `m^e < N`, ist `M` die echte ganzzahlige Potenz und `m = integer_root(M, e)`

### Wiener attack: kleiner privater Exponent

Wenn `d` zu klein ist, können Kettenbrüche den Wert aus `e/n` wiederherstellen.

### Fallstricke bei Textbook RSA

Wenn du Folgendes siehst:

- Kein OAEP/PSS, rohe modulare Exponentiation
- Deterministische Verschlüsselung

dann werden algebraische Angriffe und der Missbrauch von Oracles deutlich wahrscheinlicher.

### Werkzeuge

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, Wurzeln, CF): https://www.sagemath.org/

## Verwandte-Message-Muster

Wenn du zwei Ciphertexts unter demselben Modulus mit algebraisch verwandten Nachrichten siehst (z. B. `m2 = a*m1 + b`), solltest du nach "related-message"-Angriffen wie Franklin–Reiter suchen. Diese erfordern typischerweise:

- denselben Modulus `n`
- denselben Exponenten `e`
- eine bekannte Beziehung zwischen den Plaintexts

In der Praxis wird dies häufig mit Sage gelöst, indem Polynome modulo `n` aufgestellt und ein GCD berechnet wird.

## Lattices / Coppersmith

Greife darauf zurück, wenn du teilweise bekannte Bits, strukturierten Plaintext oder enge Beziehungen hast, durch die der unbekannte Wert klein wird.

Lattice-Methoden (LLL/Coppersmith) treten immer dann auf, wenn du über teilweise Informationen verfügst:

- Teilweise bekannter Plaintext (strukturierte Nachricht mit unbekanntem Suffix)
- Teilweise bekanntes `p`/`q` (höherwertige Bits geleakt)
- Kleine unbekannte Differenzen zwischen verwandten Werten

### Was du erkennen solltest

Typische Hinweise in Challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

In der Praxis wirst du Sage für LLL und ein bekanntes Template für die jeweilige Instanz verwenden.

Gute Ausgangspunkte:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Eine Referenz im Stil einer Übersicht: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## Referenzen

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
