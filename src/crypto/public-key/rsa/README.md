# RSA-Angriffe

{{#include ../../../banners/hacktricks-training.md}}

## Schnelle Triage

Sammle:

- `n`, `e`, `c` (und alle zusätzlichen Ciphertexts)
- Jegliche Beziehungen zwischen Nachrichten (gleicher Plaintext? gemeinsamer Modulus? strukturierter Plaintext?)
- Jegliche Leaks (partielles `p/q`, Bits von `d`, `dp/dq`, bekanntes Padding)

Versuche anschließend:

- Faktorisierungsprüfung (Factordb / `sage: factor(n)` für eher kleine Werte)
- Muster bei niedrigen Exponenten (`e=3`, Broadcast)
- Common modulus / wiederholte Primzahlen
- Gittermethoden (Coppersmith/LLL), wenn etwas nahezu bekannt ist

## Häufige RSA-Angriffe

### Common modulus

Wenn zwei Ciphertexts `c1, c2` dieselbe **Nachricht** unter demselben **Modulus** `n`, aber mit unterschiedlichen Exponenten `e1, e2` verschlüsseln (und `gcd(e1,e2)=1` gilt), kannst du `m` mithilfe des erweiterten euklidischen Algorithmus wiederherstellen:

`m = c1^a * c2^b mod n`, wobei `a*e1 + b*e2 = 1`.

Beispielablauf:

1. Berechne `(a, b) = xgcd(e1, e2)`, sodass `a*e1 + b*e2 = 1`
2. Falls `a < 0`, interpretiere `c1^a` als `inv(c1)^{-a} mod n` (ebenso für `b`)
3. Multipliziere und reduziere modulo `n`

### Shared primes across moduli

Wenn du mehrere RSA-Moduli aus derselben Challenge hast, prüfe, ob sie eine Primzahl gemeinsam haben:

- `gcd(n1, n2) != 1` weist auf einen katastrophalen Fehler bei der Schlüsselgenerierung hin.

Dies tritt in CTFs häufig als "we generated many keys quickly" oder "bad randomness" auf.

### Sparse / short-sleeve moduli

Einige fehlerhafte Generatoren für große Ganzzahlen leaken die Struktur direkt in den öffentlichen Modulus: Jeder Limb enthält nur ein kleines zufälliges Teilfeld, während die übrigen Bits `0` sind. In der Praxis zeigt sich dies als **regelmäßig verteilte Nullblöcke** über `n`, oft an 32-Bit- oder 128-Bit-Limbs ausgerichtet.<sup>[[1]](#references)</sup>

Schnelle Prüfungen:

- Gib `n` hexadezimal aus und suche nach wiederholten Nullfenstern mit einem festen Abstand.
- Teile `n` erneut in Limbs (`2^32`, `2^64`, `2^128`) auf und prüfe, ob jeder Limb ungewöhnlich klein ist.
- Prüfe öffentliche SSH/TLS-Schlüssel mit Tools wie **badkeys**, wenn du eine schwache Generierung von Host-Keys vermutest.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Dies ist schwerwiegender als ein statistischer Bias: Wenn beide privaten Faktoren `p` und `q` short-sleeved sind, kann der Modulus **leicht zu faktorisieren** sein.<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

Für eine vermutete Limb-Breite `w` schreibe den Modulus zur Basis `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Da die Auswertung multiplikativ ist, gilt `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Wenn die Faktoren ebenfalls sparse Limb-Koeffizienten haben, gilt:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Angriffsschema:

1. Schätze die Limb-Breite `w`.
2. Wandle den öffentlichen Modulus `n` mithilfe der Basis `2^w` in `f_n(x)` um.
3. Faktorisiere `f_n(x)` über den ganzen Zahlen.
4. Werte mögliche Faktoren erneut bei `B = 2^w` aus.
5. Prüfe, welche Kandidaten multipliziert `n` ergeben.

Dies **bricht normales RSA nicht**. Es funktioniert nur, wenn die Primfaktoren selbst sehr kleine, stark strukturierte Limb-Koeffizienten haben.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Die sparse Bytes sind nicht immer am unteren Ende jedes Limbs ausgerichtet. Wenn die direkte Konvertierung zur Basis `2^w` große Koeffizienten erzeugt, suche nach Verschiebungen `i,j`, sodass `2^i p` und `2^j q` in dieser Limb-Basis sparse werden. Das Produktpolynom kann weiterhin aus dem öffentlichen Modulus abgeleitet, faktorisiert und zu den ursprünglichen ganzzahligen Faktoren rekombiniert werden.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

Ein gefährliches Muster besteht darin, die Anzahl der **32-Bit-Limbs** zu berechnen, nur so viele **Bytes** zu reservieren und diese in das Limb-Array zu kopieren:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Dies gibt jedem 32-Bit-Limb nur **8 bits of entropy** sowie ein erzwungenes höchstes Bit im letzten Limb. Die resultierenden RSA-Primzahlen können oft allein anhand des öffentlichen Schlüssels erkannt und faktorisiert werden.<sup>[[1]](#references)</sup>

### Verwandter DSA failure mode

Wenn dieselbe fehlerhafte Big-Integer-Routine zur Erzeugung des privaten DSA-Exponenten wiederverwendet wird, kann der öffentliche Schlüssel `y = g^x` einen **dramatisch verkleinerten und strukturierten** Suchraum für `x` preisgeben. Sobald das Limb-Muster bekannt ist, können Discrete-Log-Angriffe wie **baby-step giant-step** gegen die öffentlichen Parameter praktikabel werden.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Wenn derselbe Klartext mit kleinem `e` (häufig `e=3`) und ohne korrektes Padding an mehrere Empfänger gesendet wird, kannst du `m` über CRT und eine ganzzahlige Wurzel wiederherstellen.

Technische Bedingung:

Wenn du `e` Ciphertexts derselben Nachricht unter paarweise teilerfremden Moduli `n_i` hast:

- Verwende CRT, um `M = m^e` über dem Produkt `N = Π n_i` wiederherzustellen
- Wenn `m^e < N` gilt, ist `M` die echte ganzzahlige Potenz, und `m = integer_root(M, e)`

### Wiener attack: small private exponent

Wenn `d` zu klein ist, können Kettenbrüche den Wert aus `e/n` wiederherstellen.

### Textbook RSA pitfalls

Wenn du Folgendes siehst:

- Kein OAEP/PSS, rohe modulare Exponentiation
- Deterministic encryption

werden algebraische Angriffe und der Missbrauch von Oracles deutlich wahrscheinlicher.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Wenn du zwei Ciphertexts unter demselben Modulus mit algebraisch verwandten Nachrichten siehst (z. B. `m2 = a*m1 + b`), halte Ausschau nach "related-message"-Angriffen wie Franklin–Reiter. Diese erfordern typischerweise:

- denselben Modulus `n`
- denselben Exponenten `e`
- eine bekannte Beziehung zwischen den Klartexten

In der Praxis wird dies häufig mit Sage gelöst, indem Polynome modulo `n` aufgestellt und ein GCD berechnet wird.

## Lattices / Coppersmith

Greife darauf zurück, wenn du über partielle Bits, strukturierten Klartext oder nahe Beziehungen verfügst, die den unbekannten Wert klein machen.

Lattice-Methoden (LLL/Coppersmith) treten immer dann auf, wenn du über Teilinformationen verfügst:

- Teilweise bekannter Klartext (strukturierte Nachricht mit unbekanntem Ende)
- Teilweise bekanntes `p`/`q` (höhere Bits geleakt)
- Kleine unbekannte Unterschiede zwischen verwandten Werten

### What to recognize

Typische Hinweise in Challenges:

- "Wir haben die oberen/unteren Bits von p geleakt"
- "Das Flag ist eingebettet wie: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Wir haben RSA mit einem kleinen zufälligen Padding verwendet"

### Tooling

In der Praxis wirst du Sage für LLL und ein bekanntes Template für die jeweilige Instanz verwenden.

Gute Ausgangspunkte:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Eine Referenz im Stil einer Übersicht: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Faktorisieren von "short-sleeve"-RSA-Schlüsseln mit Polynomen](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [eigenständiges badkeys-Tool](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
