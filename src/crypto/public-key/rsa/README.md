# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

Sammle:

- `n`, `e`, `c` (und alle zusätzlichen ciphertexts)
- Jegliche Beziehungen zwischen Messages (gleicher plaintext? shared modulus? strukturierter plaintext?)
- Jegliche leaks (partielle `p/q`, Bits von `d`, `dp/dq`, bekanntes padding)

Dann probiere:

- Faktorisierungs-Check (Factordb / `sage: factor(n)` für etwas kleinere)
- Niedrige Exponentenmuster (`e=3`, broadcast)
- Common modulus / wiederholte Primzahlen
- Lattice-Methoden (Coppersmith/LLL), wenn etwas fast bekannt ist

## Common RSA attacks

### Common modulus

Wenn zwei ciphertexts `c1, c2` dieselbe Message unter demselben Modulus `n` verschlüsseln, aber mit unterschiedlichen Exponenten `e1, e2` (und `gcd(e1,e2)=1`), kannst du `m` mit dem erweiterten euklidischen Algorithmus zurückgewinnen:

`m = c1^a * c2^b mod n` wobei `a*e1 + b*e2 = 1`.

Beispielablauf:

1. Berechne `(a, b) = xgcd(e1, e2)`, sodass `a*e1 + b*e2 = 1`
2. Wenn `a < 0`, interpretiere `c1^a` als `inv(c1)^{-a} mod n` (gleiches für `b`)
3. Multipliziere und reduziere modulo `n`

### Shared primes across moduli

Wenn du mehrere RSA-Moduli aus derselben Challenge hast, prüfe, ob sie eine Primzahl teilen:

- `gcd(n1, n2) != 1` impliziert einen katastrophalen Fehler bei der Key-Generierung.

Das taucht in CTFs oft auf als „wir haben schnell viele Keys erzeugt“ oder „bad randomness“.

### Sparse / short-sleeve moduli

Manche kaputten Big-Integer-Generatoren leaken Struktur direkt in das öffentliche Modulus: Jeder limb enthält nur ein kleines zufälliges Teilfeld, und der Rest der Bits ist `0`. In der Praxis zeigt sich das als **regelmäßig verteilte Nullblöcke** über `n`, oft auf 32-bit- oder 128-bit-limbs ausgerichtet.

Schnelle Checks:

- Gib `n` in hex aus und suche nach wiederholten Nullfenstern mit festem Abstand.
- Schneide `n` als limbs neu zu (`2^32`, `2^64`, `2^128`) und prüfe, ob jeder limb ungewöhnlich klein ist.
- Prüfe öffentliche SSH/TLS-Keys mit Tools wie **badkeys**, wenn du schwache Host-Key-Generierung vermutest.

Das ist ernster als ein statistischer Bias: Wenn beide privaten Faktoren `p` und `q` short-sleeved sind, kann das Modulus **leicht zu faktorisieren** werden.

### Polynomial factorization of structured RSA keys

Für eine vermutete limb-Breite `w`, schreibe das Modulus in Basis `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Da Evaluation multiplikativ ist, gilt `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Wenn die Faktoren ebenfalls sparse limb-Koeffizienten haben, dann:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack outline:

1. Rate die limb-Breite `w`.
2. Konvertiere das öffentliche Modulus `n` in `f_n(x)` mit Basis `2^w`.
3. Faktorisiere `f_n(x)` über den ganzen Zahlen.
4. Werte die Kandidatenfaktoren wieder bei `B = 2^w` aus.
5. Verifiziere, welche Kandidaten zu `n` multiplizieren.

Das **bricht kein normales RSA**. Es funktioniert nur, wenn die Primfaktoren selbst sehr kleine, stark strukturierte limb-Koeffizienten haben.

### Shifted limb leakage

Die sparse Bytes sind nicht immer am unteren Ende jedes limb ausgerichtet. Wenn die direkte Base-`2^w`-Konvertierung große Koeffizienten erzeugt, suche nach Shifts `i,j`, sodass `2^i p` und `2^j q` in dieser limb-Basis sparse werden. Das Produktpolynom kann trotzdem aus dem öffentlichen Modulus abgeleitet, faktorisiert und wieder zu den ursprünglichen ganzzahligen Faktoren zusammengesetzt werden.

### Implementation smell: byte-to-limb RNG bug

Ein gefährliches Muster ist, die Anzahl der **32-bit limbs** zu berechnen, nur so viele **bytes** zu allozieren und sie dann in das limb-Array zu kopieren:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Dies gibt jedem 32-bit-Limb nur **8 Bits Entropie** plus ein erzwungenes Top-Bit im letzten Limb. Die resultierenden RSA-Primzahlen können oft direkt am public key erkannt und nur aus dem public key allein faktorisiert werden.

### Related DSA failure mode

Wenn dieselbe defekte Big-Integer-Routine für die DSA private exponent generation wiederverwendet wird, kann der public key `y = g^x` einen **dramatisch reduzierten und strukturierten** Suchraum für `x` preisgeben. Sobald das Limb-Muster bekannt ist, können discrete-log attacks wie **baby-step giant-step** gegen die öffentlichen Parameter praktisch werden.

### Håstad broadcast / low exponent

Wenn derselbe plaintext an mehrere Empfänger mit kleinem `e` (oft `e=3`) und ohne korrektes padding gesendet wird, kannst du `m` via CRT und integer root wiederherstellen.

Technische Bedingung:

Wenn du `e` ciphertexts derselben Nachricht unter paarweise koprimierten Moduli `n_i` hast:

- Verwende CRT, um `M = m^e` über das Produkt `N = Π n_i` wiederherzustellen
- Wenn `m^e < N`, dann ist `M` die echte ganzzahlige Potenz, und `m = integer_root(M, e)`

### Wiener attack: small private exponent

Wenn `d` zu klein ist, können continued fractions es aus `e/n` rekonstruieren.

### Textbook RSA pitfalls

Wenn du Folgendes siehst:

- Kein OAEP/PSS, rohe modulare Exponentiation
- Deterministische encryption

dann werden algebraic attacks und oracle abuse viel wahrscheinlicher.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Wenn du zwei ciphertexts unter demselben modulus mit messages siehst, die algebraisch verwandt sind (z. B. `m2 = a*m1 + b`), suche nach "related-message"-Attacks wie Franklin–Reiter. Diese erfordern typischerweise:

- derselbe modulus `n`
- derselbe exponent `e`
- bekannte Beziehung zwischen plaintexts

In der Praxis wird das oft mit Sage gelöst, indem man Polynome modulo `n` aufsetzt und einen GCD berechnet.

## Lattices / Coppersmith

Setze das ein, wenn du partielle Bits, structured plaintext oder enge Beziehungen hast, die das Unbekannte klein machen.

Lattice-Methoden (LLL/Coppersmith) tauchen immer dann auf, wenn du partielle Informationen hast:

- Teilweise bekannter plaintext (structured message mit unbekanntem Tail)
- Teilweise bekanntes `p`/`q` (High-Bits geleakt)
- Kleine unbekannte Differenzen zwischen verwandten Werten

### What to recognize

Typische Hinweise in Challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

In der Praxis verwendest du Sage für LLL und ein bekanntes Template für die spezifische Instanz.

Gute Startpunkte:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Eine referenzartige Übersicht: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
