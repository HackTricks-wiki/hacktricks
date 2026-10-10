# RSA-Angriffe

{{#include ../../../banners/hacktricks-training.md}}

## Schnelle Triage

Sammle:

- `n`, `e`, `c` (und alle weiteren Ciphertexts)
- Alle Beziehungen zwischen Nachrichten (gleicher Plaintext? Gemeinsamer Modulus? Strukturierter Plaintext?)
- Alle Leaks (`p/q`-Teilwerte, Bits von `d`, `dp/dq`, bekanntes Padding)

Versuche dann:

- Faktorisierungsprüfung (Factordb / `sage: factor(n)` bei eher kleinen Werten)
- Muster bei kleinen Exponenten (`e=3`, Broadcast)
- Common modulus / wiederholte Primzahlen
- Lattice-Methoden (Coppersmith/LLL), wenn etwas fast bekannt ist

## Gängige RSA-Angriffe

### Common modulus

Wenn zwei Ciphertexts `c1, c2` dieselbe **Nachricht** mit unterschiedlichen Exponenten `e1, e2` (und `gcd(e1,e2)=1`) unter demselben **Modulus** `n` verschlüsseln, kannst du `m` mithilfe des erweiterten euklidischen Algorithmus wiederherstellen:

`m = c1^a * c2^b mod n` wobei `a*e1 + b*e2 = 1`.

Beispielablauf:

1. Berechne `(a, b) = xgcd(e1, e2)`, sodass `a*e1 + b*e2 = 1`
2. Wenn `a < 0`, interpretiere `c1^a` als `inv(c1)^{-a} mod n` (dasselbe gilt für `b`)
3. Multipliziere die Werte und bilde den Rest modulo `n`

### Gemeinsame Primfaktoren mehrerer Moduli

Wenn du mehrere RSA-Moduli aus derselben Challenge hast, prüfe, ob sie einen Primfaktor gemeinsam haben:

- `gcd(n1, n2) != 1` weist auf einen katastrophalen Fehler bei der Schlüsselerzeugung hin.

Das kommt in CTFs häufig vor, etwa bei Aussagen wie „wir haben schnell viele Schlüssel erzeugt“ oder „schlechte Zufallswerte“.

### Sparse / short-sleeve-Moduli

Manche fehlerhaften Big-Integer-Generatoren leaken Strukturen direkt in den öffentlichen Modulus: Jeder Limb enthält nur ein kleines zufälliges Teilfeld, während die restlichen Bits `0` sind. In der Praxis zeigt sich das oft in **regelmäßig verteilten Nullblöcken** in `n`, die häufig an 32-Bit- oder 128-Bit-Limbs ausgerichtet sind.<sup>[[1]](#references)</sup>

Schnellprüfungen:

- Gib `n` in Hexadezimaldarstellung aus und suche nach wiederholten Nullbereichen mit festem Abstand.
- Teile `n` erneut in Limbs (`2^32`, `2^64`, `2^128`) auf und prüfe, ob jeder Limb ungewöhnlich klein ist.
- Prüfe öffentliche SSH/TLS-Schlüssel mit Tools wie **badkeys**, wenn du eine schwache Erzeugung von Host-Schlüsseln vermutest.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Das ist schwerwiegender als eine statistische Verzerrung: Wenn beide privaten Faktoren `p` und `q` short-sleeve sind, lässt sich der Modulus möglicherweise **leicht faktorisieren**.<sup>[[1]](#references)</sup>

### Polynomfaktorisierung strukturierter RSA-Schlüssel

Schreibe den Modulus für eine vermutete Limb-Breite `w` zur Basis `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Da die Auswertung multiplikativ ist, gilt `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Wenn die Faktoren außerdem dünn besetzte Limb-Koeffizienten haben, gilt:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Angriffsablauf:

1. Rate die Limb-Breite `w`.
2. Wandle den öffentlichen Modulus `n` mithilfe der Basis `2^w` in `f_n(x)` um.
3. Faktorisiere `f_n(x)` über den ganzen Zahlen.
4. Werte die Kandidatenfaktoren wieder bei `B = 2^w` aus.
5. Prüfe, welche Kandidaten miteinander multipliziert `n` ergeben.

Das **bricht kein normales RSA**. Es funktioniert nur, wenn die Primfaktoren selbst sehr kleine, stark strukturierte Limb-Koeffizienten haben.<sup>[[1]](#references)</sup>

### Verschobenes Limb-Leakage

Die dünn besetzten Bytes sind nicht immer am unteren Ende jedes Limbs ausgerichtet. Wenn die direkte Umwandlung zur Basis `2^w` große Koeffizienten ergibt, suche nach Verschiebungen `i,j`, sodass `2^i p` und `2^j q` in dieser Limb-Basis dünn besetzt sind. Das Produktpolynom lässt sich weiterhin aus dem öffentlichen Modulus ableiten, faktorisieren und zu den ursprünglichen ganzzahligen Faktoren zusammensetzen.<sup>[[1]](#references)</sup>

### Implementierungswarnsignal: Byte-zu-Limb-RNG-Fehler

Ein gefährliches Muster ist, die Anzahl der **32-Bit-Limbs** zu berechnen, nur so viele **Bytes** zu reservieren und diese in das Limb-Array zu kopieren:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

This gibt jedem 32-Bit-Limb nur **8 Bits Entropie** sowie ein erzwungenes höchstes Bit im letzten Limb. Die resultierenden RSA-Primzahlen lassen sich oft allein anhand des öffentlichen Schlüssels erkennen und faktorisieren.<sup>[[1]](#references)</sup>

### Verwandter DSA-Fehlermodus

Wenn dieselbe fehlerhafte Big-Integer-Routine zur Generierung des privaten DSA-Exponenten wiederverwendet wird, kann der öffentliche Schlüssel `y = g^x` einen **drastisch verkleinerten und strukturierten** Suchraum für `x` offenlegen. Sobald das Limb-Muster bekannt ist, können diskrete Logarithmus-Angriffe wie **baby-step giant-step** bei den öffentlichen Parametern praktikabel werden.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Wenn dieselbe Nachricht ohne korrektes Padding an mehrere Empfänger mit kleinem `e` (oft `e=3`) gesendet wird, kannst du `m` mithilfe von CRT und einer ganzzahligen Wurzel wiederherstellen.

Technische Voraussetzung:

Wenn du `e` Chiffretexte derselben Nachricht unter paarweise teilerfremden Moduli `n_i` hast:

- Verwende CRT, um `M = m^e` über dem Produkt `N = Π n_i` wiederherzustellen
- Wenn `m^e < N`, dann ist `M` die tatsächliche ganzzahlige Potenz, und `m = integer_root(M, e)`

### Wiener-Angriff: kleiner privater Exponent

Wenn `d` zu klein ist, können Kettenbrüche ihn aus `e/n` wiederherstellen.

### Fallstricke bei Textbook RSA

Wenn du Folgendes siehst:

- Kein OAEP/PSS, rohe modulare Exponentiation
- Deterministische Verschlüsselung

dann werden algebraische Angriffe und der Missbrauch von Oracles deutlich wahrscheinlicher.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, Wurzeln, Kettenbrüche): https://www.sagemath.org/

## Muster bei Related-Message-Angriffen

Wenn du zwei Chiffretexte unter demselben Modulus siehst, deren Nachrichten algebraisch miteinander verknüpft sind (z. B. `m2 = a*m1 + b`), suche nach Related-Message-Angriffen wie Franklin–Reiter. Diese erfordern typischerweise:

- denselben Modulus `n`
- denselben Exponenten `e`
- eine bekannte Beziehung zwischen den Klartexten

In der Praxis löst man dies oft mit Sage, indem man Polynome modulo `n` aufstellt und einen GCD berechnet.

## Gitter / Coppersmith

Greife darauf zurück, wenn du Teilbits, strukturierten Klartext oder nahe Beziehungen hast, durch die der unbekannte Wert klein ist.

Gittermethoden (LLL/Coppersmith) kommen immer dann zum Einsatz, wenn Teilinformationen vorliegen:

- Teilweise bekannter Klartext (strukturierte Nachricht mit unbekanntem Ende)
- Teilweise bekanntes `p`/`q` (höhere Bits geleakt)
- Kleine unbekannte Differenzen zwischen verwandten Werten

### Woran du es erkennst

Typische Hinweise in Challenges:

- „Wir haben die oberen/unteren Bits von p geleakt“
- „Das Flag ist eingebettet wie: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`“
- „Wir haben RSA mit einem kleinen zufälligen Padding verwendet“

### Tools

In der Praxis verwendest du Sage für LLL und ein bekanntes Template für den jeweiligen Fall.

Gute Ausgangspunkte:

- Sage-CTF-Krypto-Templates: https://github.com/defund/coppersmith
- Eine Übersicht als Referenz: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Faktorisierung von „short-sleeve“-RSA-Schlüsseln mit Polynomen](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys-Standalone-Tool](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

