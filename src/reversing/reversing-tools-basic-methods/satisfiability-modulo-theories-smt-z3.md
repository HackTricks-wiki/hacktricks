# Im Wesentlichen hilft uns dieses Tool dabei, Werte für Variablen zu finden, die bestimmte Bedingungen erfüllen müssen. Diese von Hand zu berechnen, wäre ziemlich mühsam. Daher können Sie Z3 die Bedingungen mitteilen, die die Variablen erfüllen müssen, und Z3 findet passende Werte (falls möglich).

{{#include ../../banners/hacktricks-training.md}}

# Grundlegende Operationen

## Boolesche Werte/Und/Oder/Nicht

```python
# pip3 install z3-solver
from z3 import *

s = Solver() # The solver will be given the conditions

x = Bool("x") # Declare the symbols x, y and z
y = Bool("y")
z = Bool("z")

# (x or y or !z) and y
s.add(And(Or(x, y, Not(z)), y))
s.check() # If response is "sat" then the model is satisfiable, if "unsat" something is wrong
print(s.model()) # Print valid values to satisfy the model
```

## Ints/Simplify/Reals

```python
from z3 import *

x = Int('x')
y = Int('y')

# Simplify a "complex" equation
print(simplify(And(x + 1 >= 3, x**2 + x**2 + y**2 + 2 >= 5)))
# And(x >= 2, 2*x**2 + y**2 >= 3)

# Note that Z3 is capable of treating irrational numbers
# (an irrational algebraic number is a root of a polynomial with integer coefficients).
# Internally, Z3 represents all these numbers precisely.
r1 = Real('r1')
r2 = Real('r2')

# Solve the equation
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))

# Solve the equation with 30 decimals
set_option(precision=30)
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))
```

## Druckmodell

```python
from z3 import *

x, y, z = Reals('x y z')
s = Solver()
s.add(x > 1, y > 1, x + y > 3, z - x < 10)
s.check()

m = s.model()
print("x = %s" % m[x])
for d in m.decls():
    print("%s = %s" % (d.name(), m[d]))
```

# Maschinenarithmetik

Moderne CPUs und gängige Programmiersprachen verwenden Arithmetik über Bit-Vektoren fester Größe. In Z3Py ist Maschinenarithmetik als Bit-Vectors verfügbar.

```python
from z3 import *

x = BitVec('x', 16) # Bit vector variable "x" of length 16 bits
y = BitVec('y', 16)
e = BitVecVal(10, 16) # Bit vector with value 10 of length 16 bits
a = BitVecVal(-1, 16)
b = BitVecVal(65535, 16)
print(simplify(a == b)) # This is True!

a = BitVecVal(-1, 32)
b = BitVecVal(65535, 32)
print(simplify(a == b)) # This is False
```

## Vorzeichenbehaftete/vorzeichenlose Zahlen

Z3 stellt spezielle vorzeichenbehaftete Versionen arithmetischer Operationen bereit, bei denen es einen Unterschied macht, ob der Bit-Vektor als vorzeichenbehaftet oder vorzeichenlos behandelt wird. In Z3Py entsprechen die Operatoren `<`, `<=`, `>`, `>=`, `/`, `%` und `>>` den vorzeichenbehafteten Versionen. Die entsprechenden vorzeichenlosen Operatoren sind `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` und `LShR`.<sup>[[1]](#references)</sup>

```python
from z3 import *

# Create two bit-vectors of size 32
x, y = BitVecs('x y', 32)
solve(x + y == 2, x > 0, y > 0)

# Bit-wise operators
# & bit-wise and
# | bit-wise or
# ~ bit-wise not
solve(x & y == ~y)
solve(x < 0)

# Using unsigned version of <
solve(ULT(x, 0))
```

## Funktionen

Interpretierte Funktionen wie arithmetische Funktionen haben eine feste Standardinterpretation. Nicht interpretierte Funktionen und Konstanten sind maximal flexibel; sie erlauben jede Interpretation, die mit den Einschränkungen für die Funktion oder Konstante vereinbar ist.<sup>[[1]](#references)</sup>

Beispiel: `f` zweimal auf `x` angewendet ergibt wieder `x`, aber einmal auf `x` angewendetes `f` ist nicht gleich `x`.

```python
from z3 import *

x = Int('x')
y = Int('y')
f = Function('f', IntSort(), IntSort())
s = Solver()
s.add(f(f(x)) == x, f(x) == y, x != y)
s.check()
m = s.model()
print("f(f(x)) =", m.evaluate(f(f(x))))
print("f(x)    =", m.evaluate(f(x)))

print(m.evaluate(f(2)))
s.add(f(x) == 4) # Find the value that generates 4 as response
s.check()
print(s.model())
```

# Auf Reversing ausgerichtete Muster

Wenn du statt nur einiger weniger Prüfungen manuell zu übertragen eine vollständige symbolische Ausführung einer Binärdatei benötigst, schau dir [Angr - Examples](angr/angr-examples.md) an. In der Praxis besteht ein sehr gängiger Workflow darin, die relevanten Prädikate aus dem Decompiler/Assembly zu ermitteln und in Z3 nur die interessanten arithmetischen oder speicherbezogenen Constraints nachzubilden.

## Vom Benutzer kontrollierte Daten zunächst als Bytes modellieren

Beim Reversing ist es normalerweise besser, für jedes Eingabebyte mit `BitVec(..., 8)` zu beginnen und anschließend die Wörter genau so zusammenzusetzen, wie es das Zielprogramm tut. So bleiben Wrap-around, Vorzeichenfehler, Shifts, Rotationen und Byte-Reihenfolge-Probleme erhalten.<sup>[[2]](#references)</sup>

```python
from z3 import *

b0, b1, b2, b3 = BitVecs('b0 b1 b2 b3', 8)
dword = Concat(b3, b2, b1, b0) # bytes -> little-endian uint32

s = Solver()
s.add(b0 == ord('A'), b1 == ord('B'), b2 == ord('C'), b3 == ord('D'))
s.add(Extract(15, 0, dword) == 0x4241)
s.add(RotateRight(dword, 8) == 0x41444342)

print(s.check())
print(hex(s.model().eval(dword).as_long()))
```

Nützliche Hilfsfunktionen beim Übersetzen von Assembly- oder Decompiler-Code:

- `Concat`: 16-/32-/64-Bit-Werte aus Bytes rekonstruieren
- `Extract`: High-/Low-Wörter vergleichen oder Masks/Shifts nachbilden
- `ZeroExt` / `SignExt`: Zero-/Sign-Extension-Fehler korrekt modellieren
- `LShR` / `RotateLeft` / `RotateRight`: häufig in Crackmes, Hashes und Obfuskatoren

## Speicher-/Registertabellen mit Arrays modellieren

Wenn eine Prüfung von `buf[i]`, Lookup-Tabellen oder emuliertem Speicher abhängt, kann `Array` übersichtlicher sein, als Dutzende separate Variablen zu erstellen.<sup>[[3]](#references)</sup>

```python
from z3 import *

mem = Array('mem', BitVecSort(32), BitVecSort(8))
mem = Store(mem, BitVecVal(0x1000, 32), BitVecVal(0x41, 8))
mem = Store(mem, BitVecVal(0x1001, 32), BitVecVal(0x42, 8))

word = Concat(
    Select(mem, BitVecVal(0x1001, 32)),
    Select(mem, BitVecVal(0x1000, 32))
)

s = Solver()
s.add(word == 0x4241)
print(s.check())
```

Das ist besonders hilfreich, wenn das Binary Werte im Speicher kopiert, bevor es sie validiert, oder wenn du die Wirkung einiger `mov`-/`xor`-/`add`-Operationen modellieren möchtest, ohne das ganze Programm auszuführen.

## Inkrementelles Solving eignet sich hervorragend zur Bewertung von Branches

Wenn du die Basisbedingungen bereits extrahiert hast, kannst du `push()` / `pop()` (oder Annahmen) verwenden, um alternative Branches zu testen, ohne den Solver jedes Mal neu aufzubauen:<sup>[[3]](#references)</sup>

```python
from z3 import *

x = BitVec('x', 32)
s = Solver()
s.add(x & 0xff == 0x41)

s.push()
s.add(x > 0x1000)
print("branch 1:", s.check())
s.pop()

s.push()
s.add(x < 0x100)
print("branch 2:", s.check())
s.pop()
```

Dies ist nützlich, wenn du aus einem Decompiler gewonnene Pfadbedingungen erneut abspielst oder schnell herausfinden möchtest, welcher Vergleich das Modell `unsat` macht.

## Für besser nutzbare Payloads optimieren

Sobald ein Modell erfüllbar ist, kann `Optimize()` dir helfen, eine besser nutzbare Lösung zu erhalten: Du kannst zum Beispiel druckbare Bytes bevorzugen, eine Prüfsummenkomponente minimieren oder eine Struktur maximieren, die das rekonstruierte Passwort leichter eintippen oder kopieren lässt.<sup>[[3]](#references)</sup>

```python
from z3 import *

key = [BitVec(f'k{i}', 8) for i in range(6)]
o = Optimize()
for c in key:
    o.add(c != 0)
    o.add_soft(And(c >= 0x20, c <= 0x7e))

print(o.check())
print(bytes(o.model()[c].as_long() for c in key))
```

## Strings/Sequenzen für formatlastige Zeichenfolgen

Wenn das Zielprogramm hauptsächlich Präfixe, Suffixe, Teilzeichenfolgen oder regexartige Strukturen prüft, können `String`-/`Seq`-Constraints einfacher sein als Bitvektoren für jedes einzelne Byte:<sup>[[3]](#references)</sup>

```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```

Sobald die Binärdatei jedoch mit Zeichen rechnet, sie rotiert, Prüfsummen berechnet oder sie umwandelt, ist es normalerweise besser, wieder 8-Bit-Bitvektoren zu verwenden.

# Beispiele

## Sudoku-Löser

```python
# 9x9 matrix of integer variables
X = [[Int("x_%s_%s" % (i+1, j+1)) for j in range(9)]
     for i in range(9)]

# each cell contains a value in {1, ..., 9}
cells_c = [And(1 <= X[i][j], X[i][j] <= 9)
           for i in range(9) for j in range(9)]

# each row contains a digit at most once
rows_c = [Distinct(X[i]) for i in range(9)]

# each column contains a digit at most once
cols_c = [Distinct([X[i][j] for i in range(9)])
          for j in range(9)]

# each 3x3 square contains a digit at most once
sq_c = [Distinct([X[3*i0 + i][3*j0 + j]
                  for i in range(3) for j in range(3)])
        for i0 in range(3) for j0 in range(3)]

sudoku_c = cells_c + rows_c + cols_c + sq_c

# sudoku instance, we use '0' for empty cells
instance = ((0,0,0,0,9,4,0,3,0),
            (0,0,0,5,1,0,0,0,7),
            (0,8,9,0,0,0,0,4,0),
            (0,0,0,0,0,0,2,0,8),
            (0,6,0,2,0,1,0,5,0),
            (1,0,2,0,0,0,0,0,0),
            (0,7,0,0,0,0,5,2,0),
            (9,0,0,0,6,5,0,0,0),
            (0,4,0,9,7,0,0,0,0))

instance_c = [If(instance[i][j] == 0, True, X[i][j] == instance[i][j])
              for i in range(9) for j in range(9)]

s = Solver()
s.add(sudoku_c + instance_c)
if s.check() == sat:
    m = s.model()
    r = [[m.evaluate(X[i][j]) for j in range(9)]
         for i in range(9)]
    print_matrix(r)
else:
    print("failed to solve")
```

## References

- [1] [Z3Py-Leitfaden mit Beispielen (ericpony z3py-Tutorial)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Z3-Leitfaden – Theorie der Bit-Vektoren (Microsoft z3guide)](https://microsoft.github.io/z3guide/)
- [3] [Programmieren mit Z3 (Nikolaj Bjørner, Leonardo de Moura, Lev Nachmanson, Christoph Wintersteiger)](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
