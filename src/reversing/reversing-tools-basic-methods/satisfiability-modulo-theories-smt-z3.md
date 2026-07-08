# Molto in generale, questo strumento ci aiuterà a trovare valori per variabili che devono soddisfare alcune condizioni e calcolarli a mano sarebbe molto fastidioso. Quindi, puoi indicare a Z3 le condizioni che le variabili devono soddisfare e lui troverà alcuni valori (se possibile).

{{#include ../../banners/hacktricks-training.md}}

# Operazioni di base

## Booleans/And/Or/Not
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
## Modello di stampa
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
# Aritmetica Macchina

Le moderne CPU e i linguaggi di programmazione mainstream usano l'aritmetica su bit-vector di dimensione fissa. L'aritmetica macchina è disponibile in Z3Py come Bit-Vectors.
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
## Numeri Signed/Unsigned

Z3 fornisce versioni signed speciali delle operazioni aritmetiche, dove fa differenza se il bit-vector è trattato come signed o unsigned. In Z3Py, gli operatori `<`, `<=`, `>`, `>=`, `/`, `%` e `>>` corrispondono alle versioni signed. Gli operatori unsigned corrispondenti sono `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` e `LShR`.
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
## Funzioni

Le funzioni interpretate, come quelle aritmetiche, hanno un'interpretazione standard fissa. Le funzioni e le costanti uninterpreted sono massimamente flessibili; consentono qualsiasi interpretazione coerente con i vincoli sulla funzione o sulla costante.

Esempio: `f` applicata due volte a `x` restituisce di nuovo `x`, ma `f` applicata una volta a `x` è diversa da `x`.
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
# Reversing-Oriented Patterns

Se hai bisogno di full symbolic execution su un binary invece di sollevare manualmente solo pochi check, consulta [Angr - Examples](angr/angr-examples.md). In pratica, un workflow molto comune è recuperare i predicati rilevanti dal decompiler/assembly e ricostruire solo i vincoli aritmetici o di memoria interessanti in Z3.

## Model user-controlled data as bytes first

Per il reversing, di solito è meglio iniziare con `BitVec(..., 8)` per ogni byte di input e poi ricostruire le word esattamente come fa il target. Questo preserva wrap-around, bug di signedness, shift, rotate e problemi di byte-order.
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
Strumenti utili quando si traduce assembly o codice decompiler:

- `Concat`: ricostruisce valori a 16/32/64 bit da byte
- `Extract`: confronta word alte/basse o emula mask/shift
- `ZeroExt` / `SignExt`: modella correttamente bug di estensione zero/segno
- `LShR` / `RotateLeft` / `RotateRight`: comuni in crackmes, hash e obfuscator

## Modella tabelle di memoria/register con array

Quando un controllo dipende da `buf[i]`, lookup table o memoria emulata, `Array` può essere più pulito che creare decine di variabili separate.
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
Questo è particolarmente utile quando il binario copia valori nella memoria prima di validarli, o quando vuoi modellare l'effetto di alcune operazioni `mov`/`xor`/`add` senza eseguire l'intero programma.

## Incremental solving è ottimo per il branch triage

Quando hai già estratto i vincoli di base, usa `push()` / `pop()` (o assumptions) per testare branch alternativi senza ricostruire ogni volta il solver:
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
Questo è utile quando si rigiocano le path conditions recuperate da un decompiler, o quando vuoi identificare rapidamente quale comparison sta rendendo il model `unsat`.

## Optimize for nicer payloads

Una volta che un model è satisfiable, `Optimize()` può aiutarti a ottenere una soluzione più usabile: per esempio, preferire bytes stampabili, minimizzare un componente checksum, oppure massimizzare una struttura che renda la password recuperata più facile da digitare o copiare.
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
## String/sequences per seriali con molti formati

Se il target controlla soprattutto prefissi, suffissi, sottostringhe o una struttura simile a regex, i vincoli `String`/`Seq` possono essere più semplici dei bit-vector byte per byte:
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
Tuttavia, una volta che il binario inizia a fare operazioni aritmetiche, rotazioni, checksum o cast sui caratteri, di solito è meglio tornare ai bit-vector a 8 bit.

# Examples

## Sudoku solver
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

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
* [https://microsoft.github.io/z3guide/](https://microsoft.github.io/z3guide/)
* [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
