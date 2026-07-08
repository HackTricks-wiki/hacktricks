# Très basiquement, cet outil nous aidera à trouver des valeurs pour des variables qui doivent satisfaire certaines conditions, et les calculer à la main serait très pénible. Par conséquent, vous pouvez indiquer à Z3 les conditions que les variables doivent satisfaire et il trouvera certaines valeurs (si possible).

{{#include ../../banners/hacktricks-training.md}}

# Basic Operations

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
## Modèle d'impression
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
# Arithmétique machine

Les CPU modernes et les langages de programmation grand public utilisent une arithmétique sur des vecteurs de bits de taille fixe. L'arithmétique machine est disponible dans Z3Py sous forme de Bit-Vectors.
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
## Nombres signés/non signés

Z3 fournit des versions signées spéciales des opérations arithmétiques, où il y a une différence selon que le bit-vector est traité comme signé ou non signé. Dans Z3Py, les opérateurs `<`, `<=`, `>`, `>=`, `/`, `%` et `>>` correspondent aux versions signées. Les opérateurs non signés correspondants sont `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` et `LShR`.
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
## Fonctions

Les fonctions interprétées, comme l'arithmétique, ont une interprétation standard fixe. Les fonctions et constantes non interprétées sont maximement flexibles ; elles permettent toute interprétation cohérente avec les contraintes sur la fonction ou la constante.

Exemple : `f` appliquée deux fois à `x` donne à nouveau `x`, mais `f` appliquée une fois à `x` est différente de `x`.
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

Si vous avez besoin d’une exécution symbolique complète sur un binaire au lieu de relever manuellement seulement quelques vérifications, consultez [Angr - Examples](angr/angr-examples.md). En pratique, un flux de travail très courant consiste à récupérer les prédicats pertinents depuis le decompiler/assembly et à reconstruire uniquement les contraintes arithmétiques ou mémoire intéressantes dans Z3.

## Modélisez d’abord les données contrôlées par l’utilisateur comme des bytes

Pour le reversing, il est généralement préférable de commencer avec `BitVec(..., 8)` pour chaque byte d’entrée, puis de reconstruire les words exactement comme la cible le fait. Cela préserve le wrap-around, les bugs de signedness, les shifts, les rotates et les problèmes d’ordre des bytes.
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
Utiles lors de la traduction de code assembly ou de décompilation :

- `Concat` : reconstruire des valeurs 16/32/64-bit à partir d'octets
- `Extract` : comparer des mots hauts/bas ou émuler des masques/décalages
- `ZeroExt` / `SignExt` : modéliser correctement les bugs d'extension zéro/signe
- `LShR` / `RotateLeft` / `RotateRight` : courants dans les crackmes, hashes et obfuscators

## Modéliser les tables mémoire/registres avec des arrays

Quand un check dépend de `buf[i]`, de lookup tables ou de mémoire émulée, `Array` peut être plus propre que de créer des dizaines de variables séparées.
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
C'est particulièrement utile lorsque le binaire copie des valeurs en mémoire avant de les valider, ou lorsque vous voulez modéliser l'effet de quelques opérations `mov`/`xor`/`add` sans exécuter tout le programme.

## Incremental solving est idéal pour le triage des branches

Lorsque vous avez déjà extrait les contraintes de base, utilisez `push()` / `pop()` (ou des assumptions) pour tester des branches alternatives sans reconstruire le solver à chaque fois:
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
Ceci est utile lorsque vous rejouez des path conditions récupérées depuis un decompiler, ou lorsque vous voulez identifier rapidement quelle comparaison rend le modèle `unsat`.

## Optimiser pour de meilleurs payloads

Une fois qu’un modèle est satisfiable, `Optimize()` peut vous aider à obtenir une solution plus exploitable : par exemple, privilégier des bytes imprimables, minimiser une composante de checksum, ou maximiser une structure qui rend le password récupéré plus facile à saisir ou à copier.
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
## Strings/séquences pour des serials très axés sur le format

Si la cible vérifie principalement des préfixes, suffixes, sous-chaînes ou une structure de type regex, les contraintes `String`/`Seq` peuvent être plus simples que les bit-vectors octet par octet :
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
Cependant, dès que le binaire commence à faire de l’arithmétique, des rotations, des checksums ou des casts sur des caractères, il est généralement préférable de revenir aux bit-vectors de 8 bits.

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
## Références

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
* [https://microsoft.github.io/z3guide/](https://microsoft.github.io/z3guide/)
* [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
