# Satisfiabilité modulo des théories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

Très simplement, cet outil nous aide à trouver des valeurs pour des variables qui doivent satisfaire certaines conditions, et les calculer à la main serait très fastidieux. Ainsi, vous pouvez indiquer à Z3 les conditions que les variables doivent satisfaire et il trouvera des valeurs (si possible).

**Certains textes et exemples sont extraits de [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Opérations de base

### Booléens/And/Or/Not
```python
#pip3 install z3-solver
from z3 import *
s = Solver() #The solver will be given the conditions

x = Bool("x") #Declare the symbos x, y and z
y = Bool("y")
z = Bool("z")

# (x or y or !z) and y
s.add(And(Or(x,y,Not(z)),y))
s.check() #If response is "sat" then the model is satifable, if "unsat" something is wrong
print(s.model()) #Print valid values to satisfy the model
```
### Ints/Simplify/Reals
```python
from z3 import *

x = Int('x')
y = Int('y')
#Simplify a "complex" ecuation
print(simplify(And(x + 1 >= 3, x**2 + x**2 + y**2 + 2 >= 5)))
#And(x >= 2, 2*x**2 + y**2 >= 3)

#Note that Z3 is capable to treat irrational numbers (An irrational algebraic number is a root of a polynomial with integer coefficients. Internally, Z3 represents all these numbers precisely.)
#so you can get the decimals you need from the solution
r1 = Real('r1')
r2 = Real('r2')
#Solve the ecuation
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))
#Solve the ecuation with 30 decimals
set_option(precision=30)
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))
```
### Affichage du modèle
```python
from z3 import *

x, y, z = Reals('x y z')
s = Solver()
s.add(x > 1, y > 1, x + y > 3, z - x < 10)
s.check()

m = s.model()
print ("x = %s" % m[x])
for d in m.decls():
print("%s = %s" % (d.name(), m[d]))
```
## Arithmétique machine

Les CPU modernes et les langages de programmation courants utilisent l'arithmétique sur des **vecteurs de bits de taille fixe**. L'arithmétique machine est disponible dans Z3Py sous forme de **Bit-Vectors**.
```python
from z3 import *

x = BitVec('x', 16) #Bit vector variable "x" of length 16 bit
y = BitVec('y', 16)

e = BitVecVal(10, 16) #Bit vector with value 10 of length 16bits
a = BitVecVal(-1, 16)
b = BitVecVal(65535, 16)
print(simplify(a == b)) #This is True!
a = BitVecVal(-1, 32)
b = BitVecVal(65535, 32)
print(simplify(a == b)) #This is False
```
### Nombres signés/non signés

Z3 fournit des versions signées spéciales des opérations arithmétiques lorsqu'il fait une différence de savoir si le **vecteur de bits est traité comme signé ou non signé**. Dans Z3Py, les opérateurs **<, <=, >, >=, /, % et >>** correspondent aux versions **signées**. Les opérateurs **non signés** correspondants sont **ULT, ULE, UGT, UGE, UDiv, URem et LShR.**
```python
from z3 import *

# Create to bit-vectors of size 32
x, y = BitVecs('x y', 32)
solve(x + y == 2, x > 0, y > 0)

# Bit-wise operators
# & bit-wise and
# | bit-wise or
# ~ bit-wise not
solve(x & y == ~y)
solve(x < 0)

# using unsigned version of <
solve(ULT(x, 0))
```
### Bit-vector helpers couramment nécessaires en reversing

Lorsque vous effectuez des **lifting checks from assembly or decompiler output**, il est généralement préférable de modéliser chaque octet d'entrée comme un `BitVec(..., 8)` puis de reconstruire les mots exactement comme le code cible le fait. Cela évite les bugs causés par le mélange d'entiers mathématiques et d'arithmétique machine.
```python
from z3 import *

b0, b1, b2, b3 = BitVecs('b0 b1 b2 b3', 8)
eax = Concat(b3, b2, b1, b0)        # little-endian bytes -> 32-bit register value
low_byte = Extract(7, 0, eax)        # AL
high_word = Extract(31, 16, eax)     # upper 16 bits
signed_b0 = SignExt(24, b0)          # movsx eax, byte ptr [...]
unsigned_b0 = ZeroExt(24, b0)        # movzx eax, byte ptr [...]
rot = RotateLeft(eax, 13)            # rol eax, 13
logical = LShR(eax, 3)               # shr eax, 3
arith = eax >> 3                     # sar eax, 3 (signed shift)
```
Quelques pièges courants lors de la traduction de code en contraintes :

- `>>` est un décalage à droite **arithmétique** pour les vecteurs de bits. Utilisez `LShR` pour l'instruction logique `shr`.
- Utilisez `UDiv`, `URem`, `ULT`, `ULE`, `UGT` et `UGE` lorsque la comparaison/la division d'origine était **non signée**.
- Gardez les largeurs explicites. Si le binaire est tronqué à 8 ou 16 bits, ajoutez `Extract` ou reconstruisez la valeur avec `Concat` au lieu de promouvoir silencieusement tout en entiers Python.

### Fonctions

**Fonctions interprétées** telles que l'arithmétique, où la **fonction +** a une **interprétation standard fixe** (elle additionne deux nombres). Les **fonctions non interprétées** et les constantes sont **maximement flexibles** ; elles permettent **toute interprétation** qui est **cohérente** avec les **contraintes** portant sur la fonction ou la constante.

Exemple : appliquer f deux fois à x donne à nouveau x, mais appliquer f une seule fois à x donne un résultat différent de x.
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
s.add(f(x) == 4) #Find the value that generates 4 as response
s.check()
print(m.model())
```
## Exemples

### Solveur de Sudoku
```python
# 9x9 matrix of integer variables
X = [ [ Int("x_%s_%s" % (i+1, j+1)) for j in range(9) ]
for i in range(9) ]

# each cell contains a value in {1, ..., 9}
cells_c  = [ And(1 <= X[i][j], X[i][j] <= 9)
for i in range(9) for j in range(9) ]

# each row contains a digit at most once
rows_c   = [ Distinct(X[i]) for i in range(9) ]

# each column contains a digit at most once
cols_c   = [ Distinct([ X[i][j] for i in range(9) ])
for j in range(9) ]

# each 3x3 square contains a digit at most once
sq_c     = [ Distinct([ X[3*i0 + i][3*j0 + j]
for i in range(3) for j in range(3) ])
for i0 in range(3) for j0 in range(3) ]

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

instance_c = [ If(instance[i][j] == 0,
True,
X[i][j] == instance[i][j])
for i in range(9) for j in range(9) ]

s = Solver()
s.add(sudoku_c + instance_c)
if s.check() == sat:
m = s.model()
r = [ [ m.evaluate(X[i][j]) for j in range(9) ]
for i in range(9) ]
print_matrix(r)
else:
print "failed to solve"
```
### Flux de travail de reversing

Si vous avez besoin d'**exécuter symboliquement le binaire et de collecter automatiquement les contraintes**, consultez les notes angr ici:

{{#ref}}
angr/README.md
{{#endref}}

Si vous regardez déjà les vérifications décompilées et devez seulement les résoudre, Z3 pur est généralement plus rapide et plus facile à contrôler.

#### Extraction de vérifications basées sur des octets depuis un crackme

Un schéma très courant dans les crackmes et les packed loaders est une longue liste d'équations d'octets appliquées à un mot de passe candidat. Modélisez les octets comme des vecteurs de 8 bits, contraignez l'alphabet, et ne les élargissez que lorsque le code original les élargit.

<details>
<summary>Exemple : reconstruire une vérification de numéro de série à partir d'arithmétique décompilée</summary>
```python
from z3 import *

flag = [BitVec(f'flag_{i}', 8) for i in range(8)]
s = Solver()

for c in flag:
s.add(c >= 0x20, c <= 0x7e)

w0 = Concat(flag[3], flag[2], flag[1], flag[0])
w1 = Concat(flag[7], flag[6], flag[5], flag[4])

s.add((ZeroExt(24, flag[0]) + ZeroExt(24, flag[5])) == 0x90)
s.add((flag[1] ^ flag[2] ^ flag[3]) == 0x5a)
s.add(RotateLeft(w0, 7) ^ w1 == BitVecVal(0x4f625a13, 32))
s.add(ULE(flag[6], flag[7]))
s.add(LShR(w1, 5) == BitVecVal(0x03a1f21, 32))

if s.check() == sat:
m = s.model()
print(bytes(m[c].as_long() for c in flag))
```
</details>

Ce style s'applique bien au reversing réel car il correspond à ce que font les writeups modernes en pratique : reconstituer les relations arithmétiques/bitwise, transformer chaque comparaison en contrainte, et résoudre l'ensemble du système d'un coup.

#### Résolution incrémentale avec `push()` / `pop()`

Lors du reversing, vous souhaitez souvent tester plusieurs hypothèses sans reconstruire entièrement le solver. `push()` crée un point de contrôle et `pop()` supprime les contraintes ajoutées après ce point. Ceci est utile lorsque vous n'êtes pas sûr si une branch est signed ou unsigned, si un register est zero-extended ou sign-extended, ou lorsque vous testez plusieurs candidate constants extraites de la disassembly.
```python
from z3 import *

x = BitVec('x', 32)
s = Solver()
s.add((x & 0xff) == 0x41)

s.push()
s.add(UGT(x, 0x1000))
print(s.check())
s.pop()

s.push()
s.add(x == 0x41)
print(s.check())
print(s.model())
s.pop()
```
#### Énumérer plus d'une entrée valide

Certaines keygens, vérifications de licence et challenges CTF admettent intentionnellement **de nombreuses** entrées valides. Z3 ne les énumère pas automatiquement, mais vous pouvez ajouter une **clause de blocage** après chaque modèle pour forcer le résultat suivant à différer sur au moins une position.
```python
from z3 import *

xs = [BitVec(f'x{i}', 8) for i in range(4)]
s = Solver()
for x in xs:
s.add(And(x >= 0x30, x <= 0x39))
s.add(xs[0] + xs[1] == xs[2] + 1)
s.add(xs[3] == xs[0] ^ 3)

while s.check() == sat:
m = s.model()
print(''.join(chr(m[x].as_long()) for x in xs))
s.add(Or([x != m.eval(x, model_completion=True) for x in xs]))
```
#### Tactiques pour formules bit-vector peu lisibles

Le solver par défaut de Z3 suffit généralement, mais les formules générées par un décompilateur contenant de nombreuses égalités et réécritures bit-vector deviennent souvent plus simples après une première passe de normalisation. Dans ces cas, il peut être utile de construire un solver à partir de tactiques :
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
Ceci est particulièrement utile lorsque le problème est presque entièrement **bit-vector + Boolean logic** et que vous voulez que Z3 simplifie et élimine les égalités évidentes avant de confier la formule au backend SAT.

#### CRCs et autres checkers personnalisés

Les challenges récents de reversing utilisent encore Z3 pour des contraintes qu'il est fastidieux de brute-forcer mais simples à modéliser, comme des vérifications CRC32 sur des entrées ASCII-only, des pipelines mixtes rotate/xor/add, ou de nombreux prédicats arithmétiques enchaînés extraits d'un checker JITed/obfuscated. Pour les problèmes de type CRC, gardez l'état en bit-vectors et appliquez dès le début des contraintes ASCII per-byte pour réduire l'espace de recherche.

## References

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
