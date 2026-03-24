# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

In termini molto semplici, questo strumento ci aiuta a trovare valori per variabili che devono soddisfare alcune condizioni e calcolarli a mano sarebbe davvero noioso. Pertanto, puoi indicare a Z3 le condizioni che le variabili devono soddisfare e lui troverà alcuni valori (se possibile).

**Alcuni testi ed esempi sono estratti da [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Operazioni di base

### Booleani/And/Or/Not
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
### Interi/Semplifica/Reali
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
### Stampa del modello
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
## Aritmetica di macchina

Le CPU moderne e i linguaggi di programmazione più diffusi usano l'aritmetica su bit-vectors di dimensione fissa. L'aritmetica di macchina è disponibile in Z3Py come **Bit-Vectors**.
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
### Numeri con segno/senza segno

Z3 fornisce versioni speciali delle operazioni aritmetiche in cui fa differenza se il **bit-vector è trattato come con segno o senza segno**. In Z3Py, gli operatori **<, <=, >, >=, /, % e >>** corrispondono alle versioni **con segno**. Gli operatori corrispondenti **senza segno** sono **ULT, ULE, UGT, UGE, UDiv, URem e LShR.**
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
### Bit-vector helpers comunemente necessari in reversing

Quando stai **lifting checks from assembly or decompiler output**, è generalmente meglio modellare ogni byte di input come `BitVec(..., 8)` e poi ricostruire le parole esattamente come fa il codice target. Questo evita bug dovuti alla mescolanza di interi matematici con machine arithmetic.
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
Alcune insidie comuni durante la traduzione del codice in vincoli:

- `>>` è uno shift aritmetico a destra per i vettori di bit. Usa `LShR` per l'istruzione logica `shr`.
- Usa `UDiv`, `URem`, `ULT`, `ULE`, `UGT` e `UGE` quando la comparazione/divisione originale era **senza segno**.
- Mantieni le larghezze esplicite. Se il binario tronca a 8 o 16 bit, aggiungi `Extract` o ricostruisci il valore con `Concat` invece di promuovere tutto silenziosamente a interi Python.

### Funzioni

**Funzioni interpretate** come quelle aritmetiche dove la **funzione +** ha una **interpretazione standard fissa** (somma due numeri). **Funzioni non interpretate** e costanti sono **massimamente flessibili**; consentono **qualsiasi interpretazione** che sia **coerente** con i **vincoli** sulla funzione o sulla costante.

Esempio: applicando f due volte a x si ottiene nuovamente x, ma applicando f una volta a x si ottiene qualcosa di diverso da x.
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
## Esempi

### Risolutore di Sudoku
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
### Flussi di lavoro di reversing

Se hai bisogno di **symbolically execute the binary and collect constraints automatically**, consulta gli appunti di angr qui:

{{#ref}}
angr/README.md
{{#endref}}

Se stai già esaminando i decompiled checks e hai solo bisogno di risolverli, raw Z3 è solitamente più veloce e più semplice da controllare.

#### Lifting byte-based checks da un crackme

Un pattern molto comune in crackmes e packed loaders è una lunga lista di byte equations che coinvolgono una candidate password. Modella i byte come 8-bit vectors, vincola l'alfabeto e allargali solo quando il codice originale li allarga.

<details>
<summary>Esempio: ricostruire un serial check da decompiled arithmetic</summary>
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

Questo stile si adatta bene al real-world reversing perché corrisponde a ciò che fanno nella pratica i modern writeups: recuperare le arithmetic/bitwise relations, trasformare ogni comparison in una constraint e risolvere l'intero system in una sola volta.

#### Risoluzione incrementale con `push()` / `pop()`

Mentre fai reversing, spesso vuoi testare diverse ipotesi senza ricostruire l'intero solver. `push()` crea un checkpoint e `pop()` scarta le constraints aggiunte dopo quel checkpoint. Questo è utile quando non sei sicuro se un branch è signed o unsigned, se un register è zero-extended o sign-extended, o quando provi diversi candidate constants estratti dalla disassembly.
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
#### Enumerare più di un input valido

Alcuni keygens, controlli di licenza e challenge CTF ammettono intenzionalmente **molti** input validi. Z3 non li enumera automaticamente, ma puoi aggiungere una **clausola di blocco** dopo ogni modello per forzare che il risultato successivo differisca in almeno una posizione.
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
#### Tattiche per formule bit-vector complesse

Il solver predefinito di Z3 è di solito sufficiente, ma le formule generate dal decompilatore con molte uguaglianze e riscritture di bit-vector spesso diventano più semplici dopo una prima passata di normalizzazione. In questi casi può essere utile costruire un solver a partire da tattiche:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
Questo è particolarmente utile quando il problema è quasi interamente **bit-vector + Boolean logic** e vuoi che Z3 semplifichi ed elimini uguaglianze ovvie prima di consegnare la formula al SAT backend.

#### CRCs e altri custom checkers

Le recenti challenge di reversing usano ancora Z3 per vincoli che sono tediosi da risolvere via brute-force ma semplici da modellare, come CRC32 checks su input ASCII-only, pipeline miste rotate/xor/add, o molti predicati aritmetici concatenati estratti da un JITed/obfuscated checker. Per problemi tipo CRC, mantieni lo stato come bit-vectors e applica per-byte ASCII constraints fin da subito per ridurre lo spazio di ricerca.

## Riferimenti

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
