# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

U najosnovnijem smislu, ovaj alat će nam pomoći da pronađemo vrednosti za promenljive koje moraju zadovoljiti određene uslove, a računanje toga ručno bi bilo veoma naporno. Zato možete Z3-u navesti uslove koje promenljive treba da ispune i on će pronaći neke vrednosti (ako je moguće).

**Neki tekstovi i primeri su preuzeti sa [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Osnovne operacije

### Booleans/And/Or/Not
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
### Ispis modela
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
## Mašinska aritmetika

Moderni CPU-i i uobičajeni programski jezici koriste aritmetiku nad **fixed-size bit-vectors**. Mašinska aritmetika je dostupna u Z3Py kao **Bit-Vectors**.
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
### Brojevi sa i bez predznaka

Z3 pruža posebne verzije aritmetičkih operacija za slučajeve kada je **bit-vektor tretiran kao sa predznakom ili bez predznaka**. U Z3Py, operatori **<, <=, >, >=, /, % i >>** odgovaraju **verzijama sa predznakom**. Odgovarajući **operatori bez predznaka** su **ULT, ULE, UGT, UGE, UDiv, URem i LShR.**
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
### Bit-vector pomoćni alati često potrebni pri reversing-u

Kada radite **lifting checks from assembly or decompiler output**, obično je bolje modelovati svaki ulazni bajt kao `BitVec(..., 8)` i zatim rekonstruisati reči tačno onako kako to radi ciljni kod. Ovo izbegava greške uzrokovane mešanjem matematičkih celih brojeva sa mašinskom aritmetikom.
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
Neki uobičajeni problemi prilikom prevođenja koda u ograničenja:

- `>>` predstavlja **aritmetičko** desno pomeranje za bit-vektore. Koristite `LShR` za logičku `shr` instrukciju.
- Koristite `UDiv`, `URem`, `ULT`, `ULE`, `UGT` i `UGE` kada je originalno poređenje/podela bilo **unsigned**.
- Držite širine eksplicitnim. Ako binarni kod skraćuje vrednost na 8 ili 16 bita, dodajte `Extract` ili obnovite vrednost pomoću `Concat` umesto da tiho promovišete sve u Python integers.

### Funkcije

**Interpretirane funkcije** kao aritmetičke gde **funkcija +** ima **fiksnu standardnu interpretaciju** (ona sabira dva broja). **Neinterpretirane funkcije** i konstante su **maksimalno fleksibilne**; one dozvoljavaju **bilo koju interpretaciju** koja je **u skladu** sa **ograničenjima** nad funkcijom ili konstantom.

Primer: f primenjena dva puta na x rezultira ponovo x, ali f primenjena jednom na x je različita od x.
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
## Primeri

### Rešavač Sudokua
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
### Reversing workflows

Ako treba da **simbolički izvršite binarni fajl i automatski prikupite ograničenja**, pogledajte angr beleške ovde:

{{#ref}}
angr/README.md
{{#endref}}

Ako već pregledate dekompajlovane provere i samo treba da ih rešite, sirovi Z3 je obično brži i lakši za kontrolu.

#### Ekstrakcija provera zasnovanih na bajtovima iz crackme-a

Veoma čest obrazac u crackmes i packed loaderima je duga lista jednačina po bajtu nad kandidatom za lozinku. Modelujte bajtove kao 8-bitne vektore, ograničite alfabet (skup dozvoljenih karaktera) i proširite ih samo kada ih izvorni kod proširi.

<details>
<summary>Primer: rekonstrukcija provere serijskog broja iz dekompajlovane aritmetike</summary>
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

Ovaj stil se dobro uklapa u real-world reversing jer odgovara onome što moderni writeup-i rade u praksi: rekonstruisati aritmetičke i bitovske relacije, pretvoriti svaku poredbu u ograničenje i rešiti ceo sistem odjednom.

#### Inkrementalno rešavanje pomoću `push()` / `pop()`

Dok radite reversing, često želite da testirate više hipoteza bez ponovnog građenja celog solver-a. `push()` kreira checkpoint, a `pop()` odbacuje ograničenja dodata nakon te tačke. Ovo je korisno kada niste sigurni da li je grana signed ili unsigned, da li je registar zero-extended ili sign-extended, ili kada isprobavate nekoliko kandidata konstanti iz disasembliranja.
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
#### Enumerisanje više od jednog važećeg unosa

Neki keygens, license checks i CTF challenges namerno dopuštaju **mnoge** važeće unose. Z3 ih ne navodi automatski, ali možeš dodati **blocking clause** nakon svakog modela da bi naredni rezultat bio drugačiji bar u jednoj poziciji.
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
#### Taktike za neugledne bit-vektorske formule

Z3-ov podrazumevani solver je obično dovoljan, ali formule koje generiše dekompajler sa mnogo jednakosti i prepravki bit-vektora često postanu jednostavnije nakon prvog prolaza normalizacije. U tim slučajevima može biti korisno konstruisati solver koristeći taktike:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
Ovo je posebno korisno kada je problem gotovo u potpunosti **bit-vector + Boolean logic** i želite da Z3 pojednostavi i eliminiše očigledne jednakosti pre nego što preda formulu SAT backendu.

#### CRCs i drugi prilagođeni checkeri

Recent reversing challenges i dalje koriste Z3 za constraints koji su naporni za brute-force, ali jednostavni za modelovanje, kao što su CRC32 provere nad ASCII-only inputom, mešane rotate/xor/add pipelines, ili mnogi u lancu povezani aritmetički predikati izvučeni iz JITed/obfuscated checkera. Za CRC-like probleme, držite stanje kao bit-vectors i primenite per-byte ASCII constraints rano kako biste smanjili prostor pretrage.

## Izvori

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
