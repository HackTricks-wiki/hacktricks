# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

Very basically, this tool will help us to find values for variables that need to satisfy some conditions and calculating them by hand will be so annoying. Therefore, you can indicate to Z3 the conditions the variables need to satisfy and it will find some values (if possible).

**Some texts and examples are extracted from [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Basic Operations

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

### Printing Model

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

## Machine Arithmetic

Modern CPUs and main-stream programming languages use arithmetic over **fixed-size bit-vectors**. Machine arithmetic is available in Z3Py as **Bit-Vectors**.

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

### Signed/Unsigned Numbers

Z3 provides special signed versions of arithmetical operations where it makes a difference whether the **bit-vector is treated as signed or unsigned**. In Z3Py, the operators **<, <=, >, >=, /, % and >>** correspond to the **signed** versions. The corresponding **unsigned** operators are **ULT, ULE, UGT, UGE, UDiv, URem and LShR.**

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


### Bit-vector helpers commonly needed in reversing

When you are **lifting checks from assembly or decompiler output**, it is usually better to model every input byte as a `BitVec(..., 8)` and then rebuild words exactly like the target code does. This avoids bugs caused by mixing mathematical integers with machine arithmetic.

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

Some common pitfalls while translating code into constraints:

- `>>` is an **arithmetic** right shift for bit-vectors. Use `LShR` for the logical `shr` instruction.
- Use `UDiv`, `URem`, `ULT`, `ULE`, `UGT` and `UGE` when the original comparison/division was **unsigned**.
- Keep widths explicit. If the binary truncates to 8 or 16 bits, add `Extract` or rebuild the value with `Concat` instead of silently promoting everything to Python integers.

### Functions

**Interpreted functio**ns such as arithmetic where the **function +** has a **fixed standard interpretation** (it adds two numbers). **Uninterpreted functions** and constants are **maximally flexible**; they allow **any interpretation** that is **consistent** with the **constraints** over the function or constant.

Example: f applied twice to x results in x again, but f applied once to x is different from x.

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

## Examples

### Sudoku solver

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

If you need to **symbolically execute the binary and collect constraints automatically**, check the angr notes here:

{{#ref}}
angr/README.md
{{#endref}}

If you are already looking at the decompiled checks and only need to solve them, raw Z3 is usually faster and easier to control.

#### Lifting byte-based checks from a crackme

A very common pattern in crackmes and packed loaders is a long list of byte equations over a candidate password. Model bytes as 8-bit vectors, constrain the alphabet, and only widen them when the original code widens them.

<details>
<summary>Example: rebuild a serial check from decompiled arithmetic</summary>

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

This style maps well to real-world reversing because it matches what modern writeups do in practice: recover the arithmetic/bitwise relations, turn each comparison into a constraint, and solve the whole system at once.

#### Incremental solving with `push()` / `pop()`

While reversing, you often want to test several hypotheses without rebuilding the whole solver. `push()` creates a checkpoint and `pop()` discards the constraints added after that checkpoint. This is useful when you are not sure whether a branch is signed or unsigned, whether a register is zero-extended or sign-extended, or when you are trying several candidate constants extracted from disassembly.

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

#### Enumerating more than one valid input

Some keygens, license checks, and CTF challenges intentionally admit **many** valid inputs. Z3 does not enumerate them automatically, but you can add a **blocking clause** after every model to force the next result to differ in at least one position.

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

#### Tactics for ugly bit-vector formulas

Z3's default solver is usually enough, but decompiler-generated formulas with lots of equalities and bit-vector rewrites often become easier after a first normalization pass. In those cases it can be useful to build a solver from tactics:

```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```

This is specially helpful when the problem is almost entirely **bit-vector + Boolean logic** and you want Z3 to simplify and eliminate obvious equalities before handing the formula to the SAT backend.

#### CRCs and other custom checkers

Recent reversing challenges still use Z3 for constraints that are annoying to brute-force but straightforward to model, such as CRC32 checks over ASCII-only input, mixed rotate/xor/add pipelines, or many chained arithmetic predicates extracted from a JITed/obfuscated checker. For CRC-like problems, keep the state as bit-vectors and apply per-byte ASCII constraints early to shrink the search space.

## References

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}



