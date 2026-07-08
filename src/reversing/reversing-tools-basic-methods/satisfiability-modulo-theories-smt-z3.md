# 非常に基本的に、このツールは、いくつかの条件を満たす必要がある変数の値を見つけるのに役立ち、手で計算するのはとても面倒です。したがって、Z3 に変数が満たす必要のある条件を示すと、Z3 はいくつかの値を見つけます（可能であれば）。

{{#include ../../banners/hacktricks-training.md}}

# 基本操作

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
## 印刷モデル
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
# Machine Arithmetic

現代のCPUと一般的なプログラミング言語は、固定サイズのビットベクター上の算術を使います。Machine arithmetic は Z3Py では Bit-Vectors として利用できます。
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
## Signed/Unsigned Numbers

Z3は、ビットベクタをsignedとして扱うかunsignedとして扱うかで結果が変わる算術演算のspecialなsigned版を提供します。Z3Pyでは、`<`、`<=`、`>`、`>=`、`/`、`%`、`>>` はsigned版に対応します。対応するunsigned演算子は `ULT`、`ULE`、`UGT`、`UGE`、`UDiv`、`URem`、`LShR` です。
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
## 関数

算術のような解釈済み関数には、固定された標準解釈があります。未解釈関数と定数は最大限に柔軟で、関数や定数に対する制約と矛盾しない任意の解釈を許します。

例: `f` を `x` に 2 回適用すると `x` に戻りますが、`f` を `x` に 1 回適用した結果は `x` とは異なります。
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

バイナリ全体に対して、いくつかのチェックだけを手作業で持ち上げる代わりに完全な symbolic execution が必要な場合は、[Angr - Examples](angr/angr-examples.md) を確認してください。実務では、decompiler/assembly から関連する predicate を回収し、Z3 で面白い arithmetic や memory constraints だけを再構築する、というワークフローが非常に一般的です。

## Model user-controlled data as bytes first

reversing では、通常は各入力 byte ごとに `BitVec(..., 8)` から始め、その後 target が行うのとまったく同じように word を再構築するのがよいです。これにより、wrap-around、signedness bug、shift、rotate、byte-order の問題を保持できます。
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
アセンブリやdecompilerコードを翻訳する際に役立つヘルパー:

- `Concat`: 16/32/64-bit値をbyteから再構築する
- `Extract`: 上位/下位wordを比較する、またはmask/shiftをエミュレートする
- `ZeroExt` / `SignExt`: zero/sign extensionのバグを正しくモデル化する
- `LShR` / `RotateLeft` / `RotateRight`: crackmes、hashes、obfuscatorsでよく使われる

## 配列でmemory/registerテーブルをモデル化する

チェックが `buf[i]`、lookup tables、またはエミュレートされたmemoryに依存する場合、`Array` は多数の個別変数を作るよりもきれいに書ける。
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
これは、バイナリが値を検証する前にメモリ内でコピーしている場合や、プログラム全体を実行せずに少数の `mov`/`xor`/`add` 操作の効果をモデル化したい場合に特に便利です。

## Incremental solving は branch triage に最適

すでに base constraints を抽出しているなら、`push()` / `pop()`（または assumptions）を使って、毎回 solver を再構築せずに alternative branches をテストします:
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
これは、decompiler から復元した path conditions を再実行するときや、どの比較が model を `unsat` にしているのかを素早く特定したいときに役立ちます。

## より扱いやすい payload のために最適化する

model が satisfiable になったら、`Optimize()` を使うことで、より実用的な solution を得られます。たとえば、printable bytes を優先したり、checksum component を最小化したり、復元した password を入力またはコピーしやすくするような structure を最大化したりできます。
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
## フォーマット重視のシリアル向けの strings/sequences

対象が主に prefix、suffix、substring、または regex 風の構造をチェックする場合、`String`/`Seq` 制約は byte-by-byte の bit-vectors より簡単なことがあります:
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
しかし、バイナリが文字に対して算術、回転、チェックサム、またはキャストを行い始めると、通常は8-bit bit-vectorsに戻したほうがよいです。

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
## 参考

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
* [https://microsoft.github.io/z3guide/](https://microsoft.github.io/z3guide/)
* [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
