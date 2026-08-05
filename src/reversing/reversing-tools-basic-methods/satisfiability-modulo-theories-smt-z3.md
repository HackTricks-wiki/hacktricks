# 非常に基本的には、このツールを使うと、いくつかの条件を満たす必要がある変数の値を見つけられます。手計算で求めるのは非常に面倒です。そのため、変数が満たす必要のある条件を Z3 に指定すれば、可能な場合にはいくつかの値を見つけてくれます。

{{#include ../../banners/hacktricks-training.md}}

# 基本操作

## ブール値/And/Or/Not
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
## 整数/簡約/実数
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
## モデルの出力
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
# マシン算術

現代のCPUと主流のプログラミング言語は、固定サイズのビットベクトル上で算術演算を行います。マシン算術は、Z3PyではBit-Vectorsとして利用できます。<sup>[[1]](#references)</sup>
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
## 符号付き/符号なし数値

Z3 は、ビットベクトルを符号付きまたは符号なしとして扱うかによって結果が異なる算術演算について、専用の符号付きバージョンを提供します。Z3Py では、演算子 `<`、`<=`、`>`、`>=`、`/`、`%`、`>>` が符号付きバージョンに対応します。対応する符号なし演算子は `ULT`、`ULE`、`UGT`、`UGE`、`UDiv`、`URem`、`LShR` です。<sup>[[1]](#references)</sup>
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
## Functions

算術などの解釈付き関数には、固定された標準的な解釈があります。未解釈関数と定数は最大限に柔軟であり、その関数または定数に対する制約と整合する任意の解釈を許容します。<sup>[[1]](#references)</sup>

例: `f` を `x` に2回適用すると再び `x` になりますが、`f` を `x` に1回適用した結果は `x` とは異なります。
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
# Reversing向けパターン

手動で少数のチェックだけをliftingするのではなく、binary全体に対してfull symbolic executionが必要な場合は、[Angr - Examples](angr/angr-examples.md)を確認してください。実際には、decompiler/assemblyから関連するpredicateを復元し、興味のある算術またはmemoryのconstraintだけをZ3で再構築するワークフローが非常によく使われます。

## user-controlled dataはまずbytesとしてモデル化する

Reversingでは、通常、各入力byteに対して`BitVec(..., 8)`から始め、その後、targetが行うとおりにwordを正確に再構築する方が適切です。これにより、wrap-around、signedness bug、shift、rotate、byte-orderの問題を維持できます。
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
assembly または decompiler code の翻訳時に役立つ便利なヘルパー:

- `Concat`: バイトから 16/32/64-bit 値を再構築
- `Extract`: 上位/下位ワードの比較、またはマスク/シフトをエミュレート
- `ZeroExt` / `SignExt`: zero/sign extension のバグを正確にモデル化
- `LShR` / `RotateLeft` / `RotateRight`: crackmes、hashes、obfuscators で一般的

## arrays を使用して memory/register tables をモデル化

チェックが `buf[i]`、lookup tables、または emulated memory に依存する場合、多数の個別変数を作成するよりも `Array` の方が簡潔です。
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
これは、binary が値を検証する前に memory 上でコピーする場合や、プログラム全体を実行せずに、いくつかの `mov`/`xor`/`add` 操作の効果を model 化したい場合に特に便利です。

## Incremental solving は branch triage に最適

base constraints をすでに抽出している場合は、毎回 solver を再構築せずに、`push()` / `pop()`（または assumptions）を使って別の branch をテストできます。
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
これは、decompilerから復元した path conditions を再現するときや、モデルを `unsat` にしている比較をすばやく特定したいときに役立ちます。

## より扱いやすい payload に最適化する

モデルが satisfiable になったら、`Optimize()` を使ってより扱いやすい解を取得できます。たとえば、printable bytes を優先したり、checksum component を最小化したり、復元したパスワードを入力またはコピーしやすくする構造を最大化したりできます。
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
## フォーマット依存のシリアル向け文字列/シーケンス

対象が主にプレフィックス、サフィックス、部分文字列、または正規表現に似た構造をチェックする場合、バイトごとのビットベクターよりも `String`/`Seq` 制約の方が扱いやすくなります。
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
しかし、バイナリが文字に対して算術演算、ローテーション、チェックサム、またはキャストを行い始めたら、通常は8-bit bit-vectorsに戻したほうがよいでしょう。

# 例

## 数独ソルバー
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
## 参考資料

- [1] [Z3Py Guide - Examples (ericpony)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Z3 Guide (Microsoft)](https://microsoft.github.io/z3guide/)
- [3] [Programming Z3 (Stanford)](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
