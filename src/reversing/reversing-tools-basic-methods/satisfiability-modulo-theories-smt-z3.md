# 非常に基本的な使い方として、このツールは、いくつかの条件を満たす必要がある変数の値を見つけるのに役立ちます。手作業で計算すると非常に面倒です。そのため、変数が満たすべき条件をZ3に指定すれば、可能な場合は値を見つけてくれます。

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

## モデルの表示

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

# 機械算術

現代のCPUと主流のプログラミング言語では、固定サイズのビットベクトル上で演算を行います。Z3Pyでは、Bit-Vectorsとして機械算術を利用できます。

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

Z3 には、ビットベクターを符号付きとして扱うか符号なしとして扱うかによって結果が異なる、算術演算の符号付きバージョンが用意されています。Z3Py では、演算子 `<`、`<=`、`>`、`>=`、`/`、`%`、`>>` は符号付きバージョンに対応します。対応する符号なし演算子は `ULT`、`ULE`、`UGT`、`UGE`、`UDiv`、`URem`、`LShR` です。<sup>[[1]](#references)</sup>

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

算術などの解釈済み関数には、固定された標準的な解釈があります。未解釈関数と定数は最大限に柔軟であり、その関数または定数に対する制約と矛盾しない任意の解釈が可能です。<sup>[[1]](#references)</sup>

例: `x` に `f` を2回適用すると再び `x` になりますが、`f` を `x` に1回適用した結果は `x` とは異なります。

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

# リバースエンジニアリング向けパターン

binary 全体に対する symbolic execution が必要で、いくつかのチェックだけを手作業で取り出すのでは不十分な場合は、[Angr - Examples](angr/angr-examples.md) を確認してください。実際には、decompiler/assembly から関連する predicate を特定し、興味のある算術制約やメモリ制約だけを Z3 で再構築するのが、非常によく使われるワークフローです。

## まずユーザー制御データをバイト列としてモデル化する

リバースエンジニアリングでは、各入力バイトに `BitVec(..., 8)` を使って始め、その後、対象プログラムとまったく同じ方法でワードを再構築するのが一般的に適しています。これにより、桁あふれ、符号の扱いに関するバグ、シフト、ローテート、バイト順の問題を保持できます。<sup>[[2]](#references)</sup>

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

アセンブリやデコンパイラのコードを翻訳する際に役立つ関数:

- `Concat`: バイト列から16/32/64ビット値を再構築する
- `Extract`: 上位/下位ワードを比較したり、マスクやシフトをエミュレートしたりする
- `ZeroExt` / `SignExt`: ゼロ拡張/符号拡張のバグを正しくモデル化する
- `LShR` / `RotateLeft` / `RotateRight`: crackmes、ハッシュ、難読化ツールでよく使われる

## 配列でメモリ/レジスタのテーブルをモデル化する

チェックが `buf[i]`、ルックアップテーブル、またはエミュレートされたメモリに依存する場合、個別の変数を何十個も作るより、`Array` を使うほうがすっきりします。<sup>[[3]](#references)</sup>

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

これは、バイナリが値を検証する前にメモリ上でコピーする場合や、プログラム全体を実行せずにいくつかの `mov`/`xor`/`add` 操作の影響をモデル化したい場合に特に便利です。

## インクリメンタルソルビングは分岐のトリアージに最適

ベースとなる制約をすでに抽出している場合は、`push()` / `pop()`（または assumptions）を使うと、ソルバーを毎回作り直さずに、別の分岐をテストできます。<sup>[[3]](#references)</sup>

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

これは、decompilerから復元したpath conditionを再現するときや、どの比較によってmodelが`unsat`になるのかをすばやく特定したいときに役立ちます。

## より扱いやすいpayloadを最適化する

modelがsatisfiableになったら、`Optimize()`を使うことで、より扱いやすい解を得られます。たとえば、表示可能なバイトを優先したり、checksumの一部を最小化したり、復元したpasswordを入力・コピーしやすくする構造を最大化したりできます。<sup>[[3]](#references)</sup>

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

## 書式が重視されるシリアル番号向けの文字列/シーケンス

対象が主にprefix、suffix、substring、または正規表現のような構造をチェックする場合、`String`/`Seq` の制約は、ビットベクトルを1バイトずつ扱うより簡単なことがあります:<sup>[[3]](#references)</sup>

```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```

ただし、バイナリが算術演算、ローテーション、チェックサム、または文字のキャストを行い始めたら、通常は8ビットのビットベクトルに戻すほうが適切です。

# 例

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

- [1] [Z3Pyの例付きガイド (ericpony z3py-tutorial)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Z3ガイド - Bit-Vectors理論 (Microsoft z3guide)](https://microsoft.github.io/z3guide/)
- [3] [Z3のプログラミング (Nikolaj Bjørner, Leonardo de Moura, Lev Nachmanson, Christoph Wintersteiger)](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
