# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

非常に簡単に言うと、このツールは、ある条件を満たす必要がある変数の値を見つけるのを助けます。手で計算するのは面倒なので、変数が満たすべき条件を Z3 に指定すると、（可能であれば）その値を見つけてくれます。

**一部の文章と例は [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm) から抽出されています**

## 基本操作

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
### モデルの表示
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
## マシン算術

現代のCPUと主流のプログラミング言語は、**fixed-size bit-vectors**上での算術を使用します。マシン算術は Z3Py では **Bit-Vectors** として利用できます。
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
### 符号付き/符号なし数値

Z3 は、**ビットベクタが符号付きとして扱われるか符号なしとして扱われるか**によって差が生じる算術演算の特別な符号付きバージョンを提供します。In Z3Py、演算子 **<, <=, >, >=, /, % and >>** は **符号付き** バージョンに対応します。対応する **符号なし** 演算子は **ULT, ULE, UGT, UGE, UDiv, URem and LShR.**
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
### リバースでよく必要になるビットベクトルのヘルパー

**アセンブリやデコンパイラの出力からチェックを抽出する場合**、通常、各入力バイトを `BitVec(..., 8)` としてモデル化し、ターゲットコードが行うのとまったく同じ方法でワードを再構築する方が望ましいです。これにより、数学的整数とマシン算術を混ぜることによって生じるバグを回避できます。
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

- `>>` is an **算術的** right shift for bit-vectors. Use `LShR` for the logical `shr` instruction.
- Use `UDiv`, `URem`, `ULT`, `ULE`, `UGT` and `UGE` when the original comparison/division was **unsigned**.
- Keep widths explicit. If the binary truncates to 8 or 16 bits, add `Extract` or rebuild the value with `Concat` instead of silently promoting everything to Python integers.

### 関数

**解釈された関数**（例えば算術のように **function +** が **固定された標準的解釈**（2つの数を足す）を持つもの）は、一方で **未解釈関数** と定数は **最大限柔軟** です；それらは関数や定数にかかる**制約**と**矛盾しない**限り **任意の解釈** を許します。

例：f を x に2回適用すると再び x になるが、f を1回適用した x は元の x と異なる。
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
## 例

### 数独ソルバー
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
### リバース解析のワークフロー

バイナリを**シンボリック実行して制約を自動収集する**必要があるなら、angrのノートをここで確認してください:

{{#ref}}
angr/README.md
{{#endref}}

既にデコンパイルされたチェックを見ていて、それらを解くだけでよければ、raw Z3は通常より高速かつ制御しやすいです。

#### crackmeからのバイトベースのチェックの抽出

crackmesやpacked loadersでは、候補パスワードに対するバイト等式の長いリストが非常に一般的なパターンです。バイトを8ビットベクトルとしてモデル化し、アルファベットに制約をかけ、元のコードが幅を広げるときだけそれらを拡張してください。

<details>
<summary>例: デコンパイルされた算術からシリアルチェックを再構築する</summary>
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

このスタイルは現実の reversing にうまく適合します。なぜなら現代の writeups が実務で行っていることに一致するからです: 算術・ビット演算の関係を復元し、各比較を制約に変換し、システム全体を一度に解く。

#### `push()` / `pop()` を使った増分的な解法

reversing 中は、ソルバー全体を再構築せずに複数の仮説を試したいことがよくあります。`push()` はチェックポイントを作成し、`pop()` はそのチェックポイント以降に追加した制約を破棄します。これは、分岐が符号付きか符号なしなのかわからない場合や、レジスタがゼロ拡張か符号拡張か判別できない場合、あるいは逆アセンブルから抽出した複数の候補定数を試すときに便利です。
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
#### 複数の有効な入力を列挙する

一部の keygens、license checks、CTF challenges は意図的に **多くの** 有効な入力を受け入れます。Z3 はそれらを自動で列挙しませんが、各モデルの後に **blocking clause** を追加することで、次の結果が少なくとも1つの位置で異なるように強制できます。
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
#### 見にくい bit-vector 式のための Tactics

Z3 のデフォルトの solver は通常十分だが、decompiler によって生成され、多数の等式や bit-vector の書き換えを含む式は、最初の正規化パスを通すことで扱いやすくなることが多い。そうした場合には、tactics から solver を構築するのが有用なことがある:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
This is specially helpful when the problem is almost entirely **bit-vector + Boolean logic** and you want Z3 to simplify and eliminate obvious equalities before handing the formula to the SAT backend.

#### CRCs とその他のカスタムチェッカー

最近のリバース課題では、総当たりが面倒だがモデリング自体は比較的簡単な制約（例：ASCII-only入力に対するCRC32チェック、rotate/xor/addの混合パイプライン、JITed/obfuscatedチェッカーから抽出された多数の連鎖する算術述語など）に対してもZ3が使われています。CRC-likeな問題では、状態をbit-vectorsのまま保持し、探索空間を縮小するために各バイトに対するASCII制約を早期に適用してください。

## 参考資料

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
