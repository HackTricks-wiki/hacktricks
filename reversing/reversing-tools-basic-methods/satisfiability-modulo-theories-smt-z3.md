<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>


非常に基本的に、このツールは、いくつかの条件を満たす必要がある変数の値を見つけるのに役立ちます。手計算で計算するのは非常に面倒です。したがって、Z3に変数が満たす必要のある条件を指示することができ、それが可能であればいくつかの値を見つけることができます。

# 基本的な操作

## ブール値/And/Or/Not
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
## Ints/Simplify/Reals

整数/簡略化/実数
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
## モデルの表示

To print the model, you can use the `model` method provided by the Z3 library. This method returns a string representation of the model.

モデルを表示するには、Z3ライブラリが提供する`model`メソッドを使用します。このメソッドは、モデルの文字列表現を返します。

```python
print(s.model())
```

```python
print(s.model())
```

The output will display the values assigned to each variable in the model.

出力には、モデル内の各変数に割り当てられた値が表示されます。
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
# マシンの算術

現代のCPUと主流のプログラミング言語は、**固定サイズのビットベクトル**上での算術を使用しています。マシンの算術は、Z3Pyでは**ビットベクトル**として利用できます。
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
## 符号付き/符号なしの数値

Z3は、**ビットベクトルが符号付きか符号なしかによって処理が異なる**特別な符号付きバージョンの算術演算を提供します。Z3Pyでは、演算子**<、<=、>、>=、/、%、および>>**が**符号付き**バージョンに対応しています。対応する**符号なし**演算子は**ULT、ULE、UGT、UGE、UDiv、URem、およびLShR**です。
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
## 関数

**解釈された関数**は、**関数 +** が**固定された標準的な解釈**を持つ算術などの関数です（2つの数を足します）。**解釈されていない関数**と定数は**最大限の柔軟性**を持ち、関数または定数に関する制約と**整合性のある****任意の解釈**を許容します。

例：xに対してfを2回適用すると、再びxになりますが、xに対してfを1回適用するとxとは異なります。
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
# 例

## 数独ソルバー

```python
from z3 import *

def solve_sudoku(grid):
    # Create a 9x9 grid of integer variables
    cells = [[Int(f"cell_{i}_{j}") for j in range(9)] for i in range(9)]

    # Each cell must contain a value between 1 and 9
    cell_constraints = [And(1 <= cells[i][j], cells[i][j] <= 9) for i in range(9) for j in range(9)]

    # Each row must contain distinct values
    row_constraints = [Distinct(cells[i]) for i in range(9)]

    # Each column must contain distinct values
    column_constraints = [Distinct([cells[i][j] for i in range(9)]) for j in range(9)]

    # Each 3x3 subgrid must contain distinct values
    subgrid_constraints = [Distinct([cells[i + k][j + l] for k in range(3) for l in range(3)]) for i in range(0, 9, 3) for j in range(0, 9, 3)]

    # Add the initial values to the grid
    initial_constraints = [cells[i][j] == grid[i][j] for i in range(9) for j in range(9) if grid[i][j] != 0]

    # Create the solver and add all the constraints
    solver = Solver()
    solver.add(cell_constraints + row_constraints + column_constraints + subgrid_constraints + initial_constraints)

    # Check if there is a solution
    if solver.check() == sat:
        # Get the solution
        model = solver.model()

        # Extract the values from the model
        solution = [[model.evaluate(cells[i][j]).as_long() for j in range(9)] for i in range(9)]

        return solution

    return None

# Example Sudoku grid
grid = [
    [5, 3, 0, 0, 7, 0, 0, 0, 0],
    [6, 0, 0, 1, 9, 5, 0, 0, 0],
    [0, 9, 8, 0, 0, 0, 0, 6, 0],
    [8, 0, 0, 0, 6, 0, 0, 0, 3],
    [4, 0, 0, 8, 0, 3, 0, 0, 1],
    [7, 0, 0, 0, 2, 0, 0, 0, 6],
    [0, 6, 0, 0, 0, 0, 2, 8, 0],
    [0, 0, 0, 4, 1, 9, 0, 0, 5],
    [0, 0, 0, 0, 8, 0, 0, 7, 9]
]

# Solve the Sudoku
solution = solve_sudoku(grid)

# Print the solution
if solution:
    for row in solution:
        print(row)
else:
    print("No solution found.")
```

```python
from z3 import *

def solve_sudoku(grid):
    # 9x9の整数変数のグリッドを作成
    cells = [[Int(f"cell_{i}_{j}") for j in range(9)] for i in range(9)]

    # 各セルは1から9の値を含む必要がある
    cell_constraints = [And(1 <= cells[i][j], cells[i][j] <= 9) for i in range(9) for j in range(9)]

    # 各行は異なる値を含む必要がある
    row_constraints = [Distinct(cells[i]) for i in range(9)]

    # 各列は異なる値を含む必要がある
    column_constraints = [Distinct([cells[i][j] for i in range(9)]) for j in range(9)]

    # 各3x3のサブグリッドは異なる値を含む必要がある
    subgrid_constraints = [Distinct([cells[i + k][j + l] for k in range(3) for l in range(3)]) for i in range(0, 9, 3) for j in range(0, 9, 3)]

    # グリッドに初期値を追加
    initial_constraints = [cells[i][j] == grid[i][j] for i in range(9) for j in range(9) if grid[i][j] != 0]

    # ソルバーを作成し、すべての制約を追加
    solver = Solver()
    solver.add(cell_constraints + row_constraints + column_constraints + subgrid_constraints + initial_constraints)

    # 解が存在するかチェック
    if solver.check() == sat:
        # 解を取得
        model = solver.model()

        # モデルから値を抽出
        solution = [[model.evaluate(cells[i][j]).as_long() for j in range(9)] for i in range(9)]

        return solution

    return None

# 例となる数独グリッド
grid = [
    [5, 3, 0, 0, 7, 0, 0, 0, 0],
    [6, 0, 0, 1, 9, 5, 0, 0, 0],
    [0, 9, 8, 0, 0, 0, 0, 6, 0],
    [8, 0, 0, 0, 6, 0, 0, 0, 3],
    [4, 0, 0, 8, 0, 3, 0, 0, 1],
    [7, 0, 0, 0, 2, 0, 0, 0, 6],
    [0, 6, 0, 0, 0, 0, 2, 8, 0],
    [0, 0, 0, 4, 1, 9, 0, 0, 5],
    [0, 0, 0, 0, 8, 0, 0, 7, 9]
]

# 数独を解く
solution = solve_sudoku(grid)

# 解を表示
if solution:
    for row in solution:
        print(row)
else:
    print("解が見つかりませんでした。")
```
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
# 参考文献

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
