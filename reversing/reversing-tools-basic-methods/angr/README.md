<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


# インストール
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# 基本的なアクション

## Load Binary

### Load a binary into an angr project

### angrプロジェクトにバイナリをロードする

```python
import angr

proj = angr.Project("/path/to/binary")
```

## Find Functions

### Find all functions in the binary

### バイナリ内のすべての関数を見つける

```python
cfg = proj.analyses.CFGFast()
functions = cfg.functions
```

## Find Basic Blocks

### Find all basic blocks in a function

### 関数内のすべての基本ブロックを見つける

```python
function = cfg.functions["function_name"]
basic_blocks = function.blocks
```

## Find Instructions

### Find all instructions in a basic block

### 基本ブロック内のすべての命令を見つける

```python
basic_block = function.blocks[0]
instructions = basic_block.instructions
```

## Symbolic Execution

### Perform symbolic execution on a basic block

### 基本ブロック上でシンボリック実行を行う

```python
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0xdeadbeef, avoid=0xcafebabe)
```

## Path Exploration

### Explore all possible paths in a binary

### バイナリ内のすべての可能なパスを探索する

```python
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore()
```

## Constraint Solving

### Solve constraints using angr's symbolic expressions

### angrのシンボリック式を使用して制約を解決する

```python
state = proj.factory.entry_state()
solver = state.solver
solution = solver.eval(expr, cast_to=str)
```

## Patching Binaries

### Patch a binary with new instructions

### 新しい命令でバイナリをパッチする

```python
proj.hook(0xdeadbeef, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
```
```python
import angr
import monkeyhex # this will format numerical results in hexadecimal
#Load binary
proj = angr.Project('/bin/true')

#BASIC BINARY DATA
proj.arch #Get arch "<Arch AMD64 (LE)>"
proj.arch.name #'AMD64'
proj.arch.memory_endness #'Iend_LE'
proj.entry #Get entrypoint "0x4023c0"
proj.filename #Get filename "/bin/true"

#There are specific options to load binaries
#Usually you won't need to use them but you could
angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
```
# 読み込まれたデータ

The loaded data refers to the information that is loaded into the memory when a program is executed. This can include variables, functions, libraries, and other resources that are necessary for the program to run.

読み込まれたデータとは、プログラムが実行される際にメモリに読み込まれる情報のことを指します。これには、変数、関数、ライブラリ、およびプログラムの実行に必要なその他のリソースが含まれる場合があります。

## Main Object

The main object is the entry point of a program. It is the first function that is executed when the program starts running. The main object typically contains the program's initialization code and calls other functions as needed.

メインオブジェクトは、プログラムのエントリーポイントです。プログラムが実行されるときに最初に実行される関数です。メインオブジェクトには通常、プログラムの初期化コードが含まれ、必要に応じて他の関数を呼び出します。
```python
#LOADED DATA
proj.loader #<Loaded true, maps [0x400000:0x5004000]>
proj.loader.min_addr #0x400000
proj.loader.max_addr #0x5004000
proj.loader.all_objects #All loaded
proj.loader.shared_objects #Loaded binaries
"""
OrderedDict([('true', <ELF Object true, maps [0x400000:0x40a377]>),
('libc.so.6',
<ELF Object libc-2.31.so, maps [0x500000:0x6c4507]>),
('ld-linux-x86-64.so.2',
<ELF Object ld-2.31.so, maps [0x700000:0x72c177]>),
('extern-address space',
<ExternObject Object cle##externs, maps [0x800000:0x87ffff]>),
('cle##tls',
<ELFTLSObjectV2 Object cle##tls, maps [0x900000:0x91500f]>)])
"""
proj.loader.all_elf_objects #Get all ELF objects loaded (Linux)
proj.loader.all_pe_objects #Get all binaries loaded (Windows)
proj.loader.find_object_containing(0x400000)#Get object loaded in an address "<ELF Object fauxware, maps [0x400000:0x60105f]>"
```
## メインオブジェクト

The main object in angr is the `Project` class. It represents the binary being analyzed and provides various methods and attributes for performing analysis and manipulation.

angrのメインオブジェクトは`Project`クラスです。これは解析されるバイナリを表し、解析や操作を行うためのさまざまなメソッドと属性を提供します。

## Loading a Binary

To create a `Project` object, you need to provide the path to the binary file you want to analyze. You can do this using the `angr.Project()` constructor.

バイナリを解析するために`Project`オブジェクトを作成するには、解析したいバイナリファイルへのパスを指定する必要があります。これは`angr.Project()`コンストラクタを使用して行うことができます。

```python
import angr

# Load the binary
project = angr.Project('/path/to/binary')
```

```python
import angr

# バイナリをロードする
project = angr.Project('/path/to/binary')
```

## Exploring the Binary

Once you have loaded the binary, you can explore its properties and perform various analysis tasks. Some of the commonly used methods and attributes of the `Project` class are:

バイナリをロードしたら、そのプロパティを調査し、さまざまな解析タスクを実行することができます。`Project`クラスの一部のよく使用されるメソッドと属性は次のとおりです。

- `project.arch`: The architecture of the binary.
- `project.entry`: The entry point address of the binary.
- `project.loader`: The loader object that provides access to the binary's sections, symbols, and other information.
- `project.factory`: The factory object that provides methods for creating various analysis objects, such as `project.factory.block()` for creating basic blocks.

- `project.arch`: バイナリのアーキテクチャ。
- `project.entry`: バイナリのエントリポイントアドレス。
- `project.loader`: バイナリのセクション、シンボル、およびその他の情報にアクセスするためのローダーオブジェクト。
- `project.factory`: 基本ブロックを作成するための`project.factory.block()`など、さまざまな解析オブジェクトを作成するためのメソッドを提供するファクトリーオブジェクト。

## Symbolic Execution

One of the powerful features of angr is its support for symbolic execution. Symbolic execution allows you to explore all possible paths through a binary by treating inputs as symbolic variables. This can be useful for finding vulnerabilities, understanding program behavior, and generating test cases.

angrの強力な機能の1つは、シンボリック実行のサポートです。シンボリック実行により、入力をシンボリック変数として扱い、バイナリを通過するすべての可能なパスを探索することができます。これは脆弱性の発見、プログラムの動作の理解、テストケースの生成に役立ちます。

To perform symbolic execution, you can use the `project.factory.simulation_manager()` method to create a `SimulationManager` object. The `SimulationManager` object allows you to explore different paths through the binary and collect information about the program state at each path.

シンボリック実行を行うには、`project.factory.simulation_manager()`メソッドを使用して`SimulationManager`オブジェクトを作成します。`SimulationManager`オブジェクトを使用すると、バイナリを通過するさまざまなパスを探索し、各パスでのプログラムの状態に関する情報を収集することができます。

```python
import angr

# Load the binary
project = angr.Project('/path/to/binary')

# Create a SimulationManager object
sim_manager = project.factory.simulation_manager()

# Explore the binary
sim_manager.explore()
```

```python
import angr

# バイナリをロードする
project = angr.Project('/path/to/binary')

# SimulationManagerオブジェクトを作成する
sim_manager = project.factory.simulation_manager()

# バイナリを探索する
sim_manager.explore()
```

## Analyzing Program State

During symbolic execution, you can analyze the program state at each path to gather information about the program's behavior. Some of the commonly used methods and attributes of the `SimulationManager` class are:

シンボリック実行中に、各パスでプログラムの状態を分析してプログラムの動作に関する情報を収集することができます。`SimulationManager`クラスの一部のよく使用されるメソッドと属性は次のとおりです。

- `sim_manager.active`: A list of active states, representing the current program state at each path.
- `sim_manager.deadended`: A list of deadended states, representing the program states that have reached an exit point.
- `sim_manager.stashes`: A dictionary of stashes, which can be used to organize and manage states.

- `sim_manager.active`: アクティブな状態のリストで、各パスの現在のプログラムの状態を表します。
- `sim_manager.deadended`: 終了ポイントに到達したプログラムの状態を表す、終了した状態のリスト。
- `sim_manager.stashes`: 状態を整理管理するために使用できるスタッシュの辞書。

## Manipulating Program State

In addition to analyzing program state, angr allows you to manipulate the program state to guide the analysis or explore specific behaviors. Some of the commonly used methods and attributes for manipulating program state are:

プログラムの状態を分析するだけでなく、angrではプログラムの状態を操作して解析を誘導したり、特定の動作を探索したりすることができます。プログラムの状態を操作するための一部のよく使用されるメソッドと属性は次のとおりです。

- `state.solver`: The solver object associated with a state, which can be used to solve constraints and perform symbolic operations.
- `state.memory`: The memory object associated with a state, which can be used to read from and write to memory.
- `state.regs`: The register object associated with a state, which can be used to read from and write to registers.

- `state.solver`: 状態に関連付けられたソルバーオブジェクトで、制約を解決したりシンボリック操作を実行したりするために使用できます。
- `state.memory`: 状態に関連付けられたメモリオブジェクトで、メモリから読み取りや書き込みを行うために使用できます。
- `state.regs`: 状態に関連付けられたレジスタオブジェクトで、レジスタへの読み取りや書き込みを行うために使用できます。

## Conclusion

This is just a brief introduction to the basic methods and concepts in angr. There are many more advanced features and techniques that can be explored. The angr documentation and examples provide more detailed information on how to use angr for various analysis tasks.

これはangrの基本的なメソッドと概念の簡単な紹介です。さらに詳細な情報やさまざまな解析タスクにangrを使用する方法については、angrのドキュメントと例を参照してください。
```python
#Main Object (main binary loaded)
obj = proj.loader.main_object #<ELF Object true, maps [0x400000:0x60721f]>
obj.execstack #"False" Check for executable stack
obj.pic #"True" Check PIC
obj.imports #Get imports
obj.segments #<Regions: [<ELFSegment flags=0x5, relro=0x0, vaddr=0x400000, memsize=0xa74, filesize=0xa74, offset=0x0>, <ELFSegment flags=0x4, relro=0x1, vaddr=0x600e28, memsize=0x1d8, filesize=0x1d8, offset=0xe28>, <ELFSegment flags=0x6, relro=0x0, vaddr=0x601000, memsize=0x60, filesize=0x50, offset=0x1000>]>
obj.find_segment_containing(obj.entry) #Get segment by address
obj.sections #<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>, <.interp | offset 0x238, vaddr 0x400238, size 0x1c>, <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>, <.note.gnu.build-id ...
obj.find_section_containing(obj.entry) #Get section by address
obj.plt['strcmp'] #Get plt address of a funcion (0x400550)
obj.reverse_plt[0x400550] #Get function from plt address ('strcmp')
```
## シンボルとリロケーション

Symbols and relocations are important concepts in reverse engineering and binary analysis. They provide valuable information about the structure and functionality of a binary executable.

シンボルとリロケーションは、リバースエンジニアリングとバイナリ解析において重要な概念です。これらは、バイナリ実行ファイルの構造と機能に関する貴重な情報を提供します。

### Symbols

シンボル

Symbols are identifiers used to represent various entities in a binary executable, such as functions, variables, and data structures. They serve as references to specific memory locations or code sections within the binary.

シンボルは、バイナリ実行ファイル内のさまざまなエンティティ（関数、変数、データ構造など）を表すために使用される識別子です。これらは、バイナリ内の特定のメモリ位置やコードセクションへの参照として機能します。

Symbols can be either global or local. Global symbols are accessible from other parts of the binary, while local symbols are only visible within their respective code sections.

シンボルは、グローバルまたはローカルのいずれかになります。グローバルシンボルは、バイナリの他の部分からアクセスできますが、ローカルシンボルは、それぞれのコードセクション内でのみ表示されます。

### Relocations

リロケーション

Relocations are instructions or records that specify how to modify the binary's code or data during the linking process. They are used to resolve references to symbols that are not yet known at compile time.

リロケーションは、リンクプロセス中にバイナリのコードやデータをどのように修正するかを指定する命令またはレコードです。これらは、コンパイル時にはまだ不明なシンボルへの参照を解決するために使用されます。

Relocations are typically stored in a separate section of the binary called the relocation section. During the linking process, the linker will use the relocation information to adjust the addresses of symbols and ensure that all references are resolved correctly.

リロケーションは通常、リロケーションセクションと呼ばれるバイナリの別のセクションに格納されます。リンクプロセス中、リンカはリロケーション情報を使用してシンボルのアドレスを調整し、すべての参照が正しく解決されるようにします。

Understanding symbols and relocations is crucial for analyzing and modifying binary executables. By examining these elements, reverse engineers can gain insights into the inner workings of a program and identify potential vulnerabilities or areas for improvement.

シンボルとリロケーションの理解は、バイナリ実行ファイルの解析と修正において重要です。これらの要素を調査することで、リバースエンジニアはプログラムの内部動作を理解し、潜在的な脆弱性や改善の余地を特定することができます。
```python
strcmp = proj.loader.find_symbol('strcmp') #<Symbol "strcmp" in libc.so.6 at 0x1089cd0>

strcmp.name #'strcmp'
strcmp.owne #<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>
strcmp.rebased_addr #0x1089cd0
strcmp.linked_addr #0x89cd0
strcmp.relative_addr #0x89cd0
strcmp.is_export #True, as 'strcmp' is a function exported by libc

#Get strcmp from the main object
main_strcmp = proj.loader.main_object.get_symbol('strcmp')
main_strcmp.is_export #False
main_strcmp.is_import #True
main_strcmp.resolvedby #<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```
## ブロック

### Basic Blocks

基本ブロックは、プログラムの実行中に連続して実行される命令のシーケンスです。基本ブロックは、制御フローグラフ内のノードとして表されます。基本ブロックは、単一の入力と単一の出力を持ち、通常は最初の命令から最後の命令まで直線的に実行されます。

### Super Blocks

スーパーブロックは、基本ブロックの集合です。スーパーブロックは、複数の基本ブロックを含むことができますが、制御フローグラフ内の単一のノードとして表されます。スーパーブロックは、複数の入力と複数の出力を持つことができます。

### Function Blocks

関数ブロックは、関数内のすべての基本ブロックを含むスーパーブロックです。関数ブロックは、関数の制御フローグラフ内の単一のノードとして表されます。関数ブロックは、関数の入力と出力を持つことができます。

### Exception Blocks

例外ブロックは、例外処理のために使用される特殊なブロックです。例外ブロックは、例外が発生した場合に制御フローが移動する場所を示します。例外ブロックは、通常、try-catch文や例外ハンドラ内のコードの一部として表されます。

### Loop Blocks

ループブロックは、ループ構造を表すブロックです。ループブロックは、ループ内の基本ブロックの集合として表されます。ループブロックは、ループの制御フローグラフ内の単一のノードとして表されます。

### Conditional Blocks

条件ブロックは、条件分岐を表すブロックです。条件ブロックは、条件分岐の各パスに対応する基本ブロックの集合として表されます。条件ブロックは、条件分岐の制御フローグラフ内の単一のノードとして表されます。
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# シミュレーションマネージャー、ステート

シミュレーションマネージャーは、angrの中核的なコンポーネントであり、バイナリの実行をシミュレートするために使用されます。シミュレーションマネージャーは、バイナリの実行を制御し、異なるステート（状態）を管理します。

ステートは、バイナリの実行時の特定の状態を表します。ステートには、レジスタの値、メモリの内容、フラグの状態など、バイナリの実行に関連する情報が含まれます。

シミュレーションマネージャーは、複数のステートを管理し、それらを適切な方法で制御します。これにより、異なるパスを探索し、バイナリの実行のさまざまな側面を分析することができます。

ステートの作成や変更、制御フローの解析など、さまざまな操作を実行するために、angrは強力なAPIを提供しています。これにより、バイナリの解析やリバースエンジニアリングのプロセスを効率化することができます。
```python
#Live States
#This is useful to modify content in a live analysis
state = proj.factory.entry_state()
state.regs.rip #Get the RIP
state.mem[proj.entry].int.resolved #Resolve as a C int (BV)
state.mem[proj.entry].int.concreteved #Resolve as python int
state.regs.rsi = state.solver.BVV(3, 64) #Modify RIP
state.mem[0x1000].long = 4 #Modify mem

#Other States
project.factory.entry_state()
project.factory.blank_state() #Most of its data left uninitialized
project.factory.full_init_statetate() #Execute through any initializers that need to be run before the main binary's entry point
project.factory.call_state() #Ready to execute a given function.

#Simulation manager
#The simulation manager stores all the states across the execution of the binary
simgr = proj.factory.simulation_manager(state) #Start
simgr.step() #Execute one step
simgr.active[0].regs.rip #Get RIP from the last state
```
## 関数の呼び出し

* `args`を介して引数のリストと`env`を介して環境変数の辞書を`entry_state`と`full_init_state`に渡すことができます。これらの構造体の値は、文字列またはビットベクトルであることができ、シミュレートされた実行の引数と環境として状態にシリアライズされます。デフォルトの`args`は空のリストですので、解析しているプログラムが少なくとも`argv[0]`を見つけることを期待している場合は、常にそれを提供する必要があります！
* `argc`をシンボリックにしたい場合は、`entry_state`と`full_init_state`のコンストラクタにシンボリックなビットベクトルとして`argc`を渡すことができます。ただし、注意してください。これを行う場合は、`args`に渡した引数の数よりも大きい値にならないように、結果の状態に制約を追加する必要があります。
* コールステートを使用するには、`.call_state(addr, arg1, arg2, ...)`と呼び出す必要があります。ここで、`addr`は呼び出したい関数のアドレスであり、`argN`はその関数のN番目の引数です。これは、Pythonの整数、文字列、配列、またはビットベクトルとして指定できます。オブジェクトにポインタを割り当てて実際に渡す場合は、PointerWrapperでラップする必要があります。例えば、`angr.PointerWrapper("point to me!")`です。このAPIの結果は少し予測できないことがありますが、改善に取り組んでいます。

## ビットベクトル
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## シンボリックビットベクトルと制約

シンボリックビットベクトルは、バイナリコードの解析において非常に重要な役割を果たします。シンボリックビットベクトルは、具体的な値ではなく、論理的な制約を表すビットの集合です。これにより、プログラムの実行パスに関する制約を表現することができます。

制約は、プログラムの実行中に特定の条件が満たされる必要があることを示します。例えば、ある変数が特定の値に等しい必要がある場合、その変数に対する制約を設定することができます。シンボリックビットベクトルを使用すると、プログラムの実行パスに関する制約を表現し、解析することができます。

シンボリックビットベクトルと制約を使用すると、プログラムの実行パスを制御することができます。これにより、特定の条件下でのプログラムの挙動を分析することができます。また、シンボリックビットベクトルを使用することで、プログラムの実行パスに関する制約を解決し、具体的な入力値を見つけることもできます。

シンボリックビットベクトルと制約は、逆アセンブリやバイナリ解析において非常に強力なツールです。これらのツールを使用することで、プログラムの内部の動作を理解し、脆弱性を特定することができます。
```python
x = state.solver.BVS("x", 64) #Symbolic variable BV of length 64
y = state.solver.BVS("y", 64)

#Symbolic oprations
tree = (x + 1) / (y + 2)
tree #<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
tree.op #'__floordiv__' Access last operation
tree.args #(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
tree.args[0].op #'__add__' Access of dirst arg
tree.args[0].args #(<BV64 x_9_64>, <BV64 0x1>)
tree.args[0].args[1].op #'BVV'
tree.args[0].args[1].args #(1, 64)

#Symbolic constraints solver
state = proj.factory.entry_state() #Get a fresh state without constraints
input = state.solver.BVS('input', 64)
operation = (((input + 4) * 3) >> 1) + input
output = 200
state.solver.add(operation == output)
state.solver.eval(input) #0x3333333333333381
state.solver.add(input < 2**32)
state.satisfiable() #False

#Solver solutions
solver.eval(expression) #one possible solution
solver.eval_one(expression) #solution to the given expression, or throw an error if more than one solution is possible.
solver.eval_upto(expression, n) #n solutions to the given expression, returning fewer than n if fewer than n are possible.
solver.eval_atleast(expression, n) #n solutions to the given expression, throwing an error if fewer than n are possible.
solver.eval_exact(expression, n) #n solutions to the given expression, throwing an error if fewer or more than are possible.
solver.min(expression) #minimum possible solution to the given expression.
solver.max(expression) #maximum possible solution to the given expression.
```
## フック

フックは、プログラムの実行中に特定の関数やイベントを監視し、それらに対してカスタムコードを実行する技術です。フックは、リバースエンジニアリングやマルウェア分析などの様々なセキュリティ関連のタスクで使用されます。

フックの一般的な使用例は、関数フックです。関数フックは、特定の関数が呼び出されるたびに、カスタムコードを実行することができます。これにより、関数の引数や戻り値を監視したり、関数の動作を変更したりすることができます。

フックの実装方法はいくつかありますが、一般的な方法は以下の通りです。

1. フック関数を定義します。この関数は、フックしたい関数と同じシグネチャを持つ必要があります。
2. フック関数をターゲット関数にフックします。これにより、ターゲット関数が呼び出されるたびに、フック関数が実行されます。
3. フック関数内で必要な処理を実装します。これには、引数や戻り値の監視、変更、または追加の処理などが含まれます。

フックは、プログラムの実行中に動的に適用されるため、デバッグや解析のために非常に便利です。また、フックを使用することで、既存のプログラムの動作を変更することも可能です。しかし、フックは悪意のある目的で使用されることもあるため、注意が必要です。
```python
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```
さらに、`proj.hook_symbol(name, hook)`を使用することで、最初の引数としてシンボルの名前を指定し、シンボルが存在するアドレスにフックを設定することができます。

# 例

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
