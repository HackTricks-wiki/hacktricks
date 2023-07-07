# Angr - 例

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

{% hint style="info" %}
プログラムが\*\*`scanf` \*\*を使用して**stdinから一度に複数の値を取得**している場合、**`scanf`**の後から開始する状態を生成する必要があります。
{% endhint %}

### アドレスを指定して到達するための入力
```python
import angr
import sys

def main(argv):
path_to_binary = argv[1]  # :string
project = angr.Project(path_to_binary)

# Start in main()
initial_state = project.factory.entry_state()
# Start simulation
simulation = project.factory.simgr(initial_state)

# Find the way yo reach the good address
good_address = 0x804867d

# Avoiding this address
avoid_address = 0x080485A8
simulation.explore(find=good_address , avoid=avoid_address ))

# If found a way to reach the address
if simulation.found:
solution_state = simulation.found[0]

# Print the string that Angr wrote to stdin to follow solution_state
print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### アドレスに到達するための入力（プリントを示す）
```python
# If you don't know the address you want to recah, but you know it's printing something
# You can also indicate that info

import angr
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state)

def is_successful(state):
#Successful print
stdout_output = state.posix.dumps(sys.stdout.fileno())
return b'Good Job.' in stdout_output

def should_abort(state):
#Avoid this print
stdout_output = state.posix.dumps(sys.stdout.fileno())
return b'Try again.' in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### レジストリの値

Registry values are key-value pairs stored in the Windows Registry. They are used to store configuration settings and other important information for the operating system and installed applications. Understanding how to work with registry values is essential for various tasks, including troubleshooting, system optimization, and malware analysis.

レジストリの値は、Windowsレジストリに格納されるキーと値のペアです。これらは、オペレーティングシステムやインストールされたアプリケーションの設定やその他の重要な情報を格納するために使用されます。レジストリの値を操作する方法を理解することは、トラブルシューティング、システムの最適化、マルウェアの分析など、さまざまなタスクにおいて重要です。

When analyzing malware or performing system forensics, examining registry values can provide valuable insights into the behavior of the malicious software or the system's configuration. It can help identify persistence mechanisms, command and control (C2) communication channels, and other indicators of compromise.

マルウェアの分析やシステムのフォレンジックを行う際には、レジストリの値を調査することで、悪意のあるソフトウェアやシステムの構成に関する貴重な情報を得ることができます。これにより、持続性のメカニズム、コマンドアンドコントロール（C2）の通信チャネル、およびその他の侵害の指標を特定するのに役立ちます。

There are various tools and techniques available for working with registry values. These include manual inspection using the Windows Registry Editor (regedit), command-line tools like reg.exe, and automated analysis using tools like volatility and Registry Explorer.

レジストリの値を操作するためには、さまざまなツールや技術が利用できます。これには、Windows Registry Editor（regedit）を使用した手動の検査、reg.exeなどのコマンドラインツール、およびvolatilityやRegistry Explorerなどのツールを使用した自動化された分析が含まれます。

When examining registry values, it is important to be cautious and take appropriate precautions to avoid accidentally modifying or deleting critical system settings. Creating backups and using virtualized environments for analysis can help mitigate the risk of unintended consequences.

レジストリの値を調査する際には、誤って重要なシステム設定を変更または削除することを防ぐために、注意を払い、適切な予防措置を取ることが重要です。バックアップの作成や仮想化環境の使用は、意図しない結果のリスクを軽減するのに役立ちます。
```python
# Angr doesn't currently support reading multiple things with scanf (Ex:
# scanf("%u %u).) You will have to tell the simulation engine to begin the
# program after scanf is called and manually inject the symbols into registers.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Address were you want to indicate the relation BitVector - registries
start_address = 0x80488d1
initial_state = project.factory.blank_state(addr=start_address)


# Create Bit Vectors
password0_size_in_bits = 32  # :integer
password0 = claripy.BVS('password0', password0_size_in_bits)

password1_size_in_bits = 32  # :integer
password1 = claripy.BVS('password1', password1_size_in_bits)

password2_size_in_bits = 32  # :integer
password2 = claripy.BVS('password2', password2_size_in_bits)

# Relate it Vectors with the registriy values you are interested in to reach an address
initial_state.regs.eax = password0
initial_state.regs.ebx = password1
initial_state.regs.edx = password2

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution0 = solution_state.solver.eval(password0)
solution1 = solution_state.solver.eval(password1)
solution2 = solution_state.solver.eval(password2)

# Aggregate and format the solutions you computed above, and then print
# the full string. Pay attention to the order of the integers, and the
# expected base (decimal, octal, hexadecimal, etc).
solution = ' '.join(map('{:x}'.format, [ solution0, solution1, solution2 ]))  # :string
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### スタックの値

The stack is a data structure used in computer programming to store and manage variables and function calls. It operates on a "last in, first out" (LIFO) principle, meaning that the last item added to the stack is the first one to be removed.

スタックは、コンピュータプログラミングで変数や関数呼び出しを格納および管理するために使用されるデータ構造です。スタックは「後入れ先出し」（LIFO）の原則に基づいて動作し、スタックに追加された最後のアイテムが最初に削除されます。

In the context of reverse engineering and binary analysis, understanding the values stored in the stack can be crucial for understanding the behavior of a program. By analyzing the stack, you can gain insights into how variables are manipulated and how function calls are made.

逆アセンブリやバイナリ解析の文脈において、スタックに格納された値を理解することは、プログラムの動作を理解する上で重要です。スタックを分析することで、変数の操作方法や関数呼び出しの仕組みについて洞察を得ることができます。

To examine the values stored in the stack during the execution of a program, you can use various debugging and analysis tools. These tools allow you to inspect the memory addresses and contents of the stack, helping you understand how the program manipulates and uses the stack.

プログラムの実行中にスタックに格納された値を調べるためには、さまざまなデバッグおよび解析ツールを使用することができます。これらのツールを使用すると、スタックのメモリアドレスや内容を調査することができ、プログラムがスタックをどのように操作し利用しているかを理解するのに役立ちます。

By analyzing the stack values, you can identify important variables, function arguments, return values, and other critical information that can aid in understanding the program's logic and behavior.

スタックの値を分析することで、重要な変数、関数の引数、戻り値、および他の重要な情報を特定することができます。これらの情報は、プログラムのロジックと動作を理解するのに役立ちます。
```python
# Put bit vectors in th stack to find out the vallue that stack position need to
# have to reach a rogram flow

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Go to some address after the scanf where values have already being set in the stack
start_address = 0x8048697
initial_state = project.factory.blank_state(addr=start_address)

# Since we are starting after scanf, we are skipping this stack construction
# step. To make up for this, we need to construct the stack ourselves. Let us
# start by initializing ebp in the exact same way the program does.
initial_state.regs.ebp = initial_state.regs.esp

# In this case scanf("%u %u") is used, so 2 BVS are going to be needed
password0 = claripy.BVS('password0', 32)
password1 = claripy.BVS('password1', 32)

# Now, in the address were you have stopped, check were are the scanf values saved
# Then, substrack form the esp registry the needing padding to get to the
# part of the stack were the scanf values are being saved and push the BVS
# (see the image below to understan this -8)
padding_length_in_bytes = 8  # :integer
initial_state.regs.esp -= padding_length_in_bytes

initial_state.stack_push(password0)
initial_state.stack_push(password1)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution0 = solution_state.solver.eval(password0)
solution1 = solution_state.solver.eval(password1)

solution = ' '.join(map(str, [ solution0, solution1 ]))
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
このシナリオでは、入力は `scanf("%u %u")` で受け取られ、値 `"1 1"` が与えられたため、スタックの値 **`0x00000001`** は **ユーザーの入力** から来ています。これらの値は `$ebp - 8` から始まることがわかります。したがって、コードでは **`$esp` から 8 バイトを引いて（その時点で `$ebp` と `$esp` は同じ値を持っていたため）** BVS をプッシュしました。

![](<../../../.gitbook/assets/image (614).png>)

### 静的メモリ値（グローバル変数）
```python
import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

#Get an address after the scanf. Once the input has already being saved in the memory positions
start_address = 0x8048606
initial_state = project.factory.blank_state(addr=start_address)

# The binary is calling scanf("%8s %8s %8s %8s").
# So we need 4 BVS of size 8*8
password0 = claripy.BVS('password0', 8*8)
password1 = claripy.BVS('password1', 8*8)
password2 = claripy.BVS('password2', 8*8)
password3 = claripy.BVS('password3', 8*8)

# Write the symbolic BVS in the memory positions
password0_address = 0xa29faa0
initial_state.memory.store(password0_address, password0)
password1_address = 0xa29faa8
initial_state.memory.store(password1_address, password1)
password2_address = 0xa29fab0
initial_state.memory.store(password2_address, password2)
password3_address = 0xa29fab8
initial_state.memory.store(password3_address, password3)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

# Get the values the memory addresses should store
solution0 = solution_state.solver.eval(password0,cast_to=bytes).decode()
solution1 = solution_state.solver.eval(password1,cast_to=bytes).decode()
solution2 = solution_state.solver.eval(password2,cast_to=bytes).decode()
solution3 = solution_state.solver.eval(password3,cast_to=bytes).decode()

solution = ' '.join([ solution0, solution1, solution2, solution3 ])

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### 動的メモリの値（Malloc）

In this example, we will use angr to analyze a binary that dynamically allocates memory using the `malloc` function. The goal is to find the values stored in the dynamically allocated memory.

```python
import angr

# Load the binary
project = angr.Project("/path/to/binary")

# Set up the initial state
state = project.factory.entry_state()

# Create a simulation manager
simgr = project.factory.simulation_manager(state)

# Explore the program's execution
simgr.explore()

# Get the final states
final_states = simgr.deadended

# Iterate over the final states
for state in final_states:
    # Get the memory address of the dynamically allocated memory
    malloc_address = state.solver.eval(state.regs.rax)

    # Get the value stored in the dynamically allocated memory
    malloc_value = state.mem[malloc_address].int.concrete

    # Print the memory address and value
    print(f"Memory Address: {malloc_address}")
    print(f"Value: {malloc_value}")
```

In this example, we first load the binary using `angr.Project` and set up the initial state using `project.factory.entry_state()`. We then create a simulation manager using `project.factory.simulation_manager(state)`.

We explore the program's execution using `simgr.explore()`, which will automatically explore all possible paths in the binary. The final states are obtained using `simgr.deadended`.

We iterate over the final states and use `state.solver.eval(state.regs.rax)` to get the memory address of the dynamically allocated memory. We then use `state.mem[malloc_address].int.concrete` to get the value stored in that memory address.

Finally, we print the memory address and value using `print(f"Memory Address: {malloc_address}")` and `print(f"Value: {malloc_value}")`, respectively.
```python
import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Get address after scanf
start_address = 0x804869e
initial_state = project.factory.blank_state(addr=start_address)

# The binary is calling scanf("%8s %8s") so 2 BVS are needed.
password0 = claripy.BVS('password0', 8*8)
password1 = claripy.BVS('password0', 8*8)

# Find a coupble of addresses that aren't used by the binary (like 0x4444444 & 0x4444454)
# The address generated by mallosc is going to be saved in some address
# Then, make that address point to the fake heap addresses were the BVS are going to be saved
fake_heap_address0 = 0x4444444
pointer_to_malloc_memory_address0 = 0xa79a118
initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
fake_heap_address1 = 0x4444454
pointer_to_malloc_memory_address1 = 0xa79a120
initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)

# Save the VBS in the new fake heap addresses created
initial_state.memory.store(fake_heap_address0, password0)
initial_state.memory.store(fake_heap_address1, password1)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution0 = solution_state.solver.eval(password0,cast_to=bytes).decode()
solution1 = solution_state.solver.eval(password1,cast_to=bytes).decode()

solution = ' '.join([ solution0, solution1 ])

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### ファイルシミュレーション

The `angr` framework provides a powerful feature called file simulation, which allows you to analyze the behavior of a program when interacting with files. This feature is particularly useful when reverse engineering binary files or when analyzing the impact of file operations on program execution.

To perform file simulation with `angr`, you need to create a `SimFile` object that represents the file you want to simulate. You can specify the file's name, size, and other attributes. Once you have created the `SimFile` object, you can use it to interact with the program being analyzed.

For example, you can use the `write` method of the `SimFile` object to simulate writing data to the file. This can be useful to understand how the program handles user input or to analyze the impact of specific data on program execution.

Similarly, you can use the `read` method of the `SimFile` object to simulate reading data from the file. This can help you understand how the program processes input from files or how it reacts to specific file contents.

By combining file simulation with other features of `angr`, such as symbolic execution or taint analysis, you can gain a deeper understanding of the program's behavior and identify potential vulnerabilities or interesting code paths.

Overall, file simulation is a powerful technique provided by the `angr` framework that allows you to analyze the behavior of a program when interacting with files. It can be used for reverse engineering, vulnerability analysis, or any other task that involves understanding the impact of file operations on program execution.
```python
#In this challenge a password is read from a file and we want to simulate its content

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Get an address just before opening the file with th simbolic content
# Or at least when the file is not going to suffer more changes before being read
start_address = 0x80488db
initial_state = project.factory.blank_state(addr=start_address)

# Specify the filena that is going to open
# Note that in theory, the filename could be symbolic.
filename = 'WCEXPXBW.txt'
symbolic_file_size_bytes = 64

# Create a BV which is going to be the content of the simbolic file
password = claripy.BVS('password', symbolic_file_size_bytes * 8)

# Create the file simulation with the simbolic content
password_file = angr.storage.SimFile(filename, content=password)

# Add the symbolic file we created to the symbolic filesystem.
initial_state.fs.insert(filename, password_file)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution = solution_state.solver.eval(password,cast_to=bytes).decode()

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
{% hint style="info" %}
シンボリックファイルには、シンボリックデータと結合された定数データも含まれる場合があることに注意してください。
```python
# Hello world, my name is John.
# ^                       ^
# ^ address 0             ^ address 24 (count the number of characters)
# In order to represent this in memory, we would want to write the string to
# the beginning of the file:
#
# hello_txt_contents = claripy.BVV('Hello world, my name is John.', 30*8)
#
# Perhaps, then, we would want to replace John with a
# symbolic variable. We would call:
#
# name_bitvector = claripy.BVS('symbolic_name', 4*8)
#
# Then, after the program calls fopen('hello.txt', 'r') and then
# fread(buffer, sizeof(char), 30, hello_txt_file), the buffer would contain
# the string from the file, except four symbolic bytes where the name would be
# stored.
# (!)
```
{% endhint %}

### 制約の適用

{% hint style="info" %}
時には、16文字の単語を1文字ずつ比較するような単純な人間の操作は、**angr**にとって非常にコストがかかります。なぜなら、それは1つのifごとに1つの分岐を生成するため、指数的に分岐を生成する必要があるからです: `2^16`\
そのため、**angrに以前のポイントに到達してもらい**（実際の難しい部分がすでに完了している場所）、**手動で制約を設定する**方が簡単です。
{% endhint %}
```python
# After perform some complex poperations to the input the program checks
# char by char the password against another password saved, like in the snippet:
#
# #define REFERENCE_PASSWORD = "AABBCCDDEEFFGGHH";
# int check_equals_AABBCCDDEEFFGGHH(char* to_check, size_t length) {
#   uint32_t num_correct = 0;
#   for (int i=0; i<length; ++i) {
#     if (to_check[i] == REFERENCE_PASSWORD[i]) {
#       num_correct += 1;
#     }
#   }
#   return num_correct == length;
# }
#
# ...
#
# char* input = user_input();
# char* encrypted_input = complex_function(input);
# if (check_equals_AABBCCDDEEFFGGHH(encrypted_input, 16)) {
#   puts("Good Job.");
# } else {
#   puts("Try again.");
# }
#
# The function checks if *to_check == "AABBCCDDEEFFGGHH". This is very RAM consumming
# as the computer needs to branch every time the if statement in the loop was called (16
# times), resulting in 2^16 = 65,536 branches, which will take too long of a
# time to evaluate for our needs.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

simulation = project.factory.simgr(initial_state)

# Get an address to check after the complex function and before the "easy compare" operation
address_to_check_constraint = 0x8048671
simulation.explore(find=address_to_check_constraint)


if simulation.found:
solution_state = simulation.found[0]

# Find were the input that is going to be compared is saved in memory
constrained_parameter_address = 0x804a050
constrained_parameter_size_bytes = 16
# Set the bitvector
constrained_parameter_bitvector = solution_state.memory.load(
constrained_parameter_address,
constrained_parameter_size_bytes
)

# Indicate angr that this BV at this point needs to be equal to the password
constrained_parameter_desired_value = 'BWYRUBQCMVSBRGFU'.encode()
solution_state.add_constraints(constrained_parameter_bitvector == constrained_parameter_desired_value)

print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
{% hint style="danger" %}
いくつかのシナリオでは、似たような状態をマージして不要なブランチを省略し、解決策を見つけるために**veritesting**を有効にすることができます：`simulation = project.factory.simgr(initial_state, veritesting=True)`
{% endhint %}

{% hint style="info" %}
これらのシナリオでは、angrにより理解しやすいものを提供するために、関数を**フックする**こともできます。
{% endhint %}

### シミュレーションマネージャー

一部のシミュレーションマネージャーは、他のものよりも便利です。前の例では、多くの有用なブランチが作成されるという問題がありました。ここでは、**veritesting**のテクニックを使用してそれらをマージし、解決策を見つけます。\
このシミュレーションマネージャーは、次のようにも有効にできます：`simulation = project.factory.simgr(initial_state, veritesting=True)`
```python
import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

simulation = project.factory.simgr(initial_state)
# Set simulation technique
simulation.use_technique(angr.exploration_techniques.Veritesting())


def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())

return 'Good Job.'.encode() in stdout_output  # :boolean

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output  # :boolean

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')


if __name__ == '__main__':
main(sys.argv)
```
### 関数への1つの呼び出しのフック/バイパス

In this example, we will use angr to hook or bypass a specific call to a function in a binary. 

この例では、angrを使用して、バイナリ内の特定の関数への呼び出しをフックまたはバイパスします。

First, we need to create an angr project and load the binary:

まず、angrプロジェクトを作成し、バイナリをロードする必要があります。

```python
import angr

project = angr.Project("/path/to/binary")
```

Next, we need to find the address of the call instruction we want to hook or bypass. We can use the `find` method to search for the address:

次に、フックまたはバイパスしたい呼び出し命令のアドレスを見つける必要があります。`find`メソッドを使用してアドレスを検索できます。

```python
call_address = project.loader.find_symbol("function_to_hook").rebased_addr
```

Now, we can create a hook for the call instruction using the `SimProcedure` class:

これで、`SimProcedure`クラスを使用して、呼び出し命令のフックを作成できます。

```python
class Hook(angr.SimProcedure):
    def run(self):
        # Perform custom actions here
        # Custom code to execute instead of the original function call
        # You can modify registers, memory, etc.
        # Return a value if necessary
        return 0

# Hook the call instruction
project.hook(call_address, Hook())
```

Alternatively, if we want to bypass the call instruction completely, we can use the `SimProcedure` class to create a custom procedure that does nothing:

または、呼び出し命令を完全にバイパスしたい場合は、`SimProcedure`クラスを使用して何もしないカスタム手続きを作成できます。

```python
class Bypass(angr.SimProcedure):
    def run(self):
        # Do nothing
        pass

# Bypass the call instruction
project.hook(call_address, Bypass())
```

Finally, we can execute the binary with angr and observe the effects of the hook or bypass:

最後に、angrでバイナリを実行し、フックまたはバイパスの効果を観察できます。

```python
state = project.factory.entry_state()
simulation = project.factory.simgr(state)
simulation.run()
```

By hooking or bypassing a specific call to a function, we can modify the behavior of the binary and potentially achieve desired outcomes.
```python
# This level performs the following computations:
#
# 1. Get 16 bytes of user input and encrypt it.
# 2. Save the result of check_equals_AABBCCDDEEFFGGHH (or similar)
# 3. Get another 16 bytes from the user and encrypt it.
# 4. Check that it's equal to a predefined password.
#
# The ONLY part of this program that we have to worry about is #2. We will be
# replacing the call to check_equals_ with our own version, using a hook, since
# check_equals_ will run too slowly otherwise.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

# Hook the address of the call to hook indicating th length of the instruction (of the call)
check_equals_called_address = 0x80486b8
instruction_to_skip_length = 5
@project.hook(check_equals_called_address, length=instruction_to_skip_length)
def skip_check_equals_(state):
#Load the input of the function reading direcly the memory
user_input_buffer_address = 0x804a054
user_input_buffer_length = 16
user_input_string = state.memory.load(
user_input_buffer_address,
user_input_buffer_length
)

# Create a simbolic IF that if the loaded string frommemory is the expected
# return True (1) if not returns False (0) in eax
check_against_string = 'XKSPZSJKJYQCQXZV'.encode() # :string

state.regs.eax = claripy.If(
user_input_string == check_against_string,
claripy.BVV(1, 32),
claripy.BVV(0, 32)
)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### 関数のフック / シムプロシージャ

In some cases, you may want to modify the behavior of a specific function during the execution of a binary. This can be achieved using a technique called function hooking or simprocedure.

関数の実行中に特定の関数の動作を変更したい場合、関数フックまたはシムプロシージャと呼ばれる技術を使用することができます。

Function hooking involves replacing the original function with a custom implementation that you define. This allows you to intercept the function call and modify its behavior according to your needs. By hooking a function, you can control its input, output, or even completely change its functionality.

関数フックでは、元の関数を定義したカスタム実装で置き換えます。これにより、関数呼び出しを傍受し、必要に応じて動作を変更することができます。関数をフックすることで、入力や出力を制御したり、機能を完全に変更したりすることができます。

Simprocedure is a similar concept, but it is specific to the angr framework. It allows you to replace a function with a custom implementation using the `SimProcedure` class provided by angr. This class provides a set of methods that you can override to define the behavior of the simprocedure.

シムプロシージャは、angrフレームワーク固有の概念ですが、似たような概念です。angrが提供する`SimProcedure`クラスを使用して、関数をカスタム実装で置き換えることができます。このクラスは、シムプロシージャの動作を定義するためにオーバーライドできる一連のメソッドを提供します。

By hooking a function or using a simprocedure, you can gain control over the execution flow of a binary and modify its behavior to suit your needs. This can be particularly useful in scenarios where you want to bypass certain checks or modify the output of a function.

関数をフックするか、シムプロシージャを使用することで、バイナリの実行フローを制御し、動作を変更することができます。これは、特定のチェックをバイパスしたり、関数の出力を変更したりする必要がある場合に特に役立ちます。
```python
# Hook to the function called check_equals_WQNDNKKWAWOLXBAC

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

# Define a class and a tun method to hook completelly a function
class ReplacementCheckEquals(angr.SimProcedure):
# This C code:
#
# int add_if_positive(int a, int b) {
#   if (a >= 0 && b >= 0) return a + b;
#   else return 0;
# }
#
# could be simulated with python:
#
# class ReplacementAddIfPositive(angr.SimProcedure):
#   def run(self, a, b):
#     if a >= 0 and b >=0:
#       return a + b
#     else:
#       return 0
#
# run(...) receives the params of the hooked function
def run(self, to_check, length):
user_input_buffer_address = to_check
user_input_buffer_length = length

# Read the data from the memory address given to the function
user_input_string = self.state.memory.load(
user_input_buffer_address,
user_input_buffer_length
)

check_against_string = 'WQNDNKKWAWOLXBAC'.encode()

# Return 1 if equals to the string, 0 otherways
return claripy.If(
user_input_string == check_against_string,
claripy.BVV(1, 32),
claripy.BVV(0, 32)
)


# Hook the check_equals symbol. Angr automatically looks up the address
# associated with the symbol. Alternatively, you can use 'hook' instead
# of 'hook_symbol' and specify the address of the function. To find the
# correct symbol, disassemble the binary.
# (!)
check_equals_symbol = 'check_equals_WQNDNKKWAWOLXBAC' # :string
project.hook_symbol(check_equals_symbol, ReplacementCheckEquals())

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### 複数のパラメータを持つscanfのシミュレーション

To simulate `scanf` with several parameters, you can use the `angr` framework. `angr` is a powerful binary analysis tool that allows you to perform symbolic execution and solve complex constraints.

Here is an example of how you can simulate `scanf` with multiple parameters using `angr`:

```python
import angr

# Create an angr project
project = angr.Project("/path/to/binary")

# Define the symbolic input variables
input1 = angr.claripy.BVS("input1", 8 * 4)  # 4-byte input
input2 = angr.claripy.BVS("input2", 8 * 4)  # 4-byte input

# Create a state with symbolic input
state = project.factory.entry_state(stdin=angr.SimFile(fd=0, content=input1+input2))

# Simulate the execution until the scanf function
simulation = project.factory.simgr(state)
simulation.explore(find=0xaddress_of_scanf)

# Get the state after the scanf function
state_after_scanf = simulation.found[0]

# Get the concrete values of the symbolic input
concrete_input1 = state_after_scanf.solver.eval(input1)
concrete_input2 = state_after_scanf.solver.eval(input2)

# Print the concrete values
print("Input 1:", concrete_input1)
print("Input 2:", concrete_input2)
```

In this example, we first create an `angr` project by providing the path to the binary we want to analyze. Then, we define symbolic input variables using `angr.claripy.BVS`. We create a state with symbolic input by passing the symbolic input variables to `angr.SimFile` and setting it as the `stdin` of the state.

Next, we use the `project.factory.simgr` function to create a simulation manager and explore the program's execution until the `scanf` function is reached. We specify the address of the `scanf` function as the `find` parameter.

After the simulation, we retrieve the state after the `scanf` function using `simulation.found[0]`. We can then use the `state.solver.eval` function to get the concrete values of the symbolic input variables.

Finally, we print the concrete values of the inputs.
```python
# This time, the solution involves simply replacing scanf with our own version,
# since Angr does not support requesting multiple parameters with scanf.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

class ReplacementScanf(angr.SimProcedure):
# The code uses: 'scanf("%u %u", ...)'
def run(self, format_string, param0, param1):
scanf0 = claripy.BVS('scanf0', 32)
scanf1 = claripy.BVS('scanf1', 32)

# Get the addresses from the params and store the BVS in memory
scanf0_address = param0
self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
scanf1_address = param1
self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)

# Now, we want to 'set aside' references to our symbolic values in the
# globals plugin included by default with a state. You will need to
# store multiple bitvectors. You can either use a list, tuple, or multiple
# keys to reference the different bitvectors.
self.state.globals['solutions'] = (scanf0, scanf1)

scanf_symbol = '__isoc99_scanf'
project.hook_symbol(scanf_symbol, ReplacementScanf())

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

# Grab whatever you set aside in the globals dict.
stored_solutions = solution_state.globals['solutions']
solution = ' '.join(map(str, map(solution_state.solver.eval, stored_solutions)))

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### 静的バイナリ

静的バイナリは、実行可能なプログラムの形式であり、実行時に外部のライブラリや依存関係を必要とせず、単独で動作することができます。静的バイナリは、バイナリ解析やリバースエンジニアリングのコンテキストで非常に重要です。静的バイナリを解析することで、プログラムの内部構造や機能、セキュリティ上の脆弱性を理解することができます。

静的バイナリの解析には、さまざまなツールが利用されます。これらのツールは、バイナリのヘッダやセクション、シンボル、関数、命令などの情報を取得し、解析者に有用な情報を提供します。静的バイナリの解析には、バイナリエディタ、ディスアセンブラ、デバッガ、リバースエンジニアリングフレームワークなどが使用されます。

静的バイナリの解析は、セキュリティ評価や脆弱性診断、マルウェア解析、逆コンパイルなどの目的で使用されます。解析者は、静的バイナリの構造や動作を理解することで、セキュリティ上の問題を特定し、改善策を提案することができます。

静的バイナリの解析は、リバースエンジニアリングの基本的な手法の一つであり、セキュリティ専門家やハッカーにとって重要なスキルです。静的バイナリの解析には、知識と経験が必要ですが、適切なツールと手法を使用することで、効果的な解析が可能となります。
```python
# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc

import angr
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

#Find the addresses were the lib functions are loaded in the binary
#For example you could find: call   0x804ed80 <__isoc99_scanf>
project.hook(0x804ed40, angr.SIM_PROCEDURES['libc']['printf']())
project.hook(0x804ed80, angr.SIM_PROCEDURES['libc']['scanf']())
project.hook(0x804f350, angr.SIM_PROCEDURES['libc']['puts']())
project.hook(0x8048d10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output  # :boolean

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output  # :boolean

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
