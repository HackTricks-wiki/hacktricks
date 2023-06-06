# Instalação
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# Ações Básicas

## Load a binary

## Carregar um binário

To load a binary into an angr project, you can use the `angr.Project` constructor. This constructor takes a path to the binary as its first argument.

Para carregar um binário em um projeto angr, você pode usar o construtor `angr.Project`. Este construtor recebe o caminho para o binário como seu primeiro argumento.

```python
import angr

project = angr.Project("/path/to/binary")
```

## Find a function address

## Encontrar o endereço de uma função

To find the address of a function in the binary, you can use the `angr.Project.loader.find_symbol` method. This method takes the name of the function as its argument and returns the address of the function.

Para encontrar o endereço de uma função no binário, você pode usar o método `angr.Project.loader.find_symbol`. Este método recebe o nome da função como argumento e retorna o endereço da função.

```python
import angr

project = angr.Project("/path/to/binary")
function_address = project.loader.find_symbol("function_name").rebased_addr
```

## Create a state

## Criar um estado

To create a state at a specific address in the binary, you can use the `angr.Project.factory.blank_state` method. This method takes the address as its argument and returns a blank state at that address.

Para criar um estado em um endereço específico no binário, você pode usar o método `angr.Project.factory.blank_state`. Este método recebe o endereço como argumento e retorna um estado em branco nesse endereço.

```python
import angr

project = angr.Project("/path/to/binary")
state = project.factory.blank_state(addr=function_address)
```

## Explore the binary

## Explorar o binário

To explore the binary, you can use the `angr.Explorer` class. This class takes a starting state as its argument and provides methods for exploring the binary.

Para explorar o binário, você pode usar a classe `angr.Explorer`. Esta classe recebe um estado inicial como argumento e fornece métodos para explorar o binário.

```python
import angr

project = angr.Project("/path/to/binary")
function_address = project.loader.find_symbol("function_name").rebased_addr
state = project.factory.blank_state(addr=function_address)

explorer = angr.Explorer(project, start=state)
explorer.run()
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
# Informação do objeto carregado e principal

## Dados carregados
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
## Objetivo Principal
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
## Símbolos e Realocações
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
## Blocos
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# Análise Dinâmica

## Gerenciador de Simulação, Estados
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
## Chamando funções

* Você pode passar uma lista de argumentos através de `args` e um dicionário de variáveis de ambiente através de `env` para `entry_state` e `full_init_state`. Os valores nessas estruturas podem ser strings ou bitvectors, e serão serializados no estado como os argumentos e ambiente para a execução simulada. O `args` padrão é uma lista vazia, então se o programa que você está analisando espera encontrar pelo menos um `argv[0]`, você sempre deve fornecê-lo!
* Se você quiser que `argc` seja simbólico, você pode passar um bitvector simbólico como `argc` para os construtores `entry_state` e `full_init_state`. Mas tenha cuidado: se você fizer isso, você também deve adicionar uma restrição ao estado resultante de que seu valor para argc não pode ser maior do que o número de argumentos que você passou em `args`.
* Para usar o estado de chamada, você deve chamá-lo com `.call_state(addr, arg1, arg2, ...)`, onde `addr` é o endereço da função que você deseja chamar e `argN` é o N-ésimo argumento para essa função, seja como um inteiro, string ou array em Python, ou um bitvector. Se você quiser ter memória alocada e realmente passar um ponteiro para um objeto, você deve envolvê-lo em um PointerWrapper, ou seja, `angr.PointerWrapper("aponte para mim!")`. Os resultados desta API podem ser um pouco imprevisíveis, mas estamos trabalhando nisso.

## BitVectors
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## BitVectors Simbólicos e Restrições

Os BitVectors Simbólicos são uma representação de bits que permitem a criação de expressões matemáticas simbólicas. Eles são usados para representar valores desconhecidos ou variáveis em um programa. As restrições são expressões matemáticas que limitam os valores possíveis de um BitVector Simbólico. As restrições são usadas para modelar o comportamento do programa e para encontrar soluções para problemas específicos.
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
## Hooking

O hooking é uma técnica usada para interceptar e modificar o comportamento normal de um programa. Isso é feito injetando código em um processo em execução e redirecionando a execução para esse código. O hooking pode ser usado para uma variedade de propósitos, incluindo depuração, monitoramento de sistema e interceptação de chamadas de sistema. Existem várias técnicas de hooking, incluindo hooking de API, hooking de função e hooking de sistema. O angr suporta hooking de função e hooking de sistema.
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
Além disso, você pode usar `proj.hook_symbol(name, hook)`, fornecendo o nome de um símbolo como primeiro argumento, para conectar o endereço onde o símbolo está localizado.

# Exemplos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
