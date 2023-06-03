# Instalación
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# Acciones Básicas

## Load a binary

## Cargar un binario

To load a binary into an angr project, you can use the `angr.Project` constructor. This constructor takes a path to the binary as its first argument.

Para cargar un binario en un proyecto de angr, puedes usar el constructor `angr.Project`. Este constructor toma como primer argumento la ruta al binario.

```python
import angr

project = angr.Project("/path/to/binary")
```

## Find a function address

## Encontrar la dirección de una función

To find the address of a function in the binary, you can use the `angr.Project.loader.find_symbol` method. This method takes the name of the function as its argument and returns the address of the function.

Para encontrar la dirección de una función en el binario, puedes usar el método `angr.Project.loader.find_symbol`. Este método toma como argumento el nombre de la función y devuelve la dirección de la función.

```python
import angr

project = angr.Project("/path/to/binary")
function_address = project.loader.find_symbol("function_name").rebased_addr
```

## Create a state

## Crear un estado

To create a state, you can use the `angr.Project.factory.entry_state` method. This method creates a state at the entry point of the binary.

Para crear un estado, puedes usar el método `angr.Project.factory.entry_state`. Este método crea un estado en el punto de entrada del binario.

```python
import angr

project = angr.Project("/path/to/binary")
state = project.factory.entry_state()
```

## Explore the binary

## Explorar el binario

To explore the binary, you can use the `angr.Explorer` class. This class takes a starting state as its argument and allows you to explore the binary using various methods.

Para explorar el binario, puedes usar la clase `angr.Explorer`. Esta clase toma como argumento un estado inicial y te permite explorar el binario usando varios métodos.

```python
import angr

project = angr.Project("/path/to/binary")
state = project.factory.entry_state()
explorer = angr.Explorer(project, start=state)
```

## Solve constraints

## Resolver restricciones

To solve constraints, you can use the `state.solver` object. This object allows you to add constraints and solve them.

Para resolver restricciones, puedes usar el objeto `state.solver`. Este objeto te permite agregar restricciones y resolverlas.

```python
import angr

project = angr.Project("/path/to/binary")
state = project.factory.entry_state()
solver = state.solver
```

## Execute the binary

## Ejecutar el binario

To execute the binary, you can use the `state` object's `step` method. This method takes a number of steps to execute as its argument.

Para ejecutar el binario, puedes usar el método `step` del objeto `state`. Este método toma como argumento el número de pasos a ejecutar.

```python
import angr

project = angr.Project("/path/to/binary")
state = project.factory.entry_state()
state.step()
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
# Información de objetos cargados y principales

## Datos cargados
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
## Objetivo principal
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
## Símbolos y reubicaciones
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
## Bloques
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# Análisis Dinámico

## Simulación Manager, Estados
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
## Llamando funciones

* Puedes pasar una lista de argumentos a través de `args` y un diccionario de variables de entorno a través de `env` en `entry_state` y `full_init_state`. Los valores en estas estructuras pueden ser cadenas de texto o bitvectors, y se serializarán en el estado como los argumentos y el entorno para la ejecución simulada. El valor predeterminado de `args` es una lista vacía, por lo que si el programa que estás analizando espera encontrar al menos un `argv[0]`, ¡siempre debes proporcionarlo!
* Si deseas que `argc` sea simbólico, puedes pasar un bitvector simbólico como `argc` a los constructores `entry_state` y `full_init_state`. Sin embargo, ten cuidado: si haces esto, también debes agregar una restricción al estado resultante de que tu valor para `argc` no puede ser mayor que el número de argumentos que pasaste a `args`.
* Para usar el estado de llamada, debes llamarlo con `.call_state(addr, arg1, arg2, ...)`, donde `addr` es la dirección de la función que deseas llamar y `argN` es el N-ésimo argumento de esa función, ya sea como un entero, cadena de texto, array o bitvector de Python. Si deseas que se asigne memoria y realmente pasar un puntero a un objeto, debes envolverlo en un PointerWrapper, es decir, `angr.PointerWrapper("¡apúntame!")`. Los resultados de esta API pueden ser un poco impredecibles, pero estamos trabajando en ello.

## BitVectors
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## BitVectors Simbólicos y Restricciones

Los BitVectors Simbólicos son una herramienta poderosa en el análisis de binarios. Permiten representar valores desconocidos o no determinados en el análisis de un programa. Las restricciones son condiciones que se imponen a los valores de los BitVectors Simbólicos. Estas restricciones pueden ser utilizadas para encontrar soluciones a problemas específicos, como por ejemplo, encontrar entradas que satisfagan una determinada condición en un programa.
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

El hooking es una técnica utilizada en ingeniería inversa para interceptar y modificar el comportamiento de una aplicación. En el contexto de angr, el hooking se utiliza para modificar el comportamiento de una función específica en un binario. Esto se logra mediante la inserción de código personalizado en la función objetivo. El hooking puede ser útil para evitar la ejecución de ciertas funciones, para modificar los argumentos de entrada o para cambiar el valor de retorno de una función.
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
Además, puedes usar `proj.hook_symbol(name, hook)` proporcionando el nombre de un símbolo como primer argumento, para enganchar la dirección donde vive el símbolo.

# Ejemplos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
