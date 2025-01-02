{{#include ../../../banners/hacktricks-training.md}}

इस चीटशीट का एक भाग [angr दस्तावेज़ीकरण](https://docs.angr.io/_/downloads/en/stable/pdf/) पर आधारित है।

# स्थापना
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# बुनियादी क्रियाएँ
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
# लोडेड और मुख्य ऑब्जेक्ट जानकारी

## लोडेड डेटा
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
## मुख्य वस्तु
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
## प्रतीक और पुनर्स्थापनाएँ
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
## ब्लॉक्स
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# डायनामिक विश्लेषण

## सिमुलेशन प्रबंधक, राज्य
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
## फ़ंक्शंस को कॉल करना

- आप `entry_state` और `full_init_state` में `args` के माध्यम से तर्कों की एक सूची और `env` के माध्यम से पर्यावरण चर का एक शब्दकोश पास कर सकते हैं। इन संरचनाओं में मान स्ट्रिंग या बिटवेक्टर हो सकते हैं, और इन्हें अनुकरणित निष्पादन के लिए तर्कों और पर्यावरण के रूप में स्थिति में अनुक्रमित किया जाएगा। डिफ़ॉल्ट `args` एक खाली सूची है, इसलिए यदि प्रोग्राम जिसे आप विश्लेषण कर रहे हैं, कम से कम एक `argv[0]` खोजने की अपेक्षा करता है, तो आपको हमेशा वह प्रदान करना चाहिए!
- यदि आप `argc` को प्रतीकात्मक बनाना चाहते हैं, तो आप `entry_state` और `full_init_state` कंस्ट्रक्टर्स को `argc` के रूप में एक प्रतीकात्मक बिटवेक्टर पास कर सकते हैं। हालांकि, सावधान रहें: यदि आप ऐसा करते हैं, तो आपको परिणामी स्थिति में एक बाधा भी जोड़नी चाहिए कि आपके लिए argc का मान उन args की संख्या से बड़ा नहीं हो सकता जो आपने `args` में पास किए हैं।
- कॉल स्थिति का उपयोग करने के लिए, आपको इसे `.call_state(addr, arg1, arg2, ...)` के साथ कॉल करना चाहिए, जहाँ `addr` उस फ़ंक्शन का पता है जिसे आप कॉल करना चाहते हैं और `argN` उस फ़ंक्शन के लिए Nवां तर्क है, या तो एक पायथन पूर्णांक, स्ट्रिंग, या ऐरे, या एक बिटवेक्टर के रूप में। यदि आप मेमोरी आवंटित करना चाहते हैं और वास्तव में एक ऑब्जेक्ट के लिए एक पॉइंटर पास करना चाहते हैं, तो आपको इसे एक PointerWrapper में लपेटना चाहिए, यानी `angr.PointerWrapper("point to me!")`। इस API के परिणाम थोड़े अप्रत्याशित हो सकते हैं, लेकिन हम इस पर काम कर रहे हैं।

## बिटवेक्टर
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## प्रतीकात्मक बिटवेक्टर और प्रतिबंध
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
## हुकिंग
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
इसके अलावा, आप `proj.hook_symbol(name, hook)` का उपयोग कर सकते हैं, पहले तर्क के रूप में एक प्रतीक का नाम प्रदान करते हुए, उस पते को हुक करने के लिए जहां प्रतीक स्थित है

# उदाहरण

{{#include ../../../banners/hacktricks-training.md}}
