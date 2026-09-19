# Static Deobfuscation of Node.js/V8 Cached Bytecode

{{#include ../../banners/hacktricks-training.md}}

V8 cached data is a **version-dependent, lossy representation**, not JavaScript source and not a conventional native executable. A useful static workflow is therefore: remove any outer packing, disassemble the cache with the matching V8 build, lift it to an intermediate pseudocode model, and apply dependency-aware transformations without executing the sample. [View8](https://github.com/suleram/View8) and [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implement this approach for `javascript-obfuscator`-protected Node.js payloads.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Acquire and disassemble the cache

First inspect the preload/launcher rather than assuming every `.jsc` file has the same wrapper. For example, a launcher such as `node.exe -r preflight.js app.jsc` executes `preflight.js` before the main module; in the analyzed family the preload removed a Brotli layer. After unpacking, identify the exact Node.js/V8 generation from the bundled runtime. A cache produced by one V8 version can be rejected or incorrectly decoded by another, so build or obtain a `v8dasm` for that precise V8 tag and apply the required View8 and string-printing patches.<sup>[[1]](#references)[[2]](#references)</sup>

The toolkit's non-executing workflow is:<sup>[[2]](#references)</sup>

```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
  --inp app.jsc.disasm.txt --normalize \
  --out decompiled/app.dec.txt \
  --export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
  --out deobfuscated/app.deobf.txt \
  --export_format decompiled serialized
```

`--normalize` gives generated functions stable identifiers across runs. The text output is for inspection; the serialized object graph lets independent passes preserve function, declarer, scope and metadata relationships. It is **not reconstructed or runnable JavaScript**.<sup>[[1]](#references)[[2]](#references)</sup>

### Read View8 pseudocode as an IR

Typical names are `func_<name>_0x<address>`, arguments are `a0...aN`, virtual registers are `r0...rN`, and `ACCU` is V8's accumulator. `start` is the root declarer, while `Scope[...]`, globals and dictionaries model values captured or shared by nested functions. Do not parse every expression as JavaScript syntax: for example, View8's `!r6 === "0"` represents negation of the complete comparison (`r6 !== "0"`), which matters when rebuilding branches.<sup>[[1]](#references)[[3]](#references)</sup>

## Dependency-aware deobfuscation

Apply transformations in an order that exposes the inputs required by the next pass, and repeat propagation until the output stabilizes. A practical order is:<sup>[[1]](#references)[[2]](#references)</sup>

1. Walk the declarer hierarchy and propagate values from globals, registers, dictionaries and `Scope[...]` references.
2. Recover string-decoder arguments and replace encrypted calls with plaintext.
3. Fold adjacent string chunks; the resulting property names and dispatcher-order strings unlock later passes.
4. Unflatten control flow, inline call proxies and atomic-operation wrappers, and resolve dictionary-held function references.
5. Propagate again because each resolved string, key or proxy can expose another layer of indirection.
6. Collapse recognized one-shot initialization thunks and remove dead helpers only after their call sites are resolved.

### Recover shifted RC4 string arrays as a black box

A common `javascript-obfuscator` layout stores Base64-encoded RC4 chunks in one array. Decoder wrappers supply a numeric offset and a short key, sometimes in reversed argument order, then add or subtract constants captured in closure scopes. When the root decoder is too heavily obfuscated, recover its unknown array-index shift empirically instead of reconstructing the whole function.<sup>[[1]](#references)</sup>

For an array of `N` chunks and several calls to the same decoder:<sup>[[1]](#references)</sup>

```text
for each observed (numeric_argument, rc4_key):
    candidates = {}
    for shift in 0 .. N-1:
        index = apply_observed_sign(numeric_argument, shift)
        plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
        if plaintext passes encoding/printability checks:
            candidates.add(shift)
root_shift = intersection(candidate_sets)
```

Do not accept a shift from a single printable decryption: the wrong ciphertext can look printable by chance. Use at least three distinct observations and accept only a unique shift that yields plausible text for all of them. Then traverse the wrapper/declarer graph, accumulating each addition or subtraction and recording whether the numeric argument comes first. Cache this metadata per sample, replace decoder calls, concatenate adjacent plaintext chunks and export strings separately for triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Preserve semantics while unflattening

For dispatcher loops driven by strings such as `3|2|1|0|4`, decode the order string, map each state comparison to its block, account for View8's negated-condition notation, then emit blocks in dispatcher order. A nested `continue` may represent an early jump back to the dispatcher rather than an ordinary fall-through. When removing the loop, delete that `continue` and move the statements that originally followed its enclosing `if` into a generated `else` branch; merely deleting the dispatcher changes behavior.<sup>[[1]](#references)</sup>

### Inline proxies, operations and lazy thunks

Normalize forwarding helpers such as `return a0(a1, a2)` before replacing their call sites with direct calls. Treat wrappers for subtraction, division, comparison, membership tests or invocation similarly. Because the helper reference may itself be stored behind a decrypted dictionary key or closure value, run string and structure propagation before and after inlining.<sup>[[1]](#references)</sup>

Also recognize closures that invoke a stored function once, clear its reference, cache the result and return that cache on later calls. Collapsing such a thunk at an initialization site exposes the underlying dispatcher or capability function, but annotate that the original execution was **one-shot and cached** rather than modeling every call as a fresh invocation.<sup>[[1]](#references)</sup>

## Safety and validation notes

- Python `pickle` loading can execute code. Only load `.pkl` files generated locally by the trusted View8 run; never treat a sample-supplied pickle as data.<sup>[[2]](#references)</sup>
- Pattern-driven passes are not a general JavaScript decompiler. Preserve unresolved expressions and manually inspect ambiguous dispatcher variants rather than forcing a rewrite.<sup>[[1]](#references)[[2]](#references)</sup>
- LLM-assisted function names are navigation hints, not evidence. Process dependencies leaf-first if using them, but verify every label against the body, arguments, strings, data flow, APIs and side effects.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Breaking the Seal: Static Deobfuscation of JSCeal's Compiled V8 Bytecode](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)

{{#include ../../banners/hacktricks-training.md}}
