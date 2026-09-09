# Node.js/V8 Cached Bytecode 的静态反混淆

{{#include ../../banners/hacktricks-training.md}}

V8 cached data 是一种**依赖版本的有损表示**，既不是 JavaScript 源代码，也不是传统的原生可执行文件。因此，一种实用的静态 workflow 是：移除外层打包，使用匹配的 V8 build 反汇编 cache，将其提升为中间伪代码模型，并在不执行 sample 的情况下应用依赖感知的转换。[View8](https://github.com/suleram/View8) 和 [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) 实现了这一方法，适用于受 `javascript-obfuscator` 保护的 Node.js payload。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## 获取并反汇编 cache

首先检查 preload/启动器，而不是假设每个 `.jsc` 文件都使用相同的 wrapper。例如，`node.exe -r preflight.js app.jsc` 这样的启动器会在主模块之前执行 `preflight.js`；在所分析的样本系列中，preload 移除了一个 Brotli layer。解包后，从 bundled runtime 中确定确切的 Node.js/V8 generation。某个 V8 版本生成的 cache 可能会被另一个版本拒绝或错误解码，因此应针对该确切的 V8 tag 构建或获取 `v8dasm`，并应用所需的 View8 和 string-printing patches。<sup>[[1]](#references)[[2]](#references)</sup>

该 toolkit 的 non-executing workflow 如下：<sup>[[2]](#references)</sup>
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
`--normalize` 使生成的函数在不同运行之间拥有稳定的标识符。文本输出用于检查；序列化的对象图则让相互独立的 passes 能够保留函数、声明者、作用域和 metadata 之间的关系。它**不是经过重构或可运行的 JavaScript**。<sup>[[1]](#references)[[2]](#references)</sup>

### 将 View8 伪代码视为 IR

典型名称为 `func_<name>_0x<address>`，参数为 `a0...aN`，虚拟寄存器为 `r0...rN`，而 `ACCU` 是 V8 的累加器。`start` 是根声明者，而 `Scope[...]`、globals 和 dictionaries 则用于表示被嵌套函数捕获或共享的值。不要将每个表达式都解析为 JavaScript 语法：例如，View8 的 `!r6 === "0"` 表示对完整比较结果取反（`r6 !== "0"`），这在重建分支时很重要。<sup>[[1]](#references)[[3]](#references)</sup>

## 依赖感知的去混淆

按能够暴露下一 pass 所需输入的顺序应用 transformations，并持续重复 propagation，直到输出稳定。一个实用顺序如下：<sup>[[1]](#references)[[2]](#references)</sup>

1. 遍历声明者层级，并从 globals、registers、dictionaries 和 `Scope[...]` references 中 propagation values。
2. 恢复 string-decoder arguments，并将加密调用替换为明文。
3. 合并相邻的 string chunks；生成的 property names 和 dispatcher-order strings 将解锁后续 passes。
4. 解除控制流扁平化、inline call proxies 和 atomic-operation wrappers，并解析由 dictionaries 保存的 function references。
5. 再次执行 propagation，因为每个已解析的 string、key 或 proxy 都可能暴露另一层间接引用。
6. 折叠已识别的一次性 initialization thunks，并且只有在其 call sites 解析完成后才移除 dead helpers。

### 将移位的 RC4 string arrays 作为黑盒恢复

常见的 `javascript-obfuscator` 布局会将 Base64 编码的 RC4 chunks 存储在一个 array 中。Decoder wrappers 提供 numeric offset 和 short key，有时会反转参数顺序，然后加上或减去在 closure scopes 中捕获的 constants。当 root decoder 被严重 obfuscate 时，应通过经验方式恢复其未知的 array-index shift，而不是重构整个 function。<sup>[[1]](#references)</sup>

对于包含 `N` 个 chunks 且对同一 decoder 存在多次调用的 array：<sup>[[1]](#references)</sup>
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
不要仅凭单个可打印解密结果接受某个 shift：错误的 ciphertext 可能会因偶然而呈现可打印内容。至少使用三个不同的观测结果，并且只有当某个唯一的 shift 对所有观测结果都产生合理文本时才接受它。随后遍历 wrapper/declarer graph，累积每次 addition 或 subtraction，并记录 numeric argument 是否位于前面。为每个 sample 缓存这些 metadata，替换 decoder calls，拼接相邻的 plaintext chunks，并单独导出 strings 以便 triage。<sup>[[1]](#references)[[2]](#references)</sup>

### 在 unflattening 时保留语义

对于由 `3|2|1|0|4` 等 strings 驱动的 dispatcher loops，先 decode order string，将每个 state comparison 映射到对应的 block，处理 View8 的 negated-condition notation，然后按 dispatcher order 输出 blocks。嵌套的 `continue` 可能表示跳回 dispatcher 的 early jump，而不是普通的 fall-through。移除 loop 时，删除该 `continue`，并将原本位于其 enclosing `if` 后面的 statements 移入生成的 `else` branch；仅删除 dispatcher 会改变行为。<sup>[[1]](#references)</sup>

### Inline proxies、operations 和 lazy thunks

在将 call sites 替换为 direct calls 之前，先规范化 `return a0(a1, a2)` 等 forwarding helpers。对 subtraction、division、comparison、membership tests 或 invocation 的 wrappers 也采用相同处理。由于 helper reference 本身可能存储在 decrypted dictionary key 或 closure value 后面，因此应在 inlining 前后都执行 string 和 structure propagation。<sup>[[1]](#references)</sup>

还要识别这类 closures：它们只调用一次 stored function，清除其 reference，缓存结果，并在后续 calls 中返回该 cache。在 initialization site 将此类 thunk 折叠后，可以暴露底层的 dispatcher 或 capability function；但应注明原始执行是 **one-shot and cached**，而不是将每次 call 都建模为一次新的 invocation。<sup>[[1]](#references)</sup>

## Safety and validation notes

- Python `pickle` loading can execute code. 只加载由受信任的 View8 run 在本地生成的 `.pkl` files；绝不要将 sample-supplied pickle 当作 data。<sup>[[2]](#references)</sup>
- Pattern-driven passes 不是通用的 JavaScript decompiler。保留 unresolved expressions，并手动检查有歧义的 dispatcher variants，而不是强行执行 rewrite。<sup>[[1]](#references)[[2]](#references)</sup>
- LLM-assisted function names 只是 navigation hints，并非 evidence。如果使用它们，请按 leaf-first 顺序处理 dependencies，但必须根据 body、arguments、strings、data flow、APIs 和 side effects 验证每个 label。<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Breaking the Seal: Static Deobfuscation of JSCeal's Compiled V8 Bytecode](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
