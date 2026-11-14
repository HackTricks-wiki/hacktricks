# Node.js/V8 缓存字节码的静态去混淆

{{#include ../../banners/hacktricks-training.md}}

V8 缓存数据是**依赖版本且有损的表示形式**，既不是 JavaScript 源代码，也不是常规的原生可执行文件。因此，实用的静态工作流程是：移除外层打包，用匹配的 V8 构建版本反汇编缓存，将其提升为中间伪代码模型，然后在不执行样本的情况下应用依赖感知转换。[View8](https://github.com/suleram/View8) 和 [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) 针对受 `javascript-obfuscator` 保护的 Node.js payload 实现了这种方法。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## 获取并反汇编缓存

首先检查 preload/launcher，不要想当然地认为所有 `.jsc` 文件都使用相同的包装器。例如，像 `node.exe -r preflight.js app.jsc` 这样的 launcher 会在主模块之前执行 `preflight.js`；在分析的这类样本中，preload 移除了一层 Brotli 压缩。解包后，根据捆绑的 runtime 确定确切的 Node.js/V8 版本。某个 V8 版本生成的缓存可能会被另一个版本拒绝或错误解码，因此应为精确匹配的 V8 tag 构建或获取 `v8dasm`，并应用所需的 View8 和字符串打印补丁。<sup>[[1]](#references)[[2]](#references)</sup>

该工具包的非执行工作流程如下：<sup>[[2]](#references)</sup>

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

`--normalize` 会让生成的函数在不同运行中具有稳定的标识符。文本输出用于检查；序列化对象图则让独立的处理阶段能够保留函数、声明者、作用域和元数据之间的关系。它**不是重建出的、可运行的 JavaScript**。<sup>[[1]](#references)[[2]](#references)</sup>

### 无需构建 V8 即可对缓存进行初步分析

对于原始缓存或经 Brotli 封装的缓存，`jscd` 可以识别头部并枚举常量和函数，无需在 Node.js 中加载样本。首先使用它检查版本表是否支持该文件，并在运行更专业的 View8 去混淆处理阶段之前，确定优先检查哪些函数。<sup>[[4]](#references)</sup>

版本哈希只是识别线索，不能证明独立反汇编器使用了与生成方相同的标志或只读快照。<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` 会输出与 View8 兼容的反汇编列表，因此在缓存受支持时，上面的 View8 命令可以使用该输出，而不是使用 `v8dasm`。结合函数树检查字符串，以定位解码器调用和可能的入口点；不要把 `jscd` 生成的近似 JavaScript 输出当作原始源代码。如果工具拒绝该版本，或留下只读堆占位符，请改用匹配的 V8 构建，或提供来自同一构建的名称映射，而不要猜测属性名。<sup>[[4]](#references)</sup>

对于 Electron 应用程序中的缓存，先[提取 ASAR 并检查其 main 和 preload 入口点](../../desktop-application-security/electron-desktop-apps/)。即使 Electron 和 Node 的 V8 版本字符串相同，其缓存中的 snapshot 和指针压缩布局也可能不同。<sup>[[4]](#references)</sup>

### 将 View8 伪代码视为 IR 阅读

常见名称包括 `func_<name>_0x<address>`；参数为 `a0...aN`，虚拟寄存器为 `r0...rN`，`ACCU` 是 V8 的累加器。`start` 是根声明器，而 `Scope[...]`、全局变量和字典则表示由嵌套函数捕获或共享的值。不要把每个表达式都解析成 JavaScript 语法：例如，View8 的 `!r6 === "0"` 表示对整个比较结果取反（`r6 !== "0"`），这在重建分支时很重要。<sup>[[1]](#references)[[3]](#references)</sup>

## 依赖感知的反混淆

按能够暴露下一轮所需输入的顺序应用转换，并反复传播，直到输出稳定。实用顺序如下：<sup>[[1]](#references)[[2]](#references)</sup>

1. 遍历声明器层级，并传播来自全局变量、寄存器、字典和 `Scope[...]` 引用的值。
2. 还原字符串解码器的参数，并将加密调用替换为明文。
3. 合并相邻的字符串片段；由此得到的属性名和 dispatcher 顺序字符串可解锁后续步骤。
4. 展平控制流，内联调用代理和原子操作封装器，并解析字典中保存的函数引用。
5. 再次传播，因为每个解析出的字符串、键或代理都可能暴露另一层间接引用。
6. 只有在调用点解析完毕后，才折叠已识别的一次性初始化 thunk 并移除无用辅助函数。

### 将移位的 RC4 字符串数组作为黑盒还原

常见的 `javascript-obfuscator` 布局会将 Base64 编码的 RC4 字符串片段存放在一个数组中。解码器封装器会提供一个数字偏移量和一个短密钥，有时参数顺序会反转，然后再加上或减去闭包作用域中捕获的常量。如果根解码器经过了重度混淆，与其重建整个函数，不如通过实测还原未知的数组索引偏移量。<sup>[[1]](#references)</sup>

对于包含 `N` 个片段的数组，以及对同一解码器的多次调用：<sup>[[1]](#references)</sup>

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

不要仅凭一次解密结果可打印就接受某个偏移量：错误的密文也可能碰巧得到可打印文本。至少使用三条不同的观察结果，并且只有在唯一的偏移量能让所有结果都成为合理文本时才接受。然后遍历 wrapper/declarer 图，累积每次加法或减法，并记录数值参数是否位于首位。为每个样本缓存这些元数据，替换解码器调用，将相邻的明文块拼接起来，并单独导出字符串以供初步分析。<sup>[[1]](#references)[[2]](#references)</sup>

### 展开控制流平坦化时保留语义

对于由 `3|2|1|0|4` 这类字符串驱动的 dispatcher 循环，先解码顺序字符串，将每个状态比较映射到对应代码块，考虑 View8 中取反条件的表示方式，然后按 dispatcher 的顺序输出代码块。嵌套的 `continue` 可能表示提前跳回 dispatcher，而不是普通的顺序执行。移除循环时，删除该 `continue`，并将原本位于其外层 `if` 后面的语句移入生成的 `else` 分支；仅删除 dispatcher 会改变行为。<sup>[[1]](#references)</sup>

### 内联代理、运算操作和惰性 thunk

在将调用点替换为直接调用之前，先规范化 `return a0(a1, a2)` 这类转发 helper。对减法、除法、比较、成员测试或调用操作的 wrapper 也采用相同处理。由于 helper 引用本身可能存储在解密后的字典键或闭包值中，因此应在内联前后执行字符串和结构传播。<sup>[[1]](#references)</sup>

还应识别这类闭包：它们调用一次已存储的函数，清除该函数引用，缓存结果，并在后续调用时返回缓存值。在初始化位置折叠这类 thunk，可以暴露底层 dispatcher 或 capability 函数，但要注明原始执行是**仅执行一次并缓存结果**，而不是将每次调用都视为一次新的调用。<sup>[[1]](#references)</sup>

## 安全与验证说明

- Python 的 `pickle` 加载可能执行代码。只加载由可信的 View8 运行在本地生成的 `.pkl` 文件；绝不要将样本提供的 pickle 当作数据处理。<sup>[[2]](#references)</sup>
- 缺少函数体并不能证明源代码中没有该函数：V8 可能会将惰性函数序列化为元数据，直到首次调用时才编译。静态初步分析期间，应将此类函数标记为未解析。<sup>[[6]](#references)</sup>
- 基于模式的处理流程并不是通用的 JavaScript 反编译器。保留未解析的表达式，并手动检查有歧义的 dispatcher 变体，不要强行改写。<sup>[[1]](#references)[[2]](#references)</sup>
- LLM 辅助生成的函数名只能作为导航提示，不能作为证据。如果使用这类函数名，应按依赖关系从叶节点开始处理，但必须根据函数体、参数、字符串、数据流、API 和副作用逐一验证每个标签。<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [揭开封印：对 JSCeal 编译后的 V8 字节码进行静态反混淆](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [V8 SerializedCodeData 头部](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Node.js vm.Script 代码缓存](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
