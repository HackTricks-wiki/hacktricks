# Crypto CTF 杂项

{{#include ../../banners/hacktricks-training.md}}

本节汇集了出现在密码学挑战中、但不易归入其他类别的技术。

## эзотерические языки

### 技术

当挑战要求运行 эзотерический язык 程序并解码其输出时，请使用此工作流程。

如果挑战给出的代码看起来不像常见语言：

- 搜索独特的标记或指令序列，以识别语言。
- 使用在线解释器或 Docker 镜像。
- 如果输出很奇怪，请检查执行后是否还有分层编码或压缩。

Esolang wiki 是一份实用的语言索引。<sup>[[1]](#references)</sup> 对于常见的编码和压缩层，请使用 [Crypto CTF 工作流程](../ctf-workflow/)。如果线索是不可见文本而不是可执行语法，请查看[文本隐写术](../../stego/text/)。

### 提取预加载的解释器状态

如果挑战接受 эзотерический язык 源码，并在**自定义解释器**中运行，请先检查其初始内存、栈和输出指令，再将源码当作解码谜题处理。如果解释器预先将秘密压入 Befunge 栈中，一段简短的程序就能弹出并打印已有字节，无需进行计算。这需要你能控制执行的源码，并使用输出操作码；在普通的空解释器中，这种方法无效。在一个 Befunge 挑战中，下面的输入反复输出了预先以反序压入栈中的 flag 字符。<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` 使执行向右进行，`,` 弹出并打印一个字符，而 `<` 则将指令指针送回 `,`。检查自定义解释器的下溢和指令数限制行为：引用的实现会在栈耗尽或执行 1,024 条指令后停止。如果 secret 不在栈上，检查其他已初始化的状态以及可用的输出/读取指令，而不是假定它遵循标准 Befunge 语义。<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang，深奥编程语言百科](https://esolangs.org/wiki/Main_Page)
- [2] [WolvCTF 2024 Befuddled1 原始 writeup](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [WolvCTF 2024 Befuddled1 解释器源码](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Befunge 语言参考](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
