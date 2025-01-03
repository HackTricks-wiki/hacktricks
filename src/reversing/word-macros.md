# Word Macros

{{#include ../banners/hacktricks-training.md}}

### 垃圾代码

很常见会发现**从未使用的垃圾代码**，以使宏的逆向工程更加困难。\
例如，在下图中可以看到，某个永远不会为真的条件被用来执行一些垃圾和无用的代码。

![](<../images/image (369).png>)

### 宏表单

使用**GetObject**函数可以从宏的表单中获取数据。这可以用来增加分析的难度。以下是一个宏表单的照片，用于**在文本框内隐藏数据**（一个文本框可以隐藏其他文本框）：

![](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
