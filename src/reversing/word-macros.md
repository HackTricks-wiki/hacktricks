# Word 宏

{{#include ../banners/hacktricks-training.md}}

### Junk Code

在宏中找到**从未使用的 junk code**非常常见，这会增加宏的 reversing 难度。\
例如，在下图中可以看到，使用了一个永远不会为真的 If 条件来执行一些 junk 和无用代码。

![Word Macros - Junk Code：例如，在下图中可以看到，使用了一个永远不会为真的 If 条件来执行一些 junk 和无用代码](<../images/image (369).png>)

### Macro Forms

使用 **GetObject** 函数可以获取宏表单中的数据。这可以用于增加分析难度。下面是一张宏表单的图片，该表单用于**将数据隐藏在文本框中**（一个文本框可以隐藏其他文本框）：

![Junk Code - Macro Forms：使用 GetObject 函数可以获取宏表单中的数据。这可以用于增加分析难度。下面是一张宏表单的图片，该表单用于……](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
