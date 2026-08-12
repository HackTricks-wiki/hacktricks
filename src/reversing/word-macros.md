# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Macros 可能包含旨在拖慢分析的**不可达或无关代码**。在花时间逆向某个分支之前，应先识别恒定条件并跟踪可达行为。下面的示例使用一个永远不可能为真的 `If` 条件来隐藏 junk code。

![包含不可达条件分支和 junk code 的 Word macro](<../images/image (369).png>)

## Macro Forms

VBA UserForms 可以在文本框等控件中存储数据。由于 forms、frames 和 pages 都可以提供 `Controls` collection，analysts 应枚举整个控件层级，而不应只依赖 form 所显示的内容。下面的示例将隐藏数据存储在相互重叠的文本框中。<sup>[[1]](#references)</sup>

在 dynamic analysis 期间，VBA 的 `GetObject` function 可以从文件中获取 Automation object，或连接到已经运行的 Automation server。Macros 可能利用这种 object access 获取可见文档中不明显的数据；应同时检查返回的 object 和 UserForm control tree。<sup>[[2]](#references)</sup>

![在相互重叠的文本框中隐藏数据的 macro UserForm](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collections, controls, and objects (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - `GetObject` function](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
