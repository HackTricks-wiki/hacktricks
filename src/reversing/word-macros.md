# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Macros may contain **unreachable or irrelevant code** intended to slow analysis. Identify constant conditions and trace reachable behavior before spending time reversing a branch. The example below uses an `If` condition that can never be true to conceal junk code.

![A Word macro containing an unreachable conditional branch with junk code](<../images/image (369).png>)

## Macro Forms

VBA UserForms can store data in controls such as text boxes. Because forms, frames, and pages can each expose a `Controls` collection, analysts should enumerate the entire control hierarchy rather than relying only on what the form displays. The example below stores concealed data in overlapping text boxes.<sup>[[1]](#references)</sup>

![A macro UserForm with data concealed in overlapping text boxes](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - 集合、控件和对象 (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
