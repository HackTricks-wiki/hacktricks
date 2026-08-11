# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Macros may contain **unreachable or irrelevant code** intended to slow analysis. Identify constant conditions and trace reachable behavior before spending time reversing a branch. The example below uses an `If` condition that can never be true to conceal junk code.

![A Word macro containing an unreachable conditional branch with junk code](<../images/image (369).png>)

## Macro Forms

VBA UserForms can store data in controls such as text boxes. Because forms, frames, and pages can each expose a `Controls` collection, analysts should enumerate the entire control hierarchy rather than relying only on what the form displays. The example below stores concealed data in overlapping text boxes.<sup>[[1]](#references)</sup>

During dynamic analysis, VBA's `GetObject` function can retrieve an Automation object from a file or attach to an already-running Automation server. Macros may use that object access to reach data that is not obvious in the visible document; inspect both the returned object and the UserForm control tree.<sup>[[2]](#references)</sup>

![A macro UserForm with data concealed in overlapping text boxes](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collections, controls, and objects (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - `GetObject` function](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)

{{#include ../banners/hacktricks-training.md}}
