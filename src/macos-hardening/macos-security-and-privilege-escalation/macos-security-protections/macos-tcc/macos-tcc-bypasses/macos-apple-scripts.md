# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

这是一种用于任务自动化的脚本语言，**与远程进程交互**。它使得**请求其他进程执行某些操作**变得相当简单。**恶意软件**可能会滥用这些功能，以利用其他进程导出的功能。\
例如，恶意软件可以**在浏览器打开的页面中注入任意的JS代码**。或者**自动点击**用户请求的某些允许权限；
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
这里有一些示例: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
有关使用苹果脚本的恶意软件的更多信息 [**请点击这里**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)。

苹果脚本可以很容易地 "**编译**"。这些版本可以通过 `osadecompile` 很容易地 "**反编译**"。

然而，这些脚本也可以 **导出为“只读”**（通过“导出...”选项）：

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
在这种情况下，即使使用 `osadecompile` 也无法反编译内容。

然而，仍然有一些工具可以用来理解这种可执行文件，[**阅读此研究以获取更多信息**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)。工具 [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) 和 [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) 将非常有助于理解脚本的工作原理。

{{#include ../../../../../banners/hacktricks-training.md}}
