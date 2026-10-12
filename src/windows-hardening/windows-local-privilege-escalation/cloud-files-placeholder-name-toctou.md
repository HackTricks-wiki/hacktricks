# Windows MDL 映射用户缓冲区 Double-Fetch

{{#include ../../banners/hacktricks-training.md}}

当 Windows 内核驱动在调用者提供的页面中验证数据，随后又将指向这些页面的指针传递给安全敏感 API 时，就会产生 double-fetch。锁定并映射页面并不会使其内容不可变。CVE-2025-55680 中的 `cldflt.sys` 展示了这种模式：驱动验证 Cloud Files placeholder 的相对名称后，仍引用调用者可变的缓冲区来创建对象。<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` 会在已注册的 Cloud Files sync root 下创建文件或目录。在存在漏洞的路径中，验证完成后更改名称，就可能将特权创建操作重定向到该根目录之外。<sup>[[1]](#references)[[2]](#references)</sup>

## 为什么锁定页面并未锁定数据

存在漏洞的 `HsmpOpCreatePlaceholders()` 路径为调用者的 payload 分配 MDL，调用 `ProbeForRead()` 和 `MmProbeAndLockPages()`，并将这些页面映射到内核虚拟地址空间。MDL 描述并锁定物理页面，确保它们始终驻留在内存中，但**不会**对其字节内容进行快照。因此，用户模式仍可修改同一物理内存，而驱动则通过系统映射读取这些内存。<sup>[[1]](#references)[[3]](#references)</sup>

相关请求和使用路径如下：<sup>[[1]](#references)</sup>

1. `cldapi.dll` 发送 Cloud Files 控制代码 `0x903BC`，并携带标记 `IO_REPARSE_TAG_CLOUD`（`0x9000001A`）和创建 placeholder 操作 `0xC0000001`。
2. 每条 payload 记录都包含相对名称和文件标识的 16 位偏移量/长度对。大多数固定字段会复制到栈记录中，但变长名称仍留在映射的用户页面中。
3. 驱动扫描 UTF-16 名称，并拒绝其中包含反斜杠或冒号的名称。
4. 随后，驱动构建一个 `UNICODE_STRING`，其 `Buffer` 仍指向映射的 payload，并将其赋给 `OBJECT_ATTRIBUTES.ObjectName`。
5. `FltCreateFileEx2()` 再次读取该指针。因此，并发写入者可能让验证读取到一个字符串，而文件创建读取到另一个字符串。

即使两次读取都使用内核虚拟地址，这仍然是 **double-fetch**：安全边界取决于底层存储，而不是驱动通过哪个虚拟映射进行解引用。<sup>[[1]](#references)</sup>

## Cloud Files 竞争布局

披露的利用策略使用重复请求、修改线程和 junction，将 double-fetch 转化为路径重定向：<sup>[[1]](#references)</sup>

1. 使用 `CfRegisterSyncRoot()` 注册一个由攻击者控制的目录，并在其下创建一个指向受保护目标的 junction `JUSTASTRING`。
2. 准备一条共享的 placeholder 记录，其有效的单组件名称为 `JUSTASTRINGDnewfile.dll`。
3. 让修改线程将 UTF-16 的 `D` 代码单元在 `D` 和 `\` 之间切换。后一种表示形式为 `JUSTASTRING\newfile.dll`。
4. 同时，让工作线程反复提交引用同一 payload 的创建 placeholder 请求，并让监控线程检查受保护的目标。
5. 如果某次操作成功，驱动会先验证不含分隔符的表示形式，随后在创建操作读取到含 `\` 的表示形式时跟随 junction。

该原语只能实现受保护文件或目录的创建。若要进一步实现代码执行，仍需控制所创建文件的内容，并找到特权使用者，例如合适的 DLL 侧加载目标。原始分析使用了这类最终利用链，但没有公开加载器、payload 或完整的独立利用程序。<sup>[[1]](#references)</sup>

有关刻意扩大 Windows 路径查找竞争窗口的补充技术，请参阅 [通过对象管理器慢速路径利用内核竞争条件](kernel-race-condition-object-manager-slowdown.md)。

## References

- [1] [Exodus Intelligence - Microsoft Windows Cloud Files Minifilter TOCTOU 权限提升](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - CfCreatePlaceholders 函数](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - MmProbeAndLockPages 函数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
