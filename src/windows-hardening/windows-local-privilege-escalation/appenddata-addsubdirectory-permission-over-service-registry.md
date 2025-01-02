{{#include ../../banners/hacktricks-training.md}}

**原始帖子是** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## 摘要

发现当前用户可以写入两个注册表项：

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

建议使用 **regedit GUI** 检查 **RpcEptMapper** 服务的权限，特别是 **高级安全设置** 窗口的 **有效权限** 选项卡。这种方法可以评估特定用户或组的授予权限，而无需逐个检查每个访问控制条目 (ACE)。

一张截图显示了分配给低权限用户的权限，其中 **创建子项** 权限尤为显著。该权限也称为 **AppendData/AddSubdirectory**，与脚本的发现相符。

注意到无法直接修改某些值，但可以创建新的子项。一个突出的例子是尝试更改 **ImagePath** 值，结果显示访问被拒绝的消息。

尽管存在这些限制，但通过利用 **RpcEptMapper** 服务的注册表结构中的 **Performance** 子项，识别出潜在的权限提升机会，该子项默认情况下不存在。这可能使 DLL 注册和性能监控成为可能。

查阅了关于 **Performance** 子项及其在性能监控中的使用的文档，开发了一个概念验证 DLL。该 DLL 演示了 **OpenPerfData**、**CollectPerfData** 和 **ClosePerfData** 函数的实现，通过 **rundll32** 测试，确认其操作成功。

目标是强制 **RPC Endpoint Mapper service** 加载精心制作的 Performance DLL。观察发现，通过 PowerShell 执行与性能数据相关的 WMI 类查询会导致创建日志文件，从而在 **LOCAL SYSTEM** 上下文中执行任意代码，从而授予提升的权限。

强调了该漏洞的持久性和潜在影响，突显其在后期利用策略、横向移动和规避 antivirus/EDR 系统中的相关性。

尽管该漏洞最初是通过脚本无意中披露的，但强调其利用仅限于过时的 Windows 版本（例如 **Windows 7 / Server 2008 R2**），并且需要本地访问。

{{#include ../../banners/hacktricks-training.md}}
