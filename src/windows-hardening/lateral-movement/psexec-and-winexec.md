# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## 它们是如何工作的

该过程在以下步骤中概述，说明如何操纵服务二进制文件以通过 SMB 在目标机器上实现远程执行：

1. **通过 SMB 复制服务二进制文件到 ADMIN$ 共享**。
2. **在远程机器上创建服务**，指向该二进制文件。
3. 服务被 **远程启动**。
4. 退出时，服务被 **停止，二进制文件被删除**。

### **手动执行 PsExec 的过程**

假设有一个可执行有效载荷（使用 msfvenom 创建并使用 Veil 混淆以规避防病毒检测），名为 'met8888.exe'，代表一个 meterpreter reverse_http 有效载荷，采取以下步骤：

- **复制二进制文件**：可执行文件从命令提示符复制到 ADMIN$ 共享，尽管它可以放置在文件系统的任何位置以保持隐蔽。
- **创建服务**：利用 Windows `sc` 命令，该命令允许远程查询、创建和删除 Windows 服务，创建一个名为 "meterpreter" 的服务，指向上传的二进制文件。
- **启动服务**：最后一步是启动服务，这可能会导致 "超时" 错误，因为该二进制文件不是一个真正的服务二进制文件，未能返回预期的响应代码。此错误无关紧要，因为主要目标是执行该二进制文件。

观察 Metasploit 监听器将显示会话已成功启动。

[了解更多关于 `sc` 命令的信息](https://technet.microsoft.com/en-us/library/bb490995.aspx)。

在此查找更详细的步骤: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**您还可以使用 Windows Sysinternals 二进制文件 PsExec.exe：**

![](<../../images/image (928).png>)

您还可以使用 [**SharpLateral**](https://github.com/mertdas/SharpLateral)：
```bash
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{{#include ../../banners/hacktricks-training.md}}
