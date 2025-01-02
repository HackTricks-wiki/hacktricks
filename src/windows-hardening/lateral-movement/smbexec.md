# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**从黑客的角度看待您的网络应用程序、网络和云**

**查找并报告具有实际业务影响的关键可利用漏洞。** 使用我们20多个自定义工具来映射攻击面，发现让您提升权限的安全问题，并使用自动化漏洞收集重要证据，将您的辛勤工作转化为有说服力的报告。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## 工作原理

**Smbexec** 是一个用于在Windows系统上进行远程命令执行的工具，类似于 **Psexec**，但它避免在目标系统上放置任何恶意文件。

### 关于 **SMBExec** 的关键点

- 它通过在目标机器上创建一个临时服务（例如，“BTOBTO”）来执行命令，通过cmd.exe (%COMSPEC%)，而不放置任何二进制文件。
- 尽管采用隐蔽的方法，但它确实为每个执行的命令生成事件日志，提供了一种非交互式的“shell”形式。
- 使用 **Smbexec** 连接的命令如下所示：
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### 执行无二进制文件的命令

- **Smbexec** 通过服务 binPaths 直接执行命令，消除了在目标上需要物理二进制文件的需求。
- 这种方法对于在 Windows 目标上执行一次性命令非常有用。例如，将其与 Metasploit 的 `web_delivery` 模块配对，可以执行针对 PowerShell 的反向 Meterpreter 有效载荷。
- 通过在攻击者的机器上创建一个远程服务，并将 binPath 设置为通过 cmd.exe 运行提供的命令，可以成功执行有效载荷，实现回调和有效载荷执行与 Metasploit 监听器，即使发生服务响应错误。

### 命令示例

创建和启动服务可以通过以下命令完成：
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
有关更多详细信息，请查看 [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## 参考文献

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**从黑客的角度审视您的网络应用、网络和云**

**查找并报告具有实际商业影响的关键可利用漏洞。** 使用我们20多个自定义工具来映射攻击面，发现让您提升权限的安全问题，并使用自动化漏洞利用收集重要证据，将您的辛勤工作转化为有说服力的报告。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}
