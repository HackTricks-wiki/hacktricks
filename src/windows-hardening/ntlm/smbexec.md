# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## 工作原理

**Smbexec** 是一个用于在 Windows 系统上进行远程命令执行的工具，类似于 **Psexec**，但它避免在目标系统上放置任何恶意文件。

### 关于 **SMBExec** 的关键点

- 它通过在目标机器上创建一个临时服务（例如，“BTOBTO”）来执行命令，通过 cmd.exe (%COMSPEC%)，而不放置任何二进制文件。
- 尽管采用隐蔽的方法，但它确实为每个执行的命令生成事件日志，提供了一种非交互式的“shell”。
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

{{#include ../../banners/hacktricks-training.md}}
