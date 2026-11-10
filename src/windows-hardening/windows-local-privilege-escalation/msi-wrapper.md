# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper 可以将可执行文件或脚本打包为 Windows Installer（`.msi`）文件。下载并启动免费版，然后选择要打包的可执行文件。<sup>[[3]](#references)</sup> 若要运行一系列命令，请选择 `.bat` 文件作为输入，而不是打包 `cmd.exe`。<sup>[[1]](#references)</sup>

![在 MSI Wrapper 中选择源可执行文件或批处理脚本](<../../images/image (417).png>)

请谨慎配置执行上下文和其他安装程序属性：

![在 MSI Wrapper 中配置应用程序 ID 和安全上下文](<../../images/image (312).png>)

![在 MSI Wrapper 中配置安装程序属性](<../../images/image (346).png>)

![检查 MSI Wrapper 的构建设置](<../../images/image (1072).png>)

打包自定义二进制文件时，可以更改这些值。

继续完成向导中的其余页面，然后选择 **Build** 生成安装程序。<sup>[[1]](#references)</sup>

## 验证封装命令的执行上下文

对于测试包，请封装一个用于记录自身 token 的 `.bat` 文件，不要想当然地认为 MSI 的提权设置也适用于其子进程。<sup>[[4]](#references)</sup> 在向导中，选择 **System** 安全上下文，而非 **User**；如果目标是为计算机安装并提权，请选择相应的安装方式。<sup>[[5]](#references)</sup> **System** 选项不会绕过授权：非管理员仍需要提权安装途径，例如[双策略 `AlwaysInstallElevated` 错误配置](index.html#alwaysinstallelevated)或特权安装程序工作流。<sup>[[2]](#references)</sup> 若选择 **User**，封装的命令将以安装用户的上下文运行；访问用户专属资源或网络资源时可能需要这样做。<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

使用此批处理文件作为输入构建 MSI，然后在测试主机上运行，并检查记录的身份和权限。<sup>[[4]](#references)</sup> MSI Wrapper 会将非零批处理退出代码映射为安装错误 1603，因此在测试成功后显式返回零可避免误报失败。<sup>[[4]](#references)</sup> 输出文件只是测试产物；不要仅凭 `msiexec` 成功退出或静默安装就推断其以 SYSTEM 身份运行。<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` 会隐藏 MSI UI，但不一定会隐藏被封装可执行文件自身的 UI。<sup>[[6]](#references)[[7]](#references)</sup> 对于封装的安装程序，请在向导中设置其支持的静默参数；MSI Wrapper 的动态 `WRAPPED_ARGUMENTS` 属性是 PRO 功能。<sup>[[1]](#references)[[7]](#references)</sup> 如果需要直接控制 custom-action 的执行顺序和模拟身份，请参阅 [WiX custom-action 方案](create-msi-with-wix.md)。

> [!WARNING]
> 创建 MSI 本身并不会授予提升的权限。安装是否以提升权限运行取决于 Windows Installer 策略、软件包上下文和用户授权。Microsoft 警告称，同时为用户和计算机启用 `AlwaysInstallElevated` 会允许非管理员以系统权限安装软件包。<sup>[[2]](#references)</sup>



## References

- [1] [MSI Wrapper 文档 - 入门](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - 为非管理员用户安装具有提升权限的软件包](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - 下载](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - 从批处理文件创建 MSI](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - 向导页面](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - 命令行选项](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - 命令行参数](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
