# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper 可以将可执行文件或脚本打包为 Windows Installer（`.msi`）文件。下载并启动免费版，然后选择要打包的可执行文件。<sup>[[3]](#references)</sup> 若要运行一系列命令，请选择 `.bat` 文件作为输入，而不是打包 `cmd.exe`。<sup>[[1]](#references)</sup>

![在 MSI Wrapper 中选择源可执行文件或批处理脚本](<../../images/image (417).png>)

请仔细配置执行上下文和其他安装程序属性：

![在 MSI Wrapper 中配置应用程序 ID 和安全上下文](<../../images/image (312).png>)

![在 MSI Wrapper 中配置安装程序属性](<../../images/image (346).png>)

![查看 MSI Wrapper 的构建设置](<../../images/image (1072).png>)

打包自定义 binary 时，可以更改这些值。

继续完成剩余的向导页面，然后选择 **Build** 以生成安装程序。<sup>[[1]](#references)</sup>

> [!WARNING]
> 创建 MSI 本身并不会授予提升的权限。安装是否以提升的权限执行，取决于 Windows Installer 策略、软件包上下文和用户授权。Microsoft 警告称，同时为用户和计算机启用 `AlwaysInstallElevated` 会允许非管理员用户以系统权限安装软件包。<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper 文档 - 入门](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - 为非管理员用户安装具有提升权限的软件包](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - 下载](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
