# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper 可以将可执行文件或脚本打包为 Windows Installer（`.msi`）文件。下载并启动免费版，然后选择要打包的可执行文件。若要运行一系列命令，请选择 `.bat` 文件作为输入，而不是打包 `cmd.exe`。<sup>[[1]](#references)</sup>

![在 MSI Wrapper 中选择源可执行文件或批处理脚本](<../../images/image (417).png>)

请谨慎配置执行上下文和其他安装程序属性：

![在 MSI Wrapper 中配置应用程序 ID 和安全上下文](<../../images/image (312).png>)

![在 MSI Wrapper 中配置安装程序属性](<../../images/image (346).png>)

![检查 MSI Wrapper 的构建设置](<../../images/image (1072).png>)

打包自定义 binary 时可以更改这些值。

继续完成剩余的向导页面，然后选择 **Build** 生成安装程序。<sup>[[1]](#references)</sup>

> [!WARNING]
> 创建 MSI 本身并不会授予提升的权限。安装是否以提升的权限执行，取决于 Windows Installer policy、package context 和 user authorization。Microsoft 警告称，同时为用户和计算机启用 `AlwaysInstallElevated` 会允许非管理员用户以 system privileges 安装 packages。<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper documentation - Getting started](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installing a package with elevated privileges for a non-admin](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
{{#include ../../banners/hacktricks-training.md}}
