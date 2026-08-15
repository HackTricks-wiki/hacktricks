# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper can package an executable or script as a Windows Installer (`.msi`) file. Download and start the free edition, then select the executable to package.<sup>[[3]](#references)</sup> To run a sequence of commands, select a `.bat` file as the input rather than packaging `cmd.exe`.<sup>[[1]](#references)</sup>

![Selecting the source executable or batch script in MSI Wrapper](<../../images/image (417).png>)

Configure the execution context and other installer properties carefully:

![Configuring the application ID and security context in MSI Wrapper](<../../images/image (312).png>)

![Configuring installer properties in MSI Wrapper](<../../images/image (346).png>)

![Reviewing the MSI Wrapper build settings](<../../images/image (1072).png>)

These values can be changed when packaging a custom binary.

Continue through the remaining wizard pages and select **Build** to generate the installer.<sup>[[1]](#references)</sup>

> [!WARNING]
> Creating an MSI does not by itself grant elevated privileges. Whether installation is elevated depends on Windows Installer policy, package context, and user authorization. Microsoft warns that enabling `AlwaysInstallElevated` for both the user and computer lets non-administrators install packages with system privileges.<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper documentation - Getting started](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installing a package with elevated privileges for a non-admin](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Download](https://www.exemsi.com/download/)

{{#include ../../banners/hacktricks-training.md}}
