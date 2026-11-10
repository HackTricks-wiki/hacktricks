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

## Verify the wrapped command's execution context

For a test package, wrap a `.bat` file that records its token instead of assuming the MSI's elevation setting applies to its child process.<sup>[[4]](#references)</sup> In the wizard, choose the **System** security context rather than **User** and choose a per-machine, elevated installation when that is the intended path.<sup>[[5]](#references)</sup> The **System** option does not bypass authorization: a non-admin still needs an elevated installation route, such as the [two-policy `AlwaysInstallElevated` misconfiguration](index.html#alwaysinstallelevated) or a privileged installer workflow.<sup>[[2]](#references)</sup> Choosing **User** instead runs the wrapped command with the installing user's context, which may be necessary for user-specific or network resources.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Build the MSI with this batch file as input, then run it on the test host and inspect the recorded identity and privileges.<sup>[[4]](#references)</sup> MSI Wrapper maps a nonzero batch exit code to installation error 1603, so the explicit zero exit avoids a false failure after a successful test.<sup>[[4]](#references)</sup> The output file is a test artifact; do not infer SYSTEM execution merely from a successful `msiexec` exit or a quiet install.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` silences the MSI UI, not necessarily the wrapped executable's own UI.<sup>[[6]](#references)[[7]](#references)</sup> For a wrapped installer, set its supported silent arguments in the wizard; MSI Wrapper's dynamic `WRAPPED_ARGUMENTS` property is a PRO feature.<sup>[[1]](#references)[[7]](#references)</sup> See [the WiX custom-action approach](create-msi-with-wix.md) if you need direct control over custom-action sequencing and impersonation.

> [!WARNING]
> Creating an MSI does not by itself grant elevated privileges. Whether installation is elevated depends on Windows Installer policy, package context, and user authorization. Microsoft warns that enabling `AlwaysInstallElevated` for both the user and computer lets non-administrators install packages with system privileges.<sup>[[2]](#references)</sup>



## References

- [1] [MSI Wrapper documentation - Getting started](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installing a package with elevated privileges for a non-admin](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Download](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Create msi from a batch file](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Wizard Pages](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Command-Line Options](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Command Line Arguments](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
